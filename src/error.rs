use std::{fmt, io};

/// 本地错误的处理策略。丢弃已提交操作不会自动排空、重试或回滚。
/// 调用方按请求选择等待清理、接管恢复或放弃连接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// 返回本地错误前清理已接纳的协议工作。清理期间不调用输入或结果回调。
    /// 查询与批次的恢复额度分别由各自入口定义；清理失败时同时保留两项错误。
    DrainToReady,
    /// 立即返回本地错误，调用方负责显式恢复。
    RecoverExplicitly,
    /// 发送包交给传输后发生本地错误时禁止复用。如果所有已接纳成员均已确认且发送结束，才发现输入超限，则连接仍为空闲。
    Discard,
}

/// 从完整协议帧解析的 PostgreSQL 服务端错误。
/// `Display` 与字段访问器可包含 SQL 和业务数据，应用应按自己的日志规则使用。
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseError {
    fields: Box<[u8]>,
}

impl DatabaseError {
    #[cold]
    pub(crate) fn from_response(response: crate::protocol::ErrorResponse<'_>) -> Self {
        // 字段值已按 UTF-8 校验，标签按协议保留原始字节。
        Self {
            fields: response.encoded.into(),
        }
    }

    /// 限额覆盖诊断对象及其完整的字段字节。
    pub(crate) fn fields_len_within(
        response: crate::protocol::ErrorResponse<'_>,
        budget: usize,
    ) -> Option<usize> {
        let available = budget.checked_sub(size_of::<Self>())?;
        let len = response.encoded.len();
        (len <= available).then_some(len)
    }

    pub(crate) fn storage_size(encoded_len: usize) -> Result<usize, Error> {
        std::mem::size_of::<Self>()
            .checked_add(encoded_len)
            .ok_or(Error::Limit("batch error storage size overflow"))
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize, Error> {
        Self::storage_size(self.fields.len())
    }

    /// 按协议顺序遍历全部字段，包括扩展字段。
    pub fn fields(&self) -> impl Iterator<Item = (u8, &str)> {
        crate::protocol::diagnostic_fields(&self.fields)
    }

    pub fn field(&self, code: u8) -> Option<&str> {
        self.fields()
            .find_map(|(tag, value)| (tag == code).then_some(value))
    }

    /// 优先返回服务端提供的未本地化严重级别。
    pub fn severity(&self) -> &str {
        self.field(b'V')
            .unwrap_or_else(|| self.localized_severity())
    }

    pub fn localized_severity(&self) -> &str {
        self.field(b'S').unwrap_or_default()
    }

    /// 服务端的五字符 SQLSTATE。
    pub fn code(&self) -> &str {
        self.field(b'C').unwrap_or_default()
    }

    pub fn message(&self) -> &str {
        self.field(b'M').unwrap_or_default()
    }

    pub fn detail(&self) -> Option<&str> {
        self.field(b'D')
    }

    pub fn hint(&self) -> Option<&str> {
        self.field(b'H')
    }

    /// 服务端报告的原 SQL 字符位置，从 1 开始。
    pub fn position(&self) -> Option<usize> {
        self.field(b'P')?.parse().ok()
    }

    pub fn internal_position(&self) -> Option<usize> {
        self.field(b'p')?.parse().ok()
    }

    pub fn internal_query(&self) -> Option<&str> {
        self.field(b'q')
    }

    pub fn context(&self) -> Option<&str> {
        self.field(b'W')
    }

    pub fn schema(&self) -> Option<&str> {
        self.field(b's')
    }

    pub fn table(&self) -> Option<&str> {
        self.field(b't')
    }

    pub fn column(&self) -> Option<&str> {
        self.field(b'c')
    }

    pub fn datatype(&self) -> Option<&str> {
        self.field(b'd')
    }

    pub fn constraint(&self) -> Option<&str> {
        self.field(b'n')
    }

    pub fn file(&self) -> Option<&str> {
        self.field(b'F')
    }

    pub fn line(&self) -> Option<u32> {
        self.field(b'L')?.parse().ok()
    }

    pub fn routine(&self) -> Option<&str> {
        self.field(b'R')
    }
}

impl fmt::Debug for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseError")
            .field("code", &self.code())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.severity(),
            self.code(),
            self.message()
        )
    }
}

impl std::error::Error for DatabaseError {}

/// 服务端、协议、编解码和本地校验等错误。
/// 应用可按 [`DatabaseError::code`] 区分服务端错误。处理查询错误后，
/// 通过 [`crate::Client::reuse_state`] 判断连接是否需要排空响应、处理事务或丢弃。
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(crate::protocol::ProtocolError),
    Database(DatabaseError),
    Codec(Box<crate::types::CodecError>),
    Authentication(io::Error),
    InvalidInput(&'static str),
    Unsupported(&'static str),
    Limit(&'static str),
    Busy,
    Broken,
    /// 取消通道失败，本地连接已确认关闭。
    CancelRequest(Box<Error>),
    /// 本地关闭失败；若取消通道同时失败，request 保存该错误。
    CancelRetirement {
        request: Option<Box<Error>>,
        retirement: Box<Error>,
    },
    /// 原操作和错误清理的两项失败。
    Cleanup {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "database transport failed: {error}"),
            Self::Protocol(error) => write!(f, "invalid PostgreSQL message: {error}"),
            Self::Database(error) => error.fmt(f),
            Self::Codec(error) => error.fmt(f),
            Self::Authentication(error) => write!(f, "database authentication failed: {error}"),
            Self::InvalidInput(message) => write!(f, "invalid database request: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported database capability: {message}"),
            Self::Limit(message) => write!(f, "database resource limit exceeded: {message}"),
            Self::Busy => f.write_str("the connection still owns an unfinished request"),
            Self::Broken => f.write_str("the connection cannot be reused"),
            Self::CancelRequest(error) => write!(f, "cancellation request failed: {error}"),
            Self::CancelRetirement {
                request,
                retirement,
            } => {
                if let Some(request) = request {
                    write!(f, "cancellation request failed: {request}; ")?;
                }
                write!(f, "local retirement failed: {retirement}")
            }
            Self::Cleanup { primary, cleanup } => {
                write!(f, "{primary}; cleanup also failed: {cleanup}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::Codec(error) => Some(error.as_ref()),
            Self::Authentication(error) => Some(error),
            Self::CancelRequest(error) => Some(error.as_ref()),
            Self::CancelRetirement { retirement, .. } => Some(retirement.as_ref()),
            Self::Cleanup { primary, .. } => Some(primary.as_ref()),
            _ => None,
        }
    }
}

impl From<crate::types::CodecError> for Error {
    fn from(error: crate::types::CodecError) -> Self {
        Self::Codec(Box::new(error))
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<crate::protocol::ProtocolError> for Error {
    fn from(error: crate::protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
