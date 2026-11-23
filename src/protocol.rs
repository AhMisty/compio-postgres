//! 查询、流水线和 COPY 使用的 PostgreSQL 3.2 协议消息借用视图。
//!
//! 分帧直接借用输入。调用方累积跨多次读取的字节，并在消息借用期间保持其存储不变。结构化消息先校验再返回视图。

use std::{error::Error, ffi::CStr, fmt};

pub const PROTOCOL_VERSION: i32 = 0x0003_0002;
pub const MIN_CANCEL_KEY_LEN: usize = 4;
pub const MAX_CANCEL_KEY_LEN: usize = 256;
pub(crate) const STANDARD_IDENTIFIER_BYTES: usize = 63;
const ROW_FIELD_METADATA_BYTES: usize = 18;
const CANCEL_REQUEST_CODE: i32 = 80_877_102;
pub(crate) const CANCEL_HEADER_BYTES: usize = 12;
// PostgreSQL 19 的启动包体上限为 10,000 字节，编码长度还包括四字节长度字段。
const MAX_STARTUP_PACKET_LEN: usize = 4 + 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidLength(i32),
    LengthOverflow,
    InvalidFrameLimit,
    FrameTooLarge { length: usize, limit: usize },
    UnexpectedEnd,
    MissingTerminator,
    TrailingBytes,
    EmbeddedNul,
    InvalidUtf8,
    InvalidFormatCode(i16),
    InvalidTransactionStatus(u8),
    InvalidCancelKeyLength(usize),
    DuplicateErrorField(u8),
    MissingErrorField(u8),
    InvalidSqlState,
    UnsupportedMessageTag(u8),
    UnsupportedAuthentication(i32),
    InvalidMessage(&'static str),
    AllocationFailed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "invalid PostgreSQL length: {n}"),
            Self::LengthOverflow => f.write_str("PostgreSQL message length exceeds its wire range"),
            Self::InvalidFrameLimit => {
                f.write_str("frame length limit must be at least four bytes")
            }
            Self::FrameTooLarge { length, limit } => {
                write!(f, "PostgreSQL frame length {length} exceeds limit {limit}")
            }
            Self::UnexpectedEnd => f.write_str("truncated PostgreSQL message body"),
            Self::MissingTerminator => f.write_str("missing PostgreSQL string terminator"),
            Self::TrailingBytes => f.write_str("unexpected bytes after PostgreSQL message fields"),
            Self::EmbeddedNul => f.write_str("PostgreSQL string contains a zero byte"),
            Self::InvalidUtf8 => f.write_str("PostgreSQL string is not valid UTF-8"),
            Self::InvalidFormatCode(n) => write!(f, "invalid PostgreSQL format code: {n}"),
            Self::InvalidTransactionStatus(n) => {
                write!(f, "invalid PostgreSQL transaction status byte: {n}")
            }
            Self::InvalidCancelKeyLength(n) => {
                write!(
                    f,
                    "PostgreSQL 3.2 cancellation key length {n} is outside 4..=256"
                )
            }
            Self::DuplicateErrorField(n) => write!(f, "duplicate PostgreSQL error field: {n}"),
            Self::MissingErrorField(n) => write!(f, "missing PostgreSQL error field: {n}"),
            Self::InvalidSqlState => f.write_str("invalid PostgreSQL SQLSTATE field"),
            Self::UnsupportedMessageTag(n) => write!(f, "unsupported PostgreSQL message tag: {n}"),
            Self::UnsupportedAuthentication(n) => {
                write!(f, "unsupported PostgreSQL authentication message: {n}")
            }
            Self::InvalidMessage(reason) => f.write_str(reason),
            Self::AllocationFailed => {
                f.write_str("could not allocate PostgreSQL connection packet")
            }
        }
    }
}

impl Error for ProtocolError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub tag: u8,
    pub body: &'a [u8],
}

impl fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("tag", &self.tag)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameParse<'a> {
    NeedMore,
    Complete { frame: Frame<'a>, consumed: usize },
}

/// 解析一个带标签的服务端帧。`max_frame_len` 包含四字节长度字段，不包含标签。在等待包体前拒绝错误或超限的帧头。
pub fn parse_frame(input: &[u8], max_frame_len: usize) -> Result<FrameParse<'_>, ProtocolError> {
    if max_frame_len < 4 {
        return Err(ProtocolError::InvalidFrameLimit);
    }
    let Some((tag, consumed)) = frame_header(input, max_frame_len)? else {
        return Ok(FrameParse::NeedMore);
    };
    let Some(body) = input.get(5..consumed) else {
        return Ok(FrameParse::NeedMore);
    };
    Ok(FrameParse::Complete {
        frame: Frame { tag, body },
        consumed,
    })
}

pub(crate) fn frame_header(
    input: &[u8],
    max_frame_len: usize,
) -> Result<Option<(u8, usize)>, ProtocolError> {
    let Some([tag, length @ ..]) = input.first_chunk::<5>() else {
        return Ok(None);
    };
    let wire_length = i32::from_be_bytes(*length);
    if wire_length < 4 {
        return Err(ProtocolError::InvalidLength(wire_length));
    }
    let length = usize::try_from(wire_length).map_err(|_| ProtocolError::LengthOverflow)?;
    if length > max_frame_len {
        return Err(ProtocolError::FrameTooLarge {
            length,
            limit: max_frame_len,
        });
    }
    let consumed = length.checked_add(1).ok_or(ProtocolError::LengthOverflow)?;
    Ok(Some((*tag, consumed)))
}

/// 生成不带消息标签的 3.2 启动包，并请求 UTF-8 客户端编码。含长度字段在内最多 10,004 字节。
/// 分配输出前按调用方与协议限额中的较小者校验。认证和服务端版本在握手时确认。
pub fn encode_startup(
    user: &str,
    dbname: &str,
    application_name: &str,
    max_packet_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    encode_startup_with_parameters(user, dbname, application_name, &[], max_packet_len)
}

pub(crate) fn encode_startup_with_parameters(
    user: &str,
    dbname: &str,
    application_name: &str,
    settings: &[(String, String)],
    max_packet_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    if user.contains(['\r', '\n']) || dbname.contains(['\r', '\n']) {
        return Err(ProtocolError::InvalidMessage(
            "PostgreSQL 19 user and database names cannot contain a carriage return or line feed",
        ));
    }
    let max_packet_len = max_packet_len.min(MAX_STARTUP_PACKET_LEN);
    let required = [
        ("user", user),
        ("database", dbname),
        ("application_name", application_name),
        ("client_encoding", "UTF8"),
    ];
    let parameters = required.into_iter().chain(
        settings
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let mut length = 9_usize;
    for (name, value) in parameters.clone() {
        for text in [name, value] {
            if text.as_bytes().contains(&0) {
                return Err(ProtocolError::EmbeddedNul);
            }
            length = length
                .checked_add(text.len())
                .and_then(|n| n.checked_add(1))
                .ok_or(ProtocolError::LengthOverflow)?;
        }
    }
    if length > max_packet_len {
        return Err(ProtocolError::FrameTooLarge {
            length,
            limit: max_packet_len,
        });
    }
    for (index, (name, _)) in settings.iter().enumerate() {
        if name.is_empty() {
            return Err(ProtocolError::InvalidMessage(
                "startup parameter names cannot be empty",
            ));
        }
        if required
            .iter()
            .map(|(required, _)| *required)
            .chain(["options", "replication"])
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
            || name
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("_pq_."))
        {
            return Err(ProtocolError::InvalidMessage(
                "startup parameter name is reserved",
            ));
        }
        if settings
            .iter()
            .take(index)
            .any(|(previous, _)| name.eq_ignore_ascii_case(previous))
        {
            return Err(ProtocolError::InvalidMessage(
                "startup parameter names cannot be repeated",
            ));
        }
    }
    let wire_length = i32::try_from(length).map_err(|_| ProtocolError::LengthOverflow)?;
    let mut output = allocate_packet(length)?;
    output.extend_from_slice(&wire_length.to_be_bytes());
    output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    for (name, value) in parameters {
        output.extend_from_slice(name.as_bytes());
        output.push(0);
        output.extend_from_slice(value.as_bytes());
        output.push(0);
    }
    output.push(0);
    Ok(output)
}

/// 为独立的取消连接生成请求，保留完整的不透明密钥，包括零字节。
pub fn encode_cancel(process_id: i32, secret_key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let header = cancel_header(process_id, secret_key)?;
    let mut output = allocate_packet(header.len() + secret_key.len())?;
    output.extend_from_slice(&header);
    output.extend_from_slice(secret_key);
    Ok(output)
}

pub(crate) fn cancel_header(
    process_id: i32,
    secret_key: &[u8],
) -> Result<[u8; CANCEL_HEADER_BYTES], ProtocolError> {
    check_cancel_key(secret_key)?;
    let length = CANCEL_HEADER_BYTES + secret_key.len();
    let wire_length = i32::try_from(length).map_err(|_| ProtocolError::LengthOverflow)?;
    let mut header = [0; CANCEL_HEADER_BYTES];
    header[..4].copy_from_slice(&wire_length.to_be_bytes());
    header[4..8].copy_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
    header[8..].copy_from_slice(&process_id.to_be_bytes());
    Ok(header)
}

fn allocate_packet(length: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::AllocationFailed)?;
    Ok(output)
}

fn check_cancel_key(key: &[u8]) -> Result<(), ProtocolError> {
    if !(MIN_CANCEL_KEY_LEN..=MAX_CANCEL_KEY_LEN).contains(&key.len()) {
        return Err(ProtocolError::InvalidCancelKeyLength(key.len()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    FailedTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Binary,
}

impl Format {
    pub fn code(self) -> i16 {
        match self {
            Self::Text => 0,
            Self::Binary => 1,
        }
    }

    fn parse(code: i16) -> Result<Self, ProtocolError> {
        match code {
            0 => Ok(Self::Text),
            1 => Ok(Self::Binary),
            _ => Err(ProtocolError::InvalidFormatCode(code)),
        }
    }
}

/// 执行请求的结束方式。Flush 要求刷新输出；Sync 建立 ReadyForQuery 边界；Open 不追加结束消息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryTail {
    Sync,
    Flush,
    Open,
}

/// 无需解析 SQL 文本便能确定语义的事务控制命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxCommand<'a> {
    Begin,
    Commit { chain: bool },
    Rollback { chain: bool },
    Savepoint(&'a str),
    ReleaseSavepoint(&'a str),
    RollbackToSavepoint(&'a str),
}

/// 服务端命令标签。
/// ROLLBACK TO SAVEPOINT 和事务回滚共用 Rollback 标签，须结合原命令和 Ready 状态判定事务是否结束。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTag<'a> {
    Begin,
    Commit,
    Rollback,
    Savepoint,
    Release,
    Select(u64),
    Insert(u64),
    Update(u64),
    Delete(u64),
    Merge(u64),
    Move(u64),
    Fetch(u64),
    Copy(u64),
    Other(&'a str),
}

pub fn parse_command_tag(tag: &str) -> Result<CommandTag<'_>, ProtocolError> {
    match tag {
        "" => return Err(ProtocolError::InvalidMessage("empty command tag")),
        "BEGIN" => return Ok(CommandTag::Begin),
        "COMMIT" => return Ok(CommandTag::Commit),
        "ROLLBACK" => return Ok(CommandTag::Rollback),
        "SAVEPOINT" => return Ok(CommandTag::Savepoint),
        "RELEASE" => return Ok(CommandTag::Release),
        _ => {}
    }
    let (command, count) = tag.split_once(' ').unwrap_or((tag, ""));
    let parsed = match command {
        "SELECT" => CommandTag::Select(command_count(count)?),
        "UPDATE" => CommandTag::Update(command_count(count)?),
        "DELETE" => CommandTag::Delete(command_count(count)?),
        "MERGE" => CommandTag::Merge(command_count(count)?),
        "MOVE" => CommandTag::Move(command_count(count)?),
        "FETCH" => CommandTag::Fetch(command_count(count)?),
        "COPY" => CommandTag::Copy(command_count(count)?),
        "INSERT" => {
            // PostgreSQL 19 固定发送零值作为历史 OID 字段。
            let rows = count
                .strip_prefix("0 ")
                .ok_or(ProtocolError::InvalidMessage(
                    "INSERT tag must start with the zero OID field",
                ))?;
            CommandTag::Insert(command_count(rows)?)
        }
        _ => CommandTag::Other(tag),
    };
    Ok(parsed)
}

fn command_count(value: &str) -> Result<u64, ProtocolError> {
    if let [digit @ b'0'..=b'9'] = value.as_bytes() {
        return Ok(u64::from(*digit - b'0'));
    }
    match value.parse::<u64>() {
        Ok(count) if !value.starts_with('+') => Ok(count),
        // 整数解析可能先遇到溢出再遇到非法后缀。只有整段均为无符号十进制数字时才报告溢出。
        Err(error)
            if *error.kind() == std::num::IntErrorKind::PosOverflow
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Err(ProtocolError::InvalidMessage(
                "command tag count exceeds u64",
            ))
        }
        _ => Err(ProtocolError::InvalidMessage("invalid command tag count")),
    }
}

/// 已验证的 COPY 元数据。列格式借用响应字节，只描述字段编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyResponse<'a> {
    pub format: Format,
    encoded_formats: &'a [[u8; 2]],
    uniform_format: Option<Format>,
}

impl<'a> CopyResponse<'a> {
    pub fn len(self) -> usize {
        self.encoded_formats.len()
    }

    pub fn is_empty(self) -> bool {
        self.encoded_formats.is_empty()
    }

    pub(crate) fn uniform_format(self) -> Option<Format> {
        self.uniform_format
    }

    /// 整帧解析时已经验证所有格式码。按列借用并解码，无需分配。
    pub fn column_formats(
        self,
    ) -> impl ExactSizeIterator<Item = Format> + DoubleEndedIterator + 'a {
        self.encoded_formats.iter().map(|code| {
            if code[1] == 0 {
                Format::Text
            } else {
                Format::Binary
            }
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BackendKeyData<'a> {
    pub process_id: i32,
    pub secret_key: &'a [u8],
}

impl fmt::Debug for BackendKeyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendKeyData")
            .field("process_id", &self.process_id)
            .field("secret_key_length", &self.secret_key.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Authentication<'a> {
    Ok,
    CleartextPassword,
    Md5Password { salt: [u8; 4] },
    Sasl(StringList<'a>),
    SaslContinue(&'a [u8]),
    SaslFinal(&'a [u8]),
}

impl fmt::Debug for Authentication<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("AuthenticationOk"),
            Self::CleartextPassword => f.write_str("AuthenticationCleartextPassword"),
            Self::Md5Password { .. } => f.write_str("AuthenticationMd5Password"),
            Self::Sasl(mechanisms) => f
                .debug_struct("AuthenticationSasl")
                .field("mechanism_count", &mechanisms.len())
                .finish(),
            Self::SaslContinue(data) => f
                .debug_struct("AuthenticationSaslContinue")
                .field("length", &data.len())
                .finish(),
            Self::SaslFinal(data) => f
                .debug_struct("AuthenticationSaslFinal")
                .field("length", &data.len())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringList<'a> {
    encoded: &'a [u8],
    count: usize,
}

impl<'a> StringList<'a> {
    pub fn len(self) -> usize {
        self.count
    }

    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    pub fn iter(self) -> StringListIter<'a> {
        StringListIter {
            cursor: Cursor::new(self.encoded),
            remaining: self.count,
        }
    }
}

pub struct StringListIter<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl<'a> Iterator for StringListIter<'a> {
    type Item = Result<&'a str, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = self.cursor.string();
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for StringListIter<'_> {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ErrorResponse<'a> {
    pub severity: &'a str,
    pub severity_nonlocalized: Option<&'a str>,
    pub sqlstate: &'a str,
    pub message: &'a str,
    pub detail: Option<&'a str>,
    pub hint: Option<&'a str>,
    pub(crate) encoded: &'a [u8],
}

impl fmt::Debug for ErrorResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 诊断内容可能含 SQL 参数、查询文本和用户数据；需要时由调用方显式读取字段。
        f.debug_struct("ErrorResponse")
            .field("sqlstate", &self.sqlstate)
            .finish_non_exhaustive()
    }
}

impl<'a> ErrorResponse<'a> {
    /// 按协议顺序返回全部字段，包括扩展字段。
    pub fn fields(self) -> impl Iterator<Item = (u8, &'a str)> {
        diagnostic_fields(self.encoded)
    }
}

pub(crate) fn diagnostic_fields(encoded: &[u8]) -> impl Iterator<Item = (u8, &str)> {
    let mut cursor = Cursor::new(encoded);
    std::iter::from_fn(move || {
        let code = cursor.byte().ok()?;
        if code == 0 {
            return None;
        }
        Some((code, cursor.string().ok()?))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDescription<'a> {
    pub name: &'a str,
    pub table_oid: u32,
    pub column_id: i16,
    pub type_oid: u32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: Format,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RowDescription<'a> {
    encoded: &'a [u8],
    count: u16,
    uniform_format: Option<Format>,
    first_type_oid: u32,
}

impl fmt::Debug for RowDescription<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowDescription")
            .field("column_count", &self.count)
            .field("uniform_format", &self.uniform_format)
            .finish_non_exhaustive()
    }
}

impl<'a> RowDescription<'a> {
    pub(crate) fn column_count(self) -> u16 {
        self.count
    }

    pub fn len(self) -> usize {
        usize::from(self.count)
    }

    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    /// 空结果描述使用默认文本格式；混合格式没有统一的格式码。
    pub(crate) fn uniform_format(self) -> Option<Format> {
        self.uniform_format
    }

    pub(crate) fn scalar(self) -> Option<(u32, Format)> {
        (self.count == 1).then_some((self.first_type_oid, self.uniform_format?))
    }

    pub(crate) fn name_bytes(self) -> usize {
        // 自有名称不保留 NUL 终止字节和固定元数据。
        self.encoded.len() - self.len() * (1 + ROW_FIELD_METADATA_BYTES)
    }

    pub fn iter(self) -> RowDescriptionIter<'a> {
        RowDescriptionIter {
            cursor: Cursor::new(self.encoded),
            remaining: self.count,
        }
    }
}

pub struct RowDescriptionIter<'a> {
    cursor: Cursor<'a>,
    remaining: u16,
}

impl<'a> Iterator for RowDescriptionIter<'a> {
    type Item = Result<FieldDescription<'a>, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = parse_field_description(&mut self.cursor);
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize::from(self.remaining);
        (n, Some(n))
    }
}

impl ExactSizeIterator for RowDescriptionIter<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterDescription<'a> {
    oids: &'a [[u8; 4]],
}

impl<'a> ParameterDescription<'a> {
    pub fn len(self) -> usize {
        self.oids.len()
    }

    pub fn is_empty(self) -> bool {
        self.oids.is_empty()
    }

    /// 按协议顺序读取 OID。长度和尾部字节已在解析入口验证。
    pub fn iter(self) -> impl ExactSizeIterator<Item = u32> + DoubleEndedIterator + 'a {
        self.oids.iter().copied().map(u32::from_be_bytes)
    }
}

/// 结构已完整验证的数据行。迭代时重读字段长度并借用字段内容，无需分配偏移表；标量语义由所选编解码器校验。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DataRow<'a> {
    encoded: &'a [u8],
    count: u16,
    scalar_is_null: bool,
}

/// 完整扫描行结构后取得的描述符。它只对应同一未消费且未改写的帧，消费或替换该帧前必须丢弃。
#[derive(Clone, Copy)]
pub(crate) struct ValidatedDataRow {
    encoded_len: usize,
    count: u16,
    scalar_is_null: bool,
}

impl ValidatedDataRow {
    pub(crate) fn reborrow(self, frame: Frame<'_>) -> Result<DataRow<'_>, ProtocolError> {
        const CHANGED: ProtocolError = ProtocolError::InvalidMessage("validated row frame changed");
        let (count, encoded) = frame.body.split_first_chunk::<2>().ok_or(CHANGED)?;
        if frame.tag != b'D'
            || encoded.len() != self.encoded_len
            || *count != self.count.to_be_bytes()
        {
            return Err(CHANGED);
        }
        Ok(DataRow {
            encoded,
            count: self.count,
            scalar_is_null: self.scalar_is_null,
        })
    }
}

impl fmt::Debug for DataRow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataRow")
            .field("field_count", &self.count)
            .finish_non_exhaustive()
    }
}

impl<'a> DataRow<'a> {
    pub(crate) fn descriptor(self) -> ValidatedDataRow {
        ValidatedDataRow {
            encoded_len: self.encoded.len(),
            count: self.count,
            scalar_is_null: self.scalar_is_null,
        }
    }
    pub fn len(self) -> usize {
        usize::from(self.count)
    }

    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    /// 已验证的字段长度和内容，不含最前面的两字节列数。复制后保留 NULL 与空值的区别。
    pub fn encoded_fields(self) -> &'a [u8] {
        self.encoded
    }

    /// 在已验证长度及行尾后借用唯一字段，NULL 与空切片分别表示。
    pub(crate) fn scalar_field(self) -> Option<Option<&'a [u8]>> {
        if self.count != 1 {
            return None;
        }
        if self.scalar_is_null {
            Some(None)
        } else {
            self.encoded.get(4..).map(Some)
        }
    }

    pub fn iter(self) -> DataRowIter<'a> {
        DataRowIter {
            cursor: Cursor::new(self.encoded),
            remaining: self.count,
        }
    }
}

pub struct DataRowIter<'a> {
    cursor: Cursor<'a>,
    remaining: u16,
}

impl<'a> Iterator for DataRowIter<'a> {
    type Item = Result<Option<&'a [u8]>, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = parse_data_field(&mut self.cursor);
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize::from(self.remaining);
        (n, Some(n))
    }
}

impl ExactSizeIterator for DataRowIter<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolNegotiation<'a> {
    /// 服务端选定的完整协议版本，高 16 位为主版本，低 16 位为次版本。
    pub protocol_version: u32,
    pub unrecognized_options: StringList<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BackendMessage<'a> {
    Authentication(Authentication<'a>),
    BackendKeyData(BackendKeyData<'a>),
    ParameterStatus {
        name: &'a str,
        value: &'a str,
    },
    ReadyForQuery(TransactionStatus),
    ErrorResponse(ErrorResponse<'a>),
    NoticeResponse(ErrorResponse<'a>),
    RowDescription(RowDescription<'a>),
    ParameterDescription(ParameterDescription<'a>),
    DataRow(DataRow<'a>),
    CommandComplete(&'a str),
    ParseComplete,
    BindComplete,
    CloseComplete,
    NoData,
    EmptyQueryResponse,
    PortalSuspended,
    CopyInResponse(CopyResponse<'a>),
    CopyOutResponse(CopyResponse<'a>),
    CopyBothResponse(CopyResponse<'a>),
    CopyData(&'a [u8]),
    CopyDone,
    NotificationResponse {
        process_id: i32,
        channel: &'a str,
        payload: &'a str,
    },
    NegotiateProtocolVersion(ProtocolNegotiation<'a>),
}

impl fmt::Debug for BackendMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 诊断使用消息类别；通知、COPY、服务端设置与结果字段通过各消息视图读取。
        match self {
            Self::Authentication(value) => f.debug_tuple("Authentication").field(value).finish(),
            Self::BackendKeyData(value) => f.debug_tuple("BackendKeyData").field(value).finish(),
            Self::ParameterStatus { .. } => f.write_str("ParameterStatus"),
            Self::ReadyForQuery(value) => f.debug_tuple("ReadyForQuery").field(value).finish(),
            Self::ErrorResponse(value) => f.debug_tuple("ErrorResponse").field(value).finish(),
            Self::NoticeResponse(value) => f.debug_tuple("NoticeResponse").field(value).finish(),
            Self::RowDescription(value) => f.debug_tuple("RowDescription").field(value).finish(),
            Self::ParameterDescription(value) => f
                .debug_struct("ParameterDescription")
                .field("parameter_count", &value.len())
                .finish_non_exhaustive(),
            Self::DataRow(value) => f.debug_tuple("DataRow").field(value).finish(),
            Self::CommandComplete(_) => f.write_str("CommandComplete"),
            Self::ParseComplete => f.write_str("ParseComplete"),
            Self::BindComplete => f.write_str("BindComplete"),
            Self::CloseComplete => f.write_str("CloseComplete"),
            Self::NoData => f.write_str("NoData"),
            Self::EmptyQueryResponse => f.write_str("EmptyQueryResponse"),
            Self::PortalSuspended => f.write_str("PortalSuspended"),
            Self::CopyInResponse(value) => f.debug_tuple("CopyInResponse").field(value).finish(),
            Self::CopyOutResponse(value) => f.debug_tuple("CopyOutResponse").field(value).finish(),
            Self::CopyBothResponse(value) => {
                f.debug_tuple("CopyBothResponse").field(value).finish()
            }
            Self::CopyData(value) => f
                .debug_struct("CopyData")
                .field("payload_bytes", &value.len())
                .finish_non_exhaustive(),
            Self::CopyDone => f.write_str("CopyDone"),
            Self::NotificationResponse {
                process_id,
                channel,
                payload,
            } => f
                .debug_struct("NotificationResponse")
                .field("process_id", process_id)
                .field("channel_bytes", &channel.len())
                .field("payload_bytes", &payload.len())
                .finish_non_exhaustive(),
            Self::NegotiateProtocolVersion(value) => f
                .debug_struct("NegotiateProtocolVersion")
                .field("protocol_version", &value.protocol_version)
                .field(
                    "unrecognized_option_count",
                    &value.unrecognized_options.len(),
                )
                .finish_non_exhaustive(),
        }
    }
}

/// 解析支持的服务端消息并拒绝多余的尾部字节。消息顺序、认证、服务端版本和查询结果由会话状态机检查。
pub fn parse_backend(frame: Frame<'_>) -> Result<BackendMessage<'_>, ProtocolError> {
    let mut cursor = Cursor::new(frame.body);
    let message = match frame.tag {
        b'R' => return parse_authentication(frame.body).map(BackendMessage::Authentication),
        b'K' => {
            let process_id = cursor.i32()?;
            let secret_key = cursor.remaining;
            check_cancel_key(secret_key)?;
            return Ok(BackendMessage::BackendKeyData(BackendKeyData {
                process_id,
                secret_key,
            }));
        }
        b'S' => BackendMessage::ParameterStatus {
            name: cursor.string()?,
            value: cursor.string()?,
        },
        b'Z' => {
            let status = match cursor.byte()? {
                b'I' => TransactionStatus::Idle,
                b'T' => TransactionStatus::InTransaction,
                b'E' => TransactionStatus::FailedTransaction,
                value => return Err(ProtocolError::InvalidTransactionStatus(value)),
            };
            BackendMessage::ReadyForQuery(status)
        }
        b'E' => return parse_error(frame.body).map(BackendMessage::ErrorResponse),
        b'N' => return parse_error(frame.body).map(BackendMessage::NoticeResponse),
        b'T' => {
            let count = cursor.u16()?;
            let encoded = cursor.remaining;
            let (first_type_oid, uniform_format) = if count == 0 {
                (0, Some(Format::Text))
            } else {
                let first = parse_field_description(&mut cursor)?;
                let mut uniform_format = Some(first.format);
                for _ in 1..count {
                    if parse_field_description(&mut cursor)?.format != first.format {
                        uniform_format = None;
                    }
                }
                (first.type_oid, uniform_format)
            };
            BackendMessage::RowDescription(RowDescription {
                encoded,
                count,
                uniform_format,
                first_type_oid,
            })
        }
        b't' => {
            let count = cursor.u16()?;
            let required = usize::from(count)
                .checked_mul(4)
                .ok_or(ProtocolError::LengthOverflow)?;
            let (oids, _) = cursor.take(required)?.as_chunks::<4>();
            BackendMessage::ParameterDescription(ParameterDescription { oids })
        }
        b'D' => return parse_data_row(frame.body).map(BackendMessage::DataRow),
        b'C' => BackendMessage::CommandComplete(cursor.string()?),
        b'1' => BackendMessage::ParseComplete,
        b'2' => BackendMessage::BindComplete,
        b'3' => BackendMessage::CloseComplete,
        b'n' => BackendMessage::NoData,
        b'I' => BackendMessage::EmptyQueryResponse,
        b's' => BackendMessage::PortalSuspended,
        b'G' => return parse_copy_response(frame.body).map(BackendMessage::CopyInResponse),
        b'H' => return parse_copy_response(frame.body).map(BackendMessage::CopyOutResponse),
        b'W' => return parse_copy_response(frame.body).map(BackendMessage::CopyBothResponse),
        b'd' => return Ok(BackendMessage::CopyData(frame.body)),
        b'c' => BackendMessage::CopyDone,
        b'A' => BackendMessage::NotificationResponse {
            process_id: cursor.i32()?,
            channel: cursor.string()?,
            payload: cursor.string()?,
        },
        b'v' => {
            let protocol_version = u32::try_from(cursor.i32()?).map_err(|_| {
                ProtocolError::InvalidMessage("negative negotiated PostgreSQL protocol version")
            })?;
            let count = usize::try_from(cursor.i32()?).map_err(|_| {
                ProtocolError::InvalidMessage("negative PostgreSQL protocol option count")
            })?;
            let encoded = cursor.remaining;
            for _ in 0..count {
                cursor.string()?;
            }
            BackendMessage::NegotiateProtocolVersion(ProtocolNegotiation {
                protocol_version,
                unrecognized_options: StringList { encoded, count },
            })
        }
        tag => return Err(ProtocolError::UnsupportedMessageTag(tag)),
    };
    cursor.finish()?;
    Ok(message)
}

/// 向调用方交付行前先校验每个字段和行尾。
pub(crate) fn parse_data_row(body: &[u8]) -> Result<DataRow<'_>, ProtocolError> {
    let mut cursor = Cursor::new(body);
    let count = cursor.u16()?;
    let encoded = cursor.remaining;
    let scalar_is_null = matches!(data_row_fields(&mut cursor, count)?, Some(None));
    cursor.finish()?;
    Ok(DataRow {
        encoded,
        count,
        scalar_is_null,
    })
}

/// 校验完整包体；单列时返回字段。外层 Option 表示是否单列，内层 Option 表示该字段是否为 NULL。
pub(crate) fn parse_scalar_data_row(body: &[u8]) -> Result<Option<Option<&[u8]>>, ProtocolError> {
    let mut cursor = Cursor::new(body);
    let count = cursor.u16()?;
    let field = data_row_fields(&mut cursor, count)?;
    cursor.finish()?;
    Ok(field)
}

fn data_row_fields<'a>(
    cursor: &mut Cursor<'a>,
    count: u16,
) -> Result<Option<Option<&'a [u8]>>, ProtocolError> {
    if count == 1 {
        return parse_data_field(cursor).map(Some);
    }
    for _ in 0..count {
        parse_data_field(cursor)?;
    }
    Ok(None)
}

fn parse_copy_response(body: &[u8]) -> Result<CopyResponse<'_>, ProtocolError> {
    let mut cursor = Cursor::new(body);
    let format = Format::parse(i16::from(cursor.byte()?))?;
    let count = cursor.u16()?;
    let (encoded_formats, _) = cursor.take(usize::from(count) * 2)?.as_chunks::<2>();
    let mut seen_formats = 0_u8;
    for bytes in encoded_formats {
        let column_format = Format::parse(i16::from_be_bytes(*bytes))?;
        if format == Format::Text && column_format != Format::Text {
            return Err(ProtocolError::InvalidMessage(
                "text COPY response contains a binary column format",
            ));
        }
        seen_formats |= 1 << u8::from(column_format == Format::Binary);
    }
    cursor.finish()?;
    Ok(CopyResponse {
        format,
        encoded_formats,
        uniform_format: match seen_formats {
            0 => Some(format),
            1 => Some(Format::Text),
            2 => Some(Format::Binary),
            _ => None,
        },
    })
}

fn parse_authentication(body: &[u8]) -> Result<Authentication<'_>, ProtocolError> {
    let mut cursor = Cursor::new(body);
    let message = match cursor.i32()? {
        0 => Authentication::Ok,
        3 => Authentication::CleartextPassword,
        5 => Authentication::Md5Password {
            salt: cursor.array()?,
        },
        10 => {
            let encoded = cursor.remaining;
            let mut count = 0;
            loop {
                let name = cursor.string()?;
                if name.is_empty() {
                    break;
                }
                count += 1;
            }
            if count == 0 {
                return Err(ProtocolError::InvalidMessage(
                    "empty PostgreSQL SASL mechanism list",
                ));
            }
            Authentication::Sasl(StringList { encoded, count })
        }
        11 => return Ok(Authentication::SaslContinue(cursor.remaining)),
        12 => return Ok(Authentication::SaslFinal(cursor.remaining)),
        code => return Err(ProtocolError::UnsupportedAuthentication(code)),
    };
    cursor.finish()?;
    Ok(message)
}

fn parse_error(body: &[u8]) -> Result<ErrorResponse<'_>, ProtocolError> {
    let mut cursor = Cursor::new(body);
    let mut seen = [0_u64; 4];
    let mut severity = None;
    let mut severity_nonlocalized = None;
    let mut sqlstate = None;
    let mut message = None;
    let mut detail = None;
    let mut hint = None;
    loop {
        let code = cursor.byte()?;
        if code == 0 {
            break;
        }
        // 一个字节的标签空间对应四个 u64，高两位是有效的数组下标。
        let word = seen
            .get_mut(usize::from(code >> 6))
            .ok_or(ProtocolError::InvalidMessage(
                "invalid diagnostic field tag",
            ))?;
        let mask = 1_u64 << (u32::from(code) % 64);
        if *word & mask != 0 {
            return Err(ProtocolError::DuplicateErrorField(code));
        }
        *word |= mask;
        let value = cursor.string()?;
        match code {
            b'S' => severity = Some(value),
            b'V' => severity_nonlocalized = Some(value),
            b'C' => sqlstate = Some(value),
            b'M' => message = Some(value),
            b'D' => detail = Some(value),
            b'H' => hint = Some(value),
            // ErrorResponse::fields 保留全部字段。
            _ => {}
        }
    }
    cursor.finish()?;
    let sqlstate = sqlstate.ok_or(ProtocolError::MissingErrorField(b'C'))?;
    if sqlstate.len() != 5
        || !sqlstate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidSqlState);
    }
    Ok(ErrorResponse {
        severity: severity.ok_or(ProtocolError::MissingErrorField(b'S'))?,
        severity_nonlocalized,
        sqlstate,
        message: message.ok_or(ProtocolError::MissingErrorField(b'M'))?,
        detail,
        hint,
        encoded: body,
    })
}

fn parse_field_description<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<FieldDescription<'a>, ProtocolError> {
    let name = cursor.string()?;
    // 固定元数据一次验证长度，随后按协议偏移解码。
    let wire = cursor.array::<ROW_FIELD_METADATA_BYTES>()?;
    Ok(FieldDescription {
        name,
        table_oid: u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]),
        column_id: i16::from_be_bytes([wire[4], wire[5]]),
        type_oid: u32::from_be_bytes([wire[6], wire[7], wire[8], wire[9]]),
        type_size: i16::from_be_bytes([wire[10], wire[11]]),
        type_modifier: i32::from_be_bytes([wire[12], wire[13], wire[14], wire[15]]),
        format: Format::parse(i16::from_be_bytes([wire[16], wire[17]]))?,
    })
}

fn parse_data_field<'a>(cursor: &mut Cursor<'a>) -> Result<Option<&'a [u8]>, ProtocolError> {
    let wire_length = cursor.i32()?;
    if wire_length == -1 {
        return Ok(None);
    }
    let length =
        usize::try_from(wire_length).map_err(|_| ProtocolError::InvalidLength(wire_length))?;
    cursor.take(length).map(Some)
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let (value, rest) = self
            .remaining
            .split_first_chunk::<N>()
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.remaining = rest;
        Ok(*value)
    }

    fn byte(&mut self) -> Result<u8, ProtocolError> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        self.array().map(u16::from_be_bytes)
    }

    fn i32(&mut self) -> Result<i32, ProtocolError> {
        self.array().map(i32::from_be_bytes)
    }

    fn string(&mut self) -> Result<&'a str, ProtocolError> {
        let value = CStr::from_bytes_until_nul(self.remaining)
            .map_err(|_| ProtocolError::MissingTerminator)?;
        self.remaining = self
            .remaining
            .get(value.to_bytes_with_nul().len()..)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        value.to_str().map_err(|_| ProtocolError::InvalidUtf8)
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_field_iterators_report_remaining_items() {
        let fields = [0, 2, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        let row = parse_data_row(&fields).unwrap();
        let mut iter = row.iter();
        assert_eq!(iter.size_hint(), (2, Some(2)));
        assert_eq!(iter.next(), Some(Ok(Some(&[][..]))));
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.next(), Some(Ok(None)));
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn row_descriptors_reborrow_only_the_same_header_shape_after_strict_validation() {
        let body = [0, 1, 0, 0, 0, 4, 0, 0, 0, 42];
        let frame = Frame {
            tag: b'D',
            body: &body,
        };
        let BackendMessage::DataRow(row) = parse_backend(frame).unwrap() else {
            panic!("row")
        };
        let descriptor = row.descriptor();
        assert_eq!(descriptor.reborrow(frame).unwrap(), row);
        assert!(
            descriptor
                .reborrow(Frame {
                    tag: b'C',
                    body: &body
                })
                .is_err()
        );
        assert!(
            descriptor
                .reborrow(Frame {
                    tag: b'D',
                    body: &body[..9]
                })
                .is_err()
        );
        let mut changed = body;
        changed[1] = 2;
        assert!(
            descriptor
                .reborrow(Frame {
                    tag: b'D',
                    body: &changed
                })
                .is_err()
        );
        let mut malformed = body;
        malformed[5] = 5;
        assert!(
            parse_backend(Frame {
                tag: b'D',
                body: &malformed
            })
            .is_err()
        );
    }
    fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
        let length = i32::try_from(body.len() + 4).expect("test frame fits wire length");
        let mut output = vec![tag];
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(body);
        output
    }

    fn backend(tag: u8, body: &[u8]) -> Result<BackendMessage<'_>, ProtocolError> {
        parse_backend(Frame { tag, body })
    }

    #[test]
    fn startup_uses_untagged_32_and_complete_parameter_termination() {
        let output =
            encode_startup("alice", "db", "probe", MAX_STARTUP_PACKET_LEN).expect("valid startup");
        let mut expected = Vec::from(PROTOCOL_VERSION.to_be_bytes());
        expected.extend_from_slice(
            b"user\0alice\0database\0db\0application_name\0probe\0client_encoding\0UTF8\0\0",
        );
        let length = i32::try_from(expected.len() + 4).expect("small startup");
        assert_eq!(&output[..4], &length.to_be_bytes());
        assert_eq!(&output[4..], &expected);
        assert_eq!(PROTOCOL_VERSION, 196_610);
        for (user, db, app) in [
            ("a\0b", "db", "app"),
            ("a", "d\0b", "app"),
            ("a", "db", "a\0p"),
        ] {
            assert_eq!(
                encode_startup(user, db, app, MAX_STARTUP_PACKET_LEN),
                Err(ProtocolError::EmbeddedNul)
            );
        }
        for name in ["a\rb", "a\nb"] {
            for (user, database) in [(name, "db"), ("alice", name)] {
                assert!(matches!(
                    encode_startup(user, database, "app", MAX_STARTUP_PACKET_LEN),
                    Err(ProtocolError::InvalidMessage(_))
                ));
            }
        }
        assert!(encode_startup("alice", "db", "a\nb", MAX_STARTUP_PACKET_LEN).is_ok());
    }

    #[test]
    fn startup_session_defaults_follow_core_fields_and_keep_wire_bounds() {
        let settings = [
            ("search_path".to_owned(), "public, safe".to_owned()),
            ("statement_timeout".to_owned(), "7s".to_owned()),
        ];
        let message =
            encode_startup_with_parameters("alice", "db", "probe", &settings, 4096).unwrap();
        assert!(message.ends_with(
            b"client_encoding\0UTF8\0search_path\0public, safe\0statement_timeout\x007s\0\0"
        ));
        assert_eq!(
            encode_startup_with_parameters("alice", "db", "probe", &settings, message.len() - 1),
            Err(ProtocolError::FrameTooLarge {
                length: message.len(),
                limit: message.len() - 1,
            })
        );
    }

    #[test]
    fn startup_session_defaults_cannot_override_core_or_protocol_fields() {
        for key in [
            "user",
            "DATABASE",
            "APPLICATION_NAME",
            "Client_Encoding",
            "options",
            "replication",
            "_pq_.test_protocol_negotiation",
            "",
        ] {
            let settings = [(key.into(), "value".into())];
            assert!(matches!(
                encode_startup_with_parameters("alice", "db", "probe", &settings, 4096),
                Err(ProtocolError::InvalidMessage(_))
            ));
        }
        let duplicate = [
            ("search_path".into(), "public".into()),
            ("SEARCH_PATH".into(), "safe".into()),
        ];
        assert!(matches!(
            encode_startup_with_parameters("alice", "db", "probe", &duplicate, 4096),
            Err(ProtocolError::InvalidMessage(_))
        ));
        let embedded_nul = [("search_path".into(), "public\0other".into())];
        assert_eq!(
            encode_startup_with_parameters("alice", "db", "probe", &embedded_nul, 4096),
            Err(ProtocolError::EmbeddedNul)
        );
    }

    #[test]
    fn startup_enforces_the_smaller_of_the_wire_and_caller_limits() {
        let header_len = encode_startup("alice", "db", "", MAX_STARTUP_PACKET_LEN)
            .unwrap()
            .len();
        let at_wire_limit = "x".repeat(MAX_STARTUP_PACKET_LEN - header_len);
        assert_eq!(
            encode_startup("alice", "db", &at_wire_limit, usize::MAX)
                .unwrap()
                .len(),
            10_004
        );

        let application_name = at_wire_limit + "x";
        assert_eq!(
            encode_startup("alice", "db", &application_name, usize::MAX),
            Err(ProtocolError::FrameTooLarge {
                length: 10_005,
                limit: 10_004,
            })
        );
        assert_eq!(
            encode_startup("alice", "db", "", header_len - 1),
            Err(ProtocolError::FrameTooLarge {
                length: header_len,
                limit: header_len - 1,
            })
        );
    }

    #[test]
    fn cancellation_preserves_every_key_byte_including_middleware_lengths() {
        for length in [4, 32, 33, 256] {
            let key: Vec<u8> = (0_u8..=255).cycle().take(length).collect();
            let mut body = Vec::from(12345_i32.to_be_bytes());
            body.extend_from_slice(&key);
            let BackendMessage::BackendKeyData(parsed) = backend(b'K', &body).expect("valid key")
            else {
                panic!("wrong message");
            };
            assert_eq!(parsed.process_id, 12345);
            assert_eq!(parsed.secret_key, key);
            let packet = encode_cancel(parsed.process_id, parsed.secret_key).expect("valid cancel");
            assert_eq!(&packet[4..8], &80_877_102_i32.to_be_bytes());
            assert_eq!(&packet[8..12], &12345_i32.to_be_bytes());
            assert_eq!(&packet[12..], &key);
            assert_eq!(
                &packet[..4],
                &i32::try_from(12 + length)
                    .expect("small packet")
                    .to_be_bytes()
            );
            assert!(!format!("{parsed:?}").contains("[0, 1, 2, 3"));
        }
        for length in [0, 1, 3, 257] {
            let key = vec![0; length];
            assert_eq!(
                encode_cancel(1, &key),
                Err(ProtocolError::InvalidCancelKeyLength(length))
            );
            let mut body = Vec::from(1_i32.to_be_bytes());
            body.extend_from_slice(&key);
            assert_eq!(
                backend(b'K', &body),
                Err(ProtocolError::InvalidCancelKeyLength(length))
            );
        }
    }

    #[test]
    fn framing_waits_for_each_split_and_preserves_following_frames() {
        let first = framed(b'S', b"server_version\x0019.0\0");
        for split in 0..first.len() {
            assert_eq!(parse_frame(&first[..split], 1024), Ok(FrameParse::NeedMore));
        }
        let second = framed(b'Z', b"I");
        let mut combined = first.clone();
        combined.extend_from_slice(&second);
        let FrameParse::Complete { frame, consumed } =
            parse_frame(&combined, 1024).expect("valid frame")
        else {
            panic!("complete frame");
        };
        assert_eq!(consumed, first.len());
        assert_eq!(frame.body, b"server_version\x0019.0\0");
        assert!(std::ptr::eq(frame.body.as_ptr(), combined[5..].as_ptr()));
        let FrameParse::Complete { frame, consumed } =
            parse_frame(&combined[consumed..], 1024).expect("second frame")
        else {
            panic!("complete second frame");
        };
        assert_eq!(consumed, second.len());
        assert_eq!(
            parse_backend(frame),
            Ok(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        );
    }

    #[test]
    fn malformed_and_oversized_headers_fail_without_a_body() {
        for length in [i32::MIN, -1, 0, 3] {
            let mut header = vec![b'D'];
            header.extend_from_slice(&length.to_be_bytes());
            assert_eq!(
                parse_frame(&header, 1024),
                Err(ProtocolError::InvalidLength(length))
            );
        }
        let mut header = vec![b'D'];
        header.extend_from_slice(&i32::MAX.to_be_bytes());
        assert_eq!(
            parse_frame(&header, 1024),
            Err(ProtocolError::FrameTooLarge {
                length: usize::try_from(i32::MAX).expect("fits usize"),
                limit: 1024
            })
        );
        assert_eq!(parse_frame(&[], 3), Err(ProtocolError::InvalidFrameLimit));
        assert!(matches!(
            parse_frame(&framed(b'1', &[]), 4),
            Ok(FrameParse::Complete { consumed: 5, .. })
        ));
    }

    #[test]
    fn fixed_messages_and_ready_reject_extra_or_unknown_bytes() {
        for (value, status) in [
            (b'I', TransactionStatus::Idle),
            (b'T', TransactionStatus::InTransaction),
            (b'E', TransactionStatus::FailedTransaction),
        ] {
            assert_eq!(
                backend(b'Z', &[value]),
                Ok(BackendMessage::ReadyForQuery(status))
            );
            assert_eq!(
                backend(b'Z', &[value, 0]),
                Err(ProtocolError::TrailingBytes)
            );
        }
        assert_eq!(
            backend(b'Z', b"?"),
            Err(ProtocolError::InvalidTransactionStatus(b'?'))
        );
        assert_eq!(backend(b'Z', b""), Err(ProtocolError::UnexpectedEnd));
        for tag in *b"123nIs" {
            assert!(backend(tag, &[]).is_ok());
            assert_eq!(backend(tag, &[0]), Err(ProtocolError::TrailingBytes));
        }
        assert_eq!(
            backend(b'?', &[]),
            Err(ProtocolError::UnsupportedMessageTag(b'?'))
        );
    }

    #[test]
    fn string_messages_require_valid_utf8_exact_terminators_and_no_tail() {
        assert_eq!(
            backend(b'S', b"name\0value\0"),
            Ok(BackendMessage::ParameterStatus {
                name: "name",
                value: "value"
            })
        );
        for body in [b"name\0value".as_slice(), b"name".as_slice()] {
            assert_eq!(backend(b'S', body), Err(ProtocolError::MissingTerminator));
        }
        assert_eq!(
            backend(b'S', b"name\0value\0x"),
            Err(ProtocolError::TrailingBytes)
        );
        assert_eq!(
            backend(b'C', b"SELECT 1\0"),
            Ok(BackendMessage::CommandComplete("SELECT 1"))
        );
        assert_eq!(backend(b'C', &[255, 0]), Err(ProtocolError::InvalidUtf8));
    }

    #[test]
    fn sasl_mechanisms_have_an_additional_final_terminator() {
        let mut body = Vec::from(10_i32.to_be_bytes());
        body.extend_from_slice(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        let BackendMessage::Authentication(Authentication::Sasl(mechanisms)) =
            backend(b'R', &body).expect("valid SASL list")
        else {
            panic!("SASL list");
        };
        assert_eq!(
            mechanisms
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .expect("valid names"),
            ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]
        );
        body.pop();
        assert_eq!(backend(b'R', &body), Err(ProtocolError::MissingTerminator));
        body.extend_from_slice(b"\0extra");
        assert_eq!(backend(b'R', &body), Err(ProtocolError::TrailingBytes));
        assert_eq!(
            backend(b'R', &0_i32.to_be_bytes()),
            Ok(BackendMessage::Authentication(Authentication::Ok))
        );
        assert_eq!(
            backend(b'R', &[0, 0, 0, 0, 0]),
            Err(ProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn error_fields_allow_unknown_codes_but_validate_required_fields_and_duplicates() {
        let body = b"Mbad input\0C22000\0VERROR\0Slocalized severity\0xfuture field\0\0";
        let BackendMessage::ErrorResponse(error) = backend(b'E', body).expect("valid error") else {
            panic!("error response");
        };
        assert_eq!(error.message, "bad input");
        assert_eq!(error.sqlstate, "22000");
        assert_eq!(error.severity_nonlocalized, Some("ERROR"));
        let diagnostic = format!("{error:?}");
        assert!(diagnostic.contains("22000"));
        assert!(!diagnostic.contains("bad input"));
        assert!(!diagnostic.contains("future field"));
        assert_eq!(
            backend(b'E', b"SERROR\0C22000\0Mbad\0C22001\0\0"),
            Err(ProtocolError::DuplicateErrorField(b'C'))
        );
        assert_eq!(
            backend(b'E', b"SERROR\0C22000\0\0"),
            Err(ProtocolError::MissingErrorField(b'M'))
        );
        assert_eq!(
            backend(b'E', b"SERROR\0C22a00\0Mbad\0\0"),
            Err(ProtocolError::InvalidSqlState)
        );
        assert_eq!(
            backend(b'E', b"SERROR\0C22000\0Mbad\0\0x"),
            Err(ProtocolError::TrailingBytes)
        );
        assert!(backend(b'E', b"SERROR\0C22000\0Mbad\0").is_err());
    }

    #[test]
    fn data_rows_distinguish_null_empty_and_binary_values_without_offsets() {
        let mut body = Vec::from(3_u16.to_be_bytes());
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        body.extend_from_slice(&0_i32.to_be_bytes());
        body.extend_from_slice(&4_i32.to_be_bytes());
        body.extend_from_slice(&42_i32.to_be_bytes());
        let BackendMessage::DataRow(row) = backend(b'D', &body).expect("valid row") else {
            panic!("data row");
        };
        assert_eq!(row.len(), 3);
        let fields = row
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("valid fields");
        assert_eq!(
            fields,
            [
                None,
                Some([].as_slice()),
                Some(42_i32.to_be_bytes().as_slice())
            ]
        );
        assert!(std::ptr::eq(
            fields[2].expect("non-null").as_ptr(),
            body[14..].as_ptr()
        ));
        for end in 0..body.len() {
            assert!(
                backend(b'D', &body[..end]).is_err(),
                "truncated row at {end}"
            );
        }
        body.push(0);
        assert_eq!(backend(b'D', &body), Err(ProtocolError::TrailingBytes));
        assert_eq!(
            backend(b'D', &[0, 1, 255, 255, 255, 254]),
            Err(ProtocolError::InvalidLength(-2))
        );
    }

    #[test]
    fn scalar_row_parser_checks_the_complete_envelope() {
        let bodies: &[&[u8]] = &[
            &[0, 0],
            &[0, 1, 255, 255, 255, 255],
            &[0, 1, 0, 0, 0, 0],
            &[0, 1, 0, 0, 0, 4, 0, 0, 0, 42],
            &[0, 1, 0, 0, 0, 0, 9],
            &[0, 2, 0, 0, 0, 0, 255, 255, 255, 255],
            &[0, 2, 0, 0, 0, 0, 255, 255, 255, 254],
        ];
        for body in bodies {
            for end in 0..=body.len() {
                let body = &body[..end];
                let reference = backend(b'D', body).map(|message| match message {
                    BackendMessage::DataRow(row) => row.scalar_field(),
                    _ => unreachable!(),
                });
                assert_eq!(parse_scalar_data_row(body), reference);
            }
        }
    }

    #[test]
    fn description_counts_are_unsigned_and_oids_keep_all_bits() {
        let count = u16::MAX;
        let mut body = Vec::from(count.to_be_bytes());
        for _ in 0..count {
            body.extend_from_slice(&u32::MAX.to_be_bytes());
        }
        let BackendMessage::ParameterDescription(description) =
            backend(b't', &body).expect("unsigned count")
        else {
            panic!("parameter description");
        };
        assert_eq!(description.len(), usize::from(count));
        assert_eq!(description.iter().count(), usize::from(count));
        assert_eq!(description.iter().next_back(), Some(u32::MAX));
        assert_eq!(backend(b't', &[0, 0, 0]), Err(ProtocolError::TrailingBytes));
        body.pop();
        assert_eq!(backend(b't', &body), Err(ProtocolError::UnexpectedEnd));
    }

    #[test]
    fn row_descriptions_validate_every_field_and_format() {
        let mut body = Vec::from(1_u16.to_be_bytes());
        body.extend_from_slice(b"value\0");
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(&(-1_i16).to_be_bytes());
        body.extend_from_slice(&23_u32.to_be_bytes());
        body.extend_from_slice(&4_i16.to_be_bytes());
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        body.extend_from_slice(&1_i16.to_be_bytes());
        let BackendMessage::RowDescription(description) =
            backend(b'T', &body).expect("valid description")
        else {
            panic!("row description");
        };
        assert_eq!(
            description.iter().next(),
            Some(Ok(FieldDescription {
                name: "value",
                table_oid: u32::MAX,
                column_id: -1,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: Format::Binary
            }))
        );
        for end in 0..body.len() {
            assert!(backend(b'T', &body[..end]).is_err());
        }
        let last = body.last_mut().expect("format byte");
        *last = 2;
        assert_eq!(
            backend(b'T', &body),
            Err(ProtocolError::InvalidFormatCode(2))
        );
    }

    #[test]
    fn frame_debug_keeps_wire_payload_private() {
        let frame = |body| Frame { tag: b'K', body };
        assert_eq!(
            format!("{:?}", frame(b"abcdefgh")),
            format!("{:?}", frame(b"12345678")),
        );
    }

    #[test]
    fn backend_debug_keeps_business_data_in_message_views() {
        let data = b"first";
        let alternative = b"other";
        for (left, right) in [
            (
                BackendMessage::CopyData(data),
                BackendMessage::CopyData(alternative),
            ),
            (
                BackendMessage::ParameterStatus {
                    name: "custom",
                    value: "first",
                },
                BackendMessage::ParameterStatus {
                    name: "custom",
                    value: "other",
                },
            ),
            (
                BackendMessage::NotificationResponse {
                    process_id: 1,
                    channel: "a",
                    payload: "first",
                },
                BackendMessage::NotificationResponse {
                    process_id: 1,
                    channel: "b",
                    payload: "other",
                },
            ),
        ] {
            assert_eq!(format!("{left:?}"), format!("{right:?}"));
        }
    }

    #[test]
    fn negotiation_is_exposed_for_the_session_to_reject_without_downgrading() {
        let mut body = Vec::from(0x0003_0000_u32.to_be_bytes());
        body.extend_from_slice(&1_i32.to_be_bytes());
        body.extend_from_slice(b"_pq_.unsupported\0");
        let BackendMessage::NegotiateProtocolVersion(message) =
            backend(b'v', &body).expect("valid negotiation")
        else {
            panic!("negotiation message");
        };
        assert_eq!(message.protocol_version, 0x0003_0000);
        assert!(backend(b'v', &[255, 255, 255, 255, 0, 0, 0, 0]).is_err());
        assert_eq!(
            message.unrecognized_options.iter().next(),
            Some(Ok("_pq_.unsupported"))
        );
        body.push(0);
        assert_eq!(backend(b'v', &body), Err(ProtocolError::TrailingBytes));
        assert!(backend(b'v', &[0, 0, 0, 2, 255, 255, 255, 255]).is_err());
    }

    #[test]
    fn every_partition_of_a_small_frame_decodes_identically() {
        let packet = framed(b'Z', b"I");
        let complete = FrameParse::Complete {
            frame: Frame {
                tag: b'Z',
                body: b"I",
            },
            consumed: packet.len(),
        };
        for cuts in 0..(1 << (packet.len() - 1)) {
            let mut received = Vec::new();
            let mut start = 0;
            let ends = (1..packet.len())
                .filter(|end| cuts & (1 << (*end - 1)) != 0)
                .chain([packet.len()]);
            for end in ends {
                received.extend_from_slice(&packet[start..end]);
                let parsed = parse_frame(&received, 64).expect("valid partial frame");
                let expected = if end == packet.len() {
                    complete
                } else {
                    FrameParse::NeedMore
                };
                assert_eq!(parsed, expected, "cuts={cuts:b}, end={end}");
                start = end;
            }
        }
    }

    #[test]
    fn copy_responses_validate_formats_counts_and_trailing_bytes() {
        let body = [1, 0, 2, 0, 1, 0, 0];
        for tag in *b"GHW" {
            let response = match backend(tag, &body).expect("valid binary COPY metadata") {
                BackendMessage::CopyInResponse(response)
                | BackendMessage::CopyOutResponse(response)
                | BackendMessage::CopyBothResponse(response) => response,
                _ => panic!("COPY response"),
            };
            assert_eq!(response.format, Format::Binary);
            assert_eq!(response.len(), 2);
            assert_eq!(
                response.column_formats().collect::<Vec<_>>(),
                [Format::Binary, Format::Text]
            );
            for length in 0..body.len() {
                assert!(backend(tag, &body[..length]).is_err());
            }
            let mut trailing = body.to_vec();
            trailing.push(0);
            assert_eq!(backend(tag, &trailing), Err(ProtocolError::TrailingBytes));
        }
        assert!(backend(b'G', &[0, 0, 1, 0, 1]).is_err());
        assert_eq!(
            backend(b'H', &[2, 0, 0]),
            Err(ProtocolError::InvalidFormatCode(2))
        );
        assert_eq!(
            backend(b'H', &[1, 0, 1, 0, 2]),
            Err(ProtocolError::InvalidFormatCode(2))
        );
        let BackendMessage::CopyOutResponse(empty) =
            backend(b'H', &[0, 0, 0]).expect("empty metadata")
        else {
            panic!("COPY OUT");
        };
        assert!(empty.is_empty());
        assert_eq!(empty.column_formats().next(), None);
    }

    #[test]
    fn copy_data_is_opaque_and_copy_done_has_no_body() {
        let data = [0xff, 0, 0xf0];
        let packet = framed(b'd', &data);
        for length in 0..packet.len() {
            assert_eq!(
                parse_frame(&packet[..length], 64).expect("partial COPY frame"),
                FrameParse::NeedMore
            );
        }
        let FrameParse::Complete { frame, consumed } =
            parse_frame(&packet, 64).expect("complete COPY frame")
        else {
            panic!("complete frame");
        };
        assert_eq!(consumed, packet.len());
        assert_eq!(parse_backend(frame), Ok(BackendMessage::CopyData(&data)));
        assert_eq!(backend(b'd', &[]), Ok(BackendMessage::CopyData(&[])));
        assert_eq!(backend(b'c', &[]), Ok(BackendMessage::CopyDone));
        assert_eq!(backend(b'c', &[0]), Err(ProtocolError::TrailingBytes));
        assert_eq!(
            backend(b'f', b"failure\0"),
            Err(ProtocolError::UnsupportedMessageTag(b'f'))
        );
    }

    #[test]
    fn command_tags_preserve_transaction_identity_and_checked_counts() {
        for (tag, expected) in [
            ("BEGIN", CommandTag::Begin),
            ("COMMIT", CommandTag::Commit),
            ("ROLLBACK", CommandTag::Rollback),
            ("SAVEPOINT", CommandTag::Savepoint),
            ("RELEASE", CommandTag::Release),
            ("SELECT 12", CommandTag::Select(12)),
            ("UPDATE 0", CommandTag::Update(0)),
            ("DELETE 3", CommandTag::Delete(3)),
            ("MERGE 4", CommandTag::Merge(4)),
            ("MOVE 2", CommandTag::Move(2)),
            ("FETCH 7", CommandTag::Fetch(7)),
            ("COPY 9", CommandTag::Copy(9)),
            (
                "INSERT 0 18446744073709551615",
                CommandTag::Insert(u64::MAX),
            ),
            ("CREATE TABLE", CommandTag::Other("CREATE TABLE")),
            (
                "ROLLBACK TO SAVEPOINT s",
                CommandTag::Other("ROLLBACK TO SAVEPOINT s"),
            ),
        ] {
            assert_eq!(parse_command_tag(tag), Ok(expected));
        }
        for tag in [
            "",
            "SELECT",
            "SELECT -1",
            "SELECT +1",
            "SELECT 1 2",
            "COPY 18446744073709551616",
            "INSERT 0",
            "INSERT 1 1",
            "INSERT 4294967296 1",
        ] {
            assert!(parse_command_tag(tag).is_err(), "{tag}");
        }
    }

    #[test]
    fn command_counts_distinguish_malformed_fields_from_decimal_overflow() {
        assert_eq!(
            parse_command_tag("UPDATE 00000123"),
            Ok(CommandTag::Update(123))
        );
        for tag in [
            "SELECT ",
            "SELECT +9",
            "SELECT -0",
            "SELECT ９",
            "SELECT 184467440737095516160x",
            "SELECT +18446744073709551616",
        ] {
            assert_eq!(
                parse_command_tag(tag),
                Err(ProtocolError::InvalidMessage("invalid command tag count")),
                "{tag}"
            );
        }
        assert_eq!(
            parse_command_tag("COPY 18446744073709551616"),
            Err(ProtocolError::InvalidMessage(
                "command tag count exceeds u64"
            ))
        );
        assert_eq!(
            parse_command_tag("INSERT 0 18446744073709551616"),
            Err(ProtocolError::InvalidMessage(
                "command tag count exceeds u64"
            ))
        );
    }

    #[test]
    fn row_encoded_fields_exclude_the_count_and_preserve_raw_values() {
        let body = b"\0\x02\xff\xff\xff\xff\0\0\0\x03a\0b";
        let BackendMessage::DataRow(row) = backend(b'D', body).expect("valid row") else {
            panic!("data row");
        };
        assert_eq!(row.encoded_fields(), &body[2..]);
        assert_eq!(
            row.iter().collect::<Result<Vec<_>, _>>().expect("fields"),
            [None, Some(b"a\0b".as_slice())]
        );
    }
}
