use std::{
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};

pub use crate::transport::SendPolicy;
#[cfg(feature = "window-cache")]
use crate::transport::WindowSendCache;
use crate::{
    DatabaseError, Error,
    protocol::{
        self, Authentication, BackendMessage, ErrorResponse, ProtocolError, TransactionStatus,
    },
    transport::{Transport, TransportExt, WireOps, WireTransport},
};

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(0);
const MAX_STARTUP_MESSAGES: usize = 128;
const PIPELINE_TRANSACTION_CONFLICT: &str =
    "transaction control preceded later admitted pipeline members; discard the connection";
type NoticeHandler = Arc<dyn for<'notice> Fn(ErrorResponse<'notice>) + Send + Sync>;
/// TLS 已验证证书支持通道绑定时，启动流程在选用 SCRAM-PLUS 后才生成摘要。
type ChannelBindingProvider<Io> = fn(&Io) -> Result<Vec<u8>, Error>;

pub(crate) mod api;
mod cancel;
mod copy;
mod general;
mod listener;
mod pipeline;
mod portal;
mod socket_options;
mod transaction;
pub use cancel::CancelHandle;
pub use copy::{
    CopyAbort, CopyBatchCompletion, CopyBatchError, CopyBatchLimits, CopyChunk, CopyCompletion,
    CopyDataBuffer, CopyInfo, CopyInput, CopyOutput, CopyProtocol, CopyStreamLimits,
};
pub use general::{
    CloseItem, ClosePipelineError, CommandKind, PrepareItem, PreparePipelineError, PrepareRequest,
    PreparedStatement, PreparedStatementStorage, Query, QueryCompletion, QueryLimits, RowLease,
    StatementLimits, StatementPipelineLimits,
};
pub use listener::{Listener, Notification};
pub use pipeline::{
    AbandonPolicy, FrozenEncodedGroup, GroupPipelineError, GroupPipelineLimits,
    GroupPipelineProgress, GroupSyncCompletion, PipelineError, PipelineItem, PipelineLimits,
    PipelineRequest, PipelineResult, ProvisionalGroupConsumeEvent, ProvisionalGroupEvent,
    ProvisionalGroupLimits, ProvisionalWindowCompletion, ProvisionalWindowConsumeEvent,
    ProvisionalWindowControl, ProvisionalWindowError, ProvisionalWindowErrorOrigin,
    ProvisionalWindowEvent, ProvisionalWindowLimits, ReadyBatchEvent, ReadyBatchResult,
    VisitCompletion, VisitError, VisitLimits, WindowCompletion, WindowError, WindowLimits,
    WindowParameters, WindowRequest,
};
pub use portal::{Portal, PortalFetchCompletion, PortalFetchLimits};
pub use socket_options::{TcpNoDelay, TcpOptions};
#[cfg(target_os = "linux")]
pub use socket_options::{TcpOptionsExt, TcpReceiveBufferPolicy, TcpReceiveBufferSnapshot};
pub use transaction::{
    ControlCompletion, ControlKind, IsolationLevel, Transaction, TransactionAccess,
    TransactionDeferrability, TransactionEnd, TransactionOptions,
};

/// 协议消息和接收缓冲区的容量限制。
#[derive(Debug, Clone, Copy)]
pub struct WireLimits {
    /// 明文连接建连时预留的接收字节数，至少为 5。较大的合法帧按需扩容。
    /// TLS 优先借用已认证明文，跨块帧按帧长上限分配拼接空间。
    pub receive_capacity: usize,
    /// 帧长度包含四字节长度字段，不含消息标签。
    pub max_frame_len: usize,
    pub max_request_len: usize,
    /// 每次 SQL 请求或独立 Sync 成员累计接收的控制帧数，DataRow 与 CopyData 除外。恢复单独限制连续控制帧数；
    /// 启动阶段最多接收 128 条消息，包含认证、参数状态和 Ready。
    pub max_messages_per_request: usize,
}

impl WireLimits {
    /// 短查询使用的限额。明文连接初始预留 8 KiB 接收缓冲区，合法大帧可按需扩容。
    /// 帧上限为 65,535 字节加标签，请求上限为 64 KiB，每次请求最多接收 1,024 个控制帧。
    pub const fn short_queries() -> Self {
        Self {
            receive_capacity: 8 * 1024,
            max_frame_len: 64 * 1024 - 1,
            max_request_len: 64 * 1024,
            max_messages_per_request: 1024,
        }
    }
}

/// 建连前选定的认证策略，服务端必须满足该策略。
#[derive(Clone)]
pub enum AuthenticationPolicy {
    /// 允许已获信任的端点直接返回 AuthenticationOk。此方式不能验证服务端身份。
    AllowAuthenticationOk,
    /// 要求 SCRAM 认证。经过验证的 TLS 连接在服务端支持时优先使用通道绑定。
    ScramSha256 {
        password: String,
        max_iterations: u32,
    },
    /// 要求经过验证的 TLS 通道绑定，且服务端必须提供 SCRAM-PLUS。
    ScramSha256Plus {
        password: String,
        max_iterations: u32,
    },
}

/// 不随请求或连接变化的启动参数。配置克隆共享这些输入，只有构建器修改副本时才复制。
#[derive(Clone)]
struct StartupSettings {
    user: String,
    database: String,
    application_name: std::borrow::Cow<'static, str>,
    parameters: Vec<(String, String)>,
    authentication: AuthenticationPolicy,
}

impl StartupSettings {
    fn new(
        user: impl Into<String>,
        database: impl Into<String>,
        authentication: AuthenticationPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            user: user.into(),
            database: database.into(),
            authentication,
            application_name: std::borrow::Cow::Borrowed("compio-postgres"),
            parameters: Vec::new(),
        })
    }
}

/// 明文 TCP 连接配置。启用 TLS 后可用 `TcpConfig::tls` 验证服务端并进行 SCRAM 通道绑定。
///
/// 用户和数据库名必须非空，且各不超过标准 PostgreSQL 标识符上限 63 个 UTF-8 字节。
/// 使用自定义编译服务器时也按此上限检查。
#[derive(Clone)]
pub struct TcpConfig {
    endpoint: SocketAddr,
    settings: ConnectSettings,
    tcp_no_delay: TcpNoDelay,
    #[cfg(target_os = "linux")]
    tcp_receive_buffer_policy: TcpReceiveBufferPolicy,
}

#[derive(Clone)]
struct ConnectSettings {
    startup: Arc<StartupSettings>,
    notice_handler: Option<NoticeHandler>,
    limits: WireLimits,
    send_policy: SendPolicy,
}

// 建连成功后保留原端点及验证配置，供独立取消连接使用。
#[derive(Clone)]
enum Endpoint {
    Tcp(SocketAddr),
    #[cfg(feature = "tls")]
    Tls(SocketAddr, Arc<crate::tls::TlsConfig>),
    #[cfg(unix)]
    Unix(Arc<std::path::Path>),
}

impl TcpConfig {
    /// 使用指定的认证策略和套接字选项建立明文 TCP 连接。
    pub fn plaintext(
        endpoint: SocketAddr,
        user: impl Into<String>,
        database: impl Into<String>,
        authentication: AuthenticationPolicy,
        limits: WireLimits,
        tcp: TcpOptions,
    ) -> Self {
        Self {
            endpoint,
            settings: ConnectSettings::new(user, database, authentication, limits, tcp.send_policy),
            tcp_no_delay: tcp.no_delay,
            #[cfg(target_os = "linux")]
            tcp_receive_buffer_policy: tcp.receive_buffer,
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls(
        endpoint: SocketAddr,
        user: impl Into<String>,
        database: impl Into<String>,
        authentication: AuthenticationPolicy,
        limits: WireLimits,
        tls: crate::tls::TlsConfig,
        tcp: TcpOptions,
    ) -> SecureConfig {
        SecureConfig {
            tcp: Self::plaintext(endpoint, user, database, authentication, limits, tcp),
            tls: Arc::new(tls),
        }
    }

    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.settings.application_name(name);
        self
    }

    /// 在启动包中设置 `search_path` 等会话参数。打开套接字前检查参数名、重复项与包大小。核心字段和应用名使用专用配置入口。
    pub fn startup_parameter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.settings.startup_parameter(name, value);
        self
    }

    /// 在连接所属 worker 上同步处理服务器诊断消息（NoticeResponse）。
    /// 回调借用接收缓冲区，须及时返回。显式恢复期间只排空消息。
    /// 回调 panic 后连接不可复用。克隆的配置共享回调，可在不同 worker 上并发调用。
    pub fn notice_handler(
        mut self,
        handler: impl for<'notice> Fn(ErrorResponse<'notice>) + Send + Sync + 'static,
    ) -> Self {
        self.settings.notice_handler = Some(Arc::new(handler));
        self
    }

    /// 选择发送与消费缓冲响应的顺序。BeforeBufferedRead 先推进发送；
    /// CoalesceBuffered 可在缓冲区仍有完整响应时推迟发送后续 SQL，以排队时间换取合并发送的机会。
    pub fn send_policy(mut self, policy: SendPolicy) -> Self {
        self.settings.send_policy = policy;
        self
    }

    async fn connect_socket(&self) -> Result<socket_options::ConnectedTcp, Error> {
        socket_options::connect_tcp(
            self.endpoint,
            self.tcp_no_delay,
            #[cfg(target_os = "linux")]
            self.tcp_receive_buffer_policy,
        )
        .await
    }

    fn startup_packet(&self, tls: bool) -> Result<Vec<u8>, Error> {
        #[cfg(target_os = "linux")]
        self.tcp_receive_buffer_policy.validate()?;
        self.settings.startup_packet(tls)
    }
}

impl ConnectSettings {
    fn new(
        user: impl Into<String>,
        database: impl Into<String>,
        authentication: AuthenticationPolicy,
        limits: WireLimits,
        send_policy: SendPolicy,
    ) -> Self {
        Self {
            startup: StartupSettings::new(user, database, authentication),
            notice_handler: None,
            limits,
            send_policy,
        }
    }

    fn application_name(&mut self, name: impl Into<String>) {
        Arc::make_mut(&mut self.startup).application_name = std::borrow::Cow::Owned(name.into());
    }

    fn startup_parameter(&mut self, name: impl Into<String>, value: impl Into<String>) {
        Arc::make_mut(&mut self.startup)
            .parameters
            .push((name.into(), value.into()));
    }

    fn startup_packet(&self, tls: bool) -> Result<Vec<u8>, Error> {
        self.validate(tls)?;
        Ok(protocol::encode_startup_with_parameters(
            &self.startup.user,
            &self.startup.database,
            &self.startup.application_name,
            &self.startup.parameters,
            self.limits.max_request_len,
        )?)
    }

    fn validate(&self, tls: bool) -> Result<(), Error> {
        if self.startup.user.is_empty()
            || self.startup.database.is_empty()
            || self.limits.max_messages_per_request == 0
        {
            return Err(Error::InvalidInput(
                "user, database and a positive message bound are required",
            ));
        }
        if self.startup.user.len() > protocol::STANDARD_IDENTIFIER_BYTES
            || self.startup.database.len() > protocol::STANDARD_IDENTIFIER_BYTES
        {
            return Err(Error::InvalidInput(
                "startup user and database names must contain at most 63 UTF-8 bytes",
            ));
        }
        crate::transport::validate_buffers(
            self.limits.receive_capacity,
            self.limits.max_frame_len,
            self.limits.max_request_len,
        )?;
        match &self.startup.authentication {
            AuthenticationPolicy::ScramSha256 { max_iterations, .. }
            | AuthenticationPolicy::ScramSha256Plus { max_iterations, .. }
                if *max_iterations == 0 || *max_iterations > 100_000 =>
            {
                Err(Error::InvalidInput(
                    "SCRAM iteration limit must be within 1..=100000",
                ))
            }
            AuthenticationPolicy::ScramSha256Plus { .. } if !tls => {
                Err(Error::Unsupported("SCRAM-PLUS requires verified TLS"))
            }
            _ => Ok(()),
        }
    }
}

/// 通过绝对文件系统路径连接明文 Unix 域套接字。
///
/// 只使用指定的 Unix 域套接字。用户名、数据库名的限制与 [`TcpConfig`] 相同。
#[cfg(unix)]
#[derive(Clone)]
pub struct UnixConfig {
    path: Arc<std::path::Path>,
    settings: ConnectSettings,
}

#[cfg(unix)]
impl UnixConfig {
    pub fn plaintext(
        path: impl AsRef<std::path::Path>,
        user: impl Into<String>,
        database: impl Into<String>,
        authentication: AuthenticationPolicy,
        limits: WireLimits,
        send_policy: SendPolicy,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidInput(
                "a Unix connection requires an absolute filesystem socket path without NUL",
            ));
        }
        Ok(Self {
            path: Arc::from(path),
            settings: ConnectSettings::new(user, database, authentication, limits, send_policy),
        })
    }

    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.settings.application_name(name);
        self
    }

    /// 在启动包中设置会话参数。参见 [`TcpConfig::startup_parameter`]。
    pub fn startup_parameter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.settings.startup_parameter(name, value);
        self
    }

    /// 设置服务器诊断回调。参见 [`TcpConfig::notice_handler`]。
    pub fn notice_handler(
        mut self,
        handler: impl for<'notice> Fn(ErrorResponse<'notice>) + Send + Sync + 'static,
    ) -> Self {
        self.settings.notice_handler = Some(Arc::new(handler));
        self
    }

    /// 选择发送顺序，适用于原生和就绪通知两种 Unix 套接字传输。
    pub fn send_policy(mut self, policy: SendPolicy) -> Self {
        self.settings.send_policy = policy;
        self
    }
}

#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct SecureConfig {
    tcp: TcpConfig,
    tls: Arc<crate::tls::TlsConfig>,
}

#[cfg(feature = "tls")]
impl SecureConfig {
    /// 指定 TLS 连接启动包中的应用名。
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.tcp = self.tcp.application_name(name);
        self
    }

    /// 在启动包中设置会话参数。参见 [`TcpConfig::startup_parameter`]。
    pub fn startup_parameter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.tcp = self.tcp.startup_parameter(name, value);
        self
    }

    /// 设置服务器诊断回调。参见 [`TcpConfig::notice_handler`]。
    pub fn notice_handler(
        mut self,
        handler: impl for<'notice> Fn(ErrorResponse<'notice>) + Send + Sync + 'static,
    ) -> Self {
        self.tcp = self.tcp.notice_handler(handler);
        self
    }

    /// 选择发送与消费缓冲响应的顺序。只有 TLS 已接受数据并完成刷新后才可复用发送包。
    pub fn send_policy(mut self, policy: SendPolicy) -> Self {
        self.tcp = self.tcp.send_policy(policy);
        self
    }
}

#[derive(Debug)]
pub struct ServerInfo {
    pub version: String,
    pub process_id: i32,
    pub cancel_key_length: usize,
}

/// 连接池需要处理的协议状态。ProtocolIdle 表示协议空闲；不同租户之间的会话清理仍由应用决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseState {
    ProtocolIdle,
    NeedsRecovery,
    NeedsCopyCompletion,
    NeedsTransactionDecision,
    DiscardOnly,
}

/// 原始 ROLLBACK 须等 Ready 确认后才能报告事务结束，尚未交付的结束通知仍占用此槽。
/// 受事务守卫约束的流水线拒绝在结束命令后接纳其他成员。
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TransactionEndRetirement {
    None,
    RawRollbackReady,
    Taken,
}

/// 由当前调用方驱动的 worker 本地 PostgreSQL 19、协议 3.2 会话。
/// 提交、轮询、恢复和关闭均须在建立连接的 Compio runtime 上执行。
///
/// 丢弃或遗忘已轮询的请求后，连接仍持有进行中的操作；须显式恢复或丢弃连接才能继续。
pub struct Session<T: WireTransport> {
    transport: T::Io,
    id: u64,
    active: bool,
    transaction_status: TransactionStatus,
    info: ServerInfo,
    cancel_key: Option<Rc<[u8]>>,
    max_messages: usize,
    max_request_len: usize,
    endpoint: Endpoint,
    notice_handler: Option<NoticeHandler>,
    #[cfg(target_os = "linux")]
    tcp_receive_buffer_snapshot: Option<TcpReceiveBufferSnapshot>,
    remaining_boundaries: usize,
    transaction_lease: bool,
    transaction_end: Option<TransactionEnd>,
    transaction_end_retirement: TransactionEndRetirement,
    pending_transaction_control: Option<transaction::PendingTransactionControl>,
    extended: Option<Box<general::Extended>>,
    copy_state: copy::CopyWorkspace,
}

pub type TcpConnection = Session<Transport>;

/// 在建连时选定的明文 Unix 域套接字会话。
#[cfg(unix)]
pub type UnixConnection = Session<Transport<compio::net::UnixStream>>;

/// 使用非阻塞就绪通知 I/O 的 Linux 明文 TCP 会话。
#[cfg(target_os = "linux")]
pub type TcpReadinessConnection = Session<crate::readiness::ReadinessTransport>;

/// 使用非阻塞就绪通知 I/O 的 Linux 明文 Unix 域套接字会话。
#[cfg(target_os = "linux")]
pub type UnixReadinessConnection =
    Session<crate::readiness::ReadinessTransport<compio::net::UnixStream>>;

#[cfg(feature = "tls")]
pub type TlsConnection = Session<api::TlsTransport>;

impl Session<Transport> {
    pub async fn connect(config: TcpConfig) -> Result<Self, Error> {
        connect_on_worker(std::pin::pin!(Self::connect_tcp(config, Transport::new))).await
    }
}

#[cfg(unix)]
impl Session<Transport<compio::net::UnixStream>> {
    pub async fn connect(config: UnixConfig) -> Result<Self, Error> {
        connect_on_worker(std::pin::pin!(Self::connect_unix(config, Transport::new))).await
    }
}

#[cfg(target_os = "linux")]
impl Session<crate::readiness::ReadinessTransport> {
    /// 用非阻塞就绪通知 I/O 建立明文 TCP 连接。挂起后保留原来的就绪注册。
    pub async fn connect(config: TcpConfig) -> Result<Self, Error> {
        connect_on_worker(std::pin::pin!(Self::connect_tcp(
            config,
            crate::readiness::ReadinessTransport::new,
        )))
        .await
    }
}

#[cfg(target_os = "linux")]
impl Session<crate::readiness::ReadinessTransport<compio::net::UnixStream>> {
    pub async fn connect(config: UnixConfig) -> Result<Self, Error> {
        connect_on_worker(std::pin::pin!(Self::connect_unix(
            config,
            crate::readiness::ReadinessTransport::new,
        )))
        .await
    }
}

impl<T: WireTransport> Session<T> {
    async fn connect_tcp(
        config: TcpConfig,
        make_transport: impl FnOnce(compio::net::TcpStream, usize, usize, usize) -> Result<T::Io, Error>,
    ) -> Result<Self, Error> {
        let startup = config.startup_packet(false)?;
        let id = allocate_connection_id()?;
        let socket = config.connect_socket().await?;
        let limits = config.settings.limits;
        let mut transport = make_transport(
            socket.stream,
            limits.receive_capacity,
            limits.max_frame_len,
            limits.max_request_len,
        )?;
        transport.set_send_policy(config.settings.send_policy)?;
        let (mut connection, settings) = Self::starting(
            transport,
            Endpoint::Tcp(config.endpoint),
            config.settings,
            id,
        );
        #[cfg(target_os = "linux")]
        {
            connection.tcp_receive_buffer_snapshot = socket.receive_buffer_snapshot;
        }
        connection.transport.send(startup).await?;
        connection.startup(&settings.authentication, None).await?;
        Ok(connection)
    }
    #[cfg(unix)]
    async fn connect_unix(
        config: UnixConfig,
        make_transport: impl FnOnce(
            compio::net::UnixStream,
            usize,
            usize,
            usize,
        ) -> Result<T::Io, Error>,
    ) -> Result<Self, Error> {
        let startup = config.settings.startup_packet(false)?;
        let id = allocate_connection_id()?;
        let socket = compio::net::UnixStream::connect(&config.path).await?;
        let limits = config.settings.limits;
        let mut transport = make_transport(
            socket,
            limits.receive_capacity,
            limits.max_frame_len,
            limits.max_request_len,
        )?;
        transport.set_send_policy(config.settings.send_policy)?;
        let (mut connection, settings) =
            Self::starting(transport, Endpoint::Unix(config.path), config.settings, id);
        connection.transport.send(startup).await?;
        connection.startup(&settings.authentication, None).await?;
        Ok(connection)
    }
}

#[cfg(feature = "tls")]
impl Session<api::TlsTransport> {
    pub async fn connect(config: SecureConfig) -> Result<Self, Error> {
        connect_on_worker(std::pin::pin!(Self::connect_inner(config))).await
    }

    async fn connect_inner(config: SecureConfig) -> Result<Self, Error> {
        let SecureConfig { tcp: config, tls } = config;
        let startup = config.startup_packet(true)?;
        let id = allocate_connection_id()?;
        let socket = config.connect_socket().await?;
        let stream = crate::tls::connect(socket.stream, &tls).await?;
        let binding_available = stream.info().channel_binding_available;
        let limits = config.settings.limits;
        let mut transport = crate::buffered::BufferedTransport::new(
            stream,
            limits.receive_capacity,
            limits.max_frame_len,
            limits.max_request_len,
        )?;
        transport.set_send_policy(config.settings.send_policy)?;
        let (mut connection, settings) = Self::starting(
            transport,
            Endpoint::Tls(config.endpoint, tls),
            config.settings,
            id,
        );
        #[cfg(target_os = "linux")]
        {
            connection.tcp_receive_buffer_snapshot = socket.receive_buffer_snapshot;
        }
        connection.transport.send(startup).await?;
        connection
            .startup(
                &settings.authentication,
                binding_available.then_some(|transport| transport.stream().channel_binding()),
            )
            .await?;
        Ok(connection)
    }

    pub fn tls_info(&self) -> &crate::tls::TlsInfo {
        self.transport.stream().info()
    }
}

impl<T: WireTransport> Session<T> {
    #[cfg(test)]
    fn from_transport(
        transport: T::Io,
        config: TcpConfig,
        id: u64,
    ) -> (Self, Arc<StartupSettings>) {
        Self::starting(
            transport,
            Endpoint::Tcp(config.endpoint),
            config.settings,
            id,
        )
    }

    // 将已验证端点和通知回调移交给会话。认证策略只交给本次握手，完成后释放凭据。
    fn starting(
        transport: T::Io,
        endpoint: Endpoint,
        settings: ConnectSettings,
        id: u64,
    ) -> (Self, Arc<StartupSettings>) {
        let session = Self {
            transport,
            id,
            active: true,
            transaction_status: TransactionStatus::Idle,
            info: ServerInfo {
                version: String::new(),
                process_id: 0,
                cancel_key_length: 0,
            },
            cancel_key: None,
            max_messages: settings.limits.max_messages_per_request,
            max_request_len: settings.limits.max_request_len,
            endpoint,
            notice_handler: settings.notice_handler,
            #[cfg(target_os = "linux")]
            tcp_receive_buffer_snapshot: None,
            remaining_boundaries: 1,
            transaction_lease: false,
            transaction_end: None,
            transaction_end_retirement: TransactionEndRetirement::None,
            pending_transaction_control: None,
            extended: None,
            copy_state: copy::CopyWorkspace::default(),
        };
        (session, settings.startup)
    }
}

impl<T: WireTransport> Session<T> {
    /// 返回当前发送与消费缓冲响应的顺序。
    pub fn send_policy(&self) -> SendPolicy {
        self.transport.send_policy()
    }

    /// 只在会话和发送端空闲时更改发送顺序。此操作只更新配置。
    pub fn set_send_policy(&mut self, policy: SendPolicy) -> Result<(), Error> {
        self.check_idle()?;
        self.transport.set_send_policy(policy)
    }

    /// 返回空闲发送窗口缓冲区的保留策略。
    #[cfg(feature = "window-cache")]
    pub fn window_send_cache(&self) -> WindowSendCache {
        self.transport.window_send_cache()
    }

    /// 只在会话和发送端空闲时修改策略。新策略可立即释放空闲缓存，无需执行 I/O。
    #[cfg(feature = "window-cache")]
    pub fn set_window_send_cache(&mut self, policy: WindowSendCache) -> Result<(), Error> {
        self.check_idle()?;
        self.transport.set_window_send_cache(policy)
    }

    /// 释放已完成发送包和空闲窗口的全部缓冲区，返回释放的容量（字节）。在途发送继续持有原始缓冲区。
    pub fn trim_send_buffer(&mut self) -> Result<usize, Error> {
        self.check_idle()?;
        self.transport.trim_send_buffers()
    }
    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    pub fn transaction_status(&self) -> TransactionStatus {
        self.transaction_status
    }

    /// 当前会话能否接纳另一项受支持的请求。连接池还须检查事务和会话状态。
    pub fn is_usable(&self) -> bool {
        !self.active
            && self.remaining_boundaries == 0
            && !self.transaction_lease
            && !self.transport.is_broken()
            && self.transaction_status != TransactionStatus::FailedTransaction
    }

    /// 根据协议进度和待交付的事务结束通知判断连接能否复用。只读取本地状态。
    pub fn reuse_state(&self) -> ReuseState {
        if self.transport.is_broken()
            || self.extended.as_ref().is_some_and(|state| {
                state.callback_aborted() || state.provisional_window_requires_discard()
            })
        {
            return ReuseState::DiscardOnly;
        }
        if self.active || self.remaining_boundaries != 0 {
            if self
                .extended
                .as_ref()
                .is_some_and(|state| state.query_cancel_requested())
            {
                return ReuseState::DiscardOnly;
            }
            if let Some(copy) = self.copy_state.as_ref() {
                return if copy.can_finish_abandoned() {
                    ReuseState::NeedsCopyCompletion
                } else {
                    ReuseState::DiscardOnly
                };
            }
            return if self.pending_transaction_control.is_some()
                || self
                    .extended
                    .as_ref()
                    .is_some_and(|state| state.work_kind.is_some())
            {
                ReuseState::NeedsRecovery
            } else {
                ReuseState::DiscardOnly
            };
        }
        if self.transaction_lease
            || self.transaction_end.is_some()
            || self.transaction_status != TransactionStatus::Idle
        {
            return ReuseState::NeedsTransactionDecision;
        }
        ReuseState::ProtocolIdle
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 读取连接当前的发送和缓存响应交付顺序。
    pub fn send_policy(&self) -> SendPolicy {
        self.session().send_policy()
    }

    /// 在 Ready 且本地发送完成后调整发送顺序。
    /// 失败事务中也可调整，事务仍保持原状态。
    /// 此配置属于连接，跨 COMMIT、ROLLBACK 及连接池租借生效，必要时应显式恢复。
    pub fn set_send_policy(&mut self, policy: SendPolicy) -> Result<(), Error> {
        let session = self.session_mut();
        session.check_transaction_access(true)?;
        session.transport.set_send_policy(policy)
    }

    /// 释放空闲发送缓冲，保留当前事务。
    /// 仍有协议请求、本地发送或 TLS 刷新时返回 Busy。
    pub fn trim_send_buffer(&mut self) -> Result<usize, Error> {
        let session = self.session_mut();
        session.check_transaction_access(true)?;
        session.transport.trim_send_buffers()
    }

    /// 读取连接对空闲窗口缓冲的保留策略。
    #[cfg(feature = "window-cache")]
    pub fn window_send_cache(&self) -> WindowSendCache {
        self.session().window_send_cache()
    }

    /// 在 Ready 且本地发送完成后调整窗口缓冲保留策略。
    /// 失败事务中也可调整。
    /// 配置属于连接，跨事务和池租借生效，必要时应显式恢复。
    #[cfg(feature = "window-cache")]
    pub fn set_window_send_cache(&mut self, policy: WindowSendCache) -> Result<(), Error> {
        let session = self.session_mut();
        session.check_transaction_access(true)?;
        session.transport.set_window_send_cache(policy)
    }

    pub fn transaction_status(&self) -> TransactionStatus {
        self.session().transaction_status()
    }

    /// 查看协议恢复义务及事务状态，提交或回滚仍由事务守卫驱动。
    pub fn reuse_state(&self) -> ReuseState {
        self.session().reuse_state()
    }
}

impl<T: WireTransport> Session<T> {
    /// 放弃连接。Compio 保留在途操作的缓冲区直到操作结束；调用方不会收到回滚确认。
    pub fn discard(mut self) {
        self.transport.break_connection();
    }

    /// 等待本地套接字引用退出。此方法消耗会话，不发送 PostgreSQL Terminate，也不等待服务端确认事务回滚；
    /// 在错误的 runtime 上调用同样会消耗会话。
    pub async fn close_local(self) -> Result<(), Error> {
        let owner = self.transport.owner_waker().cloned();
        poll_on_worker(std::pin::pin!(self.close_local_on_owner()), || {
            crate::transport::IoOwner::check_waker(owner.as_ref())
        })
        .await
    }

    async fn close_local_on_owner(mut self) -> Result<(), Error> {
        self.transport.break_connection();
        self.transport.close().await
    }

    /// 在协议空闲时发送 PostgreSQL Terminate，并在所属 runtime 关闭本地套接字。
    /// 此方法消耗会话，包括发送失败的情况。PostgreSQL 不回复终止确认。
    pub async fn terminate(mut self) -> Result<(), Error> {
        let owner = self.transport.owner_waker().cloned();
        let check_owner = || crate::transport::IoOwner::check_waker(owner.as_ref());
        check_owner()?;
        let delivery = match self.reuse_state() {
            ReuseState::ProtocolIdle => {
                match self
                    .transport
                    .take_send_buffer()
                    .and_then(|buffer| crate::frontend::terminate(buffer, self.max_request_len))
                {
                    Ok(packet) => {
                        poll_on_worker(std::pin::pin!(self.transport.send(packet)), &check_owner)
                            .await
                    }
                    Err(error) => Err(error),
                }
            }
            ReuseState::DiscardOnly => Err(Error::Broken),
            _ => Err(Error::Busy),
        };
        let retirement =
            poll_on_worker(std::pin::pin!(self.close_local_on_owner()), check_owner).await;
        match (delivery, retirement) {
            (Err(primary), Err(cleanup)) => Err(Error::Cleanup {
                primary: Box::new(primary),
                cleanup: Box::new(cleanup),
            }),
            (delivery, retirement) => delivery.and(retirement),
        }
    }

    fn check_idle(&self) -> Result<(), Error> {
        self.check_inactive()?;
        if self.transaction_lease {
            return Err(Error::Busy);
        }
        if self.transaction_status == TransactionStatus::FailedTransaction {
            return Err(Error::Unsupported(
                "the transaction is failed; explicitly roll it back before issuing business queries",
            ));
        }
        Ok(())
    }

    fn check_idle_access(&self, in_transaction: bool) -> Result<(), Error> {
        self.check_idle_state(in_transaction)?;
        self.check_runtime_owner()
    }

    fn check_idle_state(&self, in_transaction: bool) -> Result<(), Error> {
        if in_transaction {
            self.check_transaction_access(false)
        } else {
            self.check_idle()
        }
    }

    fn check_inactive(&self) -> Result<(), Error> {
        if self.transport.is_broken() {
            return Err(Error::Broken);
        }
        if self.active
            || self.remaining_boundaries != 0
            || self.pending_transaction_control.is_some()
        {
            return Err(Error::Busy);
        }
        Ok(())
    }

    fn check_runtime_owner(&self) -> Result<(), Error> {
        crate::transport::IoOwner::check_waker(self.transport.owner_waker())
    }

    async fn startup(
        &mut self,
        policy: &AuthenticationPolicy,
        channel_binding: Option<ChannelBindingProvider<T::Io>>,
    ) -> Result<(), Error> {
        enum ScramState {
            Initial,
            Continue(ScramSha256),
            Final(ScramSha256),
            Verified,
        }
        let mut scram_state = ScramState::Initial;
        let mut authenticated = false;
        let mut encoding_valid = false;
        for _ in 0..MAX_STARTUP_MESSAGES {
            self.transport.receive_frame().await?;
            let message = protocol::parse_backend(self.transport.frame()?)?;
            let mut reply = None;
            let mut ready = false;
            match message {
                BackendMessage::Authentication(authentication) if !authenticated => {
                    match authentication {
                        Authentication::Ok => match (policy, &scram_state) {
                            (AuthenticationPolicy::AllowAuthenticationOk, ScramState::Initial)
                            | (
                                AuthenticationPolicy::ScramSha256 { .. }
                                | AuthenticationPolicy::ScramSha256Plus { .. },
                                ScramState::Verified,
                            ) => authenticated = true,
                            _ => {
                                return Err(Error::Unsupported(
                                    "AuthenticationOk did not satisfy the selected authentication policy",
                                ));
                            }
                        },
                        Authentication::Sasl(mechanisms)
                            if matches!(scram_state, ScramState::Initial) =>
                        {
                            let (password, require_plus) = match policy {
                                AuthenticationPolicy::ScramSha256 { password, .. } => {
                                    (password, false)
                                }
                                AuthenticationPolicy::ScramSha256Plus { password, .. } => {
                                    (password, true)
                                }
                                _ => {
                                    return Err(Error::Unsupported(
                                        "the endpoint requires SCRAM authentication",
                                    ));
                                }
                            };
                            let mut plain = false;
                            let mut plus = false;
                            for mechanism in mechanisms.iter() {
                                match mechanism? {
                                    "SCRAM-SHA-256" => plain = true,
                                    "SCRAM-SHA-256-PLUS" => plus = true,
                                    _ => {}
                                }
                            }
                            let use_plus = plus && channel_binding.is_some();
                            if require_plus && !use_plus {
                                return Err(Error::Unsupported(
                                    "SCRAM-PLUS requires verified TLS binding and a server PLUS offer",
                                ));
                            }
                            if !use_plus && !plain {
                                return Err(Error::Unsupported(
                                    "the endpoint did not offer SCRAM-SHA-256",
                                ));
                            }
                            let binding = match (use_plus, channel_binding) {
                                (true, Some(binding)) => {
                                    ChannelBinding::tls_server_end_point(binding(&self.transport)?)
                                }
                                (false, Some(_)) => ChannelBinding::unrequested(),
                                _ => ChannelBinding::unsupported(),
                            };
                            let scram = ScramSha256::new(password.as_bytes(), binding);
                            reply = Some(sasl_initial(
                                scram.message(),
                                use_plus,
                                self.max_request_len,
                            )?);
                            scram_state = ScramState::Continue(scram);
                        }
                        Authentication::SaslContinue(message) => {
                            let max_iterations = match policy {
                                AuthenticationPolicy::ScramSha256 { max_iterations, .. }
                                | AuthenticationPolicy::ScramSha256Plus {
                                    max_iterations, ..
                                } => *max_iterations,
                                _ => {
                                    return Err(Error::Unsupported(
                                        "unexpected SCRAM continuation",
                                    ));
                                }
                            };
                            check_iterations(message, max_iterations)?;
                            let ScramState::Continue(mut scram) = scram_state else {
                                return Err(protocol_error(
                                    "SCRAM continuation arrived out of order",
                                ));
                            };
                            scram.update(message).map_err(Error::Authentication)?;
                            reply = Some(sasl_response(scram.message(), self.max_request_len)?);
                            scram_state = ScramState::Final(scram);
                        }
                        Authentication::SaslFinal(message) => {
                            let ScramState::Final(mut scram) = scram_state else {
                                return Err(protocol_error(
                                    "SCRAM final message arrived out of order",
                                ));
                            };
                            scram.finish(message).map_err(Error::Authentication)?;
                            scram_state = ScramState::Verified;
                        }
                        _ => {
                            return Err(Error::Unsupported(
                                "the requested authentication method or order is not supported",
                            ));
                        }
                    }
                }
                BackendMessage::ParameterStatus { name, value } if authenticated => match name {
                    "server_version" => {
                        validate_version(value)?;
                        self.info.version = value.to_owned();
                    }
                    "client_encoding" => {
                        if value != "UTF8" {
                            return Err(Error::Unsupported("client_encoding must remain UTF8"));
                        }
                        encoding_valid = true;
                    }
                    _ => {}
                },
                BackendMessage::BackendKeyData(key)
                    if authenticated && self.cancel_key.is_none() =>
                {
                    self.info.process_id = key.process_id;
                    self.info.cancel_key_length = key.secret_key.len();
                    self.cancel_key = Some(Rc::from(key.secret_key));
                }
                BackendMessage::ReadyForQuery(TransactionStatus::Idle)
                    if authenticated
                        && self.cancel_key.is_some()
                        && encoding_valid
                        && !self.info.version.is_empty() =>
                {
                    ready = true
                }
                BackendMessage::NoticeResponse(notice) => {
                    observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                }
                BackendMessage::ErrorResponse(error) => {
                    return Err(Error::Database(owned_error(error)));
                }
                BackendMessage::NegotiateProtocolVersion(_) => {
                    return Err(Error::Unsupported(
                        "protocol negotiation or downgrade is not allowed",
                    ));
                }
                _ => {
                    return Err(protocol_error(
                        "unexpected message during PostgreSQL startup",
                    ));
                }
            }
            self.transport.consume_frame()?;
            if let Some(reply) = reply {
                self.transport.send(reply).await?;
            }
            if ready {
                self.active = false;
                self.remaining_boundaries = 0;
                return Ok(());
            }
        }
        Err(Error::Limit("startup exceeded its 128-message limit"))
    }

    fn note_ready(&mut self, status: TransactionStatus) -> Result<(), Error> {
        if self.remaining_boundaries == 0 {
            return Err(protocol_error("ReadyForQuery has no admitted boundary"));
        }
        self.remaining_boundaries -= 1;
        self.transaction_status = status;
        if self.transaction_end_retirement == TransactionEndRetirement::RawRollbackReady {
            self.resolve_raw_rollback(status);
        }
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn resolve_raw_rollback(&mut self, status: TransactionStatus) {
        self.transaction_end_retirement = TransactionEndRetirement::None;
        if status == TransactionStatus::Idle {
            self.transaction_end = Some(TransactionEnd::RolledBack);
        }
    }

    /// 已确认的原始 COMMIT 可直接记录。
    /// ROLLBACK 和 ROLLBACK TO 使用相同标签，要等 Ready 返回 Idle 才能确认事务结束；
    /// 类型化控制方法保留保存点或续接事务的语义。
    #[inline(always)]
    fn record_query_transaction_end(&mut self, command: CommandKind) -> Result<(), Error> {
        if matches!(
            command,
            CommandKind::DeallocateAll | CommandKind::DiscardAll
        ) {
            self.note_server_statement_reset()?;
        }
        if !self.transaction_lease
            || !matches!(command, CommandKind::Commit | CommandKind::Rollback)
        {
            return Ok(());
        }
        self.record_guarded_transaction_end(command)
    }

    /// 保留已确认的事务结束事实；后继成员已接纳时，连接不能继续按原事务语义处理。
    #[inline]
    fn record_pipeline_transaction_end(&mut self, command: CommandKind) -> Result<(), Error> {
        self.record_query_transaction_end(command)?;
        if self.transaction_lease
            && self.remaining_boundaries > 1
            && matches!(command, CommandKind::Commit | CommandKind::Rollback)
        {
            self.transport.break_connection();
            return Err(Error::Unsupported(PIPELINE_TRANSACTION_CONFLICT));
        }
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn record_guarded_transaction_end(&mut self, command: CommandKind) -> Result<(), Error> {
        if self.pending_transaction_control.is_some() {
            return Ok(());
        }
        let end = match command {
            CommandKind::Commit => Some(TransactionEnd::Committed),
            CommandKind::Rollback => None,
            _ => return Ok(()),
        };
        if self.transaction_end.is_some() {
            return Err(protocol_error(
                "a previous transaction end is still undelivered",
            ));
        }
        if let Some(end) = end {
            self.transaction_end = Some(end);
        } else {
            self.transaction_end_retirement = TransactionEndRetirement::RawRollbackReady;
        }
        Ok(())
    }
}

// 建连、独立取消和关闭的每次轮询都须属于原 worker。由调用方固定 future，守卫只保留借用。
fn poll_on_worker<T>(
    mut operation: std::pin::Pin<&mut impl Future<Output = Result<T, Error>>>,
    check: impl Fn() -> Result<(), Error>,
) -> impl Future<Output = Result<T, Error>> {
    std::future::poll_fn(move |cx| {
        check()?;
        operation.as_mut().poll(cx)
    })
}

async fn connect_on_worker<T>(
    mut operation: std::pin::Pin<&mut impl Future<Output = Result<T, Error>>>,
) -> Result<T, Error> {
    let owner = compio::runtime::Runtime::try_with_current(compio::runtime::Runtime::waker)
        .map_err(|_| Error::InvalidInput("connect must run inside the owning Compio runtime"))?;
    let mut suspended = false;
    std::future::poll_fn(|cx| {
        if suspended {
            crate::transport::IoOwner::check_waker(Some(&owner))?;
        }
        let result = operation.as_mut().poll(cx);
        suspended = result.is_pending();
        result
    })
    .await
}

fn protocol_error(message: &'static str) -> Error {
    Error::Protocol(ProtocolError::InvalidMessage(message))
}

#[must_use]
struct NoticeDelivery(std::thread::Result<()>);

#[derive(Clone, Copy, PartialEq, Eq)]
enum NoticePolicy {
    Deliver,
    Drain,
}

#[cold]
fn observe_notice(notice: ErrorResponse<'_>, handler: Option<&NoticeHandler>) -> NoticeDelivery {
    NoticeDelivery(handler.map_or(Ok(()), |handler| {
        catch_unwind(AssertUnwindSafe(|| handler(notice)))
    }))
}

impl NoticeDelivery {
    // 通知借用帧到回调结束；此后才可独占传输，标记连接并继续展开原 panic。
    fn finish(self, transport: &mut impl WireOps) {
        if let Err(payload) = self.0 {
            transport.break_connection();
            resume_unwind(payload);
        }
    }
}

fn allocate_connection_id() -> Result<u64, Error> {
    NEXT_CONNECTION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map(|previous| previous + 1)
        .map_err(|_| Error::Limit("connection identity space is exhausted"))
}

fn validate_version(version: &str) -> Result<(), Error> {
    let major = version
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .unwrap_or("");
    if major != "19" {
        return Err(Error::Unsupported(
            "only PostgreSQL major version 19 is accepted",
        ));
    }
    Ok(())
}

fn validate_parameter(name: &str, value: &str) -> Result<(), Error> {
    match name {
        "client_encoding" if value != "UTF8" => {
            Err(Error::Unsupported("client_encoding must remain UTF8"))
        }
        "server_version" => validate_version(value),
        _ => Ok(()),
    }
}

fn is_fatal(error: ErrorResponse<'_>) -> bool {
    matches!(
        error.severity_nonlocalized.unwrap_or(error.severity),
        "FATAL" | "PANIC"
    )
}

fn owned_error(error: ErrorResponse<'_>) -> DatabaseError {
    DatabaseError::from_response(error)
}

const DIAGNOSTIC_BUDGET: Error =
    Error::Limit("the batch exceeded its retained error storage limit");

fn owned_error_bounded(
    error: ErrorResponse<'_>,
    remaining: &mut usize,
) -> Result<DatabaseError, Error> {
    let fields_len =
        DatabaseError::fields_len_within(error, *remaining).ok_or(DIAGNOSTIC_BUDGET)?;
    retain_diagnostic(error, fields_len, remaining)
}

fn retain_diagnostic(
    error: ErrorResponse<'_>,
    fields_len: usize,
    remaining: &mut usize,
) -> Result<DatabaseError, Error> {
    let needed = DatabaseError::storage_size(fields_len)?;
    *remaining = remaining.checked_sub(needed).ok_or(DIAGNOSTIC_BUDGET)?;
    Ok(DatabaseError::from_response(error))
}

fn terminal_database_error(error: ErrorResponse<'_>, limit: Option<usize>) -> Error {
    match limit {
        Some(mut remaining) => match owned_error_bounded(error, &mut remaining) {
            Ok(error) => Error::Database(error),
            Err(error) => error,
        },
        None => Error::Database(owned_error(error)),
    }
}

fn check_iterations(message: &[u8], maximum: u32) -> Result<(), Error> {
    let text =
        std::str::from_utf8(message).map_err(|_| protocol_error("SCRAM challenge is not UTF8"))?;
    let mut iterations = None;
    for attribute in text.split(',') {
        if let Some(value) = attribute.strip_prefix("i=") {
            if iterations.is_some() {
                return Err(protocol_error("duplicate SCRAM iteration count"));
            }
            // SCRAM 的正整数须从 1 至 9 开始，拒绝正号和前导零。
            if !matches!(value.as_bytes().first(), Some(b'1'..=b'9')) {
                return Err(protocol_error("invalid SCRAM iteration count"));
            }
            iterations = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| protocol_error("invalid SCRAM iteration count"))?,
            );
        }
    }
    match iterations {
        Some(value) if value > 0 && value <= maximum => Ok(()),
        _ => Err(Error::Limit(
            "SCRAM challenge exceeds the selected iteration bound",
        )),
    }
}

fn sasl_initial(message: &[u8], plus: bool, max_request_len: usize) -> Result<Vec<u8>, Error> {
    let mechanism: &[u8] = if plus {
        b"SCRAM-SHA-256-PLUS\0"
    } else {
        b"SCRAM-SHA-256\0"
    };
    let body_length = mechanism
        .len()
        .checked_add(4)
        .and_then(|len| len.checked_add(message.len()))
        .ok_or(Error::Limit("SCRAM message length overflow"))?;
    let mut output = password_header(body_length, max_request_len)?;
    output.extend_from_slice(mechanism);
    output.extend_from_slice(
        &i32::try_from(message.len())
            .map_err(|_| Error::Limit("SCRAM message is too large"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(message);
    Ok(output)
}

fn sasl_response(message: &[u8], max_request_len: usize) -> Result<Vec<u8>, Error> {
    let mut output = password_header(message.len(), max_request_len)?;
    output.extend_from_slice(message);
    Ok(output)
}

fn password_header(body_length: usize, max_request_len: usize) -> Result<Vec<u8>, Error> {
    let length = body_length
        .checked_add(4)
        .ok_or(Error::Limit("SCRAM message length overflow"))?;
    let wire_length =
        i32::try_from(length).map_err(|_| Error::Limit("SCRAM message is too large"))?;
    let packet_length = length
        .checked_add(1)
        .ok_or(Error::Limit("SCRAM message length overflow"))?;
    if packet_length > max_request_len {
        return Err(Error::Limit(
            "SCRAM message exceeds its configured request limit",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(packet_length)
        .map_err(|_| Error::Limit("cannot allocate the authentication message"))?;
    output.push(b'p');
    output.extend_from_slice(&wire_length.to_be_bytes());
    Ok(output)
}

#[cfg(target_os = "linux")]
/// 读取 Linux TCP 会话在建连时记录的内核套接字选项。
pub trait TcpSessionExt {
    /// 显式设置接收缓冲区后返回内核实际值。由系统管理时返回 None，读取快照不执行 I/O。
    fn tcp_receive_buffer_snapshot(&self) -> Option<TcpReceiveBufferSnapshot>;
}

#[cfg(target_os = "linux")]
impl TcpSessionExt for TcpConnection {
    fn tcp_receive_buffer_snapshot(&self) -> Option<TcpReceiveBufferSnapshot> {
        self.tcp_receive_buffer_snapshot
    }
}

#[cfg(target_os = "linux")]
impl TcpSessionExt for TcpReadinessConnection {
    fn tcp_receive_buffer_snapshot(&self) -> Option<TcpReceiveBufferSnapshot> {
        self.tcp_receive_buffer_snapshot
    }
}

#[cfg(all(target_os = "linux", feature = "tls"))]
impl TcpSessionExt for TlsConnection {
    fn tcp_receive_buffer_snapshot(&self) -> Option<TcpReceiveBufferSnapshot> {
        self.tcp_receive_buffer_snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_startup_settings_detach_only_on_mutation() {
        let original = TcpConfig::plaintext(
            "127.0.0.1:5432".parse().unwrap(),
            "user",
            "database",
            AuthenticationPolicy::AllowAuthenticationOk,
            WireLimits::short_queries(),
            socket_options::TEST_TCP_OPTIONS,
        )
        .startup_parameter("search_path", "public");
        let clone = original.clone();
        assert!(Arc::ptr_eq(
            &original.settings.startup,
            &clone.settings.startup
        ));
        let changed = clone
            .application_name("web")
            .startup_parameter("timezone", "UTC");
        assert_eq!(
            original.settings.startup.application_name,
            "compio-postgres"
        );
        assert_eq!(changed.settings.startup.application_name, "web");
        assert_eq!(original.settings.startup.parameters.len(), 1);
        assert_eq!(changed.settings.startup.parameters.len(), 2);
    }

    #[cfg(all(feature = "diagnostics", feature = "tls"))]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn cloning_connection_options_for_workers_needs_no_heap_allocation() {
        use crate::tls::{TlsConfig, TlsNegotiation, TlsOptions, TlsResumption, TlsVersions};
        let tls = TlsConfig::from_ca_pem(
            "localhost",
            include_bytes!("../tests/fixtures/tls/sha256.pem"),
            TlsOptions {
                negotiation: TlsNegotiation::Direct,
                versions: TlsVersions::Tls13,
                resumption: TlsResumption::Disabled,
                send_buffer_limit: None,
            },
        )
        .unwrap();
        let options = api::ClientOptions::short_queries(
            TcpConfig::tls(
                "127.0.0.1:5432".parse().unwrap(),
                "user",
                "database",
                AuthenticationPolicy::ScramSha256 {
                    password: "fixture".to_owned(),
                    max_iterations: 4096,
                },
                WireLimits::short_queries(),
                tls,
                socket_options::TEST_TCP_OPTIONS,
            )
            .application_name("web")
            .startup_parameter("search_path", "public"),
        );
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        for _ in 0..64 {
            drop(std::hint::black_box(options.clone()));
        }
        let stats = region.change();
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }

    #[test]
    fn owned_diagnostic_preserves_non_ascii_extension_tags_and_utf8() {
        let body = b"\xf1vendor\0SERROR\0C22000\0M\xc3\xa9\0\0";
        let BackendMessage::ErrorResponse(message) =
            protocol::parse_backend(protocol::Frame { tag: b'E', body }).unwrap()
        else {
            panic!("expected a database error");
        };
        let raw_budget = size_of::<DatabaseError>() + body.len();
        let mut budget = raw_budget - 1;
        assert!(matches!(
            owned_error_bounded(message, &mut budget),
            Err(Error::Limit(_))
        ));
        assert_eq!(budget, raw_budget - 1);
        let mut budget = raw_budget;
        let diagnostic = owned_error_bounded(message, &mut budget).unwrap();
        assert_eq!(budget, 0);
        assert_eq!(diagnostic.field(0xf1), Some("vendor"));
        assert_eq!(diagnostic.message(), "é");
        assert_eq!(
            diagnostic.fields().collect::<Vec<_>>(),
            message.fields().collect::<Vec<_>>()
        );
    }

    #[test]
    fn diagnostic_budget_includes_all_reported_fields() {
        let body = b"Slocalized severity\0VERROR\0C23505\0Mduplicate\0Ddetail\0Hhint\0P9\0sapp\0tusers\0nusers_key\0xextension\0\0";
        let BackendMessage::ErrorResponse(message) =
            protocol::parse_backend(protocol::Frame { tag: b'E', body }).unwrap()
        else {
            panic!("error message");
        };
        let exact = std::mem::size_of::<DatabaseError>() + body.len();
        let mut remaining = exact;
        let diagnostic =
            owned_error_bounded(message, &mut remaining).expect("exact diagnostic budget");
        assert_eq!(diagnostic.code(), "23505");
        assert_eq!(diagnostic.severity(), "ERROR");
        assert_eq!(diagnostic.localized_severity(), "localized severity");
        assert_eq!(diagnostic.message(), "duplicate");
        assert_eq!(diagnostic.detail(), Some("detail"));
        assert_eq!(diagnostic.hint(), Some("hint"));
        assert_eq!(diagnostic.position(), Some(9));
        assert_eq!(diagnostic.schema(), Some("app"));
        assert_eq!(diagnostic.table(), Some("users"));
        assert_eq!(diagnostic.constraint(), Some("users_key"));
        assert_eq!(diagnostic.field(b'x'), Some("extension"));
        assert_eq!(diagnostic.retained_bytes().unwrap(), exact);
        assert_eq!(remaining, 0);
        for limit in [body.len(), exact - 1] {
            let mut remaining = limit;
            assert!(matches!(
                owned_error_bounded(message, &mut remaining),
                Err(Error::Limit(_))
            ));
            assert_eq!(remaining, limit);
        }
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn database_error_allocates_only_its_field_bytes() {
        let body = b"SERROR\0C23505\0Mduplicate\0\0";
        let BackendMessage::ErrorResponse(response) =
            protocol::parse_backend(protocol::Frame { tag: b'E', body }).unwrap()
        else {
            panic!("expected a database error");
        };
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let error = std::hint::black_box(Error::Database(owned_error(response)));
        let stats = region.change();

        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.bytes_allocated, body.len());
        assert!(matches!(error, Error::Database(error) if error.code() == "23505"));
    }

    #[test]
    fn sasl_packets_respect_the_request_byte_limit() {
        let message = b"abc";
        for (plus, mechanism) in [
            (false, b"SCRAM-SHA-256\0".as_slice()),
            (true, b"SCRAM-SHA-256-PLUS\0".as_slice()),
        ] {
            let exact = 1 + 4 + mechanism.len() + 4 + message.len();
            assert!(matches!(
                sasl_initial(message, plus, exact - 1),
                Err(Error::Limit(_))
            ));
            let packet = sasl_initial(message, plus, exact).unwrap();
            assert_eq!(packet.len(), exact);
            assert_eq!(&packet[5..5 + mechanism.len()], mechanism);
            assert_eq!(&packet[5 + mechanism.len()..], b"\0\0\0\x03abc");
        }
        assert!(matches!(sasl_response(message, 7), Err(Error::Limit(_))));
        assert_eq!(sasl_response(message, 8).unwrap(), b"p\0\0\0\x07abc");
    }

    #[test]
    fn version_and_scram_limits_are_strict() {
        for version in ["19", "19rc1", "19.1", "19beta3 (Debian)"] {
            assert!(validate_version(version).is_ok());
        }
        for version in ["18.6", "190.0", "", "PostgreSQL 19"] {
            assert!(validate_version(version).is_err());
        }
        assert!(check_iterations(b"r=nonce,s=c2FsdA==,i=4096", 4096).is_ok());
        for challenge in [
            b"i=0".as_slice(),
            b"i=4097",
            b"i=1,i=1",
            b"i=-1",
            b"i=+4096",
            b"i=04096",
            b"r=nonce",
        ] {
            assert!(check_iterations(challenge, 4096).is_err());
        }
    }
}
