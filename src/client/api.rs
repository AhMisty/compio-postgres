//! 常规连接、事务、查询与批处理入口。
//! 传输类型在编译期确定。

mod batch;
mod copy;
mod query;

use std::num::NonZeroUsize;

use super as core;
use crate::{
    Error,
    protocol::TransactionStatus,
    row::AllocationPolicy,
    scheduler::ExecutionScheduling,
    transport::{Transport, WireTransport},
};

pub use crate::error::OnError;
pub use batch::{
    BatchBuilder, BatchError, BatchOptions, BatchProgress, BatchReport, BatchRequest, ReadyResult,
};
pub use copy::{
    CopyAbort, CopyBatchCompletion, CopyBatchError, CopyBatchLimits, CopyChunk, CopyCompletion,
    CopyDataBuffer, CopyInfo, CopyInput, CopyOutput, CopyStreamLimits,
};
pub use query::{
    OneShotRequest, QueryLimits, QueryOptions, QueryRequest, QueryResult, Rows, Statement,
};

/// 自有输出的保留空间。
/// 接收缓冲、元数据和扩容时的临时空间另计。
#[derive(Debug, Clone, Copy)]
pub struct OwnedOutput {
    pub max_bytes: usize,
    pub allocation: AllocationPolicy,
}

/// 本连接的新查询和批次继承的执行配置。
#[derive(Debug, Clone, Copy)]
pub struct ExecutionOptions {
    pub query: QueryOptions,
    /// 默认批次配置。
    /// 选 `None` 时，调用方须通过 `BatchBuilder::with_options` 明确指定。
    pub batch: Option<BatchOptions>,
}
impl ExecutionOptions {
    pub const fn direct(query: QueryOptions) -> Self {
        Self { query, batch: None }
    }
}
/// 连接的传输配置、执行策略和预备语句限额。
#[derive(Clone)]
pub struct ClientOptions<C> {
    config: C,
    settings: ClientSettings,
}

#[derive(Clone, Copy)]
struct ClientSettings {
    execution: ExecutionOptions,
    statements: crate::StatementLimits,
}

impl<C> ClientOptions<C> {
    /// 为同一 worker 上的短查询配置最多 256 行、256 KiB 结果和 16 KiB 元数据，每 128 个工作单元协作让出。
    /// 16 个预备语句槽共用 64 KiB。
    /// 连接的收发与帧限额取自传入的配置。批次须通过 [`BatchBuilder::with_options`] 单独配置。
    pub fn short_queries(config: C) -> Self {
        Self::direct(
            config,
            QueryOptions {
                limits: QueryLimits {
                    max_rows: 256,
                    max_result_bytes: 256 * 1024,
                    max_metadata_bytes: 16 * 1024,
                },
                scheduling: ExecutionScheduling::Cooperative {
                    max_work_per_turn: NonZeroUsize::MIN.saturating_add(128 - 1),
                },
            },
            crate::StatementLimits {
                max_statements: 16,
                max_metadata_bytes: 64 * 1024,
            },
        )
    }

    pub fn new(config: C, execution: ExecutionOptions, statements: crate::StatementLimits) -> Self {
        Self {
            config,
            settings: ClientSettings {
                execution,
                statements,
            },
        }
    }

    pub fn direct(config: C, query: QueryOptions, statements: crate::StatementLimits) -> Self {
        Self::new(config, ExecutionOptions::direct(query), statements)
    }
}

impl ClientSettings {
    fn validate(&self, max_request_len: usize) -> Result<(), Error> {
        if let Some(batch) = self.execution.batch {
            batch.validate(max_request_len)?;
        }
        if self.statements.max_statements != 0 && self.statements.max_metadata_bytes == 0 {
            return Err(Error::InvalidInput(
                "statement metadata bound must be positive when storage is enabled",
            ));
        }
        self.statements.slot_storage_minimum()?;
        Ok(())
    }
}

/// 持有具体传输类型的客户端。
/// 在服务所在的 Compio runtime 中建连，并在同一 runtime 上驱动该连接。
/// 一个查询或事务独占借用连接。需要在一个连接上同时提交多项请求时使用 [`Self::streaming_batch`]。
pub struct Client<T: WireTransport> {
    inner: core::Session<T>,
    defaults: ExecutionOptions,
}
pub type TcpConnection = Client<Transport>;
#[cfg(feature = "tls")]
/// TLS 连接的传输类型，可用于声明具体事务、行流或 COPY 句柄。
///
/// ```no_run
/// use compio_postgres::{AbandonPolicy, Error, Rows, Statement, TlsConnection, TlsTransport};
///
/// async fn open_rows<'a>(
///     client: &'a mut TlsConnection,
///     statement: &Statement,
/// ) -> Result<Rows<'a, TlsTransport>, Error> {
///     client.query(statement, &[])
///         .stream_provisional(AbandonPolicy::RecoverExplicitly)
///         .await
/// }
/// ```
pub type TlsTransport = crate::buffered::BufferedTransport<crate::tls::TlsSession>;
#[cfg(feature = "tls")]
pub type TlsConnection = Client<TlsTransport>;
#[cfg(unix)]
pub type UnixConnection = Client<Transport<compio::net::UnixStream>>;
/// Linux 上通过就绪通知驱动的 TCP 连接。
#[cfg(target_os = "linux")]
pub type TcpReadinessConnection = Client<crate::readiness::ReadinessTransport>;
/// Linux 上通过就绪通知驱动的文件系统 Unix socket 连接。
#[cfg(target_os = "linux")]
pub type UnixReadinessConnection =
    Client<crate::readiness::ReadinessTransport<compio::net::UnixStream>>;

impl Client<Transport> {
    pub fn connect(
        options: ClientOptions<crate::TcpConfig>,
    ) -> impl Future<Output = Result<Self, Error>> {
        let limit = options.config.settings.limits.max_request_len;
        Self::connect_configured(options, limit, core::TcpConnection::connect)
    }
}
#[cfg(feature = "tls")]
impl Client<TlsTransport> {
    pub fn connect(
        options: ClientOptions<crate::SecureConfig>,
    ) -> impl Future<Output = Result<Self, Error>> {
        let limit = options.config.tcp.settings.limits.max_request_len;
        Self::connect_configured(options, limit, core::TlsConnection::connect)
    }
    pub fn tls_info(&self) -> &crate::tls::TlsInfo {
        self.inner.tls_info()
    }
}
#[cfg(unix)]
impl Client<Transport<compio::net::UnixStream>> {
    pub fn connect(
        options: ClientOptions<crate::UnixConfig>,
    ) -> impl Future<Output = Result<Self, Error>> {
        let limit = options.config.settings.limits.max_request_len;
        Self::connect_configured(options, limit, core::UnixConnection::connect)
    }
}
#[cfg(target_os = "linux")]
impl Client<crate::readiness::ReadinessTransport> {
    pub fn connect(
        options: ClientOptions<crate::TcpConfig>,
    ) -> impl Future<Output = Result<Self, Error>> {
        let limit = options.config.settings.limits.max_request_len;
        Self::connect_configured(options, limit, core::TcpReadinessConnection::connect)
    }
}
#[cfg(target_os = "linux")]
impl Client<crate::readiness::ReadinessTransport<compio::net::UnixStream>> {
    pub fn connect(
        options: ClientOptions<crate::UnixConfig>,
    ) -> impl Future<Output = Result<Self, Error>> {
        let limit = options.config.settings.limits.max_request_len;
        Self::connect_configured(options, limit, core::UnixReadinessConnection::connect)
    }
}
impl<T: WireTransport> Client<T> {
    #[cfg(test)]
    pub(super) fn with_test_session(inner: core::Session<T>, defaults: ExecutionOptions) -> Self {
        Self { inner, defaults }
    }

    async fn connect_configured<C>(
        options: ClientOptions<C>,
        max_request_len: usize,
        connect: impl AsyncFnOnce(C) -> Result<core::Session<T>, Error>,
    ) -> Result<Self, Error> {
        let ClientOptions { config, settings } = options;
        settings.validate(max_request_len)?;
        let mut inner = connect(config).await?;
        inner.configure_statements(settings.statements)?;
        Ok(Self {
            inner,
            defaults: settings.execution,
        })
    }
    pub fn execution_options(&self) -> ExecutionOptions {
        self.defaults
    }

    #[cfg(feature = "service")]
    pub(crate) fn pool_identity(&self) -> (u64, Option<&std::task::Waker>) {
        use crate::transport::WireOps;

        (self.inner.id, self.inner.transport.owner_waker())
    }
    pub fn server_info(&self) -> &crate::ServerInfo {
        self.inner.server_info()
    }
    pub fn transaction_status(&self) -> TransactionStatus {
        self.inner.transaction_status()
    }

    /// 释放本地 socket。
    /// 此操作不发送 Terminate，也不确认服务器已回滚。
    pub async fn close_local(self) -> Result<(), Error> {
        self.inner.close_local().await
    }
    /// 在协议空闲时发送 Terminate，然后释放本地 socket。
    /// 发送失败时仍会释放。
    pub async fn terminate(self) -> Result<(), Error> {
        self.inner.terminate().await
    }
    /// 重置空闲会话并使原预备语句失效。
    pub async fn reset_session(&mut self) -> Result<(), Error> {
        self.inner.reset_session().await
    }
    /// 永久丢弃连接，经原端点和安全策略另行发送取消请求，再释放原 socket。
    /// 取消送达不确认 SQL 已中止或事务已回滚。
    /// [`Error::CancelRequest`] 表示原 socket 已释放，[`Error::CancelRetirement`] 表示释放未得到确认。
    pub async fn request_cancel_and_discard(self) -> Result<(), Error> {
        self.inner.request_cancel_and_discard().await
    }
    pub fn discard(self) {
        self.inner.discard();
    }
    /// 借用底层会话以使用专家接口。
    pub fn expert(&mut self) -> &mut crate::expert::Session<T> {
        &mut self.inner
    }
    pub fn into_expert(self) -> crate::expert::Session<T> {
        self.inner
    }

    /// 将空闲连接专用于 LISTEN 和通知接收。订阅操作和通知共用所选调度额度。
    pub fn into_listener(
        self,
        scheduling: ExecutionScheduling,
    ) -> Result<crate::Listener<T>, Error> {
        self.inner.into_listener(scheduling)
    }

    /// 按会话默认设置开启事务，原未命名语句随之失效。
    pub async fn begin_transaction(&mut self) -> Result<Transaction<'_, T>, Error> {
        self.begin_transaction_with(crate::TransactionOptions::default())
            .await
    }

    /// 在一个往返内按指定特性开启事务，与 [`Self::begin_transaction`] 一样会替换未命名语句。
    pub async fn begin_transaction_with(
        &mut self,
        options: crate::TransactionOptions,
    ) -> Result<Transaction<'_, T>, Error> {
        let inner = self.inner.begin_transaction_with(options).await?;
        Ok(Transaction {
            inner,
            defaults: &self.defaults,
        })
    }
}

/// 独占借用连接的事务。丢弃事务句柄后，调用 [`Client::recover_and_rollback`] 可排空挂起操作并处理遗留事务。
#[must_use = "复用连接前须提交或回滚事务"]
pub struct Transaction<'connection, T: WireTransport> {
    inner: core::Transaction<'connection, T>,
    defaults: &'connection ExecutionOptions,
}
impl<'connection, T: WireTransport> Transaction<'connection, T> {
    pub fn expert(&mut self) -> &mut crate::expert::SessionTransaction<'connection, T> {
        &mut self.inner
    }
    pub fn into_expert(self) -> crate::expert::SessionTransaction<'connection, T> {
        self.inner
    }

    pub async fn savepoint(&mut self, name: &str) -> Result<crate::ControlCompletion, Error> {
        self.inner.savepoint(name).await
    }
    pub async fn release_savepoint(
        &mut self,
        name: &str,
    ) -> Result<crate::ControlCompletion, Error> {
        self.inner.release_savepoint(name).await
    }
    pub async fn rollback_to_savepoint(
        &mut self,
        name: &str,
    ) -> Result<crate::ControlCompletion, Error> {
        self.inner.rollback_to_savepoint(name).await
    }
    pub async fn commit_and_chain(&mut self) -> Result<crate::ControlCompletion, Error> {
        self.inner.commit_and_chain().await
    }
    pub async fn rollback_and_chain(&mut self) -> Result<crate::ControlCompletion, Error> {
        self.inner.rollback_and_chain().await
    }

    pub fn execution_options(&self) -> ExecutionOptions {
        *self.defaults
    }

    pub fn transaction_status(&self) -> TransactionStatus {
        self.inner.transaction_status()
    }
    /// 等待服务端确认结束。已失败的事务执行 COMMIT 时可能以回滚结束，实际结果见 `transaction_end`。
    pub async fn commit(self) -> Result<crate::ControlCompletion, Error> {
        self.inner.commit().await
    }
    pub async fn rollback(self) -> Result<crate::ControlCompletion, Error> {
        self.inner.rollback().await
    }
}

impl<T: WireTransport> Client<T> {
    pub fn reuse_state(&self) -> crate::ReuseState {
        self.inner.reuse_state()
    }

    pub fn recover_to_ready(&mut self) -> impl Future<Output = Result<(), Error>> {
        self.inner.recover_to_ready()
    }

    /// 按本次指定的行数与字节上限排空响应，不重放 SQL。
    pub fn recover_to_ready_with_limits(
        &mut self,
        max_rows: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<(), Error>> {
        self.inner.recover_to_ready_with_limits(max_rows, max_bytes)
    }

    /// 恢复已接纳请求并回滚遗留事务。
    /// 若先前的提交已经确认，返回实际提交结果。
    pub async fn recover_and_rollback(&mut self) -> Result<crate::ControlCompletion, Error> {
        self.inner.recover_and_rollback().await
    }

    pub fn take_transaction_end(&mut self) -> Option<crate::TransactionEnd> {
        self.inner.take_transaction_end()
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub fn reuse_state(&self) -> crate::ReuseState {
        self.inner.reuse_state()
    }

    /// 恢复已接纳的请求，保留当前事务的提交或回滚决定。
    pub fn recover_to_ready(&mut self) -> impl Future<Output = Result<(), Error>> {
        self.inner.recover_to_ready()
    }

    /// 根据本次指定的行数和字节上限排空响应，保留当前事务。
    pub fn recover_to_ready_with_limits(
        &mut self,
        max_rows: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<(), Error>> {
        self.inner.recover_to_ready_with_limits(max_rows, max_bytes)
    }

    pub fn take_transaction_end(&mut self) -> Option<crate::TransactionEnd> {
        self.inner.take_transaction_end()
    }
}

mod sealed {
    pub trait Scope {}
    impl<T: crate::transport::WireTransport> Scope for super::Client<T> {}
    impl<T: crate::transport::WireTransport> Scope for super::Transaction<'_, T> {}
}
/// 连接与事务共用的内部静态派发接口。
#[doc(hidden)]
pub trait ApiScope: sealed::Scope {
    type Io: WireTransport;
    fn profile(&self) -> &ExecutionOptions;
    fn max_request_len(&self) -> usize;
    fn access(&mut self) -> (&mut core::Session<Self::Io>, bool);
    fn state(&self) -> crate::ReuseState;
    fn status(&self) -> TransactionStatus;
}
impl<T: WireTransport> ApiScope for Client<T> {
    type Io = T;
    fn profile(&self) -> &ExecutionOptions {
        &self.defaults
    }
    fn max_request_len(&self) -> usize {
        self.inner.max_request_len
    }
    fn access(&mut self) -> (&mut core::Session<T>, bool) {
        (&mut self.inner, false)
    }
    fn state(&self) -> crate::ReuseState {
        self.inner.reuse_state()
    }
    fn status(&self) -> TransactionStatus {
        self.inner.transaction_status()
    }
}
impl<T: WireTransport> ApiScope for Transaction<'_, T> {
    type Io = T;
    fn profile(&self) -> &ExecutionOptions {
        self.defaults
    }
    fn max_request_len(&self) -> usize {
        self.inner.session().max_request_len
    }
    fn access(&mut self) -> (&mut core::Session<T>, bool) {
        (self.inner.session_mut(), true)
    }
    fn state(&self) -> crate::ReuseState {
        self.inner.reuse_state()
    }
    fn status(&self) -> TransactionStatus {
        self.inner.transaction_status()
    }
}
