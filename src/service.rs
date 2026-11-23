//! 应用自行决定接纳策略时可选用的 worker 本地服务组件。
//!
//! [LocalPool] 管理预热连接，[BoundedFifo] 暂存等待请求，两者均可独立使用。
//! [LocalDispatcher] 用应用提供的执行方法派发请求。应用可以直接轮询驱动或在本 worker 启动驱动任务，并负责定时、恢复和补充连接。
//!
//! # 预热和租借连接
//!
//! 两个函数须在同一 Compio runtime 上运行。示例执行固定只读查询，归还时会话可供下一租约复用。
//!
//! ```no_run
//! use compio_postgres::{
//!     ClientOptions, Error, NativeTransport, OnError, PreparedStatementStorage, ResultFormats,
//!     Statement, TcpConfig, TcpConnection,
//!     service::{LocalPool, PoolEntry, PoolReuse, PrewarmFailure, ReleaseOutcome, SessionHygiene},
//!     types::{Format, Oid, Parameter},
//! };
//! use std::num::NonZeroUsize;
//!
//! type ReadPool = LocalPool<NativeTransport, Statement>;
//!
//! async fn prewarm(options: ClientOptions<TcpConfig>, capacity: NonZeroUsize) -> Result<ReadPool, Box<dyn std::error::Error>> {
//!     let mut pool = LocalPool::try_new(capacity, PoolReuse::VerifyOnRelease)?;
//!     pool.prewarm(async || {
//!         let mut client = TcpConnection::connect(options.clone()).await
//!             .map_err(PrewarmFailure::Uncertain)?;
//!         let statement = client.prepare(
//!             "SELECT $1::int4",
//!             &[Oid::INT4],
//!             PreparedStatementStorage::Named,
//!             ResultFormats::All(Format::Binary),
//!         ).await.map_err(PrewarmFailure::Uncertain)?;
//!         Ok(PoolEntry::new(client, statement))
//!     }).await?;
//!     Ok(pool)
//! }
//!
//! async fn read(pool: &ReadPool, value: i32) -> Result<Option<i32>, Error> {
//!     let Some(mut lease) = pool.try_acquire()? else {
//!         return Ok(None);
//!     };
//!     let (client, statement) = lease.client_and_state();
//!     let result = client.query(statement, &[Parameter::int4(value)])
//!         .one::<i32>(OnError::RecoverExplicitly).await;
//!     let hygiene = if result.is_ok() {
//!         SessionHygiene::Verified
//!     } else {
//!         SessionHygiene::Quarantine
//!     };
//!     if lease.release(hygiene) != ReleaseOutcome::Returned && result.is_ok() {
//!         return Err(Error::Broken);
//!     }
//!     result.map(Some)
//! }
//! ```
//!
//! 池为空时，应用可以拒绝请求或将其放入独立的有界 FIFO。按应用实际保留的存储计量等待字节；等待队列、连接数和协议在途窗口分别设限。
//!
//! [SessionHygiene::Verified] 由应用确认。池仍会隔离协议工作尚未完成的连接；
//! 用 [LocalPool::try_acquire_quarantined] 接管后显式恢复、关闭或取消。
//! 每个保留槽只承载一次建连尝试，借用期间保持原连接身份。
//!
//! 请求的最晚发起时间应在发起 SQL 前用单调时钟核对。已经发出的 SQL 可能在截止时间后执行并提交，
//! 应用需确认结果或显式恢复、取消。

type Guarded<T> = std::mem::DropGuard<T, fn(T)>;

/// 维护入口已验证当前 worker。只有真正挂起后才保存其身份，覆盖尚无连接、尚未绑定的池。
fn await_on_worker<F: std::future::Future>(
    mut future: std::pin::Pin<&mut F>,
) -> impl std::future::Future<Output = Option<F::Output>> {
    let mut owner: Option<crate::transport::IoOwner> = None;
    std::future::poll_fn(move |cx| {
        if owner.as_ref().is_some_and(|owner| owner.check().is_err()) {
            return std::task::Poll::Ready(None);
        }
        let outcome = future.as_mut().poll(cx);
        if outcome.is_pending() {
            owner.get_or_insert_with(crate::transport::IoOwner::current);
        }
        outcome.map(Some)
    })
}

pub(crate) mod dispatcher;
mod fifo;
mod pool;

pub use dispatcher::{
    BatchDispatch, BatchDispatchOperation, DispatchBatch, DispatchError, DispatchLimits,
    DispatchMode, DispatchOperation, DispatchReplaceError, DriverError, LocalDispatcher,
    MaintenanceError, SingleDispatch,
};
pub use fifo::{BoundedFifo, QueueLimits, RejectReason, Rejected};
pub use pool::{
    InstallOutcome, Lease, LocalPool, MaintenanceId, Occupancy, PendingMaintenance, PoolEntry,
    PoolReuse, PrewarmError, PrewarmFailure, ReleaseOutcome, Replacement, SessionHygiene,
};
