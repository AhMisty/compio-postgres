//! 供 Compio 使用的 PostgreSQL 19 客户端，采用协议 3.2。
//!
//! 建连前用传输配置和 [`ClientOptions`] 选择认证、I/O、资源限额及调度策略。
//! [`types`] 提供 PostgreSQL 参数与编解码接口。
//! [`expert`] 提供直接的协议和传输控制。

#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::unreachable,
    )
)]

#[cfg(feature = "tls")]
mod buffered;
mod client;
#[cfg(feature = "diagnostics")]
pub mod diagnostics;
mod error;
pub mod expert;
mod frontend;
mod protocol;
#[cfg(target_os = "linux")]
mod readiness;
mod row;
mod scheduler;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "tls")]
mod tls;
mod transport;
pub mod types;

pub use client::api::{
    BatchBuilder, BatchError, BatchOptions, BatchProgress, BatchReport, BatchRequest, Client,
    ClientOptions, CopyAbort, CopyBatchCompletion, CopyBatchError, CopyBatchLimits, CopyChunk,
    CopyCompletion, CopyDataBuffer, CopyInfo, CopyInput, CopyOutput, CopyStreamLimits,
    ExecutionOptions, OnError, OneShotRequest, OwnedOutput, QueryLimits, QueryOptions,
    QueryRequest, QueryResult, ReadyResult, Rows, Statement, TcpConnection, Transaction,
};
pub(crate) use client::*;
pub use client::{
    AbandonPolicy, AuthenticationPolicy, CancelHandle, CommandKind, ControlCompletion, ControlKind,
    IsolationLevel, Listener, Notification, Portal, PortalFetchCompletion, PortalFetchLimits,
    PreparedStatementStorage, ProvisionalWindowControl as BatchControl,
    ProvisionalWindowErrorOrigin as BatchErrorOrigin, ProvisionalWindowEvent as BatchEvent,
    QueryCompletion, ReadyBatchEvent, ReadyBatchResult, ReuseState, RowLease, SendPolicy,
    ServerInfo, StatementLimits, StatementPipelineLimits, TcpConfig, TcpNoDelay, TcpOptions,
    TransactionAccess, TransactionDeferrability, TransactionEnd, TransactionOptions, WireLimits,
};
#[cfg(feature = "tls")]
pub use client::{
    SecureConfig,
    api::{TlsConnection, TlsTransport},
};
#[cfg(unix)]
pub use client::{UnixConfig, api::UnixConnection};
pub use error::{DatabaseError, Error};
pub use protocol::{ErrorResponse, ProtocolError, TransactionStatus};
pub use row::{
    AllocationPolicy, Column, ColumnRef, OwnedBatch, OwnedRow, OwnedRows, ResultFormats,
    RowDecoder, RowFields, RowLayout, RowView,
};
pub use scheduler::ExecutionScheduling;
#[cfg(feature = "tls")]
pub use tls::{
    CipherSuite, TlsConfig, TlsInfo, TlsNegotiation, TlsOptions, TlsResumption, TlsVersion,
    TlsVersions,
};
pub use transport::{Transport as NativeTransport, WireTransport};
