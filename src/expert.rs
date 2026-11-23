//! 高级协议接口、传输选项与固定批处理控制。
//!
//! 普通服务从 [`crate::ClientOptions`] 和 [`crate::Client`] 接入；
//! 本模块提供同一协议实现的底层控制。

#[cfg(feature = "tls")]
pub use crate::client::TlsConnection as TlsSession;
#[cfg(unix)]
pub use crate::client::UnixConnection as UnixSession;
pub use crate::client::{
    CloseItem, ClosePipelineError, CopyProtocol, FrozenEncodedGroup, GroupPipelineError,
    GroupPipelineLimits, GroupPipelineProgress, GroupSyncCompletion, PipelineError, PipelineItem,
    PipelineLimits, PipelineRequest, PipelineResult, PrepareItem, PreparePipelineError,
    PrepareRequest, PreparedStatement, ProvisionalGroupConsumeEvent, ProvisionalGroupEvent,
    ProvisionalGroupLimits, ProvisionalWindowConsumeEvent, ProvisionalWindowError,
    ProvisionalWindowLimits, Query, Session, TcpConnection as TcpSession,
    Transaction as SessionTransaction, VisitCompletion, VisitError, VisitLimits, WindowCompletion,
    WindowError, WindowLimits, WindowParameters, WindowRequest,
};
pub use crate::row::RowConsumer;
pub use crate::scheduler::BatchQuantum;
pub use crate::transport::NativeStream;
#[cfg(feature = "window-cache")]
pub use crate::transport::WindowSendCache;

/// PostgreSQL 3.2 原始帧、消息和报文编码。
pub mod protocol {
    pub use crate::protocol::{
        Authentication, BackendKeyData, BackendMessage, CommandTag, CopyResponse, DataRow,
        DataRowIter, FieldDescription, Frame, FrameParse, MAX_CANCEL_KEY_LEN, MIN_CANCEL_KEY_LEN,
        PROTOCOL_VERSION, ParameterDescription, ProtocolNegotiation, RowDescription,
        RowDescriptionIter, StringList, StringListIter, encode_cancel, encode_startup,
        parse_backend, parse_command_tag, parse_frame,
    };
}

/// Linux 非阻塞 TCP、Unix 域套接字及 io_uring 的专用接口。
#[cfg(target_os = "linux")]
pub mod linux {
    pub use crate::client::api::{TcpReadinessConnection, UnixReadinessConnection};
    pub use crate::client::{
        TcpOptionsExt, TcpReadinessConnection as TcpReadinessSession, TcpReceiveBufferPolicy,
        TcpReceiveBufferSnapshot, TcpSessionExt, UnixReadinessConnection as UnixReadinessSession,
    };
    pub use crate::readiness::ReadinessTransport;
    #[cfg(feature = "service")]
    pub use crate::service::dispatcher::DispatcherExt;
}
