use crate::transport::WireOps;
use std::fmt;

use super::{NoticePolicy, Session, is_fatal, owned_error, protocol_error, validate_parameter};
use crate::{
    Error, frontend,
    protocol::{self, BackendMessage, CommandTag, TransactionStatus, TxCommand},
    transport::{TransportExt, WireTransport},
};

/// 已由 CommandComplete 确认的事务结束结果。
/// 之后传输失败也不会抹去这一事实；连接能否复用、AND CHAIN 新开的事务是否结束须另行判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEnd {
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// PostgreSQL 对这一选项采用与 ReadCommitted 相同的隔离行为。
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionDeferrability {
    /// 在可串行化的只读事务中生效，取得合适的初始快照可能需要等待。
    Deferrable,
    NotDeferrable,
}

/// 首次 BEGIN 使用的事务属性。
/// 未指定的属性沿用 PostgreSQL 会话默认值。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TransactionOptions {
    pub isolation: Option<IsolationLevel>,
    pub access: Option<TransactionAccess>,
    pub deferrability: Option<TransactionDeferrability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlRequest {
    Begin,
    Commit { chain: bool },
    Rollback { chain: bool },
    Savepoint,
    Release,
    RollbackTo,
}

impl From<TxCommand<'_>> for ControlRequest {
    fn from(command: TxCommand<'_>) -> Self {
        match command {
            TxCommand::Begin => Self::Begin,
            TxCommand::Commit { chain } => Self::Commit { chain },
            TxCommand::Rollback { chain } => Self::Rollback { chain },
            TxCommand::Savepoint(_) => Self::Savepoint,
            TxCommand::ReleaseSavepoint(_) => Self::Release,
            TxCommand::RollbackToSavepoint(_) => Self::RollbackTo,
        }
    }
}

/// 放弃控制命令后仍需保留确认进度，避免遇到重复标签时再次交付已领取的结束结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingTransactionControl {
    Waiting(ControlRequest),
    Complete(ControlRequest),
    Failed,
    // 已确认 Ready，但原命令的本地发送尚未完成。
    ReadyObserved { failed_idle: bool },
}

/// 服务端已确认的事务控制命令。回滚到保存点使用同一个 ROLLBACK 标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Begin,
    Commit,
    Rollback,
    Savepoint,
    Release,
}

impl ControlKind {
    pub(super) fn from_tag(tag: CommandTag<'_>) -> Result<Self, Error> {
        match tag {
            CommandTag::Begin => Ok(Self::Begin),
            CommandTag::Commit => Ok(Self::Commit),
            CommandTag::Rollback => Ok(Self::Rollback),
            CommandTag::Savepoint => Ok(Self::Savepoint),
            CommandTag::Release => Ok(Self::Release),
            _ => Err(protocol_error(
                "transaction command returned an unexpected completion tag",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlCompletion {
    pub kind: ControlKind,
    pub transaction_status: TransactionStatus,
    pub transaction_end: Option<TransactionEnd>,
}

/// 事务的独占访问权。
/// 丢弃或遗忘句柄不会启动 I/O，原会话仍保留事务责任。
/// 恢复普通访问前须显式恢复、回滚或丢弃会话。
#[must_use = "事务必须显式结束、恢复或丢弃"]
pub struct Transaction<'a, T: WireTransport> {
    session: &'a mut Session<T>,
}

impl<T: WireTransport> fmt::Debug for Transaction<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("transaction_status", &self.session.transaction_status)
            .field("request_active", &self.session.active)
            .finish_non_exhaustive()
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub(super) fn session(&self) -> &Session<T> {
        self.session
    }

    pub(super) fn session_mut(&mut self) -> &mut Session<T> {
        self.session
    }

    pub fn take_transaction_end(&mut self) -> Option<TransactionEnd> {
        self.session.take_transaction_end()
    }

    pub async fn savepoint(&mut self, name: &str) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::Savepoint(name))
            .await
    }

    pub async fn release_savepoint(&mut self, name: &str) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::ReleaseSavepoint(name))
            .await
    }

    pub async fn rollback_to_savepoint(&mut self, name: &str) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::RollbackToSavepoint(name))
            .await
    }

    /// 结束当前事务。
    /// 事务已失败时，PostgreSQL 可用 ROLLBACK 响应 COMMIT；返回值记录实际结果。
    pub async fn commit(self) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::Commit { chain: false })
            .await
    }

    pub async fn rollback(self) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::Rollback { chain: false })
            .await
    }

    pub async fn commit_and_chain(&mut self) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::Commit { chain: true })
            .await
    }

    pub async fn rollback_and_chain(&mut self) -> Result<ControlCompletion, Error> {
        self.session
            .transaction_control(TxCommand::Rollback { chain: true })
            .await
    }
}

impl<T: WireTransport> Session<T> {
    /// 采用会话默认设置开启事务。
    /// 简单查询消息会使已有未命名语句失效。
    pub async fn begin_transaction(&mut self) -> Result<Transaction<'_, T>, Error> {
        self.begin_transaction_with(TransactionOptions::default())
            .await
    }

    /// 在 BEGIN 的同一次往返中设置事务属性。
    /// 与 `begin_transaction` 一样会使未命名语句失效。
    pub async fn begin_transaction_with(
        &mut self,
        options: TransactionOptions,
    ) -> Result<Transaction<'_, T>, Error> {
        self.check_idle_access(false)?;
        if self.transaction_status != TransactionStatus::Idle {
            return Err(Error::Unsupported(
                "an existing transaction must be explicitly resolved before BEGIN",
            ));
        }
        if self.transaction_end.is_some() {
            return Err(Error::Busy);
        }
        let packet = frontend::SimpleQueryPacket::begin(options, self.max_request_len)?;
        let buffer = self.transport.take_send_buffer()?;
        let bytes = packet.encode_into(buffer)?;
        // 提交或挂起前先登记事务归属，使放弃 future 也不能跳过结束事务的责任。
        self.transaction_lease = true;
        self.run_transaction_control_on_owner(TxCommand::Begin, bytes, NoticePolicy::Deliver)
            .await?;
        Ok(Transaction { session: self })
    }

    /// 领取已确认的事务结束结果，即使之后连接失败仍可读取。
    /// 确认 Ready 且本地发送完成后释放空闲事务；若发送尚未完成仍须显式恢复。
    pub fn take_transaction_end(&mut self) -> Option<TransactionEnd> {
        let end = self.transaction_end.take();
        if end.is_some() && !self.transport.is_broken() {
            if self.active
                || self.remaining_boundaries != 0
                || self.pending_transaction_control.is_some()
            {
                self.transaction_end_retirement = super::TransactionEndRetirement::Taken;
            } else if self.transaction_status == TransactionStatus::Idle {
                self.transaction_lease = false;
            }
        }
        end
    }

    /// 仅在所有已提交边界与本地发送均确认后调用。
    pub(super) fn finish_taken_transaction_end_recovery(&mut self) {
        if self.transaction_end_retirement == super::TransactionEndRetirement::Taken {
            self.transaction_end_retirement = super::TransactionEndRetirement::None;
            if self.transaction_status == TransactionStatus::Idle && self.transaction_end.is_none()
            {
                self.transaction_lease = false;
            }
        }
    }

    /// 排空已提交工作并显式回滚。
    /// 若之前已确定事务结束且恢复到 Idle，返回原结束结果；已提交事务无法再回滚。
    pub async fn recover_and_rollback(&mut self) -> Result<ControlCompletion, Error> {
        self.recover_to_ready().await?;
        if self.transport.is_broken() {
            return Err(Error::Broken);
        }
        if self.active
            || self.remaining_boundaries != 0
            || self.pending_transaction_control.is_some()
        {
            return Err(Error::Busy);
        }
        if let Some(end) = self.transaction_end {
            if self.transaction_status != TransactionStatus::Idle {
                // 不覆盖尚未领取的 AND CHAIN 结果。
                // 调用方可先领取再恢复。
                return Err(Error::Busy);
            }
            self.transaction_lease = false;
            return Ok(ControlCompletion {
                kind: match end {
                    TransactionEnd::Committed => ControlKind::Commit,
                    TransactionEnd::RolledBack => ControlKind::Rollback,
                },
                transaction_status: self.transaction_status,
                transaction_end: self.transaction_end.take(),
            });
        }
        if self.transaction_status == TransactionStatus::Idle {
            return Err(Error::Unsupported(
                "there is no open transaction and no retained end fact; a new ROLLBACK cannot establish the earlier outcome",
            ));
        }
        let packet = frontend::SimpleQueryPacket::transaction(
            TxCommand::Rollback { chain: false },
            self.max_request_len,
        )?;
        let buffer = self.transport.take_send_buffer()?;
        let bytes = packet.encode_into(buffer)?;
        self.transaction_lease = true;
        self.run_transaction_control_on_owner(
            TxCommand::Rollback { chain: false },
            bytes,
            NoticePolicy::Drain,
        )
        .await
    }

    pub(in crate::client) fn check_transaction_access(
        &self,
        allow_failed: bool,
    ) -> Result<(), Error> {
        self.check_inactive()?;
        if !self.transaction_lease {
            return Err(Error::InvalidInput(
                "the transaction no longer owns its session lease",
            ));
        }
        match self.transaction_status {
            TransactionStatus::Idle => Err(Error::Unsupported(
                "the transaction is already idle; explicitly recover or discard its lease",
            )),
            TransactionStatus::FailedTransaction if !allow_failed => Err(Error::Unsupported(
                "the transaction is failed; explicitly roll back or end it",
            )),
            _ => Ok(()),
        }
    }

    async fn transaction_control(
        &mut self,
        command: TxCommand<'_>,
    ) -> Result<ControlCompletion, Error> {
        let allow_failed = matches!(
            command,
            TxCommand::Commit { .. }
                | TxCommand::Rollback { .. }
                | TxCommand::RollbackToSavepoint(_)
        );
        self.check_transaction_access(allow_failed)?;
        self.check_runtime_owner()?;
        if ends_transaction(command) && self.transaction_end.is_some() {
            return Err(Error::Busy);
        }
        let packet = frontend::SimpleQueryPacket::transaction(command, self.max_request_len)?;
        let buffer = self.transport.take_send_buffer()?;
        let bytes = packet.encode_into(buffer)?;
        self.run_transaction_control_on_owner(command, bytes, NoticePolicy::Deliver)
            .await
    }

    /// 接纳和恢复均在已验证的 runtime 中交给此方法，挂起的 I/O 另行验证归属。
    async fn run_transaction_control_on_owner(
        &mut self,
        command: TxCommand<'_>,
        bytes: Vec<u8>,
        notices: NoticePolicy,
    ) -> Result<ControlCompletion, Error> {
        self.active = true;
        self.remaining_boundaries = 1;
        self.pending_transaction_control = Some(PendingTransactionControl::Waiting(command.into()));
        let result = self
            .read_transaction_control_on_owner(command, bytes, notices)
            .await;
        if result.is_err() && self.active {
            self.transport.break_connection();
        }
        result
    }

    async fn read_transaction_control_on_owner(
        &mut self,
        command: TxCommand<'_>,
        bytes: Vec<u8>,
        notices: NoticePolicy,
    ) -> Result<ControlCompletion, Error> {
        self.invalidate_unnamed_statement()?;
        self.transport.begin_send(bytes)?;
        let mut kind = None;
        let mut failure = None;
        for _ in 0..self.max_messages {
            self.transport.receive_frame_on_owner().await?;
            let message = protocol::parse_backend(self.transport.frame()?)?;
            let mut ready = None;
            let mut path_changed = false;
            match message {
                BackendMessage::CommandComplete(tag) if kind.is_none() && failure.is_none() => {
                    let tag = protocol::parse_command_tag(tag)?;
                    let observed = ControlKind::from_tag(tag)?;
                    self.observe_pending_control_tag(observed)?;
                    kind = Some(observed);
                }
                BackendMessage::ErrorResponse(error) if !is_fatal(error) => {
                    if failure.is_none() {
                        failure = Some(owned_error(error));
                    }
                    self.observe_pending_control_error();
                }
                BackendMessage::ReadyForQuery(status) if kind.is_some() || failure.is_some() => {
                    ready = Some(status)
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    path_changed = name == "search_path";
                }
                BackendMessage::NoticeResponse(notice) => {
                    if notices == NoticePolicy::Deliver {
                        super::observe_notice(notice, self.notice_handler.as_ref())
                            .finish(&mut self.transport);
                    }
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ErrorResponse(error) => {
                    return Err(Error::Database(owned_error(error)));
                }
                _ => {
                    return Err(protocol_error(
                        "unexpected message during transaction control",
                    ));
                }
            }
            self.transport.consume_frame()?;
            if path_changed {
                self.bump_schema_epoch()?;
            }
            if let Some(status) = ready {
                self.observe_pending_control_ready(status)?;
                self.note_ready(status)?;
                self.transport
                    .finish_send_on_owner()
                    .await
                    .map_err(|send| super::general::send_after_diagnostic(failure.take(), send))?;
                self.finish_pending_control_send()?;
                self.active = false;
                if let Some(error) = failure {
                    return Err(Error::Database(error));
                }
                let kind = kind.ok_or_else(|| {
                    protocol_error("transaction command completed without a command tag")
                })?;
                let transaction_end = if ends_transaction(command) {
                    if status == TransactionStatus::Idle {
                        self.transaction_lease = false;
                    }
                    self.transaction_end.take()
                } else {
                    None
                };
                return Ok(ControlCompletion {
                    kind,
                    transaction_status: status,
                    transaction_end,
                });
            }
        }
        Err(Error::Limit(
            "transaction control exceeded the configured message count",
        ))
    }

    pub(super) fn observe_pending_control_tag(&mut self, kind: ControlKind) -> Result<(), Error> {
        let Some(pending) = self.pending_transaction_control else {
            return Ok(());
        };
        let PendingTransactionControl::Waiting(request) = pending else {
            return Err(protocol_error(
                "transaction completion tag was duplicated or followed an error",
            ));
        };
        if !matches_expected_tag(request, kind) {
            return Err(protocol_error(
                "transaction command returned an unexpected completion tag",
            ));
        }
        if matches!(
            request,
            ControlRequest::Commit { .. } | ControlRequest::Rollback { .. }
        ) {
            if self.transaction_end.is_some() {
                return Err(protocol_error(
                    "an unconsumed transaction end would be overwritten",
                ));
            }
            self.transaction_end = Some(match kind {
                ControlKind::Commit => TransactionEnd::Committed,
                ControlKind::Rollback => TransactionEnd::RolledBack,
                _ => return Err(protocol_error("transaction end lacks its completion fact")),
            });
        }
        self.pending_transaction_control = Some(PendingTransactionControl::Complete(request));
        Ok(())
    }

    pub(super) fn observe_pending_control_error(&mut self) {
        if matches!(
            self.pending_transaction_control,
            Some(PendingTransactionControl::Waiting(_) | PendingTransactionControl::Complete(_))
        ) {
            self.pending_transaction_control = Some(PendingTransactionControl::Failed);
        }
    }

    pub(super) fn observe_pending_control_ready(
        &mut self,
        status: TransactionStatus,
    ) -> Result<(), Error> {
        let failed_idle = match self.pending_transaction_control {
            None => return Ok(()),
            Some(PendingTransactionControl::Waiting(_)) => {
                return Err(protocol_error(
                    "transaction Ready arrived before completion or error",
                ));
            }
            Some(PendingTransactionControl::Complete(request))
                if status != expected_status(request) =>
            {
                return Err(protocol_error(
                    "transaction completion has an inconsistent Ready status",
                ));
            }
            Some(PendingTransactionControl::Complete(_)) => false,
            Some(PendingTransactionControl::Failed) => status == TransactionStatus::Idle,
            Some(PendingTransactionControl::ReadyObserved { .. }) => {
                return Err(protocol_error("transaction Ready was already observed"));
            }
        };
        self.pending_transaction_control =
            Some(PendingTransactionControl::ReadyObserved { failed_idle });
        Ok(())
    }

    pub(super) fn finish_pending_control_send(&mut self) -> Result<(), Error> {
        let Some(pending) = self.pending_transaction_control else {
            return Ok(());
        };
        let PendingTransactionControl::ReadyObserved { failed_idle } = pending else {
            return Err(protocol_error(
                "transaction send retired before Ready was observed",
            ));
        };
        self.pending_transaction_control = None;
        // BEGIN 被拒绝或 COMMIT 出错也可能返回 Idle；保留已确认的事务结束状态。
        if failed_idle && self.transaction_end.is_none() {
            self.transaction_lease = false;
        }
        Ok(())
    }
}

fn ends_transaction(command: TxCommand<'_>) -> bool {
    matches!(
        command,
        TxCommand::Commit { .. } | TxCommand::Rollback { .. }
    )
}

fn expected_status(command: ControlRequest) -> TransactionStatus {
    match command {
        ControlRequest::Commit { chain: false } | ControlRequest::Rollback { chain: false } => {
            TransactionStatus::Idle
        }
        _ => TransactionStatus::InTransaction,
    }
}

fn matches_expected_tag(command: ControlRequest, tag: ControlKind) -> bool {
    matches!(
        (command, tag),
        (ControlRequest::Begin, ControlKind::Begin)
            | (
                ControlRequest::Commit { .. },
                ControlKind::Commit | ControlKind::Rollback
            )
            | (
                ControlRequest::Rollback { .. } | ControlRequest::RollbackTo,
                ControlKind::Rollback
            )
            | (ControlRequest::Savepoint, ControlKind::Savepoint)
            | (ControlRequest::Release, ControlKind::Release)
    )
}

#[cfg(test)]
mod local_resource_tests {
    use super::*;
    use crate::{AuthenticationPolicy, SendPolicy, TcpConfig, TcpNoDelay, TcpOptions};

    fn ready_session<T: crate::transport::WireOps>(
        transport: T,
        status: TransactionStatus,
    ) -> Session<T> {
        let config = TcpConfig::plaintext(
            "127.0.0.1:5432".parse().unwrap(),
            "resource_fixture",
            "resource_fixture",
            AuthenticationPolicy::AllowAuthenticationOk,
            crate::WireLimits {
                receive_capacity: 64,
                max_frame_len: 63,
                max_request_len: 64,
                max_messages_per_request: 8,
            },
            TcpOptions {
                send_policy: SendPolicy::BeforeBufferedRead,
                no_delay: TcpNoDelay::Enabled,
                #[cfg(target_os = "linux")]
                receive_buffer: crate::expert::linux::TcpReceiveBufferPolicy::SystemManaged,
            },
        );
        let (mut session, _) = Session::from_transport(transport, config, 1);
        // 在协议已 Ready 时继续验证本地传输完成，两者不能混为一谈。
        session.active = false;
        session.remaining_boundaries = 0;
        session.transaction_lease = true;
        session.transaction_status = status;
        session.transaction_end = Some(TransactionEnd::Committed);
        session
    }

    fn assert_fact<T: WireTransport>(transaction: &Transaction<'_, T>, status: TransactionStatus) {
        assert_eq!(transaction.transaction_status(), status);
        assert!(transaction.session.transaction_lease);
        assert_eq!(
            transaction.session.transaction_end,
            Some(TransactionEnd::Committed)
        );
    }

    #[test]
    fn transaction_controls_preserve_pending_native_packet_and_end_facts() {
        use std::{
            io,
            net::{TcpListener, TcpStream},
        };
        for status in [
            TransactionStatus::InTransaction,
            TransactionStatus::FailedTransaction,
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_nonblocking(true).unwrap();
            let runtime = compio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let socket = compio::net::TcpStream::from_std(socket).unwrap();
                let mut transport = crate::transport::Transport::new(socket, 64, 63, 64).unwrap();
                transport.begin_send(b"unretired native packet".to_vec()).unwrap();
                let mut session = ready_session(transport, status);
                let mut transaction = Transaction { session: &mut session };
                assert!(matches!(transaction.set_send_policy(SendPolicy::CoalesceBuffered), Err(Error::Busy)));
                assert!(matches!(transaction.trim_send_buffer(), Err(Error::Busy)));
                #[cfg(feature = "window-cache")]
                assert!(matches!(transaction.set_window_send_cache(crate::expert::WindowSendCache::ReleaseAfterWindow), Err(Error::Busy)));
                assert_eq!(transaction.send_policy(), SendPolicy::BeforeBufferedRead);
                assert_fact(&transaction, status);
                let mut byte = [0];
                assert!(matches!(peer.peek(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                transaction.session.transport.finish_send().await.unwrap();
                transaction.set_send_policy(SendPolicy::CoalesceBuffered).unwrap();
                assert!(transaction.trim_send_buffer().unwrap() > 0);
                assert_fact(&transaction, status);
                transaction.session.transaction_status = TransactionStatus::Idle;
                assert!(matches!(transaction.set_send_policy(SendPolicy::BeforeBufferedRead), Err(Error::Unsupported(_))));
                assert!(matches!(transaction.trim_send_buffer(), Err(Error::Unsupported(_))));
                assert_fact(&transaction, TransactionStatus::Idle);
                drop(transaction);
                assert!(session.transaction_lease);
                session.transport.close().await.unwrap();
            });
        }
    }

    #[cfg(feature = "tls")]
    mod buffered {
        use super::*;
        use futures_util::io::AsyncWrite;
        use std::{
            cell::Cell,
            io,
            pin::Pin,
            rc::Rc,
            task::{Context, Poll, Waker},
        };

        struct DeferredFlush {
            ready: Rc<Cell<bool>>,
            writes: Rc<Cell<usize>>,
            flushes: Rc<Cell<usize>>,
        }
        impl AsyncWrite for DeferredFlush {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.writes.set(self.writes.get() + 1);
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flushes.set(self.flushes.get() + 1);
                if self.ready.get() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                panic!("local TX resource controls must not close");
            }
        }
        impl crate::buffered::ManagedStream for DeferredFlush {
            fn plaintext(&mut self) -> io::Result<&[u8]> {
                panic!("local TX resource controls must not inspect plaintext");
            }

            fn consume_plaintext(&mut self, _: usize) -> Result<(), Error> {
                panic!("local TX resource controls must not consume plaintext");
            }

            fn poll_plaintext(&mut self, _: &mut Context<'_>) -> Poll<io::Result<usize>> {
                panic!("local TX resource controls must not read");
            }

            async fn dispose(self) -> Result<(), Error> {
                Ok(())
            }
        }

        #[test]
        fn transaction_controls_do_not_flush_or_release_pending_tls_backing() {
            for status in [
                TransactionStatus::InTransaction,
                TransactionStatus::FailedTransaction,
            ] {
                let ready = Rc::new(Cell::new(false));
                let writes = Rc::new(Cell::new(0));
                let flushes = Rc::new(Cell::new(0));
                let stream = DeferredFlush {
                    ready: ready.clone(),
                    writes: writes.clone(),
                    flushes: flushes.clone(),
                };
                let mut transport =
                    crate::buffered::BufferedTransport::new(stream, 64, 63, 64).unwrap();
                transport.begin_send(b"pending TLS flush".to_vec()).unwrap();
                let mut context = Context::from_waker(Waker::noop());
                assert!(transport.poll_finish_send(&mut context).is_pending());
                let before = (writes.get(), flushes.get());
                let mut session = ready_session(transport, status);
                let mut transaction = Transaction {
                    session: &mut session,
                };
                assert!(matches!(
                    transaction.set_send_policy(SendPolicy::CoalesceBuffered),
                    Err(Error::Busy)
                ));
                assert!(matches!(transaction.trim_send_buffer(), Err(Error::Busy)));
                #[cfg(feature = "window-cache")]
                assert!(matches!(
                    transaction
                        .set_window_send_cache(crate::expert::WindowSendCache::ReleaseAfterWindow),
                    Err(Error::Busy)
                ));
                assert_eq!((writes.get(), flushes.get()), before);
                assert_eq!(transaction.send_policy(), SendPolicy::BeforeBufferedRead);
                assert_fact(&transaction, status);
                ready.set(true);
                assert!(matches!(
                    transaction.session.transport.poll_finish_send(&mut context),
                    Poll::Ready(Ok(()))
                ));
                transaction
                    .set_send_policy(SendPolicy::CoalesceBuffered)
                    .unwrap();
                assert!(transaction.trim_send_buffer().unwrap() > 0);
                assert_eq!(transaction.trim_send_buffer().unwrap(), 0);
                assert_fact(&transaction, status);
            }
        }
    }
}
