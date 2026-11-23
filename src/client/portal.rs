use crate::transport::WireOps;
use std::{num::NonZeroU32, rc::Rc};

use super::{
    PreparedStatement, QueryCompletion, Session, Transaction, TransportExt, WireTransport,
    general::command_kind, is_fatal, owned_error, protocol_error, validate_parameter,
};
use crate::{
    DatabaseError, Error, frontend,
    protocol::{self, BackendMessage, TransactionStatus},
    row::{RowLayout, RowView},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    types::Parameter,
};

#[derive(Debug, Clone, Copy)]
pub struct PortalFetchLimits {
    /// 每次 Execute 最多返回的行数，上限为 i32::MAX。
    pub max_rows: NonZeroU32,
    /// 本次 fetch 的行字节上限，含每行的长度字段。
    pub max_result_bytes: usize,
    pub scheduling: ExecutionScheduling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalFetchCompletion {
    Suspended {
        rows_returned: usize,
    },
    /// 语句已完成，行数仅统计本次 fetch，事务保持打开。
    Complete(QueryCompletion),
}

/// 当前事务独占的命名 portal。
/// 构造时在本地编码 Bind，第一次 fetch 时随 Execute 和 Sync 一起发送。
/// 名称 `compio-postgres:portal` 由本会话保留。
///
/// 即使已取完结果，也须关闭 portal 才能执行其他语句或事务控制。
/// 放弃已绑定的 portal 或已提交的 fetch 时必须丢弃连接。
/// 尚未提交的 portal 可直接释放，连接仍可使用。
#[must_use = "要继续使用事务与连接，须关闭已绑定的 portal"]
pub struct Portal<'a, T: WireTransport> {
    session: &'a mut Session<T>,
    layout: Rc<RowLayout>,
    state: PortalState,
}

enum PortalState {
    Unbound(Vec<u8>),
    Bound,
    InFlight,
    Exhausted,
    Closed,
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中为 portal 编码待用 Bind，首次 fetch 时与 Execute、Sync 一同发送。
    pub fn portal(
        &mut self,
        statement: &PreparedStatement,
        parameters: &[Parameter<'_>],
    ) -> Result<Portal<'_, T>, Error> {
        let session = self.session_mut();
        session.check_idle_state(true)?;
        let admission = Session::<T>::resolve_prepared(
            session.id,
            session.extended.as_deref(),
            statement,
            true,
        )?;
        let matched = admission.parameters(
            parameters,
            "portal parameter count differs from the prepared statement",
        )?;
        let packet = frontend::bind_portal(
            || session.transport.take_send_buffer(),
            &matched,
            session.max_request_len,
            "portal parameter type differs from the prepared statement",
        )?;
        let layout = Rc::clone(admission.layout);
        Ok(Portal {
            session,
            layout,
            state: PortalState::Unbound(packet),
        })
    }
}

impl<T: WireTransport> Portal<'_, T> {
    pub fn layout(&self) -> &RowLayout {
        &self.layout
    }

    /// 用一次 Execute/Sync 获取最多 `limits.max_rows` 行。
    /// 行在 ReadyForQuery 前直接借给同步回调。
    /// 提交后若回调失败、panic 或超限，必须丢弃连接。
    /// 普通 SQL 错误会排空至 Ready 并释放 portal，允许回滚事务。
    pub async fn fetch_provisional<F>(
        &mut self,
        limits: PortalFetchLimits,
        on_row: F,
    ) -> Result<PortalFetchCompletion, Error>
    where
        F: for<'row> FnMut(RowView<'row, 'row>) -> Result<(), Error>,
    {
        if self.session.transport.is_broken() {
            return Err(Error::Broken);
        }
        self.session.check_runtime_owner()?;
        let wire_rows = i32::try_from(limits.max_rows.get())
            .map_err(|_| Error::InvalidInput("portal fetch row limit exceeds i32::MAX"))?;
        let max_rows = usize::try_from(limits.max_rows.get())
            .map_err(|_| Error::InvalidInput("portal fetch row limit exceeds usize::MAX"))?;
        let quantum = ExecutionQuantum::new(limits.scheduling);
        let max_bytes = self.session.max_request_len;
        let (packet, binding) = match &mut self.state {
            PortalState::Unbound(packet) => {
                frontend::append_portal_fetch(packet, wire_rows, max_bytes)?;
                (std::mem::take(packet), true)
            }
            PortalState::Bound => {
                let packet = self.session.transport.encode_send_buffer(|packet| {
                    frontend::append_portal_fetch(packet, wire_rows, max_bytes)
                })?;
                (packet, false)
            }
            PortalState::InFlight => return Err(Error::Broken),
            PortalState::Exhausted | PortalState::Closed => {
                return Err(Error::InvalidInput("the portal has no more rows"));
            }
        };
        self.state = PortalState::InFlight;
        let operation = PendingPortal::begin(self.session, packet, quantum)?;
        let (outcome, rows_returned) = operation
            .receive(
                PortalOperation::Fetch {
                    layout: &self.layout,
                    max_rows,
                    max_result_bytes: limits.max_result_bytes,
                },
                !binding,
                on_row,
            )
            .await?;
        match outcome {
            PortalOutcome::Suspended => {
                self.state = PortalState::Bound;
                Ok(PortalFetchCompletion::Suspended { rows_returned })
            }
            PortalOutcome::Complete(command, rows_affected) => {
                self.state = PortalState::Exhausted;
                Ok(PortalFetchCompletion::Complete(QueryCompletion {
                    command: Some(command),
                    rows_affected,
                    rows_returned,
                    transaction_status: TransactionStatus::InTransaction,
                    succeeded: true,
                }))
            }
            PortalOutcome::Failed(error) => {
                self.retire();
                Err(Error::Database(error))
            }
            PortalOutcome::Closed => Err(Error::Broken),
        }
    }

    /// 关闭服务端 portal，等待 Ready 和本地发送完成。
    /// 未提交的 portal 可直接关闭，无需 I/O。
    pub async fn close(mut self) -> Result<(), Error> {
        if matches!(self.state, PortalState::Unbound(_) | PortalState::Closed) {
            return Ok(());
        }
        if matches!(self.state, PortalState::InFlight) || self.session.transport.is_broken() {
            return Err(Error::Broken);
        }
        self.session.check_runtime_owner()?;
        let quantum = ExecutionQuantum::new(ExecutionScheduling::Uninterrupted);
        let buffer = self.session.transport.take_send_buffer()?;
        let packet = frontend::close_portal(buffer, self.session.max_request_len)?;
        let operation = PendingPortal::begin(self.session, packet, quantum)?;
        let (outcome, _) = operation
            .receive(PortalOperation::Close, true, |_| Ok(()))
            .await?;
        match outcome {
            PortalOutcome::Closed => {
                self.retire();
                Ok(())
            }
            PortalOutcome::Failed(error) => {
                self.retire();
                Err(Error::Database(error))
            }
            _ => Err(Error::Broken),
        }
    }

    fn retire(&mut self) {
        self.state = PortalState::Closed;
        self.session.active = false;
    }
}

impl<T: WireTransport> Drop for Portal<'_, T> {
    fn drop(&mut self) {
        match &mut self.state {
            PortalState::Unbound(packet) => {
                packet.clear();
                self.session
                    .transport
                    .retain_unused_send_buffer(std::mem::take(packet));
            }
            PortalState::Bound | PortalState::InFlight | PortalState::Exhausted => {
                self.session.transport.break_connection();
            }
            PortalState::Closed => {}
        }
    }
}

#[derive(Clone, Copy)]
enum PortalOperation<'a> {
    Fetch {
        layout: &'a RowLayout,
        max_rows: usize,
        max_result_bytes: usize,
    },
    Close,
}

enum PortalOutcome {
    Suspended,
    Complete(super::CommandKind, Option<u64>),
    Closed,
    Failed(DatabaseError),
}

struct PendingPortal<'a, T: WireTransport> {
    session: &'a mut Session<T>,
    quantum: ExecutionQuantum,
    finished: bool,
}

impl<'a, T: WireTransport> PendingPortal<'a, T> {
    fn begin(
        session: &'a mut Session<T>,
        packet: Vec<u8>,
        mut quantum: ExecutionQuantum,
    ) -> Result<Self, Error> {
        if session.remaining_boundaries != 0 {
            return Err(Error::Busy);
        }
        session.active = true;
        session.remaining_boundaries = 1;
        quantum.spend_bytes(packet.len());
        let pending = Self {
            session,
            quantum,
            finished: false,
        };
        pending.session.transport.begin_send(packet)?;
        Ok(pending)
    }

    async fn receive(
        mut self,
        operation: PortalOperation<'_>,
        mut bound: bool,
        mut on_row: impl for<'row> FnMut(RowView<'row, 'row>) -> Result<(), Error>,
    ) -> Result<(PortalOutcome, usize), Error> {
        let mut outcome = None;
        let mut rows = 0;
        let mut result_bytes = 0_usize;
        let mut controls = 0;
        self.quantum.yield_on_worker().await?;
        loop {
            self.session.transport.receive_frame_on_owner().await?;
            let frame = self.session.transport.frame()?;
            let wire_bytes = frame.body.len().saturating_add(5);
            if frame.tag != b'D' {
                if controls == self.session.max_messages {
                    return Err(Error::Limit("portal exceeded the control message limit"));
                }
                controls += 1;
            }
            let mut path_changed = false;
            let mut ready = None;
            let mut command = None;
            match protocol::parse_backend(frame)? {
                BackendMessage::BindComplete if !bound && outcome.is_none() => bound = true,
                BackendMessage::DataRow(row) if bound && outcome.is_none() => {
                    let PortalOperation::Fetch {
                        layout,
                        max_rows,
                        max_result_bytes,
                    } = operation
                    else {
                        return Err(protocol_error("received a row while closing a portal"));
                    };
                    if rows == max_rows {
                        return Err(protocol_error("portal exceeded the requested row count"));
                    }
                    result_bytes = result_bytes
                        .checked_add(row.encoded_fields().len().saturating_add(4))
                        .filter(|&bytes| bytes <= max_result_bytes)
                        .ok_or(Error::Limit("portal fetch exceeded the result byte limit"))?;
                    on_row(RowView::new(row, layout)?)?;
                    rows += 1;
                }
                BackendMessage::PortalSuspended
                    if bound
                        && outcome.is_none()
                        && matches!(operation, PortalOperation::Fetch { max_rows, .. } if rows == max_rows) =>
                {
                    outcome = Some(PortalOutcome::Suspended);
                }
                BackendMessage::CommandComplete(tag)
                    if bound
                        && outcome.is_none()
                        && matches!(operation, PortalOperation::Fetch { .. }) =>
                {
                    let (kind, affected) = command_kind(protocol::parse_command_tag(tag)?);
                    command = Some(kind);
                    outcome = Some(PortalOutcome::Complete(kind, affected));
                }
                BackendMessage::EmptyQueryResponse
                    if bound
                        && outcome.is_none()
                        && matches!(operation, PortalOperation::Fetch { .. }) =>
                {
                    outcome = Some(PortalOutcome::Complete(super::CommandKind::Empty, None));
                }
                BackendMessage::CloseComplete
                    if outcome.is_none() && matches!(operation, PortalOperation::Close) =>
                {
                    outcome = Some(PortalOutcome::Closed);
                }
                BackendMessage::ErrorResponse(error) => {
                    if is_fatal(error) {
                        return Err(Error::Database(owned_error(error)));
                    }
                    if !matches!(outcome, Some(PortalOutcome::Failed(_))) {
                        outcome = Some(PortalOutcome::Failed(owned_error(error)));
                    }
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    path_changed = name == "search_path";
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.session.notice_handler.as_ref())
                        .finish(&mut self.session.transport);
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ReadyForQuery(status) if outcome.is_some() => ready = Some(status),
                _ => {
                    return Err(protocol_error(
                        "unexpected response for the portal operation",
                    ));
                }
            }
            self.session.transport.consume_frame()?;
            if let Some(command) = command {
                self.session.record_query_transaction_end(command)?;
            }
            if path_changed {
                self.session.bump_schema_epoch()?;
            }
            self.quantum.spend_bytes(wire_bytes);
            if let Some(status) = ready {
                self.session.note_ready(status)?;
                let outcome = outcome.ok_or(Error::Broken)?;
                let expected_status = if matches!(outcome, PortalOutcome::Failed(_)) {
                    TransactionStatus::FailedTransaction
                } else {
                    TransactionStatus::InTransaction
                };
                if status != expected_status {
                    return Err(protocol_error(
                        "portal operation changed its transaction scope",
                    ));
                }
                self.quantum.yield_on_worker().await?;
                if let Err(send) = self.session.transport.finish_send_on_owner().await {
                    let diagnostic = match outcome {
                        PortalOutcome::Failed(error) => Some(error),
                        _ => None,
                    };
                    return Err(super::general::send_after_diagnostic(diagnostic, send));
                }
                self.finished = true;
                return Ok((outcome, rows));
            }
            self.quantum.yield_on_worker().await?;
        }
    }
}

impl<T: WireTransport> Drop for PendingPortal<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            self.session.transport.break_connection();
        }
    }
}
