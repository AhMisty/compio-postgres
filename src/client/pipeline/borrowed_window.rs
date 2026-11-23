//! 每个成员独立 Sync 的有界窗口，逐行借用尚未确认的结果。

use crate::transport::WireOps;
use std::{fmt, rc::Rc};

use super::{PipelineProgress, PipelineSignal, QueryRowLimits, WindowMemberLayout, WindowRequest};
use crate::{
    DatabaseError, Error, OnError, Session,
    client::{
        PreparedStatement, Transaction,
        general::{
            CommandKind, PreparedAdmission, QueryCompletion, WorkKind, command_kind,
            invoke_callback,
        },
        is_fatal, owned_error_bounded, protocol_error, terminal_database_error, validate_parameter,
    },
    frontend::WindowExecutionLayout,
    protocol::{self, BackendMessage, TransactionStatus},
    row::{RowConsumer, RowLayout, RowView, ScalarColumn},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::{TransportExt, WireTransport, sealed::WindowStorage},
    types::{CodecError, Decode},
};

/// 首次尝试提交数据包后，放弃该操作时如何处置会话。
/// 丢弃 future 不启动 I/O，遗忘 future 也遵守同一策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonPolicy {
    /// Abort、回调错误或放弃后，禁止继续使用会话。
    DiscardOnAbandon,
    /// 保留协议进度供显式调用 recover_to_ready。
    /// 恢复仅排空已提交结果，不重放 SQL、输入或回调。
    RecoverExplicitly,
}

impl AbandonPolicy {
    pub(in crate::client) fn on_error(self) -> OnError {
        match self {
            Self::DiscardOnAbandon => OnError::Discard,
            Self::RecoverExplicitly => OnError::RecoverExplicitly,
        }
    }
}

/// 回调可继续、停止接纳新输入，或立即终止交付。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionalWindowControl {
    Continue,
    /// 停止接纳，继续为所有已接纳的成员执行回调并排空数据。
    StopAdmission,
    /// 立即停止回调并返回 aborted 状态。
    /// 即使已观察到最后一个 Ready，仍按所选 AbandonPolicy 处置会话。
    Abort,
}

/// 借用交付的限额。
/// 单个成员受 QueryLimits 的行数、逻辑行字节和元数据限制；max_rows 与 max_row_bytes 覆盖整个操作，含后来发生 SQL 错误的暂定行。
/// 收发缓冲、恢复元数据、回调副本与最终传输错误另计。
#[derive(Debug, Clone, Copy)]
pub struct ProvisionalWindowLimits {
    pub max_inflight: usize,
    pub max_requests: usize,
    pub max_rows: usize,
    /// 各行字段的编码字节数之和，每行另计四字节长度。
    pub max_row_bytes: usize,
    pub max_queued_request_bytes: usize,
    /// 一个普通 SQL 错误的诊断存储上限，包含结构体和文本。
    /// 此专家入口的致命诊断受连接帧上限约束。
    pub max_diagnostic_bytes: usize,
    pub scheduling: ExecutionScheduling,
    pub abandon: AbandonPolicy,
}

/// 行与命令在该成员 Ready 前均为暂定。
/// Ready 确认独立 Sync 的结果；显式事务还须 COMMIT。
#[derive(Debug)]
pub enum ProvisionalWindowEvent<'row> {
    Row {
        index: usize,
        row: RowView<'row, 'row>,
    },
    Command {
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    },
    Ready {
        index: usize,
        transaction_status: TransactionStatus,
        outcome: Result<QueryCompletion, &'row DatabaseError>,
    },
}

/// 逐字段回调可能先读取有效前缀，再遇到无效后缀。
/// 即使回调返回 Abort 或 Err，驱动仍会检查整行。
/// 读取或解码失败后，两种处置策略都禁止复用。
#[derive(Debug)]
pub enum ProvisionalWindowConsumeEvent<'access, 'data, 'meta> {
    Row {
        index: usize,
        row: &'access mut RowConsumer<'data, 'meta>,
    },
    Command {
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    },
    Ready {
        index: usize,
        transaction_status: TransactionStatus,
        outcome: Result<QueryCompletion, &'access DatabaseError>,
    },
}

/// 已观察到的进度，含显式 Abort。
/// 交付计数只包含回调返回 Ok 且行结构完整有效的事件。
/// 回调报错、panic，或回调结束后发现未读后缀无效，都不能撤销调用方已经产生的副作用。
#[derive(Debug, Clone, Copy)]
pub struct ProvisionalWindowCompletion {
    /// 读取的输入项数，含失败项和已预读但未发送的项。
    /// 迭代结束不计数。
    pub consumed: usize,
    /// 已交给发送队列的成员数，不含私有编码和预读。
    /// 接纳本身不确认送达、执行或提交。
    pub admitted: usize,
    /// 已收到 ReadyForQuery 的成员数。
    /// 在显式事务中还须确认 COMMIT。
    pub confirmed: usize,
    pub events_delivered: usize,
    pub rows_delivered: usize,
    pub sql_errors: usize,
    /// 回调或事务状态已停止接纳，包含 Abort。
    pub stopped: bool,
    pub aborted: bool,
    /// 存在打开或失败的事务，或已观察到事务句柄结束，需调用方处理。
    pub needs_transaction_decision: bool,
    pub admission_limit_reached: bool,
    pub transaction_status: TransactionStatus,
}

/// 记录实际出错环节；例如回调返回 Error::Io 时来源仍是 Callback。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionalWindowErrorOrigin {
    Input,
    Callback,
    Resource,
    Transport,
    Protocol,
    Validation,
    Server,
}

pub struct ProvisionalWindowError {
    pub progress: ProvisionalWindowCompletion,
    pub origin: ProvisionalWindowErrorOrigin,
    pub source: Error,
    pub may_have_executed: bool,
}

impl ProvisionalWindowError {
    fn before_admission<T: WireTransport>(
        source: Error,
        limits: ProvisionalWindowLimits,
        session: &Session<T>,
    ) -> Self {
        let counts = Counts {
            needs_transaction_decision: session.transaction_lease
                || session.transaction_end.is_some(),
            ..Counts::default()
        };
        Self {
            progress: counts.summary(limits, session.transaction_status),
            origin: ProvisionalWindowErrorOrigin::Input,
            source,
            may_have_executed: false,
        }
    }
}

impl fmt::Debug for ProvisionalWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisionalWindowError")
            .field("progress", &self.progress)
            .field("origin", &self.origin)
            .field("source", &self.source)
            .field("may_have_executed", &self.may_have_executed)
            .finish()
    }
}
impl fmt::Display for ProvisionalWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "provisional window {:?} failure after {} confirmed members: {}",
            self.origin, self.progress.confirmed, self.source
        )
    }
}
impl std::error::Error for ProvisionalWindowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
pub(in crate::client) struct ProvisionalProgress {
    pub(in crate::client) pipeline: PipelineProgress,
    pub(in crate::client) abandon: AbandonPolicy,
    pub(in crate::client) started: bool,
}

struct Failure {
    origin: ProvisionalWindowErrorOrigin,
    source: Error,
}
impl Failure {
    fn input(source: Error) -> Self {
        Self {
            origin: ProvisionalWindowErrorOrigin::Input,
            source,
        }
    }
    fn encoding(source: Error) -> Self {
        if matches!(source, Error::Limit(_)) {
            Self::resource(source)
        } else {
            Self::input(source)
        }
    }
    fn callback(source: Error) -> Self {
        Self {
            origin: ProvisionalWindowErrorOrigin::Callback,
            source,
        }
    }
    fn resource(source: Error) -> Self {
        Self {
            origin: ProvisionalWindowErrorOrigin::Resource,
            source,
        }
    }
    fn validation(source: Error) -> Self {
        Self {
            origin: ProvisionalWindowErrorOrigin::Validation,
            source,
        }
    }
    fn protocol(source: Error) -> Self {
        Self {
            origin: ProvisionalWindowErrorOrigin::Protocol,
            source,
        }
    }
    fn wire(source: Error) -> Self {
        let origin = if matches!(source, Error::Protocol(_)) {
            ProvisionalWindowErrorOrigin::Protocol
        } else {
            ProvisionalWindowErrorOrigin::Transport
        };
        Self { origin, source }
    }
    fn recoverable(&self) -> bool {
        matches!(
            self.origin,
            ProvisionalWindowErrorOrigin::Input
                | ProvisionalWindowErrorOrigin::Callback
                | ProvisionalWindowErrorOrigin::Resource
        )
    }
}

impl WindowRequest<'_> {
    fn provisional_packet<'a>(
        &'a self,
        admission: &'a PreparedAdmission<'_>,
        layout: Option<WindowExecutionLayout>,
        max_request_len: usize,
        max_packet: usize,
        check_layout: impl FnOnce(&RowLayout) -> Result<(), Failure>,
    ) -> Result<crate::frontend::PreparedExecution<'a>, Failure> {
        if layout.is_none() {
            admission
                .validate_metadata(
                    self.limits.max_metadata_bytes,
                    "provisional member metadata exceeds its limit",
                )
                .map_err(Failure::encoding)?;
        }
        let plan = admission
            .window_packet(
                self.parameters.as_slice(),
                layout,
                max_request_len,
                "provisional parameter count or type differs from its statement",
                "provisional parameter count or type differs from its statement",
            )
            .map_err(Failure::encoding)?;
        if layout.is_none() {
            check_layout(admission.layout)?;
            if plan.encoded_len() > max_packet {
                return Err(Failure::resource(Error::Limit(
                    "provisional execution cannot fit its ready packet",
                )));
            }
        }
        Ok(plan)
    }
}

trait ProvisionalLayout: WindowMemberLayout {
    fn capture(statement: &PreparedStatement) -> Result<Self, Failure>;
    fn validate_body(&self, body: &[u8]) -> Result<(), Failure>;
}

impl ProvisionalLayout for Rc<RowLayout> {
    fn capture(statement: &PreparedStatement) -> Result<Self, Failure> {
        Ok(Rc::clone(statement.shared_layout()))
    }

    fn validate_body(&self, body: &[u8]) -> Result<(), Failure> {
        let row =
            protocol::parse_data_row(body).map_err(|error| Failure::validation(error.into()))?;
        RowView::new(row, self).map_err(|error| Failure::validation(error.into()))?;
        Ok(())
    }
}

impl ProvisionalLayout for ScalarColumn {
    fn capture(statement: &PreparedStatement) -> Result<Self, Failure> {
        // 接纳已校验类型和格式。显式恢复只使用列数。
        statement
            .layout()
            .scalar_column()
            .ok_or_else(|| Failure::protocol(Error::Broken))
    }

    fn validate_body(&self, body: &[u8]) -> Result<(), Failure> {
        structural_scalar(body).map(|_| ())
    }
}

trait Visitor {
    type Layout: ProvisionalLayout;
    const SCALAR: bool = Self::Layout::SCALAR;

    fn check_layout(&self, _layout: &RowLayout) -> Result<(), Failure> {
        Ok(())
    }

    fn row(
        &mut self,
        index: usize,
        body: &[u8],
        layout: &Self::Layout,
    ) -> Result<ProvisionalWindowControl, Failure>;
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<ProvisionalWindowControl, Failure>;
    fn ready(
        &mut self,
        index: usize,
        status: TransactionStatus,
        outcome: Result<QueryCompletion, DatabaseError>,
    ) -> Result<ProvisionalWindowControl, Failure>;
}

struct Checked<'callback, F: ?Sized>(&'callback mut F);
impl<F: ?Sized> Visitor for Checked<'_, F>
where
    F: for<'row> FnMut(ProvisionalWindowEvent<'row>) -> Result<ProvisionalWindowControl, Error>,
{
    type Layout = Rc<RowLayout>;

    fn row(
        &mut self,
        index: usize,
        body: &[u8],
        layout: &Self::Layout,
    ) -> Result<ProvisionalWindowControl, Failure> {
        let row =
            protocol::parse_data_row(body).map_err(|error| Failure::validation(error.into()))?;
        let row = RowView::new(row, layout).map_err(|error| Failure::validation(error.into()))?;
        self.0(ProvisionalWindowEvent::Row { index, row }).map_err(Failure::callback)
    }
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<ProvisionalWindowControl, Failure> {
        self.0(ProvisionalWindowEvent::Command {
            index,
            command,
            rows_affected,
            rows_returned,
        })
        .map_err(Failure::callback)
    }
    fn ready(
        &mut self,
        index: usize,
        transaction_status: TransactionStatus,
        outcome: Result<QueryCompletion, DatabaseError>,
    ) -> Result<ProvisionalWindowControl, Failure> {
        self.0(ProvisionalWindowEvent::Ready {
            index,
            transaction_status,
            outcome: outcome.as_ref().copied(),
        })
        .map_err(Failure::callback)
    }
}

struct Consuming<'callback, F: ?Sized>(&'callback mut F);
impl<F: ?Sized> Visitor for Consuming<'_, F>
where
    F: for<'access, 'data, 'meta> FnMut(
        ProvisionalWindowConsumeEvent<'access, 'data, 'meta>,
    ) -> Result<ProvisionalWindowControl, Error>,
{
    type Layout = Rc<RowLayout>;

    fn row(
        &mut self,
        index: usize,
        body: &[u8],
        layout: &Self::Layout,
    ) -> Result<ProvisionalWindowControl, Failure> {
        let mut row = RowConsumer::from_body(body, layout)
            .map_err(|error| Failure::validation(error.into()))?;
        let result = self.0(ProvisionalWindowConsumeEvent::Row {
            index,
            row: &mut row,
        });
        row.finish()
            .map_err(|error| Failure::validation(error.into()))?;
        result.map_err(Failure::callback)
    }
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<ProvisionalWindowControl, Failure> {
        self.0(ProvisionalWindowConsumeEvent::Command {
            index,
            command,
            rows_affected,
            rows_returned,
        })
        .map_err(Failure::callback)
    }
    fn ready(
        &mut self,
        index: usize,
        transaction_status: TransactionStatus,
        outcome: Result<QueryCompletion, DatabaseError>,
    ) -> Result<ProvisionalWindowControl, Failure> {
        self.0(ProvisionalWindowConsumeEvent::Ready {
            index,
            transaction_status,
            outcome: outcome.as_ref().copied(),
        })
        .map_err(Failure::callback)
    }
}

struct Scalars<'output, V, R, F> {
    output: &'output mut Vec<Result<R, DatabaseError>>,
    value: Option<V>,
    finish: F,
}

impl<V, R, F> Visitor for Scalars<'_, V, R, F>
where
    V: for<'row> Decode<'row>,
    F: Fn(Option<V>) -> Result<R, Error>,
{
    type Layout = ScalarColumn;

    fn check_layout(&self, layout: &RowLayout) -> Result<(), Failure> {
        let Some(column) = layout.scalar_column() else {
            return Err(Failure::input(Error::InvalidInput(
                "scalar batch requires exactly one result column",
            )));
        };
        column
            .validate::<V>()
            .map_err(|error| Failure::input(error.into()))
    }

    fn row(
        &mut self,
        _index: usize,
        body: &[u8],
        layout: &Self::Layout,
    ) -> Result<ProvisionalWindowControl, Failure> {
        let field = structural_scalar(body)?;
        if self.value.is_some() {
            return Err(Failure::validation(Error::InvalidInput(
                "scalar batch member received more than one result row",
            )));
        }
        self.value = Some(
            layout
                .decode(Some(field))
                .map_err(|error| Failure::validation(error.into()))?,
        );
        Ok(ProvisionalWindowControl::Continue)
    }

    fn command(
        &mut self,
        _index: usize,
        _command: CommandKind,
        _rows_affected: Option<u64>,
        _rows_returned: usize,
    ) -> Result<ProvisionalWindowControl, Failure> {
        Ok(ProvisionalWindowControl::Continue)
    }

    fn ready(
        &mut self,
        _index: usize,
        _status: TransactionStatus,
        outcome: Result<QueryCompletion, DatabaseError>,
    ) -> Result<ProvisionalWindowControl, Failure> {
        let value = self.value.take();
        let item = match outcome {
            Ok(_) => Ok((self.finish)(value).map_err(Failure::validation)?),
            Err(error) => Err(error),
        };
        if self.output.len() == self.output.capacity() {
            return Err(Failure::resource(Error::Limit(
                "scalar output exhausted its spare slots",
            )));
        }
        self.output.push(item);
        Ok(ProvisionalWindowControl::Continue)
    }
}

fn structural_scalar(body: &[u8]) -> Result<Option<&[u8]>, Failure> {
    protocol::parse_scalar_data_row(body)
        .map_err(|error| Failure::protocol(error.into()))?
        .ok_or_else(|| {
            Failure::protocol(
                CodecError::Invalid("row field count differs from its result layout").into(),
            )
        })
}

#[derive(Default)]
struct Counts {
    consumed: usize,
    admitted: usize,
    confirmed: usize,
    events: usize,
    rows_delivered: usize,
    rows_left: usize,
    row_bytes_left: usize,
    sql_errors: usize,
    stopped: bool,
    aborted: bool,
    needs_transaction_decision: bool,
}
impl Counts {
    fn apply(&mut self, control: ProvisionalWindowControl) {
        match control {
            ProvisionalWindowControl::Continue => {}
            ProvisionalWindowControl::StopAdmission => self.stopped = true,
            ProvisionalWindowControl::Abort => {
                self.stopped = true;
                self.aborted = true;
            }
        }
    }
    fn summary(
        &self,
        limits: ProvisionalWindowLimits,
        status: TransactionStatus,
    ) -> ProvisionalWindowCompletion {
        ProvisionalWindowCompletion {
            consumed: self.consumed,
            admitted: self.admitted,
            confirmed: self.confirmed,
            events_delivered: self.events,
            rows_delivered: self.rows_delivered,
            sql_errors: self.sql_errors,
            stopped: self.stopped,
            aborted: self.aborted,
            needs_transaction_decision: self.needs_transaction_decision
                || status != TransactionStatus::Idle,
            admission_limit_reached: self.admitted == limits.max_requests,
            transaction_status: status,
        }
    }
}

impl<T: WireTransport> Session<T> {
    /// 逐行借用已校验的结果，每个成员独立 Sync。
    /// 行和命令先于 Ready，后续 SQL 或 Sync 仍可能失败。
    /// StopAdmission 继续交付已接纳成员，Abort 立即停止。
    /// 普通 SQL 错误在 Ready 事件中报告，成功返回的进度也可能标记为 aborted。
    ///
    /// 回调返回错误后，只有 RecoverExplicitly 可恢复；回调 panic、非法行、协议或传输失败及致命服务器错误都须丢弃会话。
    /// 首次提交前可显式清理空前缀，之后按所选策略处置。
    /// 放弃或遗忘 future 不会启动 I/O。
    ///
    /// 为计算包大小或协作编码，可能已读取一段尚未提交的输入。
    /// 恢复不重放这些输入。
    /// 会话、schema 或事务变化影响后续 SQL 时，应分批提交。
    /// 事务内 Ready 后仍须确认 COMMIT。
    pub async fn query_window_provisional_visit<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'row> FnMut(ProvisionalWindowEvent<'row>) -> Result<ProvisionalWindowControl, Error>,
    {
        self.query_window_provisional_visit_scoped(source, limits, on_event, false)
            .await
    }

    async fn query_window_provisional_visit_scoped<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
        in_transaction: bool,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'row> FnMut(ProvisionalWindowEvent<'row>) -> Result<ProvisionalWindowControl, Error>,
    {
        self.provisional_window::<_, false>(source, limits, &mut Checked(on_event), in_transaction)
            .await
    }

    pub(in crate::client) async fn query_window_provisional_visit_ordinary_scoped<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
        in_transaction: bool,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'row> FnMut(ProvisionalWindowEvent<'row>) -> Result<ProvisionalWindowControl, Error>,
    {
        self.provisional_window::<_, true>(source, limits, &mut Checked(on_event), in_transaction)
            .await
    }

    pub(in crate::client) async fn collect_scalar_window<'input, V, R, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        output: &mut Vec<Result<R, DatabaseError>>,
        finish: F,
        in_transaction: bool,
        on_error: OnError,
    ) -> Result<ProvisionalWindowCompletion, (ProvisionalWindowError, Option<Box<Error>>)>
    where
        V: for<'row> Decode<'row>,
        F: Fn(Option<V>) -> Result<R, Error>,
    {
        self.check_idle_access(in_transaction).map_err(|source| {
            (
                ProvisionalWindowError::before_admission(source, limits, self),
                None,
            )
        })?;
        debug_assert_eq!(
            limits.abandon,
            match on_error {
                OnError::Discard => AbandonPolicy::DiscardOnAbandon,
                _ => AbandonPolicy::RecoverExplicitly,
            }
        );
        let mut counts = Counts::default();
        let mut visitor = Scalars {
            output,
            value: None::<V>,
            finish,
        };
        let result = self
            .provisional_window_inner::<_, true>(
                source,
                limits,
                &mut visitor,
                in_transaction,
                &mut counts,
            )
            .await;
        let Err(failure) = result else {
            return Ok(counts.summary(limits, self.transaction_status));
        };
        let progress = counts.summary(limits, self.transaction_status);
        let started = self.extended.as_ref().is_some_and(|extended| {
            matches!(extended.work_kind.as_ref(), Some(WorkKind::ProvisionalWindow(progress)) if progress.started)
        });
        let panicked = self
            .extended
            .as_ref()
            .is_some_and(|extended| extended.callback_aborted());
        let local =
            failure.recoverable() || failure.origin == ProvisionalWindowErrorOrigin::Validation;
        let mut cleanup_error = None;
        if panicked || !local {
            self.transport.break_connection();
        } else if !started && !self.transport.is_broken() {
            self.clear_provisional_window();
        } else {
            match on_error {
                OnError::RecoverExplicitly => {}
                OnError::DrainToReady => {
                    cleanup_error = self
                        .drain_window_to_ready(
                            limits.max_rows,
                            Some(limits.max_row_bytes),
                            Some(limits.max_diagnostic_bytes),
                        )
                        .await
                        .err()
                        .map(Box::new);
                }
                OnError::Discard => self.transport.break_connection(),
            }
        }
        Err((
            ProvisionalWindowError {
                progress,
                origin: failure.origin,
                source: failure.source,
                may_have_executed: started || counts.admitted != 0,
            },
            cleanup_error,
        ))
    }

    /// 顺序借用并校验字段，回调可能先观察到有效前缀。
    /// 忽略读取错误、返回 Abort 或用户错误均不能使无效后缀变为有效。
    /// 提交、放弃和独立 Sync 的语义同逐行访问入口。
    pub async fn query_window_provisional_consume<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'access, 'data, 'meta> FnMut(
                ProvisionalWindowConsumeEvent<'access, 'data, 'meta>,
            ) -> Result<ProvisionalWindowControl, Error>,
    {
        self.query_window_provisional_consume_scoped(source, limits, on_event, false)
            .await
    }

    async fn query_window_provisional_consume_scoped<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
        in_transaction: bool,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'access, 'data, 'meta> FnMut(
                ProvisionalWindowConsumeEvent<'access, 'data, 'meta>,
            ) -> Result<ProvisionalWindowControl, Error>,
    {
        self.provisional_window::<_, false>(
            source,
            limits,
            &mut Consuming(on_event),
            in_transaction,
        )
        .await
    }

    async fn provisional_window<'input, V: Visitor, const ORDINARY: bool>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        visitor: &mut V,
        in_transaction: bool,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError> {
        self.check_idle_access(in_transaction)
            .map_err(|source| ProvisionalWindowError::before_admission(source, limits, self))?;
        let mut counts = Counts::default();
        let result = self
            .provisional_window_inner::<_, ORDINARY>(
                source,
                limits,
                visitor,
                in_transaction,
                &mut counts,
            )
            .await;
        match result {
            Ok(()) => Ok(counts.summary(limits, self.transaction_status)),
            Err(failure) => {
                let started = self.extended.as_ref().is_some_and(|extended| {
                    matches!(extended.work_kind.as_ref(), Some(WorkKind::ProvisionalWindow(progress)) if progress.started)
                });
                if !failure.recoverable()
                    || self
                        .extended
                        .as_ref()
                        .is_some_and(|extended| extended.callback_aborted())
                    || (started && limits.abandon == AbandonPolicy::DiscardOnAbandon)
                {
                    self.transport.break_connection();
                } else if !started && !self.transport.is_broken() {
                    self.clear_provisional_window();
                }
                Err(ProvisionalWindowError {
                    progress: counts.summary(limits, self.transaction_status),
                    origin: failure.origin,
                    source: failure.source,
                    may_have_executed: started || counts.admitted != 0,
                })
            }
        }
    }

    fn clear_provisional_window(&mut self) {
        if !self.active {
            return;
        }
        let _ = self.transport.disable_send_queue();
        self.active = false;
        if let Some(extended) = self.extended.as_mut() {
            extended.clear_work();
        }
    }

    fn provisional_progress_mut(&mut self) -> Result<&mut ProvisionalProgress, Failure> {
        Self::provisional_progress(self.extended.as_deref_mut())
    }

    fn provisional_progress(
        extended: Option<&mut crate::client::general::Extended>,
    ) -> Result<&mut ProvisionalProgress, Failure> {
        match extended.and_then(|extended| extended.work_kind.as_mut()) {
            Some(WorkKind::ProvisionalWindow(progress)) => Ok(progress),
            _ => Err(Failure::protocol(Error::Broken)),
        }
    }

    async fn provisional_cancel_check(&self) -> Result<(), Failure> {
        if compio::runtime::CancelToken::current()
            .await
            .is_some_and(|token| token.is_cancelled())
        {
            Err(Failure::input(
                std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "provisional window was cancelled before admission",
                )
                .into(),
            ))
        } else {
            Ok(())
        }
    }

    async fn provisional_window_inner<'input, V: Visitor, const ORDINARY: bool>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        visitor: &mut V,
        in_transaction: bool,
        counts: &mut Counts,
    ) -> Result<(), Failure> {
        let quantum = ExecutionQuantum::new(limits.scheduling);
        counts.rows_left = limits.max_rows;
        counts.row_bytes_left = limits.max_row_bytes;
        let input_limit = if ORDINARY {
            Some(
                super::BatchInputLimit::check(source, limits.max_requests)
                    .map_err(Failure::input)?,
            )
        } else {
            None
        };
        if limits.max_requests == 0 {
            if let Some(limit) = input_limit {
                limit
                    .finish(source, 0, false, &mut counts.consumed)
                    .map_err(Failure::input)?;
            }
            return Ok(());
        }
        if limits.max_inflight == 0 {
            return Err(Failure::input(Error::InvalidInput(
                "provisional window needs positive in-flight capacity",
            )));
        }
        if limits.max_queued_request_bytes == 0
            || limits.max_queued_request_bytes > self.max_request_len
        {
            return Err(Failure::input(Error::InvalidInput(
                "provisional packet capacity must fit its connection request bound",
            )));
        }
        self.provisional_cancel_check().await?;
        let capacity = limits.max_inflight.min(limits.max_requests);
        // 读取首项时会话仍为空闲，迭代器异常退出不会改变协议状态。
        let Some(first) = source.next() else {
            return Ok(());
        };
        counts.consumed = 1;
        let first = first.map_err(Failure::input)?;
        let capacity = input_limit
            .as_ref()
            .map_or(capacity, |limit| limit.window_capacity(capacity));
        let mut startup = Some(quantum);
        let mut pending = Some((first, 0));
        let mut pending_layout = None;
        let mut source_ended = false;
        let cooperative = limits.scheduling != ExecutionScheduling::Uninterrupted;
        loop {
            self.provisional_cancel_check().await?;
            if self.transaction_status == TransactionStatus::FailedTransaction
                || (in_transaction
                    && (self.transaction_status == TransactionStatus::Idle
                        || self.transaction_end.is_some()))
            {
                counts.stopped = true;
                counts.needs_transaction_decision = true;
            }
            let before = self.remaining_boundaries;
            let mut admitted = if let Some(quantum) = startup.take() {
                if counts.stopped {
                    return Ok(());
                }
                let (first, _) = pending
                    .take()
                    .ok_or_else(|| Failure::protocol(Error::Broken))?;
                self.start_provisional_window(first, limits, visitor, capacity, quantum)?;
                if cooperative {
                    self.provisional_progress_mut()?
                        .pipeline
                        .quantum
                        .yield_on_worker()
                        .await
                        .map_err(Failure::wire)?;
                }
                1
            } else {
                0
            };
            let mut available = self.transport.send_queue_available();
            let staging = self
                .transport
                .window_send_queue()
                .and_then(|queue| queue.staging_buffer())
                .map_err(Failure::wire)?;
            let extended = self
                .extended
                .as_deref_mut()
                .ok_or_else(|| Failure::protocol(Error::Broken))?;
            while before + admitted < capacity
                && admitted < limits.max_requests - counts.admitted
                && !source_ended
                && !counts.stopped
            {
                if pending.as_ref().is_some_and(|(_, size)| *size > available) {
                    break;
                }
                let mut layout = None;
                let request = if let Some((waiting, _)) = pending.take() {
                    layout = pending_layout.take();
                    waiting
                } else {
                    match extended.invoke_callback(|| source.next()) {
                        Some(request) => {
                            counts.consumed += 1;
                            request.map_err(Failure::input)?
                        }
                        None => {
                            source_ended = true;
                            break;
                        }
                    }
                };
                let admission =
                    Self::resolve_prepared(self.id, Some(extended), request.statement, true)
                        .map_err(Failure::input)?;
                let size = {
                    let plan = request.provisional_packet(
                        &admission,
                        layout,
                        self.max_request_len,
                        limits.max_queued_request_bytes,
                        |layout| {
                            if V::SCALAR {
                                extended.invoke_callback(|| visitor.check_layout(layout))
                            } else {
                                Ok(())
                            }
                        },
                    )?;
                    let size = plan.encoded_len();
                    if layout.is_none() && size > available {
                        pending_layout = Some(plan.window_layout());
                        pending = Some((request, size));
                        break;
                    }
                    plan.append_to(staging, limits.max_queued_request_bytes)
                        .map_err(Failure::encoding)?;
                    size
                };
                let progress = &mut Self::provisional_progress(Some(extended))?.pipeline;
                progress
                    .stage_window_member(V::Layout::capture(request.statement)?, request.limits)
                    .map_err(Failure::protocol)?;
                available -= size;
                admitted += 1;
                if cooperative {
                    progress.quantum.spend_bytes(size);
                    progress
                        .quantum
                        .yield_on_worker()
                        .await
                        .map_err(Failure::wire)?;
                }
            }
            if admitted != 0 {
                self.provisional_cancel_check().await?;
                let boundaries =
                    self.remaining_boundaries
                        .checked_add(admitted)
                        .ok_or_else(|| {
                            Failure::resource(Error::Limit("provisional boundary count overflow"))
                        })?;
                let progress = Self::provisional_progress(self.extended.as_deref_mut())?;
                progress.started = true;
                self.transport
                    .window_send_queue()
                    .and_then(|queue| queue.publish_staged())
                    .map_err(Failure::wire)?;
                progress
                    .pipeline
                    .publish_window_members()
                    .map_err(Failure::protocol)?;
                self.remaining_boundaries = boundaries;
                counts.admitted += admitted;
            }
            if before + admitted == 0 {
                if !source_ended && !counts.stopped && counts.admitted < limits.max_requests {
                    return Err(Failure::protocol(Error::Broken));
                }
                self.transport
                    .finish_send_on_owner()
                    .await
                    .map_err(Failure::wire)?;
                self.transport.disable_send_queue().map_err(Failure::wire)?;
                self.active = false;
                self.extension().clear_work();
                if let Some(limit) = input_limit {
                    limit
                        .finish(
                            source,
                            counts.admitted,
                            counts.stopped,
                            &mut counts.consumed,
                        )
                        .map_err(Failure::input)?;
                }
                return Ok(());
            }
            let (layout, member_limits) = self
                .provisional_progress_mut()?
                .pipeline
                .take_window_member()
                .map_err(Failure::protocol)?;
            self.read_provisional_member::<_, ORDINARY>(
                &layout,
                member_limits,
                limits,
                visitor,
                counts,
            )
            .await?;
            if counts.aborted {
                return Ok(());
            }
        }
    }

    fn start_provisional_window<V: Visitor>(
        &mut self,
        first: WindowRequest<'_>,
        limits: ProvisionalWindowLimits,
        visitor: &V,
        capacity: usize,
        quantum: ExecutionQuantum,
    ) -> Result<(), Failure> {
        let admission =
            Self::resolve_prepared(self.id, self.extended.as_deref(), first.statement, true)
                .map_err(Failure::input)?;
        let plan = first.provisional_packet(
            &admission,
            None,
            self.max_request_len,
            limits.max_queued_request_bytes,
            |layout| visitor.check_layout(layout),
        )?;
        let size = plan.encoded_len();
        // 只有首项可接纳才启用发送缓存和恢复队列；私有编码期间仍无已提交成员。
        self.active = true;
        self.transport
            .start_window_send_queue(limits.max_queued_request_bytes, WindowStorage::InPlace)
            .map_err(|error| match error {
                Error::InvalidInput(_) | Error::Busy => Failure::input(error),
                Error::Limit(_) => Failure::resource(error),
                _ => Failure::wire(error),
            })?;
        let staging = self
            .transport
            .window_send_queue()
            .and_then(|queue| queue.staging_buffer())
            .map_err(Failure::wire)?;
        plan.append_to(staging, limits.max_queued_request_bytes)
            .map_err(Failure::encoding)?;
        let mut pipeline = PipelineProgress::window::<V::Layout>(
            &mut self.extension().window_members,
            capacity,
            limits.max_inflight.min(limits.max_requests),
            quantum,
        )
        .map_err(Failure::resource)?;
        pipeline
            .stage_window_member(V::Layout::capture(first.statement)?, first.limits)
            .map_err(Failure::protocol)?;
        pipeline.quantum.spend_bytes(size);
        self.extension().work_kind = Some(WorkKind::ProvisionalWindow(ProvisionalProgress {
            pipeline,
            abandon: limits.abandon,
            started: false,
        }));
        Ok(())
    }

    async fn read_provisional_member<V: Visitor, const ORDINARY: bool>(
        &mut self,
        layout: &V::Layout,
        member_limits: QueryRowLimits,
        limits: ProvisionalWindowLimits,
        visitor: &mut V,
        counts: &mut Counts,
    ) -> Result<(), Failure> {
        let index = counts.confirmed;
        let mut rows = 0_usize;
        let mut member_bytes_left = member_limits.max_result_bytes;
        let mut controls = 0_usize;
        let mut command = None;
        let mut failure = None;
        let mut diagnostic_limit_failure = None;
        let cooperative = limits.scheduling != ExecutionScheduling::Uninterrupted;
        if cooperative {
            self.provisional_progress_mut()?
                .pipeline
                .quantum
                .yield_on_worker()
                .await
                .map_err(Failure::wire)?;
        }
        loop {
            self.transport
                .receive_frame_on_owner()
                .await
                .map_err(Failure::wire)?;
            enum Action {
                Command(CommandKind, Option<u64>),
                Ready(TransactionStatus),
                Other,
            }
            let (action, work_bytes, path_changed) = {
                let frame = self.transport.frame().map_err(Failure::wire)?;
                let work_bytes = frame.body.len().saturating_add(5);
                let extended = self
                    .extended
                    .as_mut()
                    .ok_or_else(|| Failure::protocol(Error::Broken))?;
                let Some(WorkKind::ProvisionalWindow(progress)) = extended.work_kind.as_mut()
                else {
                    return Err(Failure::protocol(Error::Broken));
                };
                if frame.tag == b'D' {
                    progress
                        .pipeline
                        .validate_member_phase(PipelineSignal::Row)
                        .map_err(Failure::protocol)?;
                    let bytes =
                        super::data_row_record_len(frame.body).map_err(Failure::protocol)?;
                    if rows == member_limits.max_rows
                        || bytes > member_bytes_left
                        || counts.rows_left == 0
                        || bytes > counts.row_bytes_left
                    {
                        layout.validate_body(frame.body)?;
                        return Err(Failure::resource(Error::Limit(
                            "provisional row count or logical byte limit exceeded",
                        )));
                    }
                    rows += 1;
                    member_bytes_left -= bytes;
                    counts.rows_left -= 1;
                    counts.row_bytes_left -= bytes;
                    // 标量解码也可调用用户代码，遵循同一异常退出规则。
                    let result = invoke_callback(&extended.callback_in_progress, || {
                        visitor.row(index, frame.body, layout)
                    });
                    self.transport.consume_frame().map_err(Failure::wire)?;
                    let quantum = &mut progress.pipeline.quantum;
                    if cooperative {
                        quantum.spend_bytes(work_bytes);
                    }
                    let flow = result?;
                    if !V::SCALAR {
                        counts.events = counts.events.checked_add(1).ok_or_else(|| {
                            Failure::resource(Error::Limit("provisional event count overflow"))
                        })?;
                        counts.rows_delivered =
                            counts.rows_delivered.checked_add(1).ok_or_else(|| {
                                Failure::resource(Error::Limit(
                                    "provisional delivered row count overflow",
                                ))
                            })?;
                    }
                    counts.apply(flow);
                    if counts.aborted {
                        return Ok(());
                    }
                    if cooperative {
                        quantum.yield_on_worker().await.map_err(Failure::wire)?;
                    }
                    continue;
                }
                let message = protocol::parse_backend(frame)
                    .map_err(|error| Failure::protocol(error.into()))?;
                let signal = PipelineSignal::from_message(message).map_err(Failure::protocol)?;
                if let BackendMessage::ParameterStatus { name, value } = message {
                    validate_parameter(name, value).map_err(Failure::protocol)?;
                }
                let parsed_command = if let BackendMessage::CommandComplete(tag) = message {
                    Some(command_kind(
                        protocol::parse_command_tag(tag)
                            .map_err(|error| Failure::protocol(error.into()))?,
                    ))
                } else {
                    None
                };
                if let BackendMessage::ErrorResponse(error) = message
                    && is_fatal(error)
                {
                    return Err(Failure {
                        origin: ProvisionalWindowErrorOrigin::Server,
                        source: terminal_database_error(
                            error,
                            ORDINARY.then_some(limits.max_diagnostic_bytes),
                        ),
                    });
                }
                if controls == self.max_messages {
                    progress
                        .pipeline
                        .validate_member_phase(signal)
                        .map_err(Failure::protocol)?;
                    return Err(Failure::resource(Error::Limit(
                        "provisional member control limit exceeded",
                    )));
                }
                progress
                    .pipeline
                    .observe_member_signal(signal)
                    .map_err(Failure::protocol)?;
                controls += 1;
                let mut path_changed = false;
                let action = match message {
                    BackendMessage::BindComplete => Action::Other,
                    BackendMessage::CommandComplete(_) => {
                        let observed =
                            parsed_command.ok_or_else(|| Failure::protocol(Error::Broken))?;
                        command = Some(observed);
                        Action::Command(observed.0, observed.1)
                    }
                    BackendMessage::EmptyQueryResponse => {
                        command = Some((CommandKind::Empty, None));
                        Action::Command(CommandKind::Empty, None)
                    }
                    BackendMessage::ErrorResponse(error) => {
                        if failure.is_none() && diagnostic_limit_failure.is_none() {
                            let mut budget = limits.max_diagnostic_bytes;
                            match owned_error_bounded(error, &mut budget) {
                                Ok(error) => failure = Some(error),
                                Err(error) if ORDINARY => diagnostic_limit_failure = Some(error),
                                Err(error) => return Err(Failure::resource(error)),
                            }
                        }
                        Action::Other
                    }
                    BackendMessage::ReadyForQuery(status) => Action::Ready(status),
                    BackendMessage::ParameterStatus { name, .. } => {
                        path_changed = name == "search_path";
                        Action::Other
                    }
                    BackendMessage::NoticeResponse(notice) => {
                        crate::client::observe_notice(notice, self.notice_handler.as_ref())
                            .finish(&mut self.transport);
                        Action::Other
                    }
                    BackendMessage::NotificationResponse { .. } => Action::Other,
                    _ => {
                        return Err(Failure::protocol(protocol_error(
                            "unexpected provisional pipeline response",
                        )));
                    }
                };
                (action, work_bytes, path_changed)
            };
            self.transport.consume_frame().map_err(Failure::wire)?;
            if path_changed {
                self.bump_schema_epoch().map_err(Failure::protocol)?;
            }
            if let Action::Command(kind, _) = action {
                self.record_pipeline_transaction_end(kind)
                    .map_err(Failure::protocol)?;
            }
            if let Action::Ready(status) = action {
                self.note_ready(status).map_err(Failure::protocol)?;
                counts.confirmed += 1;
                if failure.is_some() || diagnostic_limit_failure.is_some() {
                    counts.sql_errors += 1;
                }
                if status == TransactionStatus::FailedTransaction
                    || (self.transaction_lease
                        && (status == TransactionStatus::Idle || self.transaction_end.is_some()))
                {
                    counts.stopped = true;
                    counts.needs_transaction_decision = true;
                }
            }
            let quantum = if cooperative {
                let quantum = &mut self.provisional_progress_mut()?.pipeline.quantum;
                quantum.spend_bytes(work_bytes);
                Some(quantum)
            } else {
                None
            };
            if let Some(quantum) = quantum {
                quantum.yield_on_worker().await.map_err(Failure::wire)?;
            }
            let result = match action {
                Action::Command(..) if V::SCALAR => None,
                Action::Command(kind, affected) => Some(
                    self.extension()
                        .invoke_callback(|| visitor.command(index, kind, affected, rows)),
                ),
                Action::Ready(status) => {
                    if let Some(error) = diagnostic_limit_failure {
                        return Err(Failure::resource(error));
                    }
                    let succeeded = failure.is_none();
                    let outcome = match failure.take() {
                        Some(error) => Err(error),
                        None => Ok(QueryCompletion {
                            command: command.map(|(kind, _)| kind),
                            rows_affected: command.and_then(|(_, rows)| rows),
                            rows_returned: rows,
                            transaction_status: status,
                            succeeded: true,
                        }),
                    };
                    let result = self
                        .extension()
                        .invoke_callback(|| visitor.ready(index, status, outcome));
                    if V::SCALAR && succeeded && result.is_ok() {
                        counts.rows_delivered += rows;
                    }
                    Some(result)
                }
                Action::Other => None,
            };
            if let Some(result) = result {
                let flow = result?;
                counts.events = counts.events.checked_add(1).ok_or_else(|| {
                    Failure::resource(Error::Limit("provisional event count overflow"))
                })?;
                counts.apply(flow);
            }
            if counts.aborted || matches!(action, Action::Ready(_)) {
                return Ok(());
            }
        }
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中借用已校验的暂定行，每个成员独立 Sync。
    /// 失败事务会停止接纳并排空在途成员，之后由调用方决定如何处理事务。
    pub async fn query_window_provisional_visit<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'row> FnMut(ProvisionalWindowEvent<'row>) -> Result<ProvisionalWindowControl, Error>,
    {
        self.session_mut()
            .query_window_provisional_visit_scoped(source, limits, on_event, true)
            .await
    }

    /// 逐字段消费暂定结果，使用与会话入口相同的放弃及控制策略。
    /// 读取或解码出错后须丢弃会话。
    pub async fn query_window_provisional_consume<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: ProvisionalWindowLimits,
        on_event: &mut F,
    ) -> Result<ProvisionalWindowCompletion, ProvisionalWindowError>
    where
        F: ?Sized
            + for<'access, 'data, 'meta> FnMut(
                ProvisionalWindowConsumeEvent<'access, 'data, 'meta>,
            ) -> Result<ProvisionalWindowControl, Error>,
    {
        self.session_mut()
            .query_window_provisional_consume_scoped(source, limits, on_event, true)
            .await
    }
}
