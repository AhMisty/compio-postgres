//! 从有限迭代器持续补充有界请求窗口；恢复只处理已接纳成员，不再轮询被放弃的输入。
use super::ProvisionalWindowErrorOrigin as ErrorOrigin;
use super::{
    MemberRead, MemberReadOptions, PipelineProgress, PipelineResult, ReadyBatchEvent,
    ReadyBatchResult,
};
use crate::error::OnError;
use crate::transport::WireOps;
use crate::{
    Error, Session, WireTransport,
    client::{
        Transaction,
        general::{PreparedStatement, QueryLimits, WorkKind},
        pipeline::PipelineItem,
    },
    frontend::WindowExecutionLayout,
    protocol::TransactionStatus,
    row::{AllocationPolicy, OwnedBatch},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::{TransportExt, sealed::WindowStorage},
    types::Parameter,
};
use std::{fmt, ops::ControlFlow, rc::Rc};

/// 参数可由调用方借出或内联存储。无参数时使用 `Borrowed(&[])`。
/// 驱动在释放借用前完成编码，无需为每个请求分配向量。
pub enum WindowParameters<'a> {
    One(Parameter<'a>),
    Borrowed(&'a [Parameter<'a>]),
}
impl WindowParameters<'_> {
    pub(in crate::client) fn as_slice(&self) -> &[Parameter<'_>] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Borrowed(values) => values,
        }
    }
}
pub struct WindowRequest<'a> {
    pub statement: &'a PreparedStatement,
    pub parameters: WindowParameters<'a>,
    pub limits: QueryLimits,
}

/// max_result_bytes 限制当前复用的结果缓冲或普通诊断。
/// 输入、调用方副本和内核分配另计。
/// 发送最多使用两个队列大小的缓冲，分别存放当前和下一个包。
/// 窗口间可复用空缓冲，也可通过 trim_send_buffer 释放。
#[derive(Debug, Clone, Copy)]
pub struct WindowLimits {
    pub max_inflight: usize,
    pub max_requests: usize,
    pub max_rows: usize,
    pub max_result_bytes: usize,
    /// 回调返回后使用的分配及跨布局复用策略。
    pub storage: AllocationPolicy,
    pub max_queued_request_bytes: usize,
    /// 接纳和所有响应帧共用的调度预算。
    pub scheduling: ExecutionScheduling,
}
#[derive(Debug, Clone, Copy)]
pub struct WindowCompletion {
    /// 已读取的输入项数，含失败项和未发送的预读项，不含迭代结束。
    /// 无法据此确定重试位置。
    pub consumed: usize,
    /// 交给传输队列的成员数。
    /// 服务器可能尚未收到、执行或提交。
    pub admitted: usize,
    /// 已收到 ReadyForQuery 的成员数。
    pub confirmed: usize,
    pub delivered: usize,
    pub sql_errors: usize,
    pub stopped: bool,
    pub admission_limit_reached: bool,
    pub transaction_status: TransactionStatus,
}
pub struct WindowError {
    pub consumed: usize,
    pub admitted: usize,
    pub confirmed: usize,
    pub delivered: usize,
    /// 出错前是否已因回调或事务状态停止接纳。
    pub stopped: bool,
    /// 首次失败时最后观察到的事务状态。
    pub transaction_status: TransactionStatus,
    /// 首次失败时是否仍须结束事务或领取确认的事务结束结果。
    pub needs_transaction_decision: bool,
    pub source: Error,
    pub may_have_executed: bool,
    pub origin: ErrorOrigin,
    pub cleanup_error: Option<Box<Error>>,
}
impl WindowError {
    fn before_admission<T: WireTransport>(source: Error, session: &Session<T>) -> Self {
        Self {
            consumed: 0,
            admitted: 0,
            confirmed: 0,
            delivered: 0,
            stopped: false,
            transaction_status: session.transaction_status,
            needs_transaction_decision: session.transaction_status != TransactionStatus::Idle
                || session.transaction_lease
                || session.transaction_end.is_some(),
            source,
            may_have_executed: false,
            origin: ErrorOrigin::Input,
            cleanup_error: None,
        }
    }
}
impl fmt::Debug for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowError")
            .field("consumed", &self.consumed)
            .field("admitted", &self.admitted)
            .field("confirmed", &self.confirmed)
            .field("delivered", &self.delivered)
            .field("stopped", &self.stopped)
            .field("transaction_status", &self.transaction_status)
            .field(
                "needs_transaction_decision",
                &self.needs_transaction_decision,
            )
            .field("source", &self.source)
            .field("origin", &self.origin)
            .field("cleanup_error", &self.cleanup_error)
            .finish()
    }
}
impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "request window stopped after {} confirmed members: {}",
            self.confirmed, self.source
        )
    }
}
impl std::error::Error for WindowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Default)]
struct Counts {
    consumed: usize,
    admitted: usize,
    confirmed: usize,
    delivered: usize,
    sql_errors: usize,
    stopped: bool,
}

struct WindowRun {
    in_transaction: bool,
    on_error: OnError,
    diagnostic_limit: Option<usize>,
    failure_origin: Option<ErrorOrigin>,
}

impl<T: WireTransport> Session<T> {
    /// 从有限或显式限量的迭代器增量补充窗口，每个成员独立 Sync。
    /// 接纳时才校验输入，计算包大小时最多预读一个成员；协作编码可在发送前挂起。
    /// 放弃会使已读取但未提交的输入失去，恢复只排空已提交的成员。
    /// Break 停止接纳和回调后排空在途结果。
    /// 达到 `max_requests` 时完成此前缀，未读取的输入留给调用方。
    /// `on_error` 指定本地失败的处置。自动排空使用尚未收到 Ready 的已接纳成员的行与字节限额之和，
    /// 行数另受 `limits.max_rows` 约束。清理达到限额时保留原错误，可用显式恢复继续排空。
    /// 依赖状态变化时应分批提交。
    pub async fn query_window<'input>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        on_error: OnError,
        on_result: &mut (
                 impl for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<ControlFlow<()>, Error> + ?Sized
             ),
    ) -> Result<WindowCompletion, WindowError> {
        self.query_window_scoped(source, limits, on_error, on_result, false)
            .await
    }

    async fn query_window_scoped<'input>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        on_error: OnError,
        on_result: &mut (
                 impl for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<ControlFlow<()>, Error> + ?Sized
             ),
        in_transaction: bool,
    ) -> Result<WindowCompletion, WindowError> {
        self.query_window_owned_scoped(
            source,
            limits,
            &mut |index, transaction_status, outcome: PipelineItem| {
                let flow = match &outcome {
                    Ok(PipelineResult { rows, completion }) => on_result(ReadyBatchEvent {
                        index,
                        transaction_status,
                        outcome: Ok(ReadyBatchResult {
                            rows,
                            completion: *completion,
                        }),
                    }),
                    Err(error) => on_result(ReadyBatchEvent {
                        index,
                        transaction_status,
                        outcome: Err(error),
                    }),
                }?;
                Ok((flow, outcome.ok().map(|result| result.rows)))
            },
            in_transaction,
            on_error,
        )
        .await
    }

    /// 每个 Ready 结果只转移一次。
    /// 接收方可保留整个结果，也可归还行缓冲供下一成员清空后复用。
    pub(in crate::client) async fn query_window_owned_scoped<'input, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        on_ready: &mut F,
        in_transaction: bool,
        on_error: OnError,
    ) -> Result<WindowCompletion, WindowError>
    where
        F: FnMut(
                usize,
                TransactionStatus,
                PipelineItem,
            ) -> Result<(ControlFlow<()>, Option<OwnedBatch>), Error>
            + ?Sized,
    {
        self.query_window_owned_with_diagnostics::<false, _>(
            source,
            limits,
            || Ok(on_ready),
            in_transaction,
            on_error,
            None,
        )
        .await
        .map_err(|(error, _)| error)
    }

    pub(in crate::client) async fn query_window_owned_with_diagnostics<
        'input,
        const ORDINARY: bool,
        F,
    >(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        open_output: impl FnOnce() -> Result<F, Error>,
        in_transaction: bool,
        on_error: OnError,
        diagnostic_limit: Option<usize>,
    ) -> Result<WindowCompletion, (WindowError, usize)>
    where
        F: FnMut(
            usize,
            TransactionStatus,
            PipelineItem,
        ) -> Result<(ControlFlow<()>, Option<OwnedBatch>), Error>,
    {
        self.check_idle_access(in_transaction)
            .map_err(|error| (WindowError::before_admission(error, self), 0))?;
        let mut counts = Counts::default();
        let mut run = WindowRun {
            in_transaction,
            on_error,
            diagnostic_limit,
            failure_origin: None,
        };
        let result = self
            .window_inner::<ORDINARY, _>(source, limits, open_output, &mut counts, &mut run)
            .await;
        match result {
            Ok(()) => Ok(WindowCompletion {
                consumed: counts.consumed,
                admitted: counts.admitted,
                confirmed: counts.confirmed,
                delivered: counts.delivered,
                sql_errors: counts.sql_errors,
                stopped: counts.stopped,
                admission_limit_reached: counts.admitted == limits.max_requests,
                transaction_status: self.transaction_status,
            }),
            Err(source) => {
                let origin = run
                    .failure_origin
                    .unwrap_or_else(|| window_error_origin(&source));
                let transaction_status = self.transaction_status;
                let needs_transaction_decision = transaction_status != TransactionStatus::Idle
                    || self.transaction_lease
                    || self.transaction_end.is_some();
                let local = matches!(
                    origin,
                    ErrorOrigin::Input | ErrorOrigin::Callback | ErrorOrigin::Resource
                );
                let panicked = self
                    .extended
                    .as_ref()
                    .is_some_and(|state| state.callback_aborted());
                let mut cleanup_error = None;
                if panicked || !local {
                    self.transport.break_connection();
                } else if self.active && counts.admitted == 0 && !self.transport.is_broken() {
                    let _ = self.transport.disable_send_queue();
                    self.active = false;
                    if let Some(extended) = self.extended.as_mut() {
                        extended.clear_work();
                    }
                } else if self.active {
                    match on_error {
                        OnError::RecoverExplicitly => {}
                        OnError::DrainToReady => {
                            cleanup_error = self
                                .drain_window_to_ready(limits.max_rows, None, diagnostic_limit)
                                .await
                                .err()
                                .map(Box::new);
                        }
                        OnError::Discard => self.transport.break_connection(),
                    }
                }
                Err((
                    WindowError {
                        consumed: counts.consumed,
                        admitted: counts.admitted,
                        confirmed: counts.confirmed,
                        delivered: counts.delivered,
                        stopped: counts.stopped,
                        transaction_status,
                        needs_transaction_decision,
                        may_have_executed: counts.admitted != 0,
                        source,
                        origin,
                        cleanup_error,
                    },
                    counts.sql_errors,
                ))
            }
        }
    }

    async fn window_inner<'input, const ORDINARY: bool, F>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        open_output: impl FnOnce() -> Result<F, Error>,
        counts: &mut Counts,
        run: &mut WindowRun,
    ) -> Result<(), Error>
    where
        F: FnMut(
            usize,
            TransactionStatus,
            PipelineItem,
        ) -> Result<(ControlFlow<()>, Option<OwnedBatch>), Error>,
    {
        let quantum = ExecutionQuantum::new(limits.scheduling);
        let input_limit = if ORDINARY {
            Some(
                super::BatchInputLimit::check(source, limits.max_requests)
                    .inspect_err(|_| run.failure_origin = Some(ErrorOrigin::Input))?,
            )
        } else {
            None
        };
        if limits.max_requests == 0 {
            if let Some(limit) = input_limit {
                limit
                    .finish(source, 0, false, &mut counts.consumed)
                    .inspect_err(|_| run.failure_origin = Some(ErrorOrigin::Input))?;
            }
            return Ok(());
        }
        if limits.max_inflight == 0 {
            return Err(Error::InvalidInput(
                "request window needs positive in-flight capacity",
            ));
        }
        let max_capacity = limits.max_inflight.min(limits.max_requests);
        if compio::runtime::CancelToken::current()
            .await
            .is_some_and(|token| token.is_cancelled())
        {
            run.failure_origin = Some(ErrorOrigin::Input);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "request window was cancelled before admission",
            )
            .into());
        }
        crate::transport::SendQueue::validate_limit(
            limits.max_queued_request_bytes,
            self.max_request_len,
        )?;
        // 读取首项时会话仍为空闲，迭代器异常退出不会改变协议状态。
        let Some(first) = source.next() else {
            return Ok(());
        };
        counts.consumed = 1;
        let first = first.inspect_err(|_| run.failure_origin = Some(ErrorOrigin::Input))?;
        let capacity = input_limit
            .as_ref()
            .map_or(max_capacity, |limit| limit.window_capacity(max_capacity));
        let mut startup = Some((open_output, quantum));
        let mut on_ready = None;
        let mut pending = Some((first, None::<WindowExecutionLayout>));
        let mut source_ended = false;
        let mut remaining_rows = limits.max_rows;
        let mut reusable = None;
        let mut discard_remainder = false;
        loop {
            if compio::runtime::CancelToken::current()
                .await
                .is_some_and(|token| token.is_cancelled())
            {
                run.failure_origin = Some(ErrorOrigin::Input);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "request window was cancelled",
                )
                .into());
            }
            if self.transaction_status == TransactionStatus::FailedTransaction
                || (run.in_transaction
                    && (self.transaction_status == TransactionStatus::Idle
                        || self.transaction_end.is_some()))
            {
                counts.stopped = true;
            }
            let before = self.remaining_boundaries;
            let mut available = if self.active {
                self.transport.send_queue_available()
            } else {
                limits.max_queued_request_bytes
            };
            let mut admitted = 0;
            while before + admitted < capacity
                && admitted < limits.max_requests - counts.admitted
                && !source_ended
                && !counts.stopped
            {
                if pending.as_ref().is_some_and(|(_, layout)| {
                    layout
                        .as_ref()
                        .is_some_and(|layout| layout.encoded_len() > available)
                }) {
                    break;
                }
                let (request, layout) = if let Some(waiting) = pending.take() {
                    waiting
                } else {
                    run.failure_origin = Some(ErrorOrigin::Input);
                    match self.extension().invoke_callback(|| source.next()) {
                        Some(request) => {
                            counts.consumed += 1;
                            let request = request?;
                            run.failure_origin = None;
                            (request, None)
                        }
                        None => {
                            run.failure_origin = None;
                            source_ended = true;
                            break;
                        }
                    }
                };
                let admission = Self::resolve_prepared(
                    self.id,
                    self.extended.as_deref(),
                    request.statement,
                    true,
                )?;
                if layout.is_none() {
                    if request.limits.max_result_bytes > limits.max_result_bytes {
                        return Err(Error::Limit(
                            "window member arena exceeds its capacity domain",
                        ));
                    }
                    admission.validate_metadata(
                        request.limits.max_metadata_bytes,
                        "window member metadata exceeds its query limit",
                    )?;
                }
                let size = {
                    let plan = admission.window_packet(
                        request.parameters.as_slice(),
                        layout,
                        self.max_request_len,
                        "window parameter count differs from its statement",
                        "window parameter type differs from its statement",
                    )?;
                    let size = plan.encoded_len();
                    if layout.is_none() {
                        if size > limits.max_queued_request_bytes {
                            return Err(Error::Limit(
                                "window execution cannot fit its ready byte capacity",
                            ));
                        }
                        if size > available {
                            let layout = plan.window_layout();
                            pending = Some((request, Some(layout)));
                            break;
                        }
                    }
                    let append = |transport: &mut T::Io| {
                        plan.append_to(
                            transport.window_send_queue()?.staging_buffer()?,
                            limits.max_queued_request_bytes,
                        )
                    };
                    // 首项通过句柄、参数和单包限额检查后才分配输出、发送缓存和窗口。
                    if let Some((open, quantum)) = startup.take() {
                        on_ready = Some(open()?);
                        self.transport.start_window_send_queue(
                            limits.max_queued_request_bytes,
                            WindowStorage::InPlace,
                        )?;
                        self.active = true;
                        append(&mut self.transport)?;
                        let mut progress = PipelineProgress::window::<Rc<crate::row::RowLayout>>(
                            &mut self.extension().window_members,
                            capacity,
                            max_capacity,
                            quantum,
                        )?;
                        progress.on_error = Some(run.on_error);
                        self.extension().work_kind = Some(WorkKind::Pipeline(progress));
                    } else {
                        append(&mut self.transport)?;
                    }
                    size
                };
                self.window_progress_mut()?.stage_window_member(
                    Rc::clone(request.statement.shared_layout()),
                    request.limits,
                )?;
                available -= size;
                admitted += 1;
                let quantum = self.execution_quantum_mut()?;
                quantum.spend_bytes(size);
                quantum.yield_on_worker().await?;
            }
            if admitted != 0 {
                if compio::runtime::CancelToken::current()
                    .await
                    .is_some_and(|token| token.is_cancelled())
                {
                    run.failure_origin = Some(ErrorOrigin::Input);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "request window was cancelled before enqueue",
                    )
                    .into());
                }
                let boundaries = self
                    .remaining_boundaries
                    .checked_add(admitted)
                    .ok_or(Error::Limit("window boundary count overflow"))?;
                self.transport.window_send_queue()?.publish_staged()?;
                self.window_progress_mut()?.publish_window_members()?;
                self.remaining_boundaries = boundaries;
                counts.admitted += admitted;
            }
            if before + admitted == 0 {
                if !source_ended && !counts.stopped && counts.admitted < limits.max_requests {
                    return Err(Error::Broken);
                }
                if self.active {
                    self.transport.finish_send_on_owner().await?;
                    self.transport.disable_send_queue()?;
                    self.extension().clear_work();
                    self.active = false;
                }
                if let Some(limit) = input_limit {
                    limit
                        .finish(
                            source,
                            counts.admitted,
                            counts.stopped,
                            &mut counts.consumed,
                        )
                        .inspect_err(|_| run.failure_origin = Some(ErrorOrigin::Input))?;
                }
                return Ok(());
            }
            let (layout, member_limits) = self.window_progress_mut()?.take_window_member()?;
            let mut remaining_bytes = limits.max_result_bytes;
            let member_read = if discard_remainder {
                self.drain_pipeline_member(
                    &layout,
                    member_limits,
                    &mut remaining_rows,
                    run.diagnostic_limit,
                )
                .await?
            } else {
                self.read_pipeline_member_into(
                    &layout,
                    member_limits,
                    &mut remaining_rows,
                    &mut remaining_bytes,
                    reusable.take(),
                    MemberReadOptions {
                        storage: limits.storage,
                        diagnostic_limit: run.diagnostic_limit,
                    },
                )
                .await?
            };
            let index = counts.confirmed;
            let result = match member_read {
                MemberRead::Confirmed(item) => item,
                MemberRead::Drained { sql_error } => {
                    counts.confirmed += 1;
                    counts.sql_errors += usize::from(sql_error);
                    continue;
                }
                MemberRead::DiagnosticLimit(error) => {
                    counts.confirmed += 1;
                    counts.sql_errors += 1;
                    run.failure_origin = Some(ErrorOrigin::Resource);
                    return Err(error);
                }
                MemberRead::Fatal(error) => {
                    run.failure_origin = Some(ErrorOrigin::Server);
                    return Err(error);
                }
            };
            counts.confirmed += 1;
            if result.is_err() {
                counts.sql_errors += 1;
            }
            let transaction_status = self.transaction_status;
            let on_ready = on_ready.as_mut().ok_or(Error::Broken)?;
            run.failure_origin = Some(ErrorOrigin::Callback);
            let (flow, next_arena) = self
                .extension()
                .invoke_callback(|| on_ready(index, transaction_status, result))?;
            run.failure_origin = None;
            counts.delivered += 1;
            reusable = next_arena;
            if matches!(flow, ControlFlow::Break(())) {
                counts.stopped = true;
                discard_remainder = true;
                reusable = None;
            }
        }
    }

    fn window_progress_mut(&mut self) -> Result<&mut PipelineProgress, Error> {
        self.extended
            .as_mut()
            .and_then(|extended| extended.pipeline_progress_mut())
            .ok_or(Error::Broken)
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中使用与 [`Session::query_window`] 相同的窗口和本地错误策略。
    pub async fn query_window<'input>(
        &mut self,
        source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
        limits: WindowLimits,
        on_error: OnError,
        on_result: &mut (
                 impl for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<ControlFlow<()>, Error> + ?Sized
             ),
    ) -> Result<WindowCompletion, WindowError> {
        self.session_mut()
            .query_window_scoped(source, limits, on_error, on_result, true)
            .await
    }
}

fn window_error_origin(error: &Error) -> ErrorOrigin {
    match error {
        Error::Io(_) | Error::Authentication(_) => ErrorOrigin::Transport,
        Error::Protocol(_)
        | Error::Broken
        | Error::Unsupported(super::super::PIPELINE_TRANSACTION_CONFLICT) => ErrorOrigin::Protocol,
        Error::Database(_) => ErrorOrigin::Server,
        Error::Codec(error) => match error.as_ref() {
            crate::types::CodecError::Limit(_) | crate::types::CodecError::Allocation => {
                ErrorOrigin::Resource
            }
            _ => ErrorOrigin::Validation,
        },
        Error::Limit(_) => ErrorOrigin::Resource,
        _ => ErrorOrigin::Input,
    }
}
