//! 按窗口接纳查询，逐项交付或收集批次结果。

use super::{ApiScope, Client, OnError, OwnedOutput, QueryResult, Statement, Transaction, core};
use crate::{
    BatchControl, BatchErrorOrigin, BatchEvent, DatabaseError, Error, ReadyBatchEvent,
    ReadyBatchResult,
    protocol::TransactionStatus,
    row::AllocationPolicy,
    scheduler::ExecutionScheduling,
    transport::{SendQueue, WireTransport},
    types::{Decode, Parameter},
};
use std::{fmt, marker::PhantomData, ops::ControlFlow};

/// 批次进度。
/// collect_ready 每保留一个已确认结果就计一次交付，rows_delivered 统计其中的行。
/// consumed 单独统计已读取的输入。
pub type BatchProgress = core::ProvisionalWindowCompletion;
pub type ReadyResult = Result<QueryResult, DatabaseError>;

/// 批次执行限额。
/// 每个成员独立发送 Sync。
/// 需要保留结果时，通过 OwnedOutput 指定存储预算。
/// `DrainToReady` 自动清理使用尚未确认的已接纳成员的行与字节限额之和。
/// 超限时保留首错与清理错误，可用 `recover_to_ready_with_limits` 继续排空。
#[derive(Debug, Clone, Copy)]
pub struct BatchOptions {
    pub member_limits: crate::QueryLimits,
    /// 整批输入的硬上限。
    /// 长度下界已超限时，发送前报错；长度未知时，已接纳前缀完成后可能额外读取一项来判定超限。
    /// 分批处理可传入 `iter.by_ref().take(n)`。
    pub max_requests: usize,
    /// 此连接上已接纳且尚待 Ready 确认的成员上限。非空批次至少为 1。
    pub max_inflight: usize,
    /// 待发送包的最大字节数，取值为 1 到连接的请求字节上限。
    pub max_queued_request_bytes: usize,
    /// 单个成员的诊断存储上限，包含结构体和所有字段。
    /// 致命诊断同样受限，超限后仍须丢弃连接。
    pub max_diagnostic_bytes: usize,
    pub scheduling: ExecutionScheduling,
}
impl BatchOptions {
    pub(super) fn validate(self, max_request_len: usize) -> Result<(), Error> {
        if self.max_requests != 0 && self.max_inflight == 0 {
            return Err(Error::InvalidInput(
                "a batch requires positive in-flight capacity",
            ));
        }
        SendQueue::validate_limit(self.max_queued_request_bytes, max_request_len)
    }

    fn provisional_limits(
        self,
        abandon: crate::AbandonPolicy,
    ) -> Result<core::ProvisionalWindowLimits, Error> {
        let Some(max_rows) = self.member_limits.max_rows.checked_mul(self.max_requests) else {
            return Err(Error::Limit("batch row bound overflow"));
        };
        let Some(max_row_bytes) = self
            .member_limits
            .max_result_bytes
            .checked_mul(self.max_requests)
        else {
            return Err(Error::Limit("batch byte bound overflow"));
        };
        Ok(core::ProvisionalWindowLimits {
            max_inflight: self.max_inflight,
            max_requests: self.max_requests,
            max_rows,
            max_row_bytes,
            max_queued_request_bytes: self.max_queued_request_bytes,
            max_diagnostic_bytes: self.max_diagnostic_bytes,
            scheduling: self.scheduling,
            abandon,
        })
    }
}

fn batch_profile<S: ApiScope>(
    scope: &S,
    selected: Option<BatchOptions>,
) -> Result<BatchOptions, Error> {
    match selected {
        Some(profile) => {
            profile.validate(scope.max_request_len())?;
            Ok(profile)
        }
        None => scope.profile().batch.ok_or(Error::InvalidInput(
            "this client requires an explicit batch profile",
        )),
    }
}

impl<T: WireTransport> Client<T> {
    /// 增量提交有界批次，每个成员独立 Sync。
    /// 输入可以逐项产生 [`BatchRequest`]，或产生 `Result<BatchRequest, Error>`。
    /// 为计算包大小可能预读一个输入，编码也可能在提交前让出执行权。
    /// 后续输入错误不撤销已提交前缀。
    /// 进度分别统计读取、提交和 Ready 确认；事务内还须确认 COMMIT。
    pub fn streaming_batch<'scope, 'query, I>(
        &'scope mut self,
        source: I,
    ) -> BatchBuilder<'scope, 'query, Self, I::IntoIter>
    where
        I: IntoIterator,
        I::Item: IntoBatchRequest<'query>,
    {
        BatchBuilder::new(self, source.into_iter())
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中增量提交有界批次。
    /// 输入校验、预读和进度语义见 [`Client::streaming_batch`]；每个成员的 Ready 确认后仍需提交事务。
    pub fn streaming_batch<'scope, 'query, I>(
        &'scope mut self,
        source: I,
    ) -> BatchBuilder<'scope, 'query, Self, I::IntoIter>
    where
        I: IntoIterator,
        I::Item: IntoBatchRequest<'query>,
    {
        BatchBuilder::new(self, source.into_iter())
    }
}

/// 用 [`Statement::bind`] 或 [`Statement::bind_one`] 创建的预备语句批次成员。
pub struct BatchRequest<'query> {
    statement: &'query Statement,
    parameters: core::WindowParameters<'query>,
}
impl Statement {
    /// 借用参数切片，无参数时传入 `&[]`。
    pub fn bind<'query>(
        &'query self,
        parameters: &'query [Parameter<'query>],
    ) -> BatchRequest<'query> {
        BatchRequest {
            statement: self,
            parameters: core::WindowParameters::Borrowed(parameters),
        }
    }
    /// 将一个参数直接存入批次成员，适合在迭代器中按需创建。
    pub fn bind_one<'query>(&'query self, parameter: Parameter<'query>) -> BatchRequest<'query> {
        BatchRequest {
            statement: self,
            parameters: core::WindowParameters::One(parameter),
        }
    }
}
#[doc(hidden)]
pub trait IntoBatchRequest<'query> {
    fn into_batch_request(self) -> Result<BatchRequest<'query>, Error>;
}
impl<'query> IntoBatchRequest<'query> for BatchRequest<'query> {
    fn into_batch_request(self) -> Result<BatchRequest<'query>, Error> {
        Ok(self)
    }
}
impl<'query> IntoBatchRequest<'query> for Result<BatchRequest<'query>, Error> {
    fn into_batch_request(self) -> Result<BatchRequest<'query>, Error> {
        self
    }
}

fn requests_with_limits<'query>(
    source: impl Iterator<Item: IntoBatchRequest<'query>>,
    limits: crate::QueryLimits,
) -> impl Iterator<Item = Result<core::WindowRequest<'query>, Error>> {
    source.map(move |item| {
        let request = item.into_batch_request()?;
        Ok(core::WindowRequest {
            statement: request.statement,
            parameters: request.parameters,
            limits,
        })
    })
}

#[must_use = "选择批次结果读取方式并等待完成后才会执行请求"]
pub struct BatchBuilder<'scope, 'query, S, I> {
    scope: &'scope mut S,
    source: I,
    profile: Option<BatchOptions>,
    marker: PhantomData<&'query ()>,
}
impl<'scope, 'query, S, I> BatchBuilder<'scope, 'query, S, I>
where
    S: ApiScope,
    I: Iterator,
    I::Item: IntoBatchRequest<'query>,
{
    fn new(scope: &'scope mut S, source: I) -> Self {
        Self {
            scope,
            source,
            profile: None,
            marker: PhantomData,
        }
    }

    pub fn with_options(mut self, profile: BatchOptions) -> Self {
        self.profile = Some(profile);
        self
    }

    /// 增量提交批次并收集已收到 Ready 的成员，每个成员独立 Sync。
    /// 后续输入无效不撤销已接纳前缀。
    /// 事务内还须确认 COMMIT。
    /// 结果缓冲直接移入报告。ReserveLimit 按输入长度上界检查描述符预算，上界未知时使用 max_requests。
    /// 首项通过语句、参数和单包限额检查后才预分配。
    ///
    /// `OwnedOutput::max_bytes` 覆盖保留的行、诊断和结果向量容量，预备语句元数据、临时扩容和正在填充的缓冲另计。
    /// 放弃 future 会失去部分结果，须按连接报告的状态恢复或丢弃。
    pub async fn collect_ready(
        self,
        output: OwnedOutput,
        on_error: OnError,
    ) -> Result<BatchReport, BatchError> {
        let allocation = output.allocation;
        let Self {
            scope,
            source,
            profile,
            ..
        } = self;
        let profile = batch_profile(scope, profile)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        let max_rows = profile
            .member_limits
            .max_rows
            .checked_mul(profile.max_requests)
            .ok_or_else(|| {
                BatchError::before_admission(Error::Limit("batch row bound overflow"), scope)
            })?;
        let limits = core::WindowLimits {
            max_inflight: profile.max_inflight,
            max_requests: profile.max_requests,
            max_rows,
            max_result_bytes: profile
                .member_limits
                .max_result_bytes
                .max(profile.max_diagnostic_bytes),
            storage: output.allocation,
            max_queued_request_bytes: profile.max_queued_request_bytes,
            scheduling: profile.scheduling,
        };
        let mut results = Vec::new();
        let mut reserved = 0;
        if allocation == AllocationPolicy::ReserveLimit {
            reserved = result_slots(&source, profile.max_requests);
            descriptor_capacity(reserved, 0, output.max_bytes)
                .map_err(|error| BatchError::before_admission(error, scope))?;
        }
        let mut source = requests_with_limits(source, profile.member_limits);
        let mut rows_delivered = 0usize;
        let (session, in_transaction) = scope.access();
        let stored = &mut results;
        let delivered = &mut rows_delivered;
        let result = session
            .query_window_owned_with_diagnostics::<true, _>(
                &mut source,
                limits,
                move || {
                    if reserved != 0 {
                        reserve_results(stored, reserved, reserved, 0, output.max_bytes)?;
                    }
                    let mut retained = 0usize;
                    Ok(move |_, _, item: ReadyResult| {
                        let bytes = result_retained_bytes(&item)?;
                        let next = retained
                            .checked_add(bytes)
                            .ok_or(Error::Limit("owned batch backing overflow"))?;
                        if stored.len() == stored.capacity() {
                            let required = stored.len() + 1;
                            let target = required
                                .max(stored.capacity().saturating_mul(2))
                                .min(profile.max_requests);
                            reserve_results(stored, required, target, next, output.max_bytes)?;
                        } else if next
                            .checked_add(
                                stored
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<ReadyResult>()),
                            )
                            .is_none_or(|bytes| bytes > output.max_bytes)
                        {
                            return Err(Error::Limit("owned batch exceeds retained output bound"));
                        }
                        if let Ok(result) = &item {
                            *delivered = delivered.saturating_add(result.rows.len());
                        }
                        retained = next;
                        stored.push(item);
                        Ok((ControlFlow::Continue(()), None))
                    })
                },
                in_transaction,
                on_error,
                Some(profile.max_diagnostic_bytes),
            )
            .await;
        match result {
            Ok(done) => Ok(BatchReport {
                results,
                progress: ready_progress(scope, done, rows_delivered, in_transaction),
            }),
            Err(failure) => Err(ready_error(
                scope,
                failure,
                results,
                rows_delivered,
                profile.max_requests,
                |origin| {
                    // 将内部结果存储错误归类为资源错误。
                    if origin == BatchErrorOrigin::Callback {
                        BatchErrorOrigin::Resource
                    } else {
                        origin
                    }
                },
            )),
        }
    }

    /// 逐个借用已收到 Ready 的结果缓冲，回调结束后可复用。
    /// Break 停止接纳和回调，仍排空已接纳成员，校验协议和行限额并统计 SQL 错误。
    pub async fn visit_ready<F>(
        self,
        output: OwnedOutput,
        on_error: OnError,
        mut on_result: F,
    ) -> Result<BatchProgress, BatchError<()>>
    where
        F: for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<ControlFlow<()>, Error>,
    {
        let Self {
            scope,
            source,
            profile,
            ..
        } = self;
        let profile = batch_profile(scope, profile)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        if profile.member_limits.max_result_bytes > output.max_bytes {
            return Err(BatchError::before_admission(
                Error::Limit("member arena exceeds the Ready visitor's bound"),
                scope,
            ));
        }
        let max_rows = profile
            .member_limits
            .max_rows
            .checked_mul(profile.max_requests)
            .ok_or_else(|| {
                BatchError::before_admission(Error::Limit("batch row bound overflow"), scope)
            })?;
        let limits = core::WindowLimits {
            max_inflight: profile.max_inflight,
            max_requests: profile.max_requests,
            max_rows,
            max_result_bytes: output.max_bytes,
            storage: output.allocation,
            max_queued_request_bytes: profile.max_queued_request_bytes,
            scheduling: profile.scheduling,
        };
        let mut source = requests_with_limits(source, profile.member_limits);
        let mut rows_delivered = 0usize;
        let (session, in_transaction) = scope.access();
        let result = session
            .query_window_owned_with_diagnostics::<true, _>(
                &mut source,
                limits,
                || {
                    Ok(|index, transaction_status, outcome: ReadyResult| {
                        let flow = match &outcome {
                            Ok(result) => {
                                let flow = on_result(ReadyBatchEvent {
                                    index,
                                    transaction_status,
                                    outcome: Ok(ReadyBatchResult {
                                        rows: &result.rows,
                                        completion: result.completion,
                                    }),
                                })?;
                                rows_delivered = rows_delivered.saturating_add(result.rows.len());
                                flow
                            }
                            Err(error) => on_result(ReadyBatchEvent {
                                index,
                                transaction_status,
                                outcome: Err(error),
                            })?,
                        };
                        Ok((flow, outcome.ok().map(|result| result.rows)))
                    })
                },
                in_transaction,
                on_error,
                Some(profile.max_diagnostic_bytes),
            )
            .await;
        result
            .map(|done| ready_progress(scope, done, rows_delivered, in_transaction))
            .map_err(|failure| {
                ready_error(
                    scope,
                    failure,
                    (),
                    rows_delivered,
                    profile.max_requests,
                    std::convert::identity,
                )
            })
    }

    /// 将每个成功成员的唯一行、唯一列解码到调用方的向量；SQL NULL 按 V 的 Decode 实现处理。
    ///
    /// 向量须为输入长度上界预留空位，最多 max_requests 个。上界未知时须预留 max_requests 个。
    /// 已接纳成员全部确认且本地发送完成后才公布新增项；出错或放弃时恢复原有前缀。
    /// 遗忘 future 会泄漏其持有的存储，调用方看到空向量。
    /// 普通 SQL 错误作为成员结果返回；布局、行数或解码错误按 OnError 处理。
    pub async fn collect_one_into_ready<V>(
        self,
        output: &mut Vec<Result<V, DatabaseError>>,
        on_error: OnError,
    ) -> Result<BatchProgress, BatchError<()>>
    where
        for<'row> V: Decode<'row>,
    {
        self.collect_scalars_into_ready(output, on_error, |value: Option<V>| match value {
            Some(value) => Ok(value),
            None => Err(Error::InvalidInput("one requires exactly one result row")),
        })
        .await
    }

    /// 与 collect_one_into_ready 相同，但允许零行。
    /// 零行返回 `None`；`V = Option<T>` 时，一行 SQL NULL 返回 `Some(None)`。
    pub async fn collect_zero_or_one_into_ready<V>(
        self,
        output: &mut Vec<Result<Option<V>, DatabaseError>>,
        on_error: OnError,
    ) -> Result<BatchProgress, BatchError<()>>
    where
        for<'row> V: Decode<'row>,
    {
        self.collect_scalars_into_ready(output, on_error, Ok).await
    }

    async fn collect_scalars_into_ready<V, R, F>(
        self,
        output: &mut Vec<Result<R, DatabaseError>>,
        on_error: OnError,
        finish: F,
    ) -> Result<BatchProgress, BatchError<()>>
    where
        for<'row> V: Decode<'row>,
        F: Fn(Option<V>) -> Result<R, Error>,
    {
        let Self {
            scope,
            source,
            profile,
            ..
        } = self;
        let profile = batch_profile(scope, profile)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        if result_slots(&source, profile.max_requests) > output.capacity() - output.len() {
            return Err(BatchError::before_admission(
                Error::Limit("scalar output has too few spare slots for the batch"),
                scope,
            ));
        }
        let abandon = match on_error {
            OnError::Discard => crate::AbandonPolicy::DiscardOnAbandon,
            OnError::DrainToReady | OnError::RecoverExplicitly => {
                crate::AbandonPolicy::RecoverExplicitly
            }
        };
        let limits = profile
            .provisional_limits(abandon)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        let mut source = requests_with_limits(source, profile.member_limits);
        let mut stage = ScalarOutput {
            prefix: output.len(),
            storage: std::mem::take(output),
            output,
            complete: false,
        };
        let (session, in_transaction) = scope.access();
        match session
            .collect_scalar_window::<V, R, F>(
                &mut source,
                limits,
                &mut stage.storage,
                finish,
                in_transaction,
                on_error,
            )
            .await
        {
            Ok(progress) => {
                stage.complete = true;
                Ok(progress)
            }
            Err((error, cleanup_error)) => Err(BatchError {
                completed: (),
                progress: BatchProgress {
                    events_delivered: 0,
                    rows_delivered: 0,
                    ..error.progress
                },
                source: error.source,
                reuse_state: scope.state(),
                origin: error.origin,
                cleanup_error,
            }),
        }
    }

    /// 借用的行和命令在成员 Ready 前只是暂定结果，每个请求独立 Sync。
    /// 调用方指定放弃、Abort 或回调失败后的连接处置。
    /// 回调在 worker 上同步运行，恢复不会重放输入、回调或 SQL。
    pub async fn visit_provisional<F>(
        self,
        abandon: crate::AbandonPolicy,
        mut on_event: F,
    ) -> Result<BatchProgress, BatchError<()>>
    where
        F: for<'row> FnMut(BatchEvent<'row>) -> Result<BatchControl, Error>,
    {
        let Self {
            scope,
            source,
            profile,
            ..
        } = self;
        let profile = batch_profile(scope, profile)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        let limits = profile
            .provisional_limits(abandon)
            .map_err(|error| BatchError::before_admission(error, scope))?;
        let mut source = requests_with_limits(source, profile.member_limits);
        let (session, in_transaction) = scope.access();
        session
            .query_window_provisional_visit_ordinary_scoped(
                &mut source,
                limits,
                &mut on_event,
                in_transaction,
            )
            .await
            .map_err(|error| BatchError {
                completed: (),
                progress: error.progress,
                source: error.source,
                reuse_state: scope.state(),
                origin: error.origin,
                cleanup_error: None,
            })
    }
}

struct ScalarOutput<'a, R> {
    output: &'a mut Vec<Result<R, DatabaseError>>,
    storage: Vec<Result<R, DatabaseError>>,
    prefix: usize,
    complete: bool,
}

impl<R> Drop for ScalarOutput<'_, R> {
    fn drop(&mut self) {
        if !self.complete {
            self.storage.truncate(self.prefix);
        }
        *self.output = std::mem::take(&mut self.storage);
    }
}

fn empty_progress(status: TransactionStatus, reuse: crate::ReuseState) -> BatchProgress {
    BatchProgress {
        consumed: 0,
        admitted: 0,
        confirmed: 0,
        events_delivered: 0,
        rows_delivered: 0,
        sql_errors: 0,
        stopped: false,
        aborted: false,
        needs_transaction_decision: status != TransactionStatus::Idle
            || reuse == crate::ReuseState::NeedsTransactionDecision,
        admission_limit_reached: false,
        transaction_status: status,
    }
}

fn ready_progress(
    scope: &impl ApiScope,
    done: core::WindowCompletion,
    rows_delivered: usize,
    in_transaction: bool,
) -> BatchProgress {
    BatchProgress {
        consumed: done.consumed,
        admitted: done.admitted,
        confirmed: done.confirmed,
        events_delivered: done.delivered,
        rows_delivered,
        sql_errors: done.sql_errors,
        stopped: done.stopped,
        aborted: false,
        needs_transaction_decision: done.transaction_status != TransactionStatus::Idle
            || (in_transaction && scope.state() == core::ReuseState::NeedsTransactionDecision),
        admission_limit_reached: done.admission_limit_reached,
        transaction_status: done.transaction_status,
    }
}

fn ready_error<Completed>(
    scope: &impl ApiScope,
    (error, sql_errors): (core::WindowError, usize),
    completed: Completed,
    rows_delivered: usize,
    max_requests: usize,
    map_origin: impl FnOnce(BatchErrorOrigin) -> BatchErrorOrigin,
) -> BatchError<Completed> {
    BatchError {
        completed,
        progress: BatchProgress {
            consumed: error.consumed,
            admitted: error.admitted,
            confirmed: error.confirmed,
            events_delivered: error.delivered,
            rows_delivered,
            sql_errors,
            stopped: error.stopped,
            aborted: false,
            needs_transaction_decision: error.needs_transaction_decision,
            admission_limit_reached: error.admitted == max_requests,
            transaction_status: error.transaction_status,
        },
        source: error.source,
        reuse_state: scope.state(),
        origin: map_origin(error.origin),
        cleanup_error: error.cleanup_error,
    }
}

fn result_retained_bytes(item: &ReadyResult) -> Result<usize, Error> {
    match item {
        Ok(result) => Ok(result.rows.retained_bytes()),
        Err(error) => error.retained_bytes(),
    }
}

fn result_slots(source: &impl Iterator, max_requests: usize) -> usize {
    max_requests.min(source.size_hint().1.unwrap_or(max_requests))
}

fn descriptor_capacity(required: usize, payload: usize, max_bytes: usize) -> Result<usize, Error> {
    let allowed = max_bytes
        .checked_sub(payload)
        .ok_or(Error::Limit("owned batch exceeds retained output bound"))?
        / std::mem::size_of::<ReadyResult>();
    if required > allowed {
        return Err(Error::Limit(
            "owned batch result descriptors exceed retained output bound",
        ));
    }
    Ok(allowed)
}

fn reserve_results(
    results: &mut Vec<ReadyResult>,
    required: usize,
    preferred: usize,
    payload: usize,
    max_bytes: usize,
) -> Result<(), Error> {
    let allowed = descriptor_capacity(required, payload, max_bytes)?;
    let mut grown = Vec::new();
    grown
        .try_reserve_exact(preferred.min(allowed))
        .map_err(|_| Error::Limit("cannot allocate owned batch descriptors"))?;
    if grown.capacity() > allowed {
        return Err(Error::Limit(
            "owned batch result backing exceeds retained output bound",
        ));
    }
    grown.append(results);
    *results = grown;
    Ok(())
}
#[must_use]
#[derive(Debug)]
pub struct BatchReport {
    pub results: Vec<ReadyResult>,
    pub progress: BatchProgress,
}
/// 批次提前结束。
/// [`BatchBuilder::collect_ready`] 在 `completed` 中返回成功保留的结果前缀。
/// 若 Ready 已到达但输出超限，`progress.confirmed` 可能大于该前缀的长度。
/// 访问器和写入调用方缓冲区的终端使用 `BatchError<()>`，交付数量见 `progress`。
/// 进度反映最初失败时的状态；随后 DrainToReady 观察到的边界不再交付，清理失败保存在 `cleanup_error`。
pub struct BatchError<Completed = Vec<ReadyResult>> {
    pub completed: Completed,
    pub progress: BatchProgress,
    pub source: Error,
    pub reuse_state: crate::ReuseState,
    pub origin: BatchErrorOrigin,
    pub cleanup_error: Option<Box<Error>>,
}
impl<Completed: Default> BatchError<Completed> {
    #[cold]
    fn before_admission(source: Error, scope: &impl ApiScope) -> Self {
        let origin = match source {
            Error::Limit(_) => BatchErrorOrigin::Resource,
            _ => BatchErrorOrigin::Input,
        };
        let reuse_state = scope.state();
        Self {
            completed: Completed::default(),
            progress: empty_progress(scope.status(), reuse_state),
            source,
            reuse_state,
            origin,
            cleanup_error: None,
        }
    }
}
impl<Completed> fmt::Debug for BatchError<Completed> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchError")
            .field("progress", &self.progress)
            .field("source", &self.source)
            .field("reuse_state", &self.reuse_state)
            .field("origin", &self.origin)
            .field("cleanup_error", &self.cleanup_error)
            .finish_non_exhaustive()
    }
}
impl<Completed> fmt::Display for BatchError<Completed> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "batch stopped after {} confirmed requests: {}",
            self.progress.confirmed, self.source
        )
    }
}
impl<Completed> std::error::Error for BatchError<Completed> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
