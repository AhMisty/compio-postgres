mod active;
mod mode;
mod queue;

use active::{ActiveJobs, JobPoll, ScannedJobs, WokenJobs};
use queue::{Entry, IndexQueue};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::TryReserveError,
    fmt,
    future::{Future, poll_fn},
    mem::DropGuard,
    num::NonZeroUsize,
    ops::{AsyncFnOnce, Deref},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

#[cfg(target_os = "linux")]
use compio::runtime::FutureExt;
use compio::runtime::JoinHandle;

use crate::{Client, Error, WireTransport, scheduler::BatchQuantum};

use super::{
    InstallOutcome, Lease, LocalPool, MaintenanceId, Occupancy, PendingMaintenance, PoolEntry,
    PrewarmFailure, QueueLimits, Rejected, ReleaseOutcome, SessionHygiene,
};

/// 执行单项派发请求，并报告连接是否适合下一次租借。
pub trait DispatchOperation<T: WireTransport, S> {
    type Request;
    type Response;

    /// 执行直接提交的单个请求或批次中唯一的请求。检查租约复用状态后才返回响应。
    fn execute_one(
        &self,
        client: &mut Client<T>,
        state: &mut S,
        request: Self::Request,
    ) -> impl Future<Output = (Self::Response, SessionHygiene)>;
}

/// 执行显式启用的批量派发。请求和响应类型与单项执行一致。
pub trait BatchDispatchOperation<T: WireTransport, S>: DispatchOperation<T, S> {
    /// 按原批次下标借用或取走请求、暂存响应，并返回工作结束后的会话状态。
    /// 派发器检查租约后交付响应；已选中但缺少响应的成员返回 Unresolved。
    fn execute_batch(
        &self,
        client: &mut Client<T>,
        state: &mut S,
        batch: &mut DispatchBatch<'_, Self::Request, Self::Response>,
    ) -> impl Future<Output = SessionHygiene>;
}

/// 由 [`LocalDispatcher::try_new`] 构造的单项派发模式。
pub struct SingleDispatch;

/// 由 [`LocalDispatcher::try_new_batched`] 构造的批量派发模式。
pub struct BatchDispatch(NonZeroUsize);

/// 派发模式，用于同时接受单项和批量派发器的泛型接口。
pub trait DispatchMode<T: WireTransport, S, O: DispatchOperation<T, S>>:
    mode::ExecuteBatch<T, S, O>
{
}

impl<T: WireTransport, S, O: DispatchOperation<T, S>> DispatchMode<T, S, O> for SingleDispatch {}

impl<T: WireTransport, S, O: BatchDispatchOperation<T, S>> DispatchMode<T, S, O> for BatchDispatch {}

/// 派发器产生的错误，与应用返回的执行结果分别处理。
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchError<J> {
    /// 提交者位于错误的 runtime，请求尚未选中。
    WrongRuntime(J),
    /// 已选中的请求挂起后在其他 runtime 恢复，数据库执行结果可能未知。
    WrongRuntimeAfterSelection,
    /// 已有等待请求或没有空闲连接，不能直接执行。
    InlineUnavailable(J),
    Overloaded(Rejected<J>),
    /// 请求尚未接纳，驱动的内部状态需要恢复。
    InvalidState(J),
    /// 所有预留回复槽均在使用，当前请求未进入队列。
    ReplySlotsExhausted(J),
    DriverNotRunning(J),
    Closed(J),
    /// 已被选中的请求没有获得响应，其数据库执行结果可能未知。
    Unresolved,
}

impl<J> DispatchError<J> {
    /// 取回从未被选中执行的请求。已选中的请求可能已经执行。
    pub fn into_unselected(self) -> Option<J> {
        match self {
            Self::WrongRuntime(request)
            | Self::InlineUnavailable(request)
            | Self::InvalidState(request)
            | Self::ReplySlotsExhausted(request)
            | Self::DriverNotRunning(request)
            | Self::Closed(request) => Some(request),
            Self::Overloaded(rejected) => Some(rejected.item),
            Self::WrongRuntimeAfterSelection | Self::Unresolved => None,
        }
    }
}

impl<J> fmt::Display for DispatchError<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRuntime(_) => f.write_str("dispatcher requires the owning Compio runtime"),
            Self::WrongRuntimeAfterSelection => {
                f.write_str("selected request resumed outside the owning Compio runtime")
            }
            Self::InlineUnavailable(_) => {
                f.write_str("inline dispatch requires an idle connection and an empty queue")
            }
            Self::Overloaded(rejected) => {
                write!(
                    f,
                    "dispatch queue rejected request because {}",
                    rejected.reason
                )
            }
            Self::InvalidState(_) => f.write_str("inconsistent dispatcher state"),
            Self::ReplySlotsExhausted(_) => f.write_str("dispatch reply slots are exhausted"),
            Self::DriverNotRunning(_) => f.write_str("dispatch driver has not started"),
            Self::Closed(_) => f.write_str("dispatcher is closed"),
            Self::Unresolved => f.write_str("selected request did not produce a response"),
        }
    }
}

impl<J: fmt::Debug> std::error::Error for DispatchError<J> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    AlreadyRunning,
    WrongRuntime,
    InvalidState,
    ContextUnavailable,
    IntakeOpen,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("inconsistent dispatcher state"),
            Self::ContextUnavailable => f.write_str("Compio task context is unavailable"),
            Self::AlreadyRunning => f.write_str("dispatch driver is already running"),
            Self::WrongRuntime => f.write_str("dispatch driver requires the owning Compio runtime"),
            Self::IntakeOpen => {
                f.write_str("close dispatch intake before returning queued requests")
            }
        }
    }
}

impl std::error::Error for DriverError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceError {
    AlreadyWaiting,
    WrongRuntime,
}

impl fmt::Display for MaintenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyWaiting => f.write_str("a maintenance call is already waiting"),
            Self::WrongRuntime => f.write_str("maintenance requires the owning Compio runtime"),
        }
    }
}

impl std::error::Error for MaintenanceError {}

#[derive(Debug)]
pub enum DispatchReplaceError<E> {
    /// 工厂挂起后在其他 runtime 续行时，pending 标识仍须确认的槽。
    WrongRuntime {
        pending: Option<MaintenanceId>,
    },
    Closed,
    NoVacantSlot,
    Factory {
        failure: PrewarmFailure<E>,
        pending: Option<MaintenanceId>,
    },
}

impl<E: fmt::Display> fmt::Display for DispatchReplaceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRuntime { .. } => {
                f.write_str("replacement requires the owning Compio runtime")
            }
            Self::Closed => f.write_str("dispatcher is closed"),
            Self::NoVacantSlot => f.write_str("connection pool has no vacant slot"),
            Self::Factory {
                failure: PrewarmFailure::Vacant(error),
                ..
            } => {
                write!(f, "replacement failed and returned the slot: {error}")
            }
            Self::Factory {
                failure: PrewarmFailure::Uncertain(error),
                ..
            } => {
                write!(f, "replacement failed and retained the slot: {error}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DispatchReplaceError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Factory {
                failure: PrewarmFailure::Vacant(error) | PrewarmFailure::Uncertain(error),
                ..
            } => Some(error),
            Self::WrongRuntime { .. } | Self::Closed | Self::NoVacantSlot => None,
        }
    }
}

/// 由应用驱动的派发器接纳额度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchLimits {
    /// 等待可用连接的请求数与字节数。
    pub queue: QueueLimits,
    /// 为等待中、已选中或已交付但未取走的响应预留槽数。零表示只允许直接执行。
    pub max_reply_slots: usize,
    /// 每轮接纳、完成和停机退回各按请求数计费。就绪模式每次返回 Pending 的作业轮询另外计一单位；
    /// 扫描模式每轮至多检查每个挂起作业一次。回调自行控制其一次轮询内的工作量。
    pub max_work_per_turn: NonZeroUsize,
}

/// 为同一租约选中的请求，顺序与批次迭代顺序一致。
pub struct DispatchBatch<'a, J, R> {
    jobs: Vec<Job<Option<J>>>,
    remaining: usize,
    state: &'a RefCell<State<J, R>>,
}

impl<J, R> DispatchBatch<'_, J, R> {
    /// 按原批次顺序借用尚未取走的请求。迭代项携带原始下标。
    pub fn requests(&self) -> impl ExactSizeIterator<Item = (usize, &J)> {
        BatchRequests {
            jobs: self.jobs.iter().enumerate(),
            remaining: self.remaining,
        }
    }

    /// 取得指定下标请求的所有权。该下标的响应仍由原槽交付。
    /// 下标超界或请求此前已取走时返回 `None`。
    pub fn take_request(&mut self, index: usize) -> Option<J> {
        let request = self.jobs.get_mut(index)?.request.take()?;
        self.remaining -= 1;
        Some(request)
    }

    /// 按从零开始的原批次下标暂存响应；回调返回且租约完成复用检查后交付。
    ///
    /// 返回前应完成已发起的协议工作。下标无效、回复已暂存或提交方已放弃等待时，返回原响应。
    pub fn stage_reply(&self, index: usize, response: R) -> Result<(), R> {
        let Some(job) = self.jobs.get(index) else {
            return Err(response);
        };
        let mut state = self.state.borrow_mut();
        let Some(ReplyState::Selected { staged, .. }) = state.replies.live(job.reply) else {
            return Err(response);
        };
        if staged.is_some() {
            return Err(response);
        }
        *staged = Some(response);
        Ok(())
    }

    fn drain_replies(&mut self, notify: impl Fn(&RefCell<State<J, R>>, ReplyKey)) {
        let state = self.state;
        let jobs = self.jobs.drain(..);
        if std::thread::panicking() {
            abandon_remaining(state, jobs);
            return;
        }
        // 唤醒或释放请求触发展开时，先让其余成员收到错误。
        let mut jobs = DropGuard::new(jobs, |remaining| abandon_remaining(state, remaining));
        for job in jobs.by_ref() {
            let job = DropGuard::new(job, |job| ignore_cleanup_panic(|| drop(job)));
            notify(state, job.reply);
            drop(DropGuard::dismiss(job));
        }
    }

    fn finish(mut self) {
        self.drain_replies(finish_staged);
    }
}

struct BatchRequests<'a, J> {
    jobs: std::iter::Enumerate<std::slice::Iter<'a, Job<Option<J>>>>,
    remaining: usize,
}

impl<'a, J> Iterator for BatchRequests<'a, J> {
    type Item = (usize, &'a J);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self
            .jobs
            .find_map(|(index, job)| job.request.as_ref().map(|request| (index, request)))?;
        self.remaining -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<J> ExactSizeIterator for BatchRequests<'_, J> {}

impl<J, R> Drop for DispatchBatch<'_, J, R> {
    fn drop(&mut self) {
        if !self.jobs.is_empty() {
            self.drain_replies(abandon_reply);
        }
        self.state
            .borrow_mut()
            .batch_jobs
            .push(std::mem::take(&mut self.jobs));
    }
}

type Response<J, R> = Result<R, DispatchError<J>>;

struct Job<J> {
    request: J,
    reply: ReplyKey,
}

impl<J> Job<J> {
    fn into_batch(self) -> Job<Option<J>> {
        Job {
            request: Some(self.request),
            reply: self.reply,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplyKey {
    index: NonZeroUsize,
    generation: u64,
}

enum ReplyState<J, R> {
    Free(Option<NonZeroUsize>),
    Queued(Queued<J>),
    Selected {
        waker: Option<Waker>,
        staged: Option<R>,
    },
    Delivered(Response<J, R>),
}

struct Queued<J> {
    charge: usize,
    request: J,
    waker: Option<Waker>,
}

struct ReplySlot<J, R> {
    generation: u64,
    state: ReplyState<J, R>,
}

struct ReplySlots<J, R> {
    slots: Vec<Entry<ReplySlot<J, R>>>,
    free: Option<NonZeroUsize>,
}

impl<J, R> ReplySlots<J, R> {
    fn try_new(capacity: usize) -> Result<Self, TryReserveError> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        for index in 1..=capacity {
            let next = if index < capacity {
                NonZeroUsize::new(index + 1)
            } else {
                None
            };
            slots.push(Entry::new(ReplySlot {
                generation: 0,
                state: ReplyState::Free(next),
            }));
        }
        Ok(Self {
            slots,
            free: (capacity != 0).then_some(NonZeroUsize::MIN),
        })
    }

    fn enqueue(
        &mut self,
        queue: &mut IndexQueue,
        queued: Queued<J>,
    ) -> Result<ReplyKey, DispatchError<J>> {
        let Some(index) = self.free else {
            return Err(DispatchError::ReplySlotsExhausted(queued.request));
        };
        let Some(slot) = self.slots.get(index.get() - 1) else {
            return Err(DispatchError::InvalidState(queued.request));
        };
        let slot = &slot.value;
        let ReplyState::Free(next) = slot.state else {
            return Err(DispatchError::InvalidState(queued.request));
        };
        let Some(generation) = slot.generation.checked_add(1) else {
            return Err(DispatchError::ReplySlotsExhausted(queued.request));
        };
        let Ok(slot) = queue.push(index, &mut self.slots) else {
            return Err(DispatchError::InvalidState(queued.request));
        };
        slot.generation = generation;
        self.free = next;
        slot.state = ReplyState::Queued(queued);
        Ok(ReplyKey { index, generation })
    }

    fn live(&mut self, key: ReplyKey) -> Option<&mut ReplyState<J, R>> {
        let slot = &mut self.slots.get_mut(key.index.get() - 1)?.value;
        if slot.generation != key.generation || matches!(slot.state, ReplyState::Free(_)) {
            return None;
        }
        Some(&mut slot.state)
    }

    fn release(&mut self, key: ReplyKey) -> Option<ReplyState<J, R>> {
        let free = self.free;
        let slot = self.live(key)?;
        let previous = std::mem::replace(slot, ReplyState::Free(free));
        // 代次耗尽的槽永久退出，避免旧生产者误用新回复槽。
        if key.generation != u64::MAX {
            self.free = Some(key.index);
        }
        Some(previous)
    }
}

struct Queue {
    limits: QueueLimits,
    jobs: IndexQueue,
    bytes: usize,
}

impl Queue {
    fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

struct State<J, R> {
    queue: Queue,
    replies: ReplySlots<J, R>,
    batch_jobs: Vec<Vec<Job<Option<J>>>>,
    driver: Option<Waker>,
    maintenance: Option<Waker>,
    maintenance_waiting: bool,
    running: bool,
}

impl<J, R> State<J, R> {
    fn enqueue(&mut self, request: J, charge: usize) -> Result<ReplyKey, DispatchError<J>> {
        let key = self.replies.enqueue(
            &mut self.queue.jobs,
            Queued {
                charge,
                request,
                waker: None,
            },
        )?;
        self.queue.bytes += charge;
        Ok(key)
    }

    fn select(&mut self) -> Result<Option<Job<J>>, DriverError> {
        let mut bytes = self.queue.bytes;
        let Some((index, slot)) =
            self.queue
                .jobs
                .pop_front_when(&mut self.replies.slots, |slot| {
                    let ReplyState::Queued(queued) = &slot.state else {
                        return Err(DriverError::InvalidState);
                    };
                    bytes = bytes
                        .checked_sub(queued.charge)
                        .ok_or(DriverError::InvalidState)?;
                    Ok(true)
                })?
        else {
            return Ok(None);
        };
        let job = select_slot(index, &mut slot.value).ok_or(DriverError::InvalidState)?;
        self.queue.bytes = bytes;
        Ok(Some(job))
    }

    fn withdraw(&mut self, key: ReplyKey) -> Option<ReplyState<J, R>> {
        if let ReplyState::Queued(queued) = self.replies.live(key)? {
            let bytes = self.queue.bytes.checked_sub(queued.charge)?;
            self.queue
                .jobs
                .remove(key.index, &mut self.replies.slots)
                .ok()?;
            self.queue.bytes = bytes;
        }
        self.replies.release(key)
    }
}

fn select_slot<J, R>(index: NonZeroUsize, slot: &mut ReplySlot<J, R>) -> Option<Job<J>> {
    let ReplyState::Queued(queued) = &mut slot.state else {
        return None;
    };
    let waker = queued.waker.take();
    let previous = std::mem::replace(
        &mut slot.state,
        ReplyState::Selected {
            waker,
            staged: None,
        },
    );
    let ReplyState::Queued(Queued { request, .. }) = previous else {
        slot.state = previous;
        return None;
    };
    Some(Job {
        request,
        reply: ReplyKey {
            index,
            generation: slot.generation,
        },
    })
}

fn deliver<J, R>(
    state: &RefCell<State<J, R>>,
    key: ReplyKey,
    result: Response<J, R>,
) -> Result<(), Response<J, R>> {
    let (wake, staged) = {
        let mut state = state.borrow_mut();
        let Some(slot) = state.replies.live(key) else {
            return Err(result);
        };
        let ReplyState::Selected { waker, staged } = slot else {
            return Err(result);
        };
        let (waker, staged) = (waker.take(), staged.take());
        *slot = ReplyState::Delivered(result);
        (waker, staged)
    };
    if let Some(staged) = staged {
        discard_staged(wake, staged);
    } else {
        wake_waiter(wake, WakeTarget::Reply);
    }
    Ok(())
}

#[cold]
fn discard_staged<R>(wake: Option<Waker>, value: R) {
    let value = DropGuard::new(value, |value| ignore_cleanup_panic(|| drop(value)));
    wake_waiter(wake, WakeTarget::Reply);
    drop(DropGuard::dismiss(value));
}

fn finish_staged<J, R>(state: &RefCell<State<J, R>>, key: ReplyKey) {
    let wake = {
        let mut state = state.borrow_mut();
        let Some(slot) = state.replies.live(key) else {
            return;
        };
        let ReplyState::Selected { waker, staged } = slot else {
            return;
        };
        let waker = waker.take();
        *slot = ReplyState::Delivered(staged.take().ok_or(DispatchError::Unresolved));
        waker
    };
    wake_waiter(wake, WakeTarget::Reply);
}

fn abandon_reply<J, R>(state: &RefCell<State<J, R>>, key: ReplyKey) {
    let _ = deliver(state, key, Err(DispatchError::Unresolved));
}

#[cold]
fn abandon_remaining<J, R>(
    state: &RefCell<State<J, R>>,
    jobs: impl Iterator<Item = Job<Option<J>>>,
) {
    for job in jobs {
        ignore_cleanup_panic(|| abandon_reply(state, job.reply));
        ignore_cleanup_panic(|| drop(job));
    }
}

#[cold]
fn ignore_cleanup_panic(operation: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(operation)) {
        discard_panic_payload(payload);
    }
}

#[cold]
fn discard_panic_payload(payload: Box<dyn Any + Send>) {
    // 已有其他 panic 需要传播。附加载荷由应用产生，释放它可能再次 panic。
    std::mem::forget(payload);
}

struct Wait<'a, J, R> {
    state: &'a RefCell<State<J, R>>,
    key: Option<ReplyKey>,
}

impl<J, R> Wait<'_, J, R> {
    fn poll(&mut self, cx: &Context<'_>, mut incoming: Option<Waker>) -> Poll<Response<J, R>> {
        let Some(key) = self.key else {
            return Poll::Ready(Err(DispatchError::Unresolved));
        };
        loop {
            let mut state = self.state.borrow_mut();
            match state.replies.live(key) {
                Some(
                    ReplyState::Queued(Queued { waker, .. }) | ReplyState::Selected { waker, .. },
                ) => {
                    if waker.as_ref().is_some_and(|old| old.will_wake(cx.waker())) {
                        return Poll::Pending;
                    }
                    if let Some(new) = incoming.take() {
                        let old = waker.replace(new);
                        drop(state);
                        drop(old);
                        return Poll::Pending;
                    }
                }
                Some(ReplyState::Delivered(_)) => {
                    self.key = None;
                    return Poll::Ready(match state.replies.release(key) {
                        Some(ReplyState::Delivered(result)) => result,
                        _ => Err(DispatchError::Unresolved),
                    });
                }
                _ => {
                    self.key = None;
                    return Poll::Ready(Err(DispatchError::Unresolved));
                }
            }
            // 克隆 Waker 可能执行应用代码；重新检查槽以接收克隆期间已交付的回复。
            drop(state);
            incoming = Some(cx.waker().clone());
        }
    }

    fn withdraw(&mut self) -> Option<J> {
        let key = self.key.take()?;
        let previous = self.state.borrow_mut().withdraw(key)?;
        match previous {
            ReplyState::Queued(Queued { request, .. })
            | ReplyState::Delivered(Err(DispatchError::Closed(request))) => Some(request),
            _ => None,
        }
    }
}

impl<J, R> Drop for Wait<'_, J, R> {
    fn drop(&mut self) {
        drop(self.withdraw());
    }
}

enum Work<'a, J, R> {
    One(J, super::Guarded<SingleReply<'a, J, R>>),
    Batch(DispatchBatch<'a, J, R>),
}

type LeasedWork<'a, T, S, O> = (
    Lease<'a, T, S>,
    Work<'a, <O as DispatchOperation<T, S>>::Request, <O as DispatchOperation<T, S>>::Response>,
);

enum InlineRejection {
    Unavailable,
    Closed,
    WrongRuntime,
}

/// 在池所属的 Compio runtime 上派发。
/// 可直接驱动 [Self::run_scanned]，或用 [Self::spawn_scanned]、[Self::spawn_ready] 启动本地任务。
/// 直接提交在调用方的 future 内执行。
pub struct LocalDispatcher<T: WireTransport, S, O: DispatchOperation<T, S>, M = SingleDispatch> {
    pool: LocalPool<T, S>,
    operation: O,
    mode: M,
    max_work_per_turn: NonZeroUsize,
    closed: Cell<bool>,
    state: RefCell<State<O::Request, O::Response>>,
}

impl<T: WireTransport, S, O: DispatchOperation<T, S>> LocalDispatcher<T, S, O> {
    /// 使用单项执行预留回复槽。构造时接管池和执行策略。
    pub fn try_new(
        pool: LocalPool<T, S>,
        operation: O,
        limits: DispatchLimits,
    ) -> Result<Self, TryReserveError> {
        Self::try_with_mode(pool, operation, limits, SingleDispatch)
    }
}

impl<T: WireTransport, S, O: BatchDispatchOperation<T, S>> LocalDispatcher<T, S, O, BatchDispatch> {
    /// 预留回复槽及当前可用连接的批次存储，后续按需增长并复用。
    /// 每批成员数还受接纳时本轮剩余额度限制。回调另行选择协议额度。
    pub fn try_new_batched(
        pool: LocalPool<T, S>,
        operation: O,
        limits: DispatchLimits,
        max_batch_requests: NonZeroUsize,
    ) -> Result<Self, TryReserveError> {
        Self::try_with_mode(pool, operation, limits, BatchDispatch(max_batch_requests))
    }
}

impl<T, S, O, M> LocalDispatcher<T, S, O, M>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
{
    fn try_with_mode(
        pool: LocalPool<T, S>,
        operation: O,
        limits: DispatchLimits,
        mode: M,
    ) -> Result<Self, TryReserveError> {
        let queued_capacity = limits.queue.max_items.min(limits.max_reply_slots);
        let reply_capacity = if queued_capacity == 0 {
            0
        } else {
            limits.max_reply_slots
        };
        let batch_capacity = mode
            .max_requests()
            .min(limits.max_work_per_turn.get())
            .min(queued_capacity);
        // 回复槽在提交方放弃等待时立即归还，已选作业仍可占用连接。
        let warm_slots = if queued_capacity == 0 {
            0
        } else {
            pool.occupancy().ready
        };
        let mut batch_jobs = Vec::new();
        let warm_batches = warm_slots.min(queued_capacity / 2);
        if batch_capacity > 1 && warm_batches != 0 {
            let jobs_per_batch = batch_capacity.min(queued_capacity.div_ceil(warm_batches));
            batch_jobs.try_reserve_exact(warm_batches)?;
            for _ in 0..warm_batches {
                let mut jobs = Vec::new();
                jobs.try_reserve_exact(jobs_per_batch)?;
                batch_jobs.push(jobs);
            }
        }
        Ok(Self {
            pool,
            operation,
            mode,
            max_work_per_turn: limits.max_work_per_turn,
            closed: Cell::new(false),
            state: RefCell::new(State {
                queue: Queue {
                    limits: limits.queue,
                    jobs: IndexQueue::default(),
                    bytes: 0,
                },
                replies: ReplySlots::try_new(reply_capacity)?,
                batch_jobs,
                driver: None,
                maintenance: None,
                maintenance_waiting: false,
                running: false,
            }),
        })
    }

    /// 连接槽的占用状态。等待请求与回复使用各自的额度。
    pub fn pool_occupancy(&self) -> Occupancy {
        self.pool.occupancy()
    }

    /// 查看尚未完成的池维护工作，以及原关闭操作能否继续驱动。
    pub fn pending_maintenance(&self) -> Vec<PendingMaintenance> {
        self.pool.pending_maintenance()
    }

    /// 在所属 worker 上继续驱动保留的关闭操作。
    pub async fn resume_retirement(&self, id: MaintenanceId) -> Result<(), Error> {
        self.pool.resume_retirement(id).await
    }

    /// 释放当前等待方的独占资格，保留底层关闭操作。
    pub fn release_retirement_waiter(&self, id: MaintenanceId) -> bool {
        self.pool.release_retirement_waiter(id)
    }

    /// 应用已独立确认连接关闭后，归还相应槽。
    pub fn confirm_retired(&self, id: MaintenanceId) -> bool {
        self.pool.confirm_retired(id)
    }

    /// 取回连接池，供调用方在派发任务结束后显式关闭连接。
    pub fn into_pool(self) -> LocalPool<T, S> {
        self.pool
    }

    /// 有空闲连接且没有等待请求时，在提交方的 Compio 上下文中直接执行；否则退回未选中的请求。
    /// 丢弃执行中的 future 或在其他 runtime 恢复它都会隔离租约。后者返回 [`DispatchError::WrongRuntimeAfterSelection`]。
    pub async fn try_submit_inline(
        &self,
        request: O::Request,
    ) -> Result<O::Response, DispatchError<O::Request>> {
        match self.checkout_inline() {
            Ok(lease) => {
                let mut operation =
                    pin!(self.execute_single(self.guard_lease::<true>(lease), request));
                let mut resumed = false;
                poll_fn(move |cx| {
                    // 首轮已在租借时检查。恢复时验证 worker，并沿用提交方本轮的上下文。
                    if resumed && !self.pool.is_current_worker() {
                        return Poll::Ready(Err(DispatchError::WrongRuntimeAfterSelection));
                    }
                    let result = operation.as_mut().poll(cx);
                    resumed = result.is_pending();
                    result.map(Ok)
                })
                .await
            }
            Err(InlineRejection::Unavailable) => Err(DispatchError::InlineUnavailable(request)),
            Err(InlineRejection::Closed) => Err(DispatchError::Closed(request)),
            Err(InlineRejection::WrongRuntime) => Err(DispatchError::WrongRuntime(request)),
        }
    }

    #[inline]
    fn checkout_inline(&self) -> Result<Lease<'_, T, S>, InlineRejection> {
        self.pool
            .try_acquire_when(
                || InlineRejection::WrongRuntime,
                || {
                    if self.closed.get() {
                        return Err(InlineRejection::Closed);
                    }
                    if !self.state.borrow().queue.is_empty() {
                        return Err(InlineRejection::Unavailable);
                    }
                    Ok(())
                },
            )?
            .ok_or(InlineRejection::Unavailable)
    }

    /// 即使存在空闲连接也进入队列，驱动须已启动。
    /// 丢弃等待方会撤回未选中的请求；选中后执行由驱动继续，等待方只释放回复槽。
    /// 若在其他 runtime 恢复，未选中的请求随 [`DispatchError::WrongRuntime`] 退回，
    /// 选中的请求返回 [`DispatchError::WrongRuntimeAfterSelection`]。
    pub async fn submit_queued(
        &self,
        request: O::Request,
        charged_bytes: usize,
    ) -> Result<O::Response, DispatchError<O::Request>> {
        if !self.pool.is_current_worker() {
            return Err(DispatchError::WrongRuntime(request));
        }
        let (key, driver) = {
            let mut state = self.state.borrow_mut();
            if self.closed.get() {
                return Err(DispatchError::Closed(request));
            }
            if !state.running {
                return Err(DispatchError::DriverNotRunning(request));
            }
            if let Some(reason) = state.queue.limits.rejection(
                state.queue.jobs.len(),
                state.queue.bytes,
                charged_bytes,
            ) {
                return Err(DispatchError::Overloaded(Rejected {
                    item: request,
                    reason,
                }));
            }
            let key = state.enqueue(request, charged_bytes)?;
            let driver = if state.driver.is_some() && self.pool.has_ready() {
                state.driver.take()
            } else {
                None
            };
            (key, driver)
        };
        let mut wait = Wait {
            state: &self.state,
            key: Some(key),
        };
        let driver_notified = driver.is_some();
        wake_waiter(driver, WakeTarget::Driver);
        let mut resumed = false;
        poll_fn(|cx| {
            if resumed && !self.pool.is_current_worker() {
                let error = wait.withdraw().map_or(
                    DispatchError::WrongRuntimeAfterSelection,
                    DispatchError::WrongRuntime,
                );
                return Poll::Ready(Err(error));
            }
            // 没有唤醒驱动时，当前 worker 尚未处理刚入队的请求。
            let incoming = (!resumed && !driver_notified).then(|| cx.waker().clone());
            let result = wait.poll(cx, incoming);
            resumed = result.is_pending();
            result
        })
        .await
    }

    /// 在当前 Compio runtime 上启动 [Self::run_scanned]。直接执行的请求使用提交方的上下文。
    /// 用 [Self::close_intake] 停止接纳并等待已选任务结束。
    ///
    /// 返回句柄后即可提交排队请求。保留句柄以等待结束，或显式分离任务。丢弃仍在运行的句柄会取消任务。
    ///
    /// 没有当前 Compio runtime 或归属不符时，返回 [`DriverError::WrongRuntime`]。
    /// 同一派发器已启动驱动时，返回 [`DriverError::AlreadyRunning`]。
    pub fn spawn_scanned(self: Rc<Self>) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>
    where
        Self: 'static,
    {
        self.spawn_scanned_context(DriverContext::default())
    }

    fn spawn_scanned_context(
        self: Rc<Self>,
        context: DriverContext,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>
    where
        Self: 'static,
    {
        let runtime = context.bind_runtime(&self.pool)?;
        let owner = Self::claim_driver(self)?;
        Ok(runtime.spawn(async move {
            let waker = poll_fn(move |cx| Poll::Ready(context.owned_waker(cx))).await?;
            let mut driver = pin!(owner.drive_scanned());
            match waker {
                Some(waker) => {
                    poll_fn(|_| driver.as_mut().poll(&mut Context::from_waker(&waker))).await
                }
                None => driver.await,
            }
        }))
    }

    /// 启动就绪驱动。每个作业首次被轮询，之后由其 waker 入队。多个唤醒合并，就绪作业按 FIFO 轮询。
    /// 其他线程可以通知就绪，回调始终运行在池所属的 worker。
    /// 驱动任务提供稳定的唤醒目标，供已经挂起的作业继续通知。
    ///
    /// 句柄生命周期同 [Self::spawn_scanned]。每项作业保留自身唤醒目标；直接执行沿用提交方上下文。
    /// 返回句柄后即可提交排队请求。
    /// 接纳与每次轮询均消耗额度，包括返回 Pending 的轮询。
    ///
    /// 启动错误同 [Self::spawn_scanned]。
    pub fn spawn_ready(self: Rc<Self>) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>
    where
        Self: 'static,
    {
        self.spawn_ready_context(DriverContext::default())
    }

    fn spawn_ready_context(
        self: Rc<Self>,
        context: DriverContext,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>
    where
        Self: 'static,
    {
        let runtime = context.bind_runtime(&self.pool)?;
        let owner = Self::claim_driver(self)?;
        Ok(runtime.spawn(async move {
            // 只有普通任务 waker 跨线程传递，Compio 本地 I/O 扩展保留在本 worker 的作业槽内。
            let parent = poll_fn(|cx| Poll::Ready(cx.waker().clone())).await;
            let jobs = WokenJobs::new(owner.ready_job_capacity(), parent, context)?;
            owner
                .drive(jobs, |(lease, work)| owner.execute_work(lease, work))
                .await
        }))
    }

    /// 在当前 future 的 Compio 上下文中并发驱动已选作业，并复用预热的 future 槽。接纳和完成消耗额度；
    /// 一次驱动轮询对每项挂起作业最多检查一次，开销为 O(活跃作业数 + 工作额度)。
    /// 大量作业独立等待时，可用 [Self::spawn_ready] 按每次轮询计量。只允许一个驱动；
    /// 手动驱动在首次轮询后开始接纳。丢弃驱动会停止接纳并退回尚在排队的请求。
    pub async fn run_scanned(&self) -> Result<(), DriverError> {
        if !self.pool.bind_current_worker() {
            return Err(DriverError::WrongRuntime);
        }
        let _guard = Self::claim_driver(self)?;
        self.drive_scanned().await
    }

    async fn drive_scanned(&self) -> Result<(), DriverError> {
        self.drive(
            ScannedJobs::new(self.ready_job_capacity()),
            |(lease, work)| self.execute_work(lease, work),
        )
        .await
    }

    fn ready_job_capacity(&self) -> usize {
        if self.state.borrow().replies.slots.is_empty() {
            0
        } else {
            self.pool.occupancy().ready
        }
    }

    fn claim_driver<P: Deref<Target = Self>>(owner: P) -> Result<super::Guarded<P>, DriverError> {
        {
            let mut state = owner.state.borrow_mut();
            if state.running {
                return Err(DriverError::AlreadyRunning);
            }
            state.running = true;
        }
        // 派发任务持有守卫，尚未轮询时取消也会结束接纳并退回请求。
        Ok(DropGuard::new(owner, |owner| owner.exit_driver()))
    }

    async fn drive<'a, F: Future<Output = ()>, A: ActiveJobs<F>>(
        &'a self,
        mut active: A,
        execute: impl Fn(LeasedWork<'a, T, S, O>) -> F,
    ) -> Result<(), DriverError> {
        let mut quantum = BatchQuantum::new(self.max_work_per_turn);
        let mut poll_before_admission = false;
        let mut poll_turn = |cx: &mut Context<'_>| {
            if yield_driver(&mut quantum, cx) {
                return Poll::Pending;
            }
            active.begin_turn()?;
            loop {
                let polled_first = std::mem::take(&mut poll_before_admission);
                if !polled_first {
                    if self.closed.get() {
                        let mut panic = None;
                        let returned = self.return_waiting(quantum.remaining(), false, &mut panic);
                        propagate_panic(panic, std::thread::panicking());
                        quantum.spend(returned?);
                        if self.shutdown_drained() {
                            return Poll::Ready(Ok(()));
                        }
                        if yield_driver(&mut quantum, cx) {
                            poll_before_admission = true;
                            return Poll::Pending;
                        }
                    } else {
                        while let Some(work) = self.take_work(quantum.remaining())? {
                            let members = match &work.1 {
                                Work::One(..) => 1,
                                Work::Batch(batch) => batch.jobs.len(),
                            };
                            active.push(execute(work), members)?;
                            quantum.spend(members);
                            if yield_driver(&mut quantum, cx) {
                                // 接纳用尽本轮额度时，下轮先让已选作业推进。
                                poll_before_admission = true;
                                return Poll::Pending;
                            }
                        }
                    }
                }
                let mut completed = false;
                // 重新入队的作业排在已就绪的同伴之后。
                for _ in 0..active.ready_count()? {
                    let charge = match active.poll_next(cx, quantum.remaining())? {
                        JobPoll::Pending if !A::COUNT_PENDING => continue,
                        JobPoll::Pending => 1,
                        JobPoll::Finished(members) => {
                            completed = true;
                            members
                        }
                        JobPoll::InsufficientBudget => quantum.remaining(),
                    };
                    quantum.spend(charge);
                    if yield_driver(&mut quantum, cx) {
                        return Poll::Pending;
                    }
                }
                if self.shutdown_drained() {
                    return Poll::Ready(Ok(()));
                }
                if !(polled_first || completed) || self.state.borrow().queue.is_empty() {
                    return Poll::Pending;
                }
            }
        };
        poll_fn(|cx| {
            if !self.pool.is_current_worker() {
                return Poll::Ready(Err(DriverError::WrongRuntime));
            }
            let shared = self
                .state
                .borrow()
                .driver
                .as_ref()
                .is_some_and(|old| old.will_wake(cx.waker()));
            let owned = if shared {
                None
            } else {
                let stored = cx.waker().clone();
                let owned = (!stored.will_wake(cx.waker())).then(|| stored.clone());
                let retired = self.state.borrow_mut().driver.replace(stored);
                drop(retired);
                owned
            };
            match owned {
                Some(waker) => poll_turn(&mut Context::from_waker(&waker)),
                None => poll_turn(cx),
            }
        })
        .await
    }

    fn shutdown_drained(&self) -> bool {
        self.closed.get()
            && self.pool.occupancy().leased == 0
            && self.state.borrow().queue.is_empty()
    }

    /// 停止接纳，唤醒驱动和维护等待方。驱动在每轮预算内退回未选请求并完成已选作业。
    pub fn close_intake(&self) {
        if self.closed.replace(true) {
            return;
        }
        let (driver, maintenance) = {
            let mut state = self.state.borrow_mut();
            (state.driver.take(), state.maintenance.take())
        };
        wake_driver_and_maintenance(driver, maintenance);
    }

    /// 停止接纳后，立即退回至多 `limit` 个未选请求。返回本次退回的请求数。
    /// 手动轮询驱动时，可在轮询前按应用预算退回请求。
    pub fn drain_unselected(&self, limit: NonZeroUsize) -> Result<usize, DriverError> {
        if !self.closed.get() {
            return Err(DriverError::IntakeOpen);
        }
        let unwinding = std::thread::panicking();
        let mut panic = None;
        let returned = self.return_waiting(limit.get(), false, &mut panic);
        let driver = {
            let mut state = self.state.borrow_mut();
            if state.queue.is_empty() {
                state.driver.take()
            } else {
                None
            }
        };
        record_cleanup_panic(&mut panic, || wake_waiter(driver, WakeTarget::Driver));
        propagate_panic(panic, unwinding);
        returned
    }

    fn return_waiting(
        &self,
        limit: usize,
        repair_links: bool,
        panic: &mut Option<Box<dyn Any + Send>>,
    ) -> Result<usize, DriverError> {
        let mut fallback = None;
        let mut returned = 0;
        while returned < limit {
            let job = {
                let mut state = self.state.borrow_mut();
                if let Some(indices) = &mut fallback {
                    Iterator::find_map(indices, |position| {
                        let index = NonZeroUsize::new(position)?;
                        let slot = &mut Entry::get_mut(&mut state.replies.slots, index).ok()?.value;
                        select_slot(index, slot)
                    })
                } else {
                    match state.select() {
                        Ok(job) => job,
                        Err(_) if repair_links => {
                            // 队列链接无效时仍按回复槽退回未选请求。
                            state.queue.jobs = IndexQueue::default();
                            state.queue.bytes = 0;
                            fallback = Some(1..=state.replies.slots.len());
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            let Some(job) = job else { break };
            record_cleanup_panic(panic, || {
                let _ = deliver(
                    &self.state,
                    job.reply,
                    Err(DispatchError::Closed(job.request)),
                );
            });
            returned += 1;
        }
        Ok(returned)
    }

    fn exit_driver(&self) {
        self.closed.set(true);
        self.state.borrow_mut().running = false;
        let unwinding = std::thread::panicking();
        let mut panic = None;
        // 驱动析构后不再有人退回排队请求，须完成异常清理。
        let _ = self.return_waiting(usize::MAX, true, &mut panic);
        let (driver, maintenance) = {
            let mut state = self.state.borrow_mut();
            (state.driver.take(), state.maintenance.take())
        };
        record_cleanup_panic(&mut panic, || drop(driver));
        record_cleanup_panic(&mut panic, || {
            wake_waiter(maintenance, WakeTarget::Maintenance)
        });
        propagate_panic(panic, unwinding);
    }

    /// 等待一个隔离连接。每次只允许一个等待方；停止接纳且本 worker 已无租约或隔离连接时返回 None。
    /// 其他 worker 的连接可在取回连接池后由其所属 worker 关闭。
    ///
    /// 维护回调返回时公布新的连接池状态。先结束回调，再等待依赖该状态的工作。
    pub async fn maintain_one<R>(
        &self,
        repair: impl AsyncFnOnce(Lease<'_, T, S>) -> R,
    ) -> Result<Option<R>, MaintenanceError> {
        if !self.pool.is_current_worker() {
            return Err(MaintenanceError::WrongRuntime);
        }
        {
            let mut state = self.state.borrow_mut();
            if state.maintenance_waiting {
                return Err(MaintenanceError::AlreadyWaiting);
            }
            state.maintenance_waiting = true;
        }
        let mut guard = MaintenanceGuard {
            owner: self,
            waiting: true,
        };
        super::await_on_worker(pin!(async {
            let lease = poll_fn(|cx| {
                let registered = self
                    .state
                    .borrow()
                    .maintenance
                    .as_ref()
                    .is_some_and(|waker| waker.will_wake(cx.waker()));
                if !registered {
                    let incoming = cx.waker().clone();
                    let retired = self.state.borrow_mut().maintenance.replace(incoming);
                    drop(retired);
                }
                if let Some(lease) = self
                    .pool
                    .try_acquire_quarantined()
                    .map_err(|_| MaintenanceError::WrongRuntime)?
                {
                    return Poll::Ready(Ok(Some(lease)));
                }
                if self.closed.get() && self.pool.occupancy().leased == 0 {
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending
            })
            .await?;
            guard.finish_waiting();
            Ok(match lease {
                Some(lease) => Some(repair(lease).await),
                None => None,
            })
        }))
        .await
        .ok_or(MaintenanceError::WrongRuntime)?
    }

    /// 调用工厂前先预留空槽。已停止接纳与没有空槽返回不同错误；已经预留的尝试可在停止接纳后完成。
    /// 失败分类与 [LocalPool::prewarm] 相同。
    pub async fn try_replace<E>(
        &self,
        factory: impl AsyncFnOnce() -> Result<PoolEntry<T, S>, PrewarmFailure<E>>,
    ) -> Result<InstallOutcome, DispatchReplaceError<E>> {
        if !self.pool.is_current_worker() {
            return Err(DispatchReplaceError::WrongRuntime { pending: None });
        }
        if self.closed.get() {
            return Err(DispatchReplaceError::Closed);
        }
        let replacement = self
            .pool
            .reserve_replacement()
            .ok_or(DispatchReplaceError::NoVacantSlot)?;
        let id = replacement.maintenance_id();
        let result = match super::await_on_worker(pin!(factory())).await {
            None => {
                drop(replacement);
                Err(DispatchReplaceError::WrongRuntime { pending: Some(id) })
            }
            Some(Ok(entry)) => Ok(replacement.install(entry)),
            Some(Err(failure)) => {
                let pending = if matches!(failure, PrewarmFailure::Vacant(_)) {
                    replacement.confirm_vacant();
                    None
                } else {
                    Some(id)
                };
                Err(DispatchReplaceError::Factory { failure, pending })
            }
        };
        self.notify();
        result
    }

    fn take_work(&self, remaining: usize) -> Result<Option<LeasedWork<'_, T, S, O>>, DriverError> {
        let mut state = self.state.borrow_mut();
        if state.queue.is_empty() {
            return Ok(None);
        }
        let Some((lease, ready)) = self.pool.try_acquire_on_worker() else {
            return Ok(None);
        };
        let queued = state.queue.jobs.len();
        let batch_limit = self.mode.max_requests().min(remaining);
        let first = match state.select() {
            Ok(Some(first)) => first,
            other => {
                drop(state);
                let _ = lease.release_ready_on_worker(SessionHygiene::Verified);
                return other.map(|_| None);
            }
        };
        let work = if batch_limit == 1 || queued <= ready {
            Work::One(
                first.request,
                DropGuard::new(
                    SingleReply {
                        state: &self.state,
                        key: first.reply,
                    },
                    SingleReply::abandon,
                ),
            )
        } else {
            let count = queued.div_ceil(ready).min(batch_limit);
            let mut jobs = state.batch_jobs.pop().unwrap_or_default();
            jobs.reserve(count);
            jobs.push(first.into_batch());
            let selection = (1..count).try_for_each(|_| {
                if let Some(job) = state.select()? {
                    jobs.push(job.into_batch());
                }
                Ok(())
            });
            let batch = DispatchBatch {
                remaining: jobs.len(),
                jobs,
                state: &self.state,
            };
            drop(state);
            if let Err(error) = selection {
                let _ = lease.release_ready_on_worker(SessionHygiene::Verified);
                drop(batch);
                return Err(error);
            }
            Work::Batch(batch)
        };
        Ok(Some((lease, work)))
    }

    async fn execute_single<const INLINE: bool>(
        &self,
        mut lease: DispatchLease<'_, T, S, O, M, INLINE>,
        request: O::Request,
    ) -> O::Response {
        let (client, state) = lease.entry();
        let (response, hygiene) = self.operation.execute_one(client, state, request).await;
        lease.release(hygiene);
        response
    }

    fn execute_work<'a>(
        &'a self,
        lease: Lease<'a, T, S>,
        work: Work<'a, O::Request, O::Response>,
    ) -> impl Future<Output = ()> + 'a {
        let mut lease = self.guard_lease::<false>(lease);
        async move {
            match work {
                Work::One(request, reply) => {
                    let response = self.execute_single(lease, request).await;
                    let reply = DropGuard::dismiss(reply);
                    let _ = deliver(reply.state, reply.key, Ok(response));
                }
                Work::Batch(mut batch) => {
                    let (client, state) = lease.entry();
                    let Some(execute) =
                        self.mode
                            .execute(&self.operation, client, state, &mut batch)
                    else {
                        return;
                    };
                    let hygiene = execute.await;
                    lease.release(hygiene);
                    batch.finish();
                }
            }
        }
    }

    #[inline]
    fn guard_lease<'a, const INLINE: bool>(
        &'a self,
        lease: Lease<'a, T, S>,
    ) -> DispatchLease<'a, T, S, O, M, INLINE> {
        let mut lease = lease;
        lease.require_explicit_release();
        DispatchLease {
            guard: DropGuard::new((self, lease), |(owner, lease)| {
                drop(lease);
                owner.notify_release::<INLINE>(false);
            }),
        }
    }

    #[inline]
    fn notify_release<const INLINE: bool>(&self, returned: bool) {
        let closed = self.closed.get();
        // 驱动在本轮继续检查队列。已归还的正常租约也无需唤醒维护方。
        if !INLINE && returned && !closed {
            return;
        }
        let (driver, maintenance) = {
            let mut state = self.state.borrow_mut();
            let driver = if INLINE && (closed || (returned && !state.queue.is_empty())) {
                state.driver.take()
            } else {
                None
            };
            let maintenance = if closed || !returned {
                state.maintenance.take()
            } else {
                None
            };
            (driver, maintenance)
        };
        wake_driver_and_maintenance(driver, maintenance);
    }

    fn notify(&self) {
        let closed = self.closed.get();
        let (driver, maintenance) = {
            let mut state = self.state.borrow_mut();
            let driver = if closed
                || (state.driver.is_some() && !state.queue.is_empty() && self.pool.has_ready())
            {
                state.driver.take()
            } else {
                None
            };
            let maintenance = if closed
                || (state.maintenance.is_some() && self.pool.occupancy().quarantined != 0)
            {
                state.maintenance.take()
            } else {
                None
            };
            (driver, maintenance)
        };
        wake_driver_and_maintenance(driver, maintenance);
    }
}

struct DispatchLease<'a, T: WireTransport, S, O: DispatchOperation<T, S>, M, const INLINE: bool> {
    guard: super::Guarded<GuardedLease<'a, T, S, O, M>>,
}

type GuardedLease<'a, T, S, O, M> = (&'a LocalDispatcher<T, S, O, M>, Lease<'a, T, S>);

impl<T, S, O, M, const INLINE: bool> DispatchLease<'_, T, S, O, M, INLINE>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
{
    fn entry(&mut self) -> (&mut Client<T>, &mut S) {
        self.guard.1.client_and_state()
    }

    fn release(self, hygiene: SessionHygiene) {
        let (owner, lease) = DropGuard::dismiss(self.guard);
        let outcome = lease.release_ready_on_worker(hygiene);
        owner.notify_release::<INLINE>(outcome == ReleaseOutcome::Returned);
    }
}

struct SingleReply<'a, J, R> {
    state: &'a RefCell<State<J, R>>,
    key: ReplyKey,
}

impl<J, R> SingleReply<'_, J, R> {
    fn abandon(self) {
        let notify = || abandon_reply(self.state, self.key);
        if std::thread::panicking() {
            ignore_cleanup_panic(notify);
        } else {
            notify();
        }
    }
}

struct MaintenanceGuard<'a, T, S, O, M>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
{
    owner: &'a LocalDispatcher<T, S, O, M>,
    waiting: bool,
}

impl<T, S, O, M> MaintenanceGuard<'_, T, S, O, M>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
{
    fn finish_waiting(&mut self) {
        self.waiting = false;
        let waker = {
            let mut state = self.owner.state.borrow_mut();
            state.maintenance_waiting = false;
            state.maintenance.take()
        };
        drop(waker);
    }
}

impl<T, S, O, M> Drop for MaintenanceGuard<'_, T, S, O, M>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
{
    fn drop(&mut self) {
        if self.waiting {
            if std::thread::panicking() {
                ignore_cleanup_panic(|| self.finish_waiting());
            } else {
                self.finish_waiting();
            }
        }
        self.owner.notify();
    }
}

#[derive(Default)]
struct DriverContext {
    #[cfg(target_os = "linux")]
    personality: Option<u16>,
}

impl DriverContext {
    fn bind_runtime<T: WireTransport, S>(
        &self,
        pool: &LocalPool<T, S>,
    ) -> Result<compio::runtime::Runtime, DriverError> {
        let runtime = compio::runtime::Runtime::try_current().ok_or(DriverError::WrongRuntime)?;
        if !pool.is_current_worker() {
            return Err(DriverError::WrongRuntime);
        }
        #[cfg(target_os = "linux")]
        if self.personality.is_some() && !runtime.driver_type().is_iouring() {
            return Err(DriverError::ContextUnavailable);
        }
        pool.bind_checked_worker(&runtime);
        Ok(runtime)
    }
    fn owned_waker(&self, cx: &mut Context<'_>) -> Result<Option<Waker>, DriverError> {
        #[cfg(target_os = "linux")]
        if let Some(id) = self.personality {
            // 克隆将 Compio 借用的 personality 上下文转换为自有上下文。
            let capture = poll_fn(|cx| Poll::Ready(cx.waker().clone())).with_personality(id);
            return match pin!(capture).poll(cx) {
                Poll::Ready(waker) => Ok(Some(waker)),
                Poll::Pending => Err(DriverError::ContextUnavailable),
            };
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cx;
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
/// 使用所属 Linux io_uring 上已注册的 personality 启动驱动，完成前须保持该注册有效。
pub trait DispatcherExt: Sized + 'static {
    /// 运行扫描驱动。非 io_uring 后端返回上下文错误。
    fn spawn_scanned_with_personality(
        self: Rc<Self>,
        personality: u16,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>;
    /// 运行按唤醒派发的驱动。所有作业使用指定 ring 上的 personality。
    fn spawn_ready_with_personality(
        self: Rc<Self>,
        personality: u16,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError>;
}

#[cfg(target_os = "linux")]
impl<T, S, O, M> DispatcherExt for LocalDispatcher<T, S, O, M>
where
    T: WireTransport,
    O: DispatchOperation<T, S>,
    M: DispatchMode<T, S, O>,
    Self: 'static,
{
    fn spawn_scanned_with_personality(
        self: Rc<Self>,
        personality: u16,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError> {
        self.spawn_scanned_context(DriverContext {
            personality: Some(personality),
        })
    }
    fn spawn_ready_with_personality(
        self: Rc<Self>,
        personality: u16,
    ) -> Result<JoinHandle<Result<(), DriverError>>, DriverError> {
        self.spawn_ready_context(DriverContext {
            personality: Some(personality),
        })
    }
}

enum WakeTarget {
    Driver,
    Maintenance,
    Reply,
}

fn wake_waiter(waker: Option<Waker>, target: WakeTarget) {
    #[cfg(not(feature = "diagnostics"))]
    let _ = target;
    if let Some(waker) = waker {
        #[cfg(feature = "diagnostics")]
        match target {
            WakeTarget::Driver => crate::diagnostics::dispatcher_driver_wake(),
            WakeTarget::Maintenance => crate::diagnostics::dispatcher_maintenance_wake(),
            WakeTarget::Reply => crate::diagnostics::dispatcher_reply_wake(),
        }
        waker.wake();
    }
}

fn wake_driver_and_maintenance(driver: Option<Waker>, maintenance: Option<Waker>) {
    match (driver, maintenance) {
        (None, None) => {}
        (Some(driver), None) if !std::thread::panicking() => {
            wake_waiter(Some(driver), WakeTarget::Driver);
        }
        (None, Some(maintenance)) if !std::thread::panicking() => {
            wake_waiter(Some(maintenance), WakeTarget::Maintenance);
        }
        (driver, maintenance) => wake_during_cleanup(driver, maintenance),
    }
}

#[cold]
fn wake_during_cleanup(driver: Option<Waker>, maintenance: Option<Waker>) {
    let unwinding = std::thread::panicking();
    let mut panic = None;
    record_cleanup_panic(&mut panic, || wake_waiter(driver, WakeTarget::Driver));
    record_cleanup_panic(&mut panic, || {
        wake_waiter(maintenance, WakeTarget::Maintenance)
    });
    propagate_panic(panic, unwinding);
}

#[inline]
fn yield_driver(quantum: &mut BatchQuantum, cx: &mut Context<'_>) -> bool {
    let yielded = quantum.poll_yield_if_exhausted(cx).is_pending();
    #[cfg(feature = "diagnostics")]
    if yielded {
        crate::diagnostics::dispatcher_driver_wake();
    }
    yielded
}

// 清理期间继续退回请求和发送通知，随后恢复首个用户回调的 panic。
#[cold]
fn record_cleanup_panic(panic: &mut Option<Box<dyn Any + Send>>, operation: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(operation)) {
        if panic.is_none() {
            *panic = Some(payload);
        } else {
            discard_panic_payload(payload);
        }
    }
}

#[cold]
fn propagate_panic(panic: Option<Box<dyn Any + Send>>, unwinding: bool) {
    if let Some(panic) = panic {
        if unwinding {
            discard_panic_payload(panic);
        } else {
            resume_unwind(panic);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_returns_all_waiting_requests_before_resuming_a_panic() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::Wake,
        };

        struct Operation;
        impl DispatchOperation<crate::NativeTransport, ()> for Operation {
            type Request = usize;
            type Response = ();

            async fn execute_one(
                &self,
                _: &mut Client<crate::NativeTransport>,
                _: &mut (),
                _: usize,
            ) -> ((), SessionHygiene) {
                ((), SessionHygiene::Verified)
            }
        }

        struct Signal {
            wakes: AtomicUsize,
            panic: Option<&'static str>,
        }

        impl Wake for Signal {
            fn wake(self: Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::Relaxed);
                if let Some(message) = self.panic {
                    std::panic::panic_any(message);
                }
            }
        }

        let limits = DispatchLimits {
            queue: QueueLimits {
                max_items: 3,
                max_charged_bytes: 3,
            },
            max_reply_slots: 3,
            max_work_per_turn: NonZeroUsize::MIN,
        };
        let pool =
            LocalPool::try_new(NonZeroUsize::MIN, super::super::PoolReuse::SharedSession).unwrap();
        let dispatcher = LocalDispatcher::try_new(pool, Operation, limits).unwrap();
        let signal = |panic| {
            Arc::new(Signal {
                wakes: AtomicUsize::new(0),
                panic,
            })
        };
        let first = signal(Some("首项等待者唤醒失败"));
        let remaining = signal(None);
        let driver = signal(Some("驱动唤醒失败"));
        let maintenance = signal(None);
        {
            let mut state = dispatcher.state.borrow_mut();
            state.driver = Some(Waker::from(Arc::clone(&driver)));
            state.maintenance = Some(Waker::from(Arc::clone(&maintenance)));
        }
        let mut waits = std::array::from_fn::<_, 3, _>(|index| {
            let key = dispatcher.state.borrow_mut().enqueue(index, 1).unwrap();
            let mut wait = Wait {
                state: &dispatcher.state,
                key: Some(key),
            };
            let signal = if index == 0 { &first } else { &remaining };
            let waker = Waker::from(Arc::clone(signal));
            assert!(wait.poll(&Context::from_waker(&waker), None).is_pending());
            wait
        });

        let panic = catch_unwind(AssertUnwindSafe(|| dispatcher.close_intake())).unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>().copied(), Some("驱动唤醒失败"));
        assert_eq!(first.wakes.load(Ordering::Relaxed), 0);
        assert_eq!(remaining.wakes.load(Ordering::Relaxed), 0);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            dispatcher
                .drain_unselected(NonZeroUsize::new(3).unwrap())
                .unwrap();
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("首项等待者唤醒失败")
        );
        assert_eq!(first.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(remaining.wakes.load(Ordering::Relaxed), 2);
        assert_eq!(driver.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(maintenance.wakes.load(Ordering::Relaxed), 1);
        {
            let state = dispatcher.state.borrow();
            assert!(dispatcher.closed.get());
            assert!(state.queue.is_empty());
            assert_eq!(state.queue.bytes, 0);
        }
        let context = Context::from_waker(Waker::noop());
        for (index, wait) in waits.iter_mut().enumerate() {
            assert_eq!(
                wait.poll(&context, None),
                Poll::Ready(Err(DispatchError::Closed(index)))
            );
        }
        dispatcher.close_intake();
        assert_eq!(driver.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(maintenance.wakes.load(Ordering::Relaxed), 1);

        drop(waits);
        let dispatcher =
            LocalDispatcher::try_new(dispatcher.into_pool(), Operation, limits).unwrap();

        struct FailOnDrop;
        impl Wake for FailOnDrop {
            fn wake(self: Arc<Self>) {
                panic!("已停止的驱动不应被唤醒");
            }
        }
        impl Drop for FailOnDrop {
            fn drop(&mut self) {
                panic!("驱动唤醒器释放失败");
            }
        }

        let mut waiting = {
            let mut state = dispatcher.state.borrow_mut();
            state.running = true;
            state.driver = Some(Waker::from(Arc::new(FailOnDrop)));
            state.maintenance = Some(Waker::from(Arc::clone(&maintenance)));
            Wait {
                state: &dispatcher.state,
                key: Some(state.enqueue(7, 1).unwrap()),
            }
        };
        let panic = catch_unwind(AssertUnwindSafe(|| dispatcher.exit_driver())).unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>().copied(),
            Some("驱动唤醒器释放失败")
        );
        assert_eq!(maintenance.wakes.load(Ordering::Relaxed), 2);
        assert_eq!(
            waiting.poll(&context, None),
            Poll::Ready(Err(DispatchError::Closed(7)))
        );
        assert!(!dispatcher.state.borrow().running);

        let wake_with_panic = || {
            wake_driver_and_maintenance(
                Some(Waker::from(Arc::clone(&driver))),
                Some(Waker::from(Arc::clone(&maintenance))),
            );
        };
        let panic = catch_unwind(AssertUnwindSafe(wake_with_panic)).unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>().copied(), Some("驱动唤醒失败"));
        assert_eq!(maintenance.wakes.load(Ordering::Relaxed), 3);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _notify_on_drop = DropGuard::new((), |()| wake_with_panic());
            std::panic::panic_any("原有异常");
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>().copied(), Some("原有异常"));
        assert_eq!(maintenance.wakes.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn selected_single_reply_preserves_the_executor_panic() {
        use std::{panic::panic_any, sync::Arc, task::Wake};

        struct PanicOnWake;
        impl Wake for PanicOnWake {
            fn wake(self: Arc<Self>) {
                panic_any("回复通知失败");
            }
        }

        let state = RefCell::new(State::<(), ()> {
            queue: Queue {
                limits: QueueLimits {
                    max_items: 1,
                    max_charged_bytes: 1,
                },
                jobs: IndexQueue::default(),
                bytes: 0,
            },
            replies: ReplySlots::try_new(1).unwrap(),
            batch_jobs: Vec::new(),
            driver: None,
            maintenance: None,
            maintenance_waiting: false,
            running: true,
        });
        let key = state.borrow_mut().enqueue((), 1).unwrap();
        assert!(state.borrow_mut().select().unwrap().is_some());
        let mut wait = Wait {
            state: &state,
            key: Some(key),
        };
        let waker = Waker::from(Arc::new(PanicOnWake));
        let context = Context::from_waker(&waker);
        assert!(wait.poll(&context, None).is_pending());

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _reply = DropGuard::new(SingleReply { state: &state, key }, SingleReply::abandon);
            panic_any("执行回调失败");
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"执行回调失败"));
        assert_eq!(
            wait.poll(&context, None),
            Poll::Ready(Err(DispatchError::Unresolved))
        );
    }

    #[test]
    fn a_panicking_waker_or_request_destructor_leaves_no_selected_batch_waiter() {
        use std::{
            panic::{AssertUnwindSafe, catch_unwind},
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::Wake,
        };

        struct PanicOnWake(&'static str);
        impl Wake for PanicOnWake {
            fn wake(self: Arc<Self>) {
                std::panic::panic_any(self.0);
            }
        }
        #[derive(Debug)]
        struct Request {
            panic_on_drop: bool,
        }
        impl Drop for Request {
            fn drop(&mut self) {
                if self.panic_on_drop {
                    panic!("首项请求释放失败");
                }
            }
        }
        #[derive(Default)]
        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        for (finish, panic_on_wake) in [(true, true), (false, true), (true, false), (false, false)]
        {
            let state = RefCell::new(State {
                queue: Queue {
                    limits: QueueLimits {
                        max_items: 3,
                        max_charged_bytes: 3,
                    },
                    jobs: IndexQueue::default(),
                    bytes: 0,
                },
                replies: ReplySlots::<Request, usize>::try_new(3).unwrap(),
                batch_jobs: Vec::new(),
                driver: None,
                maintenance: None,
                maintenance_waiting: false,
                running: true,
            });
            let mut jobs = Vec::new();
            let mut waits = Vec::new();
            for index in 0..3 {
                let request = Request {
                    panic_on_drop: !panic_on_wake && index == 0,
                };
                let key = state.borrow_mut().enqueue(request, 1).unwrap();
                jobs.push(state.borrow_mut().select().unwrap().unwrap().into_batch());
                waits.push(Wait {
                    state: &state,
                    key: Some(key),
                });
            }
            let batch = DispatchBatch {
                remaining: jobs.len(),
                jobs,
                state: &state,
            };
            for index in 0..3 {
                batch.stage_reply(index, index).unwrap();
            }
            let first_waker = if panic_on_wake {
                Waker::from(Arc::new(PanicOnWake("首项等待者唤醒失败")))
            } else {
                Waker::noop().clone()
            };
            assert!(
                waits[0]
                    .poll(&Context::from_waker(&first_waker), None)
                    .is_pending()
            );
            let count = Arc::new(WakeCount::default());
            let peer_waker = Waker::from(Arc::clone(&count));
            let second_waker = Waker::from(Arc::new(PanicOnWake("第二项等待者唤醒失败")));
            assert!(
                waits[1]
                    .poll(&Context::from_waker(&second_waker), None)
                    .is_pending()
            );
            assert!(
                waits[2]
                    .poll(&Context::from_waker(&peer_waker), None)
                    .is_pending()
            );
            let panic = catch_unwind(AssertUnwindSafe(|| {
                if finish {
                    batch.finish();
                } else {
                    drop(batch);
                }
            }))
            .unwrap_err();
            let first_failure = if panic_on_wake {
                "首项等待者唤醒失败"
            } else {
                "首项请求释放失败"
            };
            assert_eq!(panic.downcast_ref::<&str>().copied(), Some(first_failure));
            assert_eq!(count.0.load(Ordering::Relaxed), 1);
            let cx = Context::from_waker(Waker::noop());
            for (index, wait) in waits.iter_mut().enumerate() {
                let reply = wait.poll(&cx, None);
                if finish && index == 0 {
                    assert!(matches!(reply, Poll::Ready(Ok(0))));
                } else {
                    assert!(matches!(reply, Poll::Ready(Err(DispatchError::Unresolved))));
                }
            }
        }
    }

    #[test]
    fn exhausted_generation_is_not_reissued() {
        let mut slots = ReplySlots::<(), ()>::try_new(1).unwrap();
        let mut queue = IndexQueue::default();
        slots.slots[0].value.generation = u64::MAX - 1;
        let queued = || Queued {
            charge: 0,
            request: (),
            waker: None,
        };
        let key = slots.enqueue(&mut queue, queued()).unwrap();
        assert_eq!(key.generation, u64::MAX);
        assert_eq!(
            queue.pop_front(&mut slots.slots).unwrap().map(|(id, _)| id),
            Some(key.index)
        );
        drop(slots.release(key));
        assert!(slots.live(key).is_none());
        assert!(matches!(
            slots.enqueue(&mut queue, queued()),
            Err(DispatchError::ReplySlotsExhausted(()))
        ));
    }

    #[test]
    fn invalid_queue_link_leaves_request_and_reply_slot_unselected() {
        let mut slots = ReplySlots::<String, ()>::try_new(1).unwrap();
        let mut queue = IndexQueue::default();
        let mut foreign: [Entry<()>; 2] = [Entry::new(()), Entry::new(())];
        let missing = NonZeroUsize::new(2).unwrap();
        queue.push(missing, &mut foreign).unwrap();
        let result = slots.enqueue(
            &mut queue,
            Queued {
                charge: 1,
                request: "原请求".to_owned(),
                waker: None,
            },
        );
        let Err(DispatchError::InvalidState(request)) = result else {
            panic!("无效链接不能接纳请求");
        };
        assert_eq!(request, "原请求");
        assert_eq!(queue.front(), Some(missing));
        assert_eq!(queue.len(), 1);
        assert_eq!(slots.free, Some(NonZeroUsize::MIN));
        assert_eq!(slots.slots[0].value.generation, 0);
        assert!(matches!(slots.slots[0].value.state, ReplyState::Free(None)));
    }
}
