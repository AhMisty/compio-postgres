use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Wake, Waker},
};

use super::{
    DriverContext, DriverError,
    queue::{Entry, IndexQueue},
};

pub(super) trait ActiveJobs<F> {
    const COUNT_PENDING: bool;
    fn begin_turn(&mut self) -> Result<(), DriverError> {
        Ok(())
    }
    fn push(&mut self, job: F, members: usize) -> Result<(), DriverError>;
    fn ready_count(&self) -> Result<usize, DriverError>;
    fn poll_next(&mut self, cx: &mut Context<'_>, remaining: usize)
    -> Result<JobPoll, DriverError>;
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum JobPoll {
    Pending,
    Finished(usize),
    /// 下一个作业可能交付整个批次，留在队首等待下一轮。
    InsufficientBudget,
}

type Slot<F> = Pin<Box<Option<F>>>;

pub(super) struct ScannedJobs<F> {
    active: IndexQueue,
    pending: IndexQueue,
    slots: Vec<Entry<ScannedSlot<F>, ()>>,
    spare: Option<NonZeroUsize>,
}

struct ScannedSlot<F> {
    job: Slot<F>,
    members: usize,
}

impl<F> ScannedSlot<F> {
    fn new() -> Self {
        Self {
            job: Box::pin(None),
            members: 0,
        }
    }
}

impl<F> ScannedJobs<F> {
    pub(super) fn new(capacity: usize) -> Self {
        let mut spare = None;
        let slots = Vec::from_fn(capacity, |index| {
            let mut slot = Entry::new(ScannedSlot::new());
            slot.link_free_slot(spare);
            spare = NonZeroUsize::MIN.checked_add(index);
            slot
        });
        Self {
            active: IndexQueue::default(),
            pending: IndexQueue::default(),
            slots,
            spare,
        }
    }
}

impl<F: Future<Output = ()>> ActiveJobs<F> for ScannedJobs<F> {
    const COUNT_PENDING: bool = false;
    fn begin_turn(&mut self) -> Result<(), DriverError> {
        self.active.append(&mut self.pending, &mut self.slots)
    }

    fn push(&mut self, job: F, members: usize) -> Result<(), DriverError> {
        let id = if let Some(id) = self.spare {
            let slot = Entry::get_mut(&mut self.slots, id)?;
            self.spare = slot.take_free_link();
            id
        } else {
            let id = NonZeroUsize::MIN
                .checked_add(self.slots.len())
                .ok_or(DriverError::InvalidState)?;
            self.slots.push(Entry::new(ScannedSlot::new()));
            id
        };
        let slot = self.active.push(id, &mut self.slots)?;
        slot.job.as_mut().set(Some(job));
        slot.members = members;
        Ok(())
    }

    fn ready_count(&self) -> Result<usize, DriverError> {
        Ok(self.active.len())
    }

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
        remaining: usize,
    ) -> Result<JobPoll, DriverError> {
        let Some((id, slot)) = self
            .active
            .pop_front_when(&mut self.slots, |slot| Ok(slot.members <= remaining))?
        else {
            if self.active.is_empty() {
                return Err(DriverError::InvalidState);
            }
            return Ok(JobPoll::InsufficientBudget);
        };
        let members = slot.value.members;
        let job = &mut slot.value.job;
        let result = job
            .as_mut()
            .as_pin_mut()
            .ok_or(DriverError::InvalidState)?
            .poll(cx);
        if result.is_ready() {
            job.as_mut().set(None);
            slot.link_free_slot(self.spare);
            self.spare = Some(id);
            Ok(JobPoll::Finished(members))
        } else {
            self.pending.push_detached(id, &mut self.slots)?;
            Ok(JobPoll::Pending)
        }
    }
}

// 就绪队列由可能跨线程传递的 waker 共享。future、Compio 本地 I/O 扩展和空闲槽表均留在所属 worker 上。
struct ReadyQueue {
    parent: Waker,
    state: Mutex<Signals>,
}

struct Signals {
    slots: Vec<Entry<Signal>>,
    ready: IndexQueue,
    spare: Option<NonZeroUsize>,
    notification: NotificationState,
}

struct Signal {
    identity: Weak<SlotWake>,
    state: SlotState,
}

#[derive(PartialEq, Eq)]
enum SlotState {
    Idle,
    Waiting,
    Queued,
}

#[derive(PartialEq, Eq)]
enum NotificationState {
    Clear,
    Notified,
    Invalid,
}

impl Signals {
    fn push_ready(&mut self, id: NonZeroUsize) -> Result<(), DriverError> {
        self.ready.push(id, &mut self.slots)?.state = SlotState::Queued;
        Ok(())
    }
}

struct SlotWake {
    queue: Weak<ReadyQueue>,
    id: NonZeroUsize,
}

impl Wake for SlotWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let Some(queue) = self.queue.upgrade() else {
            return;
        };
        {
            let Ok(mut state) = queue.lock() else {
                queue.wake_parent();
                return;
            };
            let waiting = Entry::get(&state.slots, self.id).map(|slot| {
                slot.value.state == SlotState::Waiting
                    && slot.value.identity.as_ptr() == Arc::as_ptr(self)
            });
            match waiting {
                Ok(false) => return,
                Ok(true) if state.push_ready(self.id).is_ok() => {
                    if std::mem::replace(&mut state.notification, NotificationState::Notified)
                        == NotificationState::Notified
                    {
                        return;
                    }
                }
                _ => {
                    // 唤醒器无法返回错误，交由驱动结束派发和释放已选作业。
                    state.notification = NotificationState::Invalid;
                }
            }
        }
        queue.wake_parent();
    }
}

impl ReadyQueue {
    fn lock(&self) -> Result<MutexGuard<'_, Signals>, DriverError> {
        let state = self.state.lock().map_err(|_| DriverError::InvalidState)?;
        if state.notification == NotificationState::Invalid {
            return Err(DriverError::InvalidState);
        }
        Ok(state)
    }

    fn wake_parent(&self) {
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::dispatcher_driver_wake();
        self.parent.wake_by_ref();
    }

    fn new_slot(self: &Arc<Self>) -> Result<Waker, DriverError> {
        let mut state = self.lock()?;
        let id = NonZeroUsize::MIN
            .checked_add(state.slots.len())
            .ok_or(DriverError::InvalidState)?;
        let wake = Arc::new(SlotWake {
            queue: Arc::downgrade(self),
            id,
        });
        let mut slot = Entry::new(Signal {
            identity: Arc::downgrade(&wake),
            state: SlotState::Idle,
        });
        slot.link_free_slot(state.spare);
        state.spare = Some(id);
        state.slots.push(slot);
        Ok(Waker::from(wake))
    }

    fn activate(self: &Arc<Self>) -> Result<Option<(NonZeroUsize, Option<Waker>)>, DriverError> {
        let mut state = self.lock()?;
        let Some(id) = state.spare else {
            return Ok(None);
        };
        let slot = Entry::get_mut(&mut state.slots, id)?;
        if slot.value.state != SlotState::Idle {
            return Err(DriverError::InvalidState);
        }
        let next = slot.take_free_link();
        // 旧 future 及其 Compio 上下文已释放。若仍有外部持有旧 waker，则为新作业创建独立身份。
        let replacement = if slot.value.identity.strong_count() == 1 {
            None
        } else {
            let wake = Arc::new(SlotWake {
                queue: Arc::downgrade(self),
                id,
            });
            slot.value.identity = Arc::downgrade(&wake);
            Some(Waker::from(wake))
        };
        state.spare = next;
        state.push_ready(id)?;
        Ok(Some((id, replacement)))
    }

    fn retire(&self, id: NonZeroUsize) -> Result<(), DriverError> {
        let mut state = self.lock()?;
        let Signals {
            ready,
            slots,
            spare,
            ..
        } = &mut *state;
        let mut slot = Entry::get_mut(slots, id)?;
        match slot.value.state {
            SlotState::Idle => return Err(DriverError::InvalidState),
            SlotState::Waiting => {}
            SlotState::Queued => {
                // 作业在最后一次轮询期间被唤醒，按槽位直接撤销通知。
                ready.remove(id, slots)?;
                slot = Entry::get_mut(slots, id)?;
            }
        }
        slot.value.state = SlotState::Idle;
        slot.link_free_slot(*spare);
        *spare = Some(id);
        Ok(())
    }
}

struct WokenSlot<F> {
    job: Slot<F>,
    members: usize,
    waker: Waker,
    context: Option<Waker>,
}

pub(super) struct WokenJobs<F> {
    queue: Arc<ReadyQueue>,
    slots: Vec<WokenSlot<F>>,
    context: DriverContext,
}

impl<F> WokenJobs<F> {
    pub(super) fn new(
        capacity: usize,
        parent: Waker,
        context: DriverContext,
    ) -> Result<Self, DriverError> {
        let queue = Arc::new(ReadyQueue {
            parent,
            state: Mutex::new(Signals {
                slots: Vec::with_capacity(capacity),
                ready: IndexQueue::default(),
                spare: None,
                notification: NotificationState::Clear,
            }),
        });
        let slots = (0..capacity)
            .map(|_| WokenSlot::new(&queue))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            queue,
            slots,
            context,
        })
    }
}

impl<F> WokenSlot<F> {
    fn new(queue: &Arc<ReadyQueue>) -> Result<Self, DriverError> {
        Ok(Self {
            job: Box::pin(None),
            members: 0,
            waker: queue.new_slot()?,
            context: None,
        })
    }
}

impl<F: Future<Output = ()>> ActiveJobs<F> for WokenJobs<F> {
    const COUNT_PENDING: bool = true;
    fn push(&mut self, job: F, members: usize) -> Result<(), DriverError> {
        let (id, replacement) = if let Some(slot) = self.queue.activate()? {
            slot
        } else {
            self.slots.push(WokenSlot::new(&self.queue)?);
            self.queue.activate()?.ok_or(DriverError::InvalidState)?
        };
        let slot = self
            .slots
            .get_mut(id.get() - 1)
            .ok_or(DriverError::InvalidState)?;
        slot.job.as_mut().set(Some(job));
        slot.members = members;
        if let Some(waker) = replacement {
            slot.waker = waker;
        }
        slot.context = self
            .context
            .owned_waker(&mut Context::from_waker(&slot.waker))?;
        Ok(())
    }

    fn ready_count(&self) -> Result<usize, DriverError> {
        let mut state = self.queue.lock()?;
        // 快照已包含此前的信号。快照之后的新唤醒仍可安排驱动再次轮询。
        state.notification = NotificationState::Clear;
        Ok(state.ready.len())
    }

    fn poll_next(&mut self, _: &mut Context<'_>, remaining: usize) -> Result<JobPoll, DriverError> {
        let (id, slot) = {
            let mut state = self.queue.lock()?;
            let id = state.ready.front().ok_or(DriverError::InvalidState)?;
            let slot = self
                .slots
                .get_mut(id.get() - 1)
                .ok_or(DriverError::InvalidState)?;
            if slot.members > remaining {
                return Ok(JobPoll::InsufficientBudget);
            }
            let Signals { ready, slots, .. } = &mut *state;
            let (id, signal) = ready.pop_front(slots)?.ok_or(DriverError::InvalidState)?;
            signal.value.state = SlotState::Waiting;
            (id, slot)
        };
        let future = slot
            .job
            .as_mut()
            .as_pin_mut()
            .ok_or(DriverError::InvalidState)?;
        let waker = slot.context.as_ref().unwrap_or(&slot.waker);
        let result = future.poll(&mut Context::from_waker(waker));
        if result.is_ready() {
            self.queue.retire(id)?;
            slot.job.as_mut().set(None);
            slot.context = None;
            Ok(JobPoll::Finished(slot.members))
        } else {
            Ok(JobPoll::Pending)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, future::poll_fn, task::Poll};

    fn job(calls: &Cell<usize>, ready: bool) -> impl Future<Output = ()> {
        poll_fn(move |_| {
            calls.set(calls.get() + 1);
            if ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }

    #[test]
    fn ready_batches_wait_for_enough_budget_before_running_their_callbacks() {
        fn verify<F: Future<Output = ()>>(
            mut jobs: impl ActiveJobs<F>,
            make: impl Fn() -> F,
            polls: &Cell<usize>,
        ) {
            for members in [2, 2, 1] {
                jobs.push(make(), members).unwrap();
            }
            let mut cx = Context::from_waker(Waker::noop());
            jobs.begin_turn().unwrap();
            assert_eq!(jobs.poll_next(&mut cx, 3).unwrap(), JobPoll::Finished(2));
            assert_eq!(
                jobs.poll_next(&mut cx, 1).unwrap(),
                JobPoll::InsufficientBudget
            );
            assert_eq!(polls.get(), 1);
            jobs.begin_turn().unwrap();
            assert_eq!(jobs.poll_next(&mut cx, 3).unwrap(), JobPoll::Finished(2));
            assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Finished(1));
            assert_eq!(polls.get(), 3);
            assert_eq!(jobs.ready_count().unwrap(), 0);
        }
        let polls = Cell::new(0);
        verify(ScannedJobs::new(3), || job(&polls, true), &polls);
        polls.set(0);
        verify(
            WokenJobs::new(3, Waker::noop().clone(), DriverContext::default()).unwrap(),
            || job(&polls, true),
            &polls,
        );
    }

    #[test]
    fn scanned_pending_jobs_run_once_per_driver_poll() {
        let waiting = Cell::new(0);
        let finished = Cell::new(0);
        let mut jobs = ScannedJobs::new(2);
        let mut cx = Context::from_waker(Waker::noop());
        jobs.push(job(&waiting, false), 1).unwrap();
        jobs.push(job(&finished, true), 1).unwrap();
        jobs.begin_turn().unwrap();
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Pending);
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Finished(1));
        jobs.push(job(&finished, true), 1).unwrap();
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Finished(1));
        assert_eq!(jobs.ready_count().unwrap(), 0);
        assert_eq!((waiting.get(), finished.get()), (1, 2));
        jobs.begin_turn().unwrap();
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Pending);
        assert_eq!(waiting.get(), 2);
    }

    #[test]
    fn scanned_queue_resumes_unpolled_jobs_before_deferred_jobs() {
        let waiting = Cell::new(0);
        let finished = Cell::new(0);
        let mut jobs = ScannedJobs::new(2);
        let mut cx = Context::from_waker(Waker::noop());
        jobs.push(job(&waiting, false), 1).unwrap();
        jobs.push(job(&finished, true), 2).unwrap();
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Pending);
        assert_eq!(
            jobs.poll_next(&mut cx, 1).unwrap(),
            JobPoll::InsufficientBudget
        );
        jobs.begin_turn().unwrap();
        assert_eq!(jobs.ready_count().unwrap(), 2);
        assert_eq!(jobs.poll_next(&mut cx, 2).unwrap(), JobPoll::Finished(2));
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Pending);
        assert_eq!((waiting.get(), finished.get()), (2, 1));
    }

    #[test]
    fn ready_queue_can_retire_a_middle_notification() {
        let calls = [const { Cell::new(0) }; 3];
        let mut jobs = WokenJobs::new(3, Waker::noop().clone(), DriverContext::default()).unwrap();
        for calls in &calls {
            jobs.push(job(calls, true), 1).unwrap();
        }
        let middle = NonZeroUsize::new(2).unwrap();
        jobs.queue.retire(middle).unwrap();
        assert_eq!(jobs.ready_count().unwrap(), 2);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Finished(1));
        assert_eq!(jobs.poll_next(&mut cx, 1).unwrap(), JobPoll::Finished(1));
        assert_eq!(jobs.ready_count().unwrap(), 0);
        assert_eq!(calls.each_ref().map(Cell::get), [1, 0, 1]);
    }

    #[test]
    fn an_invalid_waker_slot_notifies_the_driver_to_stop() {
        use std::{
            future::Ready,
            sync::atomic::{AtomicBool, Ordering},
        };

        struct SignalParent(AtomicBool);

        impl Wake for SignalParent {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let signal = Arc::new(SignalParent(AtomicBool::new(false)));
        let jobs = WokenJobs::<Ready<()>>::new(
            0,
            Waker::from(Arc::clone(&signal)),
            DriverContext::default(),
        )
        .unwrap();
        Waker::from(Arc::new(SlotWake {
            queue: Arc::downgrade(&jobs.queue),
            id: NonZeroUsize::MIN,
        }))
        .wake();
        assert!(signal.0.load(Ordering::Relaxed));
        assert_eq!(jobs.ready_count(), Err(DriverError::InvalidState));
    }
}
