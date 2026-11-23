#![cfg(feature = "service")]

#[path = "support/peer.rs"]
mod peer;

use compio::runtime::{CancelToken, FutureExt};
use compio_postgres::{
    AllocationPolicy, BatchOptions, Client, ClientOptions, Error, ExecutionOptions,
    ExecutionScheduling, NativeTransport, OnError, OwnedBatch, OwnedOutput,
    PreparedStatementStorage, QueryOptions, ResultFormats, ReuseState, Statement, StatementLimits,
    TcpConnection,
    service::{
        BatchDispatchOperation, DispatchBatch, DispatchError, DispatchLimits, DispatchOperation,
        DispatchReplaceError, DriverError, InstallOutcome, LocalDispatcher, LocalPool,
        MaintenanceError, PoolEntry, PoolReuse, PrewarmFailure, QueueLimits, RejectReason,
        Rejected, ReleaseOutcome, SessionHygiene,
    },
    types::{Format, Oid, Parameter},
};
use futures_util::future::{join, join3};
use std::{
    alloc::System,
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    io::Write,
    num::NonZeroUsize,
    ops::ControlFlow,
    pin::{Pin, pin},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[derive(Clone, Copy, Debug)]
enum Request {
    Probe,
    Gate,
    Query(i32),
}

struct Operation {
    gate_open: Rc<Cell<bool>>,
    batch_sizes: Rc<RefCell<Vec<usize>>>,
}

fn scalar(rows: &OwnedBatch) -> Result<i32, Error> {
    let mut rows = rows.rows();
    let row = rows
        .next()
        .ok_or(Error::InvalidInput("one requires exactly one result row"))??;
    if row.len() != 1 {
        return Err(Error::InvalidInput(
            "one requires exactly one result column",
        ));
    }
    let mut decoder = row.decoder();
    let value = decoder.decode_next()?;
    decoder.finish()?;
    if rows.next().is_some() {
        return Err(Error::InvalidInput("one received more than one result row"));
    }
    Ok(value)
}

impl DispatchOperation<NativeTransport, Statement> for Operation {
    type Request = Request;
    type Response = Result<i32, Error>;

    async fn execute_one(
        &self,
        client: &mut Client<NativeTransport>,
        statement: &mut Statement,
        request: Request,
    ) -> (Self::Response, SessionHygiene) {
        let result = match request {
            Request::Probe => Ok(1),
            Request::Gate => {
                let owner = compio::runtime::Runtime::current().waker();
                poll_fn(|_| {
                    assert!(owner.will_wake(&compio::runtime::Runtime::current().waker()));
                    if self.gate_open.get() {
                        Poll::Ready(Ok(0))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            }
            Request::Query(value) => {
                client
                    .query(statement, &[Parameter::int4(value)])
                    .one(OnError::DrainToReady)
                    .await
            }
        };
        (result, SessionHygiene::Verified)
    }
}

impl BatchDispatchOperation<NativeTransport, Statement> for Operation {
    async fn execute_batch(
        &self,
        client: &mut Client<NativeTransport>,
        statement: &mut Statement,
        batch: &mut DispatchBatch<'_, Request, Self::Response>,
    ) -> SessionHygiene {
        let requests = batch.requests();
        let count = requests.len();
        self.batch_sizes.borrow_mut().push(count);
        // 本回调按原顺序提交整个未取出的批次，SQL 事件索引即原派发槽位。
        let requests = requests.map(|(_, request)| match request {
            Request::Query(value) => statement.bind_one(Parameter::int4(*value)),
            _ => panic!("non-query request reached the batch fixture"),
        });
        let mut responses = 0;
        let progress = client
            .streaming_batch(requests)
            .visit_ready(
                OwnedOutput {
                    max_bytes: peer::query_limits().max_result_bytes,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::DrainToReady,
                |event| {
                    let result = match event.outcome {
                        Ok(result) => scalar(result.rows),
                        Err(error) => Err(Error::Database(error.clone())),
                    };
                    let _ = batch.stage_reply(event.index, result);
                    responses += 1;
                    Ok(ControlFlow::Continue(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(progress.confirmed, count);
        assert_eq!(responses, count);
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
        SessionHygiene::Verified
    }
}

async fn prepare_entry(peer: &peer::Peer) -> Result<PoolEntry<NativeTransport, Statement>, Error> {
    let limits = peer::query_limits();
    let scheduling = ExecutionScheduling::Uninterrupted;
    let options = ClientOptions::new(
        peer.config(),
        ExecutionOptions {
            query: QueryOptions { limits, scheduling },
            batch: Some(BatchOptions {
                member_limits: limits,
                max_requests: 2,
                max_inflight: 2,
                max_queued_request_bytes: 8192,
                max_diagnostic_bytes: 4096,
                scheduling,
            }),
        },
        StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        },
    );
    let mut client = TcpConnection::connect(options).await?;
    let statement = client
        .prepare(
            "SELECT $1::int4",
            &[Oid::INT4],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await?;
    let layout = statement.layout();
    if layout.len() != 1
        || !layout
            .column(0)
            .is_some_and(|column| column.type_oid == Oid::INT4)
        || layout.formats().as_slice() != [Format::Binary]
    {
        return Err(Error::InvalidInput(
            "expected one binary int4 result column",
        ));
    }
    Ok(PoolEntry::new(client, statement))
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

fn assert_sql_failure(result: Result<i32, Error>) {
    let Err(Error::Database(error)) = result else {
        panic!("expected the same SQL error from either execution path");
    };
    assert_eq!(error.code(), "22012");
}

#[derive(Default)]
struct Gate {
    open: Cell<bool>,
    waiter: RefCell<Option<Waker>>,
}

impl Gate {
    async fn wait(&self) {
        poll_fn(|cx| {
            if self.open.get() {
                return Poll::Ready(());
            }
            *self.waiter.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
        .await;
    }

    fn open(&self) {
        self.open.set(true);
        let waiter = self.waiter.borrow_mut().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

#[derive(Default)]
struct SlotOperation {
    direct_gate: Rc<Gate>,
    batch_gate: Rc<Gate>,
    finish_batch_gate: Rc<Gate>,
    replies: Rc<RefCell<Vec<Result<(), i32>>>>,
}

impl DispatchOperation<NativeTransport, Statement> for SlotOperation {
    type Request = i32;
    type Response = i32;

    async fn execute_one(
        &self,
        _client: &mut Client<NativeTransport>,
        _statement: &mut Statement,
        request: i32,
    ) -> (i32, SessionHygiene) {
        if request == 0 {
            self.direct_gate.wait().await;
        }
        (request, SessionHygiene::Verified)
    }
}

impl BatchDispatchOperation<NativeTransport, Statement> for SlotOperation {
    async fn execute_batch(
        &self,
        _client: &mut Client<NativeTransport>,
        _statement: &mut Statement,
        batch: &mut DispatchBatch<'_, i32, i32>,
    ) -> SessionHygiene {
        self.batch_gate.wait().await;
        for (index, &request) in batch.requests() {
            self.replies
                .borrow_mut()
                .push(batch.stage_reply(index, request));
        }
        self.replies.borrow_mut().push(batch.stage_reply(1, 99));
        self.finish_batch_gate.wait().await;
        SessionHygiene::Verified
    }
}

fn reply_slots() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::prepare(socket, &[23], &[23])?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            prepare_entry(&peer)
                .await
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let limits = DispatchLimits {
            queue: QueueLimits {
                max_items: 4,
                max_charged_bytes: 4,
            },
            max_reply_slots: 2,
            max_work_per_turn: NonZeroUsize::new(16).unwrap(),
        };
        assert!(
            LocalDispatcher::try_new(
                LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap(),
                SlotOperation::default(),
                DispatchLimits {
                    queue: QueueLimits {
                        max_items: 0,
                        max_charged_bytes: 0,
                    },
                    max_reply_slots: usize::MAX,
                    ..limits
                },
            )
            .is_ok()
        );
        let operation = SlotOperation::default();
        let direct_gate = Rc::clone(&operation.direct_gate);
        let direct_only = LocalDispatcher::try_new(
            pool,
            operation,
            DispatchLimits {
                max_reply_slots: 0,
                ..limits
            },
        )
        .unwrap();
        {
            let mut driver = pin!(direct_only.run_scanned());
            let mut direct = pin!(direct_only.try_submit_inline(0));
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert!(poll(direct.as_mut(), Waker::noop()).is_pending());
            let region = stats_alloc::Region::new(ALLOCATOR);
            let rejected = poll(pin!(direct_only.submit_queued(1, 1)), Waker::noop());
            let change = region.change();
            assert_eq!(
                rejected,
                Poll::Ready(Err(DispatchError::ReplySlotsExhausted(1)))
            );
            assert_eq!(change.allocations, 0);
            assert_eq!(change.reallocations, 0);
            direct_gate.open();
            assert_eq!(direct.await, Ok(0));
            direct_only.close_intake();
            driver.await.unwrap();
        }

        let operation = SlotOperation::default();
        let direct_gate = Rc::clone(&operation.direct_gate);
        let batch_gate = Rc::clone(&operation.batch_gate);
        let finish_batch_gate = Rc::clone(&operation.finish_batch_gate);
        let replies = Rc::clone(&operation.replies);
        let dispatcher = LocalDispatcher::try_new_batched(
            direct_only.into_pool(),
            operation,
            limits,
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();

        {
            let mut driver = pin!(dispatcher.run_scanned());
            let mut direct = pin!(dispatcher.try_submit_inline(0));
            let mut cancelled = Box::pin(dispatcher.submit_queued(10, 1));
            let mut kept = pin!(dispatcher.submit_queued(11, 1));
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert!(poll(direct.as_mut(), Waker::noop()).is_pending());
            assert!(poll(cancelled.as_mut(), Waker::noop()).is_pending());
            assert!(poll(kept.as_mut(), Waker::noop()).is_pending());
            direct_gate.open();
            assert_eq!(poll(direct.as_mut(), Waker::noop()), Poll::Ready(Ok(0)));
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert!(batch_gate.waiter.borrow().is_some());

            drop(cancelled);
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut replacement = pin!(dispatcher.submit_queued(12, 1));
            assert!(poll(replacement.as_mut(), &waker).is_pending());
            assert_eq!(
                dispatcher.submit_queued(13, 1).await,
                Err(DispatchError::ReplySlotsExhausted(13))
            );

            batch_gate.open();
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert_eq!(&*replies.borrow(), &[Err(10), Ok(()), Err(99)]);
            assert!(poll(kept.as_mut(), Waker::noop()).is_pending());
            assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
            finish_batch_gate.open();
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert_eq!(wakes.0.load(Ordering::Relaxed), 1);

            direct_gate.open.set(false);
            let mut direct = pin!(dispatcher.try_submit_inline(0));
            assert!(poll(direct.as_mut(), Waker::noop()).is_pending());
            assert_eq!(
                dispatcher.submit_queued(14, 1).await,
                Err(DispatchError::ReplySlotsExhausted(14))
            );
            assert_eq!(kept.await, Ok(11));
            let mut closing = pin!(dispatcher.submit_queued(14, 1));
            assert!(poll(closing.as_mut(), Waker::noop()).is_pending());
            assert_eq!(replacement.await, Ok(12));
            dispatcher.close_intake();
            assert_eq!(dispatcher.drain_unselected(NonZeroUsize::MIN).unwrap(), 1);
            assert_eq!(closing.await, Err(DispatchError::Closed(14)));
            direct_gate.open();
            assert_eq!(direct.await, Ok(0));
            driver.await.unwrap();
        }

        let operation = SlotOperation::default();
        let direct_gate = Rc::clone(&operation.direct_gate);
        let batch_gate = Rc::clone(&operation.batch_gate);
        let dispatcher = LocalDispatcher::try_new_batched(
            dispatcher.into_pool(),
            operation,
            limits,
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let mut driver = Box::pin(dispatcher.run_scanned());
        let mut direct = pin!(dispatcher.try_submit_inline(0));
        let mut cancelled = Box::pin(dispatcher.submit_queued(20, 1));
        let mut selected = pin!(dispatcher.submit_queued(21, 1));
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        assert!(poll(direct.as_mut(), Waker::noop()).is_pending());
        assert!(poll(cancelled.as_mut(), Waker::noop()).is_pending());
        assert!(poll(selected.as_mut(), Waker::noop()).is_pending());
        direct_gate.open();
        assert_eq!(direct.await, Ok(0));
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        assert!(batch_gate.waiter.borrow().is_some());
        drop(cancelled);
        let mut waiting = pin!(dispatcher.submit_queued(22, 1));
        assert!(poll(waiting.as_mut(), Waker::noop()).is_pending());
        batch_gate.open();
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        assert!(poll(selected.as_mut(), Waker::noop()).is_pending());
        drop(driver);
        assert_eq!(selected.await, Err(DispatchError::Unresolved));
        assert_eq!(waiting.await, Err(DispatchError::Closed(22)));
        assert_eq!(dispatcher.pool_occupancy().quarantined, 1);
    });
    peer.finish();
}

fn suspended_maintenance_keeps_shutdown_and_reservations_consistent() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    let pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
    let dispatcher = LocalDispatcher::try_new(
        pool,
        Operation {
            gate_open: Rc::new(Cell::new(false)),
            batch_sizes: Rc::new(RefCell::new(Vec::new())),
        },
        DispatchLimits {
            queue: QueueLimits {
                max_items: 1,
                max_charged_bytes: 1,
            },
            max_reply_slots: 1,
            max_work_per_turn: NonZeroUsize::MIN,
        },
    )
    .unwrap();
    let mut wait = pin!(dispatcher.maintain_one(async |_| panic!("空池不能选出维护租约")));
    assert!(
        owner
            .enter(|| poll(wait.as_mut(), Waker::noop()))
            .is_pending()
    );
    assert!(matches!(
        foreign.enter(|| poll(wait.as_mut(), Waker::noop())),
        Poll::Ready(Err(MaintenanceError::WrongRuntime))
    ));

    let notified = Arc::new(WakeCount::default());
    let waker = Waker::from(notified.clone());
    let mut next = pin!(dispatcher.maintain_one(async |_| panic!("空池不能选出维护租约")));
    assert!(owner.enter(|| poll(next.as_mut(), &waker)).is_pending());
    let polls = Cell::new(0);
    let mut replace = pin!(
        dispatcher.try_replace(async || -> Result<_, PrewarmFailure<Error>> {
            poll_fn(|_| {
                polls.set(polls.get() + 1);
                Poll::Pending
            })
            .await
        })
    );
    assert!(
        owner
            .enter(|| poll(replace.as_mut(), Waker::noop()))
            .is_pending()
    );
    assert_eq!(dispatcher.pool_occupancy().maintenance, 1);
    dispatcher.close_intake();
    assert_eq!(notified.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        owner.enter(|| poll(next.as_mut(), &waker)),
        Poll::Ready(Ok(None))
    ));
    let Poll::Ready(Err(DispatchReplaceError::WrongRuntime { pending: Some(id) })) =
        foreign.enter(|| poll(replace.as_mut(), Waker::noop()))
    else {
        panic!("建连预留必须保持可确认");
    };
    assert_eq!(polls.get(), 1);
    assert_eq!(dispatcher.pool_occupancy().vacant, 0);
    let pending = dispatcher.pending_maintenance();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert!(!pending[0].claimed && !pending[0].resumable);
    assert!(dispatcher.confirm_retired(id));
    assert_eq!(dispatcher.pool_occupancy().vacant, 1);
}

fn enqueuing_a_request_only_wakes_the_driver() {
    let [ready_peer, foreign_peer] = [(); 2].map(|_| {
        peer::Peer::start(|socket| {
            peer::handshake(socket)?;
            peer::prepare(socket, &[23], &[23])?;
            peer::eof(socket)
        })
    });
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    let pool =
        LocalPool::try_new(NonZeroUsize::new(2).unwrap(), PoolReuse::VerifyOnRelease).unwrap();
    owner.block_on(async {
        let entry = prepare_entry(&ready_peer).await.unwrap();
        assert_eq!(
            pool.reserve_replacement().unwrap().install(entry),
            InstallOutcome::Installed
        );
    });
    foreign.block_on(async {
        let entry = prepare_entry(&foreign_peer).await.unwrap();
        assert_eq!(
            pool.reserve_replacement().unwrap().install(entry),
            InstallOutcome::WrongRuntime
        );
    });
    let dispatcher = LocalDispatcher::try_new(
        pool,
        SlotOperation::default(),
        DispatchLimits {
            queue: QueueLimits {
                max_items: 1,
                max_charged_bytes: 1,
            },
            max_reply_slots: 1,
            max_work_per_turn: NonZeroUsize::new(4).unwrap(),
        },
    )
    .unwrap();
    owner.enter(|| {
        let driver_wakes = Arc::new(WakeCount::default());
        let driver_waker = Waker::from(Arc::clone(&driver_wakes));
        let maintenance_wakes = Arc::new(WakeCount::default());
        let maintenance_waker = Waker::from(Arc::clone(&maintenance_wakes));
        let mut driver = pin!(dispatcher.run_scanned());
        let mut maintenance =
            pin!(dispatcher.maintain_one(async |_| { panic!("隔离连接属于另一 runtime") }));
        assert!(poll(driver.as_mut(), &driver_waker).is_pending());
        assert!(poll(maintenance.as_mut(), &maintenance_waker).is_pending());
        #[cfg(feature = "diagnostics")]
        let wakes_before = compio_postgres::diagnostics::snapshot();
        let mut reply = pin!(dispatcher.submit_queued(7, 1));
        assert!(poll(reply.as_mut(), Waker::noop()).is_pending());
        assert_eq!(driver_wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(maintenance_wakes.0.load(Ordering::Relaxed), 0);
        assert!(poll(driver.as_mut(), &driver_waker).is_pending());
        assert_eq!(poll(reply.as_mut(), Waker::noop()), Poll::Ready(Ok(7)));
        dispatcher.close_intake();
        assert_eq!(maintenance_wakes.0.load(Ordering::Relaxed), 1);
        #[cfg(feature = "diagnostics")]
        {
            let wakes = compio_postgres::diagnostics::snapshot()
                .delta(wakes_before)
                .unwrap();
            assert_eq!(
                (
                    wakes.dispatcher_driver_wakes,
                    wakes.dispatcher_maintenance_wakes,
                    wakes.dispatcher_reply_wakes,
                ),
                (2, 1, 1)
            );
        }
        assert!(matches!(
            poll(maintenance.as_mut(), &maintenance_waker),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(poll(driver.as_mut(), &driver_waker), Poll::Ready(Ok(())));
    });
    let pool = dispatcher.into_pool();
    owner.block_on(async { pool.try_acquire().unwrap().unwrap().close().await.unwrap() });
    foreign.block_on(async {
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap()
    });
    ready_peer.finish();
    foreign_peer.finish();
}

fn reject_driver_poll_from_another_runtime() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::prepare(socket, &[23], &[23])?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            prepare_entry(&peer)
                .await
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let dispatcher = Rc::new(
            LocalDispatcher::try_new(
                pool,
                Operation {
                    gate_open: Rc::new(Cell::new(false)),
                    batch_sizes: Rc::new(RefCell::new(Vec::new())),
                },
                DispatchLimits {
                    queue: QueueLimits {
                        max_items: 1,
                        max_charged_bytes: 1,
                    },
                    max_reply_slots: 1,
                    max_work_per_turn: NonZeroUsize::new(16).unwrap(),
                },
            )
            .unwrap(),
        );
        let foreign = compio::runtime::Runtime::new().unwrap();
        {
            let mut inline = pin!(dispatcher.try_submit_inline(Request::Gate));
            let inline_wakes = Arc::new(WakeCount::default());
            let inline_waker = Waker::from(Arc::clone(&inline_wakes));
            assert!(poll(inline.as_mut(), &inline_waker).is_pending());
            assert_eq!(Arc::strong_count(&inline_wakes), 2);
            assert_eq!(dispatcher.pool_occupancy().leased, 1);
            let notified = Arc::new(WakeCount::default());
            let waker = Waker::from(notified.clone());
            let repair_polls = Cell::new(0);
            let mut repair = pin!(dispatcher.maintain_one(async |lease| {
                poll_fn(|_| {
                    repair_polls.set(repair_polls.get() + 1);
                    Poll::<()>::Pending
                })
                .await;
                lease.release(SessionHygiene::Verified)
            }));
            assert!(poll(repair.as_mut(), &waker).is_pending());
            let Poll::Ready(Err(error)) = foreign.enter(|| poll(inline.as_mut(), Waker::noop()))
            else {
                panic!("已选中的直接请求必须拒绝在其他 runtime 继续执行");
            };
            assert!(matches!(error, DispatchError::WrongRuntimeAfterSelection));
            assert!(error.into_unselected().is_none());
            assert_eq!(dispatcher.pool_occupancy().leased, 0);
            assert_eq!(dispatcher.pool_occupancy().quarantined, 1);
            assert_eq!(notified.0.load(Ordering::Relaxed), 1);
            assert!(poll(repair.as_mut(), &waker).is_pending());
            assert_eq!(dispatcher.pool_occupancy().leased, 1);
            let mut next = pin!(
                dispatcher.maintain_one(async |lease| lease.release(SessionHygiene::Verified))
            );
            assert!(poll(next.as_mut(), &waker).is_pending());
            assert!(matches!(
                foreign.enter(|| poll(repair.as_mut(), Waker::noop())),
                Poll::Ready(Err(MaintenanceError::WrongRuntime))
            ));
            assert_eq!(repair_polls.get(), 1);
            assert_eq!(dispatcher.pool_occupancy().leased, 0);
            assert_eq!(dispatcher.pool_occupancy().quarantined, 1);
            assert_eq!(notified.0.load(Ordering::Relaxed), 2);
            assert_eq!(next.await.unwrap(), Some(ReleaseOutcome::Returned));
            assert_eq!(dispatcher.pool_occupancy().ready, 1);
        }
        {
            let mut driver = pin!(dispatcher.run_scanned());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            foreign.enter(|| {
                assert!(matches!(
                    poll(
                        pin!(dispatcher.try_replace(
                            async || -> Result<_, PrewarmFailure<Error>> {
                                panic!("错误 worker 不能开始建连")
                            }
                        )),
                        Waker::noop()
                    ),
                    Poll::Ready(Err(DispatchReplaceError::WrongRuntime { pending: None }))
                ));
                assert!(matches!(
                    Rc::clone(&dispatcher).spawn_scanned(),
                    Err(DriverError::WrongRuntime)
                ));
                assert!(matches!(
                    Rc::clone(&dispatcher).spawn_ready(),
                    Err(DriverError::WrongRuntime)
                ));
                #[cfg(target_os = "linux")]
                {
                    use compio_postgres::expert::linux::DispatcherExt;
                    assert!(matches!(
                        Rc::clone(&dispatcher).spawn_scanned_with_personality(0),
                        Err(DriverError::WrongRuntime)
                    ));
                    assert!(matches!(
                        Rc::clone(&dispatcher).spawn_ready_with_personality(0),
                        Err(DriverError::WrongRuntime)
                    ));
                }

                assert!(matches!(
                    poll(
                        pin!(dispatcher.try_submit_inline(Request::Probe)),
                        Waker::noop()
                    ),
                    Poll::Ready(Err(DispatchError::WrongRuntime(Request::Probe)))
                ));
                assert!(matches!(
                    poll(
                        pin!(dispatcher.submit_queued(Request::Probe, 1)),
                        Waker::noop()
                    ),
                    Poll::Ready(Err(DispatchError::WrongRuntime(Request::Probe)))
                ));
            });
            let mut waiting = pin!(dispatcher.submit_queued(Request::Probe, 1));
            assert!(poll(waiting.as_mut(), Waker::noop()).is_pending());
            assert!(matches!(
                foreign.enter(|| poll(waiting.as_mut(), Waker::noop())),
                Poll::Ready(Err(DispatchError::WrongRuntime(Request::Probe)))
            ));
            let mut selected = pin!(dispatcher.submit_queued(Request::Probe, 1));
            assert!(poll(selected.as_mut(), Waker::noop()).is_pending());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert!(matches!(
                foreign.enter(|| poll(selected.as_mut(), Waker::noop())),
                Poll::Ready(Err(DispatchError::WrongRuntimeAfterSelection))
            ));
            let mut request = pin!(dispatcher.submit_queued(Request::Probe, 1));
            assert!(poll(request.as_mut(), Waker::noop()).is_pending());
            foreign.enter(|| {
                assert!(matches!(
                    poll(
                        pin!(dispatcher.submit_queued(Request::Probe, 1)),
                        Waker::noop()
                    ),
                    Poll::Ready(Err(DispatchError::WrongRuntime(Request::Probe)))
                ));
                assert!(matches!(
                    poll(
                        pin!(dispatcher.try_submit_inline(Request::Probe)),
                        Waker::noop()
                    ),
                    Poll::Ready(Err(DispatchError::WrongRuntime(Request::Probe)))
                ));
                assert!(matches!(
                    poll(driver.as_mut(), Waker::noop()),
                    Poll::Ready(Err(DriverError::WrongRuntime))
                ))
            });
            assert!(matches!(
                poll(request.as_mut(), Waker::noop()),
                Poll::Ready(Err(DispatchError::Closed(Request::Probe)))
            ));
        }
        Rc::into_inner(dispatcher)
            .unwrap()
            .into_pool()
            .try_acquire()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
    });
    peer.finish();
}

#[derive(Debug)]
struct ProbeRequest {
    id: usize,
    context: Option<CancelToken>,
}

struct DriverProbe;

impl DispatchOperation<NativeTransport, Statement> for DriverProbe {
    type Request = ProbeRequest;
    type Response = usize;

    async fn execute_one(
        &self,
        _client: &mut Client<NativeTransport>,
        _statement: &mut Statement,
        request: ProbeRequest,
    ) -> (usize, SessionHygiene) {
        assert_eq!(CancelToken::current().await, request.context);
        (request.id, SessionHygiene::Verified)
    }
}

impl BatchDispatchOperation<NativeTransport, Statement> for DriverProbe {
    async fn execute_batch(
        &self,
        _client: &mut Client<NativeTransport>,
        _statement: &mut Statement,
        batch: &mut DispatchBatch<'_, ProbeRequest, usize>,
    ) -> SessionHygiene {
        let context = CancelToken::current().await;
        let count = batch.requests().len();
        for index in 0..count {
            let request = batch.take_request(index).unwrap();
            assert!(batch.take_request(index).is_none());
            let mut remaining = batch.requests();
            assert_eq!(remaining.len(), count - index - 1);
            assert_eq!(
                remaining.next().map(|(slot, _)| slot),
                (index + 1 < count).then_some(index + 1)
            );
            assert_eq!(context.as_ref(), request.context.as_ref());
            assert_eq!(batch.stage_reply(index, request.id), Ok(()));
        }
        SessionHygiene::Verified
    }
}

fn driver_context_allocations_and_fairness() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::prepare(socket, &[23], &[23])?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            prepare_entry(&peer)
                .await
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let limits = DispatchLimits {
            queue: QueueLimits {
                max_items: 4,
                max_charged_bytes: 4,
            },
            max_reply_slots: 4,
            max_work_per_turn: NonZeroUsize::new(2).unwrap(),
        };
        let dispatcher = LocalDispatcher::try_new_batched(
            pool,
            DriverProbe,
            limits,
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let request = |id| ProbeRequest { id, context: None };
        {
            let mut driver = pin!(dispatcher.run_scanned());
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            assert!(poll(driver.as_mut(), &waker).is_pending());
            let region = stats_alloc::Region::new(ALLOCATOR);
            let mut first = pin!(dispatcher.submit_queued(request(1), 1));
            let mut second = pin!(dispatcher.submit_queued(request(2), 1));
            let mut third = pin!(dispatcher.submit_queued(request(3), 1));
            assert!(poll(first.as_mut(), Waker::noop()).is_pending());
            assert!(poll(second.as_mut(), Waker::noop()).is_pending());
            assert!(poll(third.as_mut(), Waker::noop()).is_pending());
            let wakes_before_turn = wakes.0.load(Ordering::Relaxed);
            assert!(poll(driver.as_mut(), &waker).is_pending());
            assert!(wakes.0.load(Ordering::Relaxed) > wakes_before_turn);
            // 首轮的两个单位用于接纳，两项完成须等下一轮才可交付。
            assert!(poll(first.as_mut(), Waker::noop()).is_pending());
            assert!(poll(second.as_mut(), Waker::noop()).is_pending());
            let wakes_before_finish = wakes.0.load(Ordering::Relaxed);
            assert!(poll(driver.as_mut(), &waker).is_pending());
            assert_eq!(wakes.0.load(Ordering::Relaxed), wakes_before_finish + 1);
            assert_eq!(first.await.unwrap(), 1);
            assert_eq!(second.await.unwrap(), 2);
            assert!(poll(third.as_mut(), Waker::noop()).is_pending());
            assert!(poll(driver.as_mut(), &waker).is_pending());
            assert_eq!(third.await.unwrap(), 3);
            let change = region.change();
            assert_eq!(change.allocations, 0);
            assert_eq!(change.reallocations, 0);
            let region = stats_alloc::Region::new(ALLOCATOR);
            assert!(matches!(
                poll(pin!(dispatcher.try_submit_inline(request(4))), &waker),
                Poll::Ready(Ok(4))
            ));
            assert_eq!(region.change().allocations, 0);
            // 使用不同的 I/O 上下文再次轮询同一驱动。
            for context in [Some(CancelToken::new()), Some(CancelToken::new()), None] {
                let mut reply = pin!(dispatcher.submit_queued(
                    ProbeRequest {
                        id: 5,
                        context: context.clone()
                    },
                    1,
                ));
                assert!(poll(reply.as_mut(), Waker::noop()).is_pending());
                let turn = match context {
                    Some(token) => poll(pin!(driver.as_mut().with_cancel(token)), &waker),
                    None => poll(driver.as_mut(), &waker),
                };
                assert!(turn.is_pending());
                assert!(matches!(
                    poll(reply.as_mut(), Waker::noop()),
                    Poll::Ready(Ok(5))
                ));
            }
            dispatcher.close_intake();
            driver.await.unwrap();
        }
        let dispatcher = LocalDispatcher::try_new_batched(
            dispatcher.into_pool(),
            DriverProbe,
            limits,
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        {
            let submitter_context = CancelToken::new();
            let mut driver = pin!(dispatcher.run_scanned());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            let mut first = pin!(
                dispatcher
                    .submit_queued(request(1), 1)
                    .with_cancel(submitter_context.clone())
            );
            let mut second = pin!(dispatcher.submit_queued(request(2), 1));
            assert!(poll(first.as_mut(), Waker::noop()).is_pending());
            assert!(poll(second.as_mut(), Waker::noop()).is_pending());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert!(poll(first.as_mut(), Waker::noop()).is_pending());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert_eq!(first.await.unwrap(), 1);
            assert_eq!(second.await.unwrap(), 2);
            let mut single = pin!(dispatcher.submit_queued(request(3), 1));
            assert!(poll(single.as_mut(), Waker::noop()).is_pending());
            assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
            assert_eq!(single.await.unwrap(), 3);
            let direct = dispatcher
                .try_submit_inline(ProbeRequest {
                    id: 4,
                    context: Some(submitter_context.clone()),
                })
                .with_cancel(submitter_context);
            let region = stats_alloc::Region::new(ALLOCATOR);
            assert!(matches!(
                poll(pin!(direct), Waker::noop()),
                Poll::Ready(Ok(4))
            ));
            assert_eq!(region.change().allocations, 0);
            dispatcher.close_intake();
            driver.await.unwrap();
        }
        dispatcher
            .into_pool()
            .try_acquire()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
    });
    peer.finish();
}

fn spawn_requires_a_current_runtime() {
    let pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
    let limits = DispatchLimits {
        queue: QueueLimits {
            max_items: 1,
            max_charged_bytes: 1,
        },
        max_reply_slots: 1,
        max_work_per_turn: NonZeroUsize::MIN,
    };
    let dispatcher =
        Rc::new(LocalDispatcher::try_new(pool, SlotOperation::default(), limits).unwrap());
    assert!(matches!(
        Rc::clone(&dispatcher).spawn_scanned(),
        Err(compio_postgres::service::DriverError::WrongRuntime)
    ));
    assert!(matches!(
        dispatcher.spawn_ready(),
        Err(compio_postgres::service::DriverError::WrongRuntime)
    ));
}

fn vacant_pool_driver_allocations(capacity: NonZeroUsize) -> stats_alloc::Stats {
    let pool = LocalPool::try_new(capacity, PoolReuse::VerifyOnRelease).unwrap();
    let operation = SlotOperation::default();
    let limits = DispatchLimits {
        queue: QueueLimits {
            max_items: 4,
            max_charged_bytes: 4,
        },
        max_reply_slots: 4,
        max_work_per_turn: NonZeroUsize::new(16).unwrap(),
    };
    let region = stats_alloc::Region::new(ALLOCATOR);
    let dispatcher =
        LocalDispatcher::try_new_batched(pool, operation, limits, NonZeroUsize::new(4).unwrap())
            .unwrap();
    let mut driver = pin!(dispatcher.run_scanned());
    assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
    let stats = region.change();
    dispatcher.close_intake();
    assert_eq!(poll(driver.as_mut(), Waker::noop()), Poll::Ready(Ok(())));
    stats
}

fn queue_slot_reuse_preserves_fifo_after_cancellation() {
    let remote = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::prepare(socket, &[23], &[23])?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            prepare_entry(&remote)
                .await
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let dispatcher = LocalDispatcher::try_new(
            pool,
            SlotOperation::default(),
            DispatchLimits {
                queue: QueueLimits {
                    max_items: 4,
                    max_charged_bytes: 5,
                },
                max_reply_slots: 4,
                max_work_per_turn: NonZeroUsize::MIN,
            },
        )
        .unwrap();
        let waker = Waker::noop();
        let mut driver = pin!(dispatcher.run_scanned());
        assert!(poll(driver.as_mut(), waker).is_pending());
        let enqueue = |id, bytes| {
            let mut wait = Box::pin(dispatcher.submit_queued(id, bytes));
            assert!(poll(wait.as_mut(), waker).is_pending());
            wait
        };

        let mut first = enqueue(1, 1);
        let mut second = enqueue(2, 1);
        let middle = enqueue(3, 2);
        let fourth = enqueue(4, 1);
        assert_eq!(
            dispatcher.submit_queued(0, 0).await,
            Err(DispatchError::Overloaded(Rejected {
                item: 0,
                reason: RejectReason::ItemLimit,
            })),
        );
        // 选中和完成各消耗一个工作单位。请求 2、3、4 仍在排队时接纳请求 5。
        assert!(poll(driver.as_mut(), waker).is_pending());
        assert!(poll(driver.as_mut(), waker).is_pending());
        assert_eq!(poll(first.as_mut(), waker), Poll::Ready(Ok(1)));
        let fifth = enqueue(5, 1);
        drop(middle);
        assert_eq!(
            dispatcher.submit_queued(99, 3).await,
            Err(DispatchError::Overloaded(Rejected {
                item: 99,
                reason: RejectReason::ByteLimit,
            })),
        );
        let sixth = enqueue(6, 2);
        assert!(poll(driver.as_mut(), waker).is_pending());
        assert!(poll(driver.as_mut(), waker).is_pending());
        assert_eq!(poll(second.as_mut(), waker), Poll::Ready(Ok(2)));

        // 分别撤回队尾和队首请求，随后立即复用释放的槽。
        let tail = enqueue(7, 1);
        drop(tail);
        let eighth = enqueue(8, 1);
        drop(fourth);
        let ninth = enqueue(9, 1);

        // 请求 5 已被选中但回调尚未执行。槽复用后，旧请求的完成不能唤醒请求 10。
        assert!(poll(driver.as_mut(), waker).is_pending());
        drop(fifth);
        let mut tenth = enqueue(10, 1);
        assert!(poll(driver.as_mut(), waker).is_pending());
        assert!(poll(tenth.as_mut(), waker).is_pending());
        for (mut waiting, expected) in [(sixth, 6), (eighth, 8), (ninth, 9), (tenth, 10)] {
            assert!(poll(driver.as_mut(), waker).is_pending());
            assert!(poll(driver.as_mut(), waker).is_pending());
            assert_eq!(poll(waiting.as_mut(), waker), Poll::Ready(Ok(expected)));
        }
        let unselected = enqueue(11, 5);
        dispatcher.close_intake();
        assert_eq!(dispatcher.drain_unselected(NonZeroUsize::MIN).unwrap(), 1);
        assert_eq!(unselected.await, Err(DispatchError::Closed(11)));
        driver.await.unwrap();
    });
    remote.finish();
}

#[derive(Clone, Copy)]
enum Warmup {
    BeforeDispatcher,
    BeforeDriver,
    AfterDriver,
}

fn selected_jobs_keep_their_connections_after_reply_reuse(warmup: Warmup) {
    let peers = [(); 2].map(|_| {
        peer::Peer::start(|socket| {
            peer::handshake(socket)?;
            peer::prepare(socket, &[23], &[23])?;
            peer::eof(socket)
        })
    });
    peer::run(async {
        let mut pool =
            LocalPool::try_new(NonZeroUsize::new(2).unwrap(), PoolReuse::VerifyOnRelease).unwrap();
        if matches!(warmup, Warmup::BeforeDispatcher) {
            let mut entries = peers.iter();
            pool.prewarm(async || {
                prepare_entry(entries.next().unwrap())
                    .await
                    .map_err(PrewarmFailure::Uncertain)
            })
            .await
            .unwrap();
        }
        let operation = SlotOperation::default();
        let gate = Rc::clone(&operation.direct_gate);
        let dispatcher = LocalDispatcher::try_new(
            pool,
            operation,
            DispatchLimits {
                queue: QueueLimits {
                    max_items: 1,
                    max_charged_bytes: 1,
                },
                max_reply_slots: 1,
                max_work_per_turn: NonZeroUsize::new(16).unwrap(),
            },
        )
        .unwrap();
        let install = async || {
            for peer in &peers {
                assert_eq!(
                    dispatcher
                        .try_replace(async || prepare_entry(peer)
                            .await
                            .map_err(PrewarmFailure::Uncertain))
                        .await
                        .unwrap(),
                    InstallOutcome::Installed
                );
            }
        };
        if matches!(warmup, Warmup::BeforeDriver) {
            install().await;
        }
        let startup = stats_alloc::Region::new(ALLOCATOR);
        let mut driver = pin!(dispatcher.run_scanned());
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        if matches!(warmup, Warmup::AfterDriver) {
            install().await;
        } else {
            // 扫描驱动只预分配一张执行槽表及每个作业的固定存储。
            assert_eq!(startup.change().allocations, peers.len() + 1);
            assert_eq!(startup.change().reallocations, 0);
        }
        let mut first = Box::pin(dispatcher.submit_queued(0, 1));
        assert!(poll(first.as_mut(), Waker::noop()).is_pending());
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        assert_eq!(dispatcher.pool_occupancy().leased, 1);
        drop(first);

        let region = stats_alloc::Region::new(ALLOCATOR);
        let mut second = pin!(dispatcher.submit_queued(7, 1));
        assert!(poll(second.as_mut(), Waker::noop()).is_pending());
        assert!(poll(driver.as_mut(), Waker::noop()).is_pending());
        assert_eq!(poll(second.as_mut(), Waker::noop()), Poll::Ready(Ok(7)));
        if !matches!(warmup, Warmup::AfterDriver) {
            assert_eq!(region.change().allocations, 0);
            assert_eq!(region.change().reallocations, 0);
        }
        assert_eq!(dispatcher.pool_occupancy().leased, 1);
        gate.open();
        dispatcher.close_intake();
        assert_eq!(driver.await, Ok(()));
        assert_eq!(dispatcher.pool_occupancy().ready, 2);
    });
    for peer in peers {
        peer.finish();
    }
}

// 单独在本测试进程中测量全局分配计数，避免其他测试并发分配。
#[test]
fn direct_allocation_batch_bounds_and_cancelled_waiters() {
    spawn_requires_a_current_runtime();
    peer::run(async {
        let small = vacant_pool_driver_allocations(NonZeroUsize::MIN);
        let large = vacant_pool_driver_allocations(NonZeroUsize::new(1024).unwrap());
        assert_eq!(large.allocations, small.allocations);
        assert_eq!(large.bytes_allocated, small.bytes_allocated);
    });
    queue_slot_reuse_preserves_fifo_after_cancellation();
    for warmup in [
        Warmup::BeforeDispatcher,
        Warmup::BeforeDriver,
        Warmup::AfterDriver,
    ] {
        selected_jobs_keep_their_connections_after_reply_reuse(warmup);
    }
    driver_context_allocations_and_fairness();
    enqueuing_a_request_only_wakes_the_driver();
    reject_driver_poll_from_another_runtime();
    suspended_maintenance_keeps_shutdown_and_reservations_consistent();
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        let statement = peer::prepare(socket, &[23], &[23])?;

        peer::execution(socket, &statement)?;
        socket.write_all(&peer::sql_error("22012", b'I'))?;

        // 收到两个独立的 Sync 后再回复，以检验第二项能在第一项确认前发送。
        peer::execution(socket, &statement)?;
        peer::execution(socket, &statement)?;
        socket.write_all(&peer::result(2, b'I'))?;
        socket.write_all(&peer::sql_error("22012", b'I'))?;

        peer::execution(socket, &statement)?;
        socket.write_all(&peer::result(5, b'I'))?;
        peer::execution(socket, &statement)?;
        socket.write_all(&peer::result(7, b'I'))?;
        peer::eof(socket)
    });

    let replacement = peer::run(async {
        let gate_open = Rc::new(Cell::new(false));
        let batch_sizes = Rc::new(RefCell::new(Vec::new()));
        let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            prepare_entry(&peer)
                .await
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let dispatcher = LocalDispatcher::try_new_batched(
            pool,
            Operation {
                gate_open: Rc::clone(&gate_open),
                batch_sizes: Rc::clone(&batch_sizes),
            },
            DispatchLimits {
                queue: QueueLimits {
                    max_items: 3,
                    max_charged_bytes: 3,
                },
                max_reply_slots: 4,
                max_work_per_turn: NonZeroUsize::new(16).unwrap(),
            },
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            dispatcher.submit_queued(Request::Probe, 1).await,
            Err(DispatchError::DriverNotRunning(Request::Probe))
        ));
        let mut before_driver = pin!(dispatcher.try_submit_inline(Request::Gate));
        assert!(poll(before_driver.as_mut(), Waker::noop()).is_pending());
        let rejected = dispatcher
            .try_submit_inline(Request::Probe)
            .await
            .unwrap_err();
        assert!(matches!(
            &rejected,
            DispatchError::InlineUnavailable(Request::Probe)
        ));
        assert!(matches!(rejected.into_unselected(), Some(Request::Probe)));
        assert!(matches!(
            dispatcher.submit_queued(Request::Probe, 1).await,
            Err(DispatchError::DriverNotRunning(Request::Probe))
        ));
        gate_open.set(true);
        assert!(matches!(
            poll(before_driver.as_mut(), Waker::noop()),
            Poll::Ready(Ok(Ok(0)))
        ));
        gate_open.set(false);

        let wakes = Arc::new(WakeCount::default());
        let dispatch_waker = Waker::from(Arc::clone(&wakes));
        let mut driver = pin!(dispatcher.run_scanned());
        assert!(poll(driver.as_mut(), &dispatch_waker).is_pending());
        assert_eq!(
            dispatcher.run_scanned().await,
            Err(DriverError::AlreadyRunning)
        );

        let region = stats_alloc::Region::new(ALLOCATOR);
        let direct = poll(
            pin!(dispatcher.try_submit_inline(Request::Probe)),
            Waker::noop(),
        );
        let allocation_change = region.change();
        assert!(matches!(direct, Poll::Ready(Ok(Ok(1)))));
        assert_eq!(allocation_change.allocations, 0);
        assert_eq!(allocation_change.reallocations, 0);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);

        let mut queued_probe = pin!(dispatcher.submit_queued(Request::Probe, 1));
        assert!(poll(queued_probe.as_mut(), Waker::noop()).is_pending());
        assert!(poll(driver.as_mut(), &dispatch_waker).is_pending());
        assert!(matches!(
            poll(queued_probe.as_mut(), Waker::noop()),
            Poll::Ready(Ok(Ok(1)))
        ));

        let replacement = peer::Peer::start(|socket| {
            peer::handshake(socket)?;
            let statement = peer::prepare(socket, &[23], &[23])?;
            peer::execution(socket, &statement)?;
            socket.write_all(&peer::result(11, b'I'))?;
            peer::eof(socket)
        });
        assert_sql_failure(
            dispatcher
                .try_submit_inline(Request::Query(-1))
                .await
                .unwrap(),
        );
        let mut direct = pin!(dispatcher.try_submit_inline(Request::Gate));
        assert!(poll(direct.as_mut(), Waker::noop()).is_pending());

        let mut first = pin!(dispatcher.submit_queued(Request::Query(2), 1));
        let mut cancelled = Box::pin(dispatcher.submit_queued(Request::Query(4), 1));
        let mut second = pin!(dispatcher.submit_queued(Request::Query(3), 1));
        assert!(poll(first.as_mut(), Waker::noop()).is_pending());
        assert!(poll(cancelled.as_mut(), Waker::noop()).is_pending());
        assert!(matches!(
            poll(
                pin!(dispatcher.submit_queued(Request::Probe, 2)),
                Waker::noop()
            ),
            Poll::Ready(Err(DispatchError::Overloaded(Rejected {
                item: Request::Probe,
                reason: RejectReason::ByteLimit,
            })))
        ));
        assert!(poll(second.as_mut(), Waker::noop()).is_pending());
        assert!(matches!(
            poll(
                pin!(dispatcher.submit_queued(Request::Probe, 1)),
                Waker::noop()
            ),
            Poll::Ready(Err(DispatchError::Overloaded(Rejected {
                item: Request::Probe,
                reason: RejectReason::ItemLimit,
            })))
        ));

        drop(cancelled);
        let mut tail = pin!(dispatcher.submit_queued(Request::Query(5), 1));
        assert!(poll(tail.as_mut(), Waker::noop()).is_pending());
        assert!(poll(driver.as_mut(), &dispatch_waker).is_pending());
        let wakes_before_return = wakes.0.load(Ordering::Relaxed);

        gate_open.set(true);
        assert!(matches!(
            poll(direct.as_mut(), Waker::noop()),
            Poll::Ready(Ok(Ok(0)))
        ));
        assert!(wakes.0.load(Ordering::Relaxed) > wakes_before_return);
        // 归还连接后仍须遵守 FIFO；队列满时拒绝后来者。
        assert!(matches!(
            poll(
                pin!(dispatcher.submit_queued(Request::Probe, 1)),
                Waker::noop()
            ),
            Poll::Ready(Err(_))
        ));

        let (driver_result, ()) = join(driver, async {
            let (first, second, tail) = join3(first, second, tail).await;
            assert_eq!(first.unwrap().unwrap(), 2);
            assert_sql_failure(second.unwrap());
            assert_eq!(tail.unwrap().unwrap(), 5);
            assert_eq!(&*batch_sizes.borrow(), &[2]);

            let cancelled_maintenance_wakes = Arc::new(WakeCount::default());
            let cancelled_maintenance_waker = Waker::from(Arc::clone(&cancelled_maintenance_wakes));
            let mut cancelled_maintenance = Box::pin(
                dispatcher.maintain_one(async |lease| lease.release(SessionHygiene::Verified)),
            );
            assert!(
                poll(cancelled_maintenance.as_mut(), &cancelled_maintenance_waker).is_pending()
            );
            assert_eq!(Arc::strong_count(&cancelled_maintenance_wakes), 3);
            drop(cancelled_maintenance);
            assert_eq!(Arc::strong_count(&cancelled_maintenance_wakes), 2);

            let maintenance_wakes = Arc::new(WakeCount::default());
            let maintenance_waker = Waker::from(Arc::clone(&maintenance_wakes));
            let mut repair = pin!(
                dispatcher.maintain_one(async |lease| lease.release(SessionHygiene::Verified))
            );
            assert!(poll(repair.as_mut(), &maintenance_waker).is_pending());
            let competing_wakes = Arc::new(WakeCount::default());
            let competing_waker = Waker::from(Arc::clone(&competing_wakes));
            assert!(matches!(
                poll(
                    pin!(
                        dispatcher.maintain_one(async |lease| {
                            lease.release(SessionHygiene::Verified)
                        })
                    ),
                    &competing_waker
                ),
                Poll::Ready(Err(MaintenanceError::AlreadyWaiting))
            ));
            assert_eq!(Arc::strong_count(&maintenance_wakes), 3);
            assert_eq!(Arc::strong_count(&competing_wakes), 2);

            gate_open.set(false);
            let mut abandoned = Box::pin(dispatcher.try_submit_inline(Request::Gate));
            assert!(poll(abandoned.as_mut(), Waker::noop()).is_pending());
            let mut waiting = pin!(dispatcher.submit_queued(Request::Query(7), 1));
            assert!(poll(waiting.as_mut(), Waker::noop()).is_pending());
            drop(abandoned);
            assert_eq!(dispatcher.pool_occupancy().quarantined, 1);
            assert_eq!(maintenance_wakes.0.load(Ordering::Relaxed), 1);
            assert_eq!(competing_wakes.0.load(Ordering::Relaxed), 0);
            assert!(matches!(
                poll(repair.as_mut(), &maintenance_waker),
                Poll::Ready(Ok(Some(ReleaseOutcome::Returned)))
            ));
            assert_eq!(waiting.await.unwrap().unwrap(), 7);
            assert!(matches!(
                dispatcher
                    .try_replace(async || -> Result<_, PrewarmFailure<Error>> {
                        panic!("a full pool must not call the replacement factory")
                    })
                    .await,
                Err(DispatchReplaceError::NoVacantSlot)
            ));

            let mut retiring = Box::pin(dispatcher.try_submit_inline(Request::Gate));
            assert!(poll(retiring.as_mut(), Waker::noop()).is_pending());
            drop(retiring);
            dispatcher
                .maintain_one(async |lease| lease.close().await)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(dispatcher.pool_occupancy().vacant, 1);
            let mut waiting = pin!(dispatcher.submit_queued(Request::Query(11), 1));
            assert!(poll(waiting.as_mut(), Waker::noop()).is_pending());
            assert_eq!(
                dispatcher
                    .try_replace(async || {
                        prepare_entry(&replacement)
                            .await
                            .map_err(PrewarmFailure::Uncertain)
                    })
                    .await
                    .unwrap(),
                InstallOutcome::Installed
            );
            assert_eq!(waiting.await.unwrap().unwrap(), 11);

            let mut held = pin!(dispatcher.try_submit_inline(Request::Gate));
            let mut closing = pin!(dispatcher.submit_queued(Request::Query(12), 1));
            assert!(poll(held.as_mut(), Waker::noop()).is_pending());
            assert!(poll(closing.as_mut(), Waker::noop()).is_pending());
            dispatcher.close_intake();
            assert!(matches!(
                closing.await,
                Err(DispatchError::Closed(Request::Query(12)))
            ));
            gate_open.set(true);
            assert_eq!(held.await.unwrap().unwrap(), 0);
        })
        .await;
        driver_result.unwrap();
        assert!(matches!(
            dispatcher.submit_queued(Request::Probe, 1).await,
            Err(DispatchError::Closed(Request::Probe))
        ));
        assert!(matches!(
            dispatcher
                .try_replace(async || -> Result<_, PrewarmFailure<Error>> {
                    panic!("a closed dispatcher must not call the replacement factory")
                })
                .await,
            Err(DispatchReplaceError::Closed)
        ));
        replacement
    });
    peer.finish();
    replacement.finish();
    reply_slots();
}
