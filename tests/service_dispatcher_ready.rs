#![cfg(feature = "service")]

#[path = "support/peer.rs"]
mod peer;

#[cfg(target_os = "linux")]
use compio::runtime::Runtime;
use compio_postgres::{
    Client, ClientOptions, Error, NativeTransport, TcpConnection,
    service::{
        BatchDispatch, BatchDispatchOperation, DispatchBatch, DispatchError, DispatchLimits,
        DispatchOperation, DriverError, LocalDispatcher, LocalPool, PoolEntry, PoolReuse,
        PrewarmFailure, QueueLimits, SessionHygiene,
    },
};
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    num::NonZeroUsize,
    rc::Rc,
    task::{Context, Poll, Waker},
    time::Duration,
};

#[derive(Debug, Default)]
struct Job {
    index: usize,
    complete: Cell<bool>,
    wake_self: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Job {
    fn wake(&self) {
        self.waker.borrow().as_ref().unwrap().wake_by_ref();
    }
}

#[derive(Clone)]
struct Probe {
    polls: Rc<RefCell<Vec<usize>>>,
    batches: Rc<RefCell<Vec<Vec<usize>>>>,
}

impl Probe {
    async fn wait_for_polls(&self, count: usize) {
        while self.polls.borrow().len() < count {
            compio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

impl DispatchOperation<NativeTransport, ()> for Probe {
    type Request = Rc<Job>;
    type Response = usize;

    async fn execute_one(
        &self,
        _: &mut Client<NativeTransport>,
        _: &mut (),
        job: Rc<Job>,
    ) -> (usize, SessionHygiene) {
        poll_fn(|cx| {
            self.polls.borrow_mut().push(job.index);
            job.waker.replace(Some(cx.waker().clone()));
            if job.wake_self.replace(false) {
                cx.waker().wake_by_ref();
            }
            if job.complete.get() {
                Poll::Ready((job.index, SessionHygiene::Verified))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

impl BatchDispatchOperation<NativeTransport, ()> for Probe {
    async fn execute_batch(
        &self,
        _: &mut Client<NativeTransport>,
        _: &mut (),
        batch: &mut DispatchBatch<'_, Rc<Job>, usize>,
    ) -> SessionHygiene {
        self.batches
            .borrow_mut()
            .push(batch.requests().map(|(_, job)| job.index).collect());
        for (index, job) in batch.requests() {
            batch.stage_reply(index, job.index).unwrap();
        }
        SessionHygiene::Verified
    }
}

fn peers(count: usize) -> Vec<peer::Peer> {
    (0..count)
        .map(|_| {
            peer::Peer::start(|socket| {
                peer::handshake(socket)?;
                peer::eof(socket)
            })
        })
        .collect()
}

async fn dispatcher(
    peers: &[peer::Peer],
    batch: usize,
    replies: usize,
    quantum: usize,
) -> (
    Rc<LocalDispatcher<NativeTransport, (), Probe, BatchDispatch>>,
    Probe,
) {
    let mut pool = LocalPool::try_new(
        NonZeroUsize::new(peers.len()).unwrap(),
        PoolReuse::VerifyOnRelease,
    )
    .unwrap();
    let mut servers = peers.iter();
    pool.prewarm(async || {
        let client = TcpConnection::connect(ClientOptions::short_queries(
            servers.next().unwrap().config(),
        ))
        .await
        .map_err(PrewarmFailure::Uncertain)?;
        Ok::<_, PrewarmFailure<Error>>(PoolEntry::new(client, ()))
    })
    .await
    .unwrap();
    let probe = Probe {
        polls: Rc::default(),
        batches: Rc::default(),
    };
    let dispatcher = LocalDispatcher::try_new_batched(
        pool,
        probe.clone(),
        DispatchLimits {
            queue: QueueLimits {
                max_items: replies,
                max_charged_bytes: replies,
            },
            max_reply_slots: replies,
            max_work_per_turn: NonZeroUsize::new(quantum).unwrap(),
        },
        NonZeroUsize::new(batch).unwrap(),
    )
    .unwrap();
    (Rc::new(dispatcher), probe)
}

#[test]
fn a_spawned_driver_reserves_intake_before_its_first_poll() {
    for ready in [false, true] {
        let peers = peers(1);
        peer::run(async {
            let (dispatcher, probe) = dispatcher(&peers, 1, 1, 2).await;
            let driver = if ready {
                Rc::clone(&dispatcher).spawn_ready()
            } else {
                Rc::clone(&dispatcher).spawn_scanned()
            }
            .unwrap();
            assert!(matches!(
                Rc::clone(&dispatcher).spawn_scanned(),
                Err(DriverError::AlreadyRunning)
            ));
            assert!(matches!(
                Rc::clone(&dispatcher).spawn_ready(),
                Err(DriverError::AlreadyRunning)
            ));
            assert_eq!(
                dispatcher.run_scanned().await,
                Err(DriverError::AlreadyRunning)
            );

            let job = Rc::new(Job {
                index: 9,
                complete: Cell::new(true),
                ..Job::default()
            });
            assert_eq!(dispatcher.submit_queued(job, 1).await.unwrap(), 9);
            assert_eq!(probe.polls.take(), [9]);
            dispatcher.close_intake();
            driver.await.unwrap().unwrap();
        });
        for peer in peers {
            peer.finish();
        }
    }
}

#[test]
fn a_spawned_driver_returns_waiting_requests_if_stopped_before_polling() {
    enum Stop {
        CloseIntake,
        Cancel,
        Drop,
    }

    for ready in [false, true] {
        for stop in [Stop::CloseIntake, Stop::Cancel, Stop::Drop] {
            let peers = peers(1);
            peer::run(async {
                let (dispatcher, probe) = dispatcher(&peers, 1, 1, 1).await;
                let driver = if ready {
                    Rc::clone(&dispatcher).spawn_ready()
                } else {
                    Rc::clone(&dispatcher).spawn_scanned()
                }
                .unwrap();
                {
                    let job = Rc::new(Job {
                        complete: Cell::new(true),
                        ..Job::default()
                    });
                    let mut waiting = std::pin::pin!(dispatcher.submit_queued(Rc::clone(&job), 1));
                    assert!(
                        waiting
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    );
                    match stop {
                        Stop::CloseIntake => {
                            dispatcher.close_intake();
                            driver.await.unwrap().unwrap();
                        }
                        Stop::Cancel => assert!(driver.cancel().await.is_none()),
                        Stop::Drop => drop(driver),
                    }
                    assert!(
                        matches!(waiting.await, Err(DispatchError::Closed(returned)) if Rc::ptr_eq(&job, &returned))
                    );
                    assert!(probe.polls.borrow().is_empty());
                }
                let pool = Rc::into_inner(dispatcher).unwrap().into_pool();
                assert_eq!(pool.occupancy().ready, 1);
            });
            for peer in peers {
                peer.finish();
            }
        }
    }
}

#[test]
fn wakes_are_coalesced_fair_and_isolated_across_reuse_and_cancellation() {
    const ACTIVE: usize = 8;
    let peers = peers(ACTIVE);
    peer::run(async {
        let (d, probe) = dispatcher(&peers, 1, ACTIVE + 1, 1).await;
        #[cfg(target_os = "linux")]
        let runtime = Runtime::current();
        #[cfg(target_os = "linux")]
        let personality = runtime
            .driver_type()
            .is_iouring()
            .then(|| runtime.register_personality().unwrap());
        #[cfg(target_os = "linux")]
        let driver = match personality {
            Some(id) => {
                use compio_postgres::expert::linux::DispatcherExt;
                Rc::clone(&d).spawn_ready_with_personality(id)
            }
            None => Rc::clone(&d).spawn_ready(),
        }
        .unwrap();
        #[cfg(not(target_os = "linux"))]
        let driver = Rc::clone(&d).spawn_ready().unwrap();
        let jobs: Vec<_> = (0..ACTIVE + 4)
            .map(|index| {
                Rc::new(Job {
                    index,
                    ..Job::default()
                })
            })
            .collect();
        let submit = |index: usize| {
            let mut waiter = Box::pin(d.submit_queued(Rc::clone(&jobs[index]), 1));
            assert!(
                waiter
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            waiter
        };
        let mut selected: Vec<_> = (0..ACTIVE).map(submit).collect();
        probe.wait_for_polls(ACTIVE).await;
        assert_eq!(probe.polls.take(), (0..ACTIVE).collect::<Vec<_>>());

        let last = &jobs[7];
        let stale = last.waker.borrow().as_ref().unwrap().clone();
        last.complete.set(true);
        // 作业也可能在返回 Ready 的那次轮询中唤醒自己。
        last.wake_self.set(true);
        let foreign = stale.clone();
        std::thread::spawn(move || {
            for _ in 0..8 {
                foreign.wake_by_ref();
            }
        })
        .join()
        .unwrap();
        assert_eq!(selected.pop().unwrap().await.unwrap(), 7);
        assert_eq!(probe.polls.take(), [7]);
        let reused = submit(8);
        probe.wait_for_polls(1).await;
        assert_eq!(probe.polls.take(), [8]);
        stale.wake_by_ref();
        compio::time::sleep(Duration::from_millis(1)).await;
        assert!(probe.polls.borrow().is_empty());

        jobs[0].wake_self.set(true);
        for job in &jobs[..3] {
            job.wake();
        }
        probe.wait_for_polls(4).await;
        assert_eq!(probe.polls.take(), [0, 1, 2, 0]);

        drop(submit(9));
        drop(selected.pop().unwrap());
        let replacement = submit(10);
        assert_eq!(d.pool_occupancy().leased, ACTIVE);
        jobs[6].complete.set(true);
        jobs[6].wake();
        probe.wait_for_polls(2).await;
        assert_eq!(probe.polls.take(), [6, 10]);
        let waiting = submit(11);
        assert!(driver.cancel().await.is_none());
        assert!(matches!(replacement.await, Err(DispatchError::Unresolved)));
        assert!(matches!(reused.await, Err(DispatchError::Unresolved)));
        assert!(matches!(waiting.await, Err(DispatchError::Closed(job)) if job.index == 11));
        assert_eq!(d.pool_occupancy().quarantined, ACTIVE);
        stale.wake();
        #[cfg(target_os = "linux")]
        if let Some(id) = personality {
            runtime.unregister_personality(id).unwrap();
        }
    });
    for peer in peers {
        peer.finish();
    }
}

#[test]
fn a_turn_spent_selecting_requests_does_not_delay_the_first_poll() {
    let peers = peers(4);
    peer::run(async {
        let (dispatcher, probe) = dispatcher(&peers, 1, 4, 1).await;
        let mut driver = std::pin::pin!(dispatcher.run_scanned());
        let mut context = Context::from_waker(Waker::noop());
        assert!(driver.as_mut().poll(&mut context).is_pending());
        let jobs: Vec<_> = (0..peers.len())
            .map(|index| {
                let job = Rc::new(Job {
                    index,
                    complete: Cell::new(true),
                    ..Job::default()
                });
                let mut waiter = Box::pin(dispatcher.submit_queued(job, 1));
                assert!(waiter.as_mut().poll(&mut context).is_pending());
                waiter
            })
            .collect();

        assert!(driver.as_mut().poll(&mut context).is_pending());
        assert!(probe.polls.borrow().is_empty());
        assert_eq!(dispatcher.pool_occupancy().leased, 1);

        assert!(driver.as_mut().poll(&mut context).is_pending());
        assert_eq!(probe.polls.take(), [0]);
        assert_eq!(dispatcher.pool_occupancy().leased, 0);

        drop(jobs);
        dispatcher.close_intake();
        driver.await.unwrap();
    });
    for peer in peers {
        peer.finish();
    }
}

#[test]
fn shutdown_never_returns_more_requests_than_the_selected_budget() {
    peer::run(async {
        let pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        let probe = Probe {
            polls: Rc::default(),
            batches: Rc::default(),
        };
        let dispatcher = LocalDispatcher::try_new(
            pool,
            probe.clone(),
            DispatchLimits {
                queue: QueueLimits {
                    max_items: 3,
                    max_charged_bytes: 3,
                },
                max_reply_slots: 3,
                max_work_per_turn: NonZeroUsize::MIN,
            },
        )
        .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut driver = std::pin::pin!(dispatcher.run_scanned());
        assert!(driver.as_mut().poll(&mut context).is_pending());
        let mut waiters = std::array::from_fn::<_, 3, _>(|index| {
            let request = Rc::new(Job {
                index,
                ..Job::default()
            });
            let mut waiter = Box::pin(dispatcher.submit_queued(request, 1));
            assert!(waiter.as_mut().poll(&mut context).is_pending());
            waiter
        });

        assert!(matches!(
            dispatcher.drain_unselected(NonZeroUsize::MIN),
            Err(compio_postgres::service::DriverError::IntakeOpen)
        ));
        dispatcher.close_intake();
        for waiter in &mut waiters {
            assert!(waiter.as_mut().poll(&mut context).is_pending());
        }
        let [first, second, third] = &mut waiters;
        assert_eq!(dispatcher.drain_unselected(NonZeroUsize::MIN).unwrap(), 1);
        assert!(
            matches!(first.as_mut().poll(&mut context), Poll::Ready(Err(DispatchError::Closed(job))) if job.index == 0)
        );
        assert!(second.as_mut().poll(&mut context).is_pending());
        assert!(third.as_mut().poll(&mut context).is_pending());

        assert!(driver.as_mut().poll(&mut context).is_pending());
        assert!(
            matches!(second.as_mut().poll(&mut context), Poll::Ready(Err(DispatchError::Closed(job))) if job.index == 1)
        );
        assert!(third.as_mut().poll(&mut context).is_pending());
        assert_eq!(driver.as_mut().poll(&mut context), Poll::Ready(Ok(())));
        assert!(
            matches!(third.as_mut().poll(&mut context), Poll::Ready(Err(DispatchError::Closed(job))) if job.index == 2)
        );
        assert!(probe.polls.borrow().is_empty());
        assert_eq!(dispatcher.drain_unselected(NonZeroUsize::MIN).unwrap(), 0);
    });
}

#[test]
fn drivers_bound_admission_by_member_and_preserve_fifo_batches() {
    for ready in [false, true] {
        for (slots, quantum, requests, batches, singles) in [
            (1, 1, 3, vec![], vec![0, 1, 2]),
            (1, 2, 3, vec![vec![0, 1]], vec![2]),
            (2, 3, 4, vec![vec![0, 1]], vec![2, 3]),
            (2, 3, 7, vec![vec![0, 1, 2], vec![3, 4]], vec![5, 6]),
        ] {
            let peers = peers(slots);
            peer::run(async {
                let (d, probe) = dispatcher(&peers, 4, requests, quantum).await;
                let driver = if ready {
                    Rc::clone(&d).spawn_ready()
                } else {
                    Rc::clone(&d).spawn_scanned()
                }
                .unwrap();
                let waiters: Vec<_> = (0..requests)
                    .map(|index| {
                        let job = Rc::new(Job {
                            index,
                            complete: Cell::new(true),
                            ..Job::default()
                        });
                        let mut waiter = Box::pin(d.submit_queued(job, 1));
                        assert!(
                            waiter
                                .as_mut()
                                .poll(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                        waiter
                    })
                    .collect();
                for (index, waiter) in waiters.into_iter().enumerate() {
                    assert_eq!(waiter.await.unwrap(), index);
                }
                assert_eq!(probe.batches.take(), batches);
                assert_eq!(probe.polls.take(), singles);
                d.close_intake();
                driver.await.unwrap().unwrap();
            });
            for peer in peers {
                peer.finish();
            }
        }
    }
}
