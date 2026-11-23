#![cfg(feature = "service")]

#[cfg(unix)]
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{
    BatchOptions, ClientOptions, Error, ExecutionOptions, ExecutionScheduling, NativeTransport,
    OnError, PreparedStatementStorage, QueryOptions, ResultFormats, ReuseState, Statement,
    StatementLimits, TcpConnection,
    service::{
        BoundedFifo, InstallOutcome, LocalPool, Occupancy, PoolEntry, PoolReuse, PrewarmError,
        PrewarmFailure, QueueLimits, RejectReason, ReleaseOutcome, SessionHygiene,
    },
    types::{Format, Oid, Parameter},
};
use std::{
    future::{Future, pending, poll_fn},
    io::Write,
    num::NonZeroUsize,
    task::Poll,
    time::Duration,
};

fn options<C>(config: C) -> ClientOptions<C> {
    let query = QueryOptions {
        limits: peer::query_limits(),
        scheduling: ExecutionScheduling::Uninterrupted,
    };
    ClientOptions::new(
        config,
        ExecutionOptions {
            query,
            batch: Some(BatchOptions {
                member_limits: query.limits,
                max_inflight: 4,
                max_requests: 16,
                max_queued_request_bytes: 8192,
                max_diagnostic_bytes: 4096,
                scheduling: query.scheduling,
            }),
        },
        StatementLimits {
            max_statements: 4,
            max_metadata_bytes: 4096,
        },
    )
}

fn slots(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).unwrap()
}

#[test]
fn cancellation_route_failure_refunds_a_retired_connection_slot() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        drop(listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        peer::handshake(&mut socket).unwrap();
        peer::eof(&mut socket).unwrap();
    });
    peer::run(async {
        let config = compio_postgres::TcpConfig::plaintext(
            endpoint,
            "test",
            "test",
            compio_postgres::AuthenticationPolicy::AllowAuthenticationOk,
            compio_postgres::WireLimits {
                receive_capacity: 8192,
                max_frame_len: 8191,
                max_request_len: 8192,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        );
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || {
            TcpConnection::connect(options(config.clone()))
                .await
                .map(|connection| PoolEntry::new(connection, ()))
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        assert!(matches!(
            pool.try_acquire().unwrap()
                .unwrap()
                .request_cancel_and_discard()
                .await,
            Err(Error::CancelRequest(error)) if matches!(*error, Error::Io(_))
        ));
        let occupancy = pool.occupancy();
        assert_eq!((occupancy.maintenance, occupancy.vacant), (0, 1));
    });
    server.join().unwrap();
}

#[test]
fn retirement_resumes_after_waiter_drop_and_rejects_a_second_driver() {
    use std::io::Read;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (release, wait_to_reply) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut original, _) = listener.accept().unwrap();
        original
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        peer::handshake(&mut original).unwrap();
        let (mut cancel, _) = listener.accept().unwrap();
        cancel
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut packet = [0; 20];
        cancel.read_exact(&mut packet).unwrap();
        assert_eq!(&packet[..4], &20_u32.to_be_bytes());
        wait_to_reply.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(cancel);
        peer::eof(&mut original).unwrap();
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let config = compio_postgres::TcpConfig::plaintext(
            endpoint,
            "test",
            "test",
            compio_postgres::AuthenticationPolicy::AllowAuthenticationOk,
            compio_postgres::WireLimits {
                receive_capacity: 8192,
                max_frame_len: 8191,
                max_request_len: 8192,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        );
        pool.prewarm(async || {
            TcpConnection::connect(options(config.clone()))
                .await
                .map(|connection| PoolEntry::new(connection, ()))
                .map_err(PrewarmFailure::Uncertain)
        })
        .await
        .unwrap();
        let mut retiring = Box::pin(
            pool.try_acquire()
                .unwrap()
                .unwrap()
                .request_cancel_and_discard(),
        );
        poll_fn(|cx| {
            assert!(retiring.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(retiring);
        let pending = pool.pending_maintenance();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].resumable);
        let id = pending[0].id;
        assert!(!pool.confirm_retired(id));
        assert!(pool.reserve_replacement().is_none());

        let mut resumed = Box::pin(pool.resume_retirement(id));
        poll_fn(|cx| {
            assert!(resumed.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(matches!(pool.resume_retirement(id).await, Err(Error::Busy)));
        drop(resumed);
        assert_eq!(pool.pending_maintenance(), pending);

        struct RetirementWake(std::sync::atomic::AtomicBool);
        impl std::task::Wake for RetirementWake {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let signal = std::sync::Arc::new(RetirementWake(false.into()));
        let waker = std::task::Waker::from(signal.clone());
        let mut old = Box::pin(pool.resume_retirement(id));
        assert!(
            old.as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        assert!(pool.release_retirement_waiter(id));
        assert!(signal.0.load(std::sync::atomic::Ordering::Relaxed));

        let mut forgotten = Box::pin(pool.resume_retirement(id));
        poll_fn(|cx| {
            assert!(forgotten.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(matches!(
            old.await,
            Err(Error::InvalidInput("the retirement waiter was released"))
        ));
        assert!(pool.pending_maintenance()[0].claimed);
        std::mem::forget(forgotten);
        assert!(pool.pending_maintenance()[0].claimed);
        assert!(pool.release_retirement_waiter(id));
        assert_eq!(pool.pending_maintenance(), pending);
        release.send(()).unwrap();
        pool.resume_retirement(id).await.unwrap();
        assert!(pool.pending_maintenance().is_empty());
        assert_eq!(pool.occupancy().vacant, 1);
    });
    server.join().unwrap();
}

#[test]
fn a_suspended_first_factory_preserves_its_reservation_on_worker_change() {
    use compio::runtime::Runtime;
    use compio_postgres::NativeTransport;
    use std::{
        cell::Cell,
        task::{Context, Waker},
    };

    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut pool =
        LocalPool::<NativeTransport, ()>::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease)
            .unwrap();
    let polls = Cell::new(0);
    let mut warm = Box::pin(pool.prewarm(async || -> Result<_, PrewarmFailure<Error>> {
        poll_fn(|_| {
            polls.set(polls.get() + 1);
            Poll::Pending
        })
        .await
    }));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(owner.enter(|| warm.as_mut().poll(&mut cx)).is_pending());
    let Poll::Ready(Err(PrewarmError::WrongRuntime {
        installed: 0,
        pending: Some(id),
    })) = foreign.enter(|| warm.as_mut().poll(&mut cx))
    else {
        panic!("预热须保留未决槽");
    };
    drop(warm);
    assert_eq!(polls.get(), 1);
    assert_eq!(pool.occupancy().vacant, 0);
    let pending = pool.pending_maintenance();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert!(!pending[0].claimed && !pending[0].resumable);
    assert!(pool.confirm_retired(id));
    assert_eq!(pool.occupancy().vacant, 1);
}

#[test]
fn pool_rejects_checkout_prewarm_and_install_on_a_foreign_worker() {
    let first = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    let foreign = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    let owner = compio::runtime::Runtime::new().unwrap();
    let other = compio::runtime::Runtime::new().unwrap();
    let mut pool = LocalPool::try_new(slots(2), PoolReuse::VerifyOnRelease).unwrap();
    owner.block_on(async {
        let client = TcpConnection::connect(options(first.config()))
            .await
            .unwrap();
        assert_eq!(
            pool.reserve_replacement()
                .unwrap()
                .install(PoolEntry::new(client, ())),
            InstallOutcome::Installed
        );
    });
    other.block_on(async {
        assert!(!pool.is_current_worker());
        assert!(matches!(pool.try_acquire(), Err(Error::InvalidInput(_))));
        let occupancy = pool.occupancy();
        assert!(matches!(
            pool.prewarm(async || -> Result<_, PrewarmFailure<Error>> {
                panic!("prewarm must reject a foreign worker before calling the factory")
            })
            .await,
            Err(PrewarmError::WrongRuntime {
                installed: 0,
                pending: None
            })
        ));
        assert_eq!(pool.occupancy(), occupancy);
        let client = TcpConnection::connect(options(foreign.config()))
            .await
            .unwrap();
        assert_eq!(
            pool.reserve_replacement()
                .unwrap()
                .install(PoolEntry::new(client, ())),
            InstallOutcome::WrongRuntime
        );
        assert_eq!(pool.occupancy().quarantined, 1);
    });
    owner.block_on(async {
        assert!(pool.try_acquire_quarantined().unwrap().is_none());
        pool.try_acquire().unwrap().unwrap().close().await.unwrap();
    });
    other.block_on(async {
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
        assert_eq!(pool.occupancy().vacant, 2);
    });
    first.finish();
    foreign.finish();
}

#[test]
fn first_return_from_quarantine_binds_the_pool() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    let owner = compio::runtime::Runtime::new().unwrap();
    let other = compio::runtime::Runtime::new().unwrap();
    let pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
    let client = owner
        .block_on(TcpConnection::connect(options(peer.config())))
        .unwrap();
    other.enter(|| {
        assert_eq!(
            pool.reserve_replacement()
                .unwrap()
                .install(PoolEntry::new(client, ())),
            InstallOutcome::WrongRuntime
        );
    });
    owner.enter(|| {
        let lease = pool.try_acquire_quarantined().unwrap().unwrap();
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Returned
        );
    });
    other.enter(|| assert!(matches!(pool.try_acquire(), Err(Error::InvalidInput(_)))));
    let lease = owner.enter(|| pool.try_acquire().unwrap().unwrap());
    other.enter(|| {
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::WrongRuntime
        );
    });
    owner.block_on(async {
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
    });
    peer.finish();
}

#[test]
fn replaced_client_is_quarantined_and_does_not_refund_the_original_connection() {
    let first = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    let replacement = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    peer::run(async {
        let pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let original = TcpConnection::connect(options(first.config()))
            .await
            .unwrap();
        let fresh = TcpConnection::connect(options(replacement.config()))
            .await
            .unwrap();
        assert_eq!(
            pool.reserve_replacement()
                .unwrap()
                .install(PoolEntry::new(original, ())),
            InstallOutcome::Installed
        );
        let mut lease = pool.try_acquire().unwrap().unwrap();
        let original = std::mem::replace(lease.client_and_state().0, fresh);
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::ConnectionReplaced
        );
        assert!(pool.try_acquire().unwrap().is_none());
        let mismatch = pool.try_acquire_quarantined().unwrap().unwrap();
        assert!(matches!(
            mismatch.close().await,
            Err(Error::InvalidInput(_))
        ));
        assert!(pool.reserve_replacement().is_none());
        let pending = pool.pending_maintenance();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].resumable);
        original.close_local().await.unwrap();
        assert!(pool.confirm_retired(pending[0].id));
        assert_eq!(pool.occupancy().vacant, 1);
    });
    first.finish();
    replacement.finish();
}

async fn prepared(client: &mut TcpConnection) -> Result<Statement, Error> {
    client
        .prepare(
            "SELECT $1::int4",
            &[Oid::INT4],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await
}

#[test]
fn prewarm_reuses_prepared_state_and_retirement_controls_capacity() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        let statement = peer::prepare(socket, &[23], &[23])?;
        for value in [17, 23] {
            peer::execution(socket, &statement)?;
            socket.write_all(&peer::result(value, b'I'))?;
        }
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let installed = pool
            .prewarm(async || -> Result<_, PrewarmFailure<Error>> {
                let mut client = TcpConnection::connect(options(peer.config()))
                    .await
                    .map_err(PrewarmFailure::Uncertain)?;
                let statement = prepared(&mut client)
                    .await
                    .map_err(PrewarmFailure::Uncertain)?;
                Ok(PoolEntry::new(client, statement))
            })
            .await
            .unwrap();
        assert_eq!(installed, 1);
        for value in [17, 23] {
            let mut lease = pool.try_acquire().unwrap().unwrap();
            assert!(pool.try_acquire().unwrap().is_none());
            assert!(pool.reserve_replacement().is_none());
            let (client, statement) = lease.client_and_state();
            assert_eq!(
                client
                    .query(statement, &[Parameter::int4(value)])
                    .one::<i32>(OnError::RecoverExplicitly)
                    .await
                    .unwrap(),
                value
            );
            assert_eq!(
                lease.release(SessionHygiene::Verified),
                ReleaseOutcome::Returned
            );
        }

        let lease = pool.try_acquire().unwrap().unwrap();
        let unpolled_close = lease.close();
        drop(unpolled_close);
        assert!(pool.try_acquire().unwrap().is_none());
        assert!(pool.reserve_replacement().is_none());
        assert_eq!(pool.occupancy().quarantined, 1);

        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
        assert_eq!(pool.occupancy().vacant, 1);
        let replacement = pool.reserve_replacement().unwrap();
        assert!(pool.reserve_replacement().is_none());
        replacement.confirm_vacant();
        assert_eq!(pool.occupancy().vacant, 1);
    });
    peer.finish();
}

#[test]
fn installation_quarantines_connections_that_are_not_protocol_idle() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        peer::control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        peer::eof(socket)
    });
    peer::run(async {
        let pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
        let mut client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        drop(client.begin_transaction().await.unwrap());
        let outcome = pool
            .reserve_replacement()
            .unwrap()
            .install(PoolEntry::new(client, ()));
        assert_eq!(
            outcome,
            InstallOutcome::Quarantined(ReuseState::NeedsTransactionDecision)
        );
        assert!(pool.try_acquire().unwrap().is_none());
        assert!(pool.reserve_replacement().is_none());
        let mut lease = pool.try_acquire_quarantined().unwrap().unwrap();
        lease
            .client_and_state()
            .0
            .recover_and_rollback()
            .await
            .unwrap();
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Returned
        );
        pool.try_acquire().unwrap().unwrap().close().await.unwrap();
        assert_eq!(pool.occupancy().vacant, 1);
    });
    peer.finish();
}

#[test]
fn release_checks_protocol_even_when_hygiene_is_verified() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        peer::control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        pool.prewarm(async || -> Result<_, PrewarmFailure<Error>> {
            Ok(PoolEntry::new(
                TcpConnection::connect(options(peer.config()))
                    .await
                    .map_err(PrewarmFailure::Uncertain)?,
                (),
            ))
        })
        .await
        .unwrap();

        let mut lease = pool.try_acquire().unwrap().unwrap();
        {
            let (client, _) = lease.client_and_state();
            let _open = client.begin_transaction().await.unwrap();
        }
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Quarantined(ReuseState::NeedsTransactionDecision)
        );
        assert!(pool.try_acquire().unwrap().is_none());
        assert!(pool.reserve_replacement().is_none());

        let mut lease = pool.try_acquire_quarantined().unwrap().unwrap();
        let (client, _) = lease.client_and_state();
        client.recover_and_rollback().await.unwrap();
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Returned
        );
        let lease = pool.try_acquire().unwrap().unwrap();
        assert_eq!(
            lease.release(SessionHygiene::Quarantine),
            ReleaseOutcome::Quarantined(ReuseState::ProtocolIdle)
        );
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
    });
    peer.finish();
}

#[test]
fn partial_prewarm_retains_successes_and_charges_unconfirmed_attempt() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(2), PoolReuse::VerifyOnRelease).unwrap();
        let mut calls = 0;
        let failure = pool
            .prewarm(async || -> Result<_, PrewarmFailure<Error>> {
                calls += 1;
                if calls == 2 {
                    return Err(PrewarmFailure::Uncertain(Error::InvalidInput(
                        "fixture factory failed",
                    )));
                }
                Ok(PoolEntry::new(
                    TcpConnection::connect(options(peer.config()))
                        .await
                        .map_err(PrewarmFailure::Uncertain)?,
                    (),
                ))
            })
            .await;
        let Err(PrewarmError::Factory {
            installed: 1,
            failure: PrewarmFailure::Uncertain(Error::InvalidInput("fixture factory failed")),
            pending: Some(id),
        }) = failure
        else {
            panic!("failed factory must identify its uncertain slot")
        };
        assert_eq!(
            pool.occupancy(),
            Occupancy {
                ready: 1,
                maintenance: 1,
                ..Occupancy::default()
            }
        );
        assert!(pool.reserve_replacement().is_none());
        let pending = pool.pending_maintenance();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert!(!pending[0].resumable);
        assert!(pool.confirm_retired(id));
        assert!(!pool.confirm_retired(id));
        assert_eq!(pool.occupancy().vacant, 1);
        pool.try_acquire().unwrap().unwrap().close().await.unwrap();
    });
    peer.finish();
}

#[test]
fn classified_vacancy_can_be_retried() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let failure = pool
            .prewarm(async || {
                Err(PrewarmFailure::Vacant(Error::InvalidInput(
                    "factory did not connect",
                )))
            })
            .await;
        assert!(matches!(
            failure,
            Err(PrewarmError::Factory {
                installed: 0,
                failure: PrewarmFailure::Vacant(Error::InvalidInput("factory did not connect")),
                pending: None,
            })
        ));
        assert_eq!(pool.occupancy().vacant, 1);
        assert_eq!(pool.occupancy().maintenance, 0);
        assert_eq!(
            pool.prewarm(async || {
                let client = TcpConnection::connect(options(peer.config()))
                    .await
                    .map_err(PrewarmFailure::Uncertain)?;
                Ok(PoolEntry::new(client, ()))
            })
            .await
            .unwrap(),
            1
        );
        pool.try_acquire().unwrap().unwrap().close().await.unwrap();
    });
    peer.finish();
}

#[test]
fn cancelling_polled_prewarm_keeps_its_reservation() {
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let mut warming = Box::pin(pool.prewarm(async || {
            pending::<Result<PoolEntry<NativeTransport>, PrewarmFailure<Error>>>().await
        }));
        poll_fn(|cx| {
            assert!(warming.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(warming);
        assert_eq!(pool.occupancy().maintenance, 1);
        assert!(pool.try_acquire().unwrap().is_none());
        assert!(pool.reserve_replacement().is_none());
        let pending = pool.pending_maintenance();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].resumable);
        assert!(pool.confirm_retired(pending[0].id));
        assert_eq!(pool.occupancy().vacant, 1);
    });
}

#[test]
fn a_forgotten_factory_reservation_can_be_resolved_with_exclusive_access() {
    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let mut warming = Box::pin(pool.prewarm(async || {
            pending::<Result<PoolEntry<NativeTransport>, PrewarmFailure<Error>>>().await
        }));
        poll_fn(|cx| {
            assert!(warming.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        std::mem::forget(warming);
        let pending = pool.pending_maintenance();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].claimed);
        assert!(!pending[0].resumable);
        assert!(!pool.confirm_retired(pending[0].id));
        // 工厂在建连前挂起，槽可以直接归还。
        assert!(pool.confirm_abandoned_reservation(pending[0].id));
        assert_eq!(pool.occupancy().vacant, 1);
    });
}

#[test]
fn waiting_fifo_returns_ownership_and_refunds_charged_bytes() {
    let mut queue = BoundedFifo::try_new(QueueLimits {
        max_items: 2,
        max_charged_bytes: 8,
    })
    .unwrap();
    queue.try_push_back(Box::new(1), 5).unwrap();
    let request = Box::new(2);
    let pointer = std::ptr::from_ref(&*request);
    let rejected = queue.try_push_back(request, 4).unwrap_err();
    assert_eq!(rejected.reason, RejectReason::ByteLimit);
    assert_eq!(std::ptr::from_ref(&*rejected.item), pointer);
    queue.try_push_back(Box::new(3), 3).unwrap();
    let rejected = queue.try_push_back(Box::new(4), 0).unwrap_err();
    assert_eq!(rejected.reason, RejectReason::ItemLimit);
    let rejected = queue.try_push_back(Box::new(5), 9).unwrap_err();
    assert_eq!(rejected.reason, RejectReason::Oversize);
    assert_eq!((queue.len(), queue.charged_bytes()), (2, 8));

    assert_eq!(queue.front().map(|request| **request), Some(1));
    assert_eq!(*queue.pop_front().unwrap(), 1);
    assert_eq!(queue.charged_bytes(), 3);
    queue.try_push_back(Box::new(6), 4).unwrap();
    assert_eq!(*queue.pop_front().unwrap(), 3);
    assert_eq!(*queue.pop_front().unwrap(), 6);
    assert!(queue.is_empty());
    assert_eq!(queue.charged_bytes(), 0);

    let mut disabled = BoundedFifo::try_new(QueueLimits {
        max_items: 0,
        max_charged_bytes: 0,
    })
    .unwrap();
    let rejected = disabled.try_push_back((), 0).unwrap_err();
    assert_eq!(rejected.reason, RejectReason::ItemLimit);
    assert_eq!((disabled.len(), disabled.charged_bytes()), (0, 0));
}

#[cfg(unix)]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_prewarmed_pool_retains_statement_through_transaction_recovery() {
    use compio_postgres::{SendPolicy, UnixConnection, WireLimits};
    let config = live::unix_config(
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 128,
        },
        SendPolicy::BeforeBufferedRead,
    );

    peer::run(async {
        let mut pool = LocalPool::try_new(slots(1), PoolReuse::VerifyOnRelease).unwrap();
        let options = options(config);
        pool.prewarm(async || -> Result<_, PrewarmFailure<Error>> {
            let mut client = UnixConnection::connect(options.clone())
                .await
                .map_err(PrewarmFailure::Uncertain)?;
            let statement = client
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    ResultFormats::All(Format::Binary),
                )
                .await
                .map_err(PrewarmFailure::Uncertain)?;
            Ok(PoolEntry::new(client, statement))
        })
        .await
        .unwrap();

        let mut lease = pool.try_acquire().unwrap().unwrap();
        {
            let (client, _) = lease.client_and_state();
            assert!(client.server_info().version.starts_with("19"));
            let _abandoned = client.begin_transaction().await.unwrap();
        }
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Quarantined(ReuseState::NeedsTransactionDecision)
        );
        assert!(pool.reserve_replacement().is_none());
        let mut lease = pool.try_acquire_quarantined().unwrap().unwrap();
        let (client, statement) = lease.client_and_state();
        client.recover_and_rollback().await.unwrap();
        assert_eq!(
            client
                .query(statement, &[Parameter::int4(42)])
                .one::<i32>(OnError::RecoverExplicitly)
                .await
                .unwrap(),
            42
        );
        assert_eq!(
            lease.release(SessionHygiene::Verified),
            ReleaseOutcome::Returned
        );
        pool.try_acquire().unwrap().unwrap().close().await.unwrap();
        assert_eq!(pool.occupancy().vacant, 1);
    });
}

#[test]
fn fallible_pool_construction_reports_capacity_failure_before_connecting() {
    type Pool = LocalPool<compio_postgres::NativeTransport>;
    let pool = Pool::try_new(slots(3), PoolReuse::VerifyOnRelease).unwrap();
    assert_eq!(
        pool.occupancy(),
        Occupancy {
            vacant: 3,
            ..Occupancy::default()
        }
    );
    assert!(Pool::try_new(slots(usize::MAX), PoolReuse::VerifyOnRelease).is_err());
}

#[test]
fn quarantine_checkout_reports_missing_runtime_separately_from_empty_inventory() {
    let pool = LocalPool::<NativeTransport>::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease)
        .unwrap();
    assert!(matches!(
        pool.try_acquire_quarantined(),
        Err(Error::InvalidInput(_))
    ));
    pool.reserve_replacement().unwrap().confirm_vacant();
    let owner = compio::runtime::Runtime::new().unwrap();
    assert!(
        owner
            .enter(|| pool.try_acquire_quarantined())
            .unwrap()
            .is_none()
    );
}

#[test]
fn shared_session_reuses_only_an_idle_normal_lease_on_its_worker() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    let owner = compio::runtime::Runtime::new().unwrap();
    let other = compio::runtime::Runtime::new().unwrap();
    let pool = LocalPool::try_new(slots(1), PoolReuse::SharedSession).unwrap();
    owner.block_on(async {
        let client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        assert_eq!(
            pool.reserve_replacement()
                .unwrap()
                .install(PoolEntry::new(client, ())),
            InstallOutcome::Installed
        );
        drop(pool.try_acquire().unwrap().unwrap());
        assert_eq!(pool.occupancy().ready, 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lease = pool.try_acquire().unwrap().unwrap();
            panic!("application callback unwinds");
        }));
        assert!(result.is_err());
        assert_eq!(pool.occupancy().quarantined, 1);
        drop(pool.try_acquire_quarantined().unwrap().unwrap());
        assert_eq!(pool.occupancy().quarantined, 1);
        assert_eq!(
            pool.try_acquire_quarantined()
                .unwrap()
                .unwrap()
                .release(SessionHygiene::Verified),
            ReleaseOutcome::Returned
        );
    });
    let lease = owner.block_on(async { pool.try_acquire().unwrap().unwrap() });
    other.block_on(async { drop(lease) });
    assert_eq!(pool.occupancy().quarantined, 1);
    owner.block_on(async {
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap()
    });
    peer.finish();
}
