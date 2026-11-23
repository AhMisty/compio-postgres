#![cfg(feature = "service")]

#[path = "support/peer.rs"]
mod peer;

#[cfg(target_os = "linux")]
use compio::runtime::Runtime;
use compio::{
    driver::ErrorExt,
    runtime::{CancelToken, FutureExt},
};
use compio_postgres::{
    Client, ClientOptions, Error, NativeTransport, OnError, PreparedStatementStorage,
    ResultFormats, Statement, TcpConnection,
    service::{
        DispatchLimits, DispatchOperation, LocalDispatcher, LocalPool, PoolEntry, PoolReuse,
        PrewarmFailure, QueueLimits, SessionHygiene,
    },
    types::{Format, Oid, Parameter},
};
use std::{
    future::{Future, poll_fn},
    io::{ErrorKind, Write},
    num::NonZeroUsize,
    pin::pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Waker},
    time::Duration,
};

struct Query {
    stable_driver_context: bool,
}

impl DispatchOperation<NativeTransport, Statement> for Query {
    type Request = i32;
    type Response = Result<i32, Error>;

    async fn execute_one(
        &self,
        client: &mut Client<NativeTransport>,
        statement: &mut Statement,
        value: i32,
    ) -> (Self::Response, SessionHygiene) {
        let args = [Parameter::int4(value)];
        let mut query = pin!(client.query(statement, &args).one(OnError::DrainToReady));
        let mut initial: Option<Waker> = None;
        let mut repolled = false;
        let result = poll_fn(|cx| {
            if self.stable_driver_context {
                if let Some(waker) = &initial {
                    assert!(
                        waker.will_wake(cx.waker()),
                        "driver replaced its task context"
                    );
                    repolled = true;
                } else {
                    initial = Some(cx.waker().clone());
                }
            }
            query.as_mut().poll(cx)
        })
        .await;
        let hygiene = if result.is_ok() {
            assert!(
                !self.stable_driver_context || repolled,
                "the peer withholds each success until after submission"
            );
            SessionHygiene::Verified
        } else {
            SessionHygiene::Quarantine
        };
        (result, hygiene)
    }
}

#[derive(Clone, Copy)]
enum Driver {
    Scan,
    Wake,
}

async fn make_dispatcher(
    peer: &peer::Peer,
    stable_driver_context: bool,
) -> Rc<LocalDispatcher<NativeTransport, Statement, Query>> {
    let mut pool = LocalPool::try_new(NonZeroUsize::MIN, PoolReuse::VerifyOnRelease).unwrap();
    pool.prewarm(async || {
        let mut client = TcpConnection::connect(ClientOptions::short_queries(peer.config()))
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
        Ok::<_, PrewarmFailure<Error>>(PoolEntry::new(client, statement))
    })
    .await
    .unwrap();
    Rc::new(
        LocalDispatcher::try_new(
            pool,
            Query {
                stable_driver_context,
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
        .unwrap(),
    )
}

async fn exercise(driver: Driver, personality: Option<u16>, revoked: bool) {
    let observed = Arc::new(AtomicUsize::new(0));
    let executions = Arc::clone(&observed);
    let (reply, permission) = mpsc::channel();
    let peer = peer::Peer::start(move |socket| {
        peer::handshake(socket)?;
        let statement = peer::prepare(socket, &[23], &[23])?;
        if revoked {
            return peer::eof(socket);
        }
        for value in [1, 2] {
            peer::execution(socket, &statement)?;
            executions.fetch_add(1, Ordering::Release);
            match permission.recv_timeout(Duration::from_secs(2)) {
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(()) => socket.write_all(&peer::result(value, b'I'))?,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "没有收到用例的回包许可",
                    ));
                }
            }
        }
        Ok(())
    });
    let dispatcher = make_dispatcher(&peer, true).await;
    #[cfg(target_os = "linux")]
    use compio_postgres::expert::linux::DispatcherExt;
    let driver = match (driver, personality) {
        (Driver::Scan, None) => Rc::clone(&dispatcher).spawn_scanned(),
        (Driver::Wake, None) => Rc::clone(&dispatcher).spawn_ready(),
        #[cfg(target_os = "linux")]
        (Driver::Scan, Some(id)) => Rc::clone(&dispatcher).spawn_scanned_with_personality(id),
        #[cfg(target_os = "linux")]
        (Driver::Wake, Some(id)) => Rc::clone(&dispatcher).spawn_ready_with_personality(id),
        #[cfg(not(target_os = "linux"))]
        (_, Some(_)) => panic!("unexpected io_uring personality"),
    }
    .unwrap();
    if revoked {
        let result = dispatcher.submit_queued(1, 1).await.unwrap();
        assert!(
            matches!(result, Err(Error::Io(ref e)) if e.kind() == ErrorKind::InvalidInput),
            "{result:?}"
        );
    } else {
        let wait_for_execution = async |count| {
            while observed.load(Ordering::Acquire) < count {
                compio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let submitter = CancelToken::new();
        let mut first = pin!(
            dispatcher
                .submit_queued(1, 1)
                .with_cancel(submitter.clone())
        );
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        wait_for_execution(1).await;
        submitter.cancel();
        assert!(
            compio::time::timeout(Duration::from_millis(10), first.as_mut())
                .await
                .is_err()
        );
        reply.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);

        let mut second = pin!(dispatcher.submit_queued(2, 1));
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        wait_for_execution(2).await;
        reply.send(()).unwrap();
        assert_eq!(second.await.unwrap().unwrap(), 2);
    }
    drop(reply);
    dispatcher.close_intake();
    driver.await.unwrap().unwrap();
    drop(dispatcher);
    peer.finish();
}

fn exercise_contexts(driver: Driver) {
    peer::run(async {
        exercise(driver, None, false).await;
        #[cfg(target_os = "linux")]
        if Runtime::current().driver_type().is_iouring() {
            let runtime = Runtime::current();
            let id = runtime.register_personality().unwrap();
            assert_ne!(id, 0);
            exercise(driver, Some(id), false).await;
            runtime.unregister_personality(id).unwrap();
            exercise(driver, Some(id), true).await;
        }
    });
}

#[test]
fn scanned_driver_keeps_its_context_and_isolates_submitter_cancellation() {
    exercise_contexts(Driver::Scan);
}

#[test]
fn ready_driver_keeps_its_context_and_isolates_submitter_cancellation() {
    exercise_contexts(Driver::Wake);
}

#[test]
fn inline_native_io_uses_submitter_cancellation_context() {
    let observed = Arc::new(AtomicUsize::new(0));
    let executed = Arc::clone(&observed);
    let peer = peer::Peer::start(move |socket| {
        peer::handshake(socket)?;
        let statement = peer::prepare(socket, &[23], &[23])?;
        peer::execution(socket, &statement)?;
        executed.store(1, Ordering::Release);
        peer::eof(socket)
    });
    peer::run(async {
        let dispatcher = make_dispatcher(&peer, false).await;
        let token = CancelToken::new();
        let result = {
            let mut request = pin!(dispatcher.try_submit_inline(1).with_cancel(token.clone()));
            assert!(
                request
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            while observed.load(Ordering::Acquire) == 0 {
                compio::time::sleep(Duration::from_millis(1)).await;
            }
            token.cancel();
            request.await.unwrap()
        };
        assert!(
            matches!(result, Err(Error::Io(ref error)) if error.is_cancelled()),
            "{result:?}"
        );
        assert_eq!(dispatcher.pool_occupancy().quarantined, 1);
    });
    peer.finish();
}

#[cfg(target_os = "linux")]
#[test]
fn inline_native_io_uses_submitter_personality() {
    peer::run(async {
        let runtime = Runtime::current();
        if !runtime.driver_type().is_iouring() {
            return;
        }
        let peer = peer::Peer::start(|socket| {
            use std::io::{self, Read};

            peer::handshake(socket)?;
            let statement = peer::prepare(socket, &[23], &[23])?;
            peer::execution(socket, &statement)?;
            socket.write_all(&peer::result(1, b'I'))?;
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(0) => Ok(()),
                Ok(_) => Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("revoked personality sent frontend byte {:#04x}", byte[0]),
                )),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            }
        });
        let dispatcher = make_dispatcher(&peer, false).await;
        let personality = runtime.register_personality().unwrap();
        assert_eq!(
            dispatcher
                .try_submit_inline(1)
                .with_personality(personality)
                .await
                .unwrap()
                .unwrap(),
            1
        );
        runtime.unregister_personality(personality).unwrap();
        let result = dispatcher
            .try_submit_inline(2)
            .with_personality(personality)
            .await
            .unwrap();
        assert!(
            matches!(result, Err(Error::Io(ref error)) if error.kind() == ErrorKind::InvalidInput),
            "{result:?}"
        );
        let pool = Rc::into_inner(dispatcher).unwrap().into_pool();
        assert_eq!(pool.occupancy().quarantined, 1);
        // 等到 io_uring 收回可能仍持有套接字的操作，再阻塞等待对端线程。
        pool.try_acquire_quarantined()
            .unwrap()
            .unwrap()
            .close()
            .await
            .unwrap();
        assert_eq!(pool.occupancy().vacant, 1);
        peer.finish();
    });
}
