//! 文件系统 Unix 套接字沿用相同的协议和连接所有权契约。
#![cfg(unix)]

#[path = "support/live.rs"]
mod live;

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{
    future::Future,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use compio_postgres::{
    AuthenticationPolicy, Error, UnixConfig, WireLimits, WireTransport,
    expert::{Session, UnixSession as UnixConnection, protocol},
};

const DEADLINE: Duration = Duration::from_secs(8);
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 8192,
        max_messages_per_request: 128,
    }
}

fn config(path: &Path) -> UnixConfig {
    UnixConfig::plaintext(
        path,
        "test",
        "test",
        AuthenticationPolicy::AllowAuthenticationOk,
        limits(),
        compio_postgres::SendPolicy::BeforeBufferedRead,
    )
    .unwrap()
}

fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(DEADLINE, future)
            .await
            .expect("Unix socket test deadline")
    })
}

struct Peer {
    path: PathBuf,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Peer {
    fn start(
        script: impl FnOnce(UnixListener, UnixStream, &Path) -> io::Result<()> + Send + 'static,
    ) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cpg-uds-{}-{}.sock",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let worker_path = path.clone();
        let worker = thread::spawn(move || {
            let socket = accept(&listener)?;
            script(listener, socket, &worker_path)
        });
        Self {
            path,
            worker: Some(worker),
        }
    }

    fn finish(mut self) {
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn accept(listener: &UnixListener) -> io::Result<UnixStream> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(DEADLINE))?;
                socket.set_write_timeout(Some(DEADLINE))?;
                return Ok(socket);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn body(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = usize::try_from(i32::from_be_bytes(length))
        .map_err(|_| io::Error::other("negative fixture length"))?;
    if !(4..=8192).contains(&length) {
        return Err(io::Error::other("invalid fixture length"));
    }
    let mut bytes = vec![0; length - 4];
    socket.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn expect(socket: &mut UnixStream, expected: u8) -> io::Result<Vec<u8>> {
    let mut tag = [0];
    socket.read_exact(&mut tag)?;
    if tag != [expected] {
        return Err(io::Error::other("unexpected frontend fixture tag"));
    }
    body(socket)
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn handshake(socket: &mut UnixStream, key: &[u8]) -> io::Result<()> {
    assert_eq!(
        &body(socket)?[..4],
        &protocol::PROTOCOL_VERSION.to_be_bytes()
    );
    let mut response = frame(b'R', &0_i32.to_be_bytes());
    response.extend(frame(b'S', b"server_version\x0019.0\0"));
    response.extend(frame(b'S', b"client_encoding\0UTF8\0"));
    let mut backend_key = Vec::from(17_i32.to_be_bytes());
    backend_key.extend_from_slice(key);
    response.extend(frame(b'K', &backend_key));
    response.extend(frame(b'Z', b"I"));
    socket.write_all(&response)
}

fn roundtrip_script(_: UnixListener, mut socket: UnixStream, _: &Path) -> io::Result<()> {
    handshake(&mut socket, &[7; 8])?;
    expect(&mut socket, b'P')?;
    expect(&mut socket, b'D')?;
    assert!(expect(&mut socket, b'S')?.is_empty());
    let mut response = frame(b'1', &[]);
    let mut parameters = Vec::from(1_u16.to_be_bytes());
    parameters.extend_from_slice(&23_u32.to_be_bytes());
    response.extend(frame(b't', &parameters));
    let mut description = Vec::from(1_u16.to_be_bytes());
    description.extend_from_slice(b"value\0");
    description.extend_from_slice(&0_u32.to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    description.extend_from_slice(&23_u32.to_be_bytes());
    description.extend_from_slice(&4_i16.to_be_bytes());
    description.extend_from_slice(&(-1_i32).to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    response.extend(frame(b'T', &description));
    response.extend(frame(b'Z', b"I"));
    socket.write_all(&response)?;
    expect(&mut socket, b'B')?;
    expect(&mut socket, b'E')?;
    assert!(expect(&mut socket, b'S')?.is_empty());
    let mut response = frame(b'2', &[]);
    let mut row = Vec::from(1_u16.to_be_bytes());
    row.extend_from_slice(&4_i32.to_be_bytes());
    row.extend_from_slice(&73_i32.to_be_bytes());
    response.extend(frame(b'D', &row));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(frame(b'Z', b"I"));
    socket.write_all(&response)?;
    let mut byte = [0];
    assert_eq!(
        socket.read(&mut byte)?,
        0,
        "close must retire the original FD"
    );
    Ok(())
}

async fn exercise<T: WireTransport>(mut connection: Session<T>) {
    scalar::configure(&mut connection);
    let statement = connection
        .prepare_scalar("SELECT $1::int4 AS value")
        .await
        .unwrap();
    assert_eq!(
        connection.query_scalar(&statement, Some(73)).await.unwrap(),
        Some(73)
    );
    connection.close_local().await.unwrap();
}

#[test]
fn completion_unix_socket_preserves_prepare_query_and_retirement() {
    let peer = Peer::start(roundtrip_script);
    run(async { exercise(UnixConnection::connect(config(&peer.path)).await.unwrap()).await });
    peer.finish();
}

#[cfg(target_os = "linux")]
#[test]
fn readiness_unix_socket_preserves_prepare_query_and_retirement() {
    let peer = Peer::start(roundtrip_script);
    run(async {
        exercise(
            compio_postgres::expert::linux::UnixReadinessSession::connect(config(&peer.path))
                .await
                .unwrap(),
        )
        .await
    });
    peer.finish();
}

fn cancel_script(key: Vec<u8>) -> impl FnOnce(UnixListener, UnixStream, &Path) -> io::Result<()> {
    move |listener, mut original, _| {
        handshake(&mut original, &key)?;
        let mut cancellation = accept(&listener)?;
        let mut expected = Vec::new();
        expected.extend_from_slice(&i32::try_from(12 + key.len()).unwrap().to_be_bytes());
        expected.extend_from_slice(&80_877_102_i32.to_be_bytes());
        expected.extend_from_slice(&17_i32.to_be_bytes());
        expected.extend_from_slice(&key);
        let mut received = vec![0; expected.len()];
        cancellation.read_exact(&mut received)?;
        assert_eq!(received, expected);
        cancellation.shutdown(Shutdown::Write)?;
        let mut byte = [0];
        assert_eq!(cancellation.read(&mut byte)?, 0);
        assert_eq!(original.read(&mut byte)?, 0);
        Ok(())
    }
}

#[test]
fn completion_cancel_reuses_the_original_path_and_preserves_variable_keys() {
    for length in [
        protocol::MIN_CANCEL_KEY_LEN,
        17,
        protocol::MAX_CANCEL_KEY_LEN,
    ] {
        let peer = Peer::start(cancel_script(vec![91; length]));
        run(async {
            let connection = UnixConnection::connect(config(&peer.path)).await.unwrap();
            assert_eq!(connection.server_info().cancel_key_length, length);
            connection.request_cancel_and_discard().await.unwrap();
        });
        peer.finish();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn readiness_cancel_reuses_the_original_path_and_preserves_variable_keys() {
    for length in [
        protocol::MIN_CANCEL_KEY_LEN,
        17,
        protocol::MAX_CANCEL_KEY_LEN,
    ] {
        let peer = Peer::start(cancel_script(vec![31; length]));
        run(async {
            let connection =
                compio_postgres::expert::linux::UnixReadinessSession::connect(config(&peer.path))
                    .await
                    .unwrap();
            assert_eq!(connection.server_info().cancel_key_length, length);
            connection.request_cancel_and_discard().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn a_failed_unix_cancel_route_still_retires_the_original_connection() {
    let peer = Peer::start(|_, mut socket, path| {
        std::fs::remove_file(path)?;
        handshake(&mut socket, &[3; 8])?;
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte)?, 0);
        Ok(())
    });
    run(async {
        let connection = UnixConnection::connect(config(&peer.path)).await.unwrap();
        assert!(matches!(
            connection.request_cancel_and_discard().await,
            Err(Error::CancelRequest(error)) if matches!(*error, Error::Io(_))
        ));
    });
    peer.finish();
}

#[test]
fn filesystem_paths_are_explicit_and_relative_or_abstract_names_are_rejected() {
    for path in [
        PathBuf::from("relative.sock"),
        PathBuf::from("\0abstract"),
        PathBuf::from("/tmp/a\0b"),
    ] {
        assert!(matches!(
            UnixConfig::plaintext(
                path,
                "test",
                "test",
                AuthenticationPolicy::AllowAuthenticationOk,
                limits(),
                compio_postgres::SendPolicy::BeforeBufferedRead,
            ),
            Err(Error::InvalidInput(_))
        ));
    }
}

#[test]
fn scram_plus_is_rejected_before_opening_a_plaintext_unix_socket() {
    run(async {
        let configuration = UnixConfig::plaintext(
            "/nonexistent/compio-postgres.sock",
            "test",
            "test",
            AuthenticationPolicy::ScramSha256Plus {
                password: String::new(),
                max_iterations: 1,
            },
            limits(),
            compio_postgres::SendPolicy::BeforeBufferedRead,
        )
        .unwrap();
        assert!(matches!(
            UnixConnection::connect(configuration).await,
            Err(Error::Unsupported(_))
        ));
    });
}

fn live_config() -> UnixConfig {
    live::unix_config(limits(), compio_postgres::SendPolicy::BeforeBufferedRead)
}

async fn live_exercise<T: WireTransport>(mut connection: Session<T>) {
    scalar::configure(&mut connection);
    let statement = connection
        .prepare_scalar("SELECT $1::int4 AS value")
        .await
        .unwrap();
    for value in [None, Some(73), Some(i32::MIN), Some(i32::MAX)] {
        assert_eq!(
            connection.query_scalar(&statement, value).await.unwrap(),
            value
        );
    }
    connection.close_prepared(&statement).await.unwrap();
    let key_length = connection.server_info().cancel_key_length;
    assert!((protocol::MIN_CANCEL_KEY_LEN..=protocol::MAX_CANCEL_KEY_LEN).contains(&key_length));
    connection.request_cancel_and_discard().await.unwrap();
}

#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_completion_unix_socket_query_null_boundaries_close_and_cancel() {
    run(async { live_exercise(UnixConnection::connect(live_config()).await.unwrap()).await });
}

#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_deferred_commit_error_retires_the_lease_and_allows_reuse() {
    use compio_postgres::{
        ExecutionScheduling, QueryLimits, ResultFormats, ReuseState, TransactionStatus,
        types::Format,
    };
    use std::{future::poll_fn, task::Poll};

    run(async {
        let mut connection = UnixConnection::connect(live_config()).await.unwrap();
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 1024,
        };
        let scheduling = ExecutionScheduling::Uninterrupted;
        connection
            .query_simple_single(
                "CREATE TEMP TABLE cpg_failed_commit (n int UNIQUE DEFERRABLE INITIALLY DEFERRED)",
                compio_postgres::QueryOptions { limits, scheduling },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();

        // io_uring 在取得完成事件前提交收发，首次轮询后即可确定操作已经交给驱动。
        let can_abandon =
            compio::runtime::Runtime::with_current(|runtime| runtime.driver_type().is_iouring());
        for abandon in [false, true] {
            if abandon && !can_abandon {
                continue;
            }
            let mut transaction = connection.begin_transaction().await.unwrap();
            transaction
                .query_simple_single(
                    "INSERT INTO pg_temp.cpg_failed_commit VALUES (1), (1)",
                    compio_postgres::QueryOptions { limits, scheduling },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();

            if abandon {
                let mut commit = Box::pin(transaction.commit());
                poll_fn(|cx| {
                    assert!(commit.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(commit);
                assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                connection.recover_to_ready().await.unwrap();
            } else {
                assert!(matches!(
                    transaction.commit().await,
                    Err(Error::Database(error)) if error.code() == "23505"
                ));
            }
            assert_eq!(connection.transaction_status(), TransactionStatus::Idle);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            assert_eq!(connection.take_transaction_end(), None);

            let mut query = connection
                .one_shot(
                    "SELECT count(*)::int4 FROM pg_temp.cpg_failed_commit",
                    &[],
                    ResultFormats::All(Format::Binary),
                    compio_postgres::QueryOptions { limits, scheduling },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            {
                let row = query.next_row().await.unwrap().unwrap();
                assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 0);
            }
            query.finish().await.unwrap();
        }
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_portal_listener_and_session_reset() {
    use compio_postgres::{
        ExecutionScheduling, PortalFetchCompletion, PortalFetchLimits, QueryLimits, ResultFormats,
        types::Format,
    };
    use std::num::NonZeroU32;

    run(async {
        let mut connection = UnixConnection::connect(live_config()).await.unwrap();
        scalar::configure(&mut connection);
        let statement = connection
            .prepare(
                "SELECT generate_series(1, 5)::int4",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        let limits = PortalFetchLimits {
            max_rows: NonZeroU32::new(2).unwrap(),
            max_result_bytes: 64,
            scheduling: ExecutionScheduling::Uninterrupted,
        };
        let mut rows = Vec::new();
        for expected in [true, true, false] {
            let fetch = portal
                .fetch_provisional(limits, |row| {
                    rows.push(row.decoder().decode_next::<i32>()?);
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                matches!(fetch, PortalFetchCompletion::Suspended { .. }),
                expected
            );
        }
        assert_eq!(rows, [1, 2, 3, 4, 5]);
        portal.close().await.unwrap();
        transaction.commit().await.unwrap();

        let mut listener = UnixConnection::connect(live_config())
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Uninterrupted)
            .unwrap();
        let process_id = connection.server_info().process_id;
        let channel = format!("compio_fixture_{process_id}");
        listener.listen(&channel, |_| {}).await.unwrap();
        let query_limits = QueryLimits {
            max_rows: 0,
            max_result_bytes: 0,
            max_metadata_bytes: 1024,
        };
        connection
            .query_simple_single(
                &format!("NOTIFY {channel}, 'fixture'"),
                compio_postgres::QueryOptions {
                    limits: query_limits,
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        let payload = listener
            .next_notification(|notice| {
                assert_eq!(notice.channel, channel);
                assert_eq!(notice.process_id, process_id);
                notice.payload.to_owned()
            })
            .await
            .unwrap();
        assert_eq!(payload, "fixture");
        listener.unlisten(&channel, |_| {}).await.unwrap();
        listener.close_local().await.unwrap();

        connection.reset_session().await.unwrap();
        assert!(matches!(
            connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits,
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        connection.terminate().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_readiness_unix_socket_query_null_boundaries_close_and_cancel() {
    run(async {
        live_exercise(
            compio_postgres::expert::linux::UnixReadinessSession::connect(live_config())
                .await
                .unwrap(),
        )
        .await
    });
}
