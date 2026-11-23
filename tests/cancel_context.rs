//! 验证 Compio 的 I/O 取消，以及 PostgreSQL 取消请求使用的独立连接。
#[path = "support/peer.rs"]
mod peer;

use compio::{
    BufResult,
    buf::IntoInner,
    driver::{
        ErrorExt, ToSharedFd,
        op::{Recv, RecvFlags},
    },
    io::AsyncRead,
    net::TcpStream,
    runtime::{CancelToken, FutureExt, Runtime, submit},
};
use compio_postgres::{
    AuthenticationPolicy, Error, ExecutionScheduling, ResultFormats, ReuseState, StatementLimits,
    TcpConfig, WireLimits, expert::TcpSession, types::Format,
};
use std::{
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream as StdTcpStream},
    thread,
    time::{Duration, Instant},
};

#[test]
fn an_attached_token_is_visible_in_the_current_poll_context() {
    Runtime::new().unwrap().block_on(async {
        let token = CancelToken::new();
        let observed = CancelToken::current().with_cancel(token.clone()).await;
        assert_eq!(observed, Some(token));
    });
}

async fn read(socket: &mut TcpStream, raw: bool) -> BufResult<usize, Vec<u8>> {
    if raw {
        let BufResult(result, op) = submit(Recv::new(
            socket.to_shared_fd(),
            vec![0; 1],
            RecvFlags::empty(),
        ))
        .await;
        BufResult(result, op.into_inner())
    } else {
        socket.read(vec![0; 1]).await
    }
}
fn cancellation(raw: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (send_after_cancel, cancelled) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener).unwrap();
        cancelled.recv_timeout(Duration::from_secs(5)).unwrap();
        socket.write_all(&[7]).unwrap();
    });
    peer::run(async {
        let mut socket = TcpStream::connect(address).await.unwrap();
        let token = CancelToken::new();
        {
            let pending = read(&mut socket, raw).with_cancel(token.clone());
            let mut pending = std::pin::pin!(pending);
            poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            token.cancel();
            let BufResult(result, _) = compio::time::timeout(Duration::from_secs(3), pending)
                .await
                .expect("native cancellation must settle");
            assert!(
                result.is_cancelled(),
                "the attached token did not cancel the read: {result:?}"
            );
        }
        send_after_cancel.send(()).unwrap();
        let BufResult(result, buffer) = read(&mut socket, raw).await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(buffer, [7]);
        socket.close().await.unwrap();
    });
    peer.join().unwrap();
}
#[test]
fn raw_native_submission_observes_the_attached_token() {
    cancellation(true);
}
#[test]
fn public_socket_receive_observes_the_attached_token() {
    cancellation(false);
}

fn accept(listener: &TcpListener) -> io::Result<StdTcpStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                socket.set_write_timeout(Some(Duration::from_secs(3)))?;
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

#[test]
fn postgres_cancel_uses_a_new_tcp_connection_and_retires_the_original() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> io::Result<()> {
        let mut original = accept(&listener)?;
        peer::handshake(&mut original)?;
        let mut cancellation = accept(&listener)?;
        read_cancel(&mut cancellation)?;
        confirm_cancel_length(&mut cancellation)?;
        peer::eof(&mut original)
    });

    peer::run(async {
        let connection = TcpSession::connect(TcpConfig::plaintext(
            address,
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            WireLimits {
                receive_capacity: 8192,
                max_frame_len: 8191,
                max_request_len: 8192,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        ))
        .await
        .unwrap();
        connection.request_cancel_and_discard().await.unwrap();
    });
    server.join().unwrap().unwrap();
}

fn read_cancel(socket: &mut StdTcpStream) -> io::Result<()> {
    // 协议长度、取消请求码、进程号 17 和八字节密钥。
    let expected = *b"\0\0\0\x14\x04\xd2\x16\x2e\0\0\0\x11\0\0\0\0\0\0\0\0";
    let mut packet = [0; 20];
    socket.read_exact(&mut packet)?;
    assert_eq!(packet, expected);
    Ok(())
}

fn confirm_cancel_length(socket: &mut StdTcpStream) -> io::Result<()> {
    // 先让客户端收到 EOF，再确认它未发送包长之外的字节。
    socket.shutdown(Shutdown::Write)?;
    assert_eq!(socket.read(&mut [0])?, 0);
    Ok(())
}

#[test]
fn an_independent_cancel_keeps_the_query_result_and_prevents_reuse() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> io::Result<()> {
        let mut original = accept(&listener)?;
        peer::handshake(&mut original)?;
        let statement = peer::prepare(&mut original, &[], &[23])?;
        peer::execution(&mut original, &statement)?;
        let mut cancellation = accept(&listener)?;
        read_cancel(&mut cancellation)?;
        confirm_cancel_length(&mut cancellation)?;
        original.write_all(&peer::sql_error("57014", b'I'))?;
        peer::eof(&mut original)
    });

    peer::run(async {
        let mut connection = connect_for_query(address).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        {
            let mut query = connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: peer::query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let handle = query.cancel_handle().unwrap();
            let (query_result, cancel_result) =
                futures_util::future::join(query.finish(), handle.request_cancel_and_invalidate())
                    .await;
            cancel_result.unwrap();
            assert!(matches!(query_result, Err(Error::Database(error)) if error.code() == "57014"));
        }
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        assert!(matches!(
            connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: peer::query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await,
            Err(Error::Broken)
        ));
        connection.close_local().await.unwrap();
    });
    server.join().unwrap().unwrap();
}

#[test]
fn cancellation_cannot_continue_on_another_runtime_after_it_yields() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || -> io::Result<()> {
        let mut original = accept(&listener)?;
        peer::handshake(&mut original)?;
        // 原连接保持打开，取消连接无论提交到哪一阶段都不会收到 EOF。
        peer::eof(&mut original)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut session = owner.block_on(connect_for_query(address));
    let mut query = owner
        .block_on(session.one_shot(
            "SELECT 1",
            &[],
            ResultFormats::All(Format::Binary),
            compio_postgres::QueryOptions {
                limits: peer::query_limits(),
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        ))
        .unwrap();
    let mut cancel = Box::pin(
        query
            .cancel_handle()
            .unwrap()
            .request_cancel_and_invalidate(),
    );
    owner.enter(|| {
        assert!(
            cancel
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        )
    });
    assert!(matches!(
        foreign.block_on(async {
            compio::time::timeout(Duration::from_secs(3), cancel)
                .await
                .expect("foreign runtime must reject the cancel waiter")
        }),
        Err(Error::InvalidInput(_))
    ));
    drop(query);
    owner.block_on(session.close_local()).unwrap();
    server.join().unwrap().unwrap();
}

#[test]
fn cancel_before_the_first_io_prevents_sending_the_original_query() {
    for (recover, route_fails) in [(false, false), (true, false), (false, true), (true, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || -> io::Result<()> {
            let mut original = accept(&listener)?;
            peer::handshake(&mut original)?;
            let mut cancellation = accept(&listener)?;
            read_cancel(&mut cancellation)?;
            if route_fails {
                cancellation.write_all(b"?")?;
            } else {
                confirm_cancel_length(&mut cancellation)?;
            }
            drop(cancellation);
            peer::eof(&mut original)
        });
        peer::run(async {
            let mut connection = connect_for_query(address).await;
            let mut query = connection
                .one_shot(
                    "SELECT 1",
                    &[],
                    ResultFormats::All(Format::Binary),
                    compio_postgres::QueryOptions {
                        limits: peer::query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let first = query.cancel_handle().unwrap();
            let duplicate = query.cancel_handle().unwrap();
            let outcome = first.request_cancel_and_invalidate().await;
            if route_fails {
                assert!(matches!(outcome, Err(Error::Protocol(_))));
            } else {
                outcome.unwrap();
            }
            assert!(matches!(
                duplicate.request_cancel_and_invalidate().await,
                Err(Error::InvalidInput(_))
            ));
            let result = if recover {
                drop(query);
                connection.recover_to_ready().await
            } else {
                query.finish().await.map(|_| ())
            };
            assert!(
                matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
            );
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        server.join().unwrap().unwrap();
    }
}

#[test]
fn a_completed_query_expires_its_unused_cancel_handle() {
    let peer = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        let statement = peer::prepare(socket, &[], &[23])?;
        for number in [1, 2] {
            peer::execution(socket, &statement)?;
            socket.write_all(&peer::result(number, b'I'))?;
        }
        peer::eof(socket)
    });
    peer::run(async {
        let mut connection = TcpSession::connect(peer.config()).await.unwrap();
        configure(&mut connection);
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let handle = {
            let mut query = connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: peer::query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let handle = query.cancel_handle().unwrap();
            query.finish().await.unwrap();
            handle
        };
        assert!(matches!(
            handle.request_cancel_and_invalidate().await,
            Err(Error::InvalidInput(_))
        ));
        connection
            .query(
                &statement,
                &[],
                compio_postgres::QueryOptions {
                    limits: peer::query_limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

async fn connect_for_query(address: std::net::SocketAddr) -> TcpSession {
    let mut connection = TcpSession::connect(TcpConfig::plaintext(
        address,
        "test",
        "test",
        AuthenticationPolicy::AllowAuthenticationOk,
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 128,
        },
        peer::TCP_OPTIONS,
    ))
    .await
    .unwrap();
    configure(&mut connection);
    connection
}

fn configure(connection: &mut TcpSession) {
    connection
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
}
