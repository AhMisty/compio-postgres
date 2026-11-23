//! 通过真实的 Compio TCP 连接验证会话状态。
//!
//! 每个测试对端只接受一条本地连接，执行预定的协议交互后退出。
//! 它直接返回 AuthenticationOk；SCRAM 验证在真实数据库测试中完成。

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{IO_DEADLINE as IO_TIMEOUT, run};
use peer::{Peer, frame};

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    task::Poll,
    time::Instant,
};

use compio_postgres::{
    AuthenticationPolicy, Error, TcpConfig, WireLimits, expert::TcpSession as TcpConnection,
};
use futures_util::FutureExt;

const SQL: &str = "SELECT $1::int4 AS result";

#[test]
fn connection_configurations_can_be_shared_between_workers() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<TcpConfig>();
    #[cfg(unix)]
    assert_send_sync::<compio_postgres::UnixConfig>();
    #[cfg(feature = "tls")]
    {
        assert_send_sync::<compio_postgres::SecureConfig>();
        assert_send_sync::<compio_postgres::TlsConfig>();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_length(stream: &mut TcpStream) -> io::Result<usize> {
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes)?;
    let length = usize::try_from(i32::from_be_bytes(bytes))
        .map_err(|_| invalid("negative client message length"))?;
    if !(4..=8192).contains(&length) {
        return Err(invalid("client message exceeds the test bounds"));
    }
    Ok(length)
}

fn read_startup(stream: &mut TcpStream) -> io::Result<()> {
    let length = read_length(stream)?;
    if length < 8 {
        return Err(invalid("startup lacks a protocol version"));
    }
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body)?;
    if body.get(..4) != Some(196_610_i32.to_be_bytes().as_slice()) {
        return Err(invalid("client did not request protocol 3.2"));
    }
    Ok(())
}

fn expect_request(stream: &mut TcpStream, tags: &[u8]) -> io::Result<()> {
    for expected in tags {
        let mut tag = [0; 1];
        stream.read_exact(&mut tag)?;
        let length = read_length(stream)?;
        let mut body = vec![0; length - 4];
        stream.read_exact(&mut body)?;
        if tag[0] != *expected {
            return Err(invalid("unexpected client message sequence"));
        }
        if *expected == b'S' && !body.is_empty() {
            return Err(invalid("Sync must have an empty body"));
        }
    }
    Ok(())
}

fn parameter(name: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::from(name.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    frame(b'S', &body)
}

fn authentication_ok() -> Vec<u8> {
    frame(b'R', &0_i32.to_be_bytes())
}

fn key_data() -> Vec<u8> {
    let mut body = Vec::from(707_i32.to_be_bytes());
    body.extend_from_slice(&[1, 0, 2, 0, 3, 0, 4, 5]);
    frame(b'K', &body)
}

fn ready() -> Vec<u8> {
    frame(b'Z', b"I")
}

fn startup_response(version: &str, encoding: &str, include_key: bool) -> Vec<u8> {
    let mut bytes = authentication_ok();
    bytes.extend(parameter("server_version", version));
    bytes.extend(parameter("client_encoding", encoding));
    if include_key {
        bytes.extend(key_data());
    }
    bytes.extend(ready());
    bytes
}

fn handshake(stream: &mut TcpStream) -> io::Result<()> {
    read_startup(stream)?;
    stream.write_all(&startup_response("19.0", "UTF8", true))
}

fn prepared_response(type_oid: u32, type_size: i16) -> Vec<u8> {
    let mut bytes = frame(b'1', &[]);
    let mut parameters = Vec::from(1_u16.to_be_bytes());
    parameters.extend_from_slice(&23_u32.to_be_bytes());
    bytes.extend(frame(b't', &parameters));
    let mut column = Vec::from(1_u16.to_be_bytes());
    column.extend_from_slice(b"result\0");
    column.extend_from_slice(&0_u32.to_be_bytes());
    column.extend_from_slice(&0_i16.to_be_bytes());
    column.extend_from_slice(&type_oid.to_be_bytes());
    column.extend_from_slice(&type_size.to_be_bytes());
    column.extend_from_slice(&(-1_i32).to_be_bytes());
    column.extend_from_slice(&0_i16.to_be_bytes());
    bytes.extend(frame(b'T', &column));
    bytes.extend(ready());
    bytes
}

fn prepare(stream: &mut TcpStream) -> io::Result<()> {
    expect_request(stream, b"PDS")?;
    stream.write_all(&prepared_response(23, 4))
}

fn row(value: Option<i32>) -> Vec<u8> {
    let mut body = Vec::from(1_u16.to_be_bytes());
    match value {
        Some(value) => {
            body.extend_from_slice(&4_i32.to_be_bytes());
            body.extend_from_slice(&value.to_be_bytes());
        }
        None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
    }
    frame(b'D', &body)
}

fn query_success(value: Option<i32>) -> Vec<u8> {
    let mut bytes = frame(b'2', &[]);
    bytes.extend(row(value));
    bytes.extend(frame(b'C', b"SELECT 1\0"));
    bytes.extend(ready());
    bytes
}

fn database_error(code: &str) -> Vec<u8> {
    database_error_severity(code, "ERROR")
}

fn database_error_severity(code: &str, severity: &str) -> Vec<u8> {
    let body = format!("S{severity}\0V{severity}\0C{code}\0Mscripted database error\0\0");
    frame(b'E', body.as_bytes())
}

fn wait_for_discard(stream: &mut TcpStream) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut buffer = [0; 1024];
    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the client did not close the connection",
    ))
}

#[test]
fn sql_message_limit_applies_to_listen_but_not_startup_or_idle_notifications() {
    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        expect_request(stream, b"Q")?;
        let notice = frame(b'N', b"SNOTICE\0C00000\0Mfixture notice\0\0");
        let mut response = frame(b'C', b"LISTEN\0");
        response.extend(ready());
        response.extend_from_slice(&notice);
        response.extend_from_slice(&notice);
        response.extend(frame(b'A', b"\0\0\0\x07fixture\0ready\0"));
        stream.write_all(&response)?;

        // UNLISTEN 的三条响应消息也受同一个 SQL 请求限额约束。
        expect_request(stream, b"Q")?;
        let mut response = notice;
        response.extend(frame(b'C', b"UNLISTEN\0"));
        response.extend(ready());
        stream.write_all(&response)?;
        wait_for_discard(stream)
    });
    run(async {
        let config = TcpConfig::plaintext(
            peer.endpoint,
            "界".repeat(21),
            "db",
            AuthenticationPolicy::AllowAuthenticationOk,
            WireLimits {
                receive_capacity: 8192,
                max_frame_len: 8191,
                max_request_len: 8192,
                max_messages_per_request: 2,
            },
            peer::TCP_OPTIONS,
        );
        let mut listener = TcpConnection::connect(config)
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Uninterrupted)
            .unwrap();
        listener.listen("fixture", |_| {}).await.unwrap();
        assert_eq!(
            listener
                .next_notification(|notification| notification.payload.to_owned())
                .await
                .unwrap(),
            "ready"
        );
        assert!(matches!(
            listener.unlisten("fixture", |_| {}).await,
            Err(Error::Limit(
                "subscription command exceeded its control-message limit"
            ))
        ));
        listener.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn startup_rejects_oversize_names_and_wire_packets_before_opening_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let config = |user, database| {
        TcpConfig::plaintext(
            endpoint,
            user,
            database,
            AuthenticationPolicy::AllowAuthenticationOk,
            WireLimits {
                receive_capacity: 8192,
                max_frame_len: 8191,
                max_request_len: 16 * 1024,
                max_messages_per_request: 2,
            },
            peer::TCP_OPTIONS,
        )
    };
    run(async {
        for (user, database) in [
            ("界".repeat(22), "db".to_owned()),
            ("alice".to_owned(), "x".repeat(64)),
        ] {
            assert!(matches!(
                TcpConnection::connect(config(user, database)).await,
                Err(Error::InvalidInput(
                    "startup user and database names must contain at most 63 UTF-8 bytes"
                ))
            ));
        }
        let oversized_packet =
            config("alice".to_owned(), "db".to_owned()).application_name("x".repeat(10_004));
        assert!(matches!(
            TcpConnection::connect(oversized_packet).await,
            Err(Error::Protocol(
                compio_postgres::ProtocolError::FrameTooLarge { limit: 10_004, .. }
            ))
        ));
        let reserved_parameter =
            config("alice".into(), "db".into()).startup_parameter("client_encoding", "LATIN1");
        assert!(matches!(
            TcpConnection::connect(reserved_parameter).await,
            Err(Error::Protocol(
                compio_postgres::ProtocolError::InvalidMessage(
                    "startup parameter name is reserved"
                )
            ))
        ));
    });
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn connection_sends_session_defaults_in_the_startup_packet() {
    let peer = Peer::short_queries(|stream| {
        let length = read_length(stream)?;
        let mut body = vec![0; length - 4];
        stream.read_exact(&mut body)?;
        if !body.ends_with(b"search_path\0public, safe\0statement_timeout\x007s\0\0") {
            return Err(invalid("startup session defaults were not sent"));
        }
        stream.write_all(&startup_response("19", "UTF8", true))?;
        wait_for_discard(stream)
    });
    run(async {
        let connection = TcpConnection::connect(
            peer.config()
                .startup_parameter("search_path", "public, safe")
                .startup_parameter("statement_timeout", "7s"),
        )
        .await
        .unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn opt_in_notice_handler_borrows_fields_and_discards_reuse_on_panic() {
    let peer = Peer::short_queries(|stream| {
        read_startup(stream)?;
        let mut startup = frame(b'N', b"SNOTICE\0C00000\0Mstartup\0Dstartup detail\0\0");
        startup.extend(startup_response("19", "UTF8", true));
        stream.write_all(&startup)?;
        for message in [
            &b"SNOTICE\0C00000\0Mquery\0Dquery detail\0\0"[..],
            &b"SNOTICE\0C00000\0Mpanicking\0\0"[..],
        ] {
            expect_request(stream, b"Q")?;
            let mut response = frame(b'N', message);
            response.extend(frame(b'C', b"UPDATE 1\0"));
            response.extend(ready());
            stream.write_all(&response)?;
        }
        wait_for_discard(stream)
    });
    run(async {
        use compio_postgres::{ExecutionScheduling, QueryLimits, ReuseState};

        let details = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&details);
        let config = peer.config().notice_handler(move |notice| {
            assert_ne!(notice.message, "panicking", "fixture NOTICE callback panic");
            let detail = notice
                .fields()
                .find_map(|(tag, value)| (tag == b'D').then_some(value))
                .unwrap();
            observed.lock().unwrap().push(detail.to_owned());
        });
        let mut connection = TcpConnection::connect(config).await.unwrap();
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        };
        let scheduling = ExecutionScheduling::Uninterrupted;
        connection
            .query_simple_single(
                "UPDATE fixture SET n = 1",
                compio_postgres::QueryOptions { limits, scheduling },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert_eq!(*details.lock().unwrap(), ["startup detail", "query detail"]);
        let operation = async {
            connection
                .query_simple_single(
                    "UPDATE fixture SET n = 2",
                    compio_postgres::QueryOptions { limits, scheduling },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .finish()
                .await
        };
        assert!(AssertUnwindSafe(operation).catch_unwind().await.is_err());
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn startup_enforces_its_own_message_limit() {
    let peer = Peer::short_queries(|stream| {
        read_startup(stream)?;
        let notice = frame(b'N', b"SNOTICE\0C00000\0Mfixture notice\0\0");
        // 正常启动需要五条消息。这里的 Ready 将是第 129 条。
        let mut response = notice.repeat(124);
        response.extend(startup_response("19.0", "UTF8", true));
        stream.write_all(&response)?;
        wait_for_discard(stream)
    });
    run(async {
        assert!(matches!(
            TcpConnection::connect(peer.config()).await,
            Err(Error::Limit("startup exceeded its 128-message limit"))
        ));
    });
    peer.finish();
}

#[test]
fn idle_listener_yields_and_delivers_notifications_after_control_frames() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        let mut notice_body = b"SNOTICE\0C00000\0M".to_vec();
        notice_body.resize(1536, b'x');
        notice_body.extend_from_slice(b"\0\0");
        let notice = frame(b'N', &notice_body);
        let mut response = notice.repeat(257);
        response.extend(frame(b'A', b"\0\0\0\x07fixture\0late\0"));
        response.extend(frame(b'A', b"\0\0\0\x07fixture\0next\0"));
        stream.write_all(&response)?;
        wait_for_discard(stream)
    });
    run(async {
        let notices = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notices);
        let config = peer.config().notice_handler(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });
        let mut listener = TcpConnection::connect(config)
            .await
            .unwrap()
            .into_listener(compio_postgres::ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(256).unwrap(),
            })
            .unwrap();
        for checkpoint in [128, 256] {
            let mut wait = std::pin::pin!(listener.next_notification(|_| ()));
            poll_fn(|cx| {
                assert!(wait.as_mut().poll(cx).is_pending());
                if notices.load(Ordering::Relaxed) == checkpoint {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        for expected in ["late", "next"] {
            assert_eq!(
                listener
                    .next_notification(|n| n.payload.to_owned())
                    .await
                    .unwrap(),
                expected
            );
        }
        assert_eq!(notices.load(Ordering::Relaxed), 257);
        listener.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn startup_rejects_parameters_or_ready_before_authentication() {
    for response in [parameter("server_version", "19"), ready()] {
        let peer = Peer::short_queries(move |stream| {
            read_startup(stream)?;
            stream.write_all(&response)
        });
        run(async {
            assert!(matches!(
                TcpConnection::connect(peer.config()).await,
                Err(Error::Protocol(_))
            ));
        });
        peer.finish();
    }
}

#[test]
fn startup_rejects_protocol_negotiation_before_or_after_authentication_ok() {
    for after_authentication in [false, true] {
        let peer = Peer::short_queries(move |stream| {
            read_startup(stream)?;
            let mut response = if after_authentication {
                authentication_ok()
            } else {
                Vec::new()
            };
            let mut negotiation = Vec::from(0x0003_0000_u32.to_be_bytes());
            negotiation.extend_from_slice(&0_i32.to_be_bytes());
            response.extend(frame(b'v', &negotiation));
            stream.write_all(&response)
        });
        run(async {
            assert!(matches!(
                TcpConnection::connect(peer.config()).await,
                Err(Error::Unsupported(_))
            ));
        });
        peer.finish();
    }
}

#[test]
fn startup_requires_pg19_utf8_and_cancellation_key() {
    for (version, encoding, include_key) in [
        ("18.6", "UTF8", true),
        ("190.0", "UTF8", true),
        ("19", "LATIN1", true),
        ("19", "UTF8", false),
    ] {
        let peer = Peer::short_queries(move |stream| {
            read_startup(stream)?;
            stream.write_all(&startup_response(version, encoding, include_key))
        });
        run(async {
            let result = TcpConnection::connect(peer.config()).await;
            if include_key {
                assert!(matches!(result, Err(Error::Unsupported(_))));
            } else {
                assert!(matches!(result, Err(Error::Protocol(_))));
            }
        });
        peer.finish();
    }
}

#[test]
fn prepare_retains_a_non_int4_layout_without_discarding_the_connection() {
    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        expect_request(stream, b"PDS")?;
        stream.write_all(&prepared_response(20, 8))?;
        wait_for_discard(stream)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("test startup");
        scalar::configure(&mut connection);
        assert_eq!(connection.server_info().version, "19.0");
        assert_eq!(connection.server_info().cancel_key_length, 8);
        assert!(connection.is_usable());
        let statement = connection
            .prepare_scalar(SQL)
            .await
            .expect("general int8 layout");
        assert_eq!(
            statement.layout().column(0).unwrap().type_oid,
            compio_postgres::types::Oid::INT8
        );
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn query_error_consumes_ready_before_reuse_and_close_invalidates_the_handle() {
    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        prepare(stream)?;
        expect_request(stream, b"BES")?;
        let mut error = frame(b'2', &[]);
        error.extend(database_error("22012"));
        error.extend(ready());
        stream.write_all(&error)?;
        expect_request(stream, b"BES")?;
        stream.write_all(&query_success(Some(-7)))?;
        expect_request(stream, b"CS")?;
        let mut closed = frame(b'3', &[]);
        closed.extend(ready());
        stream.write_all(&closed)?;
        wait_for_discard(stream)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("test startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare int4");
        let error = connection
            .query_scalar(&statement, Some(0))
            .await
            .expect_err("SQL error must be returned");
        assert!(matches!(error, Error::Database(error) if error.code() == "22012"));
        assert!(connection.is_usable());
        assert_eq!(
            connection.query_scalar(&statement, Some(-7)).await.unwrap(),
            Some(-7)
        );
        connection
            .close_prepared(&statement)
            .await
            .expect("close succeeds after recovery");
        assert!(connection.is_usable());
        assert!(matches!(
            connection.query_scalar(&statement, Some(8)).await,
            Err(Error::InvalidInput(_))
        ));
        connection.discard();
    });
    peer.finish();
}

#[test]
fn late_error_after_command_complete_prevents_false_success() {
    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        prepare(stream)?;
        expect_request(stream, b"BES")?;
        let mut response = frame(b'2', &[]);
        response.extend(row(Some(42)));
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(database_error("40001"));
        response.extend(ready());
        stream.write_all(&response)?;
        expect_request(stream, b"BES")?;
        stream.write_all(&query_success(None))?;
        wait_for_discard(stream)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("test startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare int4");
        let error = connection
            .query_scalar(&statement, Some(42))
            .await
            .expect_err("late boundary error must override provisional success");
        assert!(matches!(error, Error::Database(error) if error.code() == "40001"));
        assert!(connection.is_usable());
        assert_eq!(
            connection.query_scalar(&statement, None).await.unwrap(),
            None
        );
        connection.discard();
    });
    peer.finish();
}

#[test]
fn failed_transaction_and_fatal_errors_are_not_usable_connections() {
    for fatal in [false, true] {
        let peer = Peer::short_queries(move |stream| {
            handshake(stream)?;
            prepare(stream)?;
            expect_request(stream, b"BES")?;
            let mut response = frame(b'2', &[]);
            if fatal {
                response.extend(database_error_severity("57P01", "FATAL"));
            } else {
                response.extend(database_error("25P02"));
                response.extend(frame(b'Z', b"E"));
            }
            stream.write_all(&response)?;
            // FATAL 没有后续 Ready。对端保持连接，以验证客户端能立即结束等待。
            wait_for_discard(stream)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config())
                .await
                .expect("test startup");
            scalar::configure(&mut connection);
            let statement = connection.prepare_scalar(SQL).await.expect("prepare int4");
            let error = connection
                .query_scalar(&statement, Some(1))
                .await
                .expect_err("database error must be reported");
            assert!(matches!(
                error,
                Error::Database(error) if error.code() == if fatal { "57P01" } else { "25P02" }
            ));
            assert!(!connection.is_usable());
            if fatal {
                assert!(matches!(
                    connection.query_scalar(&statement, Some(2)).await,
                    Err(Error::Broken)
                ));
            } else {
                assert_eq!(
                    connection.transaction_status(),
                    compio_postgres::TransactionStatus::FailedTransaction
                );
                assert!(matches!(
                    connection.query_scalar(&statement, Some(2)).await,
                    Err(Error::Unsupported(_))
                ));
            }
            connection.discard();
        });
        peer.finish();
    }
}

fn abandoned_query(forget: bool) {
    let peer = Peer::short_queries(|stream| {
        handshake(stream)?;
        prepare(stream)?;
        // 保持查询未完成。等待方退出时请求可能只发了一部分，对端只等连接关闭。
        wait_for_discard(stream)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("test startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare int4");
        let mut future = Box::pin(connection.query_scalar(&statement, Some(1)));
        let first_poll = poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await;
        assert!(matches!(first_poll, Poll::Pending));
        if forget {
            // 故意遗忘持有请求的 future，验证连接的复用保护不依赖它的析构。
            std::mem::forget(future);
        } else {
            drop(future);
        }
        assert!(!connection.is_usable());
        assert!(matches!(
            connection.query_scalar(&statement, Some(2)).await,
            Err(Error::Busy)
        ));
        assert!(matches!(
            connection.prepare_scalar(SQL).await,
            Err(Error::Busy)
        ));
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn dropped_polled_query_keeps_the_connection_active() {
    abandoned_query(false);
}

#[test]
fn forgotten_polled_query_keeps_the_connection_active() {
    abandoned_query(true);
}
