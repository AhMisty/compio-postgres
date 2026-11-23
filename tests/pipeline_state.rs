//! 通过本地 TCP 对端控制协议响应，验证流水线各成员独立的 Sync 边界。

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{expect as expect_tag, handshake, prepare, ready, run};
use peer::{Peer, close_statement, eof, frame};

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{
    future::Future,
    io::{self, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use compio_postgres::{
    Error,
    expert::{PipelineLimits, TcpSession as TcpConnection},
};

const SQL: &str = "SELECT $1::int4 AS result";

fn batch_limits() -> PipelineLimits {
    scalar::pipeline_limits(16, 16 * 1024)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn expected_bind(statement: &str, value: Option<i32>) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(statement.as_bytes());
    body.push(0);
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&1_i16.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    match value {
        Some(value) => {
            body.extend_from_slice(&4_i32.to_be_bytes());
            body.extend_from_slice(&value.to_be_bytes());
        }
        None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
    }
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&1_i16.to_be_bytes());
    body
}

fn expect_members(
    socket: &mut TcpStream,
    statement: &str,
    values: &[Option<i32>],
) -> io::Result<()> {
    for value in values {
        if expect_tag(socket, b'B')? != expected_bind(statement, *value) {
            return Err(invalid("Bind value or binary format was reordered"));
        }
        if expect_tag(socket, b'E')? != [0, 0, 0, 0, 0] {
            return Err(invalid(
                "Execute must use the unnamed portal without a row limit",
            ));
        }
        if !expect_tag(socket, b'S')?.is_empty() {
            return Err(invalid("each member must have an independent empty Sync"));
        }
    }
    Ok(())
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

fn success(value: Option<i32>) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    response.extend(row(value));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(ready());
    response
}

fn database_error(severity: &str, code: &str, message: &str) -> Vec<u8> {
    frame(
        b'E',
        format!("S{severity}\0V{severity}\0C{code}\0M{message}\0\0").as_bytes(),
    )
}

#[test]
fn each_member_keeps_its_sync_and_binary_value_order() {
    let values = [Some(i32::MIN), None, Some(i32::MAX)];
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("result", 23, 4)])?;
        expect_members(socket, &statement, &values)?;
        let response: Vec<u8> = values.into_iter().flat_map(success).collect();
        socket.write_all(&response)?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let results = scalar::pipeline(&mut connection, &statement, &values, batch_limits())
            .await
            .unwrap_or_else(|error| panic!("unexpected batch failure: {}", error.source));
        assert_eq!(
            scalar::values(&results),
            values.into_iter().map(Ok).collect::<Vec<_>>()
        );
        assert!(connection.is_usable());
        connection
            .close_prepared(&statement)
            .await
            .expect("close after all member boundaries");
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn ordinary_sql_error_does_not_skip_the_next_independent_member() {
    let values = [Some(1), Some(0), Some(2)];
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("result", 23, 4)])?;
        expect_members(socket, &statement, &values)?;
        let mut response = success(Some(100));
        response.extend(frame(b'2', &[]));
        response.extend(database_error("ERROR", "22012", "division by zero"));
        response.extend(ready());
        response.extend(success(Some(50)));
        socket.write_all(&response)?;
        expect_members(socket, &statement, &[Some(4)])?;
        socket.write_all(&success(Some(25)))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let results = scalar::pipeline(&mut connection, &statement, &values, batch_limits())
            .await
            .unwrap_or_else(|error| panic!("unexpected batch failure: {}", error.source));
        assert_eq!(results.len(), 3);
        assert_eq!(scalar::values(&results)[0], Ok(Some(100)));
        assert!(matches!(&results[1], Err(error) if error.code() == "22012"));
        assert_eq!(scalar::values(&results)[2], Ok(Some(50)));
        assert!(connection.is_usable());
        assert_eq!(
            connection.query_scalar(&statement, Some(4)).await.unwrap(),
            Some(25)
        );
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn eof_preserves_only_members_with_a_completed_ready_boundary() {
    let values = [Some(10), Some(20), Some(30)];
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("result", 23, 4)])?;
        expect_members(socket, &statement, &values)?;
        let mut response = success(Some(10));
        response.extend(frame(b'2', &[]));
        response.extend(row(Some(20)));
        socket.write_all(&response)
        // 在第二项的 CommandComplete 前断开，第三项也收不到响应。
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let error = scalar::pipeline(&mut connection, &statement, &values, batch_limits())
            .await
            .expect_err("EOF must fail the batch");
        assert_eq!(scalar::values(&error.completed), vec![Ok(Some(10))]);
        assert!(error.may_have_executed);
        assert!(matches!(error.source, Error::Io(_)));
        assert!(!connection.is_usable());
        assert!(matches!(
            connection.query_scalar(&statement, Some(40)).await,
            Err(Error::Broken)
        ));
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn fatal_error_returns_the_completed_prefix_and_breaks_the_connection() {
    let values = [Some(10), Some(20)];
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("result", 23, 4)])?;
        expect_members(socket, &statement, &values)?;
        let mut response = success(Some(10));
        response.extend(database_error("FATAL", "57P01", "fixture termination"));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("startup");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let error = scalar::pipeline(&mut connection, &statement, &values, batch_limits())
            .await
            .expect_err("fatal error must fail the batch");
        assert_eq!(scalar::values(&error.completed), vec![Ok(Some(10))]);
        assert!(error.may_have_executed);
        assert!(matches!(error.source, Error::Database(error) if error.code() == "57P01"));
        assert!(!connection.is_usable());
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn first_ready_does_not_release_an_abandoned_batch() {
    for forget in [false, true] {
        let first_consumed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&first_consumed);
        let values = [Some(10), Some(20)];
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[("result", 23, 4)])?;
            expect_members(socket, &statement, &values)?;
            let mut reply = success(Some(10));
            // NOTICE 位于第一条 Ready 之后。只有驱动已读过该边界，回调才可能执行。
            reply.extend(frame(
                b'N',
                b"SNOTICE\0VNOTICE\0C00000\0Mfirst ready consumed\0\0",
            ));
            socket.write_all(&reply)?;
            eof(socket)
        });
        run(async {
            let config = peer.config().notice_handler(move |notice| {
                assert_eq!(notice.message, "first ready consumed");
                marker.store(true, Ordering::Release);
            });
            let mut connection = TcpConnection::connect(config).await.expect("startup");
            scalar::configure(&mut connection);
            let statement = connection.prepare_scalar(SQL).await.expect("prepare");
            let mut batch = Box::pin(scalar::pipeline(
                &mut connection,
                &statement,
                &values,
                batch_limits(),
            ));
            std::future::poll_fn(|cx| {
                assert!(batch.as_mut().poll(cx).is_pending(), "第二项还没有 Ready");
                if first_consumed.load(Ordering::Acquire) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            if forget {
                std::mem::forget(batch);
            } else {
                drop(batch);
            }
            assert!(!connection.is_usable());
            assert!(matches!(
                connection.query_scalar(&statement, Some(30)).await,
                Err(Error::Busy)
            ));
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}
