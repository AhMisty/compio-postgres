//! 有限流水线可包含不同类型的成员，每个成员有独立的 Sync 边界和结果所有权。
//! 真实数据库用例使用 PostgreSQL 19 和 SCRAM 认证。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{
    IO_DEADLINE, database_error, execution, expect, handshake, limits, preparation_response,
    prepare, read_prepare, ready, row, run,
};
use peer::{Peer, frame, invalid};

use compio_postgres::{
    CommandKind, DatabaseError, Error, QueryLimits, ResultFormats, StatementLimits, TcpConfig,
    TransactionEnd, TransactionStatus,
    expert::{
        PipelineItem, PipelineLimits, PipelineRequest, PipelineResult, TcpSession as TcpConnection,
    },
    types::{Format, Oid, Parameter},
};
use std::{
    future::{Future, poll_fn},
    io::Write,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
};

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1024,
        max_result_bytes: 64 * 1024,
        max_metadata_bytes: 16 * 1024,
    }
}

fn result_rows(count: u32) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    for value in 0..count {
        response.extend(row(&[Some(&i32::try_from(value).unwrap().to_be_bytes())]));
    }
    response.extend(frame(b'C', format!("SELECT {count}\0").as_bytes()));
    response.extend(ready());
    response
}

fn pipeline_limits() -> PipelineLimits {
    PipelineLimits {
        storage: compio_postgres::AllocationPolicy::ReserveLimit,
        max_requests: 32,
        max_rows: 4096,
        max_result_bytes: 1024 * 1024,
        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
    }
}

async fn connect(config: TcpConfig) -> TcpConnection {
    let mut connection = TcpConnection::connect(config).await.unwrap();
    connection
        .configure_statements(StatementLimits {
            max_statements: 8,
            max_metadata_bytes: 32 * 1024,
        })
        .unwrap();
    connection
}

fn request<'a>(
    statement: &'a compio_postgres::expert::PreparedStatement,
    parameters: &'a [Parameter<'a>],
) -> PipelineRequest<'a> {
    PipelineRequest {
        statement,
        parameters,
        limits: query_limits(),
    }
}

fn integer_values(result: &PipelineResult) -> Vec<i32> {
    result
        .rows
        .rows()
        .map(|row| row.unwrap().decoder().decode_next::<i32>().unwrap())
        .collect()
}

fn append_checkpoint(response: &mut Vec<u8>) {
    response.extend(frame(b'N', b"SNOTICE\0C00000\0Mpipeline checkpoint\0\0"));
}

fn checkpoint_config(config: TcpConfig) -> (TcpConfig, Arc<AtomicBool>) {
    let observed = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&observed);
    let config = config.notice_handler(move |notice| {
        assert_eq!(notice.message, "pipeline checkpoint");
        marker.store(true, Ordering::Release);
    });
    (config, observed)
}

async fn wait_for_checkpoint<F: Future>(mut operation: Pin<&mut F>, observed: &AtomicBool) {
    poll_fn(|cx| {
        assert!(operation.as_mut().poll(cx).is_pending());
        if observed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn heterogeneous_members_collect_many_rows_nulls_and_control_results() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("i", 23, 4)])?;
        let text = prepare(socket, &[25], &[("t", 25, -1)])?;
        let control = prepare(socket, &[], &[])?;
        execution(socket, &integer, false)?;
        execution(socket, &text, false)?;
        execution(socket, &control, false)?;
        let mut response = result_rows(300);
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some("你好".as_bytes())]));
        response.extend(row(&[None]));
        response.extend(frame(b'C', b"SELECT 2\0"));
        response.extend(ready());
        response.extend(frame(b'2', &[]));
        response.extend(frame(b'C', b"UPDATE 7\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let integer = connection
            .prepare(
                "SELECT generate_series(0,299)",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let text = connection
            .prepare(
                "SELECT $1::text",
                &[Oid::TEXT],
                ResultFormats::All(Format::Text),
            )
            .await
            .unwrap();
        let control = connection
            .prepare(
                "UPDATE fixture SET n=1",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let parameters = [Parameter::text(Oid::TEXT, "你好")];
        let items = connection
            .query_pipeline(
                &[
                    request(&integer, &[]),
                    request(&text, &parameters),
                    request(&control, &[]),
                ],
                pipeline_limits(),
            )
            .await
            .unwrap();
        let integer = items[0].as_ref().unwrap();
        assert_eq!(integer_values(integer), (0..300).collect::<Vec<i32>>());
        assert_eq!(integer.completion.rows_returned, 300);
        assert_eq!(integer.completion.rows_affected, Some(300));
        assert_eq!(integer.rows.used_bytes(), 300 * 12);
        let text = items[1].as_ref().unwrap();
        let values: Vec<_> = text
            .rows
            .rows()
            .map(|row| {
                row.unwrap()
                    .decoder()
                    .decode_next::<Option<&str>>()
                    .unwrap()
            })
            .collect();
        assert_eq!(values, [Some("你好"), None]);
        let control = items[2].as_ref().unwrap();
        assert!(control.rows.is_empty());
        assert_eq!(control.rows.retained_bytes(), 0);
        assert_eq!(control.completion.command, Some(CommandKind::Update));
        assert_eq!(control.completion.rows_affected, Some(7));
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn sql_error_discards_tentative_rows_preserves_first_cause_and_continues() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("i", 23, 4)])?;
        for _ in 0..3 {
            execution(socket, &statement, false)?;
        }
        let mut response = result_rows(1);
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(&7_i32.to_be_bytes())]));
        response.extend(database_error("ERROR", "22012", "first cause"));
        response.extend(database_error("ERROR", "22000", "later cause"));
        response.extend(ready());
        response.extend(result_rows(2));
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut requests = [
            request(&statement, &[]),
            request(&statement, &[]),
            request(&statement, &[]),
        ];
        for request in &mut requests {
            request.limits.max_result_bytes = 24;
        }
        let budget = 3 * std::mem::size_of::<PipelineItem>()
            + 48
            + std::mem::size_of::<DatabaseError>()
            + database_error("ERROR", "22012", "first cause").len()
            - 5;
        let items = connection
            .query_pipeline(
                &requests,
                PipelineLimits {
                    max_result_bytes: budget,
                    ..pipeline_limits()
                },
            )
            .await
            .unwrap();
        assert_eq!(integer_values(items[0].as_ref().unwrap()), [0]);
        let error = items[1].as_ref().unwrap_err();
        assert_eq!(error.code(), "22012");
        assert_eq!(error.message(), "first cause");
        assert_eq!(integer_values(items[2].as_ref().unwrap()), [0, 1]);
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn eof_and_fatal_return_only_ready_confirmed_prefixes() {
    for fatal in [false, true] {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("i", 23, 4)])?;
            for _ in 0..3 {
                execution(socket, &statement, false)?;
            }
            let mut response = result_rows(1);
            response.extend(frame(b'2', &[]));
            response.extend(row(&[Some(&9_i32.to_be_bytes())]));
            response.extend(frame(b'C', b"SELECT 1\0"));
            if fatal {
                response.extend(database_error("FATAL", "57P01", "terminated"));
            }
            socket.write_all(&response)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let error = connection
                .query_pipeline(
                    &[
                        request(&statement, &[]),
                        request(&statement, &[]),
                        request(&statement, &[]),
                    ],
                    pipeline_limits(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.completed.len(), 1);
            assert_eq!(integer_values(error.completed[0].as_ref().unwrap()), [0]);
            assert!(error.may_have_executed);
            if fatal {
                assert!(matches!(error.source, Error::Database(error) if error.code() == "57P01"));
            } else {
                assert!(matches!(error.source, Error::Io(_)));
            }
            assert!(!connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn aggregate_rows_member_rows_and_retained_bytes_are_hard_bounds() {
    for mode in 0..4 {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("i", 23, 4)])?;
            for _ in 0..2 {
                execution(socket, &statement, false)?;
            }
            let mut response = result_rows(1);
            response.extend(result_rows(2));
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let mut requests = [request(&statement, &[]), request(&statement, &[])];
            requests[0].limits.max_result_bytes = 12;
            requests[1].limits.max_result_bytes = if mode == 2 { 23 } else { 24 };
            requests[1].limits.max_rows = if mode == 1 { 1 } else { 2 };
            let limits = PipelineLimits {
                max_rows: if mode == 0 { 2 } else { 3 },
                max_result_bytes: 2 * std::mem::size_of::<PipelineItem>()
                    + if mode == 3 { 35 } else { 36 },
                ..pipeline_limits()
            };
            let error = connection
                .query_pipeline(&requests, limits)
                .await
                .unwrap_err();
            assert_eq!(error.completed.len(), 1);
            assert!(matches!(error.source, Error::Limit(_) | Error::Codec(_)));
            assert!(error.may_have_executed);
            assert!(!connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn diagnostic_budget_includes_box_and_full_wire_backing() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("i", 23, 4)])?;
        execution(socket, &statement, false)?;
        let mut response = database_error("ERROR", "22000", &"x".repeat(1024));
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let error = connection
            .query_pipeline(
                &[request(&statement, &[])],
                PipelineLimits {
                    max_result_bytes: std::mem::size_of::<PipelineItem>()
                        + std::mem::size_of::<DatabaseError>()
                        + 32,
                    ..pipeline_limits()
                },
            )
            .await
            .unwrap_err();
        assert!(error.completed.is_empty());
        assert!(error.may_have_executed);
        assert!(matches!(error.source, Error::Limit(_)));
        connection.discard();
    });
    peer.finish();
}

#[test]
fn malformed_rows_and_missing_bind_are_rejected_without_publishing_member() {
    for missing_bind in [false, true] {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("i", 23, 4)])?;
            execution(socket, &statement, false)?;
            let mut response = if missing_bind {
                Vec::new()
            } else {
                frame(b'2', &[])
            };
            response.extend(if missing_bind {
                row(&[Some(&1_i32.to_be_bytes())])
            } else {
                row(&[])
            });
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let error = connection
                .query_pipeline(&[request(&statement, &[])], pipeline_limits())
                .await
                .unwrap_err();
            assert!(error.completed.is_empty());
            assert!(error.may_have_executed);
            assert!(matches!(error.source, Error::Protocol(_) | Error::Codec(_)));
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn empty_and_preflight_failures_emit_no_pipeline_bytes() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("i", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(1))?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        assert!(
            connection
                .query_pipeline(
                    &[],
                    PipelineLimits {
                        storage: compio_postgres::AllocationPolicy::ReserveLimit,
                        max_requests: 0,
                        max_rows: 0,
                        max_result_bytes: 0,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    }
                )
                .await
                .unwrap()
                .is_empty()
        );
        let value = 1_i32.to_be_bytes();
        let parameters = [Parameter::binary(Oid::INT4, &value)];
        let wrong_type = [Parameter::text(Oid::TEXT, "1")];
        for (parameters, member_limits, limits) in [
            (&[][..], query_limits(), pipeline_limits()),
            (&wrong_type[..], query_limits(), pipeline_limits()),
            (
                &parameters[..],
                QueryLimits {
                    max_metadata_bytes: 0,
                    ..query_limits()
                },
                pipeline_limits(),
            ),
            (
                &parameters[..],
                query_limits(),
                PipelineLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_requests: 0,
                    ..pipeline_limits()
                },
            ),
            (
                &parameters[..],
                query_limits(),
                PipelineLimits {
                    max_result_bytes: 0,
                    ..pipeline_limits()
                },
            ),
        ] {
            let error = connection
                .query_pipeline(
                    &[PipelineRequest {
                        statement: &statement,
                        parameters,
                        limits: member_limits,
                    }],
                    limits,
                )
                .await
                .unwrap_err();
            assert!(error.completed.is_empty());
            assert!(!error.may_have_executed);
            assert!(matches!(
                error.source,
                Error::Limit(_) | Error::InvalidInput(_)
            ));
            assert!(connection.is_usable());
        }
        let large = vec![0; 8192];
        let oversized = [Parameter::binary(Oid::INT4, &large)];
        let error = connection
            .query_pipeline(&[request(&statement, &oversized)], pipeline_limits())
            .await
            .unwrap_err();
        assert!(!error.may_have_executed);
        assert!(matches!(error.source, Error::Limit(_)));
        let individually_bounded = vec![0; 4090];
        let individually_bounded = [Parameter::binary(Oid::INT4, &individually_bounded)];
        for (first, last) in [
            (&parameters[..], &wrong_type[..]),
            (&parameters[..], &oversized[..]),
            (&individually_bounded[..], &individually_bounded[..]),
        ] {
            let error = connection
                .query_pipeline(
                    &[request(&statement, first), request(&statement, last)],
                    pipeline_limits(),
                )
                .await
                .unwrap_err();
            assert!(error.completed.is_empty());
            assert!(!error.may_have_executed);
            assert!(matches!(
                error.source,
                Error::Limit(_) | Error::InvalidInput(_)
            ));
            assert!(connection.is_usable());
        }
        let results = connection
            .query_pipeline(&[request(&statement, &parameters)], pipeline_limits())
            .await
            .unwrap();
        assert_eq!(integer_values(results[0].as_ref().unwrap()), [0]);
        connection.invalidate_statements().unwrap();
        let error = connection
            .query_pipeline(&[request(&statement, &parameters)], pipeline_limits())
            .await
            .unwrap_err();
        assert!(!error.may_have_executed);
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn a_foreign_late_statement_never_sends_the_valid_pipeline_prefix() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("i", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(1))?;
        peer::eof(socket)
    });
    let foreign_peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        prepare(socket, &[23], &[("i", 23, 4)])?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let mut foreign_connection = connect(foreign_peer.config()).await;
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let foreign_statement = foreign_connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let parameters = [Parameter::int4(42)];
        let error = connection
            .query_pipeline(
                &[
                    request(&statement, &parameters),
                    request(&foreign_statement, &parameters),
                ],
                pipeline_limits(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::InvalidInput(_)));
        assert!(error.completed.is_empty());
        assert!(!error.may_have_executed);
        assert!(connection.is_usable());
        let results = connection
            .query_pipeline(&[request(&statement, &parameters)], pipeline_limits())
            .await
            .unwrap();
        assert_eq!(integer_values(results[0].as_ref().unwrap()), [0]);
        connection.discard();
        foreign_connection.discard();
    });
    peer.finish();
    foreign_peer.finish();
}

#[test]
fn dropped_and_forgotten_waiters_keep_the_lease_until_explicit_recovery() {
    for forget in [false, true] {
        let (release, wait) = mpsc::sync_channel(1);
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("i", 23, 4)])?;
            execution(socket, &statement, false)?;
            execution(socket, &statement, false)?;
            let mut response = result_rows(1);
            append_checkpoint(&mut response);
            socket.write_all(&response)?;
            wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
            socket.write_all(&result_rows(300))?;
            execution(socket, &statement, false)?;
            socket.write_all(&result_rows(2))?;
            peer::eof(socket)
        });
        run(async {
            let (config, checkpoint) = checkpoint_config(peer.config());
            let mut connection = connect(config).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[]), request(&statement, &[])];
            let mut future = Box::pin(connection.query_pipeline(&requests, pipeline_limits()));
            wait_for_checkpoint(future.as_mut(), &checkpoint).await;
            if forget {
                std::mem::forget(future);
            } else {
                drop(future);
            }
            assert!(!connection.is_usable());
            let error = connection
                .query_pipeline(&[], pipeline_limits())
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::Busy));
            assert!(!error.may_have_executed);
            release.send(()).unwrap();
            connection
                .recover_to_ready_with_limits(300, 3600)
                .await
                .unwrap();
            assert!(connection.is_usable());
            let items = connection
                .query_pipeline(&[request(&statement, &[])], pipeline_limits())
                .await
                .unwrap();
            assert_eq!(integer_values(items[0].as_ref().unwrap()), [0, 1]);
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn abandoned_pipeline_checks_each_remaining_member_and_its_column_count() {
    for case in 0..3 {
        let (release, wait) = mpsc::sync_channel(1);
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let first = prepare(socket, &[], &[("n", 23, 4)])?;
            let second = prepare(socket, &[], &[("n", 23, 4), ("m", 23, 4)])?;
            execution(socket, &first, false)?;
            execution(socket, &second, false)?;
            let mut response = result_rows(1);
            if case != 0 {
                response.extend(frame(b'2', &[]));
            }
            append_checkpoint(&mut response);
            socket.write_all(&response)?;
            wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
            let mut response = Vec::new();
            if case == 1 {
                response.extend(row(&[Some(&1_i32.to_be_bytes())]));
                response.extend(frame(b'C', b"SELECT 1\0"));
            } else if case == 2 {
                response.extend(row(&[
                    Some(&1_i32.to_be_bytes()),
                    Some(&2_i32.to_be_bytes()),
                ]));
                response.extend(frame(b'C', b"SELECT 1\0"));
                // 即使已收到 Execute 的完成标签，服务端仍可在 Sync 边界报告错误。
                response.extend(database_error("ERROR", "23503", "deferred constraint"));
            }
            response.extend(ready());
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let (config, checkpoint) = checkpoint_config(peer.config());
            let mut connection = connect(config).await;
            let first = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let second = connection
                .prepare("SELECT 1,2", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&first, &[]), request(&second, &[])];
            let mut pending = Box::pin(connection.query_pipeline(&requests, pipeline_limits()));
            wait_for_checkpoint(pending.as_mut(), &checkpoint).await;
            drop(pending);
            release.send(()).unwrap();
            let result = connection.recover_to_ready_with_limits(1, 20).await;
            if case == 2 {
                result.unwrap();
                assert!(connection.is_usable());
            } else {
                assert!(matches!(result, Err(Error::Protocol(_))));
                assert!(!connection.is_usable());
            }
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn pipeline_transaction_end_is_recorded_but_cannot_release_later_members() {
    for recover in [false, true] {
        let (release, wait) = mpsc::sync_channel(1);
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            if expect(socket, b'Q')? != b"BEGIN\0" {
                return Err(invalid());
            }
            let mut response = frame(b'C', b"BEGIN\0");
            response.extend(frame(b'Z', b"T"));
            socket.write_all(&response)?;
            let end = read_prepare(socket)?;
            let mut response = preparation_response(&[], &[]);
            *response.last_mut().ok_or_else(invalid)? = b'T';
            socket.write_all(&response)?;
            let next = read_prepare(socket)?;
            let mut response = preparation_response(&[], &[("n", 23, 4)]);
            *response.last_mut().ok_or_else(invalid)? = b'T';
            socket.write_all(&response)?;
            execution(socket, &end, false)?;
            execution(socket, &next, false)?;
            let mut response = frame(b'2', &[]);
            if recover {
                append_checkpoint(&mut response);
            }
            socket.write_all(&response)?;
            wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
            let mut response = frame(b'C', b"COMMIT\0");
            response.extend(ready());
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let (config, checkpoint) = checkpoint_config(peer.config());
            let mut connection = connect(config).await;
            let mut transaction = connection.begin_transaction().await.unwrap();
            let end = transaction
                .prepare("COMMIT", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let next = transaction
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&end, &[]), request(&next, &[])];
            if recover {
                let mut pending =
                    Box::pin(transaction.query_pipeline(&requests, pipeline_limits()));
                wait_for_checkpoint(pending.as_mut(), &checkpoint).await;
                drop(pending);
                drop(transaction);
                release.send(()).unwrap();
                assert!(matches!(
                    connection.recover_to_ready().await,
                    Err(Error::Unsupported(_))
                ));
                assert_eq!(
                    connection.take_transaction_end(),
                    Some(TransactionEnd::Committed)
                );
            } else {
                release.send(()).unwrap();
                let error = transaction
                    .query_pipeline(&requests, pipeline_limits())
                    .await
                    .unwrap_err();
                assert!(error.completed.is_empty());
                assert!(error.may_have_executed);
                assert!(matches!(error.source, Error::Unsupported(_)));
                assert_eq!(
                    transaction.take_transaction_end(),
                    Some(TransactionEnd::Committed)
                );
                drop(transaction);
            }
            assert!(!connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

fn live_config() -> TcpConfig {
    live::tcp_config(limits(), peer::TCP_OPTIONS)
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_heterogeneous_pipeline_matches_serial_results_and_independent_errors() {
    run(async {
        let mut connection = connect(live_config()).await;
        let integer = connection
            .prepare(
                "SELECT 10 / $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let text = connection
            .prepare(
                "SELECT $1::text, $2::bytea",
                &[Oid::TEXT, Oid::BYTEA],
                ResultFormats::PerColumn(vec![Format::Text, Format::Binary].into_boxed_slice()),
            )
            .await
            .unwrap();
        let two = 2_i32.to_be_bytes();
        let zero = 0_i32.to_be_bytes();
        let success = [Parameter::binary(Oid::INT4, &two)];
        let failure = [Parameter::binary(Oid::INT4, &zero)];
        let mixed = [
            Parameter::text(Oid::TEXT, "你好"),
            Parameter::binary(Oid::BYTEA, b"\0\xff"),
        ];
        let requests = [
            request(&integer, &success),
            request(&integer, &failure),
            request(&text, &mixed),
            request(&integer, &success),
        ];
        let items = connection
            .query_pipeline(&requests, pipeline_limits())
            .await
            .unwrap();
        assert_eq!(integer_values(items[0].as_ref().unwrap()), [5]);
        assert_eq!(items[1].as_ref().unwrap_err().code(), "22012");
        let mixed = items[2]
            .as_ref()
            .unwrap()
            .rows
            .rows()
            .next()
            .unwrap()
            .unwrap();
        let mut decoder = mixed.decoder();
        assert_eq!(decoder.decode_next::<&str>().unwrap(), "你好");
        assert_eq!(decoder.decode_next::<&[u8]>().unwrap(), b"\0\xff");
        decoder.finish().unwrap();
        let serial = connection
            .query(
                &integer,
                &success,
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let (rows, _) = serial
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(
            rows.rows()
                .next()
                .unwrap()
                .unwrap()
                .decoder()
                .decode_next::<i32>()
                .unwrap(),
            5
        );
        assert_eq!(integer_values(items[3].as_ref().unwrap()), [5]);
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_pipeline_many_rows_null_and_exact_storage_bound() {
    run(async {
        let mut connection = connect(live_config()).await;
        let series = connection
            .prepare(
                "SELECT generate_series(0,299)::int4",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let nullable = connection
            .prepare(
                "SELECT $1::text",
                &[Oid::TEXT],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let null = [Parameter::null(Oid::TEXT, Format::Binary)];
        let requests = [
            PipelineRequest {
                limits: QueryLimits {
                    max_result_bytes: 3600,
                    max_rows: 300,
                    ..query_limits()
                },
                ..request(&series, &[])
            },
            PipelineRequest {
                limits: QueryLimits {
                    max_result_bytes: 8,
                    max_rows: 1,
                    ..query_limits()
                },
                ..request(&nullable, &null)
            },
        ];
        let items = connection
            .query_pipeline(
                &requests,
                PipelineLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_requests: 2,
                    max_rows: 301,
                    max_result_bytes: 2 * std::mem::size_of::<PipelineItem>() + 3608,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            integer_values(items[0].as_ref().unwrap()),
            (0..300).collect::<Vec<i32>>()
        );
        assert_eq!(
            items[1]
                .as_ref()
                .unwrap()
                .rows
                .rows()
                .next()
                .unwrap()
                .unwrap()
                .decoder()
                .decode_next::<Option<&str>>()
                .unwrap(),
            None
        );
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_transaction_pipeline_reports_failed_successors_and_allows_rollback() {
    run(async {
        let mut connection = connect(live_config()).await;
        let mut transaction = connection.begin_transaction().await.unwrap();
        let statement = transaction
            .prepare(
                "SELECT 10 / $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let one = 1_i32.to_be_bytes();
        let zero = 0_i32.to_be_bytes();
        let success = [Parameter::binary(Oid::INT4, &one)];
        let failure = [Parameter::binary(Oid::INT4, &zero)];
        let requests = [
            request(&statement, &success),
            request(&statement, &failure),
            request(&statement, &success),
        ];
        let items = transaction
            .query_pipeline(&requests, pipeline_limits())
            .await
            .unwrap();
        assert_eq!(integer_values(items[0].as_ref().unwrap()), [10]);
        assert_eq!(
            items[0].as_ref().unwrap().completion.transaction_status,
            TransactionStatus::InTransaction
        );
        assert_eq!(items[1].as_ref().unwrap_err().code(), "22012");
        assert_eq!(items[2].as_ref().unwrap_err().code(), "25P02");
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert!(
            transaction
                .query_pipeline(&[], pipeline_limits())
                .await
                .is_err()
        );
        assert_eq!(
            transaction.rollback().await.unwrap().transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        assert!(connection.is_usable());
        connection.discard();
    });
}
