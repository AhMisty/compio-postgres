//! 有限流水线先校验全部输入，收到各成员的 Ready 后才向回调借出结果。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{
    DEADLINE, database_error, execution, expect, handshake, limits, prepare, ready, row, run,
};
use peer::{Peer, frame, invalid};

use compio_postgres::{
    Error, QueryLimits, ReadyBatchEvent, ResultFormats, ReuseState, StatementLimits, TcpConfig,
    TransactionEnd, TransactionStatus,
    expert::{PipelineRequest, TcpSession as TcpConnection, VisitLimits},
    types::{Format, Oid, Parameter},
};
use std::{cell::Cell, future::Future, io::Write, rc::Rc, sync::mpsc};

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1,
        max_result_bytes: 12,
        max_metadata_bytes: 16 * 1024,
    }
}

fn visit_limits() -> VisitLimits {
    VisitLimits {
        storage: compio_postgres::AllocationPolicy::ReserveLimit,
        max_requests: 32,
        max_rows: 4096,
        max_result_bytes: 4096,
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

fn value_result(value: i32, status: u8) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    response.extend(row(&[Some(&value.to_be_bytes())]));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(frame(b'Z', &[status]));
    response
}

#[test]
fn finite_visit_reuses_one_arena_and_confirms_every_sync_before_delivery() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for _ in 0..3 {
            execution(socket, &statement, false)?;
        }
        let mut responses = value_result(1, b'I');
        responses.extend(value_result(2, b'I'));
        responses.extend(value_result(3, b'I'));
        socket.write_all(&responses)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [
            request(&statement, &[]),
            request(&statement, &[]),
            request(&statement, &[]),
        ];
        let mut observed = Vec::new();
        let mut first_storage = None;
        let completion = connection
            .query_pipeline_visit(&requests, visit_limits(), |event: ReadyBatchEvent<'_>| {
                assert_eq!(event.index, observed.len());
                assert_eq!(event.transaction_status, TransactionStatus::Idle);
                let result = event.outcome.unwrap();
                assert!(result.completion.succeeded);
                assert_eq!(result.completion.rows_returned, 1);
                assert_eq!(result.rows.retained_bytes(), 12);
                let view = result.rows.rows().next().unwrap().unwrap();
                let storage = view
                    .fields()
                    .next()
                    .unwrap()
                    .unwrap()
                    .bytes
                    .unwrap()
                    .as_ptr();
                if let Some(first) = first_storage {
                    assert_eq!(storage, first);
                } else {
                    first_storage = Some(storage);
                }
                observed.push(view.decoder().decode_next::<i32>().unwrap());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(observed, [1, 2, 3]);
        assert_eq!(
            (
                completion.admitted,
                completion.confirmed,
                completion.delivered,
                completion.sql_errors
            ),
            (3, 3, 3, 0)
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn empty_and_late_preflight_failures_never_send_a_prefix() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        prepare(socket, &[23], &[("n", 23, 4)])?;
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
        let empty = connection
            .query_pipeline_visit(
                &[],
                VisitLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_requests: 0,
                    max_rows: 0,
                    max_result_bytes: 0,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                |_: ReadyBatchEvent<'_>| panic!("empty visit callback"),
            )
            .await
            .unwrap();
        assert_eq!(
            (empty.admitted, empty.confirmed, empty.delivered),
            (0, 0, 0)
        );
        let values = [Parameter::int4(42)];
        let wrong = [Parameter::text(Oid::TEXT, "wrong")];
        for mode in 0..4 {
            let mut requests = [
                request(&statement, &values),
                request(&statement, if mode == 0 { &wrong } else { &values }),
            ];
            let mut limits = visit_limits();
            if mode == 1 {
                requests[1].limits.max_metadata_bytes = 0;
            }
            if mode == 2 {
                requests[1].limits.max_result_bytes = limits.max_result_bytes + 1;
            }
            if mode == 3 {
                limits.max_requests = 1;
            }
            let error = connection
                .query_pipeline_visit(&requests, limits, |_: ReadyBatchEvent<'_>| {
                    panic!("invalid visit callback")
                })
                .await
                .unwrap_err();
            assert!(!error.may_have_executed);
            assert!(if mode == 0 {
                matches!(error.source, Error::InvalidInput(_))
            } else {
                matches!(error.source, Error::Limit(_))
            });
            assert_eq!(
                (error.admitted, error.confirmed, error.delivered),
                (0, 0, 0)
            );
            assert!(connection.is_usable());
        }
        let large = vec![0; 9000];
        let oversized = [Parameter::binary(Oid::INT4, &large)];
        let error = connection
            .query_pipeline_visit(
                &[
                    request(&statement, &values),
                    request(&statement, &oversized),
                ],
                visit_limits(),
                |_: ReadyBatchEvent<'_>| panic!("oversized visit callback"),
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert!(!error.may_have_executed);
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn sql_error_hides_tentative_rows_has_separate_diagnostic_room_and_continues() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for _ in 0..3 {
            execution(socket, &statement, false)?;
        }
        let mut response = value_result(1, b'I');
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(&666_i32.to_be_bytes())]));
        response.extend(database_error("ERROR", "22012", "late member failure"));
        response.extend(ready());
        response.extend(value_result(3, b'I'));
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut observed = Vec::new();
        let completion = connection
            .query_pipeline_visit(
                &[
                    request(&statement, &[]),
                    request(&statement, &[]),
                    request(&statement, &[]),
                ],
                visit_limits(),
                |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, observed.len());
                    match event.outcome {
                        Ok(result) => observed.push(Some(
                            result
                                .rows
                                .rows()
                                .next()
                                .unwrap()
                                .unwrap()
                                .decoder()
                                .decode_next::<i32>()
                                .unwrap(),
                        )),
                        Err(error) => {
                            assert_eq!(error.code(), "22012");
                            observed.push(None);
                        }
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(observed, [Some(1), None, Some(3)]);
        assert_eq!(
            (
                completion.admitted,
                completion.confirmed,
                completion.delivered,
                completion.sql_errors
            ),
            (3, 3, 3, 1)
        );
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn layout_and_capacity_switches_preserve_each_members_layout_and_bound() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        let text = prepare(socket, &[], &[("t", 25, -1)])?;
        for statement in [&integer, &text, &integer, &integer] {
            execution(socket, statement, false)?;
        }
        let mut response = value_result(7, b'I');
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(b"ok")]));
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(ready());
        response.extend(value_result(9, b'I'));
        response.extend(value_result(10, b'I'));
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let integer = connection
            .prepare("SELECT 7", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let text = connection
            .prepare("SELECT 'ok'", &[], ResultFormats::All(Format::Text))
            .await
            .unwrap();
        let mut requests = [
            request(&integer, &[]),
            request(&text, &[]),
            request(&integer, &[]),
            request(&integer, &[]),
        ];
        requests[1].limits.max_result_bytes = 32;
        requests[2].limits.max_result_bytes = 24;
        let mut capacities = Vec::new();
        connection
            .query_pipeline_visit(&requests, visit_limits(), |event: ReadyBatchEvent<'_>| {
                let result = event.outcome.unwrap();
                capacities.push(result.rows.retained_bytes());
                let view = result.rows.rows().next().unwrap().unwrap();
                if event.index == 1 {
                    assert_eq!(view.decoder().decode_next::<&str>().unwrap(), "ok");
                } else {
                    assert_eq!(
                        view.decoder().decode_next::<i32>().unwrap(),
                        [7, 0, 9, 10][event.index]
                    );
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(capacities, [12, 32, 24, 12]);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn eof_does_not_deliver_a_row_without_its_ready() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        execution(socket, &statement, false)?;
        let mut response = value_result(1, b'I');
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(&2_i32.to_be_bytes())]));
        socket.write_all(&response)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut callbacks = 0;
        let error = connection
            .query_pipeline_visit(
                &[request(&statement, &[]), request(&statement, &[])],
                visit_limits(),
                |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, 0);
                    callbacks += 1;
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Io(_)));
        assert_eq!(
            (error.admitted, error.confirmed, error.delivered),
            (2, 1, 1)
        );
        assert_eq!(callbacks, 1);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn callback_error_and_panic_leave_a_discard_only_session() {
    use futures_util::FutureExt;
    for panic in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            execution(socket, &statement, false)?;
            let mut response = value_result(1, b'I');
            response.extend(value_result(2, b'I'));
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[]), request(&statement, &[])];
            let effects = Cell::new(0);
            if panic {
                let result = std::panic::AssertUnwindSafe(connection.query_pipeline_visit(
                    &requests,
                    visit_limits(),
                    |_: ReadyBatchEvent<'_>| -> Result<(), Error> {
                        effects.set(effects.get() + 1);
                        panic!("deliberate visit panic")
                    },
                ))
                .catch_unwind()
                .await;
                assert!(result.is_err());
            } else {
                let error = connection
                    .query_pipeline_visit(&requests, visit_limits(), |_: ReadyBatchEvent<'_>| {
                        effects.set(effects.get() + 1);
                        Err(Error::InvalidInput("deliberate callback failure"))
                    })
                    .await
                    .unwrap_err();
                assert_eq!(
                    (error.admitted, error.confirmed, error.delivered),
                    (2, 1, 0)
                );
                assert!(matches!(error.source, Error::InvalidInput(_)));
            }
            assert_eq!(effects.get(), 1);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            assert!(connection.recover_to_ready().await.is_err());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn dropped_and_forgotten_visits_recover_without_repeating_deliveries() {
    for forget in [false, true] {
        let (release, wait) = mpsc::channel();
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            execution(socket, &statement, false)?;
            socket.write_all(&value_result(1, b'I'))?;
            wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
            socket.write_all(&value_result(2, b'I'))?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[]), request(&statement, &[])];
            let observed = Rc::new(Cell::new(0));
            let counter = observed.clone();
            let mut pending = Box::pin(connection.query_pipeline_visit(
                &requests,
                visit_limits(),
                move |_: ReadyBatchEvent<'_>| {
                    counter.set(counter.get() + 1);
                    Ok(())
                },
            ));
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                if observed.get() == 1 {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            if forget {
                std::mem::forget(pending);
            } else {
                drop(pending);
            }
            assert_eq!(observed.get(), 1);
            assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
            assert!(matches!(
                connection
                    .query_pipeline_visit(&[], visit_limits(), |_: ReadyBatchEvent<'_>| Ok(()))
                    .await
                    .unwrap_err()
                    .source,
                Error::Busy
            ));
            release.send(()).unwrap();
            connection
                .recover_to_ready_with_limits(1, 12)
                .await
                .unwrap();
            assert_eq!(observed.get(), 1);
            assert!(connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn transaction_visit_keeps_failed_state_until_explicit_rollback() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        if expect(socket, b'Q')? != b"BEGIN\0" {
            return Err(invalid());
        }
        let mut response = frame(b'C', b"BEGIN\0");
        response.extend(frame(b'Z', b"T"));
        socket.write_all(&response)?;
        execution(socket, &statement, false)?;
        execution(socket, &statement, false)?;
        let mut response = value_result(9, b'T');
        response.extend(frame(b'2', &[]));
        response.extend(database_error("ERROR", "22012", "transaction failure"));
        response.extend(frame(b'Z', b"E"));
        socket.write_all(&response)?;
        if expect(socket, b'Q')? != b"ROLLBACK\0" {
            return Err(invalid());
        }
        let mut response = frame(b'C', b"ROLLBACK\0");
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 9", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut statuses = Vec::new();
        let completion = transaction
            .query_pipeline_visit(
                &[request(&statement, &[]), request(&statement, &[])],
                visit_limits(),
                |event: ReadyBatchEvent<'_>| {
                    statuses.push(event.transaction_status);
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(
            statuses,
            [
                TransactionStatus::InTransaction,
                TransactionStatus::FailedTransaction
            ]
        );
        assert_eq!(completion.sql_errors, 1);
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        let error = transaction
            .query_pipeline_visit(&[], visit_limits(), |_: ReadyBatchEvent<'_>| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Unsupported(_)));
        assert!(!error.may_have_executed);
        let ended = transaction.rollback().await.unwrap();
        assert_eq!(ended.transaction_end, Some(TransactionEnd::RolledBack));
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn aggregate_row_budget_counts_tentative_rows_discarded_after_a_sql_error() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        execution(socket, &statement, false)?;
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&1_i32.to_be_bytes())]));
        response.extend(database_error("ERROR", "22012", "failure after a row"));
        response.extend(ready());
        response.extend(value_result(2, b'I'));
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut calls = 0;
        let error = connection
            .query_pipeline_visit(
                &[request(&statement, &[]), request(&statement, &[])],
                VisitLimits {
                    max_rows: 1,
                    ..visit_limits()
                },
                |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.outcome.unwrap_err().code(), "22012");
                    calls += 1;
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            (
                error.admitted,
                error.confirmed,
                error.delivered,
                error.sql_errors
            ),
            (2, 1, 1, 1)
        );
        assert!(matches!(error.source, Error::Limit(_)));
        assert_eq!(calls, 1);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn early_transaction_end_preserves_the_end_fact_and_discards_accepted_successors() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let end = prepare(socket, &[], &[])?;
        let next = prepare(socket, &[], &[("n", 23, 4)])?;
        if expect(socket, b'Q')? != b"BEGIN\0" {
            return Err(invalid());
        }
        let mut response = frame(b'C', b"BEGIN\0");
        response.extend(frame(b'Z', b"T"));
        socket.write_all(&response)?;
        execution(socket, &end, false)?;
        execution(socket, &next, false)?;
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'C', b"COMMIT\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let end = connection
            .prepare("COMMIT", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let next = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let error = transaction
            .query_pipeline_visit(
                &[request(&end, &[]), request(&next, &[])],
                visit_limits(),
                |_: ReadyBatchEvent<'_>| panic!("no Ready-confirmed member may be delivered"),
            )
            .await
            .unwrap_err();
        assert_eq!(
            (error.admitted, error.confirmed, error.delivered),
            (2, 0, 0)
        );
        assert!(error.may_have_executed);
        assert!(matches!(error.source, Error::Unsupported(_)));
        drop(transaction);
        assert_eq!(
            connection.take_transaction_end(),
            Some(TransactionEnd::Committed)
        );
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_finite_visit_confirms_independent_errors_and_transaction_rollback() {
    let config = live::tcp_config(limits(), peer::TCP_OPTIONS);
    run(async {
        let mut connection = connect(config).await;
        let statement = connection
            .prepare(
                "SELECT 100 / $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let values = [
            [Parameter::int4(2)],
            [Parameter::int4(0)],
            [Parameter::int4(4)],
        ];
        let requests = [
            request(&statement, &values[0]),
            request(&statement, &values[1]),
            request(&statement, &values[2]),
        ];
        let mut observed = Vec::new();
        let completion = connection
            .query_pipeline_visit(&requests, visit_limits(), |event: ReadyBatchEvent<'_>| {
                observed.push(
                    event
                        .outcome
                        .map(|result| {
                            result
                                .rows
                                .rows()
                                .next()
                                .unwrap()
                                .unwrap()
                                .decoder()
                                .decode_next::<i32>()
                                .unwrap()
                        })
                        .map_err(|error| error.code().to_owned()),
                );
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(observed, [Ok(50), Err("22012".to_owned()), Ok(25)]);
        assert_eq!(
            (
                completion.admitted,
                completion.confirmed,
                completion.delivered,
                completion.sql_errors
            ),
            (3, 3, 3, 1)
        );
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut errors = Vec::new();
        let completion = transaction
            .query_pipeline_visit(&requests, visit_limits(), |event: ReadyBatchEvent<'_>| {
                errors.push(event.outcome.err().map(|error| error.code().to_owned()));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            errors,
            [None, Some("22012".to_owned()), Some("25P02".to_owned())]
        );
        assert_eq!(completion.sql_errors, 2);
        transaction.rollback().await.unwrap();
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
