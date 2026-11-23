//! 在成员限额与总限额下，验证结果缓冲按需增长以及跨行布局复用。
#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{DEADLINE, database_error, execution, handshake, prepare, ready, row, run};
use peer::{Peer, control, frame, invalid, result};

use compio_postgres::{
    AllocationPolicy, Error, OwnedBatch, QueryLimits, ReadyBatchEvent, ResultFormats, ReuseState,
    StatementLimits, TcpConfig, TransactionStatus,
    expert::{
        PipelineItem, PipelineLimits, PipelineRequest, TcpSession as TcpConnection, VisitLimits,
        WindowLimits, WindowParameters, WindowRequest,
    },
    types::{CodecError, Format, Parameter},
};
use std::{cell::Cell, future::Future, io::Write, ops::ControlFlow, sync::mpsc};

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

fn mixed_result(index: usize, status: u8) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    match index {
        0 => response.extend(row(&[Some(&7_i32.to_be_bytes())])),
        1 => response.extend(row(&[Some(b"ok")])),
        2 => response.extend(row(&[Some(b"")])),
        3 => {
            response.extend(row(&[Some(&9_i32.to_be_bytes())]));
            response.extend(row(&[Some(&10_i32.to_be_bytes())]));
        }
        _ => unreachable!(),
    }
    response.extend(frame(
        b'C',
        if index == 3 {
            b"SELECT 2\0"
        } else {
            b"SELECT 1\0"
        },
    ));
    response.extend(frame(b'Z', &[status]));
    response
}

fn mixed_peer(in_transaction: bool) -> Peer {
    Peer::short_queries(move |socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        let text = prepare(socket, &[], &[("t", 25, -1)])?;
        if in_transaction {
            control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        }
        for (index, statement) in [&integer, &text, &text, &integer].into_iter().enumerate() {
            execution(socket, statement, false)?;
            socket.write_all(&mixed_result(
                index,
                if in_transaction { b'T' } else { b'I' },
            ))?;
        }
        if in_transaction {
            control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        }
        peer::eof(socket)
    })
}

fn mixed_requests<'a>(
    integer: &'a compio_postgres::expert::PreparedStatement,
    text: &'a compio_postgres::expert::PreparedStatement,
) -> [PipelineRequest<'a>; 4] {
    let mut requests = [
        request(integer, &[]),
        request(text, &[]),
        request(text, &[]),
        request(integer, &[]),
    ];
    for (request, (max_rows, max_result_bytes)) in
        requests
            .iter_mut()
            .zip([(1, 64), (2, 128), (1, 8), (2, 64)])
    {
        request.limits.max_rows = max_rows;
        request.limits.max_result_bytes = max_result_bytes;
    }
    requests
}

fn observe(
    index: usize,
    batch: &OwnedBatch,
    capacities: &mut Vec<usize>,
    pointers: &mut Vec<*const u8>,
) {
    capacities.push(batch.retained_bytes());
    assert_eq!(batch.len(), if index == 3 { 2 } else { 1 });
    for (offset, row) in batch.rows().enumerate() {
        let row = row.unwrap();
        if offset == 0 {
            let field = row.fields().next().unwrap().unwrap();
            let expected = if index == 1 || index == 2 {
                Format::Text
            } else {
                Format::Binary
            };
            assert_eq!(field.format, expected);
            pointers.push(field.bytes.unwrap().as_ptr());
        }
        let mut decoder = row.decoder();
        if index == 1 || index == 2 {
            assert_eq!(
                decoder.decode_next::<&str>().unwrap(),
                if index == 1 { "ok" } else { "" }
            );
        } else {
            assert_eq!(
                decoder.decode_next::<i32>().unwrap(),
                if index == 0 {
                    7
                } else {
                    9 + i32::try_from(offset).unwrap()
                }
            );
        }
        decoder.finish().unwrap();
    }
}

#[test]
fn borrowed_visit_and_window_retarget_only_after_delivery_and_respect_smaller_limits() {
    for in_transaction in [false, true] {
        for window in [false, true] {
            for storage in [AllocationPolicy::ReserveLimit, AllocationPolicy::Grow] {
                let peer = mixed_peer(in_transaction);
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
                    let requests = mixed_requests(&integer, &text);
                    let mut capacities = Vec::new();
                    let mut pointers = Vec::new();
                    if window {
                        let mut source = requests.iter().map(|request| {
                            Ok(WindowRequest {
                                statement: request.statement,
                                parameters: WindowParameters::Borrowed(&[]),
                                limits: request.limits,
                            })
                        });
                        let limits = WindowLimits {
                            max_inflight: 2,
                            max_requests: 4,
                            max_rows: 5,
                            max_result_bytes: 128,
                            max_queued_request_bytes: 8192,
                            scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                                max_work_per_turn: std::num::NonZeroUsize::new(8).unwrap(),
                            },
                            storage,
                        };
                        let mut callback = |event: ReadyBatchEvent<'_>| {
                            let result = event.outcome.unwrap();
                            assert!(std::ptr::eq(
                                result.rows.layout(),
                                requests[event.index].statement.layout()
                            ));
                            observe(event.index, result.rows, &mut capacities, &mut pointers);
                            Ok(ControlFlow::Continue(()))
                        };
                        if in_transaction {
                            let mut transaction = connection.begin_transaction().await.unwrap();
                            let completed = transaction
                                .query_window(
                                    &mut source,
                                    limits,
                                    compio_postgres::OnError::RecoverExplicitly,
                                    &mut callback,
                                )
                                .await
                                .unwrap();
                            assert_eq!((completed.confirmed, completed.delivered), (4, 4));
                            assert_eq!(
                                completed.transaction_status,
                                TransactionStatus::InTransaction
                            );
                            transaction.rollback().await.unwrap();
                        } else {
                            let completed = connection
                                .query_window(
                                    &mut source,
                                    limits,
                                    compio_postgres::OnError::RecoverExplicitly,
                                    &mut callback,
                                )
                                .await
                                .unwrap();
                            assert_eq!((completed.confirmed, completed.delivered), (4, 4));
                        }
                    } else {
                        let limits = VisitLimits {
                            max_requests: 4,
                            max_rows: 5,
                            max_result_bytes: 128,
                            storage,
                            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                        };
                        let mut callback = |event: ReadyBatchEvent<'_>| {
                            let result = event.outcome.unwrap();
                            assert!(std::ptr::eq(
                                result.rows.layout(),
                                requests[event.index].statement.layout()
                            ));
                            observe(event.index, result.rows, &mut capacities, &mut pointers);
                            Ok(())
                        };
                        if in_transaction {
                            let mut transaction = connection.begin_transaction().await.unwrap();
                            let completed = transaction
                                .query_pipeline_visit(&requests, limits, &mut callback)
                                .await
                                .unwrap();
                            assert_eq!((completed.confirmed, completed.delivered), (4, 4));
                            assert_eq!(
                                completed.transaction_status,
                                TransactionStatus::InTransaction
                            );
                            transaction.rollback().await.unwrap();
                        } else {
                            let completed = connection
                                .query_pipeline_visit(&requests, limits, &mut callback)
                                .await
                                .unwrap();
                            assert_eq!((completed.confirmed, completed.delivered), (4, 4));
                        }
                    }
                    match storage {
                        AllocationPolicy::ReserveLimit => assert_eq!(capacities, [64, 128, 8, 64]),
                        AllocationPolicy::Grow => {
                            assert_eq!(capacities, [12, 12, 8, 32]);
                            // 前一次借用结束后，即使布局不同、请求限额变大，也能复用同一块内存。
                            assert_eq!(pointers[0], pointers[1]);
                        }
                    }
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    connection.discard();
                });
                peer.finish();
            }
        }
    }
}

#[test]
fn owning_pipeline_charges_actual_arenas_and_preserves_completed_results_at_the_total_limit() {
    for in_transaction in [false, true] {
        let peer = mixed_peer(in_transaction);
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
            let requests = mixed_requests(&integer, &text);
            let slots = requests.len() * std::mem::size_of::<PipelineItem>();
            let limits = PipelineLimits {
                max_requests: 4,
                max_rows: 5,
                max_result_bytes: slots + 54,
                storage: AllocationPolicy::Grow,
                scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
            };
            let results = if in_transaction {
                let mut transaction = connection.begin_transaction().await.unwrap();
                let results = transaction.query_pipeline(&requests, limits).await.unwrap();
                transaction.rollback().await.unwrap();
                results
            } else {
                connection.query_pipeline(&requests, limits).await.unwrap()
            };
            let mut capacities = Vec::new();
            let mut pointers = Vec::new();
            for (index, result) in results.iter().enumerate() {
                observe(
                    index,
                    &result.as_ref().unwrap().rows,
                    &mut capacities,
                    &mut pointers,
                );
            }
            assert_eq!(capacities, [12, 10, 8, 24]);
            assert_eq!(
                capacities.iter().sum::<usize>()
                    + results.capacity() * std::mem::size_of::<PipelineItem>(),
                limits.max_result_bytes
            );
            assert_ne!(pointers[0], pointers[1]);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.discard();
        });
        peer.finish();
    }
    let peer = mixed_peer(false);
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
        let requests = mixed_requests(&integer, &text);
        let error = connection
            .query_pipeline(
                &requests,
                PipelineLimits {
                    max_requests: 4,
                    max_rows: 5,
                    max_result_bytes: requests.len() * std::mem::size_of::<PipelineItem>() + 53,
                    storage: AllocationPolicy::Grow,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.completed.len(), 3);
        assert!(
            matches!(&error.source, Error::Limit(_))
                || matches!(&error.source, Error::Codec(error) if matches!(error.as_ref(), CodecError::Limit(_)))
        );
        assert!(error.may_have_executed);
        let mut capacities = Vec::new();
        let mut pointers = Vec::new();
        for (index, result) in error.completed.iter().enumerate() {
            observe(
                index,
                &result.as_ref().unwrap().rows,
                &mut capacities,
                &mut pointers,
            );
        }
        assert_eq!(capacities, [12, 10, 8]);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn growth_cannot_bypass_a_smaller_member_bound_after_retargeting() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        let text = prepare(socket, &[], &[("t", 25, -1)])?;
        execution(socket, &integer, false)?;
        socket.write_all(&result(7, b'I'))?;
        execution(socket, &text, false)?;
        socket.write_all(&mixed_result(1, b'I'))?;
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
        let mut requests = [request(&integer, &[]), request(&text, &[])];
        requests[0].limits.max_result_bytes = 64;
        requests[1].limits.max_result_bytes = 8;
        let mut delivered = 0;
        let error = connection
            .query_pipeline_visit(
                &requests,
                VisitLimits {
                    storage: AllocationPolicy::Grow,
                    ..visit_limits()
                },
                |event| {
                    assert_eq!(event.index, 0);
                    assert_eq!(event.outcome.unwrap().rows.retained_bytes(), 12);
                    delivered += 1;
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert_eq!((delivered, error.confirmed, error.delivered), (1, 1, 1));
        assert!(matches!(error.source, Error::Limit(_)));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn a_sql_error_releases_tentative_rows_before_diagnostic_and_the_next_layout() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        let text = prepare(socket, &[], &[("t", 25, -1)])?;
        execution(socket, &integer, false)?;
        socket.write_all(&result(7, b'I'))?;
        execution(socket, &text, false)?;
        let mut failure = frame(b'2', &[]);
        failure.extend(row(&[Some(b"discard me")]));
        failure.extend(database_error("ERROR", "22012", "division by zero"));
        failure.extend(ready());
        socket.write_all(&failure)?;
        execution(socket, &integer, false)?;
        socket.write_all(&result(9, b'I'))?;
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
        ];
        let diagnostic_bytes = std::mem::size_of::<compio_postgres::DatabaseError>()
            + database_error("ERROR", "22012", "division by zero").len()
            - 5;
        for request in &mut requests {
            request.limits.max_result_bytes = diagnostic_bytes;
        }
        let mut values = Vec::new();
        let completion = connection
            .query_pipeline_visit(
                &requests,
                VisitLimits {
                    storage: AllocationPolicy::Grow,
                    max_result_bytes: diagnostic_bytes,
                    ..visit_limits()
                },
                |event| {
                    match event.outcome {
                        Ok(result) => {
                            assert_eq!(result.rows.len(), 1);
                            assert_eq!(result.rows.retained_bytes(), 12);
                            values.push(
                                result
                                    .rows
                                    .rows()
                                    .next()
                                    .unwrap()
                                    .unwrap()
                                    .decoder()
                                    .decode_next::<i32>()?,
                            );
                        }
                        Err(error) => {
                            assert_eq!(event.index, 1);
                            assert_eq!(error.code(), "22012");
                        }
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(values, [7, 9]);
        assert_eq!(
            (
                completion.confirmed,
                completion.delivered,
                completion.sql_errors
            ),
            (3, 3, 1)
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn an_empty_zero_budget_member_retires_the_previous_arena() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        execution(socket, &integer, false)?;
        socket.write_all(&result(7, b'I'))?;
        execution(socket, &integer, false)?;
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'C', b"SELECT 0\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        execution(socket, &integer, false)?;
        socket.write_all(&result(9, b'I'))?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT n", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut requests = [
            request(&statement, &[]),
            request(&statement, &[]),
            request(&statement, &[]),
        ];
        requests[1].limits.max_rows = 0;
        requests[1].limits.max_result_bytes = 0;
        let mut capacities = Vec::new();
        let mut values = Vec::new();
        let completion = connection
            .query_pipeline_visit(
                &requests,
                VisitLimits {
                    storage: AllocationPolicy::Grow,
                    ..visit_limits()
                },
                |event| {
                    let result = event.outcome.unwrap();
                    capacities.push(result.rows.retained_bytes());
                    assert!(std::ptr::eq(result.rows.layout(), statement.layout()));
                    for row in result.rows.rows() {
                        values.push(row?.decoder().decode_next::<i32>()?);
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(capacities, [12, 0, 12]);
        assert_eq!(values, [7, 9]);
        assert_eq!((completion.confirmed, completion.delivered), (3, 3));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn dropping_a_growing_visit_keeps_only_protocol_recovery_and_never_repeats_delivery() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let integer = prepare(socket, &[], &[("n", 23, 4)])?;
        let text = prepare(socket, &[], &[("t", 25, -1)])?;
        execution(socket, &integer, false)?;
        execution(socket, &text, false)?;
        let mut response = result(7, b'I');
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(b"ok")]));
        socket.write_all(&response)?;
        wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
        let mut response = frame(b'C', b"SELECT 1\0");
        response.extend(ready());
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
        let requests = [request(&integer, &[]), request(&text, &[])];
        let delivered = Cell::new(0);
        let mut future = Box::pin(connection.query_pipeline_visit(
            &requests,
            VisitLimits {
                storage: AllocationPolicy::Grow,
                ..visit_limits()
            },
            |event| {
                assert_eq!(event.index, 0);
                let result = event.outcome.unwrap();
                assert_eq!(result.rows.retained_bytes(), 12);
                assert_eq!(
                    result
                        .rows
                        .rows()
                        .next()
                        .unwrap()
                        .unwrap()
                        .decoder()
                        .decode_next::<i32>()?,
                    7
                );
                delivered.set(delivered.get() + 1);
                Ok(())
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            if delivered.get() == 1 {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        drop(future);
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        release.send(()).unwrap();
        connection
            .recover_to_ready_with_limits(1, 64)
            .await
            .unwrap();
        assert_eq!(delivered.get(), 1);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}
