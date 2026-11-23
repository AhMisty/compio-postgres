//! 每项独立 Sync 的借用窗口。回调收到的行先于最终确认。
#[path = "support/peer.rs"]
mod peer;

use std::{
    cell::{Cell, RefCell},
    future::Future,
    io::{self, Write},
    panic::AssertUnwindSafe,
    sync::mpsc,
    task::Poll,
};

use compio_postgres::{
    AbandonPolicy, BatchControl, BatchErrorOrigin, BatchEvent, BatchProgress, CommandKind, Error,
    ExecutionScheduling, QueryLimits, ResultFormats, ReuseState, StatementLimits,
    TransactionStatus, WireTransport,
    expert::{
        PreparedStatement, ProvisionalWindowConsumeEvent, ProvisionalWindowError,
        ProvisionalWindowLimits, Session, TcpSession as TcpConnection, WindowParameters,
        WindowRequest,
    },
    types::{Format, Oid, Parameter},
};
use futures_util::FutureExt;
use peer::{
    Peer, close_statement, control, eof, execution, frame, handshake, prepare, ready, result, row,
    run, sql_error,
};

#[derive(Clone, Copy, Debug)]
enum Delivery {
    Checked,
    Consume,
}

#[derive(Debug, PartialEq, Eq)]
enum Observed {
    Row(usize, i32),
    Command(usize, CommandKind),
    Ready(usize, TransactionStatus, Option<String>),
}

fn limits(requests: usize, inflight: usize, abandon: AbandonPolicy) -> ProvisionalWindowLimits {
    ProvisionalWindowLimits {
        max_inflight: inflight,
        max_requests: requests,
        max_rows: requests.saturating_mul(1024),
        max_row_bytes: 64 * 1024,
        max_queued_request_bytes: 1024,
        max_diagnostic_bytes: 4096,
        scheduling: ExecutionScheduling::Uninterrupted,
        abandon,
    }
}

async fn connect(peer: &Peer, parameter_oids: &[Oid]) -> (TcpConnection, PreparedStatement) {
    let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
    connection
        .configure_statements(StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 32 * 1024,
        })
        .unwrap();
    let statement = connection
        .prepare(
            "SELECT $1::int4",
            parameter_oids,
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap();
    (connection, statement)
}

fn request(statement: &PreparedStatement, value: i32) -> Result<WindowRequest<'_>, Error> {
    Ok(WindowRequest {
        statement,
        parameters: WindowParameters::One(Parameter::int4(value)),
        limits: peer::query_limits(),
    })
}

async fn execute<'input, T: WireTransport>(
    connection: &mut Session<T>,
    source: &mut dyn Iterator<Item = Result<WindowRequest<'input>, Error>>,
    limits: ProvisionalWindowLimits,
    delivery: Delivery,
    observe: &mut dyn FnMut(Observed) -> Result<BatchControl, Error>,
) -> Result<BatchProgress, ProvisionalWindowError> {
    match delivery {
        Delivery::Checked => {
            connection
                .query_window_provisional_visit(source, limits, &mut |event| {
                    let observed = match event {
                        BatchEvent::Row { index, row } => {
                            let mut decoder = row.decoder();
                            let value = decoder.decode_next::<i32>()?;
                            decoder.finish()?;
                            Observed::Row(index, value)
                        }
                        BatchEvent::Command { index, command, .. } => {
                            Observed::Command(index, command)
                        }
                        BatchEvent::Ready {
                            index,
                            transaction_status,
                            outcome,
                        } => Observed::Ready(
                            index,
                            transaction_status,
                            outcome.err().map(|error| error.code().to_owned()),
                        ),
                    };
                    observe(observed)
                })
                .await
        }
        Delivery::Consume => {
            connection
                .query_window_provisional_consume(source, limits, &mut |event| {
                    let observed = match event {
                        ProvisionalWindowConsumeEvent::Row { index, row } => {
                            Observed::Row(index, row.decode_next::<i32>()?)
                        }
                        ProvisionalWindowConsumeEvent::Command { index, command, .. } => {
                            Observed::Command(index, command)
                        }
                        ProvisionalWindowConsumeEvent::Ready {
                            index,
                            transaction_status,
                            outcome,
                        } => Observed::Ready(
                            index,
                            transaction_status,
                            outcome.err().map(|error| error.code().to_owned()),
                        ),
                    };
                    observe(observed)
                })
                .await
        }
    }
}

#[test]
fn independent_syncs_keep_success_sql_error_and_later_success_in_input_order() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for delivery in [Delivery::Checked, Delivery::Consume] {
            let peer = Peer::start(|socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                for _ in 0..3 {
                    execution(socket, &statement)?;
                }
                let mut bytes = result(11, b'I');
                bytes.extend(sql_error("22012", b'I'));
                bytes.extend(result(13, b'I'));
                socket.write_all(&bytes)?;
                close_statement(socket, &statement)?;
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut source = (11..14).map(|value| request(&statement, value));
                let mut observed = Vec::new();
                let completed = execute(
                    &mut connection,
                    &mut source,
                    limits(3, 3, abandon),
                    delivery,
                    &mut |event| {
                        observed.push(event);
                        Ok(BatchControl::Continue)
                    },
                )
                .await
                .unwrap();
                assert_eq!(
                    (
                        completed.admitted,
                        completed.confirmed,
                        completed.rows_delivered,
                        completed.sql_errors
                    ),
                    (3, 3, 2, 1)
                );
                assert_eq!(completed.events_delivered, 7);
                assert_eq!(
                    observed,
                    [
                        Observed::Row(0, 11),
                        Observed::Command(0, CommandKind::Select),
                        Observed::Ready(0, TransactionStatus::Idle, None),
                        Observed::Ready(1, TransactionStatus::Idle, Some("22012".to_owned())),
                        Observed::Row(2, 13),
                        Observed::Command(2, CommandKind::Select),
                        Observed::Ready(2, TransactionStatus::Idle, None),
                    ]
                );
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                connection.close_prepared(&statement).await.unwrap();
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn both_windows_recheck_a_measured_member_after_schema_invalidation() {
    use compio_postgres::{AllocationPolicy, expert::WindowLimits};
    use std::ops::ControlFlow;

    for provisional in [false, true] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            let mut response = result(1, b'I');
            let boundary = response.split_off(response.len() - ready(b'I').len());
            response.extend(frame(b'S', b"search_path\0changed\0"));
            response.extend(boundary);
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
            let consumed = Cell::new(0);
            let mut source = (1..=2).map(|value| {
                consumed.set(consumed.get() + 1);
                request(&statement, value)
            });
            // 64 字节能暂存一个成员。第二项会在第一项 Ready 前读入并计算长度。
            let source_error = if provisional {
                let selected = ProvisionalWindowLimits {
                    max_queued_request_bytes: 64,
                    ..limits(2, 2, AbandonPolicy::RecoverExplicitly)
                };
                let error = execute(
                    &mut connection,
                    &mut source,
                    selected,
                    Delivery::Checked,
                    &mut |event| {
                        assert_eq!(consumed.get(), 2);
                        assert!(matches!(
                            event,
                            Observed::Row(0, _)
                                | Observed::Command(0, _)
                                | Observed::Ready(0, _, _)
                        ));
                        Ok(BatchControl::Continue)
                    },
                )
                .await
                .unwrap_err();
                assert_eq!(
                    (
                        error.progress.consumed,
                        error.progress.admitted,
                        error.progress.confirmed
                    ),
                    (2, 1, 1)
                );
                error.source
            } else {
                let error = connection
                    .query_window(
                        &mut source,
                        WindowLimits {
                            max_inflight: 2,
                            max_requests: 2,
                            max_rows: 2,
                            max_result_bytes: peer::query_limits().max_result_bytes,
                            storage: AllocationPolicy::Grow,
                            max_queued_request_bytes: 64,
                            scheduling: ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::OnError::RecoverExplicitly,
                        &mut |event| {
                            assert_eq!(consumed.get(), 2);
                            assert_eq!(event.index, 0);
                            Ok(ControlFlow::Continue(()))
                        },
                    )
                    .await
                    .unwrap_err();
                assert_eq!((error.admitted, error.confirmed), (1, 1));
                error.source
            };
            assert!(matches!(
                source_error,
                Error::InvalidInput(
                    "statement metadata was invalidated; close and prepare it again"
                )
            ));
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn stop_admission_still_delivers_every_already_admitted_member() {
    for delivery in [Delivery::Checked, Delivery::Consume] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            execution(socket, &statement)?;
            let mut bytes = result(1, b'I');
            bytes.extend(result(2, b'I'));
            socket.write_all(&bytes)?;
            close_statement(socket, &statement)?;
            eof(socket)
        });
        run(async {
            let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
            let examined = Cell::new(0);
            let mut source = (1..=100).map(|value| {
                examined.set(examined.get() + 1);
                request(&statement, value)
            });
            let mut rows = Vec::new();
            let completed = execute(
                &mut connection,
                &mut source,
                limits(100, 2, AbandonPolicy::RecoverExplicitly),
                delivery,
                &mut |event| {
                    if let Observed::Row(index, value) = event {
                        rows.push((index, value));
                        return Ok(BatchControl::StopAdmission);
                    }
                    Ok(BatchControl::Continue)
                },
            )
            .await
            .unwrap();
            assert_eq!(rows, [(0, 1), (1, 2)]);
            assert_eq!(
                (completed.admitted, completed.confirmed, examined.get()),
                (2, 2, 2)
            );
            assert!(completed.stopped);
            assert!(!completed.aborted);
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn callback_io_error_has_callback_origin_and_only_recover_policy_can_drain_it() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for delivery in [Delivery::Checked, Delivery::Consume] {
            let recover = matches!(abandon, AbandonPolicy::RecoverExplicitly);
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                for _ in 0..2 {
                    execution(socket, &statement)?;
                }
                let mut bytes = result(7, b'I');
                bytes.extend(result(8, b'I'));
                socket.write_all(&bytes)?;
                if recover {
                    close_statement(socket, &statement)?;
                }
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let examined = Cell::new(0);
                let callbacks = Cell::new(0);
                let mut source = (7..100).map(|value| {
                    examined.set(examined.get() + 1);
                    request(&statement, value)
                });
                let error = execute(
                    &mut connection,
                    &mut source,
                    limits(100, 2, abandon),
                    delivery,
                    &mut |_| {
                        callbacks.set(callbacks.get() + 1);
                        Err(io::Error::other("caller callback I/O failure").into())
                    },
                )
                .await
                .unwrap_err();
                assert!(matches!(error.origin, BatchErrorOrigin::Callback));
                assert!(
                    matches!(error.source, Error::Io(ref error) if error.kind()==io::ErrorKind::Other)
                );
                assert!(error.may_have_executed);
                assert_eq!((examined.get(), callbacks.get()), (2, 1));
                if recover {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready().await.unwrap();
                    assert_eq!((examined.get(), callbacks.get()), (2, 1));
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    connection.close_prepared(&statement).await.unwrap();
                } else {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                    assert!(connection.recover_to_ready().await.is_err());
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn panics_before_admission_keep_the_connection_and_result_panics_discard_it() {
    for delivery in [Delivery::Checked, Delivery::Consume] {
        for phase in 0..4 {
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                if phase == 0 {
                    close_statement(socket, &statement)?;
                } else {
                    execution(socket, &statement)?;
                    socket.write_all(&result(1, b'I'))?;
                }
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut source = std::iter::once_with(|| {
                    assert_ne!(phase, 0, "injected source panic");
                    request(&statement, 1)
                });
                let mut callback = |event| {
                    let chosen = matches!(
                        (&event, phase),
                        (Observed::Row(..), 1)
                            | (Observed::Command(..), 2)
                            | (Observed::Ready(..), 3)
                    );
                    assert!(!chosen, "injected provisional callback panic");
                    Ok(BatchControl::Continue)
                };
                let outcome = AssertUnwindSafe(execute(
                    &mut connection,
                    &mut source,
                    limits(1, 1, AbandonPolicy::RecoverExplicitly),
                    delivery,
                    &mut callback,
                ))
                .catch_unwind()
                .await;
                assert!(outcome.is_err());
                if phase == 0 {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    connection.close_prepared(&statement).await.unwrap();
                } else {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                    assert!(connection.recover_to_ready().await.is_err());
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn abort_returns_progress_without_draining_and_recovery_never_replays_callbacks() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for delivery in [Delivery::Checked, Delivery::Consume] {
            let recover = matches!(abandon, AbandonPolicy::RecoverExplicitly);
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                execution(socket, &statement)?;
                execution(socket, &statement)?;
                let mut bytes = result(1, b'I');
                bytes.extend(result(2, b'I'));
                socket.write_all(&bytes)?;
                if recover {
                    close_statement(socket, &statement)?;
                }
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let examined = Cell::new(0);
                let callbacks = Cell::new(0);
                let mut source = (1..100).map(|value| {
                    examined.set(examined.get() + 1);
                    request(&statement, value)
                });
                let completed = execute(
                    &mut connection,
                    &mut source,
                    limits(100, 2, abandon),
                    delivery,
                    &mut |event| {
                        assert!(matches!(event, Observed::Row(0, 1)));
                        callbacks.set(callbacks.get() + 1);
                        Ok(BatchControl::Abort)
                    },
                )
                .await
                .unwrap();
                assert!(completed.aborted);
                assert_eq!((completed.admitted, completed.confirmed), (2, 0));
                assert_eq!((examined.get(), callbacks.get()), (2, 1));
                if recover {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection
                        .recover_to_ready_with_limits(4, 64)
                        .await
                        .unwrap();
                    assert_eq!((examined.get(), callbacks.get()), (2, 1));
                    connection.close_prepared(&statement).await.unwrap();
                } else {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn dropping_or_forgetting_after_a_provisional_command_preserves_only_admitted_work() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for delivery in [Delivery::Checked, Delivery::Consume] {
            for forget in [false, true] {
                let recover = matches!(abandon, AbandonPolicy::RecoverExplicitly);
                let (release, allowed) = mpsc::channel();
                let peer = Peer::start(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    execution(socket, &statement)?;
                    execution(socket, &statement)?;
                    let first = result(1, b'I');
                    socket.write_all(&first[..first.len() - 6])?;
                    allowed
                        .recv_timeout(peer::DEADLINE)
                        .map_err(|_| peer::invalid())?;
                    if recover {
                        let mut rest = ready(b'I');
                        rest.extend(result(2, b'I'));
                        socket.write_all(&rest)?;
                        close_statement(socket, &statement)?;
                    }
                    eof(socket)
                });
                run(async {
                    let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                    let examined = Cell::new(0);
                    let observed = RefCell::new(Vec::new());
                    let saw_command = Cell::new(false);
                    let mut source = (1..100).map(|value| {
                        examined.set(examined.get() + 1);
                        request(&statement, value)
                    });
                    let mut callback = |event| {
                        if matches!(event, Observed::Command(0, _)) {
                            saw_command.set(true);
                        }
                        observed.borrow_mut().push(event);
                        Ok(BatchControl::Continue)
                    };
                    let mut future = Box::pin(execute(
                        &mut connection,
                        &mut source,
                        limits(100, 2, abandon),
                        delivery,
                        &mut callback,
                    ));
                    std::future::poll_fn(|cx| {
                        assert!(future.as_mut().poll(cx).is_pending());
                        if saw_command.get() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    if forget {
                        std::mem::forget(future);
                    } else {
                        drop(future);
                    }
                    assert_eq!(examined.get(), 2);
                    assert_eq!(
                        *observed.borrow(),
                        [
                            Observed::Row(0, 1),
                            Observed::Command(0, CommandKind::Select)
                        ]
                    );
                    release.send(()).unwrap();
                    if recover {
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        connection.recover_to_ready().await.unwrap();
                        assert_eq!(examined.get(), 2);
                        assert_eq!(observed.borrow().len(), 2);
                        connection.close_prepared(&statement).await.unwrap();
                    } else {
                        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                        assert!(connection.recover_to_ready().await.is_err());
                    }
                    connection.close_local().await.unwrap();
                });
                peer.finish();
            }
        }
    }
}

#[test]
fn encoding_checkpoint_drop_never_enqueues_the_private_prefix_under_either_policy() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for forget in [false, true] {
            let peer = Peer::start(|socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                close_statement(socket, &statement)?;
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let examined = Cell::new(0);
                let mut source = (1..100).map(|value| {
                    examined.set(examined.get() + 1);
                    request(&statement, value)
                });
                let mut callback = |_| panic!("no wire request has been admitted");
                let mut selected = limits(100, 2, abandon);
                selected.scheduling = ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                };
                let mut future = Box::pin(execute(
                    &mut connection,
                    &mut source,
                    selected,
                    Delivery::Checked,
                    &mut callback,
                ));
                std::future::poll_fn(|cx| {
                    assert!(future.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(examined.get(), 1);
                if forget {
                    std::mem::forget(future);
                } else {
                    drop(future);
                }
                assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                connection.recover_to_ready_with_limits(0, 0).await.unwrap();
                assert_eq!(examined.get(), 1);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                connection.close_prepared(&statement).await.unwrap();
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn abort_at_the_last_ready_keeps_an_explicit_harvest_obligation() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for delivery in [Delivery::Checked, Delivery::Consume] {
            let recover = matches!(abandon, AbandonPolicy::RecoverExplicitly);
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                execution(socket, &statement)?;
                socket.write_all(&result(9, b'I'))?;
                if recover {
                    close_statement(socket, &statement)?;
                }
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut source = std::iter::once(request(&statement, 9));
                let callbacks = Cell::new(0);
                let mut selected = limits(1, 1, abandon);
                selected.scheduling = ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                };
                let completed = execute(
                    &mut connection,
                    &mut source,
                    selected,
                    delivery,
                    &mut |event| {
                        callbacks.set(callbacks.get() + 1);
                        Ok(if matches!(event, Observed::Ready(0, _, _)) {
                            BatchControl::Abort
                        } else {
                            BatchControl::Continue
                        })
                    },
                )
                .await
                .unwrap();
                assert!(completed.aborted);
                assert_eq!(
                    (completed.admitted, completed.confirmed, callbacks.get()),
                    (1, 1, 3)
                );
                if recover {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready_with_limits(0, 0).await.unwrap();
                    assert_eq!(callbacks.get(), 3);
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    connection.close_prepared(&statement).await.unwrap();
                } else {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn local_source_failure_before_handoff_is_idle_and_cannot_be_mistaken_for_transport_io() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            close_statement(socket, &statement)?;
            eof(socket)
        });
        run(async {
            let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
            let mut source =
                std::iter::once(Err(io::Error::other("source callback failed").into()));
            let error = execute(
                &mut connection,
                &mut source,
                limits(1, 1, abandon),
                Delivery::Checked,
                &mut |_| panic!("no callback before admission"),
            )
            .await
            .unwrap_err();
            assert!(matches!(error.origin, BatchErrorOrigin::Input));
            assert!(!error.may_have_executed);
            assert_eq!(error.progress.consumed, 1);
            assert_eq!(error.progress.admitted, 0);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn invalid_limits_do_not_observe_the_source_or_poison_an_idle_connection() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let examined = Cell::new(0);
        let valid = limits(1, 1, AbandonPolicy::RecoverExplicitly);
        for selected in [
            ProvisionalWindowLimits {
                max_queued_request_bytes: 0,
                ..valid
            },
            ProvisionalWindowLimits {
                max_queued_request_bytes: 9 * 1024 * 1024,
                ..valid
            },
            ProvisionalWindowLimits {
                max_inflight: 0,
                ..valid
            },
        ] {
            let mut source = std::iter::once_with(|| {
                examined.set(examined.get() + 1);
                request(&statement, 1)
            });
            let error = execute(
                &mut connection,
                &mut source,
                selected,
                Delivery::Checked,
                &mut |_| panic!("invalid limits cannot produce events"),
            )
            .await
            .unwrap_err();
            assert!(matches!(error.origin, BatchErrorOrigin::Input));
            assert!(!error.may_have_executed);
            assert_eq!(examined.get(), 0);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_late_source_error_keeps_only_the_previously_admitted_prefix_recoverable() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(1, b'I'))?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let examined = Cell::new(0);
        let callbacks = Cell::new(0);
        let mut source = std::iter::from_fn(|| {
            examined.set(examined.get() + 1);
            Some(if examined.get() == 1 {
                request(&statement, 1)
            } else {
                Err(Error::InvalidInput("late source error"))
            })
        });
        let error = execute(
            &mut connection,
            &mut source,
            limits(10, 1, AbandonPolicy::RecoverExplicitly),
            Delivery::Checked,
            &mut |_| {
                callbacks.set(callbacks.get() + 1);
                Ok(BatchControl::Continue)
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error.origin, BatchErrorOrigin::Input));
        assert_eq!(
            (
                error.progress.admitted,
                error.progress.confirmed,
                examined.get(),
                callbacks.get()
            ),
            (1, 1, 2, 3)
        );
        assert_eq!(error.progress.consumed, examined.get());
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        connection.recover_to_ready_with_limits(0, 0).await.unwrap();
        assert_eq!((examined.get(), callbacks.get()), (2, 3));
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_sync_error_after_a_provisional_command_invalidates_only_that_member() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let first = result(1, b'I');
        let mut bytes = first[..first.len() - 6].to_vec();
        bytes.extend(sql_error("40001", b'I'));
        bytes.extend(result(2, b'I'));
        socket.write_all(&bytes)?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let mut source = (1..=2).map(|value| request(&statement, value));
        let mut observed = Vec::new();
        let completed = execute(
            &mut connection,
            &mut source,
            limits(2, 2, AbandonPolicy::RecoverExplicitly),
            Delivery::Checked,
            &mut |event| {
                observed.push(event);
                Ok(BatchControl::Continue)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            (
                completed.confirmed,
                completed.rows_delivered,
                completed.sql_errors
            ),
            (2, 2, 1)
        );
        assert_eq!(
            observed,
            [
                Observed::Row(0, 1),
                Observed::Command(0, CommandKind::Select),
                Observed::Ready(0, TransactionStatus::Idle, Some("40001".to_owned())),
                Observed::Row(1, 2),
                Observed::Command(1, CommandKind::Select),
                Observed::Ready(1, TransactionStatus::Idle, None)
            ]
        );
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_busy_borrowed_window_attempt_cannot_erase_an_abandoned_query() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(7, b'I'))?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let query = connection
            .query(
                &statement,
                &[Parameter::int4(7)],
                compio_postgres::QueryOptions {
                    limits: peer::query_limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        drop(query);
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        let examined = Cell::new(0);
        let mut source = std::iter::once_with(|| {
            examined.set(examined.get() + 1);
            request(&statement, 99)
        });
        let error = execute(
            &mut connection,
            &mut source,
            limits(1, 1, AbandonPolicy::DiscardOnAbandon),
            Delivery::Checked,
            &mut |_| panic!("busy operation cannot call callbacks"),
        )
        .await
        .unwrap_err();
        assert!(matches!(error.origin, BatchErrorOrigin::Input));
        assert!(matches!(error.source, Error::Busy));
        assert_eq!(examined.get(), 0);
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        connection.recover_to_ready().await.unwrap();
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn fatal_server_diagnostic_is_terminal_and_uses_the_connection_frame_bound() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&frame(b'E', b"SFATAL\0C57P01\0Mfixture termination\0\0"))?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let mut source = std::iter::once(request(&statement, 1));
        let mut selected = limits(1, 1, AbandonPolicy::RecoverExplicitly);
        selected.max_diagnostic_bytes = 1;
        let error = execute(
            &mut connection,
            &mut source,
            selected,
            Delivery::Checked,
            &mut |_| panic!("fatal diagnostic is not a normal Ready outcome"),
        )
        .await
        .unwrap_err();
        assert!(matches!(error.origin, BatchErrorOrigin::Server));
        assert!(matches!(error.source,Error::Database(ref error) if error.code()=="57P01"));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn malformed_rows_do_not_hide_behind_a_callback_error_or_consumer_prefix() {
    for delivery in [Delivery::Checked, Delivery::Consume] {
        for callback_mode in 0..3 {
            let peer = Peer::start(|socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23, 25])?;
                execution(socket, &statement)?;
                let mut bad = Vec::from(2_u16.to_be_bytes());
                bad.extend_from_slice(&4_i32.to_be_bytes());
                bad.extend_from_slice(&1_i32.to_be_bytes());
                bad.extend_from_slice(&(-2_i32).to_be_bytes());
                let mut bytes = frame(b'2', &[]);
                bytes.extend(frame(b'D', &bad));
                socket.write_all(&bytes)?;
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut source = std::iter::once(request(&statement, 1));
                let observed = Cell::new(0);
                let selected = limits(1, 1, AbandonPolicy::RecoverExplicitly);
                let error = match delivery {
                    Delivery::Checked => connection
                        .query_window_provisional_visit(&mut source, selected, &mut |_| {
                            observed.set(observed.get() + 1);
                            if callback_mode == 2 {
                                Err(io::Error::other("callback failed").into())
                            } else {
                                Ok(if callback_mode == 1 {
                                    BatchControl::Abort
                                } else {
                                    BatchControl::Continue
                                })
                            }
                        })
                        .await
                        .unwrap_err(),
                    Delivery::Consume => connection
                        .query_window_provisional_consume(&mut source, selected, &mut |event| {
                            if let ProvisionalWindowConsumeEvent::Row { row, .. } = event {
                                assert_eq!(row.decode_next::<i32>()?, 1);
                                observed.set(observed.get() + 1);
                                if callback_mode == 2 {
                                    return Err(io::Error::other("callback failed").into());
                                }
                            }
                            Ok(if callback_mode == 1 {
                                BatchControl::Abort
                            } else {
                                BatchControl::Continue
                            })
                        })
                        .await
                        .unwrap_err(),
                };
                assert_eq!(
                    observed.get(),
                    if matches!(delivery, Delivery::Checked) {
                        0
                    } else {
                        1
                    }
                );
                assert!(matches!(
                    error.origin,
                    BatchErrorOrigin::Protocol | BatchErrorOrigin::Validation
                ));
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                assert!(connection.recover_to_ready().await.is_err());
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn ignored_consumer_decode_failure_is_sticky_and_terminal() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        let mut bytes = frame(b'2', &[]);
        bytes.extend(row(&[Some(&[1, 2, 3])]));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let mut source = std::iter::once(request(&statement, 1));
        let observed = Cell::new(0);
        let error = connection
            .query_window_provisional_consume(
                &mut source,
                limits(1, 1, AbandonPolicy::RecoverExplicitly),
                &mut |event| {
                    if let ProvisionalWindowConsumeEvent::Row { row, .. } = event {
                        assert!(row.decode_next::<i32>().is_err());
                        assert_eq!(row.remaining(), 0);
                        observed.set(observed.get() + 1);
                    }
                    Ok(BatchControl::Continue)
                },
            )
            .await
            .unwrap_err();
        assert_eq!(observed.get(), 1);
        assert!(matches!(error.origin, BatchErrorOrigin::Validation));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn local_row_and_diagnostic_limits_obey_the_abandon_policy_without_publishing_rows() {
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for mode in 0..4 {
            let recover = matches!(abandon, AbandonPolicy::RecoverExplicitly);
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                execution(socket, &statement)?;
                socket.write_all(&if mode == 3 {
                    sql_error("22012", b'I')
                } else {
                    result(1, b'I')
                })?;
                if recover {
                    close_statement(socket, &statement)?;
                }
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut member = request(&statement, 1).unwrap();
                let mut selected = limits(1, 1, abandon);
                match mode {
                    0 => member.limits.max_rows = 0,
                    1 => selected.max_rows = 0,
                    2 => selected.max_row_bytes = 1,
                    _ => selected.max_diagnostic_bytes = 1,
                }
                let mut source = std::iter::once(Ok(member));
                let callbacks = Cell::new(0);
                let error = execute(
                    &mut connection,
                    &mut source,
                    selected,
                    Delivery::Checked,
                    &mut |_| {
                        callbacks.set(callbacks.get() + 1);
                        Ok(BatchControl::Continue)
                    },
                )
                .await
                .unwrap_err();
                assert!(matches!(error.origin, BatchErrorOrigin::Resource));
                assert_eq!(callbacks.get(), 0);
                if recover {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection
                        .recover_to_ready_with_limits(1, 64)
                        .await
                        .unwrap();
                    assert_eq!(callbacks.get(), 0);
                    connection.close_prepared(&statement).await.unwrap();
                } else {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn eof_preserves_confirmed_prefix_and_never_converts_the_next_command_into_ready() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let mut bytes = result(1, b'I');
        let second = result(2, b'I');
        bytes.extend(&second[..second.len() - 6]);
        socket.write_all(&bytes)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let mut source = (1..=2).map(|value| request(&statement, value));
        let mut observed = Vec::new();
        let error = execute(
            &mut connection,
            &mut source,
            limits(2, 2, AbandonPolicy::RecoverExplicitly),
            Delivery::Checked,
            &mut |event| {
                observed.push(event);
                Ok(BatchControl::Continue)
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error.origin, BatchErrorOrigin::Transport));
        assert_eq!((error.progress.admitted, error.progress.confirmed), (2, 1));
        assert_eq!(observed.len(), 5);
        assert!(matches!(
            observed.last(),
            Some(Observed::Command(1, CommandKind::Select))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn oversized_header_is_terminal_before_waiting_for_any_body() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        let mut bytes = frame(b'2', &[]);
        bytes.extend_from_slice(b"D\0\0\x20\0");
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
        let mut source = std::iter::once(request(&statement, 1));
        let error = execute(
            &mut connection,
            &mut source,
            limits(1, 1, AbandonPolicy::RecoverExplicitly),
            Delivery::Checked,
            &mut |_| panic!("invalid header must not reach a callback"),
        )
        .await
        .unwrap_err();
        assert!(matches!(error.origin, BatchErrorOrigin::Protocol));
        assert!(matches!(error.source, Error::Protocol(_)));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

async fn transaction_window_statuses<'input>(
    transaction: &mut compio_postgres::expert::SessionTransaction<'_, impl WireTransport>,
    source: &mut (impl Iterator<Item = Result<WindowRequest<'input>, Error>> + ?Sized),
    selected: ProvisionalWindowLimits,
    delivery: Delivery,
) -> (BatchProgress, Vec<(TransactionStatus, Option<String>)>) {
    let mut statuses = Vec::new();
    let completed = match delivery {
        Delivery::Checked => transaction
            .query_window_provisional_visit(source, selected, &mut |event| {
                if let BatchEvent::Ready {
                    transaction_status,
                    outcome,
                    ..
                } = event
                {
                    statuses.push((
                        transaction_status,
                        outcome.err().map(|error| error.code().to_owned()),
                    ));
                }
                Ok(BatchControl::Continue)
            })
            .await
            .unwrap(),
        Delivery::Consume => transaction
            .query_window_provisional_consume(source, selected, &mut |event| {
                if let ProvisionalWindowConsumeEvent::Ready {
                    transaction_status,
                    outcome,
                    ..
                } = event
                {
                    statuses.push((
                        transaction_status,
                        outcome.err().map(|error| error.code().to_owned()),
                    ));
                }
                Ok(BatchControl::Continue)
            })
            .await
            .unwrap(),
    };
    (completed, statuses)
}

#[test]
fn transaction_entrypoints_keep_the_lease_and_failed_successors_require_a_decision() {
    for delivery in [Delivery::Checked, Delivery::Consume] {
        for fail in [false, true] {
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
                execution(socket, &statement)?;
                execution(socket, &statement)?;
                let bytes = if fail {
                    let mut bytes = sql_error("22012", b'E');
                    bytes.extend(sql_error("25P02", b'E'));
                    bytes
                } else {
                    let mut bytes = result(1, b'T');
                    bytes.extend(result(2, b'T'));
                    bytes
                };
                socket.write_all(&bytes)?;
                if fail {
                    control(socket, b"COMMIT\0", b"ROLLBACK\0", b'I')?;
                } else {
                    control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
                }
                close_statement(socket, &statement)?;
                eof(socket)
            });
            run(async {
                let (mut connection, statement) = connect(&peer, &[Oid::INT4]).await;
                let mut transaction = connection.begin_transaction().await.unwrap();
                let examined = Cell::new(0);
                let mut source = (1..100).map(|value| {
                    examined.set(examined.get() + 1);
                    request(&statement, value)
                });
                let selected = limits(
                    if fail { 100 } else { 2 },
                    2,
                    AbandonPolicy::RecoverExplicitly,
                );
                // 两种事务入口均接受具体迭代器，也能继续驱动调用方已擦除类型的迭代器。
                let (completed, statuses) = if fail {
                    let source: &mut dyn Iterator<Item = _> = &mut source;
                    transaction_window_statuses(&mut transaction, source, selected, delivery).await
                } else {
                    transaction_window_statuses(&mut transaction, &mut source, selected, delivery)
                        .await
                };
                assert_eq!(
                    (completed.admitted, completed.confirmed, examined.get()),
                    (2, 2, 2)
                );
                assert_eq!(completed.consumed, examined.get());
                if fail {
                    assert!(completed.needs_transaction_decision);
                    assert_eq!(completed.sql_errors, 2);
                    assert_eq!(
                        statuses,
                        [
                            (TransactionStatus::FailedTransaction, Some("22012".into())),
                            (TransactionStatus::FailedTransaction, Some("25P02".into()))
                        ]
                    );
                    let end = transaction.commit().await.unwrap();
                    assert_eq!(
                        end.transaction_end,
                        Some(compio_postgres::TransactionEnd::RolledBack)
                    );
                } else {
                    assert_eq!(
                        completed.transaction_status,
                        TransactionStatus::InTransaction
                    );
                    assert_eq!(
                        statuses,
                        [
                            (TransactionStatus::InTransaction, None),
                            (TransactionStatus::InTransaction, None)
                        ]
                    );
                    transaction.rollback().await.unwrap();
                }
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                connection.close_prepared(&statement).await.unwrap();
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn a_commit_acknowledged_before_abort_survives_recovery_without_a_second_rollback() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &statement)?;
        let mut bytes = frame(b'2', &[]);
        bytes.extend(frame(b'C', b"COMMIT\0"));
        bytes.extend(ready(b'I'));
        socket.write_all(&bytes)?;
        close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        connection
            .configure_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            })
            .unwrap();
        let statement = connection
            .prepare("COMMIT", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut source = std::iter::once(Ok(WindowRequest {
            statement: &statement,
            parameters: WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 0,
                max_result_bytes: 0,
                max_metadata_bytes: 4096,
            },
        }));
        let completed = transaction
            .query_window_provisional_visit(
                &mut source,
                limits(1, 1, AbandonPolicy::RecoverExplicitly),
                &mut |event| {
                    if let BatchEvent::Command { command, .. } = event {
                        assert_eq!(command, CommandKind::Commit);
                        return Ok(BatchControl::Abort);
                    }
                    Ok(BatchControl::Continue)
                },
            )
            .await
            .unwrap();
        assert!(completed.aborted);
        assert_eq!(completed.confirmed, 0);
        drop(transaction);
        let end = connection.recover_and_rollback().await.unwrap();
        assert_eq!(
            end.transaction_end,
            Some(compio_postgres::TransactionEnd::Committed)
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn early_rows_are_delivered_before_the_peer_drains_the_large_second_request() {
    const ROWS: usize = 4096;
    const BYTES: usize = 4096;
    const INPUT: usize = 6 * 1024 * 1024;
    for delivery in [Delivery::Checked, Delivery::Consume] {
        let (first_row_seen, wait_for_row) = mpsc::channel();
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[17], &[17])?;
            execution(socket, &statement)?;
            socket.write_all(&frame(b'2', &[]))?;
            let payload = vec![b'x'; BYTES];
            let encoded = row(&[Some(&payload)]);
            for _ in 0..ROWS {
                socket.write_all(&encoded)?;
            }
            let mut completed = frame(b'C', format!("SELECT {ROWS}\0").as_bytes());
            completed.extend(ready(b'I'));
            socket.write_all(&completed)?;
            wait_for_row
                .recv_timeout(peer::DEADLINE)
                .map_err(|_| peer::invalid())?;
            // 对端先返回超过接收缓冲容量的响应，再读取第二个大请求，以验证收发可以同时推进。
            execution(socket, &statement)?;
            let mut second = frame(b'2', &[]);
            second.extend(row(&[Some(b"ok")]));
            second.extend(frame(b'C', b"SELECT 1\0"));
            second.extend(ready(b'I'));
            socket.write_all(&second)?;
            close_statement(socket, &statement)?;
            eof(socket)
        });
        run(async {
            let (mut connection, statement) = connect(&peer, &[Oid::BYTEA]).await;
            let payload = vec![1; INPUT];
            let member_limits = QueryLimits {
                max_rows: ROWS,
                max_result_bytes: 20 * 1024 * 1024,
                max_metadata_bytes: 4096,
            };
            let mut source = [
                WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::bytea(b"small")),
                    limits: member_limits,
                },
                WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::bytea(&payload)),
                    limits: member_limits,
                },
            ]
            .into_iter()
            .map(Ok);
            let mut selected = limits(2, 2, AbandonPolicy::RecoverExplicitly);
            selected.max_queued_request_bytes = 8 * 1024 * 1024;
            selected.max_rows = ROWS + 1;
            selected.max_row_bytes = 20 * 1024 * 1024;
            let observed = Cell::new(0);
            let mut signal = Some(first_row_seen);
            let mut check = |index: usize, bytes: &[u8]| {
                if index == 0 {
                    assert_eq!(bytes.len(), BYTES);
                    assert!(bytes.iter().all(|byte| *byte == b'x'));
                    if let Some(signal) = signal.take() {
                        signal.send(()).unwrap();
                    }
                } else {
                    assert_eq!(index, 1);
                    assert_eq!(bytes, b"ok");
                }
                observed.set(observed.get() + 1);
            };
            let completed = match delivery {
                Delivery::Checked => connection
                    .query_window_provisional_visit(&mut source, selected, &mut |event| {
                        if let BatchEvent::Row { index, row } = event {
                            check(index, row.decoder().decode_next::<&[u8]>()?);
                        }
                        Ok(BatchControl::Continue)
                    })
                    .await
                    .unwrap(),
                Delivery::Consume => connection
                    .query_window_provisional_consume(&mut source, selected, &mut |event| {
                        if let ProvisionalWindowConsumeEvent::Row { index, row } = event {
                            check(index, row.decode_next::<&[u8]>()?);
                        }
                        Ok(BatchControl::Continue)
                    })
                    .await
                    .unwrap(),
            };
            assert_eq!(
                (
                    completed.admitted,
                    completed.confirmed,
                    completed.rows_delivered,
                    observed.get()
                ),
                (2, 2, ROWS + 1, ROWS + 1)
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}
