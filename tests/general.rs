#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{
    DEADLINE, IO_DEADLINE, description, execution, expect, handshake, limits, preparation_response,
    prepare, read_prepare, ready, row, run,
};
use peer::{Peer, drain_until_close, frame, invalid, name};

use std::{
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::TcpStream,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
};

use compio_postgres::{
    CommandKind, Error, OnError, QueryLimits, ReadyBatchEvent, ResultFormats, StatementLimits,
    TcpConfig,
    expert::TcpSession as TcpConnection,
    types::{
        ArrayLayout, ArrayView, CompositeLayout, CompositeView, Format, MultiRangeLayout,
        MultiRangeView, Oid, Oid8, Parameter, RangeLayout, RangeView,
    },
};
use futures_util::FutureExt;

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1024,
        max_result_bytes: 64 * 1024,
        max_metadata_bytes: 16 * 1024,
    }
}

const REQUEST_OBSERVED: &[u8] = b"SNOTICE\0C00000\0Mrequest observed\0\0";

fn observe_request(config: TcpConfig) -> (TcpConfig, Arc<AtomicBool>) {
    let observed = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&observed);
    let config = config.notice_handler(move |notice| {
        assert_eq!(notice.message, "request observed");
        marker.store(true, Ordering::Relaxed);
    });
    (config, observed)
}

async fn poll_until_observed(mut pending: Pin<&mut impl Future>, observed: &AtomicBool) {
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        if observed.load(Ordering::Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
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
fn close(socket: &mut TcpStream, statement: &str) -> io::Result<()> {
    let command = expect(socket, b'C')?;
    if command.first() != Some(&b'S')
        || name(&command[1..])? != statement
        || !expect(socket, b'S')?.is_empty()
    {
        return Err(invalid());
    }
    let mut response = frame(b'3', &[]);
    response.extend(ready());
    socket.write_all(&response)
}
fn configure(connection: &mut TcpConnection, count: usize) {
    connection
        .configure_statements(StatementLimits {
            max_statements: count,
            max_metadata_bytes: 32 * 1024,
        })
        .unwrap();
}

fn window_limits(requests: usize, inflight: usize) -> compio_postgres::expert::WindowLimits {
    compio_postgres::expert::WindowLimits {
        storage: compio_postgres::AllocationPolicy::ReserveLimit,
        max_inflight: inflight,
        max_requests: requests,
        max_rows: requests.saturating_mul(1024),
        max_result_bytes: 65536,
        max_queued_request_bytes: 1024,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
        },
    }
}

fn result_value(value: i32) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    response.extend(row(&[Some(&value.to_be_bytes())]));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(ready());
    response
}

#[test]
fn continuous_window_refills_before_the_last_old_reply_and_preserves_sql_error_boundaries() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    for coalescing in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            execution(socket, &statement, false)?;
            socket.write_all(&result_value(0))?;
            // 对端要先收到下一个窗口成员，才会发送第 2 项响应。等待整批完成后才补充窗口会在这里卡住。
            execution(socket, &statement, false)?;
            socket.write_all(&frame(b'E', b"SERROR\0C22012\0Mdivision by zero\0\0"))?;
            socket.write_all(&ready())?;
            socket.write_all(&result_value(2))?;
            close(socket, &statement)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config().send_policy(if coalescing {
                compio_postgres::SendPolicy::CoalesceBuffered
            } else {
                compio_postgres::SendPolicy::BeforeBufferedRead
            }))
            .await
            .unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let mut source = (0..3).map(|value| {
                Ok(WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: query_limits(),
                })
            });
            let mut values = Vec::new();
            let mut errors = Vec::new();
            let completion = connection
                .query_window(
                    &mut source,
                    window_limits(3, 2),
                    OnError::RecoverExplicitly,
                    &mut |event: ReadyBatchEvent<'_>| {
                        match event.outcome {
                            Ok(result) => {
                                assert_eq!(result.rows.len(), 1);
                                for row in result.rows.rows() {
                                    values
                                        .push((event.index, row?.decoder().decode_next::<i32>()?));
                                }
                            }
                            Err(error) => errors.push((event.index, error.code().to_owned())),
                        }
                        Ok(std::ops::ControlFlow::Continue(()))
                    },
                )
                .await
                .unwrap();
            assert_eq!(values, vec![(0, 0), (2, 2)]);
            assert_eq!(errors, vec![(1, "22012".to_owned())]);
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
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn a_late_initial_window_error_never_submits_the_staged_prefix() {
    use compio_postgres::{
        ReuseState,
        expert::{WindowParameters, WindowRequest},
    };
    for iterator_error in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
            // 下一条前端消息必须是 Close。若先收到 Bind，表示已经发出本应拒绝的前缀。
            close(socket, &statement)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let mut source = (0..2).map(|index| {
                if index == 1 && iterator_error {
                    Err(Error::InvalidInput("late iterator error"))
                } else {
                    Ok(WindowRequest {
                        statement: &statement,
                        parameters: WindowParameters::One(if index == 1 {
                            Parameter::text(Oid::TEXT, "wrong type")
                        } else {
                            Parameter::int4(0)
                        }),
                        limits: query_limits(),
                    })
                }
            });
            let mut delivered = 0;
            let error = connection
                .query_window(
                    &mut source,
                    window_limits(2, 2),
                    OnError::Discard,
                    &mut |_| {
                        delivered += 1;
                        Ok(std::ops::ControlFlow::Continue(()))
                    },
                )
                .await
                .err()
                .unwrap();
            assert_eq!(
                (error.admitted, error.confirmed, error.delivered),
                (0, 0, 0)
            );
            assert!(!error.may_have_executed);
            assert_eq!(delivered, 0);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn a_late_refill_error_submits_only_the_previously_admitted_members() {
    use compio_postgres::{
        ReuseState,
        expert::{WindowParameters, WindowRequest},
    };
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        execution(socket, &statement, false)?;
        let mut response = result_value(0);
        response.extend(result_value(1));
        socket.write_all(&response)?;
        let mut unexpected = [0];
        match socket.read(&mut unexpected) {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let observed = std::cell::Cell::new(0);
        let mut source = (0..4).map(|index| {
            observed.set(observed.get() + 1);
            if index == 3 {
                Err(Error::InvalidInput("late refill iterator error"))
            } else {
                Ok(WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::int4(index)),
                    limits: query_limits(),
                })
            }
        });
        let mut selected = window_limits(4, 4);
        // 语句 :p1 带一个 int4 参数时占 43 字节。窗口容纳两次执行，第三次只用于预读。
        selected.max_queued_request_bytes = 100;
        let error = connection
            .query_window(&mut source, selected, OnError::Discard, &mut |_| {
                Ok(std::ops::ControlFlow::Continue(()))
            })
            .await
            .err()
            .unwrap();
        assert_eq!(
            (error.admitted, error.confirmed, error.delivered),
            (2, 1, 1)
        );
        assert!(error.may_have_executed);
        assert_eq!(observed.get(), 4);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        drop(connection);
    });
    peer.finish();
}

#[test]
fn repeated_short_windows_keep_bounded_tx_storage_until_explicit_trim() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        for _ in 0..4 {
            for value in 0..3 {
                execution(socket, &statement, false)?;
                socket.write_all(&result_value(value))?;
            }
        }
        close(socket, &statement)?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        for _ in 0..4 {
            let mut source = (0..3).map(|value| {
                Ok(WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: query_limits(),
                })
            });
            let mut selected = window_limits(3, 2);
            selected.max_queued_request_bytes = 256;
            let completion = connection
                .query_window(
                    &mut source,
                    selected,
                    OnError::RecoverExplicitly,
                    &mut |event| {
                        let rows = event.outcome.map_err(|_| Error::Broken)?.rows;
                        let value = rows
                            .rows()
                            .next()
                            .ok_or(Error::Broken)??
                            .decoder()
                            .decode_next::<i32>()?;
                        assert_eq!(value, i32::try_from(event.index).unwrap());
                        Ok(std::ops::ControlFlow::Continue(()))
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                (
                    completion.admitted,
                    completion.confirmed,
                    completion.delivered
                ),
                (3, 3, 3)
            );
        }
        // 短请求按实际编码长度增长。窗口最多保留一个待发包和一个已完成的发送包，
        // 两者都无需占满 256 字节额度。
        assert!((1..512).contains(&connection.trim_send_buffer().unwrap()));
        assert_eq!(connection.trim_send_buffer().unwrap(), 0);
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn window_break_stops_callbacks_and_drains_all_admitted_members() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    for coalescing in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            execution(socket, &statement, false)?;
            socket.write_all(&result_value(0))?;
            socket.write_all(&result_value(1))?;
            close(socket, &statement)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config().send_policy(if coalescing {
                compio_postgres::SendPolicy::CoalesceBuffered
            } else {
                compio_postgres::SendPolicy::BeforeBufferedRead
            }))
            .await
            .unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let observed = std::cell::Cell::new(0);
            let mut source = std::iter::from_fn(|| {
                let value = observed.get();
                observed.set(value + 1);
                Some(Ok(WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: query_limits(),
                }))
            });
            let mut delivered = 0;
            let completion = connection
                .query_window(
                    &mut source,
                    window_limits(10, 2),
                    OnError::RecoverExplicitly,
                    &mut |_: ReadyBatchEvent<'_>| {
                        delivered += 1;
                        Ok(std::ops::ControlFlow::Break(()))
                    },
                )
                .await
                .unwrap();
            assert_eq!(observed.get(), 2);
            assert_eq!(delivered, 1);
            assert!(completion.stopped);
            assert_eq!(completion.confirmed, 2);
            assert_eq!(completion.admitted, 2);
            assert!(connection.is_usable());
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn busy_window_admission_cannot_erase_an_abandoned_query() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_value(42))?;
        close(socket, &statement)?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        drop(
            connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap(),
        );
        let mut source = std::iter::empty();
        let error = connection
            .query_window(
                &mut source,
                window_limits(1, 1),
                OnError::RecoverExplicitly,
                &mut |_| Ok(std::ops::ControlFlow::Continue(())),
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Busy));
        assert_eq!(error.admitted, 0);
        assert_eq!(
            connection.reuse_state(),
            compio_postgres::ReuseState::NeedsRecovery
        );
        connection.recover_to_ready().await.unwrap();
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn empty_collect_into_layout_error_preserves_explicit_policy_after_ready() {
    use compio_postgres::{ExecutionScheduling, OwnedBatch, RowLayout};
    use compio_postgres::{OnError, ReuseState};
    use std::rc::Rc;

    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            socket.write_all(&result_rows(0))?;
            if policy != OnError::Discard {
                close(socket, &statement)?;
            }
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare(
                    "SELECT 1 WHERE false",
                    &[],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let wrong_layout =
                Rc::new(RowLayout::new(Vec::new(), ResultFormats::All(Format::Binary)).unwrap());
            let mut output = OwnedBatch::new(wrong_layout, 0, 0).unwrap();
            let error = connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .collect_into(&mut output, policy)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                Error::InvalidInput("reusable arena has a different result layout")
            ));
            assert!(output.is_empty());
            if policy == OnError::Discard {
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            } else {
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                connection.close_prepared(&statement).await.unwrap();
            }
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn collect_into_reuses_one_arena_across_distinct_query_loans() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for _ in 0..3 {
            execution(socket, &statement, false)?;
            socket.write_all(&result_rows(2))?;
        }
        close(socket, &statement)?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT generate_series(0,1)::int4",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut arena = statement.new_row_buffer(2, 24).unwrap();
        for _ in 0..3 {
            let completion = connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .collect_into(&mut arena, compio_postgres::OnError::Discard)
                .await
                .unwrap();
            assert_eq!(completion.rows_returned, 2);
            assert_eq!(arena.retained_bytes(), 24);
            assert_eq!(arena.used_bytes(), 24);
            let values: Vec<_> = arena
                .rows()
                .map(|row| row.unwrap().decoder().decode_next::<i32>().unwrap())
                .collect();
            assert_eq!(values, vec![0, 1]);
        }
        connection.close_prepared(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn cancelled_window_does_not_observe_or_admit_a_new_source_item() {
    use compio::runtime::{CancelToken, FutureExt};
    for coalescing in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            close(socket, &statement)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config().send_policy(if coalescing {
                compio_postgres::SendPolicy::CoalesceBuffered
            } else {
                compio_postgres::SendPolicy::BeforeBufferedRead
            }))
            .await
            .unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let mut source = std::iter::from_fn(
                || -> Option<Result<compio_postgres::expert::WindowRequest<'_>, Error>> {
                    panic!("cancelled scope polled its source")
                },
            );
            let token = CancelToken::new();
            token.clone().cancel();
            let error = connection
                .query_window(
                    &mut source,
                    window_limits(1, 1),
                    OnError::RecoverExplicitly,
                    &mut |_| Ok(std::ops::ControlFlow::Continue(())),
                )
                .with_cancel(token)
                .await
                .unwrap_err();
            assert!(!error.may_have_executed);
            assert_eq!(error.admitted, 0);
            assert!(connection.is_usable());
            connection.close_prepared(&statement).await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn window_eof_confirms_only_members_with_ready_and_never_delivers_a_tentative_row() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_value(0))?;
        let mut tail = frame(b'2', &[]);
        tail.extend(row(&[Some(&1_i32.to_be_bytes())]));
        tail.extend(frame(b'C', b"SELECT 1\0"));
        socket.write_all(&tail)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut source = (0..2).map(|value| {
            Ok(WindowRequest {
                statement: &statement,
                parameters: WindowParameters::One(Parameter::int4(value)),
                limits: query_limits(),
            })
        });
        let mut delivered = Vec::new();
        let error = connection
            .query_window(
                &mut source,
                window_limits(2, 2),
                OnError::Discard,
                &mut |event: ReadyBatchEvent<'_>| {
                    delivered.push(event.index);
                    Ok(std::ops::ControlFlow::Continue(()))
                },
            )
            .await
            .unwrap_err();
        assert_eq!(delivered, vec![0]);
        assert_eq!(
            (error.admitted, error.confirmed, error.delivered),
            (2, 1, 1)
        );
        assert!(error.may_have_executed);
        assert!(!connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn dropped_and_forgotten_windows_recover_only_already_admitted_requests() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    for coalescing in [false, true] {
        for forget in [false, true] {
            let (release, allowed) = std::sync::mpsc::channel();
            let peer = Peer::short_queries(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
                allowed.recv_timeout(DEADLINE).map_err(|_| invalid())?;
                for value in 0..2 {
                    execution(socket, &statement, false)?;
                    socket.write_all(&result_value(value))?;
                }
                close(socket, &statement)?;
                drain_until_close(socket)
            });
            run(async {
                let mut connection =
                    TcpConnection::connect(peer.config().send_policy(if coalescing {
                        compio_postgres::SendPolicy::CoalesceBuffered
                    } else {
                        compio_postgres::SendPolicy::BeforeBufferedRead
                    }))
                    .await
                    .unwrap();
                configure(&mut connection, 1);
                let statement = connection
                    .prepare(
                        "SELECT $1::int4",
                        &[Oid::INT4],
                        ResultFormats::All(Format::Binary),
                    )
                    .await
                    .unwrap();
                let observed = std::cell::Cell::new(0);
                let mut source = std::iter::from_fn(|| {
                    let value = observed.get();
                    observed.set(value + 1);
                    Some(Ok(WindowRequest {
                        statement: &statement,
                        parameters: WindowParameters::One(Parameter::int4(value)),
                        limits: query_limits(),
                    }))
                });
                let mut sink = |_: ReadyBatchEvent<'_>| Ok(std::ops::ControlFlow::Continue(()));
                let mut selected = window_limits(10, 2);
                // 这里在 I/O 等待点放弃已接纳的请求。如果调度额度只有两个单位，执行会更早暂停，
                // 此时两个成员虽然已经编码，却都还没有进入发送队列。
                selected.scheduling = compio_postgres::ExecutionScheduling::Uninterrupted;
                let mut pending = Box::pin(connection.query_window(
                    &mut source,
                    selected,
                    OnError::RecoverExplicitly,
                    &mut sink,
                ));
                std::future::poll_fn(|cx| {
                    assert!(pending.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                if forget {
                    std::mem::forget(pending);
                } else {
                    drop(pending);
                }
                assert_eq!(observed.get(), 2);
                assert_eq!(
                    connection.reuse_state(),
                    compio_postgres::ReuseState::NeedsRecovery
                );
                release.send(()).unwrap();
                connection
                    .recover_to_ready_with_limits(2, 24)
                    .await
                    .unwrap();
                assert_eq!(observed.get(), 2);
                assert!(connection.is_usable());
                connection.close_prepared(&statement).await.unwrap();
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn windows_abandoned_at_an_encoding_checkpoint_do_not_admit_the_private_prefix() {
    use compio_postgres::{
        ExecutionScheduling,
        expert::{WindowParameters, WindowRequest},
    };
    for coalescing in [false, true] {
        for forget in [false, true] {
            let (release, allowed) = std::sync::mpsc::channel();
            let peer = Peer::short_queries(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
                allowed.recv_timeout(DEADLINE).map_err(|_| invalid())?;
                // 两个请求仍在已放弃 future 的私有缓冲中，对端不应收到 Bind、Execute 或 Sync。
                close(socket, &statement)?;
                drain_until_close(socket)
            });
            run(async {
                let mut connection =
                    TcpConnection::connect(peer.config().send_policy(if coalescing {
                        compio_postgres::SendPolicy::CoalesceBuffered
                    } else {
                        compio_postgres::SendPolicy::BeforeBufferedRead
                    }))
                    .await
                    .unwrap();
                configure(&mut connection, 1);
                let statement = connection
                    .prepare(
                        "SELECT $1::int4",
                        &[Oid::INT4],
                        ResultFormats::All(Format::Binary),
                    )
                    .await
                    .unwrap();
                let observed = std::cell::Cell::new(0);
                let mut source = std::iter::from_fn(|| {
                    let value = observed.get();
                    observed.set(value + 1);
                    Some(Ok(WindowRequest {
                        statement: &statement,
                        parameters: WindowParameters::One(Parameter::int4(value)),
                        limits: query_limits(),
                    }))
                });
                let delivered = std::cell::Cell::new(0);
                let mut sink = |_: ReadyBatchEvent<'_>| {
                    delivered.set(delivered.get() + 1);
                    Ok(std::ops::ControlFlow::Continue(()))
                };
                let mut selected = window_limits(10, 2);
                selected.scheduling = ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
                };
                let mut pending = Box::pin(connection.query_window(
                    &mut source,
                    selected,
                    OnError::RecoverExplicitly,
                    &mut sink,
                ));
                std::future::poll_fn(|cx| {
                    assert!(pending.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                if forget {
                    std::mem::forget(pending);
                } else {
                    drop(pending);
                }
                assert_eq!(observed.get(), 2);
                assert_eq!(delivered.get(), 0);
                connection.recover_to_ready_with_limits(0, 0).await.unwrap();
                assert_eq!(observed.get(), 2);
                assert!(connection.is_usable());
                release.send(()).unwrap();
                connection.close_prepared(&statement).await.unwrap();
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn window_callback_panic_keeps_a_persistent_discard_marker() {
    use compio_postgres::expert::{WindowParameters, WindowRequest};
    use futures_util::FutureExt;
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_value(0))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut source = std::iter::once(Ok(WindowRequest {
            statement: &statement,
            parameters: WindowParameters::One(Parameter::int4(0)),
            limits: query_limits(),
        }));
        let mut sink = |_: ReadyBatchEvent<'_>| -> Result<std::ops::ControlFlow<()>, Error> {
            panic!("deliberate window callback panic")
        };
        assert!(
            std::panic::AssertUnwindSafe(connection.query_window(
                &mut source,
                window_limits(1, 1),
                OnError::RecoverExplicitly,
                &mut sink
            ))
            .catch_unwind()
            .await
            .is_err()
        );
        assert_eq!(
            connection.reuse_state(),
            compio_postgres::ReuseState::DiscardOnly
        );
        assert!(connection.recover_to_ready().await.is_err());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn mixed_parameters_columns_and_stream_completion_use_the_bind_layout() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23, 25], &[("number", 23, 4), ("text", 25, -1)])?;
        let mut bind = vec![0];
        bind.extend_from_slice(statement.as_bytes());
        bind.push(0);
        // 两个参数的格式依次为二进制、文本，随后是两个带长度的值。
        bind.extend_from_slice(b"\0\x02\0\x01\0\0\0\x02");
        bind.extend_from_slice(&4_i32.to_be_bytes());
        bind.extend_from_slice(&7_i32.to_be_bytes());
        bind.extend_from_slice(b"\0\0\0\x05hello");
        // 结果列使用同样的格式顺序。
        bind.extend_from_slice(b"\0\x02\0\x01\0\0");
        if expect(socket, b'B')? != bind
            || expect(socket, b'E')? != [0; 5]
            || !expect(socket, b'S')?.is_empty()
        {
            return Err(invalid());
        }
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&7_i32.to_be_bytes()), Some(b"hello")]));
        response.extend(row(&[Some(&8_i32.to_be_bytes()), None]));
        response.extend(frame(b'C', b"SELECT 2\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        close(socket, &statement)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 2);
        let statement = connection
            .prepare(
                "SELECT $1::int4, $2::text",
                &[Oid::INT4, Oid::TEXT],
                ResultFormats::PerColumn(vec![Format::Binary, Format::Text].into_boxed_slice()),
            )
            .await
            .unwrap();
        let params = [Parameter::int4(7), Parameter::text(Oid::TEXT, "hello")];
        let mut query = connection
            .query(
                &statement,
                &params,
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        {
            let lease = query.next_row().await.unwrap().unwrap();
            let mut decoder = lease.view().decoder();
            assert_eq!(decoder.decode_next::<i32>().unwrap(), 7);
            assert_eq!(decoder.decode_next::<&str>().unwrap(), "hello");
            decoder.finish().unwrap();
        }
        {
            let lease = query.next_row().await.unwrap().unwrap();
            let mut decoder = lease.view().decoder();
            assert_eq!(decoder.decode_next::<i32>().unwrap(), 8);
            assert_eq!(decoder.decode_next::<Option<&str>>().unwrap(), None);
            decoder.finish().unwrap();
        }
        assert!(query.next_row().await.unwrap().is_none());
        let completion = query.completion().unwrap();
        assert_eq!(completion.command, Some(CommandKind::Select));
        assert_eq!(completion.rows_returned, 2);
        assert!(completion.succeeded);
        drop(query);
        assert!(connection.is_usable());
        connection.close_prepared(&statement).await.unwrap();
        drop(statement);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn owned_results_keep_closed_metadata_charged_until_last_reference() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let first = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &first, false)?;
        socket.write_all(&result_rows(1))?;
        close(socket, &first)?;
        let second = prepare(socket, &[23], &[("n", 23, 4)])?;
        if first == second {
            return Err(invalid());
        }
        close(socket, &second)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let (owned, completion) = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(completion.rows_returned, 1);
        connection.close_prepared(&statement).await.unwrap();
        assert!(matches!(
            connection
                .query(
                    &statement,
                    &[Parameter::int4(0)],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        drop(statement);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 0);
        assert!(matches!(
            connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary)
                )
                .await,
            Err(Error::Limit(_))
        ));
        assert_eq!(
            owned
                .rows()
                .next()
                .unwrap()
                .unwrap()
                .decoder()
                .decode_next::<i32>()
                .unwrap(),
            0
        );
        drop(owned);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
        let next = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        connection.close_prepared(&next).await.unwrap();
        connection.discard();
    });
    peer.finish();
}

#[test]
fn search_path_and_explicit_invalidation_preserve_remote_close_responsibility() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let first = prepare(socket, &[23], &[("n", 23, 4)])?;
        let second = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &first, false)?;
        let mut response = frame(b'S', b"search_path\0other, public\0");
        response.extend(result_rows(1));
        socket.write_all(&response)?;
        close(socket, &first)?;
        close(socket, &second)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 2);
        let first = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let second = connection
            .prepare(
                "SELECT $1::int4 + 1",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let (_, completion) = connection
            .query(
                &first,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert!(completion.succeeded);
        assert!(matches!(
            connection
                .query(
                    &second,
                    &[Parameter::int4(1)],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        connection.invalidate_statements().unwrap();
        assert!(matches!(
            connection
                .query(
                    &first,
                    &[Parameter::int4(1)],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        connection.close_prepared(&first).await.unwrap();
        connection.close_prepared(&second).await.unwrap();
        connection.discard();
    });
    peer.finish();
}

#[test]
fn forgotten_row_allows_protocol_recovery() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(2))?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(1))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let row = query.next_row().await.unwrap().unwrap();
        assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 0);
        let _forgotten = std::mem::ManuallyDrop::new(row);
        drop(query);
        connection.recover_to_ready().await.unwrap();
        assert!(connection.is_usable());
        let mut query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        assert_eq!(query.finish().await.unwrap().rows_returned, 1);
        drop(query);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn dropped_prepare_retains_its_name_for_explicit_close() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = read_prepare(socket)?;
        socket.write_all(&frame(b'1', &[]))?;
        socket.write_all(&frame(b'N', REQUEST_OBSERVED))?;
        wait.recv_timeout(IO_DEADLINE)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "prepare release"))?;
        let response = preparation_response(&[23], &[("n", 23, 4)]);
        socket.write_all(&response[5..])?;
        close(socket, &statement)
    });
    run(async {
        let (config, observed) = observe_request(peer.config());
        let mut connection = TcpConnection::connect(config).await.unwrap();
        configure(&mut connection, 1);
        let mut prepare = Box::pin(connection.prepare(
            "SELECT $1::int4",
            &[Oid::INT4],
            ResultFormats::All(Format::Binary),
        ));
        poll_until_observed(prepare.as_mut(), &observed).await;
        drop(prepare);
        assert!(!connection.is_usable());
        release.send(()).unwrap();
        connection.recover_to_ready().await.unwrap();
        connection
            .close_all_statements(compio_postgres::StatementPipelineLimits {
                max_statements: 1,
                max_packet_bytes: 1024,
                max_result_bytes: 4096,
                scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
            })
            .await
            .unwrap();
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn rows_above_the_control_message_limit_stream_and_recover() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(300))?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(300))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let mut count = 0;
        query
            .for_each_row(
                &mut |row| {
                    assert_eq!(row.decoder().decode_next::<i32>()?, count);
                    count += 1;
                    Ok(())
                },
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(count, 300);
        drop(query);
        let mut query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        drop(query.next_row().await.unwrap().unwrap());
        std::mem::forget(query);
        connection.recover_to_ready().await.unwrap();
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn compact_collection_allocates_for_actual_rows_with_a_large_result_limit() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        for count in [0, 1, 5] {
            execution(socket, &statement, false)?;
            socket.write_all(&result_rows(count))?;
        }
        close(socket, &statement)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut selected = query_limits();
        selected.max_result_bytes = 64 * 1024 * 1024;
        for count in [0, 1, 5] {
            let (batch, completion) = connection
                .query(
                    &statement,
                    &[Parameter::int4(0)],
                    compio_postgres::QueryOptions {
                        limits: selected,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .collect_with(
                    compio_postgres::AllocationPolicy::Grow,
                    compio_postgres::OnError::Discard,
                )
                .await
                .unwrap();
            assert_eq!(completion.rows_returned, count);
            assert_eq!(batch.len(), count);
            assert_eq!(batch.used_bytes(), count * 12);
            if count == 0 {
                assert_eq!(batch.retained_bytes(), 0);
            } else {
                assert!(
                    (batch.used_bytes()..=batch.used_bytes() * 2).contains(&batch.retained_bytes())
                );
            }
            let values = batch
                .rows()
                .map(|row| row.unwrap().decoder().decode_next::<i32>())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                values,
                (0..i32::try_from(count).unwrap()).collect::<Vec<_>>()
            );
            assert!(connection.is_usable());
        }
        connection.close_prepared(&statement).await.unwrap();
    });
    peer.finish();
}

#[test]
fn collect_reserves_the_selected_limit_for_reusing_larger_results() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        for count in [1, 5] {
            execution(socket, &statement, false)?;
            socket.write_all(&result_rows(count))?;
        }
        close(socket, &statement)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut selected = query_limits();
        selected.max_result_bytes = 64 * 1024 * 1024;
        let (mut batch, completion) = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: selected,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(completion.rows_returned, 1);
        assert_eq!(batch.used_bytes(), 12);
        assert_eq!(batch.retained_bytes(), selected.max_result_bytes);
        let pointer = batch
            .rows()
            .next()
            .unwrap()
            .unwrap()
            .decoder()
            .next_raw()
            .unwrap()
            .bytes
            .unwrap()
            .as_ptr();
        let completion = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: selected,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_into(&mut batch, compio_postgres::OnError::Discard)
            .await
            .unwrap();
        assert_eq!(completion.rows_returned, 5);
        assert_eq!(batch.used_bytes(), 60);
        assert_eq!(batch.retained_bytes(), selected.max_result_bytes);
        let current_pointer = batch
            .rows()
            .next()
            .unwrap()
            .unwrap()
            .decoder()
            .next_raw()
            .unwrap()
            .bytes
            .unwrap()
            .as_ptr();
        assert_eq!(pointer, current_pointer);
        let values = batch
            .rows()
            .map(|row| row.unwrap().decoder().decode_next::<i32>())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(values, [0, 1, 2, 3, 4]);
        assert!(connection.is_usable());
        connection.close_prepared(&statement).await.unwrap();
    });
    peer.finish();
}

#[test]
fn collect_limit_aborts_instead_of_waiting_on_its_own_retained_rows() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(2))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut selected = query_limits();
        selected.max_result_bytes = 12;
        let query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: selected,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        assert!(matches!(
            query
                .collect_with(
                    compio_postgres::AllocationPolicy::ReserveLimit,
                    compio_postgres::OnError::Discard
                )
                .await,
            Err(Error::Limit(_))
        ));
        assert!(!connection.is_usable());
        assert!(matches!(
            connection.recover_to_ready().await,
            Err(Error::Broken)
        ));
        connection.discard();
    });
    peer.finish();
}

#[test]
fn callback_panic_leaves_a_persistent_abort_marker() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(1))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut query = connection
            .query(
                &statement,
                &[Parameter::int4(0)],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let mut entered = false;
        let mut sink = |_row: compio_postgres::RowView<'_, '_>| -> Result<(), Error> {
            entered = true;
            panic!("deliberate synchronous sink panic");
        };
        let result = AssertUnwindSafe(
            query.for_each_row(&mut sink, compio_postgres::OnError::RecoverExplicitly),
        )
        .catch_unwind()
        .await;
        assert!(entered);
        assert!(result.is_err());
        drop(query);
        assert!(!connection.is_usable());
        assert!(matches!(
            connection.recover_to_ready().await,
            Err(Error::Broken)
        ));
        connection.discard();
    });
    peer.finish();
}

#[test]
fn one_shot_and_simple_metadata_limits_recover_without_retaining_layouts() {
    use compio_postgres::{AllocationPolicy, ExecutionScheduling};
    use compio_postgres::{OnError, ReuseState};

    for (simple, no_data) in [(false, false), (false, true), (true, false)] {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            let peer = Peer::short_queries(move |socket| {
                handshake(socket)?;
                let mut response = if simple {
                    expect(socket, b'Q')?;
                    Vec::new()
                } else {
                    if !name(&expect(socket, b'P')?)?.is_empty() {
                        return Err(invalid());
                    }
                    execution(socket, "", true)?;
                    let mut response = frame(b'1', &[]);
                    response.extend(frame(b'2', &[]));
                    response
                };
                if no_data {
                    response.extend(frame(b'n', &[]));
                    response.extend(frame(b'C', b"UPDATE 1\0"));
                } else {
                    response.extend(description(&[("n", 23, 4)], &[if simple { 0 } else { 1 }]));
                    let binary = 42_i32.to_be_bytes();
                    response.extend(row(&[Some(if simple { b"42" } else { &binary })]));
                    response.extend(frame(b'C', b"SELECT 1\0"));
                }
                response.extend(ready());
                socket.write_all(&response)?;
                if policy != OnError::Discard {
                    if expect(socket, b'Q')? != b"UPDATE fixture SET v=73\0" {
                        return Err(invalid());
                    }
                    let mut response = frame(b'C', b"UPDATE 1\0");
                    response.extend(ready());
                    socket.write_all(&response)?;
                }
                drain_until_close(socket)
            });
            run(async {
                let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
                let mut selected = query_limits();
                selected.max_metadata_bytes = 0;
                let query = if simple {
                    connection
                        .query_simple_single(
                            "SELECT 42",
                            compio_postgres::QueryOptions {
                                limits: selected,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            compio_postgres::AbandonPolicy::RecoverExplicitly,
                        )
                        .await
                } else {
                    connection
                        .one_shot(
                            "SELECT 42",
                            &[],
                            if no_data {
                                ResultFormats::All(Format::Binary)
                            } else {
                                ResultFormats::PerColumn(vec![Format::Binary].into_boxed_slice())
                            },
                            compio_postgres::QueryOptions {
                                limits: selected,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            compio_postgres::AbandonPolicy::RecoverExplicitly,
                        )
                        .await
                }
                .unwrap();
                assert!(matches!(
                    query.collect_with(AllocationPolicy::Grow, policy).await,
                    Err(Error::Limit(_))
                ));
                match policy {
                    OnError::DrainToReady => {
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                    }
                    OnError::RecoverExplicitly => {
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        connection.recover_to_ready().await.unwrap();
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    }
                    OnError::Discard => {
                        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly)
                    }
                }
                if policy != OnError::Discard {
                    let completion = connection
                        .query_simple_single(
                            "UPDATE fixture SET v=73",
                            compio_postgres::QueryOptions {
                                limits: query_limits(),
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            compio_postgres::AbandonPolicy::RecoverExplicitly,
                        )
                        .await
                        .unwrap()
                        .finish()
                        .await
                        .unwrap();
                    assert_eq!(completion.rows_affected, Some(1));
                }
                connection.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn one_shot_describes_the_portal_and_late_error_does_not_become_success() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        if !name(&expect(socket, b'P')?)?.is_empty() {
            return Err(invalid());
        }
        execution(socket, "", true)?;
        let mut response = frame(b'1', &[]);
        response.extend(frame(b'2', &[]));
        response.extend(description(&[("n", 23, 4)], &[1]));
        response.extend(row(&[Some(&4_i32.to_be_bytes())]));
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(frame(b'E', b"SERROR\0VERROR\0C40001\0Mlate error\0\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        let mut query = connection
            .one_shot(
                "SELECT $1::int4",
                &[Parameter::int4(4)],
                ResultFormats::All(Format::Binary),
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        {
            let row = query.next_row().await.unwrap().unwrap();
            assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 4);
        }
        assert!(
            matches!(query.next_row().await, Err(Error::Database(error)) if error.code() == "40001")
        );
        let completion = query.completion().unwrap();
        assert!(!completion.succeeded);
        assert_eq!(completion.command, Some(CommandKind::Select));
        drop(query);
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn recovery_rejects_ready_before_prepared_query_completion() {
    for stage in 0..3 {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            let mut response = Vec::new();
            if stage >= 1 {
                response.extend(frame(b'2', &[]));
            }
            if stage >= 2 {
                response.extend(row(&[Some(&1_i32.to_be_bytes())]));
            }
            response.extend(ready());
            socket.write_all(&response)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            drop(
                connection
                    .query(
                        &statement,
                        &[],
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
                    .unwrap(),
            );
            assert!(matches!(
                connection.recover_to_ready().await,
                Err(Error::Protocol(_))
            ));
            assert!(!connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn recovery_checks_one_shot_parse_bind_describe_and_row_shape() {
    for stage in 0..6 {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            expect(socket, b'P')?;
            expect(socket, b'B')?;
            expect(socket, b'D')?;
            expect(socket, b'E')?;
            expect(socket, b'S')?;
            let mut response = Vec::new();
            if stage >= 1 {
                response.extend(frame(b'1', &[]));
            }
            if stage >= 2 {
                response.extend(frame(b'2', &[]));
            }
            if stage == 3 {
                response.extend(frame(b'I', &[]));
            }
            if stage >= 4 {
                response.extend(description(&[("n", 23, 4)], &[1]));
                response.extend(if stage == 4 {
                    row(&[])
                } else {
                    row(&[Some(&1_i32.to_be_bytes())])
                });
                response.extend(frame(b'C', b"SELECT 1\0"));
            }
            response.extend(ready());
            socket.write_all(&response)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            drop(
                connection
                    .one_shot(
                        "SELECT 1",
                        &[],
                        ResultFormats::All(Format::Binary),
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
                    .unwrap(),
            );
            let result = connection.recover_to_ready().await;
            if stage == 5 {
                result.unwrap();
                assert!(connection.is_usable());
            } else {
                assert!(matches!(result, Err(Error::Protocol(_) | Error::Codec(_))));
                assert!(!connection.is_usable());
            }
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn recovery_limit_does_not_consume_or_repeat_the_waiting_row() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(2))?;
        execution(socket, &statement, false)?;
        socket.write_all(&result_rows(1))?;
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        drop(
            connection
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap(),
        );
        assert!(matches!(
            connection.recover_to_ready_with_limits(0, 0).await,
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            connection.recover_to_ready_with_limits(1, 12).await,
            Err(Error::Limit(_))
        ));
        connection
            .recover_to_ready_with_limits(1, 12)
            .await
            .unwrap();
        assert!(connection.is_usable());
        let (rows, _) = connection
            .query(
                &statement,
                &[],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn recovery_accepts_sync_error_after_completion_but_rejects_data_after_error() {
    for invalid_row in [false, true] {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution(socket, &statement, false)?;
            let mut response = frame(b'2', &[]);
            response.extend(frame(b'C', b"SELECT 0\0"));
            response.extend(frame(b'E', b"SERROR\0C23503\0Mdeferred failure\0\0"));
            if invalid_row {
                response.extend(row(&[Some(&1_i32.to_be_bytes())]));
            }
            response.extend(ready());
            socket.write_all(&response)?;
            drain_until_close(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            configure(&mut connection, 1);
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            drop(
                connection
                    .query(
                        &statement,
                        &[],
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
                    .unwrap(),
            );
            let result = connection.recover_to_ready().await;
            if invalid_row {
                assert!(matches!(result, Err(Error::Protocol(_))));
                assert!(!connection.is_usable());
            } else {
                result.unwrap();
                assert!(connection.is_usable());
            }
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn recovery_cannot_replace_missing_prepare_or_close_replies_with_ready() {
    for preparing in [false, true] {
        let (release, wait) = mpsc::channel();
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            if preparing {
                read_prepare(socket)?;
                socket.write_all(&frame(b'1', &[]))?;
            } else {
                prepare(socket, &[], &[("n", 23, 4)])?;
                expect(socket, b'C')?;
                expect(socket, b'S')?;
            }
            socket.write_all(&frame(b'N', REQUEST_OBSERVED))?;
            wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
            socket.write_all(&ready())?;
            drain_until_close(socket)
        });
        run(async {
            let (config, observed) = observe_request(peer.config());
            let mut connection = TcpConnection::connect(config).await.unwrap();
            configure(&mut connection, 1);
            if preparing {
                let mut pending = Box::pin(connection.prepare(
                    "SELECT 1",
                    &[],
                    ResultFormats::All(Format::Binary),
                ));
                poll_until_observed(pending.as_mut(), &observed).await;
                drop(pending);
            } else {
                let statement = connection
                    .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                    .await
                    .unwrap();
                let mut pending = Box::pin(connection.close_prepared(&statement));
                poll_until_observed(pending.as_mut(), &observed).await;
                drop(pending);
            }
            release.send(()).unwrap();
            assert!(matches!(
                connection.recover_to_ready().await,
                Err(Error::Protocol(_))
            ));
            assert!(!connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn recovery_keeps_a_consumed_close_completion_across_waiter_drop() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        prepare(socket, &[], &[("n", 23, 4)])?;
        expect(socket, b'C')?;
        expect(socket, b'S')?;
        let mut response = frame(b'3', &[]);
        response.extend(frame(b'N', REQUEST_OBSERVED));
        socket.write_all(&response)?;
        wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
        socket.write_all(&ready())?;
        drain_until_close(socket)
    });
    run(async {
        let (config, observed) = observe_request(peer.config());
        let mut connection = TcpConnection::connect(config).await.unwrap();
        configure(&mut connection, 1);
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut pending = Box::pin(connection.close_prepared(&statement));
        poll_until_observed(pending.as_mut(), &observed).await;
        drop(pending);
        release.send(()).unwrap();
        connection.recover_to_ready().await.unwrap();
        assert!(connection.is_usable());
        drop(statement);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
        connection.discard();
    });
    peer.finish();
}

fn live_config() -> TcpConfig {
    live::tcp_config(limits(), peer::TCP_OPTIONS)
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_multi_parameter_multi_column_and_owned_result() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.unwrap();
        configure(&mut connection, 4);
        let statement = connection
            .prepare(
                "SELECT $1::int4 AS n, $2::text AS s, $3::bytea AS b",
                &[Oid::INT4, Oid::TEXT, Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let params = [
            Parameter::int4(i32::MIN),
            Parameter::string("你好"),
            Parameter::bytea(b"\0\xff"),
        ];
        let (batch, completion) = connection
            .query(
                &statement,
                &params,
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .collect_with(
                compio_postgres::AllocationPolicy::ReserveLimit,
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert!(completion.succeeded);
        let row = batch.rows().next().unwrap().unwrap();
        let mut decoder = row.decoder();
        assert_eq!(decoder.decode_next::<i32>().unwrap(), i32::MIN);
        assert_eq!(decoder.decode_next::<&str>().unwrap(), "你好");
        assert_eq!(decoder.decode_next::<&[u8]>().unwrap(), b"\0\xff");
        decoder.finish().unwrap();
        connection.close_prepared(&statement).await.unwrap();
        drop(statement);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 0);
        drop(batch);
        assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
        connection.discard();
    });
}

#[cfg(feature = "postgres-types")]
#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_pg19_bootstrap_types_match_the_binary_catalog() {
    use postgres_types::Kind;

    // PostgreSQL 19 为 pg_type.dat 的条目及其数组显式分配 OID。
    // 10000 起属于自动分配区，其他系统目录的行类型也不属于这组引导条目。
    const SQL: &str = "
        SELECT t.oid, t.typname, t.typtype::text, t.typelem, COALESCE(r.rngsubtype, 0::oid)
        FROM pg_catalog.pg_type t
        LEFT JOIN pg_catalog.pg_type e ON e.oid = t.typelem
        LEFT JOIN pg_catalog.pg_range r ON t.oid IN (r.rngtypid, r.rngmultitypid)
        WHERE t.typnamespace = 'pg_catalog'::regnamespace AND t.oid < 10000
          AND (COALESCE(e.typtype, t.typtype) <> 'c'
               OR COALESCE(e.oid, t.oid) IN (71, 75, 81, 83))";

    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.unwrap();
        let mut query = connection
            .one_shot(
                SQL,
                &[],
                ResultFormats::All(Format::Binary),
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let mut count = 0;
        let mut explicit = 0;
        while let Some(row) = query.next_row().await.unwrap() {
            let mut fields = row.view().decoder();
            let oid = fields.decode_next::<Oid>().unwrap();
            let name = fields.decode_next::<&str>().unwrap();
            let typtype = fields.decode_next::<&str>().unwrap();
            let element = fields.decode_next::<Oid>().unwrap();
            let subtype = fields.decode_next::<Oid>().unwrap();
            fields.finish().unwrap();
            count += 1;
            let ty = oid.builtin_postgres_type();
            if matches!(
                oid,
                Oid::PG_TYPE
                    | Oid::PG_ATTRIBUTE
                    | Oid::PG_PROC
                    | Oid::PG_CLASS
                    | Oid::PG_TYPE_ARRAY
                    | Oid::PG_ATTRIBUTE_ARRAY
                    | Oid::PG_PROC_ARRAY
                    | Oid::PG_CLASS_ARRAY
            ) {
                // 这些复合行及其数组须由调用方提供字段布局。
                assert!(ty.is_none(), "{name}");
                explicit += 1;
                continue;
            }
            let ty = ty.unwrap_or_else(|| panic!("缺少内建类型 {name} ({})", oid.0));
            assert_eq!(
                (ty.schema(), ty.name(), ty.oid()),
                ("pg_catalog", name, oid.0)
            );
            match ty.kind() {
                Kind::Array(inner) => assert_eq!(element.0, inner.oid(), "{name}"),
                Kind::Range(inner) => {
                    assert_eq!((typtype, subtype.0), ("r", inner.oid()), "{name}")
                }
                Kind::Multirange(inner) => {
                    assert_eq!((typtype, subtype.0), ("m", inner.oid()), "{name}")
                }
                Kind::Pseudo => assert_eq!(typtype, "p", "{name}"),
                // postgres-types 将 unknown 作为 Simple，以保留其内建常量的身份。
                Kind::Simple if ty == postgres_types::Type::UNKNOWN => assert_eq!(typtype, "p"),
                Kind::Simple => assert_eq!(typtype, "b", "{name}"),
                other => panic!("引导类型 {name} 映射为未预期的种类 {other:?}"),
            }
        }
        assert_eq!((count, explicit), (197, 8));
        assert!(query.finish().await.unwrap().succeeded);
        drop(query);
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_pg19_bootstrap_catalog_row_and_array_oids() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.unwrap();
        let mut query = connection
            .one_shot(
                "SELECT typname, oid, typarray FROM pg_catalog.pg_type
                 WHERE typnamespace = 'pg_catalog'::regnamespace
                 AND typname IN ('pg_type', 'pg_attribute', 'pg_proc', 'pg_class')
                 ORDER BY oid",
                &[],
                ResultFormats::All(Format::Binary),
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        for (name, oid, array_oid) in [
            ("pg_type", Oid::PG_TYPE, Oid::PG_TYPE_ARRAY),
            ("pg_attribute", Oid::PG_ATTRIBUTE, Oid::PG_ATTRIBUTE_ARRAY),
            ("pg_proc", Oid::PG_PROC, Oid::PG_PROC_ARRAY),
            ("pg_class", Oid::PG_CLASS, Oid::PG_CLASS_ARRAY),
        ] {
            let lease = query.next_row().await.unwrap().unwrap();
            let mut fields = lease.view().decoder();
            assert_eq!(fields.decode_next::<&str>().unwrap(), name);
            assert_eq!(fields.decode_next::<Oid>().unwrap(), oid);
            assert_eq!(fields.decode_next::<Oid>().unwrap(), array_oid);
            fields.finish().unwrap();
        }
        assert!(query.next_row().await.unwrap().is_none());
        assert!(query.finish().await.unwrap().succeeded);
        drop(query);
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_pg19_containers_and_unsigned_oid8() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.unwrap();
        let mut query = connection.one_shot(
            "SELECT ARRAY[1,NULL,3]::int4[], ROW(1,'a'::text,NULL::bytea), '[1,3)'::int4range, '{[1,3),[6,9)}'::int4multirange, '18446744073709551615'::oid8",
            &[], ResultFormats::All(Format::Binary), compio_postgres::QueryOptions { limits: query_limits(), scheduling: compio_postgres::ExecutionScheduling::Uninterrupted }, compio_postgres::AbandonPolicy::RecoverExplicitly).await.unwrap();
        {
            let lease = query.next_row().await.unwrap().unwrap();
            let mut fields = lease.view().fields();
            let array = ArrayView::parse(
                fields.next().unwrap().unwrap(),
                ArrayLayout {
                    oid: Oid(1007),
                    element_oid: Oid::INT4,
                },
            )
            .unwrap();
            assert_eq!(
                array
                    .values()
                    .map(|value| value.unwrap().decode::<Option<i32>>())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                [Some(1), None, Some(3)]
            );
            let composite_layout = CompositeLayout {
                oid: Oid::RECORD,
                fields: vec![Oid::INT4, Oid::TEXT, Oid::BYTEA].into_boxed_slice(),
            };
            let composite =
                CompositeView::parse(fields.next().unwrap().unwrap(), &composite_layout).unwrap();
            assert_eq!(
                composite
                    .fields()
                    .next()
                    .unwrap()
                    .unwrap()
                    .decode::<i32>()
                    .unwrap(),
                1
            );
            let range_layout = RangeLayout {
                oid: Oid(3904),
                subtype_oid: Oid::INT4,
            };
            assert!(
                !RangeView::parse(fields.next().unwrap().unwrap(), range_layout)
                    .unwrap()
                    .is_empty()
            );
            let multi = MultiRangeView::parse(
                fields.next().unwrap().unwrap(),
                MultiRangeLayout {
                    oid: Oid(4451),
                    range: range_layout,
                },
            )
            .unwrap();
            assert_eq!(multi.len(), 2);
            assert_eq!(
                fields.next().unwrap().unwrap().decode::<Oid8>().unwrap(),
                Oid8(u64::MAX)
            );
        }
        assert!(query.finish().await.unwrap().succeeded);
        drop(query);
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_temporal_network_numeric_json_and_large_stream() {
    use compio_postgres::types::{
        BitString, JsonText, Network, NumericSign, NumericView, PgDate, PgTime, PgTimestamp,
        PgTimestampTz, Uuid,
    };
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.unwrap();
        let mut query = connection.one_shot(
            "SELECT 'infinity'::date, '-infinity'::timestamptz, '24:00'::time, '192.0.2.0/24'::cidr, B'101010101'::varbit, 12345.678::numeric, '{\"a\":1}'::jsonb, '01234567-89ab-cdef-0123-456789abcdef'::uuid",
            &[], ResultFormats::All(Format::Binary), compio_postgres::QueryOptions { limits: query_limits(), scheduling: compio_postgres::ExecutionScheduling::Uninterrupted }, compio_postgres::AbandonPolicy::RecoverExplicitly).await.unwrap();
        {
            let row = query.next_row().await.unwrap().unwrap();
            let mut decoder = row.view().decoder();
            assert_eq!(
                decoder.decode_next::<PgDate>().unwrap(),
                PgDate::PositiveInfinity
            );
            assert_eq!(
                decoder.decode_next::<PgTimestampTz>().unwrap(),
                PgTimestampTz(PgTimestamp::NegativeInfinity)
            );
            assert_eq!(
                decoder.decode_next::<PgTime>().unwrap(),
                PgTime(86_400_000_000)
            );
            assert_eq!(decoder.decode_next::<Network>().unwrap().prefix_len, 24);
            assert_eq!(decoder.decode_next::<BitString>().unwrap().bit_len, 9);
            assert_eq!(
                decoder.decode_next::<NumericView>().unwrap().sign,
                NumericSign::Positive
            );
            assert_eq!(decoder.decode_next::<JsonText>().unwrap().0, "{\"a\": 1}");
            assert_eq!(decoder.decode_next::<Uuid>().unwrap().0[0], 1);
            decoder.finish().unwrap();
        }
        query.finish().await.unwrap();
        drop(query);
        let mut query = connection
            .one_shot(
                "SELECT generate_series(1,300)::int4",
                &[],
                ResultFormats::All(Format::Binary),
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let mut total = 0_i64;
        let completion = query
            .for_each_row(
                &mut |row| {
                    total += i64::from(row.decoder().decode_next::<i32>()?);
                    Ok(())
                },
                compio_postgres::OnError::Discard,
            )
            .await
            .unwrap();
        assert_eq!(completion.rows_returned, 300);
        assert_eq!(total, 45_150);
        drop(query);
        connection.discard();
    });
}

#[test]
fn simple_fetch_uses_the_binary_cursor_description() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        for (sql, command, status) in [
            (&b"BEGIN\0"[..], &b"BEGIN\0"[..], b'T'),
            (
                &b"DECLARE c BINARY CURSOR FOR SELECT 42::int4\0"[..],
                &b"DECLARE CURSOR\0"[..],
                b'T',
            ),
            (&b"FETCH 1 FROM c\0"[..], &b"FETCH 1\0"[..], b'T'),
            (&b"ROLLBACK\0"[..], &b"ROLLBACK\0"[..], b'I'),
        ] {
            if expect(socket, b'Q')? != sql {
                return Err(invalid());
            }
            let mut response = Vec::new();
            if command == b"FETCH 1\0" {
                response.extend(description(&[("n", 23, 4)], &[1]));
                response.extend(row(&[Some(&42_i32.to_be_bytes())]));
            }
            response.extend(frame(b'C', command));
            response.extend(frame(b'Z', &[status]));
            socket.write_all(&response)?;
        }
        drain_until_close(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let scheduling = compio_postgres::ExecutionScheduling::Uninterrupted;
        transaction
            .query_simple_single(
                "DECLARE c BINARY CURSOR FOR SELECT 42::int4",
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        {
            let mut fetch = transaction
                .query_simple_single(
                    "FETCH 1 FROM c",
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let row = fetch.next_row().await.unwrap().unwrap();
            assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 42);

            assert_eq!(fetch.finish().await.unwrap().rows_returned, 1);
        }
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn invalid_simple_preflight_keeps_retired_tx_available_for_explicit_trim() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        if expect(socket, b'Q')? != b"UPDATE fixture SET v=73\0" {
            return Err(invalid());
        }
        let mut response = frame(b'C', b"UPDATE 1\0");
        response.extend(ready());
        socket.write_all(&response)?;
        let mut byte = [0];
        match socket.read(&mut byte)? {
            0 => Ok(()),
            _ => Err(invalid()),
        }
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
        let completion = connection
            .query_simple_single(
                "UPDATE fixture SET v=73",
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert_eq!(completion.rows_affected, Some(1));
        assert!(matches!(
            connection
                .query_simple_single(
                    "SELECT\0 1",
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        assert!(connection.is_usable());
        assert!(connection.trim_send_buffer().unwrap() > 0);
        assert_eq!(connection.trim_send_buffer().unwrap(), 0);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}
