//! 共用一个 Sync 的组可临时借用响应行；失败后必须停用连接。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{DEADLINE, database_error, handshake, limits, prepare, ready, row, run};
use peer::{Peer, frame, invalid, name};

use compio_postgres::{
    AuthenticationPolicy, CommandKind, Error, ExecutionScheduling, QueryLimits, ResultFormats,
    ReuseState, StatementLimits, TcpConfig, TransactionEnd, TransactionStatus, WireLimits,
    expert::{
        GroupPipelineLimits, GroupPipelineProgress, PipelineRequest, ProvisionalGroupConsumeEvent,
        ProvisionalGroupEvent, ProvisionalGroupLimits, TcpSession as TcpConnection,
    },
    types::{Format, Oid, Parameter},
};
use futures_util::FutureExt;
use std::{
    cell::Cell,
    future::Future,
    io::{self, Write},
    net::TcpStream,
    panic::AssertUnwindSafe,
    rc::Rc,
    sync::mpsc,
};

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1024,
        max_result_bytes: 64 * 1024,
        max_metadata_bytes: 16 * 1024,
    }
}

fn expect(socket: &mut TcpStream, tag: u8) -> io::Result<Vec<u8>> {
    peer::read_tag(socket, tag, 10 * 1024 * 1024)
}

fn visit_limits() -> ProvisionalGroupLimits {
    ProvisionalGroupLimits {
        max_requests: 32,
        max_rows: 4096,
        max_member_result_bytes: 64 * 1024,
        scheduling: ExecutionScheduling::Uninterrupted,
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

fn execution_open(socket: &mut TcpStream, statement: &str) -> io::Result<()> {
    let bind = expect(socket, b'B')?;
    if bind.first() != Some(&0)
        || name(&bind[1..])? != statement
        || expect(socket, b'E')? != [0, 0, 0, 0, 0]
    {
        return Err(invalid());
    }
    Ok(())
}

fn member(value: i32) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    response.extend(row(&[Some(&value.to_be_bytes())]));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response
}

#[test]
fn one_sync_and_multiple_borrowed_rows_have_exact_member_indices() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for _ in 0..2 {
            execution_open(socket, &statement)?;
        }
        if !expect(socket, b'S')?.is_empty() {
            return Err(invalid());
        }
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&1_i32.to_be_bytes())]));
        response.extend(row(&[Some(&2_i32.to_be_bytes())]));
        response.extend(frame(b'C', b"SELECT 2\0"));
        response.extend(member(3));
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
        let requests = [request(&statement, &[]), request(&statement, &[])];
        let mut rows = Vec::new();
        let mut commands = Vec::new();
        let completion = connection
            .query_group_provisional_visit(&requests, visit_limits(), |event| {
                match event {
                    ProvisionalGroupEvent::Row { index, row } => {
                        rows.push((index, row.decoder().decode_next::<i32>()?))
                    }
                    ProvisionalGroupEvent::Command {
                        index,
                        command,
                        rows_affected,
                        rows_returned,
                    } => {
                        assert_eq!(command, CommandKind::Select);
                        commands.push((index, rows_affected, rows_returned));
                    }
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(rows, [(0, 1), (0, 2), (1, 3)]);
        assert_eq!(commands, [(0, Some(2), 2), (1, Some(1), 1)]);
        assert_eq!((completion.requests, completion.rows_returned), (2, 3));
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn dropped_polled_group_poisoned_even_after_command_callback() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        socket.write_all(&member(1))?;
        wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let observed = Rc::new(Cell::new(false));
        let output = observed.clone();
        let mut future = Box::pin(connection.query_group_provisional_visit(
            &requests,
            visit_limits(),
            move |event| {
                if matches!(event, ProvisionalGroupEvent::Command { .. }) {
                    output.set(true);
                }
                Ok(())
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            if observed.get() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        drop(future);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        assert!(matches!(
            connection
                .query_group_provisional_visit(&[], visit_limits(), |_| Ok(()))
                .await
                .map_err(|error| error.source),
            Err(Error::Broken)
        ));
        release.send(()).unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn callback_error_and_panic_discard_the_session() {
    for panic in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            socket.write_all(&member(1))?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[])];
            let calls = Cell::new(0);
            let result = AssertUnwindSafe(connection.query_group_provisional_visit(
                &requests,
                visit_limits(),
                |_| {
                    calls.set(calls.get() + 1);
                    assert!(!panic, "injected group callback panic");
                    Err(Error::InvalidInput("injected callback error"))
                },
            ))
            .catch_unwind()
            .await;
            if panic {
                assert!(result.is_err());
            } else {
                assert!(matches!(
                    result.unwrap().map_err(|error| error.source),
                    Err(Error::InvalidInput("injected callback error"))
                ));
            }
            assert_eq!(calls.get(), 1);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn commit_failure_after_all_command_events_is_not_success() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        let mut response = member(1);
        response.extend(database_error("ERROR", "40001", "commit failed"));
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
        let commands = Cell::new(0);
        let error = connection
            .query_group_provisional_visit(&[request(&statement, &[])], visit_limits(), |event| {
                if matches!(event, ProvisionalGroupEvent::Command { .. }) {
                    commands.set(commands.get() + 1);
                }
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(commands.get(), 1);
        assert!(matches!(error.source, Error::Database(ref error) if error.code() == "40001"));
        assert_eq!(
            error.progress,
            GroupPipelineProgress {
                admitted_groups: 1,
                admitted_requests: 1,
                ..GroupPipelineProgress::default()
            }
        );
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn row_count_bytes_and_structure_fail_before_exposing_invalid_data() {
    for mode in 0..3 {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            let mut response = frame(b'2', &[]);
            response.extend(if mode == 2 {
                row(&[])
            } else {
                row(&[Some(&1_i32.to_be_bytes())])
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
            let mut selected = query_limits();
            if mode == 0 {
                selected.max_rows = 0;
            }
            if mode == 1 {
                selected.max_result_bytes = 11;
            }
            let request = PipelineRequest {
                statement: &statement,
                parameters: &[],
                limits: selected,
            };
            let observed = Cell::new(0);
            let error = connection
                .query_group_provisional_visit(&[request], visit_limits(), |_| {
                    observed.set(observed.get() + 1);
                    Ok(())
                })
                .await
                .unwrap_err();
            assert!(if mode == 2 {
                matches!(error.source, Error::Codec(_))
            } else {
                matches!(error.source, Error::Limit(_))
            });
            assert_eq!(observed.get(), 0);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn preflight_failure_sends_no_group_prefix_and_retains_idle_connection() {
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
        let valid = [Parameter::int4(1)];
        let invalid = [Parameter::text(Oid::TEXT, "bad")];
        let requests = [request(&statement, &valid), request(&statement, &invalid)];
        let error = connection
            .query_group_provisional_visit(&requests, visit_limits(), |_| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::InvalidInput(_)));
        assert_eq!(error.progress, GroupPipelineProgress::default());
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        assert!(connection.trim_send_buffer().unwrap() > 0);
        let limits = stream_limits(1);
        assert!(matches!(
            connection
                .query_groups_provisional_visit(
                    &mut std::iter::once(requests.as_slice()),
                    limits,
                    |_| Ok(())
                )
                .await
                .map_err(|error| error.source),
            Err(Error::InvalidInput(_))
        ));
        assert!((1..limits.max_packet_bytes).contains(&connection.trim_send_buffer().unwrap()));
        assert!(matches!(
            connection
                .query_groups_provisional_visit(
                    &mut std::iter::repeat_n(&requests[1..], 8),
                    stream_limits(8),
                    |_| Ok(()),
                )
                .await
                .map_err(|error| error.source),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(connection.trim_send_buffer().unwrap(), 0);
        assert_eq!(
            connection
                .query_group_provisional_visit(&[], visit_limits(), |_| Ok(()))
                .await
                .unwrap()
                .requests,
            0
        );
        connection.discard();
    });
    peer.finish();
}

#[test]
fn a_large_group_drains_duplex_backpressure_without_waiting_for_tx_first() {
    const RESPONSE: usize = 1024 * 1024;
    const INPUT: usize = 8 * 1024 * 1024;
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[17], &[("b", 17, -1)])?;
        execution_open(socket, &statement)?;
        let payload = vec![7; RESPONSE];
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&payload)]));
        response.extend(frame(b'C', b"SELECT 1\0"));
        socket.write_all(&response)?;
        // 客户端必须先读第一条响应，第二个 Bind 才能发完。
        wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(TcpConfig::plaintext(
            peer.endpoint,
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            WireLimits {
                receive_capacity: 2 * RESPONSE,
                max_frame_len: 2 * RESPONSE - 1,
                max_request_len: 10 * RESPONSE,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        ))
        .await;
        let statement = connection
            .prepare(
                "SELECT repeat('x',1048576)::bytea WHERE $1::bytea IS NOT NULL",
                &[Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let small = [Parameter::binary(Oid::BYTEA, b"x")];
        let input = vec![1; INPUT];
        let large = [Parameter::binary(Oid::BYTEA, &input)];
        let selected = QueryLimits {
            max_rows: 1,
            max_result_bytes: RESPONSE + 8,
            ..query_limits()
        };
        let requests = [
            PipelineRequest {
                statement: &statement,
                parameters: &small,
                limits: selected,
            },
            PipelineRequest {
                statement: &statement,
                parameters: &large,
                limits: selected,
            },
        ];
        let rows = Cell::new(0);
        let completion = connection
            .query_group_provisional_visit(
                &requests,
                ProvisionalGroupLimits {
                    max_member_result_bytes: RESPONSE + 8,
                    ..visit_limits()
                },
                |event| {
                    if let ProvisionalGroupEvent::Row { index, row } = event {
                        assert_eq!(index, rows.get());
                        let mut decoder = row.decoder();
                        let bytes = decoder.decode_next::<&[u8]>()?;
                        assert_eq!(bytes.len(), RESPONSE);
                        assert!(bytes.iter().all(|value| *value == 7));
                        rows.set(rows.get() + 1);
                        if index == 0 {
                            release.send(()).unwrap();
                        }
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (completion.requests, completion.rows_returned, rows.get()),
            (2, 2, 2)
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
    peer.finish();
}

fn live_config() -> TcpConfig {
    live::tcp_config(limits(), peer::TCP_OPTIONS)
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_multiple_rows_null_binary_and_successful_shared_sync() {
    run(async {
        let mut connection = connect(live_config()).await;
        let series = connection
            .prepare(
                "SELECT generate_series(1,3)::int4",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mixed = connection
            .prepare(
                "SELECT $1::int4,$2::text,$3::bytea",
                &[Oid::INT4, Oid::TEXT, Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let values = [
            Parameter::int4(42),
            Parameter::null(Oid::TEXT, Format::Binary),
            Parameter::binary(Oid::BYTEA, b"\0\xff"),
        ];
        let requests = [request(&series, &[]), request(&mixed, &values)];
        let mut numbers = Vec::new();
        let mut mixed_seen = false;
        let mut commands = Vec::new();
        let completion = connection
            .query_group_provisional_visit(&requests, visit_limits(), |event| {
                match event {
                    ProvisionalGroupEvent::Row { index: 0, row } => {
                        numbers.push(row.decoder().decode_next::<i32>()?)
                    }
                    ProvisionalGroupEvent::Row { index: 1, row } => {
                        let mut decoder = row.decoder();
                        assert_eq!(decoder.decode_next::<i32>()?, 42);
                        assert_eq!(decoder.decode_next::<Option<&str>>()?, None);
                        assert_eq!(decoder.decode_next::<&[u8]>()?, b"\0\xff");
                        decoder.finish()?;
                        mixed_seen = true;
                    }
                    ProvisionalGroupEvent::Row { .. } => panic!("unexpected member"),
                    ProvisionalGroupEvent::Command {
                        index,
                        rows_returned,
                        ..
                    } => commands.push((index, rows_returned)),
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(numbers, [1, 2, 3]);
        assert!(mixed_seen);
        assert_eq!(commands, [(0, 3), (1, 1)]);
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        assert_eq!(completion.rows_returned, 4);
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_sync_keeps_transaction_lease_open_until_explicit_end() {
    run(async {
        let mut connection = connect(live_config()).await;
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let first = [Parameter::int4(1)];
        let second = [Parameter::int4(2)];
        let requests = [request(&statement, &first), request(&statement, &second)];
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut observed = Vec::new();
        let completion = transaction
            .query_group_provisional_visit(&requests, visit_limits(), |event| {
                if let ProvisionalGroupEvent::Row { row, .. } = event {
                    observed.push(row.decoder().decode_next::<i32>()?);
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(observed, [1, 2]);
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_drop_and_callback_panic_poison_the_session() {
    run(async {
        let mut connection = connect(live_config()).await;
        let statement = connection
            .prepare(
                "SELECT pg_sleep(0.05)",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let mut pending =
            Box::pin(
                connection.query_group_provisional_visit(&requests, visit_limits(), |_| Ok(())),
            );
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(pending);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();

        let mut connection = connect(live_config()).await;
        let statement = connection
            .prepare("SELECT 1::int4", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let result = AssertUnwindSafe(connection.query_group_provisional_visit(
            &requests,
            visit_limits(),
            |_| panic!("injected live group callback panic"),
        ))
        .catch_unwind()
        .await;
        assert!(result.is_err());
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_large_input_and_output_progress_under_duplex_backpressure() {
    const RESPONSE: usize = 1024 * 1024;
    const INPUT: usize = 8 * 1024 * 1024;
    run(async {
        let mut connection = connect(live::tcp_config(
            WireLimits {
                receive_capacity: 2 * RESPONSE,
                max_frame_len: 2 * RESPONSE - 1,
                max_request_len: 10 * RESPONSE,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        ))
        .await;
        let statement = connection
            .prepare(
                "SELECT repeat('x',1048576)::bytea WHERE $1::bytea IS NOT NULL",
                &[Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let small = [Parameter::binary(Oid::BYTEA, b"x")];
        let payload = vec![1; INPUT];
        let large = [Parameter::binary(Oid::BYTEA, &payload)];
        let selected = QueryLimits {
            max_rows: 1,
            max_result_bytes: RESPONSE + 8,
            ..query_limits()
        };
        let requests = [
            PipelineRequest {
                statement: &statement,
                parameters: &small,
                limits: selected,
            },
            PipelineRequest {
                statement: &statement,
                parameters: &large,
                limits: selected,
            },
        ];
        let observed = Cell::new(0);
        let completion = connection
            .query_group_provisional_visit(
                &requests,
                ProvisionalGroupLimits {
                    max_member_result_bytes: RESPONSE + 8,
                    ..visit_limits()
                },
                |event| {
                    if let ProvisionalGroupEvent::Row { row, .. } = event {
                        let bytes = row.decoder().decode_next::<&[u8]>()?;
                        assert_eq!(bytes.len(), RESPONSE);
                        assert!(bytes.iter().all(|byte| *byte == b'x'));
                        observed.set(observed.get() + 1);
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (
                completion.requests,
                completion.rows_returned,
                observed.get()
            ),
            (2, 2, 2)
        );
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
}

fn stream_limits(inflight: usize) -> GroupPipelineLimits {
    GroupPipelineLimits {
        max_requests: 32,
        max_groups: 16,
        max_rows: 4096,
        max_member_result_bytes: 64 * 1024,
        max_packet_bytes: 8192,
        max_inflight_groups: inflight,
        scheduling: ExecutionScheduling::Uninterrupted,
    }
}

#[test]
fn group_stream_arbitrary_window_progresses_before_any_peer_response() {
    for inflight in [3, 8] {
        let groups = 11;
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            for _ in 0..inflight {
                execution_open(socket, &statement)?;
                expect(socket, b'S')?;
            }
            for index in 0..groups {
                let mut response = member(i32::try_from(index).unwrap());
                response.extend(ready());
                socket.write_all(&response)?;
                if index + inflight < groups {
                    execution_open(socket, &statement)?;
                    expect(socket, b'S')?;
                }
            }
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[])];
            let mut source = std::iter::repeat_n(requests.as_slice(), groups);
            let mut rows = Vec::new();
            let completion = connection
                .query_groups_provisional_visit(&mut source, stream_limits(inflight), |event| {
                    if let ProvisionalGroupEvent::Row { index, row } = event {
                        rows.push((index, row.decoder().decode_next::<i32>()?));
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(completion.groups, groups);
            assert_eq!(completion.requests, groups);
            assert_eq!(
                rows,
                (0..groups)
                    .map(|index| (index, i32::try_from(index).unwrap()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn dynamic_and_frozen_windows_keep_duplex_progress_under_both_send_policies() {
    for frozen in [false, true] {
        for policy in [
            compio_postgres::SendPolicy::BeforeBufferedRead,
            compio_postgres::SendPolicy::CoalesceBuffered,
        ] {
            for inflight in [1, 2, 4] {
                let groups = 7;
                let peer = Peer::short_queries(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[], &[("n", 23, 4)])?;
                    // 只有对端收齐整个在途窗口才会发送响应，可据此发现接纳循环等待过早。
                    for _ in 0..inflight {
                        execution_open(socket, &statement)?;
                        expect(socket, b'S')?;
                    }
                    for index in 0..groups {
                        let mut response = member(i32::try_from(index).unwrap());
                        response.extend(ready());
                        socket.write_all(&response)?;
                        if index + inflight < groups {
                            execution_open(socket, &statement)?;
                            expect(socket, b'S')?;
                        }
                    }
                    peer::eof(socket)
                });
                run(async {
                    let mut connection = connect(peer.config()).await;
                    let statement = connection
                        .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
                        .await
                        .unwrap();
                    connection.set_send_policy(policy).unwrap();
                    let requests = [request(&statement, &[])];
                    let selected = stream_limits(inflight);
                    let mut rows = Vec::new();
                    let mut on_event = |event: ProvisionalGroupEvent<'_>| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            rows.push((index, row.decoder().decode_next::<i32>()?));
                        }
                        Ok(())
                    };
                    let completion = if frozen {
                        let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                        connection
                            .replay_frozen_groups_provisional_visit(
                                group,
                                groups,
                                selected,
                                &mut on_event,
                            )
                            .await
                            .unwrap()
                            .1
                    } else {
                        connection
                            .query_groups_provisional_visit(
                                &mut std::iter::repeat_n(requests.as_slice(), groups),
                                selected,
                                &mut on_event,
                            )
                            .await
                            .unwrap()
                    };
                    assert_eq!((completion.groups, completion.requests), (groups, groups));
                    assert_eq!(
                        rows,
                        (0..groups)
                            .map(|index| (index, i32::try_from(index).unwrap()))
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    connection.close_local().await.unwrap();
                });
                peer.finish();
            }
        }
    }
}

#[test]
fn group_windows_preserve_session_and_transaction_boundaries() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for status in *b"IT" {
            if status == b'T' {
                peer::control(socket, b"BEGIN\0", b"BEGIN\0", status)?;
            }
            // 不先回复第一组，验证会话与事务均能填满两个在途组。
            for _ in 0..2 {
                execution_open(socket, &statement)?;
                expect(socket, b'S')?;
            }
            for n in [11, 12] {
                let mut response = member(n);
                response.extend(peer::ready(status));
                socket.write_all(&response)?;
            }
        }
        peer::control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let mut observed = Vec::new();
        let visit = connection
            .query_groups_provisional_visit(
                &mut std::iter::repeat_n(requests.as_slice(), 2),
                stream_limits(2),
                |event| {
                    if let ProvisionalGroupEvent::Row { index, row } = event {
                        observed.push((index, row.decoder().decode_next::<i32>()?));
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(observed, [(0, 11), (1, 12)]);
        assert_eq!(
            (visit.groups, visit.requests, visit.transaction_status),
            (2, 2, TransactionStatus::Idle)
        );

        let mut transaction = connection.begin_transaction().await.unwrap();
        observed.clear();
        let consumed = transaction
            .query_groups_provisional_consume(
                &mut std::iter::repeat_n(requests.as_slice(), 2),
                stream_limits(2),
                |event| {
                    if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                        observed.push((index, row.decode_next::<i32>()?));
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(observed, [(0, 11), (1, 12)]);
        assert_eq!(
            (
                consumed.groups,
                consumed.requests,
                consumed.transaction_status
            ),
            (2, 2, TransactionStatus::InTransaction)
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn rejected_group_transaction_control_preserves_an_observed_commit() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[])?;
        peer::control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        socket.write_all(&frame(b'2', &[]))?;
        socket.write_all(&frame(b'C', b"COMMIT\0"))?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("COMMIT", &[], ResultFormats::All(Format::Text))
            .await
            .unwrap();
        {
            let mut transaction = connection.begin_transaction().await.unwrap();
            let result = transaction
                .query_group_provisional_visit(&[request(&statement, &[])], visit_limits(), |_| {
                    Ok(())
                })
                .await;
            let error = result.unwrap_err();
            assert!(matches!(error.source, Error::Unsupported(_)));
            assert_eq!(
                error.progress,
                GroupPipelineProgress {
                    admitted_groups: 1,
                    admitted_requests: 1,
                    ..GroupPipelineProgress::default()
                }
            );
        }
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        assert_eq!(
            connection.take_transaction_end(),
            Some(TransactionEnd::Committed)
        );
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn group_stream_one_and_two_inflight_keep_global_order_and_skip_empty_inputs() {
    for inflight in [1, 2] {
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution_open(socket, &statement)?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            if inflight == 2 {
                // 对端收到两组请求后才发送第一条响应。
                execution_open(socket, &statement)?;
                expect(socket, b'S')?;
            }
            let mut response = member(1);
            response.extend(member(2));
            response.extend(ready());
            socket.write_all(&response)?;
            if inflight == 1 {
                execution_open(socket, &statement)?;
                expect(socket, b'S')?;
            }
            let mut response = member(3);
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
            let first = [request(&statement, &[]), request(&statement, &[])];
            let second = [request(&statement, &[])];
            let empty = &[][..];
            let inputs = [empty, &first[..], empty, &second[..], empty];
            let examined = Cell::new(0);
            let mut source = inputs
                .into_iter()
                .inspect(|_| examined.set(examined.get() + 1));
            let mut rows = Vec::new();
            let mut commands = Vec::new();
            let completion = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_groups: 5,
                        ..stream_limits(inflight)
                    },
                    |event| {
                        match event {
                            ProvisionalGroupEvent::Row { index, row } => {
                                if index == 0 {
                                    assert_eq!(examined.get(), if inflight == 1 { 2 } else { 4 });
                                }
                                rows.push((index, row.decoder().decode_next::<i32>()?));
                            }
                            ProvisionalGroupEvent::Command { index, .. } => commands.push(index),
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!(rows, [(0, 1), (1, 2), (2, 3)]);
            assert_eq!(commands, [0, 1, 2]);
            assert_eq!(
                (
                    completion.requests,
                    completion.groups,
                    completion.rows_returned
                ),
                (3, 2, 3)
            );
            assert_eq!(examined.get(), 5);
            assert_eq!(completion.transaction_status, TransactionStatus::Idle);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn group_stream_late_invalid_and_limits_never_silently_drop_sql() {
    for mode in 0..3 {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[("n", 23, 4)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            let mut response = member(1);
            response.extend(ready());
            socket.write_all(&response)?;
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
            let good = [Parameter::int4(1)];
            let bad = [Parameter::text(Oid::TEXT, "invalid")];
            let first = [request(&statement, &good)];
            let second = [request(&statement, if mode == 0 { &bad } else { &good })];
            let mut source = [&first[..], &second[..]].into_iter();
            let mut selected = stream_limits(1);
            if mode == 1 {
                selected.max_requests = 1;
            }
            if mode == 2 {
                selected.max_groups = 1;
            }
            let rows = Cell::new(0);
            let error = connection
                .query_groups_provisional_visit(&mut source, selected, |event| {
                    if matches!(event, ProvisionalGroupEvent::Row { .. }) {
                        rows.set(rows.get() + 1);
                    }
                    Ok(())
                })
                .await
                .unwrap_err();
            assert!(match mode {
                0 => matches!(error.source, Error::InvalidInput(_)),
                1 => matches!(
                    error.source,
                    Error::Limit("group stream exceeds its request limit")
                ),
                _ => matches!(
                    error.source,
                    Error::Limit("group stream exceeds its input group limit")
                ),
            });
            assert_eq!(
                (
                    error.progress.admitted_groups,
                    error.progress.admitted_requests,
                    error.progress.ready_groups,
                    error.progress.ready_requests,
                    error.progress.last_ready_transaction_status,
                ),
                (1, 1, 1, 1, Some(TransactionStatus::Idle))
            );
            assert_eq!(rows.get(), 1);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn group_stream_empty_source_and_empty_group_budget_do_not_admit_sql() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let mut source = std::iter::empty::<&[PipelineRequest<'_>]>();
        let completion = connection
            .query_groups_provisional_visit(&mut source, stream_limits(2), |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            (
                completion.groups,
                completion.requests,
                completion.rows_returned
            ),
            (0, 0, 0)
        );
        let empty = &[][..];
        let mut source = std::iter::repeat(empty);
        let error = connection
            .query_groups_provisional_visit(
                &mut source,
                GroupPipelineLimits {
                    max_groups: 2,
                    ..stream_limits(2)
                },
                |_| Ok(()),
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert_eq!(error.progress.admitted_groups, 0);
        assert_eq!(error.progress.ready_groups, 0);
        assert_eq!(error.progress.last_ready_transaction_status, None);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn dropped_group_stream_poisoned_with_a_queued_successor() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        for _ in 0..2 {
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
        }
        socket.write_all(&member(1))?;
        wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let group = [request(&statement, &[])];
        let mut source = std::iter::repeat_n(&group[..], 2);
        let observed = Rc::new(Cell::new(false));
        let output = observed.clone();
        let mut pending = Box::pin(connection.query_groups_provisional_visit(
            &mut source,
            stream_limits(2),
            move |event| {
                if matches!(event, ProvisionalGroupEvent::Command { .. }) {
                    output.set(true);
                }
                Ok(())
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            if observed.get() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        drop(pending);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        release.send(()).unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn group_stream_large_packet_windows_progress_while_responses_are_backpressured() {
    const RESPONSE: usize = 1024 * 1024;
    const INPUT: usize = 8 * 1024 * 1024;
    for inflight in [1, 2, 4] {
        let groups = 4;
        let (release, wait) = mpsc::channel();
        let peer = Peer::short_queries(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[17], &[("b", 17, -1)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            let payload = vec![9; RESPONSE];
            let mut response = frame(b'2', &[]);
            response.extend(row(&[Some(&payload)]));
            response.extend(frame(b'C', b"SELECT 1\0"));
            response.extend(ready());
            socket.write_all(&response)?;
            // 客户端必须先处理第一行，后续 8 MiB 请求才能发完。
            wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
            for _ in 1..groups {
                execution_open(socket, &statement)?;
                expect(socket, b'S')?;
                socket.write_all(&response)?;
            }
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(TcpConfig::plaintext(
                peer.endpoint,
                "test",
                "test",
                AuthenticationPolicy::AllowAuthenticationOk,
                WireLimits {
                    receive_capacity: 2 * RESPONSE,
                    max_frame_len: 2 * RESPONSE - 1,
                    max_request_len: 10 * RESPONSE,
                    max_messages_per_request: 128,
                },
                peer::TCP_OPTIONS,
            ))
            .await;
            let statement = connection
                .prepare(
                    "SELECT repeat('x',1048576)::bytea WHERE $1::bytea IS NOT NULL",
                    &[Oid::BYTEA],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let payload = vec![1; INPUT];
            let parameters = [Parameter::binary(Oid::BYTEA, &payload)];
            let group = [PipelineRequest {
                statement: &statement,
                parameters: &parameters,
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: RESPONSE + 8,
                    ..query_limits()
                },
            }];
            let mut source = std::iter::repeat_n(&group[..], groups);
            let rows = Cell::new(0);
            let completion = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_requests: groups,
                        max_groups: groups,
                        max_rows: groups,
                        max_member_result_bytes: RESPONSE + 8,
                        max_packet_bytes: 10 * RESPONSE,
                        max_inflight_groups: inflight,
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    |event| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            assert_eq!(index, rows.get());
                            let value = row.decoder().decode_next::<&[u8]>()?;
                            assert_eq!(value.len(), RESPONSE);
                            assert!(value.iter().all(|byte| *byte == 9));
                            rows.set(rows.get() + 1);
                            if index == 0 {
                                release.send(()).unwrap();
                            }
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                (
                    completion.groups,
                    completion.requests,
                    completion.rows_returned,
                    rows.get()
                ),
                (groups, groups, groups, groups)
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_stream_one_two_modes_and_transaction_preserve_results() {
    run(async {
        let mut connection = connect(live_config()).await;
        let statement = connection
            .prepare(
                "SELECT $1::int4,NULL::bytea",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let first = [Parameter::int4(11)];
        let second = [Parameter::int4(12)];
        let a = [request(&statement, &first)];
        let b = [request(&statement, &second), request(&statement, &first)];
        for inflight in [1, 2] {
            let mut source = [&a[..], &b[..]].into_iter();
            let mut observed = Vec::new();
            let completion = connection
                .query_groups_provisional_visit(&mut source, stream_limits(inflight), |event| {
                    if let ProvisionalGroupEvent::Row { index, row } = event {
                        let mut decoder = row.decoder();
                        let value = decoder.decode_next::<i32>()?;
                        assert_eq!(decoder.decode_next::<Option<&[u8]>>()?, None);
                        observed.push((index, value));
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(observed, [(0, 11), (1, 12), (2, 11)]);
            assert_eq!(
                (
                    completion.groups,
                    completion.requests,
                    completion.rows_returned
                ),
                (2, 3, 3)
            );
        }
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut source = [&a[..], &b[..]].into_iter();
        let completion = transaction
            .query_groups_provisional_visit(&mut source, stream_limits(2), |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_group_stream_two_large_requests_and_large_responses_do_not_deadlock() {
    const RESPONSE: usize = 1024 * 1024;
    const INPUT: usize = 8 * 1024 * 1024;
    run(async {
        let mut connection = connect(live::tcp_config(
            WireLimits {
                receive_capacity: 2 * RESPONSE,
                max_frame_len: 2 * RESPONSE - 1,
                max_request_len: 10 * RESPONSE,
                max_messages_per_request: 128,
            },
            peer::TCP_OPTIONS,
        ))
        .await;
        let statement = connection
            .prepare(
                "SELECT repeat('x',1048576)::bytea WHERE $1::bytea IS NOT NULL",
                &[Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let payload = vec![1; INPUT];
        let parameters = [Parameter::binary(Oid::BYTEA, &payload)];
        let group = [PipelineRequest {
            statement: &statement,
            parameters: &parameters,
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: RESPONSE + 8,
                ..query_limits()
            },
        }];
        for inflight in [1, 2] {
            let mut source = std::iter::repeat_n(&group[..], 2);
            let mut rows = 0;
            let completion = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_requests: 2,
                        max_groups: 2,
                        max_rows: 2,
                        max_member_result_bytes: RESPONSE + 8,
                        max_packet_bytes: 10 * RESPONSE,
                        max_inflight_groups: inflight,
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    |event| {
                        if let ProvisionalGroupEvent::Row { row, .. } = event {
                            let bytes = row.decoder().decode_next::<&[u8]>()?;
                            assert_eq!(bytes.len(), RESPONSE);
                            assert!(bytes.iter().all(|byte| *byte == b'x'));
                            rows += 1;
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                (
                    completion.groups,
                    completion.requests,
                    completion.rows_returned,
                    rows
                ),
                (2, 2, 2, 2)
            );
        }
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 SCRAM 实例以及在当前 schema 中创建表和序列的权限"]
fn live_group_sql_error_rolls_back_prior_insert_and_skips_the_successor() {
    live_write_groups(false);
}

#[test]
#[ignore = "需要 PostgreSQL 19 SCRAM 实例以及在当前 schema 中创建表和序列的权限"]
fn live_group_stream_sql_error_keeps_the_first_ready_group_committed() {
    live_write_groups(true);
}

fn live_write_groups(multiple: bool) {
    use compio_postgres::{ClientOptions, OnError};
    use std::time::{SystemTime, UNIX_EPOCH};

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let config = live_config();
        let options = ClientOptions::short_queries(config.clone());
        let mut observer = compio::time::timeout(
            DEADLINE,
            compio_postgres::TcpConnection::connect(options.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let table = format!(
            "cpg_group_{:x}_{nonce:x}",
            observer.server_info().process_id
        );
        let sequence = format!("{table}_seq");
        const BINARY: ResultFormats = ResultFormats::All(Format::Binary);
        let create = format!(
            "CREATE TABLE {table} (n int4 GENERATED ALWAYS AS IDENTITY (SEQUENCE NAME {sequence}))"
        );
        let mut may_exist = false;
        let checked = AssertUnwindSafe(compio::time::timeout(DEADLINE, async {
            may_exist = true;
            let setup = observer
                .one_shot(&create, &[], BINARY)
                .command_ready(OnError::DrainToReady)
                .await;
            if matches!(&setup, Err(Error::Database(_))) {
                may_exist = false;
            }
            setup.unwrap();

            let mut connection = connect(config).await;
            let insert = connection
                .prepare(
                    &format!("INSERT INTO {table} DEFAULT VALUES"),
                    &[],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let fail = connection
                .prepare(
                    "SELECT 10/$1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let zero = [Parameter::int4(0)];
            let failed_group = [
                request(&insert, &[]),
                request(&fail, &zero),
                request(&insert, &[]),
            ];
            let mut observed = Vec::new();
            let visitor = |event: ProvisionalGroupEvent<'_>| {
                if let ProvisionalGroupEvent::Command {
                    index,
                    command,
                    rows_affected,
                    ..
                } = event
                {
                    assert_eq!(command, CommandKind::Insert);
                    assert_eq!(rows_affected, Some(1));
                    observed.push(index);
                }
                Ok(())
            };
            let error = if multiple {
                let successful_group = [request(&insert, &[]), request(&insert, &[])];
                let mut source = [successful_group.as_slice(), failed_group.as_slice()].into_iter();
                let failure = connection
                    .query_groups_provisional_visit(&mut source, stream_limits(1), visitor)
                    .await
                    .unwrap_err();
                assert_eq!(
                    (
                        failure.progress.admitted_groups,
                        failure.progress.admitted_requests,
                        failure.progress.ready_groups,
                        failure.progress.ready_requests,
                        failure.progress.last_ready_transaction_status,
                    ),
                    (2, 5, 1, 2, Some(TransactionStatus::Idle))
                );
                failure
            } else {
                let failure = connection
                    .query_group_provisional_visit(&failed_group, visit_limits(), visitor)
                    .await
                    .unwrap_err();
                assert_eq!(
                    failure.progress,
                    GroupPipelineProgress {
                        admitted_groups: 1,
                        admitted_requests: failed_group.len(),
                        ..GroupPipelineProgress::default()
                    }
                );
                failure
            };
            assert!(matches!(error.source, Error::Database(ref error) if error.code() == "22012"));
            assert_eq!(
                observed.as_slice(),
                if multiple { &[0, 1, 2][..] } else { &[0][..] }
            );
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
            let sql = format!(
                "SELECT (SELECT array_agg(n ORDER BY n)::text FROM {table}), last_value, is_called
                 FROM {sequence}"
            );
            let observed = observer
                .one_shot(&sql, &[], BINARY)
                .map_provisional_one(OnError::DrainToReady, |row| {
                    let mut fields = row.decoder();
                    let values = fields.decode_next::<Option<String>>()?;
                    let last = fields.decode_next::<i64>()?;
                    let called = fields.decode_next::<bool>()?;
                    fields.finish()?;
                    Ok((values, last, called))
                })
                .await
                .unwrap();
            assert_eq!(observed.0.as_deref(), multiple.then_some("{1,2}"));
            // 序列的消耗在回滚后仍可观察。末次插入成功执行，错误后的同组插入未执行。
            assert_eq!(
                (observed.1, observed.2),
                (if multiple { 3 } else { 1 }, true)
            );
        }))
        .catch_unwind()
        .await;

        // IDENTITY 序列由表持有。检查超时或断言失败后仍只清理本次创建的对象。
        let cleanup = compio::time::timeout(DEADLINE, async {
            if !may_exist {
                return Ok(());
            }
            if observer.reuse_state() != ReuseState::ProtocolIdle
                && observer.recover_to_ready().await.is_err()
            {
                observer = compio_postgres::TcpConnection::connect(options).await?;
            }
            let sql = format!("DROP TABLE IF EXISTS {table} RESTRICT");
            observer
                .one_shot(&sql, &[], BINARY)
                .command_ready(OnError::DrainToReady)
                .await
                .map(|_| ())
        })
        .await;
        if !matches!(&cleanup, Ok(Ok(_))) {
            eprintln!("无法清理测试表 {table}：{cleanup:?}");
        }
        match checked {
            Ok(result) => result.expect("共享 Sync 组的回滚验证超时"),
            Err(panic) => std::panic::resume_unwind(panic),
        }
        cleanup.unwrap().unwrap();
    });
}

#[test]
fn provisional_consume_validates_unread_fields_and_reports_normal_commands() {
    let peer = Peer::short_queries(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4), ("value", 17, -1)])?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&42_i32.to_be_bytes()), None]));
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(ready());
        socket.write_all(&response)?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare(
                "SELECT 42,NULL::bytea",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let mut seen = Vec::new();
        let mut commands = 0;
        let completion = connection
            .query_group_provisional_consume(&requests, visit_limits(), |event| {
                match event {
                    ProvisionalGroupConsumeEvent::Row { index, row } => {
                        seen.push((index, row.decode_next::<i32>()?));
                        assert_eq!(row.remaining(), 1);
                        // 驱动还须校验并跳过业务代码没有读取的 NULL 字段。
                    }
                    ProvisionalGroupConsumeEvent::Command {
                        index,
                        command,
                        rows_affected,
                        rows_returned,
                    } => {
                        assert_eq!(
                            (index, command, rows_affected, rows_returned),
                            (0, CommandKind::Select, Some(1), 1)
                        );
                        commands += 1;
                    }
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(seen, [(0, 42)]);
        assert_eq!(commands, 1);
        assert_eq!((completion.requests, completion.rows_returned), (1, 1));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn provisional_consume_exposes_prefix_before_bad_suffix_but_checked_visit_does_not() {
    for consuming in [false, true] {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4), ("value", 17, -1)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            let mut body = Vec::from(2_u16.to_be_bytes());
            body.extend_from_slice(&4_i32.to_be_bytes());
            body.extend_from_slice(&42_i32.to_be_bytes());
            body.extend_from_slice(&(-2_i32).to_be_bytes());
            let mut response = frame(b'2', &[]);
            response.extend(frame(b'D', &body));
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare(
                    "SELECT 42,NULL::bytea",
                    &[],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let requests = [request(&statement, &[])];
            let mut observed = false;
            let result = if consuming {
                connection
                    .query_group_provisional_consume(&requests, visit_limits(), |event| {
                        if let ProvisionalGroupConsumeEvent::Row { row, .. } = event {
                            assert_eq!(row.decode_next::<i32>()?, 42);
                            observed = true;
                        }
                        Ok(())
                    })
                    .await
            } else {
                connection
                    .query_group_provisional_visit(&requests, visit_limits(), |event| {
                        if matches!(event, ProvisionalGroupEvent::Row { .. }) {
                            observed = true;
                        }
                        Ok(())
                    })
                    .await
            };
            let error = result.unwrap_err();
            assert!(if consuming {
                matches!(error.source, Error::Codec(_))
            } else {
                matches!(error.source, Error::Protocol(_))
            });
            assert_eq!(observed, consuming);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn provisional_consume_ignored_decode_error_callback_error_and_panic_discard() {
    for failure in 0..3 {
        let peer = Peer::short_queries(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[("n", 23, 4)])?;
            execution_open(socket, &statement)?;
            expect(socket, b'S')?;
            socket.write_all(&member(42))?;
            peer::eof(socket)
        });
        run(async {
            let mut connection = connect(peer.config()).await;
            let statement = connection
                .prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let requests = [request(&statement, &[])];
            let result = AssertUnwindSafe(connection.query_group_provisional_consume(
                &requests,
                visit_limits(),
                |event| {
                    if let ProvisionalGroupConsumeEvent::Row { row, .. } = event {
                        match failure {
                            0 => {
                                assert!(row.decode_next::<i64>().is_err());
                            }
                            1 => return Err(Error::InvalidInput("consume callback failure")),
                            _ => panic!("consume callback panic"),
                        }
                    }
                    Ok(())
                },
            ))
            .catch_unwind()
            .await;
            if failure == 2 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn dropped_provisional_consume_stream_discards_after_a_row() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::short_queries(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[("n", 23, 4)])?;
        execution_open(socket, &statement)?;
        expect(socket, b'S')?;
        socket.write_all(&member(42))?;
        wait.recv_timeout(DEADLINE).map_err(|_| invalid())?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = connect(peer.config()).await;
        let statement = connection
            .prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [request(&statement, &[])];
        let mut groups = std::iter::once(requests.as_slice());
        let observed = Rc::new(Cell::new(false));
        let output = observed.clone();
        let mut future = Box::pin(connection.query_groups_provisional_consume(
            &mut groups,
            stream_limits(2),
            move |event| {
                if let ProvisionalGroupConsumeEvent::Row { row, .. } = event {
                    assert_eq!(row.decode_next::<i32>()?, 42);
                    output.set(true);
                }
                Ok(())
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            if observed.get() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        drop(future);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        release.send(()).unwrap();
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_provisional_consume_single_stream_and_transaction_validate_results() {
    run(async {
        let mut connection = connect(live_config()).await;
        let statement = connection
            .prepare(
                "SELECT $1::int4,NULL::text,decode('00ff07','hex')::bytea",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let first = [Parameter::int4(11)];
        let second = [Parameter::int4(12)];
        let requests = [request(&statement, &first), request(&statement, &second)];
        let mut values = Vec::new();
        let result = connection
            .query_group_provisional_consume(&requests, visit_limits(), |event| {
                if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                    let value = row.decode_next::<i32>()?;
                    assert_eq!(value, [11, 12][index]);
                    values.push(value);
                    // 驱动还须校验未读的 NULL 和 bytea 字段的长度与边界。
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(values, [11, 12]);
        assert_eq!(
            (result.requests, result.groups, result.rows_returned),
            (2, 1, 2)
        );
        for inflight in [1, 2] {
            let mut source = std::iter::repeat_n(requests.as_slice(), 3);
            let mut rows = 0;
            let result = connection
                .query_groups_provisional_consume(&mut source, stream_limits(inflight), |event| {
                    if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                        assert_eq!(index, rows);
                        assert_eq!(row.decode_next::<i32>()?, [11, 12][index % 2]);
                        assert_eq!(row.decode_next::<Option<&str>>()?, None);
                        assert_eq!(row.decode_next::<&[u8]>()?, b"\0\xff\x07");
                        rows += 1;
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                (rows, result.requests, result.groups, result.rows_returned),
                (6, 6, 3, 6)
            );
            assert_eq!(result.transaction_status, TransactionStatus::Idle);
        }
        let mut transaction = connection.begin_transaction().await.unwrap();
        transaction
            .query_group_provisional_consume(&requests, visit_limits(), |_| Ok(()))
            .await
            .unwrap();
        let mut source = std::iter::once(requests.as_slice());
        let result = transaction
            .query_groups_provisional_consume(&mut source, stream_limits(2), |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(result.transaction_status, TransactionStatus::InTransaction);
        transaction.rollback().await.unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
}
