//! 批量准备命名语句时，每个成员保留独立的 Parse、Describe 和 Sync 边界。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{
    close_complete, database_error, expect_closes, handshake, no_data, prepare_no_data,
    read_prepare,
};
use peer::{IO_DEADLINE, Peer, control, eof, frame, invalid, ready, run};

use compio_postgres::{
    Error, ResultFormats, ReuseState, StatementLimits, StatementPipelineLimits, TcpConfig,
    TransactionStatus, WireLimits,
    expert::{PrepareRequest, PreparedStatement, TcpSession as TcpConnection},
    types::Format,
};
use std::{io::Write, sync::mpsc};

const WIRE: WireLimits = WireLimits {
    receive_capacity: 8192,
    max_frame_len: 8191,
    max_request_len: 8192,
    max_messages_per_request: 8,
};

fn limits() -> StatementPipelineLimits {
    StatementPipelineLimits {
        max_statements: 16,
        max_packet_bytes: 8192,
        max_result_bytes: 8192,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
        },
    }
}
fn request(sql: &str) -> PrepareRequest<'_> {
    PrepareRequest {
        sql,
        parameter_oids: &[],
        formats: ResultFormats::All(Format::Binary),
    }
}
fn close_limits() -> StatementPipelineLimits {
    StatementPipelineLimits {
        max_statements: 16,
        max_packet_bytes: 8192,
        max_result_bytes: 8192,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
        },
    }
}
async fn connect(config: TcpConfig) -> TcpConnection {
    let mut session = TcpConnection::connect(config).await.unwrap();
    session
        .configure_statements(StatementLimits {
            max_statements: 16,
            max_metadata_bytes: 65536,
        })
        .unwrap();
    session
}
async fn statements(session: &mut TcpConnection, count: usize) -> Vec<PreparedStatement> {
    let mut statements = Vec::new();
    for _ in 0..count {
        statements.push(
            session
                .prepare("UPDATE t SET n=n", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap(),
        );
    }
    statements
}

#[test]
fn local_preflight_is_atomic_and_named_members_are_sent_before_any_reply() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let names = [read_prepare(socket)?, read_prepare(socket)?];
        assert_eq!(names, [":p1", ":p2"]);
        let mut response = no_data(b'I');
        response.extend(no_data(b'I'));
        socket.write_all(&response)?;
        expect_closes(socket, &names)?;
        let mut response = close_complete(b'I');
        response.extend(close_complete(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let empty = StatementPipelineLimits {
            max_statements: 0,
            max_packet_bytes: 0,
            max_result_bytes: 0,
            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
        };
        assert!(
            session
                .prepare_pipeline(Vec::new(), empty)
                .await
                .unwrap()
                .is_empty()
        );
        for bad in [
            StatementPipelineLimits {
                max_statements: 1,
                ..limits()
            },
            StatementPipelineLimits {
                max_packet_bytes: 1,
                ..limits()
            },
            StatementPipelineLimits {
                max_result_bytes: 0,
                ..limits()
            },
        ] {
            let error = session
                .prepare_pipeline(
                    vec![request("UPDATE t SET n=n"), request("UPDATE t SET n=n")],
                    bad,
                )
                .await
                .unwrap_err();
            assert!(!error.may_have_created);
            assert!(error.completed.is_empty());
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        }
        let error = session
            .prepare_pipeline(
                vec![request("UPDATE t SET n=n"), request("bad\0SQL")],
                limits(),
            )
            .await
            .unwrap_err();
        assert!(!error.may_have_created);
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        let results = session
            .prepare_pipeline(
                vec![request("UPDATE t SET n=n"), request("UPDATE t SET n=n")],
                limits(),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            session
                .close_all_statements_pipeline(close_limits())
                .await
                .unwrap()
                .len(),
            2
        );
        drop(results);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        session.discard();
    });
    peer.finish();
}

#[test]
fn ordinary_parse_or_describe_error_keeps_created_name_obligations_and_successors() {
    for created in [false, true] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let names = [
                read_prepare(socket)?,
                read_prepare(socket)?,
                read_prepare(socket)?,
            ];
            let mut response = no_data(b'I');
            if created {
                response.extend(frame(b'1', &[]));
            }
            response.extend(if created {
                database_error("ERROR", "XX000", "fixture Describe failure")
            } else {
                database_error("ERROR", "42601", "fixture Parse failure")
            });
            response.extend(ready(b'I'));
            response.extend(no_data(b'I'));
            socket.write_all(&response)?;
            let close_names = if created {
                names.to_vec()
            } else {
                vec![names[0].clone(), names[2].clone()]
            };
            expect_closes(socket, &close_names)?;
            let mut response = Vec::new();
            for _ in &close_names {
                response.extend(close_complete(b'I'));
            }
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let mut session = connect(peer.config_with_limits(WIRE)).await;
            let results = session
                .prepare_pipeline(
                    vec![
                        request("UPDATE t SET n=n"),
                        request("broken"),
                        request("UPDATE t SET n=n"),
                    ],
                    limits(),
                )
                .await
                .unwrap();
            assert_eq!(results.len(), 3);
            assert!(results[0].is_ok());
            assert_eq!(
                results[1].as_ref().unwrap_err().code(),
                if created { "XX000" } else { "42601" }
            );
            assert!(results[2].is_ok());
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            let closed = session
                .close_all_statements_pipeline(close_limits())
                .await
                .unwrap();
            assert_eq!(closed.len(), if created { 3 } else { 2 });
            drop(results);
            assert_eq!(session.reclaim_closed_statements().unwrap(), closed.len());
            session.discard();
        });
        peer.finish();
    }
}

#[test]
fn malformed_reply_and_retained_diagnostic_limit_keep_confirmed_prefix_only() {
    for (reply, malformed) in [
        (ready(b'I'), true),
        (
            [
                database_error("ERROR", "42601", "fixture Parse failure"),
                ready(b'I'),
            ]
            .concat(),
            false,
        ),
        (
            peer::prepared::database_error("FATAL", "57P01", "shutdown"),
            false,
        ),
    ] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            read_prepare(socket)?;
            read_prepare(socket)?;
            let mut response = no_data(b'I');
            response.extend(reply);
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let mut session = connect(peer.config_with_limits(WIRE)).await;
            let error = session
                .prepare_pipeline(
                    vec![request("UPDATE t SET n=n"), request("broken")],
                    StatementPipelineLimits {
                        max_result_bytes: 2 * std::mem::size_of::<
                            compio_postgres::expert::PrepareItem,
                        >(),
                        ..limits()
                    },
                )
                .await
                .unwrap_err();
            assert!(error.may_have_created);
            assert_eq!(error.completed.len(), 1);
            assert!(error.completed[0].is_ok());
            if malformed {
                assert!(matches!(error.source, Error::Protocol(_)));
            } else {
                assert!(matches!(error.source, Error::Limit(_)));
            }
            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
            session.discard();
        });
        peer.finish();
    }
}

#[test]
fn reply_metadata_limit_discards_and_exposes_only_the_confirmed_prefix() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        read_prepare(socket)?;
        read_prepare(socket)?;
        let mut response = no_data(b'I');
        response.extend(frame(b'1', &[]));
        response.extend(frame(b't', &0_u16.to_be_bytes()));
        let mut description = Vec::from(1_u16.to_be_bytes());
        description.extend(std::iter::repeat_n(b'x', 5000));
        description.push(0);
        description.extend_from_slice(&0_u32.to_be_bytes());
        description.extend_from_slice(&0_i16.to_be_bytes());
        description.extend_from_slice(&23_u32.to_be_bytes());
        description.extend_from_slice(&4_i16.to_be_bytes());
        description.extend_from_slice(&(-1_i32).to_be_bytes());
        description.extend_from_slice(&0_i16.to_be_bytes());
        response.extend(frame(b'T', &description));
        response.extend(ready(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = TcpConnection::connect(peer.config_with_limits(WIRE))
            .await
            .unwrap();
        session
            .configure_statements(StatementLimits {
                max_statements: 4,
                max_metadata_bytes: 4096,
            })
            .unwrap();
        let error = session
            .prepare_pipeline(
                vec![request("UPDATE t SET n=n"), request("SELECT 1")],
                limits(),
            )
            .await
            .unwrap_err();
        assert!(error.may_have_created);
        assert_eq!(error.completed.len(), 1);
        assert!(error.completed[0].is_ok());
        assert!(matches!(error.source, Error::Limit(_) | Error::Codec(_)));
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        session.discard();
    });
    peer.finish();
}

#[test]
fn dropped_waiter_recovers_prior_phases_before_ready_and_closes_undelivered_names() {
    use std::{
        future::{Future, poll_fn},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
    };

    for received in 1..=3 {
        let (release, wait) = mpsc::channel();
        let parsed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&parsed);
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let names = [
                read_prepare(socket)?,
                read_prepare(socket)?,
                read_prepare(socket)?,
            ];
            let phases = [
                frame(b'1', &[]),
                frame(b't', &0_u16.to_be_bytes()),
                frame(b'n', &[]),
            ];
            let mut response = phases[..received].concat();
            response.extend(frame(
                b'N',
                b"SNOTICE\0VNOTICE\0C00000\0Mprepare checkpoint\0\0",
            ));
            socket.write_all(&response)?;
            wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
            let mut response = phases[received..].concat();
            response.extend(ready(b'I'));
            response.extend(no_data(b'I'));
            response.extend(no_data(b'I'));
            socket.write_all(&response)?;
            expect_closes(socket, &names)?;
            let mut response = Vec::new();
            for _ in &names {
                response.extend(close_complete(b'I'));
            }
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let config = peer.config_with_limits(WIRE).notice_handler(move |notice| {
                assert_eq!(notice.message, "prepare checkpoint");
                marker.store(true, Ordering::Release);
            });
            let mut session = connect(config).await;
            let mut pending = Box::pin(session.prepare_pipeline(
                vec![
                    request("UPDATE t SET n=n"),
                    request("UPDATE t SET n=n"),
                    request("UPDATE t SET n=n"),
                ],
                StatementPipelineLimits {
                    scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                        max_work_per_turn: std::num::NonZeroUsize::MIN,
                    },
                    ..limits()
                },
            ));
            poll_fn(|cx| {
                assert!(
                    pending.as_mut().poll(cx).is_pending(),
                    "ReadyForQuery 响应尚未发送"
                );
                if parsed.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            drop(pending);
            assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
            release.send(()).unwrap();
            assert!(matches!(
                session.recover_to_ready().await,
                Err(Error::Limit(_))
            ));
            session.recover_to_ready().await.unwrap();
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            assert_eq!(
                session
                    .close_all_statements_pipeline(close_limits())
                    .await
                    .unwrap()
                    .len(),
                3
            );
            assert_eq!(session.reclaim_closed_statements().unwrap(), 3);
            session.discard();
        });
        peer.finish();
    }
}

#[test]
fn vacancy_preflight_does_not_replace_a_live_statement() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let original = prepare_no_data(socket, b'I')?;
        let next = read_prepare(socket)?;
        assert_eq!(next, ":p2");
        socket.write_all(&no_data(b'I'))?;
        expect_closes(socket, &[original, next])?;
        let mut response = close_complete(b'I');
        response.extend(close_complete(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = TcpConnection::connect(peer.config_with_limits(WIRE))
            .await
            .unwrap();
        session
            .configure_statements(StatementLimits {
                max_statements: 2,
                max_metadata_bytes: 8192,
            })
            .unwrap();
        let original = statements(&mut session, 1).await;
        let error = session
            .prepare_pipeline(
                vec![request("UPDATE t SET n=n"), request("UPDATE t SET n=n")],
                limits(),
            )
            .await
            .unwrap_err();
        assert!(!error.may_have_created);
        let next = session
            .prepare_pipeline(vec![request("UPDATE t SET n=n")], limits())
            .await
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(
            session
                .close_all_statements_pipeline(close_limits())
                .await
                .unwrap()
                .len(),
            2
        );
        drop(original);
        drop(next);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        session.discard();
    });
    peer.finish();
}

#[test]
fn prepare_pipeline_reuses_the_closed_slot_only_after_the_handle_is_released() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let prior = prepare_no_data(socket, b'I')?;
        expect_closes(socket, std::slice::from_ref(&prior))?;
        socket.write_all(&close_complete(b'I'))?;
        let next = prepare_no_data(socket, b'I')?;
        assert_ne!(next, prior);
        expect_closes(socket, &[next])?;
        socket.write_all(&close_complete(b'I'))?;
        eof(socket)
    });
    run(async {
        let mut session = TcpConnection::connect(peer.config_with_limits(WIRE))
            .await
            .unwrap();
        session
            .configure_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 8192,
            })
            .unwrap();
        let held = statements(&mut session, 1).await;
        let result = session
            .close_prepared_pipeline(&[&held[0]], close_limits())
            .await
            .unwrap();
        assert!(matches!(result.as_slice(), [Ok(_)]));
        let error = session
            .prepare_pipeline(vec![request("UPDATE t SET n=n")], limits())
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert!(!error.may_have_created);
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        drop(held);
        let result = session
            .prepare_pipeline(vec![request("UPDATE t SET n=n")], limits())
            .await
            .unwrap();
        assert!(matches!(result.as_slice(), [Ok(_)]));
        let result = session
            .close_all_statements_pipeline(close_limits())
            .await
            .unwrap();
        assert!(matches!(result.as_slice(), [Ok(_)]));
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn transaction_prepare_pipeline_preserves_failed_state_and_explicit_resolution() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        read_prepare(socket)?;
        read_prepare(socket)?;
        let mut response = frame(b'E', b"SERROR\0C42601\0Msyntax error\0\0");
        response.extend(ready(b'E'));
        response.extend(frame(b'E', b"SERROR\0C25P02\0Mtransaction is aborted\0\0"));
        response.extend(ready(b'E'));
        socket.write_all(&response)?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let names = [read_prepare(socket)?, read_prepare(socket)?];
        let mut response = no_data(b'T');
        response.extend(no_data(b'T'));
        socket.write_all(&response)?;
        expect_closes(socket, &names)?;
        let mut response = close_complete(b'T');
        response.extend(close_complete(b'T'));
        socket.write_all(&response)?;
        control(socket, b"COMMIT\0", b"COMMIT\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let mut transaction = session.begin_transaction().await.unwrap();
        let results = transaction
            .prepare_pipeline(vec![request("broken"), request("SELECT 1")], limits())
            .await
            .unwrap();
        let [Err(first), Err(second)] = results.as_slice() else {
            panic!("每条已提交语句均应返回自己的错误");
        };
        assert_eq!([first.code(), second.code()], ["42601", "25P02"]);
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert!(matches!(
            transaction
                .prepare_pipeline(vec![request("SELECT 1")], limits())
                .await
                .unwrap_err()
                .source,
            Error::Unsupported(_)
        ));
        transaction.rollback().await.unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let results = transaction
            .prepare_pipeline(
                vec![request("UPDATE t SET n=n"), request("UPDATE t SET n=n")],
                limits(),
            )
            .await
            .unwrap();
        assert!(matches!(results.as_slice(), [Ok(_), Ok(_)]));
        assert_eq!(
            transaction
                .close_all_statements_pipeline(close_limits())
                .await
                .unwrap()
                .len(),
            2
        );
        transaction.commit().await.unwrap();
        session.take_transaction_end();
        drop(results);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        session.discard();
    });
    peer.finish();
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_prepare_pipeline_session_and_transaction() {
    let config = live::tcp_config(
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 128,
        },
        peer::TCP_OPTIONS,
    );
    run(async {
        let mut session = connect(config).await;
        let requests = vec![
            PrepareRequest {
                sql: "SELECT $1::int4 + 1",
                parameter_oids: &[compio_postgres::types::Oid::INT4],
                formats: ResultFormats::All(Format::Binary),
            },
            request("not valid SQL"),
            PrepareRequest {
                sql: "SELECT $1::int4 + 2",
                parameter_oids: &[compio_postgres::types::Oid::INT4],
                formats: ResultFormats::All(Format::Binary),
            },
        ];
        let mut results = session.prepare_pipeline(requests, limits()).await.unwrap();
        assert_eq!(results[1].as_ref().unwrap_err().code(), "42601");
        for (index, expected) in [(0, 8), (2, 9)] {
            let statement = results[index].as_ref().unwrap();
            let mut query = session
                .query(
                    statement,
                    &[compio_postgres::types::Parameter::int4(7)],
                    compio_postgres::QueryOptions {
                        limits: compio_postgres::QueryLimits {
                            max_rows: 1,
                            max_result_bytes: 64,
                            max_metadata_bytes: 4096,
                        },
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            assert_eq!(
                query
                    .next_row()
                    .await
                    .unwrap()
                    .unwrap()
                    .view()
                    .decoder()
                    .decode_next::<i32>()
                    .unwrap(),
                expected
            );
            query.finish().await.unwrap();
        }
        let mut transaction = session.begin_transaction().await.unwrap();
        let extra = transaction
            .prepare_pipeline(vec![request("SELECT 42")], limits())
            .await
            .unwrap();
        assert!(extra[0].is_ok());
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        session.take_transaction_end();
        results.extend(extra);
        assert_eq!(
            session
                .close_all_statements_pipeline(close_limits())
                .await
                .unwrap()
                .len(),
            3
        );
        drop(results);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 3);
        session.discard();
    });
}
