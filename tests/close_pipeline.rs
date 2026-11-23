//! 有限 Close 流水线中，每个语句都有独立的 Sync 边界和可恢复的身份。
//! 测试对端收齐所有成员后才返回结果。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{
    close_complete, database_error, expect_closes, handshake, prepare_no_data, read_prepare,
};
use peer::{IO_DEADLINE, Peer, control, eof, frame, invalid, ready, run};

use compio_postgres::{
    Error, ExecutionScheduling, QueryLimits, ResultFormats, ReuseState, StatementLimits,
    StatementPipelineLimits, TcpConfig, TransactionStatus, WireLimits,
    expert::{PreparedStatement, TcpSession as TcpConnection},
    types::Format,
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

fn close_fault() -> Vec<u8> {
    // 注入服务端释放资源失败。正常 Close 接受已经不存在的名字。
    database_error("ERROR", "XX000", "fixture close failure")
}

fn checkpoint_response(mut response: Vec<u8>) -> Vec<u8> {
    response.extend(frame(
        b'N',
        b"SNOTICE\0VNOTICE\0C00000\0Mresponse checkpoint\0\0",
    ));
    response
}

fn checkpoint_config(config: TcpConfig) -> (TcpConfig, Arc<AtomicBool>) {
    let observed = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&observed);
    let config = config.notice_handler(move |notice| {
        assert_eq!(notice.message, "response checkpoint");
        marker.store(true, Ordering::Release);
    });
    (config, observed)
}

async fn wait_for_checkpoint<F: Future>(mut pending: Pin<&mut F>, observed: &AtomicBool) {
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        if observed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn close_all_pipelines_a_bounded_prefix_and_retains_only_unclosed_statements() {
    const COUNT: usize = 67;
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let mut names = Vec::new();
        for _ in 0..COUNT {
            names.push(prepare_no_data(socket, b'I')?);
        }
        expect_closes(socket, &names[..64])?;
        let mut response = close_fault();
        response.extend(ready(b'I'));
        for _ in 1..64 {
            response.extend(close_complete(b'I'));
        }
        socket.write_all(&response)?;
        let remaining = std::iter::once(names[0].clone())
            .chain(names[64..].iter().cloned())
            .collect::<Vec<_>>();
        for packet in remaining.chunks(2) {
            expect_closes(socket, packet)?;
            socket.write_all(&close_complete(b'I').repeat(packet.len()))?;
        }
        eof(socket)
    });
    run(async {
        let mut session = TcpConnection::connect(peer.config_with_limits(WIRE))
            .await
            .unwrap();
        session
            .configure_statements(StatementLimits {
                max_statements: COUNT,
                max_metadata_bytes: 65536,
            })
            .unwrap();
        let handles = statements(&mut session, COUNT).await;
        let first_packet = StatementPipelineLimits {
            max_statements: 64,
            ..limits()
        };
        assert!(
            matches!(session.close_all_statements(first_packet).await, Err(Error::Database(error)) if error.code() == "XX000")
        );
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        session
            .close_all_statements(StatementPipelineLimits {
                max_statements: 2,
                ..limits()
            })
            .await
            .unwrap();
        drop(handles);
        assert_eq!(session.reclaim_closed_statements().unwrap(), COUNT);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn finite_close_packet_preserves_order_syncs_and_exact_admission_limits() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let names = [
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
        ];
        expect_closes(socket, &names)?;
        let mut response = close_complete(b'I');
        response.extend(close_complete(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let members = statements(&mut session, 2).await;
        let requests = [&members[0], &members[1]];
        for bad in [
            StatementPipelineLimits {
                max_statements: 1,
                ..limits()
            },
            StatementPipelineLimits {
                max_packet_bytes: 29,
                ..limits()
            },
            StatementPipelineLimits {
                max_result_bytes: 0,
                ..limits()
            },
        ] {
            let error = session
                .close_prepared_pipeline(&requests, bad)
                .await
                .unwrap_err();
            assert!(!error.may_have_executed);
            assert!(error.completed.is_empty());
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        }
        let duplicate = session
            .close_prepared_pipeline(&[&members[0], &members[0]], limits())
            .await
            .unwrap_err();
        assert!(matches!(duplicate.source, Error::InvalidInput(_)));
        assert!(!duplicate.may_have_executed);
        let outcomes = session
            .close_prepared_pipeline(
                &requests,
                StatementPipelineLimits {
                    max_packet_bytes: 30,
                    ..limits()
                },
            )
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Result::is_ok));
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        let stale = session
            .close_prepared_pipeline(&requests, limits())
            .await
            .unwrap_err();
        assert!(!stale.may_have_executed);
        assert!(matches!(stale.source, Error::InvalidInput(_)));
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        assert!(
            session
                .close_all_statements_pipeline(limits())
                .await
                .unwrap()
                .is_empty()
        );
        session.discard();
    });
    peer.finish();
}

#[test]
fn close_all_counts_only_live_names_and_preserves_reused_slot_order() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let names = [
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
        ];
        let last = prepare_no_data(socket, b'I')?;
        let replies = [close_complete(b'I'), close_complete(b'I')].concat();
        expect_closes(socket, &names)?;
        socket.write_all(&replies)?;
        let replacement = prepare_no_data(socket, b'I')?;
        expect_closes(socket, &[replacement, last])?;
        socket.write_all(&replies)?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let zero = StatementPipelineLimits {
            max_statements: 0,
            max_packet_bytes: 0,
            max_result_bytes: 0,
            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
        };
        assert!(
            session
                .close_prepared_pipeline(&[], zero)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            session
                .close_all_statements_pipeline(zero)
                .await
                .unwrap()
                .is_empty()
        );
        let mut members = statements(&mut session, 3).await;
        let failure = session
            .close_all_statements_pipeline(zero)
            .await
            .unwrap_err();
        assert!(matches!(
            failure.source,
            Error::Limit("Close pipeline statement count exceeds its limit")
        ));
        assert!(!failure.may_have_executed);
        assert!(failure.completed.is_empty());

        let done = session
            .close_prepared_pipeline(&[&members[0], &members[1]], limits())
            .await
            .unwrap();
        assert!(done.iter().all(Result::is_ok));
        // 保留槽 1 对应的已关闭句柄，此时只有槽 0 可以复用。
        drop(members.remove(0));
        assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
        let _replacement = statements(&mut session, 1).await;
        let done = session
            .close_all_statements_pipeline(StatementPipelineLimits {
                max_statements: 2,
                ..limits()
            })
            .await
            .unwrap();
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(Result::is_ok));
        assert!(
            session
                .close_all_statements_pipeline(zero)
                .await
                .unwrap()
                .is_empty()
        );
        session.discard();
    });
    peer.finish();
}

#[test]
fn ordinary_error_keeps_each_boundary_and_already_queued_successors_run() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let names = [
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
        ];
        expect_closes(socket, &names)?;
        let mut response = close_complete(b'I');
        response.extend(close_fault());
        response.extend(ready(b'I'));
        response.extend(close_complete(b'I'));
        socket.write_all(&response)?;
        expect_closes(socket, &names[1..2])?;
        socket.write_all(&close_complete(b'I'))?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let members = statements(&mut session, 3).await;
        let refs: Vec<_> = members.iter().collect();
        let results = session
            .close_prepared_pipeline(&refs, limits())
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert_eq!(results[1].as_ref().unwrap_err().code(), "XX000");
        assert!(results[2].is_ok());
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        let retry = session
            .close_all_statements_pipeline(limits())
            .await
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert!(retry[0].is_ok());
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 3);
        session.discard();
    });
    peer.finish();
}

#[test]
fn terminal_protocol_and_diagnostic_budget_failures_retain_only_ready_prefix() {
    for (reply, malformed) in [
        (ready(b'I'), true),
        ([close_fault(), ready(b'I')].concat(), false),
        (
            peer::prepared::database_error("FATAL", "57P01", "shutdown"),
            false,
        ),
    ] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let names = [
                prepare_no_data(socket, b'I')?,
                prepare_no_data(socket, b'I')?,
            ];
            expect_closes(socket, &names)?;
            let mut response = close_complete(b'I');
            response.extend(reply);
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let mut session = connect(peer.config_with_limits(WIRE)).await;
            let members = statements(&mut session, 2).await;
            let error = session
                .close_prepared_pipeline(
                    &[&members[0], &members[1]],
                    StatementPipelineLimits {
                        max_result_bytes: 2
                            * std::mem::size_of::<compio_postgres::expert::CloseItem>(),
                        ..limits()
                    },
                )
                .await
                .unwrap_err();
            assert!(error.may_have_executed);
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
fn sync_error_after_close_complete_does_not_restore_the_closed_identity() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare_no_data(socket, b'I')?;
        expect_closes(socket, &[statement])?;
        let mut response = frame(b'3', &[]);
        response.extend(database_error("ERROR", "40001", "fixture sync failure"));
        response.extend(ready(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let members = statements(&mut session, 1).await;
        let results = session
            .close_prepared_pipeline(&[&members[0]], limits())
            .await
            .unwrap();
        assert_eq!(results[0].as_ref().unwrap_err().code(), "40001");
        assert!(
            session
                .close_all_statements_pipeline(limits())
                .await
                .unwrap()
                .is_empty()
        );
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
        session.discard();
    });
    peer.finish();
}

#[test]
fn dropped_waiter_retains_consumed_close_phase_and_recovery_is_resumable() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::start(move |socket| {
        handshake(socket)?;
        let mut names = Vec::new();
        for _ in 0..6 {
            names.push(prepare_no_data(socket, b'I')?);
        }
        expect_closes(socket, &names)?;
        socket.write_all(&checkpoint_response(frame(b'3', &[])))?;
        wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
        let mut response = ready(b'I');
        for _ in 1..6 {
            response.extend(close_complete(b'I'));
        }
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let (config, observed) = checkpoint_config(peer.config_with_limits(WIRE));
        let mut session = connect(config).await;
        let members = statements(&mut session, 6).await;
        let refs: Vec<_> = members.iter().collect();
        let mut pending = Box::pin(session.close_prepared_pipeline(
            &refs,
            StatementPipelineLimits {
                scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
                ..limits()
            },
        ));
        wait_for_checkpoint(pending.as_mut(), &observed).await;
        drop(pending);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        release.send(()).unwrap();
        assert!(matches!(
            session.recover_to_ready().await,
            Err(Error::Limit(_))
        ));
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        session.recover_to_ready().await.unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 6);
        session.discard();
    });
    peer.finish();
}

#[test]
fn transaction_error_preserves_failed_state_and_close_all_is_symmetric() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let names = [
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
        ];
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        expect_closes(socket, &names)?;
        let mut response = close_fault();
        response.extend(ready(b'E'));
        response.extend(close_complete(b'E'));
        socket.write_all(&response)?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        expect_closes(socket, &names[..1])?;
        socket.write_all(&close_complete(b'T'))?;
        control(socket, b"COMMIT\0", b"COMMIT\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config_with_limits(WIRE)).await;
        let members = statements(&mut session, 2).await;
        let mut transaction = session.begin_transaction().await.unwrap();
        let results = transaction
            .close_prepared_pipeline(&[&members[0], &members[1]], limits())
            .await
            .unwrap();
        assert_eq!(results[0].as_ref().unwrap_err().code(), "XX000");
        assert!(results[1].is_ok());
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert!(matches!(
            transaction
                .close_all_statements_pipeline(limits())
                .await
                .unwrap_err()
                .source,
            Error::Unsupported(_)
        ));
        transaction.rollback().await.unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let result = transaction
            .close_all_statements_pipeline(limits())
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ok());
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.commit().await.unwrap();
        session.take_transaction_end();
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        session.discard();
    });
    peer.finish();
}

#[test]
fn dropped_transaction_close_waiter_requires_recovery_then_explicit_rollback() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::start(move |socket| {
        handshake(socket)?;
        let names = [
            prepare_no_data(socket, b'I')?,
            prepare_no_data(socket, b'I')?,
        ];
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        expect_closes(socket, &names)?;
        socket.write_all(&close_complete(b'T'))?;
        socket.write_all(&checkpoint_response(frame(b'3', &[])))?;
        wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
        socket.write_all(&ready(b'T'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let (config, observed) = checkpoint_config(peer.config_with_limits(WIRE));
        let mut session = connect(config).await;
        let members = statements(&mut session, 2).await;
        {
            let mut transaction = session.begin_transaction().await.unwrap();
            let refs = [&members[0], &members[1]];
            let mut pending = Box::pin(transaction.close_prepared_pipeline(&refs, limits()));
            wait_for_checkpoint(pending.as_mut(), &observed).await;
            drop(pending);
        }
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        release.send(()).unwrap();
        session.recover_to_ready().await.unwrap();
        assert_eq!(session.reuse_state(), ReuseState::NeedsTransactionDecision);
        session.recover_and_rollback().await.unwrap();
        session.take_transaction_end();
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 2);
        session.discard();
    });
    peer.finish();
}

#[test]
fn close_all_pipeline_includes_recovered_preparation_without_a_handle() {
    let (release, wait) = mpsc::channel();
    let peer = Peer::start(move |socket| {
        handshake(socket)?;
        let abandoned = read_prepare(socket)?;
        socket.write_all(&checkpoint_response(frame(b'1', &[])))?;
        wait.recv_timeout(IO_DEADLINE).map_err(|_| invalid())?;
        let mut remainder = frame(b't', &0_u16.to_be_bytes());
        remainder.extend(frame(b'n', &[]));
        remainder.extend(ready(b'I'));
        socket.write_all(&remainder)?;
        expect_closes(socket, &[abandoned])?;
        socket.write_all(&close_complete(b'I'))?;
        eof(socket)
    });
    run(async {
        let (config, observed) = checkpoint_config(peer.config_with_limits(WIRE));
        let mut session = connect(config).await;
        let mut pending =
            Box::pin(session.prepare("UPDATE t SET n=n", &[], ResultFormats::All(Format::Binary)));
        wait_for_checkpoint(pending.as_mut(), &observed).await;
        drop(pending);
        release.send(()).unwrap();
        session.recover_to_ready().await.unwrap();
        let result = session
            .close_all_statements_pipeline(limits())
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ok());
        assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
        session.discard();
    });
    peer.finish();
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_close_pipeline_session_and_transaction() {
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
        let mut members = Vec::new();
        for sql in ["SELECT 1", "SELECT 2", "SELECT 3", "SELECT 4"] {
            members.push(
                session
                    .prepare(sql, &[], ResultFormats::All(Format::Binary))
                    .await
                    .unwrap(),
            );
        }
        // 在服务端移除一个语句，但让客户端仍持有该名字。
        session
            .query_simple_single(
                "DO $$ DECLARE prepared_name text;
                 BEGIN
                     SELECT name INTO STRICT prepared_name
                     FROM pg_catalog.pg_prepared_statements WHERE statement = 'SELECT 2';
                     EXECUTE format('DEALLOCATE %I', prepared_name);
                 END $$",
                compio_postgres::QueryOptions {
                    limits: QueryLimits {
                        max_rows: 0,
                        max_result_bytes: 0,
                        max_metadata_bytes: 4096,
                    },
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        let results = session
            .close_prepared_pipeline(&[&members[1], &members[3]], limits())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
        let mut transaction = session.begin_transaction().await.unwrap();
        let results = transaction
            .close_all_statements_pipeline(limits())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        session.take_transaction_end();
        drop(members);
        assert_eq!(session.reclaim_closed_statements().unwrap(), 4);
        session.discard();
    });
}
