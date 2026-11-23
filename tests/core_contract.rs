//! 普通执行接口共享的协议恢复与事务租约约定。
#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{
    AbandonPolicy, AllocationPolicy, BatchControl, BatchEvent, BatchOptions, ClientOptions, Error,
    ExecutionOptions, ExecutionScheduling, OnError, OwnedOutput, PreparedStatementStorage,
    QueryLimits, QueryOptions, ResultFormats, ReuseState, StatementLimits, TcpConnection,
    TransactionEnd, TransactionStatus,
    types::{Format, Oid, Parameter},
};
use peer::{
    Peer, control, eof, execution, frame, handshake, prepare, ready, result, run, sql_error,
};
use std::{cell::Cell, io::Write};

const BINARY: ResultFormats = ResultFormats::All(Format::Binary);
const LIMITS: QueryLimits = QueryLimits {
    max_rows: 4,
    max_result_bytes: 4096,
    max_metadata_bytes: 4096,
};
const OUTPUT: OwnedOutput = OwnedOutput {
    max_bytes: 8192,
    allocation: AllocationPolicy::Grow,
};

fn options(peer: &Peer) -> ClientOptions<compio_postgres::TcpConfig> {
    ClientOptions::new(
        peer.config(),
        ExecutionOptions {
            query: QueryOptions {
                limits: LIMITS,
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            batch: Some(BatchOptions {
                member_limits: LIMITS,
                max_inflight: 2,
                max_requests: 3,
                max_queued_request_bytes: 4096,
                max_diagnostic_bytes: 4096,
                scheduling: ExecutionScheduling::Uninterrupted,
            }),
        },
        StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 8192,
        },
    )
}

#[test]
fn owned_control_limit_leaves_complete_or_ready_recoverable() {
    for warnings in [126, 127] {
        for policy in [OnError::RecoverExplicitly, OnError::DrainToReady] {
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[], &[23])?;
                execution(socket, &statement)?;
                let mut response = frame(b'2', &[]);
                for _ in 0..warnings {
                    response.extend(frame(b'N', b"SNOTICE\0C00000\0Mfixture notice\0\0"));
                }
                response.extend(frame(b'C', b"SELECT 0\0"));
                response.extend(ready(b'I'));
                socket.write_all(&response)?;
                execution(socket, &statement)?;
                socket.write_all(&result(73, b'I'))?;
                eof(socket)
            });
            run(async {
                let mut conn = TcpConnection::connect(options(&peer)).await.unwrap();
                let statement = conn
                    .prepare(
                        "SELECT 73::int4",
                        &[],
                        PreparedStatementStorage::Named,
                        BINARY,
                    )
                    .await
                    .unwrap();
                let error = conn
                    .streaming_batch([statement.bind(&[])])
                    .collect_ready(OUTPUT, policy)
                    .await
                    .unwrap_err();
                assert!(matches!(error.source, Error::Limit(_)));
                assert_eq!((error.progress.admitted, error.progress.confirmed), (1, 0));
                assert!(error.cleanup_error.is_none());
                if policy == OnError::RecoverExplicitly {
                    assert_eq!(conn.reuse_state(), ReuseState::NeedsRecovery);
                    conn.recover_to_ready().await.unwrap();
                }
                assert_eq!(conn.reuse_state(), ReuseState::ProtocolIdle);
                assert_eq!(
                    conn.query(&statement, &[])
                        .one::<i32>(policy)
                        .await
                        .unwrap(),
                    73
                );
                conn.close_local().await.unwrap();
            });
            peer.finish();
        }
    }
}

#[test]
fn owned_window_delivers_admitted_suffix_and_stops_at_failed_transaction() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let mut response = sql_error("22012", b'E');
        response.extend(sql_error("25P02", b'E'));
        socket.write_all(&response)?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        execution(socket, &statement)?;
        socket.write_all(&result(1, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut conn = TcpConnection::connect(options(&peer)).await.unwrap();
        let statement = conn
            .prepare(
                "SELECT 1 / $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut tx = conn.begin_transaction().await.unwrap();
        let reads = Cell::new(0);
        let source = (0..3).map(|i| {
            reads.set(reads.get() + 1);
            statement.bind_one(Parameter::int4(i))
        });
        let report = tx
            .streaming_batch(source)
            .collect_ready(OUTPUT, OnError::Discard)
            .await
            .unwrap();
        assert_eq!(reads.get(), 2);
        assert_eq!(report.progress.admitted, 2);
        assert_eq!(report.progress.confirmed, 2);
        assert!(report.progress.stopped);
        assert!(report.progress.needs_transaction_decision);
        assert_eq!(
            report.progress.transaction_status,
            TransactionStatus::FailedTransaction
        );
        assert_eq!(report.results[0].as_ref().unwrap_err().code(), "22012");
        assert_eq!(report.results[1].as_ref().unwrap_err().code(), "25P02");
        assert_eq!(tx.reuse_state(), ReuseState::NeedsTransactionDecision);
        tx.rollback().await.unwrap();
        assert_eq!(
            conn.query(&statement, &[Parameter::int4(1)])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            1
        );
        conn.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn taking_raw_commit_fact_preserves_lease_retirement_before_and_after_ready() {
    for (before_ready, chain) in [(false, false), (false, true), (true, false), (true, true)] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let commit = prepare(socket, &[], &[])?;
            let scalar = prepare(socket, &[], &[23])?;
            control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
            execution(socket, &commit)?;
            let mut response = frame(b'2', &[]);
            response.extend(frame(b'C', b"COMMIT\0"));
            response.extend(ready(if chain { b'T' } else { b'I' }));
            socket.write_all(&response)?;
            if chain {
                control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
            }
            execution(socket, &scalar)?;
            socket.write_all(&result(73, b'I'))?;
            eof(socket)
        });
        run(async {
            let mut conn = TcpConnection::connect(options(&peer)).await.unwrap();
            let commit_sql = if chain { "COMMIT AND CHAIN" } else { "COMMIT" };
            let commit = conn
                .prepare(commit_sql, &[], PreparedStatementStorage::Named, BINARY)
                .await
                .unwrap();
            let scalar = conn
                .prepare(
                    "SELECT 73::int4",
                    &[],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            {
                let mut tx = conn.begin_transaction().await.unwrap();
                if before_ready {
                    let progress = tx
                        .streaming_batch([commit.bind(&[])])
                        .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
                            Ok(if matches!(event, BatchEvent::Command { .. }) {
                                BatchControl::Abort
                            } else {
                                BatchControl::Continue
                            })
                        })
                        .await
                        .unwrap();
                    assert!(progress.aborted);
                    assert_eq!(progress.confirmed, 0);
                } else {
                    let mut query = tx
                        .query(&commit, &[])
                        .stream_provisional(AbandonPolicy::RecoverExplicitly)
                        .await
                        .unwrap();
                    assert_eq!(
                        query.finish().await.unwrap().transaction_status,
                        if chain {
                            TransactionStatus::InTransaction
                        } else {
                            TransactionStatus::Idle
                        }
                    );
                }
                assert_eq!(tx.take_transaction_end(), Some(TransactionEnd::Committed));
                assert_eq!(tx.take_transaction_end(), None);
                if chain {
                    tx.recover_to_ready().await.unwrap();
                    assert_eq!(tx.reuse_state(), ReuseState::NeedsTransactionDecision);
                    assert_eq!(tx.transaction_status(), TransactionStatus::InTransaction);
                    tx.rollback().await.unwrap();
                }
            }
            if before_ready && !chain {
                assert_eq!(conn.reuse_state(), ReuseState::NeedsRecovery);
                conn.recover_to_ready().await.unwrap();
            }
            assert_eq!(conn.reuse_state(), ReuseState::ProtocolIdle);
            assert_eq!(
                conn.query(&scalar, &[])
                    .one::<i32>(OnError::Discard)
                    .await
                    .unwrap(),
                73
            );
            conn.close_local().await.unwrap();
        });
        peer.finish();
    }
}
