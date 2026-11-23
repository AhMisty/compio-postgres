//! 通过本地协议脚本验证事务所有权和执行结果。

#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{body, handshake, run};
use peer::{Peer, frame, ready};

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use compio_postgres::{
    ControlKind, Error, ReuseState, TcpConfig, TransactionEnd, TransactionStatus,
    expert::TcpSession as TcpConnection,
};
use futures_util::future::{Either, select};

const SQL: &str = "SELECT 10 / $1::int4 AS result";

fn transaction_peer(
    script: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
) -> Peer {
    Peer::start_with(script, peer::prepared::DEADLINE, peer::IO_DEADLINE, 8192)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn expect_tags(socket: &mut TcpStream, tags: &[u8]) -> io::Result<()> {
    for expected in tags {
        let mut tag = [0];
        socket.read_exact(&mut tag)?;
        let message = body(socket)?;
        if tag[0] != *expected || (*expected == b'S' && !message.is_empty()) {
            return Err(invalid("unexpected frontend sequence"));
        }
    }
    Ok(())
}

fn expect_query(socket: &mut TcpStream, sql: &str) -> io::Result<()> {
    let mut tag = [0];
    socket.read_exact(&mut tag)?;
    let message = body(socket)?;
    if tag != *b"Q" || message.strip_suffix(&[0]) != Some(sql.as_bytes()) {
        return Err(invalid("unexpected transaction SQL"));
    }
    Ok(())
}

fn command(tag: &str, status: u8) -> Vec<u8> {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    let mut bytes = frame(b'C', &body);
    bytes.extend(ready(status));
    bytes
}

fn prepare(socket: &mut TcpStream, status: u8) -> io::Result<()> {
    expect_tags(socket, b"PDS")?;
    let mut bytes = frame(b'1', &[]);
    bytes.extend(frame(b't', &[0, 1, 0, 0, 0, 23]));
    let mut field = vec![0, 1];
    field.extend_from_slice(b"result\0");
    field.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    field.extend_from_slice(&23_u32.to_be_bytes());
    field.extend_from_slice(&4_i16.to_be_bytes());
    field.extend_from_slice(&(-1_i32).to_be_bytes());
    field.extend_from_slice(&0_i16.to_be_bytes());
    bytes.extend(frame(b'T', &field));
    bytes.extend(ready(status));
    socket.write_all(&bytes)
}

fn query_response(value: i32, status: u8) -> Vec<u8> {
    let mut bytes = frame(b'2', &[]);
    let mut row = vec![0, 1, 0, 0, 0, 4];
    row.extend_from_slice(&value.to_be_bytes());
    bytes.extend(frame(b'D', &row));
    bytes.extend(command("SELECT 1", status));
    bytes
}

fn sql_error(status: u8) -> Vec<u8> {
    let mut bytes = frame(b'E', b"SERROR\0VERROR\0C22012\0Mdivision by zero\0\0");
    bytes.extend(ready(status));
    bytes
}

async fn wait_seen(seen: Arc<AtomicBool>) {
    while !seen.load(Ordering::Acquire) {
        compio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[test]
fn expert_transaction_recovers_an_abandoned_query_before_choosing_its_end() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    for (end, expected) in [
        ("COMMIT", TransactionEnd::Committed),
        ("ROLLBACK", TransactionEnd::RolledBack),
    ] {
        let peer = transaction_peer(move |socket| {
            handshake(socket)?;
            expect_query(socket, "BEGIN")?;
            socket.write_all(&command("BEGIN", b'T'))?;
            prepare(socket, b'T')?;
            expect_tags(socket, b"BES")?;
            let mut response = frame(b'2', &[]);
            for value in [1_i32, 2] {
                let mut body = vec![0, 1, 0, 0, 0, 4];
                body.extend_from_slice(&value.to_be_bytes());
                response.extend(frame(b'D', &body));
            }
            response.extend(if expected == TransactionEnd::Committed {
                command("SELECT 2", b'T')
            } else {
                sql_error(b'E')
            });
            socket.write_all(&response)?;
            if expected == TransactionEnd::Committed {
                expect_tags(socket, b"BES")?;
                socket.write_all(&query_response(5, b'T'))?;
            }
            expect_query(socket, end)?;
            socket.write_all(&command(end, b'I'))
        });
        let foreign = compio::runtime::Runtime::new().unwrap();
        run(async {
            let mut connection = TcpConnection::connect(peer.config()).await.unwrap();
            scalar::configure(&mut connection);
            let mut transaction = connection.begin_transaction().await.unwrap();
            let statement = transaction.prepare_scalar(SQL).await.unwrap();
            let mut query = transaction
                .query(
                    &statement,
                    &[scalar::parameter(Some(1))],
                    compio_postgres::QueryOptions {
                        limits: scalar::limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            assert!(query.next_row().await.unwrap().is_some());
            drop(query);
            assert_eq!(transaction.reuse_state(), ReuseState::NeedsRecovery);
            assert!(matches!(
                transaction.query_scalar(&statement, Some(2)).await,
                Err(Error::Busy)
            ));
            {
                let mut recovery = pin!(transaction.recover_to_ready());
                let result = foreign.enter(|| {
                    recovery
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                });
                assert!(matches!(result, Poll::Ready(Err(Error::InvalidInput(_)))));
            }
            for (max_rows, max_bytes) in [(0, usize::MAX), (1, 11)] {
                assert!(matches!(
                    transaction
                        .recover_to_ready_with_limits(max_rows, max_bytes)
                        .await,
                    Err(Error::Limit(_))
                ));
                assert_eq!(transaction.reuse_state(), ReuseState::NeedsRecovery);
            }
            if expected == TransactionEnd::Committed {
                transaction
                    .recover_to_ready_with_limits(1, 12)
                    .await
                    .unwrap();
            } else {
                transaction.recover_to_ready().await.unwrap();
            }
            assert_eq!(
                transaction.reuse_state(),
                ReuseState::NeedsTransactionDecision
            );
            assert_eq!(transaction.take_transaction_end(), None);
            let completion = if expected == TransactionEnd::Committed {
                assert_eq!(
                    transaction.transaction_status(),
                    TransactionStatus::InTransaction
                );
                assert_eq!(
                    transaction.query_scalar(&statement, Some(2)).await.unwrap(),
                    Some(5)
                );
                transaction.commit().await.unwrap()
            } else {
                assert_eq!(
                    transaction.transaction_status(),
                    TransactionStatus::FailedTransaction
                );
                assert!(matches!(
                    transaction.query_scalar(&statement, Some(2)).await,
                    Err(Error::Unsupported(_))
                ));
                transaction.rollback().await.unwrap()
            };
            assert_eq!(completion.transaction_end, Some(expected));
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        });
        peer.finish();
    }
}

#[test]
fn guard_prepared_operations_and_commit_release_only_after_the_boundary() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        prepare(socket, b'T')?;
        expect_tags(socket, b"BES")?;
        socket.write_all(&query_response(2, b'T'))?;
        expect_tags(socket, b"CS")?;
        let mut closed = frame(b'3', &[]);
        closed.extend(ready(b'T'));
        socket.write_all(&closed)?;
        expect_query(socket, "COMMIT")?;
        socket.write_all(&command("COMMIT", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        scalar::configure(&mut connection);
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        let statement = transaction
            .prepare_scalar(SQL)
            .await
            .expect("prepare in transaction");
        assert_eq!(
            transaction
                .query_scalar(&statement, Some(5))
                .await
                .expect("query"),
            Some(2)
        );
        transaction.close_prepared(&statement).await.expect("close");
        let completed = transaction.commit().await.expect("COMMIT");
        assert_eq!(completed.kind, ControlKind::Commit);
        assert_eq!(completed.transaction_end, Some(TransactionEnd::Committed));
        assert_eq!(completed.transaction_status, TransactionStatus::Idle);
        assert!(connection.is_usable());
        assert_eq!(connection.take_transaction_end(), None);
        connection.discard();
    });
    peer.finish();
}

#[test]
fn failed_transaction_commit_reports_the_servers_rollback() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        prepare(socket, b'I')?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_tags(socket, b"BES")?;
        socket.write_all(&sql_error(b'E'))?;
        expect_query(socket, "COMMIT")?;
        socket.write_all(&command("ROLLBACK", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        assert!(matches!(
            transaction.query_scalar(&statement, Some(0)).await,
            Err(Error::Database(_))
        ));
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert!(matches!(
            transaction.query_scalar(&statement, Some(5)).await,
            Err(Error::Unsupported(_))
        ));
        let completion = transaction
            .commit()
            .await
            .expect("failed transaction COMMIT");
        assert_eq!(completion.kind, ControlKind::Rollback);
        assert_eq!(completion.transaction_end, Some(TransactionEnd::RolledBack));
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn savepoint_recovery_is_not_an_outer_transaction_end() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        prepare(socket, b'I')?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "SAVEPOINT \"sp\"")?;
        socket.write_all(&command("SAVEPOINT", b'T'))?;
        expect_tags(socket, b"BES")?;
        socket.write_all(&sql_error(b'E'))?;
        expect_query(socket, "ROLLBACK TO SAVEPOINT \"sp\"")?;
        socket.write_all(&command("ROLLBACK", b'T'))?;
        expect_tags(socket, b"BES")?;
        socket.write_all(&query_response(2, b'T'))?;
        expect_query(socket, "RELEASE SAVEPOINT \"sp\"")?;
        socket.write_all(&command("RELEASE", b'T'))?;
        expect_query(socket, "ROLLBACK")?;
        socket.write_all(&command("ROLLBACK", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        transaction.savepoint("sp").await.expect("savepoint");
        assert!(matches!(
            transaction.query_scalar(&statement, Some(0)).await,
            Err(Error::Database(_))
        ));
        let recovered = transaction
            .rollback_to_savepoint("sp")
            .await
            .expect("ROLLBACK TO");
        assert_eq!(recovered.transaction_end, None);
        assert_eq!(
            recovered.transaction_status,
            TransactionStatus::InTransaction
        );
        assert_eq!(transaction.take_transaction_end(), None);
        assert_eq!(
            transaction
                .query_scalar(&statement, Some(5))
                .await
                .expect("query after savepoint recovery"),
            Some(2)
        );
        transaction.release_savepoint("sp").await.expect("release");
        assert_eq!(
            transaction
                .rollback()
                .await
                .expect("outer rollback")
                .transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        connection.discard();
    });
    peer.finish();
}

#[test]
fn raw_rollback_to_savepoint_keeps_the_transaction_open_for_commit() {
    use compio_postgres::{ExecutionScheduling, QueryLimits};

    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "SAVEPOINT \"sp\"")?;
        socket.write_all(&command("SAVEPOINT", b'T'))?;
        expect_query(socket, "ROLLBACK TO SAVEPOINT sp")?;
        socket.write_all(&command("ROLLBACK", b'T'))?;
        expect_query(socket, "COMMIT")?;
        socket.write_all(&command("COMMIT", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        transaction.savepoint("sp").await.expect("SAVEPOINT");
        {
            let mut query = transaction
                .query_simple_single(
                    "ROLLBACK TO SAVEPOINT sp",
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
                .expect("admit raw ROLLBACK TO");
            let completion = query.finish().await.expect("finish raw ROLLBACK TO");
            assert_eq!(
                completion.transaction_status,
                TransactionStatus::InTransaction
            );
        }
        assert_eq!(transaction.take_transaction_end(), None);
        let completion = transaction
            .commit()
            .await
            .expect("COMMIT after raw ROLLBACK TO");
        assert_eq!(completion.transaction_end, Some(TransactionEnd::Committed));
        assert!(connection.is_usable());
        connection.close_local().await.expect("retire connection");
    });
    peer.finish();
}

#[test]
fn savepoint_rollback_invalidates_statements_when_search_path_changes() {
    const SET_PATH: &str = "SET LOCAL search_path TO alternate";

    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "SAVEPOINT \"sp\"")?;
        socket.write_all(&command("SAVEPOINT", b'T'))?;
        expect_query(socket, SET_PATH)?;
        let mut changed = frame(b'C', b"SET\0");
        changed.extend(frame(b'S', b"search_path\0alternate\0"));
        changed.extend(ready(b'T'));
        socket.write_all(&changed)?;
        prepare(socket, b'T')?;
        expect_query(socket, "ROLLBACK TO SAVEPOINT \"sp\"")?;
        let mut restored = frame(b'C', b"ROLLBACK\0");
        restored.extend(frame(b'S', b"search_path\0public\0"));
        restored.extend(ready(b'T'));
        socket.write_all(&restored)?;
        expect_tags(socket, b"CS")?;
        let mut closed = frame(b'3', &[]);
        closed.extend(ready(b'T'));
        socket.write_all(&closed)?;
        expect_query(socket, "ROLLBACK")?;
        socket.write_all(&command("ROLLBACK", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        scalar::configure(&mut connection);
        let mut transaction = connection.begin_transaction().await.expect("begin");
        transaction.savepoint("sp").await.expect("savepoint");
        transaction
            .query_simple_single(
                SET_PATH,
                compio_postgres::QueryOptions {
                    limits: scalar::limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .expect("admit SET LOCAL")
            .finish()
            .await
            .expect("set local search path");
        let statement = transaction.prepare_scalar(SQL).await.expect("prepare");
        transaction
            .rollback_to_savepoint("sp")
            .await
            .expect("restore search path");
        assert!(matches!(
            transaction.query_scalar(&statement, Some(5)).await,
            Err(Error::InvalidInput(_))
        ));
        transaction.close_prepared(&statement).await.expect("close");
        transaction.rollback().await.expect("outer rollback");
        connection.close_local().await.expect("retire connection");
    });
    peer.finish();
}

#[test]
fn chain_operations_keep_the_same_guard_over_a_new_transaction() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        for (sql, tag, status) in [
            ("BEGIN", "BEGIN", b'T'),
            ("COMMIT AND CHAIN", "COMMIT", b'T'),
            ("ROLLBACK AND CHAIN", "ROLLBACK", b'T'),
            ("ROLLBACK", "ROLLBACK", b'I'),
        ] {
            expect_query(socket, sql)?;
            socket.write_all(&command(tag, status))?;
        }
        Ok(())
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        let committed = transaction.commit_and_chain().await.expect("commit chain");
        assert_eq!(committed.transaction_end, Some(TransactionEnd::Committed));
        assert_eq!(
            committed.transaction_status,
            TransactionStatus::InTransaction
        );
        let rolled_back = transaction
            .rollback_and_chain()
            .await
            .expect("rollback chain");
        assert_eq!(
            rolled_back.transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.expect("final rollback");
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn dropped_or_forgotten_guard_keeps_the_parent_lease_until_explicit_recovery() {
    for forget in [false, true] {
        let peer = transaction_peer(|socket| {
            handshake(socket)?;
            expect_query(socket, "BEGIN")?;
            socket.write_all(&command("BEGIN", b'T'))?;
            expect_query(socket, "ROLLBACK")?;
            socket.write_all(&command("ROLLBACK", b'I'))
        });
        run(async {
            let mut connection = TcpConnection::connect(peer.config())
                .await
                .expect("connect");
            scalar::configure(&mut connection);
            let transaction = connection.begin_transaction().await.expect("BEGIN");
            if forget {
                // 即使持有守卫的容器绕过析构，连接仍须保留事务租约。
                std::mem::forget(Box::new(transaction));
            } else {
                drop(transaction);
            }
            assert!(!connection.is_usable());
            assert!(matches!(
                connection.prepare_scalar(SQL).await,
                Err(Error::Busy)
            ));
            let recovered = connection
                .recover_and_rollback()
                .await
                .expect("explicit rollback");
            assert_eq!(recovered.transaction_end, Some(TransactionEnd::RolledBack));
            assert!(connection.is_usable());
            connection.discard();
        });
        peer.finish();
    }
}

#[test]
fn commit_fact_survives_eof_after_command_complete() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "COMMIT")?;
        socket.write_all(&frame(b'C', b"COMMIT\0"))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        let transaction = connection.begin_transaction().await.expect("BEGIN");
        assert!(matches!(transaction.commit().await, Err(Error::Io(_))));
        assert_eq!(
            connection.take_transaction_end(),
            Some(TransactionEnd::Committed)
        );
        assert_eq!(connection.take_transaction_end(), None);
        assert!(!connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn abandoned_commit_keeps_identity_until_recovery_observes_the_end() {
    let seen = Arc::new(AtomicBool::new(false));
    let peer_seen = seen.clone();
    let (release, wait) = mpsc::channel();
    let peer = transaction_peer(move |socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "COMMIT")?;
        peer_seen.store(true, Ordering::Release);
        wait.recv_timeout(peer::IO_DEADLINE)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "commit release"))?;
        socket.write_all(&command("COMMIT", b'I'))?;
        let mut byte = [0];
        if socket.read(&mut byte)? != 0 {
            return Err(invalid(
                "recovery must not replace confirmed COMMIT with another command",
            ));
        }
        Ok(())
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        let transaction = connection.begin_transaction().await.expect("BEGIN");
        match select(Box::pin(transaction.commit()), Box::pin(wait_seen(seen))).await {
            Either::Left(_) => panic!("commit completed before the peer released its result"),
            Either::Right(((), unfinished)) => drop(unfinished),
        }
        assert!(!connection.is_usable());
        release.send(()).expect("release commit result");
        let recovered = connection
            .recover_and_rollback()
            .await
            .expect("recover known COMMIT");
        assert_eq!(recovered.kind, ControlKind::Commit);
        assert_eq!(recovered.transaction_end, Some(TransactionEnd::Committed));
        assert!(connection.is_usable());
        connection.discard();
    });
    peer.finish();
}

#[test]
fn invalid_savepoint_names_have_no_protocol_side_effect() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_query(socket, "ROLLBACK")?;
        socket.write_all(&command("ROLLBACK", b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        for name in [
            "".to_owned(),
            "s\0x".to_owned(),
            "x".repeat(64),
            "界".repeat(22),
        ] {
            for result in [
                transaction.savepoint(&name).await,
                transaction.release_savepoint(&name).await,
                transaction.rollback_to_savepoint(&name).await,
            ] {
                assert!(matches!(result, Err(Error::InvalidInput(_))));
            }
        }
        transaction
            .rollback()
            .await
            .expect("rollback after local rejection");
        connection.discard();
    });
    peer.finish();
}

fn live_config() -> TcpConfig {
    live::tcp_config(peer::prepared::limits(), peer::TCP_OPTIONS)
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_savepoint_error_recovery_and_commit() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.expect("SCRAM connect");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        transaction.savepoint("sp").await.expect("savepoint");
        assert!(matches!(
            transaction.query_scalar(&statement, Some(0)).await,
            Err(Error::Database(_))
        ));
        assert!(matches!(
            transaction.query_scalar(&statement, Some(5)).await,
            Err(Error::Unsupported(_))
        ));
        assert_eq!(
            transaction
                .rollback_to_savepoint("sp")
                .await
                .expect("ROLLBACK TO")
                .transaction_end,
            None
        );
        assert_eq!(
            transaction
                .query_scalar(&statement, Some(5))
                .await
                .expect("query"),
            Some(2)
        );
        transaction.release_savepoint("sp").await.expect("release");
        assert_eq!(
            transaction.commit().await.expect("COMMIT").transaction_end,
            Some(TransactionEnd::Committed)
        );
        connection.close_prepared(&statement).await.expect("close");
        connection.discard();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_commit_of_failed_transaction_reports_rollback() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.expect("SCRAM connect");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        assert!(matches!(
            transaction.query_scalar(&statement, Some(0)).await,
            Err(Error::Database(_))
        ));
        let completion = transaction
            .commit()
            .await
            .expect("COMMIT in failed transaction");
        assert_eq!(completion.kind, ControlKind::Rollback);
        assert_eq!(completion.transaction_end, Some(TransactionEnd::RolledBack));
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_and_chain_and_explicit_abandoned_guard_recovery() {
    let config = live_config();
    run(async {
        let mut connection = TcpConnection::connect(config).await.expect("SCRAM connect");
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar(SQL).await.expect("prepare");
        let mut transaction = connection.begin_transaction().await.expect("BEGIN");
        assert_eq!(
            transaction
                .commit_and_chain()
                .await
                .expect("COMMIT AND CHAIN")
                .transaction_status,
            TransactionStatus::InTransaction
        );
        assert!(matches!(
            transaction.query_scalar(&statement, Some(0)).await,
            Err(Error::Database(_))
        ));
        let failed_chain = transaction
            .commit_and_chain()
            .await
            .expect("failed COMMIT AND CHAIN");
        assert_eq!(
            failed_chain.transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        assert_eq!(
            failed_chain.transaction_status,
            TransactionStatus::InTransaction
        );
        assert_eq!(
            transaction
                .query_scalar(&statement, Some(5))
                .await
                .expect("query in chained transaction"),
            Some(2)
        );
        assert_eq!(
            transaction
                .rollback_and_chain()
                .await
                .expect("ROLLBACK AND CHAIN")
                .transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        drop(transaction);
        assert!(!connection.is_usable());
        assert_eq!(
            connection
                .recover_and_rollback()
                .await
                .expect("explicit rollback")
                .transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
fn idle_recovery_does_not_invent_a_rollback_outcome_or_send_sql() {
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        let mut byte = [0];
        if socket.read(&mut byte)? != 0 {
            return Err(io::Error::other(
                "idle recovery sent an unauthorized rollback",
            ));
        }
        Ok(())
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        assert!(matches!(
            connection.recover_and_rollback().await,
            Err(Error::Unsupported(_))
        ));
        assert!(connection.is_usable());
        connection
            .close_local()
            .await
            .expect("retire idle connection");
    });
    peer.finish();
}

#[test]
fn raw_guarded_commit_fact_survives_eof_without_ready() {
    use compio_postgres::{QueryLimits, ResultFormats, types::Format};
    let peer = transaction_peer(|socket| {
        handshake(socket)?;
        expect_query(socket, "BEGIN")?;
        socket.write_all(&command("BEGIN", b'T'))?;
        expect_tags(socket, b"PBDES")?;
        let mut response = frame(b'1', &[]);
        response.extend(frame(b'2', &[]));
        response.extend(frame(b'n', &[]));
        response.extend(frame(b'C', b"COMMIT\0"));
        socket.write_all(&response)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.config())
            .await
            .expect("connect");
        {
            let mut transaction = connection.begin_transaction().await.expect("begin");
            let mut query = transaction
                .one_shot(
                    "COMMIT",
                    &[],
                    ResultFormats::All(Format::Binary),
                    compio_postgres::QueryOptions {
                        limits: QueryLimits {
                            max_rows: 0,
                            max_result_bytes: 0,
                            max_metadata_bytes: 4096,
                        },
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .expect("admit raw commit");
            assert!(matches!(query.finish().await, Err(Error::Io(_))));
        }
        assert_eq!(
            connection.take_transaction_end(),
            Some(TransactionEnd::Committed)
        );
        assert!(!connection.is_usable());
        assert!(matches!(
            connection.recover_and_rollback().await,
            Err(Error::Broken)
        ));
        connection
            .close_local()
            .await
            .expect("retire failed connection");
    });
    peer.finish();
}

#[test]
fn a_commit_with_an_admitted_successor_discards_all_window_variants() {
    use compio_postgres::{
        AbandonPolicy, AllocationPolicy, BatchErrorOrigin, BatchOptions, ClientOptions,
        ExecutionScheduling, OnError, OwnedOutput, PreparedStatementStorage, QueryLimits,
        ResultFormats, TcpConnection, types::Format,
    };

    for on_error in [
        Some(OnError::DrainToReady),
        Some(OnError::RecoverExplicitly),
        None,
    ] {
        let peer = transaction_peer(|socket| {
            handshake(socket)?;
            let commit = peer::prepare(socket, &[], &[])?;
            let successor = peer::prepare(socket, &[], &[23])?;
            expect_query(socket, "BEGIN")?;
            socket.write_all(&command("BEGIN", b'T'))?;
            peer::execution(socket, &commit)?;
            peer::execution(socket, &successor)?;
            let mut response = frame(b'2', &[]);
            response.extend(command("COMMIT", b'I'));
            response.extend(peer::result(42, b'I'));
            socket.write_all(&response)?;
            peer::eof(socket)
        });
        run(async {
            let mut connection =
                TcpConnection::connect(ClientOptions::short_queries(peer.config()))
                    .await
                    .unwrap();
            let commit = connection
                .prepare(
                    "COMMIT",
                    &[],
                    PreparedStatementStorage::Named,
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let successor = connection
                .prepare(
                    "SELECT 42",
                    &[],
                    PreparedStatementStorage::Named,
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let mut tx = connection.begin_transaction().await.unwrap();
            let batch = tx
                .streaming_batch([commit.bind(&[]), successor.bind(&[])])
                .with_options(BatchOptions {
                    member_limits: QueryLimits {
                        max_rows: 1,
                        max_result_bytes: 64,
                        max_metadata_bytes: 4096,
                    },
                    max_requests: 2,
                    max_inflight: 2,
                    max_queued_request_bytes: 4096,
                    max_diagnostic_bytes: 4096,
                    scheduling: ExecutionScheduling::Uninterrupted,
                });
            let (source, cleanup, origin, admitted) = if let Some(on_error) = on_error {
                let error = batch
                    .collect_ready(
                        OwnedOutput {
                            max_bytes: 4096,
                            allocation: AllocationPolicy::Grow,
                        },
                        on_error,
                    )
                    .await
                    .unwrap_err();
                (
                    error.source,
                    error.cleanup_error,
                    error.origin,
                    error.progress.admitted,
                )
            } else {
                let error = batch
                    .visit_provisional(AbandonPolicy::RecoverExplicitly, |_| {
                        panic!("事务结束后不能交付批次结果")
                    })
                    .await
                    .unwrap_err();
                (
                    error.source,
                    error.cleanup_error,
                    error.origin,
                    error.progress.admitted,
                )
            };
            assert!(matches!(source, Error::Unsupported(_)));
            assert!(cleanup.is_none());
            assert_eq!(origin, BatchErrorOrigin::Protocol);
            assert_eq!(admitted, 2);
            assert_eq!(tx.reuse_state(), ReuseState::DiscardOnly);
            assert_eq!(tx.take_transaction_end(), Some(TransactionEnd::Committed));
            drop(tx);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_raw_commit_inside_a_guard_cannot_be_reported_as_a_later_rollback() {
    use compio_postgres::{QueryLimits, ResultFormats, types::Format};
    run(async {
        let mut connection = TcpConnection::connect(live_config())
            .await
            .expect("connect");
        let mut transaction = connection.begin_transaction().await.expect("begin");
        let limits = QueryLimits {
            max_rows: 0,
            max_result_bytes: 0,
            max_metadata_bytes: 4096,
        };
        {
            let mut query = transaction
                .one_shot(
                    "COMMIT",
                    &[],
                    ResultFormats::All(Format::Binary),
                    compio_postgres::QueryOptions {
                        limits,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .expect("admit explicit raw end");
            query.finish().await.expect("observe committed boundary");
        }
        assert!(matches!(
            transaction
                .one_shot(
                    "SELECT 1",
                    &[],
                    ResultFormats::All(Format::Binary),
                    compio_postgres::QueryOptions {
                        limits,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::Unsupported(_))
        ));
        drop(transaction);
        assert_eq!(
            connection.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        let completion = connection
            .recover_and_rollback()
            .await
            .expect("recover actual acknowledged end");
        assert_eq!(completion.transaction_end, Some(TransactionEnd::Committed));
        assert!(connection.is_usable());
        assert_eq!(connection.take_transaction_end(), None);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.expect("retire connection");
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_raw_rollback_records_an_outer_end_only_at_idle_ready() {
    use compio_postgres::{CommandKind, ExecutionScheduling, QueryLimits};

    run(async {
        let mut connection = TcpConnection::connect(live_config())
            .await
            .expect("connect");
        let limits = QueryLimits {
            max_rows: 0,
            max_result_bytes: 0,
            max_metadata_bytes: 4096,
        };
        for sql in ["ROLLBACK TO SAVEPOINT sp", "ROLLBACK AND CHAIN"] {
            let mut transaction = connection.begin_transaction().await.expect("BEGIN");
            transaction.savepoint("sp").await.expect("SAVEPOINT");
            {
                let mut query = transaction
                    .query_simple_single(
                        sql,
                        compio_postgres::QueryOptions {
                            limits,
                            scheduling: ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
                    .expect("admit raw rollback statement");
                let completion = query.finish().await.expect("finish raw rollback statement");
                assert_eq!(completion.command, Some(CommandKind::Rollback));
                assert_eq!(
                    completion.transaction_status,
                    TransactionStatus::InTransaction
                );
            }
            assert_eq!(transaction.take_transaction_end(), None, "{sql}");
            let committed = transaction
                .commit()
                .await
                .expect("commit active transaction");
            assert_eq!(committed.transaction_end, Some(TransactionEnd::Committed));
        }
        {
            let mut transaction = connection.begin_transaction().await.expect("BEGIN");
            let mut query = transaction
                .query_simple_single(
                    "ROLLBACK",
                    compio_postgres::QueryOptions {
                        limits,
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .expect("admit raw outer rollback");
            let completion = query.finish().await.expect("finish raw outer rollback");
            assert_eq!(completion.command, Some(CommandKind::Rollback));
            assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        }
        let completion = connection
            .recover_and_rollback()
            .await
            .expect("take raw rollback fact");
        assert_eq!(completion.transaction_end, Some(TransactionEnd::RolledBack));
        assert!(connection.is_usable());
        connection.close_local().await.expect("retire connection");
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_window_stops_failed_transaction_admission_and_preserves_an_acknowledged_commit_fact() {
    use compio_postgres::{
        QueryLimits, ReadyBatchEvent, ResultFormats, StatementLimits,
        expert::{WindowLimits, WindowParameters, WindowRequest},
        types::{Format, Oid, Parameter},
    };
    run(async {
        let mut connection = TcpConnection::connect(live_config()).await.unwrap();
        connection
            .configure_statements(StatementLimits {
                max_statements: 2,
                max_metadata_bytes: 32768,
            })
            .unwrap();
        let division = connection
            .prepare(
                "SELECT 10/$1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let commit = connection
            .prepare("COMMIT", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let query = QueryLimits {
            max_rows: 1,
            max_result_bytes: 12,
            max_metadata_bytes: 4096,
        };
        let limits = WindowLimits {
            storage: compio_postgres::AllocationPolicy::ReserveLimit,
            max_inflight: 2,
            max_requests: 3,
            max_rows: 3,
            max_result_bytes: 4096,
            max_queued_request_bytes: 1024,
            scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
            },
        };
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut source = [0, 1, 2].into_iter().map(|value| {
            Ok(WindowRequest {
                statement: &division,
                parameters: WindowParameters::One(Parameter::int4(value)),
                limits: query,
            })
        });
        let mut errors = Vec::new();
        let completion = transaction
            .query_window(
                &mut source,
                limits,
                compio_postgres::OnError::RecoverExplicitly,
                &mut |event: ReadyBatchEvent<'_>| {
                    errors.push(
                        event
                            .outcome
                            .expect_err("failed transaction member")
                            .code()
                            .to_owned(),
                    );
                    assert_eq!(
                        event.transaction_status,
                        TransactionStatus::FailedTransaction
                    );
                    Ok(std::ops::ControlFlow::Continue(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(errors, ["22012", "25P02"]);
        assert_eq!(completion.admitted, 2);
        assert!(completion.stopped);
        assert_eq!(
            transaction.rollback().await.unwrap().transaction_end,
            Some(TransactionEnd::RolledBack)
        );
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut source = std::iter::once(Ok(WindowRequest {
            statement: &commit,
            parameters: WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 0,
                max_result_bytes: 0,
                max_metadata_bytes: 4096,
            },
        }));
        let completion = transaction
            .query_window(
                &mut source,
                WindowLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_inflight: 1,
                    max_requests: 1,
                    max_rows: 0,
                    ..limits
                },
                compio_postgres::OnError::RecoverExplicitly,
                &mut |_| Ok(std::ops::ControlFlow::Continue(())),
            )
            .await
            .unwrap();
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        drop(transaction);
        assert_eq!(
            connection
                .recover_and_rollback()
                .await
                .unwrap()
                .transaction_end,
            Some(TransactionEnd::Committed)
        );
        connection.close_prepared(&division).await.unwrap();
        connection.close_prepared(&commit).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_coalescing_window_stops_admission_after_transaction_failure() {
    use std::{cell::Cell, ops::ControlFlow};

    use compio_postgres::{
        QueryLimits, ReadyBatchEvent, ResultFormats, StatementLimits,
        expert::{WindowLimits, WindowParameters, WindowRequest},
        types::{Format, Oid, Parameter},
    };

    run(async {
        let mut connection = TcpConnection::connect(
            live_config().send_policy(compio_postgres::SendPolicy::CoalesceBuffered),
        )
        .await
        .expect("connect with native send coalescing");
        connection
            .configure_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 32768,
            })
            .expect("configure prepared statement capacity");
        let division = connection
            .prepare(
                "SELECT 10/$1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .expect("prepare division");
        let mut transaction = connection.begin_transaction().await.expect("begin");
        let observed = Cell::new(0);
        let mut source = [0, 1, 2, 3, 4].into_iter().map(|value| {
            observed.set(observed.get() + 1);
            Ok(WindowRequest {
                statement: &division,
                parameters: WindowParameters::One(Parameter::int4(value)),
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 12,
                    max_metadata_bytes: 4096,
                },
            })
        });
        let mut delivered_errors = Vec::new();
        let completion = transaction
            .query_window(
                &mut source,
                WindowLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_inflight: 4,
                    max_requests: 5,
                    max_rows: 5,
                    max_result_bytes: 4096,
                    max_queued_request_bytes: 1024,
                    scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                        max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
                    },
                },
                compio_postgres::OnError::RecoverExplicitly,
                &mut |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, delivered_errors.len());
                    assert_eq!(
                        event.transaction_status,
                        TransactionStatus::FailedTransaction
                    );
                    delivered_errors.push(
                        event
                            .outcome
                            .expect_err("failed transaction member")
                            .code()
                            .to_owned(),
                    );
                    Ok(ControlFlow::Continue(()))
                },
            )
            .await
            .expect("failed transaction stops admission and confirms the admitted prefix");
        assert_eq!(observed.get(), 4);
        assert_eq!(delivered_errors, ["22012", "25P02", "25P02", "25P02"]);
        assert_eq!(completion.consumed, 4);
        assert_eq!(completion.admitted, 4);
        assert_eq!(completion.confirmed, 4);
        assert_eq!(completion.delivered, 4);
        assert_eq!(completion.sql_errors, 4);
        assert!(completion.stopped);
        assert!(!completion.admission_limit_reached);
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::FailedTransaction
        );
        drop(transaction);
        assert_eq!(
            connection.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        connection.recover_to_ready().await.unwrap();
        assert_eq!(observed.get(), 4);
        assert_eq!(
            connection.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        let rollback = connection.recover_and_rollback().await.unwrap();
        assert_eq!(rollback.transaction_end, Some(TransactionEnd::RolledBack));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_prepared(&division).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
