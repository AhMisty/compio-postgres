#[path = "support/live.rs"]
mod live;
#[path = "support/peer.rs"]
mod peer;

use std::{
    io::{self, Write},
    net::TcpStream,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use compio_postgres::{
    CommandKind, Error, ExecutionScheduling, PortalFetchCompletion, PortalFetchLimits,
    ResultFormats, ReuseState, StatementLimits, TcpConfig, TransactionEnd, TransactionStatus,
    WireLimits, expert::TcpSession, types::Format,
};
use peer::{Peer, control, eof, expect, frame, handshake, prepare, ready, row, run, sql_error};

async fn connect(config: TcpConfig) -> TcpSession {
    let mut session = TcpSession::connect(config).await.unwrap();
    session
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    session
}

fn fetch(rows: u32) -> PortalFetchLimits {
    PortalFetchLimits {
        max_rows: NonZeroU32::new(rows).unwrap(),
        max_result_bytes: 4096,
        scheduling: ExecutionScheduling::Uninterrupted,
    }
}

fn split_name(bytes: &[u8]) -> (&[u8], &[u8]) {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap();
    (&bytes[..end], &bytes[end + 1..])
}

fn bind(socket: &mut TcpStream, statement: &str) -> io::Result<Vec<u8>> {
    let bytes = expect(socket, b'B')?;
    let (portal, rest) = split_name(&bytes);
    assert!(!portal.is_empty());
    let (actual_statement, formats) = split_name(rest);
    assert_eq!(actual_statement, statement.as_bytes());
    assert_eq!(formats, [0, 0, 0, 0, 0, 1, 0, 1]);
    Ok(portal.to_vec())
}

fn execute(socket: &mut TcpStream, name: &[u8], rows: i32) -> io::Result<()> {
    let bytes = expect(socket, b'E')?;
    let (portal, count) = split_name(&bytes);
    assert_eq!(portal, name);
    assert_eq!(count, rows.to_be_bytes());
    assert!(expect(socket, b'S')?.is_empty());
    Ok(())
}

#[test]
fn portal_combines_first_bind_and_fetch_and_closes_explicitly() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let portal = bind(socket, &statement)?;
        execute(socket, &portal, 1)?;
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&17_i32.to_be_bytes())]));
        response.extend(frame(b's', &[]));
        response.extend(frame(b'A', b"\0\0\0\x07events\0ignored\0"));
        response.extend(ready(b'T'));
        socket.write_all(&response)?;

        execute(socket, &portal, 2)?;
        let mut response = row(&[Some(&23_i32.to_be_bytes())]);
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(ready(b'T'));
        socket.write_all(&response)?;

        let body = expect(socket, b'C')?;
        assert_eq!(body.first(), Some(&b'P'));
        let (portal_name, tail) = split_name(&body[1..]);
        assert_eq!(portal_name, portal);
        assert!(tail.is_empty());
        assert!(expect(socket, b'S')?.is_empty());
        let mut response = frame(b'3', &[]);
        response.extend(ready(b'T'));
        socket.write_all(&response)?;
        control(socket, b"COMMIT\0", b"COMMIT\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config()).await;
        let statement = session
            .prepare(
                "SELECT 17 UNION ALL SELECT 23",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        transaction.trim_send_buffer().unwrap();
        for explicitly_close in [false, true] {
            let unbound = transaction.portal(&statement, &[]).unwrap();
            if explicitly_close {
                unbound.close().await.unwrap();
            } else {
                drop(unbound);
            }
            assert!(transaction.trim_send_buffer().unwrap() > 0);
            assert_eq!(transaction.trim_send_buffer().unwrap(), 0);
        }
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        let mut rows = Vec::new();
        let first = portal
            .fetch_provisional(fetch(1), |row| {
                rows.push(row.decoder().decode_next::<i32>()?);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(first, PortalFetchCompletion::Suspended { rows_returned: 1 });
        let end = portal
            .fetch_provisional(fetch(2), |row| {
                rows.push(row.decoder().decode_next::<i32>()?);
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            end,
            PortalFetchCompletion::Complete(completion)
                if completion.rows_returned == 1
                    && completion.rows_affected == Some(1)
                    && completion.transaction_status == TransactionStatus::InTransaction
        ));
        assert_eq!(rows, [17, 23]);
        assert!(matches!(
            portal.fetch_provisional(fetch(1), |_| Ok(())).await,
            Err(Error::InvalidInput("the portal has no more rows"))
        ));
        portal.close().await.unwrap();
        transaction.commit().await.unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn portal_sql_error_releases_scope_for_transaction_rollback() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let portal = bind(socket, &statement)?;
        execute(socket, &portal, 1)?;
        socket.write_all(&sql_error("22012", b'E'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config()).await;
        let statement = session
            .prepare("SELECT 1 / 0", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        assert!(matches!(
            portal.fetch_provisional(fetch(1), |_| Ok(())).await,
            Err(Error::Database(error)) if error.code() == "22012"
        ));
        portal.close().await.unwrap();
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        transaction.rollback().await.unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn forgotten_bound_portal_cannot_become_idle_through_recovery() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let portal = bind(socket, &statement)?;
        execute(socket, &portal, 1)?;
        let mut response = frame(b'2', &[]);
        response.extend(row(&[Some(&1_i32.to_be_bytes())]));
        response.extend(frame(b's', &[]));
        response.extend(ready(b'T'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = connect(peer.config()).await;
        let statement = session
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        assert_eq!(
            portal
                .fetch_provisional(fetch(1), |_| Ok(()))
                .await
                .unwrap(),
            PortalFetchCompletion::Suspended { rows_returned: 1 }
        );
        std::mem::forget(portal);
        drop(transaction);
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        assert!(matches!(
            session.recover_to_ready().await,
            Err(Error::Broken)
        ));
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn dropping_a_fetch_waiter_after_handoff_discards_the_transaction_session() {
    let admitted = Arc::new(AtomicBool::new(false));
    let observed_admission = Arc::clone(&admitted);
    let peer = Peer::start(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let portal = bind(socket, &statement)?;
        execute(socket, &portal, 1)?;
        observed_admission.store(true, Ordering::Release);
        eof(socket)
    });
    run(async {
        use futures_util::future::{Either, select};

        let mut session = connect(peer.config()).await;
        let statement = session
            .prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        let wait_for_admission = async {
            while !admitted.load(Ordering::Acquire) {
                compio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        match select(
            Box::pin(portal.fetch_provisional(fetch(1), |_| Ok(()))),
            Box::pin(wait_for_admission),
        )
        .await
        {
            Either::Left(_) => panic!("the peer has not sent a fetch response"),
            Either::Right(((), waiting)) => drop(waiting),
        }
        assert!(matches!(portal.close().await, Err(Error::Broken)));
        drop(transaction);
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_portal_at_the_fetch_limit_requires_a_final_empty_fetch() {
    run(async {
        let config = live::tcp_config(WireLimits::short_queries(), peer::TCP_OPTIONS);
        let mut session = connect(config).await;
        let statement = session
            .prepare(
                "SELECT n FROM generate_series(17, 18) AS rows(n) ORDER BY n",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let mut transaction = session.begin_transaction().await.unwrap();
        let mut portal = transaction.portal(&statement, &[]).unwrap();
        for expected in [17, 18] {
            let mut value = None;
            let completion = portal
                .fetch_provisional(fetch(1), |row| {
                    assert!(value.is_none());
                    let mut fields = row.decoder();
                    value = Some(fields.decode_next::<i32>()?);
                    fields.finish()?;
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(value, Some(expected));
            assert_eq!(
                completion,
                PortalFetchCompletion::Suspended { rows_returned: 1 }
            );
        }
        let completion = portal
            .fetch_provisional(fetch(1), |_| panic!("最后一次提取没有结果行"))
            .await
            .unwrap();
        assert!(
            matches!(completion, PortalFetchCompletion::Complete(completion)
            if completion.command == Some(CommandKind::Select)
                && completion.rows_returned == 0
                && completion.rows_affected == Some(0)
                && completion.transaction_status == TransactionStatus::InTransaction)
        );
        portal.close().await.unwrap();
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        assert_eq!(
            transaction.commit().await.unwrap().transaction_end,
            Some(TransactionEnd::Committed)
        );
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        session.close_local().await.unwrap();
    });
}
