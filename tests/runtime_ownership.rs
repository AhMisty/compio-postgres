//! 验证同一线程的不同 runtime 无法接管连接及其在途操作。
#[path = "support/peer.rs"]
mod peer;

use compio::runtime::Runtime;
use compio_postgres::{
    AllocationPolicy, Error, ExecutionScheduling, OnError, OwnedOutput, ResultFormats, ReuseState,
    StatementLimits,
    expert::{CopyProtocol, TcpSession},
    types::Format,
};
use peer::{Peer, control, eof, execution, expect, frame, handshake, invalid, query_limits};
use std::{future::Future, io::Write};

const WRONG_RUNTIME: &str = "the operation must run inside the owning Compio runtime";
const SCHEDULING: ExecutionScheduling = ExecutionScheduling::Uninterrupted;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    compio::time::timeout(peer::DEADLINE, future)
        .await
        .expect("runtime ownership fixture deadline")
}

#[test]
fn connection_startup_cannot_resume_on_another_runtime() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let started = Arc::new(AtomicBool::new(false));
    let received = Arc::clone(&started);
    let (release, hold) = std::sync::mpsc::channel();
    let peer = Peer::start(move |socket| {
        peer::prepared::body(socket)?;
        received.store(true, Ordering::Release);
        // 保持握手未就绪，直到客户端完成外部 runtime 的轮询检查。
        hold.recv_timeout(peer::IO_DEADLINE).unwrap();
        Ok(())
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut connecting = Box::pin(TcpSession::connect(peer.config()));
    owner.block_on(bounded(async {
        use futures_util::future::{Either, select};
        let observed = async {
            while !started.load(Ordering::Acquire) {
                compio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        };
        assert!(matches!(
            select(connecting.as_mut(), Box::pin(observed)).await,
            Either::Right(_)
        ));
    }));
    assert!(matches!(
        foreign.block_on(bounded(connecting)),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    release.send(()).unwrap();
    peer.finish();
}

#[test]
fn a_distinct_runtime_on_the_same_thread_cannot_admit_session_work() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut session = owner.block_on(TcpSession::connect(peer.config())).unwrap();

    assert!(matches!(
        foreign.block_on(bounded(session.begin_transaction())),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    assert!(matches!(
        foreign.block_on(bounded(session.recover_to_ready())),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);

    let mut transaction = owner.clone().block_on(session.begin_transaction()).unwrap();
    assert!(matches!(
        foreign.block_on(bounded(transaction.savepoint("wrong_runtime"))),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    owner.block_on(transaction.rollback()).unwrap();
    owner.block_on(session.close_local()).unwrap();
    peer.finish();
}

#[test]
fn query_continuations_leave_rows_and_abandonment_policy_to_the_owner() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = peer::prepare(socket, &[], &[23])?;
        for value in [41, 42] {
            execution(socket, &statement)?;
            socket.write_all(&peer::result(value, b'I'))?;
        }
        eof(socket)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut session = owner.block_on(TcpSession::connect(peer.config())).unwrap();
    session
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    let statement = owner
        .block_on(session.prepare("SELECT 41", &[], ResultFormats::All(Format::Binary)))
        .unwrap();
    {
        let mut query = owner
            .block_on(session.query(
                &statement,
                &[],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: SCHEDULING,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            ))
            .unwrap();
        assert!(matches!(
            foreign.block_on(bounded(query.next_row())),
            Err(Error::InvalidInput(WRONG_RUNTIME))
        ));
        let row = owner.block_on(query.next_row()).unwrap().unwrap();
        assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 41);

        assert!(matches!(
            foreign.block_on(bounded(query.finish())),
            Err(Error::InvalidInput(WRONG_RUNTIME))
        ));
        assert_eq!(owner.block_on(query.finish()).unwrap().rows_returned, 1);
    }
    let query = owner
        .block_on(session.query(
            &statement,
            &[],
            compio_postgres::QueryOptions {
                limits: query_limits(),
                scheduling: SCHEDULING,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        ))
        .unwrap();
    let collection = query.collect_with(AllocationPolicy::Grow, OnError::Discard);
    assert!(matches!(
        foreign.block_on(bounded(collection)),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    owner.block_on(session.recover_to_ready()).unwrap();
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    owner.block_on(session.close_local()).unwrap();
    peer.finish();
}

#[test]
fn copy_input_rejects_foreign_sends_before_they_touch_the_socket() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        expect(socket, b'Q')?;
        socket.write_all(&frame(b'G', &[0, 0, 1, 0, 0]))?;
        if expect(socket, b'd')? != b"owner\n" || !expect(socket, b'c')?.is_empty() {
            return Err(invalid());
        }
        let mut end = frame(b'C', b"COPY 1\0");
        end.extend(peer::ready(b'I'));
        socket.write_all(&end)?;
        eof(socket)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut session = owner.block_on(TcpSession::connect(peer.config())).unwrap();
    let mut input = owner
        .block_on(session.copy_in(
            "COPY fixture FROM STDIN",
            &[],
            CopyProtocol::SimpleSingle,
            SCHEDULING,
        ))
        .unwrap();
    let rejected = foreign.block_on(bounded(input.send(b"foreign\n")));
    assert!(
        matches!(rejected, Err(Error::InvalidInput(WRONG_RUNTIME))),
        "{rejected:?}"
    );
    let error = foreign
        .block_on(bounded(input.send_batch(
            &[b"foreign\n"],
            compio_postgres::CopyBatchLimits {
                max_chunks: 1,
                max_packet_bytes: 64,
            },
        )))
        .unwrap_err();
    assert!(!error.may_have_been_sent);
    assert!(matches!(error.source, Error::InvalidInput(WRONG_RUNTIME)));
    let mut packet = compio_postgres::CopyDataBuffer::new(16).unwrap();
    packet.extend_from_slice(b"foreign\n").unwrap();
    assert!(matches!(
        foreign.block_on(bounded(input.send_owned(packet))),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    owner.block_on(input.send(b"owner\n")).unwrap();
    assert_eq!(owner.block_on(input.finish()).unwrap().rows, 1);
    owner.block_on(session.close_local()).unwrap();
    peer.finish();
}

#[test]
fn copy_output_continuations_preserve_the_original_recovery_on_a_foreign_runtime() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        expect(socket, b'Q')?;
        let mut response = frame(b'H', &[0, 0, 1, 0, 0]);
        response.extend(frame(b'd', b"first\n"));
        response.extend(frame(b'd', b"second\n"));
        response.extend(frame(b'c', &[]));
        response.extend(frame(b'C', b"COPY 2\0"));
        response.extend(peer::ready(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    let owner = Runtime::new().unwrap();
    let foreign = Runtime::new().unwrap();
    let mut session = owner.block_on(TcpSession::connect(peer.config())).unwrap();
    let mut output = owner
        .block_on(session.copy_out(
            "COPY fixture TO STDOUT",
            &[],
            CopyProtocol::SimpleSingle,
            SCHEDULING,
        ))
        .unwrap();
    assert_eq!(
        owner
            .block_on(output.next_chunk())
            .unwrap()
            .unwrap()
            .bytes(),
        b"first\n"
    );
    assert!(matches!(
        foreign.block_on(bounded(output.next_chunk())),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    assert_eq!(
        owner
            .block_on(output.next_chunk())
            .unwrap()
            .unwrap()
            .bytes(),
        b"second\n"
    );
    assert!(matches!(
        foreign.block_on(bounded(output.collect_ready(
            OwnedOutput {
                max_bytes: 64,
                allocation: AllocationPolicy::ReserveLimit,
            },
            OnError::Discard,
        ))),
        Err(Error::InvalidInput(WRONG_RUNTIME))
    ));
    assert_eq!(session.reuse_state(), ReuseState::NeedsCopyCompletion);
    assert_eq!(
        owner
            .block_on(session.finish_abandoned_copy_out())
            .unwrap()
            .rows,
        2
    );
    owner.block_on(session.close_local()).unwrap();
    peer.finish();
}
