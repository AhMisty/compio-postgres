//! 验证普通 COPY API 的本地错误处理及数据块借用。
#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{
    AllocationPolicy, ClientOptions, CopyDataBuffer, CopyStreamLimits, Error, ExecutionScheduling,
    OnError, OwnedOutput, PreparedStatementStorage, QueryOptions, ResultFormats, ReuseState,
    StatementLimits, TcpConnection, types::Format,
};
use futures_util::stream;
use peer::{
    Peer, control, eof, expect, frame, handshake, prepare, query_limits, ready, run, sql_error,
};
use std::{io, io::Write, net::TcpStream};

const SCHEDULING: ExecutionScheduling = ExecutionScheduling::Uninterrupted;
const OUTPUT: OwnedOutput = OwnedOutput {
    max_bytes: 1,
    allocation: AllocationPolicy::Grow,
};
const INPUT: CopyStreamLimits = CopyStreamLimits {
    max_chunks: 2,
    max_payload_bytes: 128,
};

async fn connect(peer: &Peer) -> TcpConnection {
    let limits = query_limits();
    TcpConnection::connect(ClientOptions::direct(
        peer.config(),
        QueryOptions {
            limits,
            scheduling: SCHEDULING,
        },
        StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        },
    ))
    .await
    .unwrap()
}

async fn statement(connection: &mut TcpConnection, direction: &str) -> compio_postgres::Statement {
    connection
        .prepare(
            direction,
            &[],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Text),
        )
        .await
        .unwrap()
}

fn start_copy(socket: &mut TcpStream, statement: &str, direction: u8) -> io::Result<Vec<u8>> {
    let mut bind = vec![0];
    bind.extend_from_slice(statement.as_bytes());
    bind.extend_from_slice(&[0; 7]); // 名称终止符、零参数格式、零参数、零结果格式。
    assert_eq!(expect(socket, b'B')?, bind);
    assert_eq!(expect(socket, b'E')?, [0; 5]);
    assert!(expect(socket, if direction == b'H' { b'S' } else { b'H' })?.is_empty());
    let mut response = frame(b'2', &[]);
    response.extend(frame(direction, &[0, 0, 1, 0, 0]));
    Ok(response)
}

fn copy_out_frames(socket: &mut TcpStream, statement: &str) -> io::Result<()> {
    let mut response = start_copy(socket, statement, b'H')?;
    response.extend(frame(b'd', b"1\n"));
    response.extend(frame(b'c', &[]));
    response.extend(frame(b'C', b"COPY 1\0"));
    socket.write_all(&response)
}

#[test]
fn output_capacity_error_obeys_each_selected_policy() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[])?;
            copy_out_frames(socket, &statement)?;
            if policy != OnError::Discard {
                socket.write_all(&ready(b'I'))?;
            }
            eof(socket)
        });
        run(async {
            let mut connection = connect(&peer).await;
            let statement = statement(&mut connection, "COPY values TO STDOUT").await;
            let copy = connection
                .copy_out(&statement, &[], SCHEDULING)
                .await
                .unwrap();
            let error = copy.collect_ready(OUTPUT, policy).await.unwrap_err();
            assert!(matches!(
                error,
                Error::Limit("COPY output exceeds its collection limit")
            ));
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsCopyCompletion);
                    assert_eq!(
                        connection.finish_abandoned_copy_out().await.unwrap().rows,
                        1
                    );
                }
                OnError::Discard => {
                    assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                    assert!(matches!(
                        connection.finish_abandoned_copy_out().await,
                        Err(Error::Broken)
                    ));
                }
            }
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn output_limit_keeps_a_failed_drain_as_separate_error() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[])?;
        let mut response = start_copy(socket, &statement, b'H')?;
        response.extend(frame(b'd', b"1\n"));
        response.extend(frame(b'C', b"SELECT 1\0"));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut connection = connect(&peer).await;
        let statement = statement(&mut connection, "COPY values TO STDOUT").await;
        let copy = connection
            .copy_out(&statement, &[], SCHEDULING)
            .await
            .unwrap();
        let error = copy
            .collect_ready(OUTPUT, OnError::DrainToReady)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Cleanup { primary, cleanup }
                if matches!(*primary, Error::Limit(_)) && matches!(*cleanup, Error::Protocol(_))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn unpolled_output_collector_retains_discard_selection() {
    for forget in [false, true] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[])?;
            copy_out_frames(socket, &statement)?;
            eof(socket)
        });
        run(async {
            let mut connection = connect(&peer).await;
            let statement = statement(&mut connection, "COPY values TO STDOUT").await;
            let copy = connection
                .copy_out(&statement, &[], SCHEDULING)
                .await
                .unwrap();
            let collect = copy.collect_ready(OUTPUT, OnError::Discard);
            if forget {
                std::mem::forget(collect);
            } else {
                drop(collect);
            }
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            assert!(matches!(
                connection.finish_abandoned_copy_out().await,
                Err(Error::Broken)
            ));
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn expert_streams_apply_the_selected_source_error_policy_in_both_scopes() {
    use compio_postgres::{CopyAbort, TransactionStatus, expert::CopyProtocol};

    #[derive(Clone, Copy)]
    enum Input {
        Bytes,
        Packet,
        Recycling,
    }

    for input in [Input::Bytes, Input::Packet, Input::Recycling] {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            for in_transaction in [false, true] {
                let peer = Peer::start(move |socket| {
                    handshake(socket)?;
                    if in_transaction {
                        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
                    }
                    assert_eq!(expect(socket, b'Q')?, b"COPY fixture FROM STDIN\0");
                    socket.write_all(&frame(b'G', &[0, 0, 1, 0, 0]))?;
                    assert_eq!(expect(socket, b'd')?, b"1\n");
                    if policy != OnError::Discard {
                        let message = if policy == OnError::DrainToReady {
                            b"input source failed\0".as_slice()
                        } else {
                            b"application cleanup\0"
                        };
                        assert_eq!(expect(socket, b'f')?, message);
                        socket.write_all(&sql_error(
                            "57014",
                            if in_transaction { b'E' } else { b'I' },
                        ))?;
                        if in_transaction {
                            control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
                        }
                    }
                    eof(socket)
                });
                run(async {
                    let mut client = connect(&peer).await;
                    macro_rules! transfer {
                        ($scope:expr) => {{
                            let scope = $scope;
                            let sql = "COPY fixture FROM STDIN";
                            let protocol = CopyProtocol::SimpleSingle;
                            let failure = Error::InvalidInput("producer failure");
                            let copy = scope.copy_in(sql, &[], protocol, SCHEDULING).await.unwrap();
                            let result = match input {
                                Input::Bytes => {
                                    let mut source = stream::iter([Ok(b"1\n".as_slice()), Err(failure)]);
                                    copy.send_stream(&mut source, INPUT, policy).await
                                }
                                Input::Packet | Input::Recycling => {
                                    let mut packet = CopyDataBuffer::new(2).unwrap();
                                    packet.extend_from_slice(b"1\n").unwrap();
                                    let mut source = stream::iter([Ok(packet), Err(failure)]);
                                    if matches!(input, Input::Packet) {
                                        copy.send_owned_stream(&mut source, INPUT, policy).await
                                    } else {
                                        let mut recycled = 0;
                                        let result = copy.send_owned_stream_recycling(
                                            &mut source, INPUT,
                                            |packet| { assert_eq!(packet.payload(), b"1\n"); recycled += 1; Ok(()) },
                                            policy,
                                        ).await;
                                        assert_eq!(recycled, 1);
                                        result
                                    }
                                }
                            };
                            assert!(matches!(result, Err(Error::InvalidInput("producer failure"))));
                            if policy == OnError::RecoverExplicitly {
                                assert!(matches!(scope.fail_abandoned_copy("application cleanup").await.unwrap(),
                                    CopyAbort::Aborted { diagnostic, .. } if diagnostic.code() == "57014"));
                            }
                        }}
                    }
                    if in_transaction {
                        let mut tx = client.begin_transaction().await.unwrap();
                        transfer!(tx.expert());
                        if policy == OnError::Discard {
                            assert_eq!(tx.reuse_state(), ReuseState::DiscardOnly);
                        } else {
                            assert_eq!(
                                tx.transaction_status(),
                                TransactionStatus::FailedTransaction
                            );
                            tx.rollback().await.unwrap();
                        }
                    } else {
                        transfer!(client.expert());
                    }
                    assert_eq!(
                        client.reuse_state(),
                        if policy == OnError::Discard {
                            ReuseState::DiscardOnly
                        } else {
                            ReuseState::ProtocolIdle
                        }
                    );
                    client.close_local().await.unwrap();
                });
                peer.finish();
            }
        }
    }
}

#[test]
fn input_source_failure_obeys_each_selected_policy() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let peer = Peer::start(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[])?;
            let response = start_copy(socket, &statement, b'G')?;
            socket.write_all(&response)?;
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(expect(socket, b'f')?, b"input source failed\0");
                    expect(socket, b'S')?;
                    socket.write_all(&sql_error("57014", b'I'))?;
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(expect(socket, b'f')?, b"explicit cleanup\0");
                    expect(socket, b'S')?;
                    socket.write_all(&sql_error("57014", b'I'))?;
                }
                OnError::Discard => {}
            }
            eof(socket)
        });
        run(async {
            let mut connection = connect(&peer).await;
            let statement = statement(&mut connection, "COPY values FROM STDIN").await;
            let copy = connection
                .copy_in(&statement, &[], SCHEDULING)
                .await
                .unwrap();
            let mut source = stream::iter([Err(Error::InvalidInput("producer failure"))]);
            let error = copy
                .send_owned_stream_recycling(
                    &mut source,
                    INPUT,
                    |_| panic!("no packet sent"),
                    policy,
                )
                .await
                .unwrap_err();
            assert!(matches!(error, Error::InvalidInput("producer failure")));
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsCopyCompletion);
                    assert!(matches!(
                        connection.fail_abandoned_copy("explicit cleanup").await,
                        Ok(compio_postgres::CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014"
                    ));
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                }
                OnError::Discard => assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly),
            }
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn input_callback_failure_preserves_broken_cleanup_after_packet_retirement() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[])?;
        let response = start_copy(socket, &statement, b'G')?;
        socket.write_all(&response)?;
        assert_eq!(expect(socket, b'd')?, b"1\n");
        assert_eq!(expect(socket, b'f')?, b"recycle callback failed\0");
        expect(socket, b'S')?;
        Ok(())
    });
    run(async {
        let mut connection = connect(&peer).await;
        let statement = statement(&mut connection, "COPY values FROM STDIN").await;
        let copy = connection
            .copy_in(&statement, &[], SCHEDULING)
            .await
            .unwrap();
        let mut packet = CopyDataBuffer::new(128).unwrap();
        packet.extend_from_slice(b"1\n").unwrap();
        let mut source = stream::iter([Ok(packet)]);
        let error = copy
            .send_owned_stream_recycling(
                &mut source,
                INPUT,
                |retired| {
                    assert_eq!(retired.payload(), b"1\n");
                    Err(Error::InvalidInput("callback failed"))
                },
                OnError::DrainToReady,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Cleanup { primary, cleanup }
                if matches!(*primary, Error::InvalidInput("callback failed"))
                    && matches!(*cleanup, Error::Io(_))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn transaction_can_retire_forgotten_live_or_abandoned_copy_chunk() {
    for abandoned in [false, true] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[])?;
            control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
            copy_out_frames(socket, &statement)?;
            socket.write_all(&ready(b'T'))?;
            control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
            eof(socket)
        });
        run(async {
            let mut connection = connect(&peer).await;
            let statement = statement(&mut connection, "COPY values TO STDOUT").await;
            let mut transaction = connection.begin_transaction().await.unwrap();
            let mut copy = transaction
                .copy_out(&statement, &[], SCHEDULING)
                .await
                .unwrap();
            let chunk = copy.next_chunk().await.unwrap().unwrap();
            assert_eq!(chunk.bytes(), b"1\n");
            let _forgotten = std::mem::ManuallyDrop::new(chunk);
            let result = if abandoned {
                drop(copy);
                transaction.finish_abandoned_copy_out().await.unwrap()
            } else {
                copy.finish().await.unwrap()
            };
            assert_eq!(result.rows, 1);
            transaction.rollback().await.unwrap();
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}

#[test]
fn unsupported_encoding_in_copy_out_invalidates_connection() {
    enum Reader {
        Chunk,
        Finish,
        Abandoned,
    }

    for reader in [Reader::Chunk, Reader::Finish, Reader::Abandoned] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[])?;
            let mut response = start_copy(socket, &statement, b'H')?;
            response.extend(frame(b'S', b"client_encoding\0LATIN1\0"));
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let mut connection = connect(&peer).await;
            let statement = statement(&mut connection, "COPY values TO STDOUT").await;
            let mut copy = connection
                .copy_out(&statement, &[], SCHEDULING)
                .await
                .unwrap();
            let result = match reader {
                Reader::Chunk => copy.next_chunk().await.map(|_| ()),
                Reader::Finish => copy.finish().await.map(|_| ()),
                Reader::Abandoned => {
                    drop(copy);
                    connection.finish_abandoned_copy_out().await.map(|_| ())
                }
            };
            assert!(matches!(
                result,
                Err(Error::Unsupported("client_encoding must remain UTF8"))
            ));
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        peer.finish();
    }
}
