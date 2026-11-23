//! 预备语句的接纳、元数据预算和报文格式。

#[path = "support/peer.rs"]
mod peer;

use std::{io, io::Write, net::TcpListener};

use compio_postgres::{
    AuthenticationPolicy, BatchOptions, ClientOptions, Column, Error, ExecutionOptions,
    ExecutionScheduling, OnError, PreparedStatementStorage, QueryOptions, ResultFormats,
    ReuseState, RowLayout, StatementLimits, TcpConfig, TcpConnection, WireLimits,
    types::{Format, Oid},
};

#[test]
fn prepared_bind_uses_the_shortest_equivalent_result_formats_after_describe() {
    use Format::{Binary, Text};

    fn cases() -> [(usize, ResultFormats, &'static [u8]); 8] {
        [
            (0, ResultFormats::All(Binary), &[0, 0]),
            (2, ResultFormats::All(Text), &[0, 0]),
            (2, ResultFormats::All(Binary), &[0, 1, 0, 1]),
            (0, ResultFormats::PerColumn(Box::new([])), &[0, 0]),
            (
                1,
                ResultFormats::PerColumn(Box::new([Binary])),
                &[0, 1, 0, 1],
            ),
            (
                3,
                ResultFormats::PerColumn(Box::new([Binary; 3])),
                &[0, 1, 0, 1],
            ),
            (3, ResultFormats::PerColumn(Box::new([Text; 3])), &[0, 0]),
            (
                3,
                ResultFormats::PerColumn(Box::new([Text, Binary, Text])),
                &[0, 3, 0, 0, 0, 1, 0, 0],
            ),
        ]
    }
    let server = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        for (columns, _, wire_codes) in cases() {
            let name = peer::prepare(socket, &[], &vec![23; columns])?;
            let bind = peer::expect(socket, b'B')?;
            // 使用未命名 portal，两个参数计数均为零。
            assert_eq!(&bind[name.len() + 6..], wire_codes);
            peer::expect(socket, b'E')?;
            peer::expect(socket, b'S')?;
            let mut response = peer::frame(b'2', &[]);
            response.extend(peer::frame(b'C', b"SELECT 0\0"));
            response.extend(peer::ready(b'I'));
            socket.write_all(&response)?;
            peer::close_statement(socket, &name)?;
        }

        // 一次性查询在获知列布局前绑定参数。必须保留两个格式码，才能让服务端发现实际只有一列。
        peer::expect(socket, b'P')?;
        let bind = peer::expect(socket, b'B')?;
        assert_eq!(&bind[6..], &[0, 2, 0, 1, 0, 1]);
        peer::expect(socket, b'D')?;
        peer::expect(socket, b'E')?;
        peer::expect(socket, b'S')?;
        let mut response = peer::frame(b'1', &[]);
        response.extend(peer::sql_error("08P01", b'I'));
        socket.write_all(&response)?;
        let name = peer::prepare(socket, &[], &[23])?;
        peer::close_statement(socket, &name)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut client = TcpConnection::connect(ClientOptions::short_queries(server.config()))
            .await
            .unwrap();
        for (_, requested, _) in cases() {
            let statement = client
                .prepare(
                    "SELECT",
                    &[],
                    PreparedStatementStorage::Named,
                    requested.clone(),
                )
                .await
                .unwrap();
            assert_eq!(statement.layout().formats(), &requested);
            let value = client
                .query(&statement, &[])
                .map_provisional_zero_or_one(OnError::DrainToReady, |_| Ok(()))
                .await
                .unwrap();
            assert_eq!(value, None);
            client.close_statement(&statement).await.unwrap();
        }
        let result = client
            .one_shot(
                "SELECT 1",
                &[],
                ResultFormats::PerColumn(Box::new([Binary; 2])),
            )
            .one::<i32>(OnError::DrainToReady)
            .await;
        assert!(matches!(result, Err(Error::Database(error)) if error.code() == "08P01"));
        let wrong_count = client
            .prepare(
                "SELECT 1",
                &[],
                PreparedStatementStorage::Named,
                ResultFormats::PerColumn(Box::new([Binary; 2])),
            )
            .await;
        assert!(matches!(wrong_count, Err(Error::Codec(error))
            if matches!(*error, compio_postgres::types::CodecError::Invalid("result format count differs from the column count"))));
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
        client.close_local().await.unwrap();
    });
    server.finish();
}

fn options(config: TcpConfig, metadata: usize) -> ClientOptions<TcpConfig> {
    let scheduling = ExecutionScheduling::Uninterrupted;
    let limits = peer::query_limits();
    ClientOptions::new(
        config,
        ExecutionOptions {
            query: QueryOptions { limits, scheduling },
            batch: Some(BatchOptions {
                member_limits: limits,
                max_requests: 1,
                max_inflight: 1,
                max_queued_request_bytes: 4096,
                max_diagnostic_bytes: 4096,
                scheduling,
            }),
        },
        StatementLimits {
            max_statements: 1,
            max_metadata_bytes: metadata,
        },
    )
}

#[test]
fn released_wide_statement_metadata_is_reclaimed_before_describe() {
    let server = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        for _ in 0..3 {
            let name = peer::prepare(socket, &[], &[23; 32])?;
            peer::close_statement(socket, &name)?;
        }
        peer::eof(socket)
    });
    peer::run(async {
        let format = ResultFormats::All(Format::Binary);
        let layout_bytes = RowLayout::new(
            (0..32)
                .map(|index| Column::new(format!("column_{index}"), Oid::INT4))
                .collect(),
            format.clone(),
        )
        .unwrap()
        .retained_bytes();
        let options = ClientOptions::direct(
            server.config(),
            QueryOptions {
                limits: peer::query_limits(),
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            StatementLimits {
                max_statements: 3,
                max_metadata_bytes: layout_bytes + layout_bytes / 2,
            },
        );
        let mut connection = TcpConnection::connect(options).await.unwrap();
        let prepare = PreparedStatementStorage::Named;
        let first = connection
            .prepare("SELECT", &[], prepare, format.clone())
            .await
            .unwrap();
        let held = first.new_row_buffer(1, 0).unwrap();
        connection.close_statement(&first).await.unwrap();
        drop(first);
        let error = connection
            .prepare("SELECT", &[], prepare, format.clone())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Codec(error)
            if matches!(*error, compio_postgres::types::CodecError::Limit("column metadata exceeds its storage limit"))));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        drop(held);
        let second = connection
            .prepare("SELECT", &[], prepare, format)
            .await
            .unwrap();
        connection.close_statement(&second).await.unwrap();
        connection.close_local().await.unwrap();
    });
    server.finish();
}

#[test]
fn prepare_preserves_local_and_server_errors_and_rejects_an_early_ready() {
    for sql_error in [false, true] {
        let server = peer::Peer::start(move |socket| {
            peer::handshake(socket)?;
            let parse = peer::expect(socket, b'P')?;
            let name = parse.split(|&byte| byte == 0).next().unwrap();
            peer::expect(socket, b'D')?;
            peer::expect(socket, b'S')?;
            let mut response = peer::frame(b'1', &[]);
            let mut oids = Vec::from(100_u16.to_be_bytes());
            for _ in 0..100 {
                oids.extend_from_slice(&23_u32.to_be_bytes());
            }
            response.extend(peer::frame(b't', &oids));
            if sql_error {
                response.extend(peer::sql_error("42P01", b'I'));
            } else {
                response.extend(peer::ready(b'I'));
            }
            socket.write_all(&response)?;
            if sql_error {
                peer::close_statement(socket, std::str::from_utf8(name).unwrap())?;
            }
            peer::eof(socket)
        });
        peer::run(async {
            let mut connection = TcpConnection::connect(options(server.config(), 384))
                .await
                .unwrap();
            let result = connection
                .prepare(
                    "SELECT",
                    &[],
                    PreparedStatementStorage::Named,
                    ResultFormats::All(Format::Text),
                )
                .await;
            let Err(Error::Cleanup { primary, cleanup }) = result else {
                panic!("expected both the metadata and cleanup error");
            };
            assert!(matches!(*primary, Error::Limit(_)));
            if sql_error {
                assert!(matches!(*cleanup, Error::Database(error) if error.code() == "42P01"));
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            } else {
                assert!(matches!(*cleanup, Error::Protocol(_)));
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            }
            connection.close_local().await.unwrap();
        });
        server.finish();
    }
}

#[test]
fn single_prepare_closes_only_a_created_undelivered_statement_and_keeps_both_errors() {
    use compio_postgres::expert::TcpSession;
    use peer::prepared::{close_complete, expect_closes, prepare_no_data, read_prepare};

    for (parsed, in_transaction, fail_close) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let server = peer::Peer::start(move |socket| {
            peer::handshake(socket)?;
            if in_transaction {
                peer::control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
            }
            let name = read_prepare(socket)?;
            let status = if in_transaction { b'E' } else { b'I' };
            let mut response = Vec::new();
            if parsed {
                response.extend(peer::frame(b'1', &[]));
            }
            response.extend(peer::sql_error("42501", status));
            socket.write_all(&response)?;
            if parsed {
                expect_closes(socket, std::slice::from_ref(&name))?;
                if fail_close {
                    socket.write_all(&peer::sql_error("XX000", status))?;
                    expect_closes(socket, &[name])?;
                }
                socket.write_all(&close_complete(status))?;
            }
            if in_transaction {
                peer::control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
            }
            let next = prepare_no_data(socket, b'I')?;
            peer::close_statement(socket, &next)?;
            peer::eof(socket)
        });
        peer::run(async {
            let mut session = TcpSession::connect(server.config()).await.unwrap();
            session
                .configure_statements(StatementLimits {
                    max_statements: 1,
                    max_metadata_bytes: 4096,
                })
                .unwrap();
            let format = ResultFormats::All(Format::Binary);
            let error = if in_transaction {
                let mut tx = session.begin_transaction().await.unwrap();
                let error = tx
                    .prepare("UPDATE t SET n=n", &[], format.clone())
                    .await
                    .unwrap_err();
                assert_eq!(
                    tx.transaction_status(),
                    compio_postgres::TransactionStatus::FailedTransaction
                );
                tx.rollback().await.unwrap();
                error
            } else {
                session
                    .prepare("UPDATE t SET n=n", &[], format.clone())
                    .await
                    .unwrap_err()
            };
            if fail_close {
                let Error::Cleanup { primary, cleanup } = error else {
                    panic!("expected the SQL and close errors")
                };
                assert!(matches!(*primary, Error::Database(error) if error.code() == "42501"));
                assert!(matches!(*cleanup, Error::Database(error) if error.code() == "XX000"));
                session
                    .close_all_statements(compio_postgres::StatementPipelineLimits {
                        max_statements: 1,
                        max_packet_bytes: 1024,
                        max_result_bytes: 4096,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    })
                    .await
                    .unwrap();
            } else {
                assert!(matches!(error, Error::Database(error) if error.code() == "42501"));
            }
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            let next = session
                .prepare("UPDATE t SET n=1", &[], format)
                .await
                .unwrap();
            session.close_prepared(&next).await.unwrap();
            session.close_local().await.unwrap();
        });
        server.finish();
    }
}

#[test]
fn impossible_slot_budget_rejects_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = TcpConfig::plaintext(
        listener.local_addr().unwrap(),
        "test",
        "test",
        AuthenticationPolicy::AllowAuthenticationOk,
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 64,
        },
        peer::TCP_OPTIONS,
    );
    peer::run(async {
        assert!(matches!(
            TcpConnection::connect(options(config, 1)).await,
            Err(Error::Limit("statement slots exceed the metadata limit"))
        ));
    });
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn impossible_empty_metadata_rejects_before_parse() {
    let server = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut connection = TcpConnection::connect(options(server.config(), 128))
            .await
            .unwrap();
        let result = connection
            .prepare(
                "SELECT",
                &[],
                PreparedStatementStorage::Named,
                ResultFormats::All(Format::Binary),
            )
            .await;
        assert!(matches!(
            result,
            Err(Error::Limit(
                "minimum statement metadata exceeds its budget"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    server.finish();
}

#[cfg(target_pointer_width = "64")]
#[test]
fn inferred_parameters_reserve_room_for_the_minimum_layout() {
    let server = peer::Peer::start(|socket| {
        peer::handshake(socket)?;
        let name = peer::prepare(socket, &[23; 32], &[])?;
        peer::close_statement(socket, &name)?;
        peer::eof(socket)
    });
    peer::run(async {
        let mut connection = TcpConnection::connect(options(server.config(), 256))
            .await
            .unwrap();
        let result = connection
            .prepare(
                "UPDATE t SET n = $32",
                &[],
                PreparedStatementStorage::Named,
                ResultFormats::All(Format::Binary),
            )
            .await;
        assert!(matches!(
            result,
            Err(Error::Limit(
                "minimum statement metadata exceeds its budget"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    server.finish();
}
