//! 普通客户端 API 的集成测试。
#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{
    AbandonPolicy, AllocationPolicy, AuthenticationPolicy, BatchControl, BatchEvent, BatchOptions,
    ClientOptions, Error, ExecutionOptions, ExecutionScheduling, OnError, OwnedOutput,
    PreparedStatementStorage, QueryLimits, QueryOptions, ResultFormats, ReuseState, SendPolicy,
    StatementLimits, TcpConfig, TcpConnection, TransactionStatus, WireLimits,
    types::{Format, Oid, Parameter},
};
use peer::{
    Peer as Fixture, TCP_OPTIONS, control, eof, execution, frame, handshake, prepare, ready,
    result, row, run, sql_error,
};
use std::{
    cell::Cell,
    io::{self, Write},
    net::TcpListener,
    time::Duration,
};

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

const BINARY: ResultFormats = ResultFormats::All(Format::Binary);

#[test]
fn resetting_a_session_retires_remote_and_local_statements_together() {
    let peer = Fixture::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[], &[23])?;
        control(socket, b"DISCARD ALL\0", b"DISCARD ALL\0", b'I')?;
        let new = prepare(socket, &[], &[23])?;
        execution(socket, &new)?;
        socket.write_all(&result(7, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(peer.options()).await.unwrap();
        let old = connection
            .prepare("SELECT 7", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        connection.reset_session().await.unwrap();
        assert!(matches!(
            connection
                .query(&old, &[])
                .one::<i32>(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput(_))
        ));
        let new = connection
            .prepare("SELECT 7", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        assert_eq!(
            connection
                .query(&new, &[])
                .one::<i32>(OnError::RecoverExplicitly)
                .await
                .unwrap(),
            7
        );
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

const FIXTURE_WIRE: WireLimits = WireLimits {
    receive_capacity: 64 * 1024,
    max_frame_len: 65535,
    max_request_len: 1024 * 1024,
    max_messages_per_request: 1024,
};
const STATEMENT_LIMITS: StatementLimits = StatementLimits {
    max_statements: 128,
    max_metadata_bytes: 1024 * 1024,
};
const QUERY_PROFILE: QueryOptions = QueryOptions {
    limits: QueryLimits {
        max_rows: 65_536,
        max_result_bytes: 1024 * 1024,
        max_metadata_bytes: 64 * 1024,
    },
    scheduling: ExecutionScheduling::Cooperative {
        max_work_per_turn: std::num::NonZeroUsize::new(256).unwrap(),
    },
};
const BATCH_PROFILE: BatchOptions = BatchOptions {
    member_limits: QUERY_PROFILE.limits,
    max_requests: 1024,
    max_inflight: 8,
    max_queued_request_bytes: 64 * 1024,
    max_diagnostic_bytes: 64 * 1024,
    scheduling: QUERY_PROFILE.scheduling,
};
const OWNED_OUTPUT: OwnedOutput = OwnedOutput {
    max_bytes: 8 * 1024 * 1024,
    allocation: AllocationPolicy::Grow,
};

impl Fixture {
    fn options(&self) -> ClientOptions<TcpConfig> {
        self.options_with_statements(STATEMENT_LIMITS)
    }
    fn options_with_statements(&self, limits: StatementLimits) -> ClientOptions<TcpConfig> {
        ClientOptions::new(
            self.config_with_limits(FIXTURE_WIRE),
            ExecutionOptions {
                query: QUERY_PROFILE,
                batch: Some(BATCH_PROFILE),
            },
            limits,
        )
    }
}

#[test]
fn short_query_profile_validates_wire_limits_and_executes_a_prepared_query() {
    let config = |endpoint, wire| {
        ClientOptions::short_queries(TcpConfig::plaintext(
            endpoint,
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            wire,
            TCP_OPTIONS,
        ))
    };
    let unconnected = TcpListener::bind("127.0.0.1:0").unwrap();
    unconnected.set_nonblocking(true).unwrap();
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(42, b'I'))?;
        eof(socket)
    });
    run(async {
        let wire = WireLimits::short_queries();
        let invalid = WireLimits {
            receive_capacity: 4,
            ..wire
        };
        assert!(matches!(
            TcpConnection::connect(config(unconnected.local_addr().unwrap(), invalid)).await,
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(
            unconnected.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        // 启动和查询响应都超过五字节初始缓冲，验证扩容后的完整帧能正常交付。
        let mut connection = TcpConnection::connect(config(
            fixture.endpoint,
            WireLimits {
                receive_capacity: 5,
                ..wire
            },
        ))
        .await
        .unwrap();
        let profile = connection.execution_options();
        assert!(profile.batch.is_none());
        assert_eq!(
            profile.query.scheduling,
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(128).unwrap()
            }
        );
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let value = connection
            .query(&statement, &[Parameter::int4(42)])
            .one::<i32>(OnError::RecoverExplicitly)
            .await
            .unwrap();
        assert_eq!(value, 42);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn short_query_profile_reads_a_frame_larger_than_the_initial_buffer() {
    const VALUE_BYTES: usize = 48 * 1024;
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[Oid::BYTEA.0])?;
        for _ in 0..2 {
            execution(socket, &statement)?;
            let mut response = frame(b'2', &[]);
            let value = vec![0x5a; VALUE_BYTES];
            response.extend(row(&[Some(&value)]));
            response.extend(frame(b'C', b"SELECT 1\0"));
            response.extend(ready(b'I'));
            socket.write_all(&response)?;
        }
        eof(socket)
    });
    run(async {
        let wire = WireLimits::short_queries();
        assert!(wire.receive_capacity < VALUE_BYTES);
        let mut connection = TcpConnection::connect(ClientOptions::short_queries(
            fixture.config_with_limits(wire),
        ))
        .await
        .unwrap();
        let statement = connection
            .prepare(
                "SELECT decode(repeat('5a', 49152), 'hex')",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        for _ in 0..2 {
            connection
                .query(&statement, &[])
                .map_provisional_one(OnError::RecoverExplicitly, |row| {
                    let mut decoder = row.decoder();
                    let value = decoder.decode_next::<&[u8]>()?;
                    decoder.finish()?;
                    assert_eq!(value.len(), VALUE_BYTES);
                    assert!(value.iter().all(|&byte| byte == 0x5a));
                    Ok(())
                })
                .await
                .unwrap();
        }
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn scalar_rejects_known_column_count_before_sending_in_both_scopes() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[23], &[23, 23])?;
        let good = prepare(socket, &[], &[23])?;
        execution(socket, &good)?;
        socket.write_all(&result(73, b'I'))?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &good)?;
        socket.write_all(&result(74, b'T'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let wrong = connection
            .prepare(
                "SELECT $1::int4, $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let good = connection
            .prepare("SELECT 73", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let parameters = [Parameter::int4(1)];

        assert!(matches!(
            connection
                .query(&wrong, &[])
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "parameter count differs from the prepared statement"
            ))
        ));
        assert!(matches!(
            connection
                .query(&wrong, &parameters)
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "one requires exactly one result column"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(
            connection
                .query(&good, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            73,
        );

        let mut transaction = connection.begin_transaction().await.unwrap();
        assert!(matches!(
            transaction
                .query(&wrong, &parameters)
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "one requires exactly one result column"
            ))
        ));
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        assert_eq!(
            transaction
                .query(&good, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            74,
        );
        transaction.rollback().await.unwrap();

        connection.expert().invalidate_statements().unwrap();
        assert!(matches!(
            connection
                .query(&wrong, &parameters)
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "statement metadata was invalidated; close and prepare it again"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn strict_terminals_distinguish_shape_cardinality_and_discard() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let scalar = prepare(socket, &[], &[23])?;
        let command = prepare(socket, &[], &[])?;
        for rows in [
            vec![],
            vec![row(&[None])],
            vec![
                row(&[Some(&1_i32.to_be_bytes())]),
                row(&[Some(&2_i32.to_be_bytes())]),
            ],
        ] {
            execution(socket, &scalar)?;
            let mut response = frame(b'2', &[]);
            response.extend(rows.iter().flatten().copied());
            response.extend(frame(b'C', format!("SELECT {}\0", rows.len()).as_bytes()));
            response.extend(ready(b'I'));
            socket.write_all(&response)?;
        }
        for rows in [0, 1, 1] {
            execution(socket, &command)?;
            let mut response = frame(b'2', &[]);
            if rows != 0 {
                response.extend(row(&[]));
            }
            response.extend(frame(b'C', format!("SELECT {rows}\0").as_bytes()));
            response.extend(ready(b'I'));
            socket.write_all(&response)?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let scalar = connection
            .prepare("SELECT 1", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let command = connection
            .prepare(
                "SELECT FROM generate_series(1, 1)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();

        assert!(matches!(
            connection
                .query(&scalar, &[])
                .command_ready(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "command_ready requires a zero-column result layout"
            ))
        ));
        assert!(matches!(
            connection
                .query(&command, &[])
                .zero_or_one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one requires exactly one result column"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        for expected in [None, Some(None)] {
            assert_eq!(
                connection
                    .query(&scalar, &[])
                    .zero_or_one::<Option<i32>>(OnError::Discard)
                    .await
                    .unwrap(),
                expected,
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
        assert!(matches!(
            connection
                .query(&scalar, &[])
                .zero_or_one::<i32>(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one received more than one result row"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        connection.recover_to_ready().await.unwrap();

        let completion = connection
            .query(&command, &[])
            .command_ready(OnError::Discard)
            .await
            .unwrap();
        assert!(completion.succeeded);
        assert_eq!(completion.rows_returned, 0);
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);
        assert!(matches!(
            connection
                .query(&command, &[])
                .command_ready(OnError::DrainToReady)
                .await,
            Err(Error::InvalidInput("command_ready received a result row"))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

        let mut rows = connection
            .query(&command, &[])
            .stream_provisional(AbandonPolicy::RecoverExplicitly)
            .await
            .unwrap();
        assert_eq!(rows.finish().await.unwrap().rows_returned, 1);
        drop(rows);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn row_mappers_share_scalar_cardinality_and_support_multiple_columns() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23, 23])?;
        for count in [1, 0, 2] {
            execution(socket, &statement)?;
            let mut response = frame(b'2', &[]);
            for _ in 0..count {
                response.extend(row(&[
                    Some(&7_i32.to_be_bytes()),
                    Some(&11_i32.to_be_bytes()),
                ]));
            }
            response.extend(frame(b'C', format!("SELECT {count}\0").as_bytes()));
            response.extend(ready(b'I'));
            socket.write_all(&response)?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare("SELECT 7, 11", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let calls = Cell::new(0);
        let map = |row: compio_postgres::RowView<'_, '_>| {
            calls.set(calls.get() + 1);
            let mut columns = row.decoder();
            let pair = (columns.decode_next::<i32>()?, columns.decode_next::<i32>()?);
            columns.finish()?;
            Ok(pair)
        };
        assert_eq!(
            connection
                .query(&statement, &[])
                .map_provisional_one(OnError::RecoverExplicitly, map)
                .await
                .unwrap(),
            (7, 11)
        );
        assert_eq!(
            connection
                .query(&statement, &[])
                .map_provisional_zero_or_one(OnError::RecoverExplicitly, map)
                .await
                .unwrap(),
            None
        );
        assert!(matches!(
            connection
                .query(&statement, &[])
                .map_provisional_zero_or_one(OnError::DrainToReady, map)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one received more than one result row"
            ))
        ));
        assert_eq!(calls.get(), 2);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_options_are_sent_in_one_begin_command() {
    use compio_postgres::{
        ControlCompletion, ControlKind, IsolationLevel, TransactionAccess,
        TransactionDeferrability, TransactionOptions,
    };

    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        for begin in [
            &b"BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE\0"[..],
            &b"BEGIN READ WRITE NOT DEFERRABLE\0"[..],
            &b"BEGIN\0"[..],
        ] {
            control(socket, begin, b"BEGIN\0", b'T')?;
            control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        for options in [
            TransactionOptions {
                isolation: Some(IsolationLevel::Serializable),
                access: Some(TransactionAccess::ReadOnly),
                deferrability: Some(TransactionDeferrability::Deferrable),
            },
            TransactionOptions {
                access: Some(TransactionAccess::ReadWrite),
                deferrability: Some(TransactionDeferrability::NotDeferrable),
                ..TransactionOptions::default()
            },
        ] {
            let transaction = connection.begin_transaction_with(options).await.unwrap();
            assert_eq!(
                transaction.transaction_status(),
                TransactionStatus::InTransaction
            );
            let completion: ControlCompletion = transaction.rollback().await.unwrap();
            assert_eq!(completion.kind, ControlKind::Rollback);
        }
        connection
            .begin_transaction()
            .await
            .unwrap()
            .rollback()
            .await
            .unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn parameterized_one_shot_shares_result_terminals_and_terminates_the_session() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        for (sql, columns, status) in [
            ("SELECT $1::int4", 1_u16, b'I'),
            ("SELECT $1::int4, 9 WHERE false", 2_u16, b'I'),
            ("DELETE FROM example WHERE id = $1", 0_u16, b'T'),
        ] {
            if status == b'T' {
                control(socket, b"BEGIN\0", b"BEGIN\0", status)?;
            }
            let mut parse = Vec::from(format!("\0{sql}\0").as_bytes());
            parse.extend_from_slice(&1_u16.to_be_bytes());
            parse.extend_from_slice(&23_u32.to_be_bytes());
            if peer::expect(socket, b'P')? != parse
                || peer::expect(socket, b'B')?.get(12..16) != Some(&7_i32.to_be_bytes())
                || peer::expect(socket, b'D')? != b"P\0"
                || peer::expect(socket, b'E')? != [0; 5]
                || !peer::expect(socket, b'S')?.is_empty()
            {
                return Err(io::Error::other("unexpected one-shot packet"));
            }
            let mut response = frame(b'1', &[]);
            response.extend(frame(b'2', &[]));
            if columns == 0 {
                response.extend(frame(b'n', &[]));
                response.extend(frame(b'C', b"DELETE 1\0"));
            } else {
                let mut description = Vec::from(columns.to_be_bytes());
                for index in 0..columns {
                    description.extend_from_slice(format!("column_{index}\0").as_bytes());
                    description.extend_from_slice(&0_u32.to_be_bytes());
                    description.extend_from_slice(&0_i16.to_be_bytes());
                    description.extend_from_slice(&23_u32.to_be_bytes());
                    description.extend_from_slice(&4_i16.to_be_bytes());
                    description.extend_from_slice(&(-1_i32).to_be_bytes());
                    description.extend_from_slice(&1_i16.to_be_bytes());
                }
                response.extend(frame(b'T', &description));
                if columns == 1 {
                    response.extend(row(&[Some(&7_i32.to_be_bytes())]));
                    response.extend(frame(b'C', b"SELECT 1\0"));
                } else {
                    response.extend(frame(b'C', b"SELECT 0\0"));
                }
            }
            response.extend(ready(status));
            socket.write_all(&response)?;
        }
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        if !peer::expect(socket, b'X')?.is_empty() {
            return Err(io::Error::other("Terminate must have an empty body"));
        }
        eof(socket)
    });
    run(async {
        let options = fixture.options_with_statements(StatementLimits {
            max_statements: 0,
            max_metadata_bytes: 0,
        });
        let mut connection = TcpConnection::connect(options).await.unwrap();
        assert!(matches!(
            connection
                .prepare("SELECT 7", &[], PreparedStatementStorage::Named, BINARY)
                .await,
            Err(Error::InvalidInput(_))
        ));
        let parameters = [Parameter::int4(7)];
        let value = connection
            .one_shot("SELECT $1::int4", &parameters, BINARY)
            .one::<i32>(OnError::RecoverExplicitly)
            .await
            .unwrap();
        assert_eq!(value, 7);
        assert!(matches!(
            connection
                .one_shot("SELECT $1::int4, 9 WHERE false", &parameters, BINARY)
                .zero_or_one::<i32>(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one requires exactly one result column"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        let mut tx = connection.begin_transaction().await.unwrap();
        let completion = tx
            .one_shot("DELETE FROM example WHERE id = $1", &parameters, BINARY)
            .command_ready(OnError::RecoverExplicitly)
            .await
            .unwrap();
        assert_eq!(completion.rows_affected, Some(1));
        tx.rollback().await.unwrap();
        connection.terminate().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn scalar_checks_cardinality_and_null_without_owned_collection() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(73, b'I'))?;
        execution(socket, &statement)?;
        let mut empty = frame(b'2', &[]);
        empty.extend(frame(b'C', b"SELECT 0\0"));
        empty.extend(ready(b'I'));
        socket.write_all(&empty)?;
        execution(socket, &statement)?;
        let mut multiple = frame(b'2', &[]);
        multiple.extend(row(&[Some(&1_i32.to_be_bytes())]));
        multiple.extend(row(&[Some(&2_i32.to_be_bytes())]));
        multiple.extend(frame(b'C', b"SELECT 2\0"));
        multiple.extend(ready(b'I'));
        socket.write_all(&multiple)?;
        for _ in 0..2 {
            execution(socket, &statement)?;
            let mut null = frame(b'2', &[]);
            null.extend(row(&[None]));
            null.extend(frame(b'C', b"SELECT 1\0"));
            null.extend(ready(b'I'));
            socket.write_all(&null)?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let parameters = [Parameter::int4(73)];
        assert_eq!(
            connection
                .query(&statement, &parameters)
                .one::<i32>(OnError::DrainToReady)
                .await
                .unwrap(),
            73
        );
        assert!(matches!(
            connection
                .query(&statement, &parameters)
                .one::<i32>(OnError::DrainToReady)
                .await,
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            connection
                .query(&statement, &parameters)
                .one::<i32>(OnError::DrainToReady)
                .await,
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            connection
                .query(&statement, &parameters)
                .one::<i32>(OnError::DrainToReady)
                .await,
            Err(Error::Codec(_))
        ));
        assert_eq!(
            connection
                .query(&statement, &parameters)
                .one::<Option<i32>>(OnError::DrainToReady)
                .await
                .unwrap(),
            None
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn zero_row_scalar_applies_all_local_error_policies_after_ready() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let fixture = Fixture::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            let mut bytes = frame(b'2', &[]);
            bytes.extend(frame(b'C', b"SELECT 0\0"));
            bytes.extend(ready(b'I'));
            socket.write_all(&bytes)?;
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let error = connection
                .query(&statement, &[Parameter::int4(1)])
                .one::<i32>(policy)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                Error::InvalidInput("one requires exactly one result row")
            ));
            if policy == OnError::Discard {
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                assert!(matches!(
                    connection.recover_to_ready().await,
                    Err(Error::Broken)
                ));
            } else {
                // Ready 已到达且发送已完成，没有待排空的响应。
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }
            connection.close_local().await.unwrap();
        });
        fixture.finish();
    }
}

#[test]
fn scalar_row_and_byte_limits_use_policy_once_at_either_row_read() {
    for second_row in [false, true] {
        for row_limit in [false, true] {
            for policy in [
                OnError::DrainToReady,
                OnError::RecoverExplicitly,
                OnError::Discard,
            ] {
                let fixture = Fixture::start(|socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    execution(socket, &statement)?;
                    let mut bytes = frame(b'2', &[]);
                    for value in [1_i32, 2] {
                        bytes.extend(row(&[Some(&value.to_be_bytes())]));
                    }
                    bytes.extend(frame(b'C', b"SELECT 2\0"));
                    bytes.extend(ready(b'I'));
                    socket.write_all(&bytes)?;
                    eof(socket)
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    let limits = QueryLimits {
                        max_rows: if row_limit {
                            usize::from(second_row)
                        } else {
                            16
                        },
                        max_result_bytes: if row_limit {
                            128
                        } else if second_row {
                            12
                        } else {
                            11
                        },
                        max_metadata_bytes: 4096,
                    };
                    let error = connection
                        .query(&statement, &[Parameter::int4(1)])
                        .with_options(QueryOptions {
                            limits,
                            scheduling: ExecutionScheduling::Uninterrupted,
                        })
                        .one::<i32>(policy)
                        .await
                        .unwrap_err();
                    if policy == OnError::DrainToReady && !second_row {
                        match error {
                            Error::Cleanup { primary, cleanup } => {
                                assert!(matches!(*primary, Error::Limit(_)));
                                assert!(matches!(*cleanup, Error::Limit(_)));
                            }
                            error => panic!("bounded drain lost failure facts: {error}"),
                        }
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        connection
                            .recover_to_ready_with_limits(16, 1024)
                            .await
                            .unwrap();
                    } else {
                        assert!(matches!(error, Error::Limit(_)));
                        match policy {
                            OnError::DrainToReady => {
                                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                            }
                            OnError::RecoverExplicitly => {
                                assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                                connection
                                    .recover_to_ready_with_limits(16, 1024)
                                    .await
                                    .unwrap();
                            }
                            OnError::Discard => {
                                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly)
                            }
                        }
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn scalar_local_errors_return_or_drain_only_as_requested() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        for decode_failure in [false, true] {
            let (release, allowed) = std::sync::mpsc::channel();
            let fixture = Fixture::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[23], &[23])?;
                execution(socket, &statement)?;
                let mut prefix = frame(b'2', &[]);
                if decode_failure {
                    prefix.extend(row(&[None]));
                } else {
                    prefix.extend(row(&[Some(&1_i32.to_be_bytes())]));
                    prefix.extend(row(&[Some(&2_i32.to_be_bytes())]));
                }
                socket.write_all(&prefix)?;
                if policy != OnError::DrainToReady {
                    allowed
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(|_| io::Error::other("local error was implicitly drained"))?;
                }
                if policy != OnError::Discard {
                    let mut suffix = frame(
                        b'C',
                        if decode_failure {
                            b"SELECT 1\0"
                        } else {
                            b"SELECT 2\0"
                        },
                    );
                    suffix.extend(ready(b'I'));
                    socket.write_all(&suffix)?;
                }
                eof(socket)
            });
            run(async {
                let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                let statement = connection
                    .prepare(
                        "SELECT $1::int4",
                        &[Oid::INT4],
                        PreparedStatementStorage::Named,
                        BINARY,
                    )
                    .await
                    .unwrap();
                let parameters = [Parameter::int4(1)];
                let error = connection
                    .query(&statement, &parameters)
                    .one::<i32>(policy)
                    .await
                    .unwrap_err();
                if decode_failure {
                    assert!(matches!(error, Error::Codec(_)));
                } else {
                    assert!(matches!(error, Error::InvalidInput(_)));
                }
                match policy {
                    OnError::DrainToReady => {
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                    }
                    OnError::RecoverExplicitly => {
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        release.send(()).unwrap();
                        connection.recover_to_ready().await.unwrap();
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    }
                    OnError::Discard => {
                        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                        release.send(()).unwrap();
                        assert!(connection.recover_to_ready().await.is_err());
                    }
                }
                connection.close_local().await.unwrap();
            });
            fixture.finish();
        }
    }
}

#[test]
fn scalar_drain_failure_preserves_the_original_local_error() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        let mut bytes = frame(b'2', &[]);
        bytes.extend(row(&[Some(&1_i32.to_be_bytes())]));
        bytes.extend(row(&[Some(&2_i32.to_be_bytes())]));
        socket.write_all(&bytes)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let error = connection
            .query(&statement, &[Parameter::int4(1)])
            .one::<i32>(OnError::DrainToReady)
            .await
            .unwrap_err();
        match error {
            Error::Cleanup { primary, cleanup } => {
                assert!(matches!(*primary, Error::InvalidInput(_)));
                assert!(matches!(*cleanup, Error::Io(_)));
            }
            error => panic!("lost one failure: {error}"),
        }
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn query_limits_apply_policy_and_do_not_restart_a_failed_bounded_drain() {
    for reuse_arena in [false, true] {
        for row_limit in [false, true] {
            for policy in [
                OnError::DrainToReady,
                OnError::RecoverExplicitly,
                OnError::Discard,
            ] {
                let fixture = Fixture::start(|socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    execution(socket, &statement)?;
                    let mut bytes = frame(b'2', &[]);
                    for value in [1_i32, 2, 3] {
                        bytes.extend(row(&[Some(&value.to_be_bytes())]));
                    }
                    bytes.extend(frame(b'C', b"SELECT 3\0"));
                    bytes.extend(ready(b'I'));
                    socket.write_all(&bytes)?;
                    eof(socket)
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    let limits = QueryLimits {
                        max_rows: if row_limit { 1 } else { 16 },
                        max_result_bytes: if row_limit { 128 } else { 12 },
                        max_metadata_bytes: 4096,
                    };
                    let mut arena = statement
                        .new_row_buffer(16, limits.max_result_bytes)
                        .unwrap();
                    let parameters = [Parameter::int4(1)];
                    let request =
                        connection
                            .query(&statement, &parameters)
                            .with_options(QueryOptions {
                                limits,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            });
                    let error = if reuse_arena {
                        request
                            .collect_into_ready(&mut arena, policy)
                            .await
                            .unwrap_err()
                    } else {
                        request
                            .collect_ready(AllocationPolicy::Grow, policy)
                            .await
                            .unwrap_err()
                    };
                    match policy {
                        OnError::DrainToReady => {
                            match error {
                                Error::Cleanup { primary, cleanup } => {
                                    assert!(matches!(*primary, Error::Limit(_)));
                                    assert!(matches!(*cleanup, Error::Limit(_)));
                                }
                                error => panic!("failed drain facts were lost: {error}"),
                            }
                            // 这次排空只消耗剩余额度。若自动排空第二次，连接就会错误地回到 Idle。
                            assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                            connection
                                .recover_to_ready_with_limits(16, 1024)
                                .await
                                .unwrap();
                        }
                        OnError::RecoverExplicitly => {
                            assert!(matches!(error, Error::Limit(_)));
                            assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                            connection
                                .recover_to_ready_with_limits(16, 1024)
                                .await
                                .unwrap();
                        }
                        OnError::Discard => {
                            assert!(matches!(error, Error::Limit(_)));
                            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                        }
                    }
                    if reuse_arena {
                        assert!(arena.is_empty());
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn expert_row_callback_errors_use_explicit_policy_without_replaying_callback() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let fixture = Fixture::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            let mut bytes = frame(b'2', &[]);
            for value in [1_i32, 2] {
                bytes.extend(row(&[Some(&value.to_be_bytes())]));
            }
            bytes.extend(frame(b'C', b"SELECT 2\0"));
            bytes.extend(ready(b'I'));
            socket.write_all(&bytes)?;
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let calls = Cell::new(0);
            let mut query = connection
                .expert()
                .query(
                    &statement,
                    &[Parameter::int4(1)],
                    compio_postgres::QueryOptions {
                        limits: QUERY_PROFILE.limits,
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let error = query
                .for_each_row(
                    &mut |_| {
                        calls.set(calls.get() + 1);
                        Err(io::Error::other("row callback failure").into())
                    },
                    policy,
                )
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Io(_)));
            drop(query);
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready().await.unwrap();
                }
                OnError::Discard => assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly),
            }
            assert_eq!(calls.get(), 1);
            connection.close_local().await.unwrap();
        });
        fixture.finish();
    }
}

#[test]
fn unpolled_expert_collection_and_callback_futures_persist_the_selected_policy() {
    fn abandon<F>(future: F, forget: bool) {
        if forget {
            std::mem::forget(future);
        } else {
            drop(future);
        }
    }
    for terminal in 0..3 {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            for forget in [false, true] {
                let fixture = Fixture::start(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    if policy != OnError::Discard {
                        execution(socket, &statement)?;
                        socket.write_all(&result(1, b'I'))?;
                    }
                    eof(socket)
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    let mut arena = statement.new_row_buffer(1, 64).unwrap();
                    let mut query = connection
                        .expert()
                        .query(
                            &statement,
                            &[Parameter::int4(1)],
                            compio_postgres::QueryOptions {
                                limits: QUERY_PROFILE.limits,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            compio_postgres::AbandonPolicy::RecoverExplicitly,
                        )
                        .await
                        .unwrap();
                    match terminal {
                        0 => abandon(query.collect_with(AllocationPolicy::Grow, policy), forget),
                        1 => abandon(query.collect_into(&mut arena, policy), forget),
                        _ => {
                            let mut sink =
                                |_: compio_postgres::RowView<'_, '_>| -> Result<(), Error> {
                                    panic!("an unpolled callback cannot run");
                                };
                            abandon(query.for_each_row(&mut sink, policy), forget);
                            drop(query);
                        }
                    }
                    if policy == OnError::Discard {
                        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                        assert!(connection.recover_to_ready().await.is_err());
                    } else {
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        connection.recover_to_ready().await.unwrap();
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn owned_source_io_failure_uses_local_policy_without_replaying_source() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let fixture = Fixture::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            socket.write_all(&result(1, b'I'))?;
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let observed = Cell::new(0);
            let source = (0..3).map(|index| {
                observed.set(observed.get() + 1);
                if index == 0 {
                    Ok(statement.bind_one(Parameter::int4(1)))
                } else {
                    Err(io::Error::other("input failure").into())
                }
            });
            let error = connection
                .streaming_batch(source)
                .with_options(BatchOptions {
                    max_inflight: 1,
                    ..BATCH_PROFILE
                })
                .collect_ready(OWNED_OUTPUT, policy)
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::Io(_)));
            assert_eq!(error.origin, compio_postgres::BatchErrorOrigin::Input);
            assert!(error.cleanup_error.is_none());
            assert_eq!(error.completed.len(), 1);
            assert_eq!(observed.get(), 2);
            assert_eq!(error.progress.consumed, 2);
            assert_eq!(error.progress.admitted, 1);
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready().await.unwrap();
                }
                OnError::Discard => assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly),
            }
            assert_eq!(observed.get(), 2);
            connection.close_local().await.unwrap();
        });
        fixture.finish();
    }
}

#[test]
fn submitted_scalar_and_owned_batch_keep_policy_after_drop_or_forget() {
    use std::{future::Future, task::Poll};
    for batch in [false, true] {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            for forget in [false, true] {
                let (release, allowed) = std::sync::mpsc::channel();
                let fixture = Fixture::start(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    allowed
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(|_| io::Error::other("no abandonment signal"))?;
                    if policy != OnError::Discard {
                        execution(socket, &statement)?;
                        socket.write_all(&result(1, b'I'))?;
                    }
                    // Discard 可在对端读完已提交的请求前关闭连接。
                    if policy == OnError::Discard {
                        peer::drain_until_close(socket)
                    } else {
                        eof(socket)
                    }
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    let parameters = [Parameter::int4(1)];
                    let scalar = async {
                        connection
                            .query(&statement, &parameters)
                            .one::<i32>(policy)
                            .await
                            .map(|_| ())
                    };
                    // 分别构造两个分支，保留各自具体的 future 类型。
                    if !batch {
                        let mut future = Box::pin(scalar);
                        std::future::poll_fn(|cx| {
                            assert!(future.as_mut().poll(cx).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        if forget {
                            std::mem::forget(future);
                        } else {
                            drop(future);
                        }
                    } else {
                        drop(scalar);
                        let source = [statement.bind_one(Parameter::int4(1))];
                        let mut future = Box::pin(
                            connection
                                .streaming_batch(source)
                                .with_options(BatchOptions {
                                    scheduling: ExecutionScheduling::Uninterrupted,
                                    ..BATCH_PROFILE
                                })
                                .collect_ready(OWNED_OUTPUT, policy),
                        );
                        std::future::poll_fn(|cx| {
                            assert!(future.as_mut().poll(cx).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        if forget {
                            std::mem::forget(future);
                        } else {
                            drop(future);
                        }
                    }
                    release.send(()).unwrap();
                    if policy == OnError::Discard {
                        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                        assert!(connection.recover_to_ready().await.is_err());
                    } else {
                        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                        connection.recover_to_ready().await.unwrap();
                        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn provisional_stream_abandonment_persists_on_both_scopes() {
    for abandon in [
        AbandonPolicy::RecoverExplicitly,
        AbandonPolicy::DiscardOnAbandon,
    ] {
        for forget in [false, true] {
            for in_transaction in [false, true] {
                let (release, allowed) = std::sync::mpsc::channel();
                let fixture = Fixture::start(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    if in_transaction {
                        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
                    }
                    execution(socket, &statement)?;
                    socket.write_all(&result(73, if in_transaction { b'T' } else { b'I' }))?;
                    allowed
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(|_| io::Error::other("no stream abandonment signal"))?;
                    if in_transaction && abandon == AbandonPolicy::RecoverExplicitly {
                        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
                    }
                    eof(socket)
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    macro_rules! abandon_stream {
                        ($scope:ident, $ready_state:expr) => {{
                            let parameters = [Parameter::int4(73)];
                            let mut rows = $scope
                                .query(&statement, &parameters)
                                .stream_provisional(abandon)
                                .await
                                .unwrap();
                            {
                                let row: compio_postgres::RowLease<'_> =
                                    rows.next_row().await.unwrap().unwrap();
                                assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 73);
                            }
                            if forget {
                                std::mem::forget(rows);
                            } else {
                                drop(rows);
                            }
                            release.send(()).unwrap();
                            if abandon == AbandonPolicy::DiscardOnAbandon {
                                assert_eq!($scope.reuse_state(), ReuseState::DiscardOnly);
                                assert!($scope.recover_to_ready().await.is_err());
                                assert_eq!($scope.reuse_state(), ReuseState::DiscardOnly);
                            } else {
                                assert_eq!($scope.reuse_state(), ReuseState::NeedsRecovery);
                                $scope.recover_to_ready().await.unwrap();
                                assert_eq!($scope.reuse_state(), $ready_state);
                            }
                        }};
                    }
                    if in_transaction {
                        let mut transaction = connection.begin_transaction().await.unwrap();
                        abandon_stream!(transaction, ReuseState::NeedsTransactionDecision);
                        if abandon == AbandonPolicy::RecoverExplicitly {
                            transaction.rollback().await.unwrap();
                        }
                    } else {
                        abandon_stream!(connection, ReuseState::ProtocolIdle);
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn unpolled_provisional_begin_never_admits_and_success_retires_either_policy() {
    for abandon in [
        AbandonPolicy::RecoverExplicitly,
        AbandonPolicy::DiscardOnAbandon,
    ] {
        for forget in [false, true] {
            for in_transaction in [false, true] {
                let fixture = Fixture::start(move |socket| {
                    handshake(socket)?;
                    let statement = prepare(socket, &[23], &[23])?;
                    if in_transaction {
                        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
                    }
                    // 对端应只收到随后实际轮询的流所发出的一次执行。
                    execution(socket, &statement)?;
                    socket.write_all(&result(73, if in_transaction { b'T' } else { b'I' }))?;
                    if in_transaction {
                        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
                    }
                    eof(socket)
                });
                run(async {
                    let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
                    let statement = connection
                        .prepare(
                            "SELECT $1::int4",
                            &[Oid::INT4],
                            PreparedStatementStorage::Named,
                            BINARY,
                        )
                        .await
                        .unwrap();
                    macro_rules! abandon_unpolled_begin {
                        ($scope:ident, $ready_state:expr) => {{
                            let parameters = [Parameter::int4(73)];
                            let begin = $scope
                                .query(&statement, &parameters)
                                .stream_provisional(abandon);
                            if forget {
                                std::mem::forget(begin);
                            } else {
                                drop(begin);
                            }
                            assert_eq!($scope.reuse_state(), $ready_state);
                            let mut rows = $scope
                                .query(&statement, &parameters)
                                .stream_provisional(abandon)
                                .await
                                .unwrap();
                            {
                                let row = rows.next_row().await.unwrap().unwrap();
                                assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 73);
                            }
                            assert_eq!(rows.finish().await.unwrap().rows_returned, 1);
                            drop(rows);
                            assert_eq!($scope.reuse_state(), $ready_state);
                        }};
                    }
                    if in_transaction {
                        let mut transaction = connection.begin_transaction().await.unwrap();
                        abandon_unpolled_begin!(transaction, ReuseState::NeedsTransactionDecision);
                        transaction.rollback().await.unwrap();
                    } else {
                        abandon_unpolled_begin!(connection, ReuseState::ProtocolIdle);
                    }
                    connection.close_local().await.unwrap();
                });
                fixture.finish();
            }
        }
    }
}

#[test]
fn ready_visits_and_separate_query_collection_reuse_their_owned_arenas() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let mut bytes = result(1, b'I');
        bytes.extend(result(2, b'I'));
        socket.write_all(&bytes)?;
        for value in [3, 4] {
            execution(socket, &statement)?;
            socket.write_all(&result(value, b'I'))?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 64,
            max_metadata_bytes: 4096,
        };
        let mut pointers = Vec::new();
        let progress = connection
            .streaming_batch([
                statement.bind_one(Parameter::int4(1)),
                statement.bind_one(Parameter::int4(2)),
            ])
            .with_options(BatchOptions {
                member_limits: limits,
                max_inflight: 2,
                ..BATCH_PROFILE
            })
            .visit_ready(
                OwnedOutput {
                    max_bytes: 64,
                    allocation: AllocationPolicy::ReserveLimit,
                },
                OnError::RecoverExplicitly,
                |event| {
                    let result = event.outcome.unwrap();
                    let row = result.rows.rows().next().unwrap().unwrap();
                    pointers.push(row.decoder().next_raw().unwrap().bytes.unwrap().as_ptr());
                    Ok(std::ops::ControlFlow::Continue(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(progress.confirmed, 2);
        assert_eq!(progress.consumed, progress.admitted);
        assert_eq!(pointers[0], pointers[1]);
        let mut output = statement.new_row_buffer(1, 64).unwrap();
        pointers.clear();
        for value in [3, 4] {
            connection
                .query(&statement, &[Parameter::int4(value)])
                .with_options(QueryOptions {
                    limits,
                    scheduling: ExecutionScheduling::Uninterrupted,
                })
                .collect_into_ready(&mut output, OnError::RecoverExplicitly)
                .await
                .unwrap();
            let row = output.rows().next().unwrap().unwrap();
            pointers.push(row.decoder().next_raw().unwrap().bytes.unwrap().as_ptr());
            assert_eq!(row.decoder().decode_next::<i32>().unwrap(), value);
        }
        assert_eq!(pointers[0], pointers[1]);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn incompatible_prepared_scalar_results_are_rejected_before_execution() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[], &[25])?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT 'text'::text",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert!(matches!(
            connection
                .query(&statement, &[])
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::Codec(_))
        ));
        assert!(matches!(
            connection
                .query(&statement, &[])
                .zero_or_one::<i32>(OnError::Discard)
                .await,
            Err(Error::Codec(_))
        ));
        let mut output = Vec::with_capacity(1);
        let error = connection
            .streaming_batch([statement.bind(&[])])
            .with_options(BatchOptions {
                max_requests: 1,
                max_inflight: 1,
                ..BATCH_PROFILE
            })
            .collect_one_into_ready::<i32>(&mut output, OnError::Discard)
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Codec(_)));
        assert_eq!(error.progress.admitted, 0);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ready_visitor_break_stops_callbacks_and_confirms_the_admitted_prefix() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let mut bytes = result(1, b'I');
        bytes.extend(frame(b'2', &[]));
        bytes.extend(sql_error("22012", b'I'));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let progress = connection
            .streaming_batch((1..=3).map(|value| statement.bind_one(Parameter::int4(value))))
            .with_options(BatchOptions {
                max_inflight: 2,
                max_diagnostic_bytes: 1,
                ..BATCH_PROFILE
            })
            .visit_ready(OWNED_OUTPUT, OnError::RecoverExplicitly, |event| {
                assert_eq!(event.index, 0);
                assert!(event.outcome.is_ok());
                Ok(std::ops::ControlFlow::Break(()))
            })
            .await
            .unwrap();
        assert_eq!(progress.consumed, 2);
        assert_eq!(progress.admitted, 2);
        assert_eq!(progress.confirmed, 2);
        assert_eq!(progress.events_delivered, 1);
        assert_eq!(progress.rows_delivered, 1);
        assert_eq!(progress.sql_errors, 1);
        assert!(progress.stopped);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ready_callback_errors_do_not_repeat_callbacks_during_selected_cleanup() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let fixture = Fixture::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            execution(socket, &statement)?;
            let mut bytes = result(1, b'I');
            bytes.extend(result(2, b'I'));
            socket.write_all(&bytes)?;
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let examined = Cell::new(0);
            let calls = Cell::new(0);
            let source = (1..10).map(|value| {
                examined.set(examined.get() + 1);
                statement.bind_one(Parameter::int4(value))
            });
            let error = connection
                .streaming_batch(source)
                .with_options(BatchOptions {
                    max_inflight: 2,
                    ..BATCH_PROFILE
                })
                .visit_ready(OWNED_OUTPUT, policy, |_| {
                    calls.set(calls.get() + 1);
                    Err(io::Error::other("callback failure").into())
                })
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::Io(_)));
            assert_eq!(error.origin, compio_postgres::BatchErrorOrigin::Callback);
            assert!(error.cleanup_error.is_none());
            assert_eq!((examined.get(), calls.get()), (2, 1));
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle)
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready().await.unwrap();
                }
                OnError::Discard => assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly),
            }
            assert_eq!((examined.get(), calls.get()), (2, 1));
            connection.close_local().await.unwrap();
        });
        fixture.finish();
    }
}

#[test]
fn ready_batch_reports_transaction_state_at_failure_before_cleanup() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let begin = prepare(socket, &[], &[])?;
        let commit = prepare(socket, &[], &[])?;
        execution(socket, &begin)?;
        execution(socket, &commit)?;
        let mut response = Vec::new();
        for (tag, status) in [(b"BEGIN\0".as_slice(), b'T'), (b"COMMIT\0", b'I')] {
            response.extend(frame(b'2', &[]));
            response.extend(frame(b'C', tag));
            response.extend(ready(status));
        }
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let begin = connection
            .prepare("BEGIN", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let commit = connection
            .prepare("COMMIT", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let failure = connection
            .streaming_batch([begin.bind(&[]), commit.bind(&[])])
            .visit_ready(OWNED_OUTPUT, OnError::DrainToReady, |_| {
                Err(Error::InvalidInput("callback failure"))
            })
            .await
            .unwrap_err();
        assert_eq!(failure.progress.confirmed, 1);
        assert_eq!(
            failure.progress.transaction_status,
            TransactionStatus::InTransaction
        );
        assert!(failure.progress.needs_transaction_decision);
        assert_eq!(failure.reuse_state, ReuseState::ProtocolIdle);
        assert!(failure.cleanup_error.is_none());
        assert_eq!(connection.transaction_status(), TransactionStatus::Idle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn owned_drain_keeps_primary_budget_failure_and_cleanup_eof_separate() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        socket.write_all(&result(1, b'I'))
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let error = connection
            .streaming_batch([
                statement.bind_one(Parameter::int4(1)),
                statement.bind_one(Parameter::int4(2)),
            ])
            .collect_ready(
                OwnedOutput {
                    max_bytes: 0,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::DrainToReady,
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert!(matches!(error.cleanup_error.as_deref(), Some(Error::Io(_))));
        assert_eq!(error.progress.confirmed, 1);
        assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn fatal_protocol_failure_never_uses_a_local_recovery_policy() {
    for policy in [OnError::DrainToReady, OnError::RecoverExplicitly] {
        let fixture = Fixture::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            socket.write_all(&frame(b'?', &[]))?;
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let error = connection
                .streaming_batch([statement.bind_one(Parameter::int4(1))])
                .collect_ready(OWNED_OUTPUT, policy)
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::Protocol(_)));
            assert!(error.cleanup_error.is_none());
            assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();
        });
        fixture.finish();
    }
}

#[test]
fn transaction_controls_and_copy_batching_share_the_ordinary_scope() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[], &[])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        control(socket, b"SAVEPOINT \"s\"\0", b"SAVEPOINT\0", b'T')?;
        control(
            socket,
            b"ROLLBACK TO SAVEPOINT \"s\"\0",
            b"ROLLBACK\0",
            b'T',
        )?;
        control(socket, b"RELEASE SAVEPOINT \"s\"\0", b"RELEASE\0", b'T')?;
        control(socket, b"COMMIT AND CHAIN\0", b"COMMIT\0", b'T')?;
        control(socket, b"ROLLBACK AND CHAIN\0", b"ROLLBACK\0", b'T')?;
        peer::expect(socket, b'B')?;
        peer::expect(socket, b'E')?;
        peer::expect(socket, b'H')?;
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'G', &[0, 0, 1, 0, 0]));
        socket.write_all(&response)?;
        assert_eq!(peer::expect(socket, b'd')?, b"1\n");
        assert_eq!(peer::expect(socket, b'd')?, b"2\n");
        peer::expect(socket, b'c')?;
        socket.write_all(&frame(b'C', b"COPY 2\0"))?;
        peer::expect(socket, b'S')?;
        socket.write_all(&ready(b'T'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "COPY target FROM STDIN",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        transaction.savepoint("s").await.unwrap();
        transaction.rollback_to_savepoint("s").await.unwrap();
        transaction.release_savepoint("s").await.unwrap();
        assert_eq!(
            transaction
                .commit_and_chain()
                .await
                .unwrap()
                .transaction_end,
            Some(compio_postgres::TransactionEnd::Committed)
        );
        assert_eq!(
            transaction
                .rollback_and_chain()
                .await
                .unwrap()
                .transaction_end,
            Some(compio_postgres::TransactionEnd::RolledBack)
        );
        assert_eq!(
            transaction.expert().transaction_status(),
            TransactionStatus::InTransaction
        );
        assert_eq!(transaction.take_transaction_end(), None);
        let mut copy = transaction
            .copy_in(&statement, &[], ExecutionScheduling::Uninterrupted)
            .await
            .unwrap();
        let sent = copy
            .send_batch(
                &[b"1\n", b"2\n"],
                compio_postgres::CopyBatchLimits {
                    max_chunks: 2,
                    max_packet_bytes: 64,
                },
            )
            .await
            .unwrap();
        assert_eq!((sent.chunks, sent.payload_bytes), (2, 4));
        assert_eq!(copy.finish().await.unwrap().rows, 2);
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn known_and_lazy_batch_limits_report_execution_and_preserve_explicit_prefixes() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        for value in [1, 2, 3, 4, 5] {
            execution(socket, &statement)?;
            socket.write_all(&result(value, b'I'))?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare("SELECT 1", &[], PreparedStatementStorage::Named, BINARY)
            .await
            .unwrap();
        let limit = BatchOptions {
            max_requests: 1,
            ..BATCH_PROFILE
        };
        let mut known = (0..3).map(|_| statement.bind(&[]));
        let error = connection
            .streaming_batch(&mut known)
            .with_options(limit)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap_err();
        assert!(matches!(
            error.source,
            Error::Limit("batch source exceeds max_requests")
        ));
        assert_eq!(
            (
                error.progress.consumed,
                error.progress.admitted,
                known.len()
            ),
            (0, 0, 3)
        );

        let mut lazy = (0..3).filter(|_| true).map(|index| {
            if index == 1 {
                Err(Error::InvalidInput("excess source item"))
            } else {
                Ok(statement.bind(&[]))
            }
        });
        let error = connection
            .streaming_batch(&mut lazy)
            .with_options(limit)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap_err();
        assert!(matches!(
            error.source,
            Error::Limit("batch source exceeds max_requests")
        ));
        assert_eq!(
            (
                error.progress.consumed,
                error.progress.admitted,
                error.progress.confirmed
            ),
            (2, 1, 1)
        );
        assert_eq!(error.completed.len(), 1);
        assert_eq!(lazy.count(), 1);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

        let report = connection
            .streaming_batch(known.by_ref().take(1))
            .with_options(limit)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap();
        assert_eq!(
            (
                report.progress.consumed,
                report.progress.confirmed,
                known.len()
            ),
            (1, 1, 2)
        );
        let mut zero = (0..1).filter(|_| true).map(|_| statement.bind(&[]));
        let error = connection
            .streaming_batch(&mut zero)
            .with_options(BatchOptions {
                max_requests: 0,
                ..limit
            })
            .visit_provisional(AbandonPolicy::DiscardOnAbandon, |_| {
                Ok(BatchControl::Continue)
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error.source,
            Error::Limit("batch source exceeds max_requests")
        ));
        assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
        let mut scalars = Vec::with_capacity(2);
        scalars.push(Ok(41_i32));
        let error = connection
            .streaming_batch((0..2).filter(|_| true).map(|_| statement.bind(&[])))
            .with_options(limit)
            .collect_one_into_ready(&mut scalars, OnError::Discard)
            .await
            .unwrap_err();
        assert_eq!(
            (
                error.progress.consumed,
                error.progress.admitted,
                error.progress.confirmed
            ),
            (2, 1, 1)
        );
        assert!(matches!(scalars.as_slice(), [Ok(41)]));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

        for provisional in [false, true] {
            let observed = Cell::new(0);
            let source = std::iter::from_fn(|| {
                observed.set(observed.get() + 1);
                Some(statement.bind(&[]))
            });
            let batch = connection.streaming_batch(source).with_options(limit);
            let progress = if provisional {
                batch
                    .visit_provisional(AbandonPolicy::RecoverExplicitly, |_| {
                        Ok(BatchControl::StopAdmission)
                    })
                    .await
            } else {
                batch
                    .visit_ready(OWNED_OUTPUT, OnError::DrainToReady, |_| {
                        Ok(std::ops::ControlFlow::Break(()))
                    })
                    .await
            }
            .unwrap();
            assert!(progress.stopped);
            assert_eq!(
                (observed.get(), progress.consumed, progress.confirmed),
                (1, 1, 1)
            );
        }
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ready_batch_keeps_owned_results_and_independent_sql_errors() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        socket.write_all(&result(10, b'I'))?;
        socket.write_all(&result(11, b'I'))?;
        execution(socket, &statement)?;
        socket.write_all(&sql_error("22003", b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let profile = BatchOptions {
            max_requests: 3,
            max_inflight: 2,
            ..BATCH_PROFILE
        };
        let report = connection
            .streaming_batch((10..13).map(|value| statement.bind_one(Parameter::int4(value))))
            .with_options(profile)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap();
        assert_eq!(report.progress.admitted, 3);
        assert_eq!(report.progress.consumed, report.progress.admitted);
        assert_eq!(report.progress.confirmed, 3);
        assert_eq!(report.progress.sql_errors, 1);
        assert_eq!(report.results.len(), 3);
        for (item, expected) in report.results[..2].iter().zip([10, 11]) {
            let result = item.as_ref().unwrap();
            let value = result
                .rows
                .rows()
                .next()
                .unwrap()
                .unwrap()
                .decoder()
                .decode_next::<i32>()
                .unwrap();
            assert_eq!(value, expected);
        }
        assert_eq!(report.results[2].as_ref().unwrap_err().code(), "22003");
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn batch_validates_lazily_and_returns_only_the_confirmed_retained_prefix() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(7, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let source = [
            Ok(statement.bind_one(Parameter::int4(7))),
            Err(Error::InvalidInput("late source failure")),
        ];
        let profile = BatchOptions {
            max_inflight: 1,
            ..BATCH_PROFILE
        };
        let error = connection
            .streaming_batch(source)
            .with_options(profile)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap_err();
        assert_eq!(error.progress.admitted, 1);
        assert_eq!(error.progress.consumed, 2);
        assert_eq!(error.progress.confirmed, 1);
        assert_eq!(error.completed.len(), 1);
        assert!(matches!(
            error.source,
            Error::InvalidInput("late source failure")
        ));
        assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
        connection.discard();
    });
    fixture.finish();
}

#[test]
fn a_direct_profile_requires_a_batch_override_before_consuming_input() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        eof(socket)
    });
    run(async {
        let options = ClientOptions::direct(
            fixture.config_with_limits(FIXTURE_WIRE),
            QUERY_PROFILE,
            STATEMENT_LIMITS,
        );
        let mut connection = TcpConnection::connect(options).await.unwrap();
        let source = std::iter::once_with(|| -> compio_postgres::BatchRequest<'_> {
            panic!("an unconfigured batch must not consume input");
        });
        let error = connection
            .streaming_batch(source)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::InvalidInput(_)));
        assert_eq!(error.progress.consumed, 0);
        let report = connection
            .streaming_batch(std::iter::empty::<compio_postgres::BatchRequest<'_>>())
            .with_options(BATCH_PROFILE)
            .collect_ready(OWNED_OUTPUT, OnError::Discard)
            .await
            .unwrap();
        assert!(report.results.is_empty());
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn a_short_batch_fits_its_actual_descriptor_budget() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[])?;
        for _ in 0..6 {
            execution(socket, &statement)?;
            let mut response = frame(b'2', &[]);
            response.extend(frame(b'C', b"UPDATE 0\0"));
            response.extend(ready(b'I'));
            socket.write_all(&response)?;
        }
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "UPDATE fixture SET n = 1 WHERE false",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        for allocation in [AllocationPolicy::Grow, AllocationPolicy::ReserveLimit] {
            let report = connection
                .streaming_batch((0..3).map(|_| statement.bind(&[])))
                .with_options(BatchOptions {
                    max_requests: 4,
                    ..BATCH_PROFILE
                })
                .collect_ready(
                    OwnedOutput {
                        max_bytes: 3 * std::mem::size_of::<compio_postgres::ReadyResult>(),
                        allocation,
                    },
                    OnError::Discard,
                )
                .await
                .unwrap();
            assert_eq!(report.progress.confirmed, 3);
            assert_eq!(report.results.len(), 3);
            assert!(report.results.iter().all(Result::is_ok));
        }
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn retained_batch_budget_reports_a_confirmed_but_unretained_result() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(7, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let error = connection
            .streaming_batch([statement.bind_one(Parameter::int4(7))])
            .collect_ready(
                OwnedOutput {
                    max_bytes: 0,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::Discard,
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert_eq!(error.progress.confirmed, 1);
        assert_eq!(error.completed.len(), 0);
        assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
        connection.discard();
    });
    fixture.finish();
}

#[test]
fn retained_batch_budget_preserves_the_confirmed_sql_error_count() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&sql_error("22003", b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let error = connection
            .streaming_batch([statement.bind_one(Parameter::int4(7))])
            .collect_ready(
                OwnedOutput {
                    max_bytes: 0,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::Discard,
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Limit(_)));
        assert_eq!(error.progress.confirmed, 1);
        assert_eq!(error.progress.sql_errors, 1);
        assert_eq!(error.progress.rows_delivered, 0);
        assert_eq!(error.progress.events_delivered, 0);
        assert_eq!(error.completed.len(), 0);
        assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
        connection.discard();
    });
    fixture.finish();
}

#[test]
fn diagnostic_budget_is_per_member_while_sql_counts_follow_ready() {
    let single = std::mem::size_of::<compio_postgres::DatabaseError>()
        + b"SERROR\0C22003\0Mfixture database failure\0\0".len();
    for (budget, large_second, delivered, confirmed) in [
        (0, false, 0, 1),
        (single, false, 2, 2),
        (single, true, 1, 2),
    ] {
        let fixture = Fixture::start(move |socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[23], &[23])?;
            execution(socket, &statement)?;
            execution(socket, &statement)?;
            socket.write_all(&sql_error("22003", b'I'))?;
            if large_second {
                let mut response = frame(
                    b'E',
                    b"SERROR\0C22003\0Mfixture database failure with a larger diagnostic\0\0",
                );
                response.extend(ready(b'I'));
                socket.write_all(&response)?;
            } else {
                socket.write_all(&sql_error("22003", b'I'))?;
            }
            eof(socket)
        });
        run(async {
            let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let profile = BatchOptions {
                max_requests: 2,
                max_inflight: 2,
                max_diagnostic_bytes: budget,
                ..BATCH_PROFILE
            };
            let outcome = connection
                .streaming_batch((0..2).map(|value| statement.bind_one(Parameter::int4(value))))
                .with_options(profile)
                .collect_ready(OWNED_OUTPUT, OnError::Discard)
                .await;
            if delivered == 2 {
                let report = outcome.unwrap();
                assert_eq!(report.results.len(), 2);
                assert!(report.results.iter().all(Result::is_err));
                assert_eq!(report.progress.confirmed, confirmed);
                assert_eq!(report.progress.sql_errors, confirmed);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                connection.close_local().await.unwrap();
            } else {
                let error = outcome.unwrap_err();
                assert!(matches!(error.source, Error::Limit(_)));
                assert_eq!(error.completed.len(), delivered);
                assert_eq!(error.progress.confirmed, confirmed);
                assert_eq!(error.progress.sql_errors, confirmed);
                assert_eq!(error.progress.events_delivered, delivered);
                assert_eq!(error.progress.rows_delivered, 0);
                assert_eq!(error.reuse_state, ReuseState::DiscardOnly);
                connection.discard();
            }
        });
        fixture.finish();
    }
}

#[test]
fn batch_input_errors_keep_the_same_stop_status_for_owned_and_borrowed_results() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let source = || {
            std::iter::once(Err::<compio_postgres::BatchRequest<'_>, _>(
                Error::InvalidInput("批次输入无效"),
            ))
        };
        let owned = connection
            .streaming_batch(source())
            .collect_ready(OWNED_OUTPUT, OnError::RecoverExplicitly)
            .await
            .unwrap_err();
        let borrowed = connection
            .streaming_batch(source())
            .visit_provisional(AbandonPolicy::RecoverExplicitly, |_| {
                panic!("输入校验失败时不会产生结果")
            })
            .await
            .unwrap_err();
        assert!(matches!(owned.source, Error::InvalidInput("批次输入无效")));
        assert!(matches!(
            borrowed.source,
            Error::InvalidInput("批次输入无效")
        ));
        assert!(!owned.progress.stopped);
        assert!(!borrowed.progress.stopped);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn invalid_batch_overrides_are_rejected_before_io_and_source_on_both_scopes() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    macro_rules! reject_overrides {
        ($scope:ident) => {{
            let profile = BatchOptions {
                max_queued_request_bytes: 0,
                ..BATCH_PROFILE
            };
            let polls = Cell::new(0);
            let source = std::iter::from_fn(|| {
                polls.set(polls.get() + 1);
                None::<compio_postgres::BatchRequest<'_>>
            });
            let error = $scope
                .streaming_batch(source)
                .with_options(profile)
                .collect_ready(OWNED_OUTPUT, OnError::Discard)
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::InvalidInput(_)));
            assert_eq!(polls.get(), 0);
            assert_eq!(error.progress.consumed, 0);
            assert_eq!(error.progress.admitted, 0);
            assert_eq!(error.reuse_state, $scope.reuse_state());
            let callbacks = Cell::new(0);
            let source = std::iter::from_fn(|| {
                polls.set(polls.get() + 1);
                None::<compio_postgres::BatchRequest<'_>>
            });
            let error = $scope
                .streaming_batch(source)
                .with_options(profile)
                .visit_provisional(AbandonPolicy::RecoverExplicitly, |_| {
                    callbacks.set(callbacks.get() + 1);
                    Ok(BatchControl::Continue)
                })
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::InvalidInput(_)));
            assert_eq!(polls.get(), 0);
            assert_eq!(callbacks.get(), 0);
            assert_eq!(error.progress.consumed, 0);
            assert_eq!(error.progress.admitted, 0);
        }};
    }
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        reject_overrides!(connection);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        let mut transaction = connection.begin_transaction().await.unwrap();
        reject_overrides!(transaction);
        assert_eq!(
            transaction.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_abort_and_dropped_rows_recover_through_the_guard() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &statement)?;
        socket.write_all(&result(7, b'T'))?;
        execution(socket, &statement)?;
        socket.write_all(&result(8, b'T'))?;
        execution(socket, &statement)?;
        socket.write_all(&result(9, b'T'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let progress = transaction
            .streaming_batch([statement.bind_one(Parameter::int4(7))])
            .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
                Ok(if matches!(event, BatchEvent::Row { .. }) {
                    BatchControl::Abort
                } else {
                    BatchControl::Continue
                })
            })
            .await
            .unwrap();
        assert!(progress.aborted);
        assert!(progress.needs_transaction_decision);
        transaction
            .recover_to_ready_with_limits(16, 1024)
            .await
            .unwrap();
        let parameters = [Parameter::int4(8)];
        let mut rows = transaction
            .query(&statement, &parameters)
            .stream_provisional(AbandonPolicy::RecoverExplicitly)
            .await
            .unwrap();
        {
            let row = rows.next_row().await.unwrap().unwrap();
            assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 8);
        }
        drop(rows);
        transaction.recover_to_ready().await.unwrap();
        assert_eq!(
            transaction
                .query(&statement, &[Parameter::int4(9)])
                .one::<i32>(OnError::DrainToReady)
                .await
                .unwrap(),
            9
        );
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn prepared_copy_confirms_input_and_output_boundaries() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let input = prepare(socket, &[], &[])?;
        let bind = peer::expect(socket, b'B')?;
        if bind.first() != Some(&0)
            || peer::name(&bind[1..])? != input
            || peer::expect(socket, b'E')? != [0; 5]
            || !peer::expect(socket, b'H')?.is_empty()
        {
            return Err(io::Error::other("unexpected prepared COPY IN packet"));
        }
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'G', &[0, 0, 1, 0, 0]));
        socket.write_all(&response)?;
        assert_eq!(peer::expect(socket, b'd')?, b"1\n");
        peer::expect(socket, b'c')?;
        socket.write_all(&frame(b'C', b"COPY 1\0"))?;
        peer::expect(socket, b'S')?;
        socket.write_all(&ready(b'I'))?;
        let output = prepare(socket, &[], &[])?;
        execution(socket, &output)?;
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'H', &[0, 0, 1, 0, 0]));
        response.extend(frame(b'd', b"1\n"));
        response.extend(frame(b'c', &[]));
        response.extend(frame(b'C', b"COPY 1\0"));
        response.extend(ready(b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let input = connection
            .prepare(
                "COPY values FROM STDIN",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut copy = connection
            .copy_in(&input, &[], ExecutionScheduling::Uninterrupted)
            .await
            .unwrap();
        copy.send(b"1\n").await.unwrap();
        assert_eq!(copy.finish().await.unwrap().rows, 1);
        let output = connection
            .prepare(
                "COPY values TO STDOUT",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let (bytes, completion) = connection
            .copy_out(&output, &[], ExecutionScheduling::Uninterrupted)
            .await
            .unwrap()
            .collect_ready(
                OwnedOutput {
                    max_bytes: 65536,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::RecoverExplicitly,
            )
            .await
            .unwrap();
        assert_eq!(bytes, b"1\n");
        assert_eq!(completion.rows, 1);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_explicitly_drains_abandoned_copy_output() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[], &[])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        peer::expect(socket, b'B')?;
        peer::expect(socket, b'E')?;
        peer::expect(socket, b'S')?;
        let mut response = frame(b'2', &[]);
        response.extend(frame(b'H', &[0, 0, 1, 0, 0]));
        response.extend(frame(b'd', b"1\n"));
        response.extend(frame(b'd', b"2\n"));
        response.extend(frame(b'c', &[]));
        response.extend(frame(b'C', b"COPY 2\0"));
        response.extend(ready(b'T'));
        socket.write_all(&response)?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "COPY values TO STDOUT",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let mut copy = transaction
            .copy_out(&statement, &[], ExecutionScheduling::Uninterrupted)
            .await
            .unwrap();
        assert_eq!(copy.next_chunk().await.unwrap().unwrap().bytes(), b"1\n");
        drop(copy);
        assert_eq!(
            transaction.finish_abandoned_copy_out().await.unwrap().rows,
            2
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ordinary_prepare_reclaims_retired_statement_slots_on_demand() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        for _ in 0..4 {
            let statement = prepare(socket, &[23], &[23])?;
            peer::close_statement(socket, &statement)?;
        }
        eof(socket)
    });
    run(async {
        let mut connection =
            TcpConnection::connect(fixture.options_with_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            }))
            .await
            .unwrap();
        for _ in 0..4 {
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            connection.close_statement(&statement).await.unwrap();
            assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 0);
            assert!(matches!(
                connection
                    .prepare(
                        "SELECT $1::int4",
                        &[Oid::INT4],
                        PreparedStatementStorage::Named,
                        BINARY
                    )
                    .await,
                Err(Error::Limit(_))
            ));
            drop(statement);
        }
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 1);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 0);
        let send_policy = connection.expert().send_policy();
        assert!(connection.expert().trim_send_buffer().unwrap() > 0);
        assert_eq!(connection.expert().trim_send_buffer().unwrap(), 0);
        assert_eq!(connection.expert().send_policy(), send_policy);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ordinary_reclamation_preserves_live_handles_and_owned_result_layouts() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(73, b'I'))?;
        peer::close_statement(socket, &statement)?;
        let statement = prepare(socket, &[23], &[23])?;
        // 本地失效操作不应发送执行请求或远端 Close。
        peer::close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let mut connection =
            TcpConnection::connect(fixture.options_with_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            }))
            .await
            .unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let retained_handle = statement.clone();
        let output = connection
            .query(&statement, &[Parameter::int4(73)])
            .collect_ready(AllocationPolicy::Grow, OnError::RecoverExplicitly)
            .await
            .unwrap();
        connection.close_statement(&statement).await.unwrap();
        drop(statement);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 0);
        drop(retained_handle);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 0);
        assert_eq!(output.rows.len(), 1);
        drop(output);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 1);
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        connection.expert().invalidate_statements().unwrap();
        assert!(matches!(
            connection
                .query(&statement, &[Parameter::int4(1)])
                .one::<i32>(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_statement(&statement).await.unwrap();
        drop(statement);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 1);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_reclaims_and_invalidates_without_ending_its_lease() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        for _ in 0..3 {
            let statement = peer::prepare_with_status(socket, &[23], &[23], b'T')?;
            execution(socket, &statement)?;
            socket.write_all(&result(73, b'T'))?;
            peer::close_statement_with_status(socket, &statement, b'T')?;
        }
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection =
            TcpConnection::connect(fixture.options_with_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            }))
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        for _ in 0..3 {
            let statement = transaction
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            assert_eq!(
                transaction
                    .query(&statement, &[Parameter::int4(73)])
                    .one::<i32>(OnError::RecoverExplicitly)
                    .await
                    .unwrap(),
                73
            );
            transaction.expert().invalidate_statements().unwrap();
            assert!(matches!(
                transaction
                    .query(&statement, &[Parameter::int4(1)])
                    .one::<i32>(OnError::RecoverExplicitly)
                    .await,
                Err(Error::InvalidInput(_))
            ));
            transaction.close_statement(&statement).await.unwrap();
            assert_eq!(transaction.expert().reclaim_closed_statements().unwrap(), 0);
            drop(statement);
            assert_eq!(transaction.expert().reclaim_closed_statements().unwrap(), 1);
            assert_eq!(
                transaction.transaction_status(),
                TransactionStatus::InTransaction
            );
            assert_eq!(
                transaction.reuse_state(),
                ReuseState::NeedsTransactionDecision
            );
        }
        transaction.rollback().await.unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn ordinary_recovers_forgotten_row_without_releasing_statement() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        for _ in 0..2 {
            execution(socket, &statement)?;
            socket.write_all(&result(73, b'I'))?;
        }
        peer::close_statement(socket, &statement)?;
        eof(socket)
    });
    run(async {
        let mut connection =
            TcpConnection::connect(fixture.options_with_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            }))
            .await
            .unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let parameters = [Parameter::int4(73)];
        let mut rows = connection
            .query(&statement, &parameters)
            .stream_provisional(AbandonPolicy::RecoverExplicitly)
            .await
            .unwrap();
        let _forgotten = std::mem::ManuallyDrop::new(rows.next_row().await.unwrap().unwrap());
        drop(rows);
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        assert!(matches!(
            connection.expert().reclaim_closed_statements(),
            Err(Error::Busy)
        ));
        assert!(matches!(
            connection.expert().invalidate_statements(),
            Err(Error::Busy)
        ));
        assert!(matches!(
            connection.expert().trim_send_buffer(),
            Err(Error::Busy)
        ));
        connection.recover_to_ready().await.unwrap();
        assert_eq!(
            connection
                .query(&statement, &parameters)
                .one::<i32>(OnError::RecoverExplicitly)
                .await
                .unwrap(),
            73
        );
        connection.close_statement(&statement).await.unwrap();
        drop(statement);
        assert_eq!(connection.expert().reclaim_closed_statements().unwrap(), 1);
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_recovers_forgotten_row_without_releasing_statement() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        let statement = peer::prepare_with_status(socket, &[23], &[23], b'T')?;
        for _ in 0..2 {
            execution(socket, &statement)?;
            socket.write_all(&result(73, b'T'))?;
        }
        peer::close_statement_with_status(socket, &statement, b'T')?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection =
            TcpConnection::connect(fixture.options_with_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 4096,
            }))
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let statement = transaction
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let parameters = [Parameter::int4(73)];
        let mut rows = transaction
            .query(&statement, &parameters)
            .stream_provisional(AbandonPolicy::RecoverExplicitly)
            .await
            .unwrap();
        let _forgotten = std::mem::ManuallyDrop::new(rows.next_row().await.unwrap().unwrap());
        drop(rows);
        assert!(matches!(
            transaction.expert().reclaim_closed_statements(),
            Err(Error::Busy)
        ));
        assert!(matches!(
            transaction.expert().invalidate_statements(),
            Err(Error::Busy)
        ));
        transaction.recover_to_ready().await.unwrap();
        assert_eq!(
            transaction
                .query(&statement, &parameters)
                .one::<i32>(OnError::RecoverExplicitly)
                .await
                .unwrap(),
            73
        );
        transaction.close_statement(&statement).await.unwrap();
        drop(statement);
        assert_eq!(transaction.expert().reclaim_closed_statements().unwrap(), 1);
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

fn live_profile() -> ExecutionOptions {
    let limits = QueryLimits {
        max_rows: 256,
        max_result_bytes: 4096,
        max_metadata_bytes: 65536,
    };
    let scheduling = ExecutionScheduling::Cooperative {
        max_work_per_turn: std::num::NonZeroUsize::MIN,
    };
    ExecutionOptions {
        query: QueryOptions { limits, scheduling },
        batch: Some(BatchOptions {
            member_limits: limits,
            scheduling,
            max_requests: 4,
            max_inflight: 2,
            ..BATCH_PROFILE
        }),
    }
}
async fn live_exercise<T: compio_postgres::WireTransport>(
    mut connection: compio_postgres::Client<T>,
    send_policy: compio_postgres::SendPolicy,
) {
    assert_eq!(connection.expert().send_policy(), send_policy);
    assert!(connection.server_info().version.starts_with("19"));
    assert_eq!(
        connection.execution_options().batch.unwrap().max_inflight,
        2
    );
    let name = connection
        .prepare(
            "SELECT current_setting('application_name') = 'ordinary-api-live'",
            &[],
            PreparedStatementStorage::Named,
            BINARY,
        )
        .await
        .unwrap();
    assert!(
        connection
            .query(&name, &[])
            .one::<bool>(OnError::DrainToReady)
            .await
            .unwrap()
    );
    let statement = connection
        .prepare(
            "SELECT $1::int4",
            &[Oid::INT4],
            PreparedStatementStorage::Named,
            BINARY,
        )
        .await
        .unwrap();
    assert_eq!(
        connection
            .query(&statement, &[Parameter::int4(73)])
            .one::<i32>(OnError::DrainToReady)
            .await
            .unwrap(),
        73
    );
    let report = connection
        .streaming_batch((0..4).map(|value| statement.bind_one(Parameter::int4(value))))
        .collect_ready(OWNED_OUTPUT, OnError::Discard)
        .await
        .unwrap();
    assert_eq!(report.results.len(), 4);
    assert_eq!(report.progress.confirmed, 4);
    for (result, expected) in report.results.into_iter().zip(0..4) {
        let batch = result.unwrap().rows;
        assert_eq!(batch.len(), 1);
        let row = batch.rows().next().unwrap().unwrap();
        let mut fields = row.decoder();
        assert_eq!(fields.decode_next::<i32>().unwrap(), expected);
        fields.finish().unwrap();
    }
    let mut rows = 0;
    let progress = connection
        .streaming_batch((0..4).map(|value| statement.bind_one(Parameter::int4(value))))
        .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
            if let BatchEvent::Row { index, row } = event {
                assert_eq!(
                    row.decoder().decode_next::<i32>()?,
                    i32::try_from(index).unwrap()
                );
                rows += 1;
            }
            Ok(BatchControl::Continue)
        })
        .await
        .unwrap();
    assert_eq!(rows, 4);
    assert_eq!(progress.confirmed, 4);

    let create = connection
        .prepare(
            "CREATE TEMP TABLE cpg_api_values(v int4)",
            &[],
            PreparedStatementStorage::Named,
            BINARY,
        )
        .await
        .unwrap();
    connection
        .query(&create, &[])
        .collect_ready(AllocationPolicy::Grow, OnError::Discard)
        .await
        .unwrap();
    let input = connection
        .prepare(
            "COPY cpg_api_values FROM STDIN (FORMAT text)",
            &[],
            PreparedStatementStorage::Named,
            BINARY,
        )
        .await
        .unwrap();
    let output = connection
        .prepare(
            "COPY (SELECT v FROM cpg_api_values ORDER BY v) TO STDOUT (FORMAT text)",
            &[],
            PreparedStatementStorage::Named,
            BINARY,
        )
        .await
        .unwrap();
    let mut transaction = connection.begin_transaction().await.unwrap();
    assert_eq!(
        transaction
            .query(&statement, &[Parameter::int4(74)])
            .one::<i32>(OnError::DrainToReady)
            .await
            .unwrap(),
        74
    );
    let mut copy = transaction
        .copy_in(&input, &[], ExecutionScheduling::Uninterrupted)
        .await
        .unwrap();
    copy.send(b"1\n2\n").await.unwrap();
    assert_eq!(copy.finish().await.unwrap().rows, 2);
    let (data, completion) = transaction
        .copy_out(&output, &[], ExecutionScheduling::Uninterrupted)
        .await
        .unwrap()
        .collect_ready(
            OwnedOutput {
                max_bytes: 65536,
                allocation: AllocationPolicy::Grow,
            },
            OnError::RecoverExplicitly,
        )
        .await
        .unwrap();
    assert_eq!(data, b"1\n2\n");
    assert_eq!(completion.rows, 2);
    transaction.commit().await.unwrap();
    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    connection.close_local().await.unwrap();
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_one_rejects_wrong_layout_without_executing_a_write() {
    run(async {
        let config = live::tcp_config(FIXTURE_WIRE, TCP_OPTIONS);
        let mut connection =
            TcpConnection::connect(ClientOptions::new(config, live_profile(), STATEMENT_LIMITS))
                .await
                .unwrap();
        let create = connection
            .prepare(
                "CREATE TEMP TABLE cpg_one_preflight (value int4)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        connection
            .query(&create, &[])
            .collect_ready(AllocationPolicy::Grow, OnError::Discard)
            .await
            .unwrap();
        let write = connection
            .prepare(
                "INSERT INTO cpg_one_preflight VALUES (11) RETURNING value, value + 1",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let count = connection
            .prepare(
                "SELECT count(*)::int4 FROM cpg_one_preflight",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert!(matches!(
            connection
                .query(&write, &[])
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "one requires exactly one result column"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(
            connection
                .query(&count, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            0
        );

        let mut transaction = connection.begin_transaction().await.unwrap();
        assert!(matches!(
            transaction
                .query(&write, &[])
                .one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "one requires exactly one result column"
            ))
        ));
        assert_eq!(
            transaction
                .query(&count, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            0
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_strict_query_terminals() {
    run(async {
        let config = live::tcp_config(FIXTURE_WIRE, TCP_OPTIONS);
        let mut connection =
            TcpConnection::connect(ClientOptions::new(config, live_profile(), STATEMENT_LIMITS))
                .await
                .unwrap();
        let create = connection
            .prepare(
                "CREATE TEMP TABLE cpg_strict_terminals (value int4)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let completion = connection
            .query(&create, &[])
            .command_ready(OnError::Discard)
            .await
            .unwrap();
        assert!(completion.succeeded);
        assert_eq!(completion.rows_returned, 0);
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);

        let returning = connection
            .prepare(
                "INSERT INTO cpg_strict_terminals VALUES (11) RETURNING value",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let insert = connection
            .prepare(
                "INSERT INTO cpg_strict_terminals VALUES (22)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert!(matches!(
            connection
                .query(&returning, &[])
                .command_ready(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "command_ready requires a zero-column result layout"
            ))
        ));
        assert!(matches!(
            connection
                .query(&insert, &[])
                .zero_or_one::<i32>(OnError::Discard)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one requires exactly one result column"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        let count = connection
            .prepare(
                "SELECT count(*)::int4 FROM cpg_strict_terminals",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert_eq!(
            connection
                .query(&count, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            0
        );
        let completion = connection
            .query(&insert, &[])
            .command_ready(OnError::Discard)
            .await
            .unwrap();
        assert_eq!(
            completion.command,
            Some(compio_postgres::CommandKind::Insert)
        );
        assert_eq!(completion.rows_affected, Some(1));
        assert_eq!(completion.transaction_status, TransactionStatus::Idle);

        let optional = connection
            .prepare(
                "SELECT CASE WHEN $1 = 0 THEN NULL ELSE $1 END WHERE $1 >= 0",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        for (parameter, expected) in [(-1, None), (0, Some(None)), (73, Some(Some(73)))] {
            assert_eq!(
                connection
                    .query(&optional, &[Parameter::int4(parameter)])
                    .zero_or_one::<Option<i32>>(OnError::Discard)
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }

        let extra = connection
            .prepare(
                "SELECT generate_series(1, 2)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert!(matches!(
            connection
                .query(&extra, &[])
                .zero_or_one::<i32>(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput(
                "zero_or_one received more than one result row"
            ))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        connection.recover_to_ready().await.unwrap();

        let zero_column_row = connection
            .prepare(
                "SELECT FROM generate_series(1, 1)",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        assert!(zero_column_row.layout().is_empty());
        assert!(matches!(
            connection
                .query(&zero_column_row, &[])
                .command_ready(OnError::RecoverExplicitly)
                .await,
            Err(Error::InvalidInput("command_ready received a result row"))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
        connection.recover_to_ready().await.unwrap();
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

        let mut transaction = connection.begin_transaction().await.unwrap();
        let unnamed = transaction
            .prepare(
                "SELECT 74::int4",
                &[],
                PreparedStatementStorage::ReplaceableUnnamed,
                BINARY,
            )
            .await
            .unwrap();
        assert_eq!(
            transaction
                .query(&unnamed, &[])
                .zero_or_one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            Some(74),
        );
        let completion = transaction
            .query(&insert, &[])
            .command_ready(OnError::Discard)
            .await
            .unwrap();
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        assert_eq!(completion.rows_affected, Some(1));
        transaction.rollback().await.unwrap();

        assert_eq!(
            connection
                .query(&count, &[])
                .one::<i32>(OnError::Discard)
                .await
                .unwrap(),
            1
        );
        connection.close_local().await.unwrap();
    });
}

fn live_backend_options<C>(config: C) -> ClientOptions<C> {
    ClientOptions::new(config, live_profile(), STATEMENT_LIMITS)
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_native_prepared_query_batch_and_copy_semantics() {
    run(async {
        let config =
            live::tcp_config(FIXTURE_WIRE, TCP_OPTIONS).application_name("ordinary-api-live");
        let connection = TcpConnection::connect(live_backend_options(config))
            .await
            .unwrap();
        live_exercise(connection, SendPolicy::BeforeBufferedRead).await;
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_readiness_prepared_query_batch_and_copy_semantics() {
    run(async {
        let config = live::tcp_config(FIXTURE_WIRE, TCP_OPTIONS)
            .application_name("ordinary-api-live")
            .send_policy(SendPolicy::CoalesceBuffered);
        let connection = compio_postgres::expert::linux::TcpReadinessConnection::connect(
            live_backend_options(config),
        )
        .await
        .unwrap();
        live_exercise(connection, SendPolicy::CoalesceBuffered).await;
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 TLS 和 SCRAM-PLUS 的 PostgreSQL 19，以及 CPG_TLS_* 证书配置"]
fn live_tls_prepared_query_batch_and_copy_semantics() {
    use compio_postgres::{TlsConnection, TlsNegotiation, TlsVersions};
    run(async {
        let config = live::tls_config(
            FIXTURE_WIRE,
            TCP_OPTIONS,
            tls_options::fixture_tls_options(TlsNegotiation::SslRequest, TlsVersions::Tls13),
        )
        .application_name("ordinary-api-live");
        let connection = TlsConnection::connect(live_backend_options(config))
            .await
            .unwrap();
        live_exercise(connection, SendPolicy::BeforeBufferedRead).await;
    });
}

#[cfg(unix)]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_prepared_query_batch_and_copy_semantics() {
    run(async {
        let config = live::unix_config(FIXTURE_WIRE, SendPolicy::BeforeBufferedRead)
            .application_name("ordinary-api-live");
        let connection = compio_postgres::UnixConnection::connect(live_backend_options(config))
            .await
            .unwrap();
        live_exercise(connection, SendPolicy::BeforeBufferedRead).await;
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_readiness_prepared_query_batch_and_copy_semantics() {
    run(async {
        let config = live::unix_config(FIXTURE_WIRE, SendPolicy::CoalesceBuffered)
            .application_name("ordinary-api-live");
        let connection = compio_postgres::expert::linux::UnixReadinessConnection::connect(
            live_backend_options(config),
        )
        .await
        .unwrap();
        live_exercise(connection, SendPolicy::CoalesceBuffered).await;
    });
}

#[test]
fn ready_visitor_diagnostic_overflow_reports_resource_without_callback() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&sql_error("22003", b'I'))?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT 1::int4 / 0",
                &[],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let failure = connection
            .streaming_batch([statement.bind(&[])])
            .with_options(BatchOptions {
                max_diagnostic_bytes: 1,
                ..BATCH_PROFILE
            })
            .visit_ready(OWNED_OUTPUT, OnError::RecoverExplicitly, |_| {
                panic!("diagnostic exceeds delivery quota")
            })
            .await
            .unwrap_err();
        assert_eq!(failure.origin, compio_postgres::BatchErrorOrigin::Resource);
        assert_eq!(failure.progress.confirmed, 1);
        assert_eq!(failure.progress.events_delivered, 0);
        connection.recover_to_ready().await.unwrap();
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_local_tx_controls_preserve_ready_and_failed_guard_authority() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &statement)?;
        socket.write_all(&sql_error("22012", b'E'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        {
            let mut transaction = connection.begin_transaction().await.unwrap();
            assert_eq!(
                transaction.expert().send_policy(),
                SendPolicy::BeforeBufferedRead
            );
            transaction
                .expert()
                .set_send_policy(SendPolicy::CoalesceBuffered)
                .unwrap();
            assert_eq!(
                transaction.expert().send_policy(),
                SendPolicy::CoalesceBuffered
            );
            assert!(transaction.expert().trim_send_buffer().unwrap() > 0);
            assert_eq!(transaction.expert().trim_send_buffer().unwrap(), 0);
            transaction
                .expert()
                .set_send_policy(SendPolicy::BeforeBufferedRead)
                .unwrap();
            #[cfg(feature = "window-cache")]
            {
                let policy = compio_postgres::expert::WindowSendCache::RetainUntilTrim {
                    max_retained_bytes: 4096,
                };
                transaction.expert().set_window_send_cache(policy).unwrap();
                assert_eq!(transaction.expert().window_send_cache(), policy);
                transaction
                    .expert()
                    .set_window_send_cache(
                        compio_postgres::expert::WindowSendCache::ReleaseAfterWindow,
                    )
                    .unwrap();
                assert_eq!(
                    transaction.expert().window_send_cache(),
                    compio_postgres::expert::WindowSendCache::ReleaseAfterWindow
                );
            }
            assert_eq!(
                transaction.transaction_status(),
                TransactionStatus::InTransaction
            );
            assert_eq!(
                transaction.reuse_state(),
                ReuseState::NeedsTransactionDecision
            );
            assert_eq!(transaction.take_transaction_end(), None);
            assert!(matches!(
                transaction
                    .query(&statement, &[Parameter::int4(0)])
                    .one::<i32>(OnError::RecoverExplicitly)
                    .await,
                Err(Error::Database(_))
            ));
            assert_eq!(
                transaction.transaction_status(),
                TransactionStatus::FailedTransaction
            );
            transaction
                .expert()
                .set_send_policy(SendPolicy::CoalesceBuffered)
                .unwrap();
            assert_eq!(
                transaction.expert().send_policy(),
                SendPolicy::CoalesceBuffered
            );
            assert!(transaction.expert().trim_send_buffer().unwrap() > 0);
            assert_eq!(transaction.expert().trim_send_buffer().unwrap(), 0);
            #[cfg(feature = "window-cache")]
            {
                transaction
                    .expert()
                    .set_window_send_cache(
                        compio_postgres::expert::WindowSendCache::ReleaseAfterWindow,
                    )
                    .unwrap();
                assert_eq!(
                    transaction.expert().window_send_cache(),
                    compio_postgres::expert::WindowSendCache::ReleaseAfterWindow
                );
            }
            assert_eq!(
                transaction.transaction_status(),
                TransactionStatus::FailedTransaction
            );
            assert_eq!(transaction.take_transaction_end(), None);
            assert!(matches!(
                transaction
                    .query(&statement, &[Parameter::int4(7)])
                    .one::<i32>(OnError::RecoverExplicitly)
                    .await,
                Err(Error::Unsupported(_))
            ));
        }
        assert_eq!(
            connection.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        assert!(matches!(
            connection.expert().trim_send_buffer(),
            Err(Error::Busy)
        ));
        assert_eq!(
            connection.expert().send_policy(),
            SendPolicy::CoalesceBuffered
        );
        assert_eq!(
            connection
                .recover_and_rollback()
                .await
                .unwrap()
                .transaction_end,
            Some(compio_postgres::TransactionEnd::RolledBack)
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(
            connection.expert().send_policy(),
            SendPolicy::CoalesceBuffered
        );
        #[cfg(feature = "window-cache")]
        assert_eq!(
            connection.expert().window_send_cache(),
            compio_postgres::expert::WindowSendCache::ReleaseAfterWindow
        );
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
fn transaction_local_tx_controls_reject_forgotten_protocol_work_without_driving_it() {
    let fixture = Fixture::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        control(socket, b"BEGIN\0", b"BEGIN\0", b'T')?;
        execution(socket, &statement)?;
        socket.write_all(&result(73, b'T'))?;
        control(socket, b"ROLLBACK\0", b"ROLLBACK\0", b'I')?;
        eof(socket)
    });
    run(async {
        let mut connection = TcpConnection::connect(fixture.options()).await.unwrap();
        let statement = connection
            .prepare(
                "SELECT $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        let parameters = [Parameter::int4(73)];
        let mut rows = transaction
            .query(&statement, &parameters)
            .stream_provisional(AbandonPolicy::RecoverExplicitly)
            .await
            .unwrap();
        let row = rows.next_row().await.unwrap().unwrap();
        assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 73);

        std::mem::forget(rows);
        assert!(matches!(
            transaction
                .expert()
                .set_send_policy(SendPolicy::CoalesceBuffered),
            Err(Error::Busy)
        ));
        assert!(matches!(
            transaction.expert().trim_send_buffer(),
            Err(Error::Busy)
        ));
        assert_eq!(
            transaction.expert().send_policy(),
            SendPolicy::BeforeBufferedRead
        );
        #[cfg(feature = "window-cache")]
        {
            let before = transaction.expert().window_send_cache();
            assert!(matches!(
                transaction.expert().set_window_send_cache(
                    compio_postgres::expert::WindowSendCache::ReleaseAfterWindow
                ),
                Err(Error::Busy)
            ));
            assert_eq!(transaction.expert().window_send_cache(), before);
        }
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        assert_eq!(transaction.reuse_state(), ReuseState::NeedsRecovery);
        transaction.recover_to_ready().await.unwrap();
        transaction
            .expert()
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        assert!(transaction.expert().trim_send_buffer().unwrap() > 0);
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        assert_eq!(
            transaction.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        transaction.rollback().await.unwrap();
        assert_eq!(
            connection.expert().send_policy(),
            SendPolicy::CoalesceBuffered
        );
        #[cfg(feature = "window-cache")]
        assert_eq!(
            connection.expert().window_send_cache(),
            compio_postgres::expert::WindowSendCache::ReleaseOnOrdinarySend
        );
        connection.close_local().await.unwrap();
    });
    fixture.finish();
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn live_transaction_local_tx_controls_keep_failed_state_until_explicit_rollback() {
    run(async {
        let config = live::tcp_config(FIXTURE_WIRE, TCP_OPTIONS);
        let mut connection =
            TcpConnection::connect(ClientOptions::new(config, live_profile(), STATEMENT_LIMITS))
                .await
                .unwrap();
        assert!(connection.server_info().version.starts_with("19"));
        let statement = connection
            .prepare(
                "SELECT 10 / $1::int4",
                &[Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        transaction
            .expert()
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        assert!(transaction.expert().trim_send_buffer().unwrap() > 0);
        #[cfg(feature = "window-cache")]
        transaction
            .expert()
            .set_window_send_cache(compio_postgres::expert::WindowSendCache::RetainUntilTrim {
                max_retained_bytes: 4096,
            })
            .unwrap();
        assert_eq!(
            transaction
                .query(&statement, &[Parameter::int4(2)])
                .one::<i32>(OnError::RecoverExplicitly)
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::InTransaction
        );
        let failed = transaction
            .query(&statement, &[Parameter::int4(0)])
            .one::<i32>(OnError::RecoverExplicitly)
            .await;
        match failed {
            Err(Error::Database(error)) => assert_eq!(error.code(), "22012"),
            other => panic!("expected PostgreSQL division error, got {other:?}"),
        }
        transaction
            .expert()
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        assert!(transaction.expert().trim_send_buffer().unwrap() > 0);
        assert_eq!(transaction.expert().trim_send_buffer().unwrap(), 0);
        #[cfg(feature = "window-cache")]
        transaction
            .expert()
            .set_window_send_cache(compio_postgres::expert::WindowSendCache::ReleaseAfterWindow)
            .unwrap();
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert_eq!(
            transaction.reuse_state(),
            ReuseState::NeedsTransactionDecision
        );
        assert_eq!(transaction.take_transaction_end(), None);
        assert_eq!(
            transaction.rollback().await.unwrap().transaction_end,
            Some(compio_postgres::TransactionEnd::RolledBack)
        );
        assert_eq!(connection.transaction_status(), TransactionStatus::Idle);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(
            connection.expert().send_policy(),
            SendPolicy::CoalesceBuffered
        );
        #[cfg(feature = "window-cache")]
        assert_eq!(
            connection.expert().window_send_cache(),
            compio_postgres::expert::WindowSendCache::ReleaseAfterWindow
        );
        connection.close_statement(&statement).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
