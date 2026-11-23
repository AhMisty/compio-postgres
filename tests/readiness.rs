//! Linux 明文就绪式传输与完成式传输遵循相同的帧解析、Sync 和错误处理契约。
#![cfg(target_os = "linux")]

#[path = "support/peer.rs"]
mod peer;
use peer::prepared::{expect, handshake, ready};
use peer::{Peer, frame};

#[path = "support/live.rs"]
mod live;

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use compio_postgres::{
    AuthenticationPolicy, Error, QueryLimits, ResultFormats, StatementLimits, TcpConfig,
    WireLimits,
    expert::{
        PipelineLimits, PipelineRequest, linux::TcpReadinessSession as TcpReadinessConnection,
    },
    types::{Format, Oid, Parameter},
};
use std::{
    future::Future,
    io::{self, Write},
    net::TcpStream,
    time::Duration,
};

const DEADLINE: Duration = Duration::from_secs(8);

fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(DEADLINE, future)
            .await
            .expect("readiness test deadline")
    })
}

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 64,
        max_frame_len: 63,
        max_request_len: 8192,
        max_messages_per_request: 128,
    }
}

fn prepare(socket: &mut TcpStream) -> io::Result<()> {
    expect(socket, b'P')?;
    expect(socket, b'D')?;
    expect(socket, b'S')?;
    let mut response = frame(b'1', &[]);
    let mut parameter = Vec::from(1_u16.to_be_bytes());
    parameter.extend_from_slice(&23_u32.to_be_bytes());
    response.extend(frame(b't', &parameter));
    let mut field = Vec::from(1_u16.to_be_bytes());
    field.extend_from_slice(b"v\0");
    field.extend_from_slice(&0_u32.to_be_bytes());
    field.extend_from_slice(&0_i16.to_be_bytes());
    field.extend_from_slice(&23_u32.to_be_bytes());
    field.extend_from_slice(&4_i16.to_be_bytes());
    field.extend_from_slice(&(-1_i32).to_be_bytes());
    field.extend_from_slice(&0_i16.to_be_bytes());
    response.extend(frame(b'T', &field));
    response.extend(ready());
    socket.write_all(&response)
}

fn execution(socket: &mut TcpStream) -> io::Result<()> {
    expect(socket, b'B')?;
    expect(socket, b'E')?;
    expect(socket, b'S')?;
    Ok(())
}

fn result(value: i32) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    let mut row = Vec::from(1_u16.to_be_bytes());
    row.extend_from_slice(&4_i32.to_be_bytes());
    row.extend_from_slice(&value.to_be_bytes());
    response.extend(frame(b'D', &row));
    response.extend(frame(b'C', b"SELECT 1\0"));
    response.extend(ready());
    response
}

#[test]
fn finite_batch_preserves_independent_sync_results_and_errors() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        prepare(socket)?;
        for index in 0..3 {
            execution(socket)?;
            let response = if index == 1 {
                let mut error = frame(b'2', &[]);
                error.extend(frame(b'E', b"SERROR\0VERROR\0C22012\0Mdivision error\0\0"));
                error.extend(ready());
                error
            } else {
                result(if index == 0 { 11 } else { 33 })
            };
            for bytes in response.chunks(3) {
                socket.write_all(bytes)?;
            }
        }
        execution(socket)?;
        socket.write_all(&result(99))?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = TcpReadinessConnection::connect(peer.config_with_limits(limits()))
            .await
            .unwrap();
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar("SELECT $1::int4").await.unwrap();
        let items = scalar::pipeline(
            &mut connection,
            &statement,
            &[Some(11), Some(0), Some(33)],
            scalar::pipeline_limits(3, 4096),
        )
        .await
        .unwrap();
        let values = scalar::values(&items);
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Ok(Some(11)));
        assert_eq!(items[1].as_ref().unwrap_err().code(), "22012");
        assert_eq!(values[2], Ok(Some(33)));
        assert!(connection.is_usable());
        assert_eq!(
            connection.query_scalar(&statement, Some(99)).await.unwrap(),
            Some(99)
        );
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn oversized_header_fails_without_waiting_for_body_or_peer_close() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        prepare(socket)?;
        execution(socket)?;
        socket.write_all(&frame(b'2', &[]))?;
        socket.write_all(&[b'D', 0, 0, 4, 0])?;
        peer::eof(socket)
    });
    run(async {
        let mut connection = TcpReadinessConnection::connect(peer.config_with_limits(limits()))
            .await
            .unwrap();
        scalar::configure(&mut connection);
        let statement = connection.prepare_scalar("SELECT $1::int4").await.unwrap();
        assert!(matches!(
            connection.query_scalar(&statement, Some(1)).await,
            Err(Error::Protocol(
                compio_postgres::ProtocolError::FrameTooLarge { .. }
            ))
        ));
        assert!(!connection.is_usable());
        connection.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn plaintext_readiness_does_not_downgrade_a_scram_plus_request() {
    run(async {
        let config = TcpConfig::plaintext(
            "127.0.0.1:9".parse().unwrap(),
            "test",
            "test",
            AuthenticationPolicy::ScramSha256Plus {
                password: "test".to_owned(),
                max_iterations: 4096,
            },
            limits(),
            peer::TCP_OPTIONS,
        );
        assert!(matches!(
            TcpReadinessConnection::connect(config).await,
            Err(Error::Unsupported(_))
        ));
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_readiness_generic_pipeline_preserves_independent_sql_errors() {
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
        let mut connection = TcpReadinessConnection::connect(config).await.unwrap();
        connection
            .configure_statements(StatementLimits {
                max_statements: 4,
                max_metadata_bytes: 65536,
            })
            .unwrap();
        let statement = connection
            .prepare(
                "SELECT 10 / $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let two = 2_i32.to_be_bytes();
        let zero = 0_i32.to_be_bytes();
        let success = [Parameter::binary(Oid::INT4, &two)];
        let failure = [Parameter::binary(Oid::INT4, &zero)];
        let query = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 8192,
        };
        let requests = [
            PipelineRequest {
                statement: &statement,
                parameters: &success,
                limits: query,
            },
            PipelineRequest {
                statement: &statement,
                parameters: &failure,
                limits: query,
            },
            PipelineRequest {
                statement: &statement,
                parameters: &success,
                limits: query,
            },
        ];
        let items = connection
            .query_pipeline(
                &requests,
                PipelineLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_requests: 3,
                    max_rows: 3,
                    max_result_bytes: 8192,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
            )
            .await
            .unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[1].as_ref().unwrap_err().code(), "22012");
        for index in [0, 2] {
            let row = items[index]
                .as_ref()
                .unwrap()
                .rows
                .rows()
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(row.decoder().decode_next::<i32>().unwrap(), 5);
        }
        assert!(connection.is_usable());
        connection.close_local().await.unwrap();
    });
}
