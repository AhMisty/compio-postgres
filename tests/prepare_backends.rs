//! 在不同传输后端验证预备语句的成功和失败路径。
#[path = "support/live.rs"]
mod live;

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    Error, QueryLimits, ResultFormats, ReuseState, StatementLimits, StatementPipelineLimits,
    TcpConfig, TransactionStatus, WireLimits, WireTransport,
    expert::{PrepareRequest, Session},
    types::{Format, Oid, Parameter},
};
use std::{future::Future, time::Duration};

fn connection_limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 65536,
        max_messages_per_request: 128,
    }
}
fn config() -> TcpConfig {
    live::tcp_config(connection_limits(), tcp_options::TCP_OPTIONS)
}
fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("Prepare provider deadline")
    });
}
fn limits() -> StatementPipelineLimits {
    StatementPipelineLimits {
        max_statements: 8,
        max_packet_bytes: 65536,
        max_result_bytes: 8192,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::MIN,
        },
    }
}
fn close_limits() -> StatementPipelineLimits {
    StatementPipelineLimits {
        max_statements: 8,
        max_packet_bytes: 65536,
        max_result_bytes: 8192,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::MIN,
        },
    }
}
fn request(sql: &str) -> PrepareRequest<'_> {
    PrepareRequest {
        sql,
        parameter_oids: &[Oid::INT4],
        formats: ResultFormats::All(Format::Binary),
    }
}
async fn exercise<T: WireTransport>(connection: &mut Session<T>) -> Result<(), Error> {
    connection.configure_statements(StatementLimits {
        max_statements: 8,
        max_metadata_bytes: 65536,
    })?;
    let results = connection
        .prepare_pipeline(
            vec![
                request("SELECT $1::int4 + 1"),
                request("invalid SQL"),
                request("SELECT $1::int4 + 2"),
            ],
            limits(),
        )
        .await
        .map_err(|e| e.source)?;
    assert_eq!(results.len(), 3);
    assert_eq!(results[1].as_ref().unwrap_err().code(), "42601");
    for (index, expected) in [(0, 8), (2, 9)] {
        let statement = results[index].as_ref().unwrap();
        let mut query = connection
            .query(
                statement,
                &[Parameter::int4(7)],
                compio_postgres::QueryOptions {
                    limits: QueryLimits {
                        max_rows: 1,
                        max_result_bytes: 64,
                        max_metadata_bytes: 4096,
                    },
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await?;
        assert_eq!(
            query
                .next_row()
                .await?
                .unwrap()
                .view()
                .decoder()
                .decode_next::<i32>()?,
            expected
        );
        query.finish().await?;
    }
    let closed = connection
        .close_all_statements_pipeline(close_limits())
        .await
        .map_err(|e| e.source)?;
    assert!(matches!(closed.as_slice(), [Ok(_), Ok(_)]));
    drop(results);
    assert_eq!(connection.reclaim_closed_statements()?, 2);
    let mut transaction = connection.begin_transaction().await?;
    let results = transaction
        .prepare_pipeline(
            vec![
                request("SELECT $1::int4 + 3"),
                request("SELECT $1::int4 + 4"),
            ],
            limits(),
        )
        .await
        .map_err(|e| e.source)?;
    assert!(results.iter().all(Result::is_ok));
    let mut query = transaction
        .query(
            results[0].as_ref().unwrap(),
            &[Parameter::int4(7)],
            compio_postgres::QueryOptions {
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 64,
                    max_metadata_bytes: 4096,
                },
                scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await?;
    assert_eq!(
        query
            .next_row()
            .await?
            .unwrap()
            .view()
            .decoder()
            .decode_next::<i32>()?,
        10
    );
    query.finish().await?;
    drop(query);
    let closed = transaction
        .close_all_statements_pipeline(close_limits())
        .await
        .map_err(|e| e.source)?;
    assert!(matches!(closed.as_slice(), [Ok(_), Ok(_)]));
    transaction.rollback().await?;
    connection.take_transaction_end();
    drop(results);
    assert_eq!(connection.reclaim_closed_statements()?, 2);
    let mut transaction = connection.begin_transaction().await?;
    let errors = transaction
        .prepare_pipeline(
            vec![request("invalid SQL"), request("SELECT $1::int4")],
            limits(),
        )
        .await
        .map_err(|e| e.source)?;
    let [Err(first), Err(second)] = errors.as_slice() else {
        panic!("每条已提交语句均应返回自己的错误");
    };
    assert_eq!([first.code(), second.code()], ["42601", "25P02"]);
    assert_eq!(
        transaction.transaction_status(),
        TransactionStatus::FailedTransaction
    );
    transaction.rollback().await?;
    connection.take_transaction_end();
    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    Ok(())
}
#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_native_prepare_pipeline_matrix() {
    run(async {
        let mut connection = compio_postgres::expert::TcpSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_readiness_prepare_pipeline_matrix() {
    run(async {
        let mut connection = compio_postgres::expert::linux::TcpReadinessSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_prepare_pipeline_matrix() {
    run(async {
        let config = live::unix_config(
            connection_limits(),
            compio_postgres::SendPolicy::BeforeBufferedRead,
        );
        let mut connection = compio_postgres::expert::UnixSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_readiness_prepare_pipeline_matrix() {
    run(async {
        let config = live::unix_config(
            connection_limits(),
            compio_postgres::SendPolicy::BeforeBufferedRead,
        );
        let mut connection = compio_postgres::expert::linux::UnixReadinessSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 TLS 和 SCRAM-PLUS 的 PostgreSQL 19，以及 CPG_TLS_* 证书配置"]
fn live_tls_prepare_pipeline_matrix() {
    use compio_postgres::{TlsNegotiation, TlsVersions};
    run(async {
        let config = live::tls_config(
            connection_limits(),
            tcp_options::TCP_OPTIONS,
            tls_options::fixture_tls_options(TlsNegotiation::SslRequest, TlsVersions::Tls12Or13),
        );
        let mut connection = compio_postgres::expert::TlsSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
