//! 通过 TCP 连接独立 PostgreSQL 19 实例，验证普通标量查询结果。

#[path = "support/live.rs"]
mod live;
#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    BatchOptions, ClientOptions, DatabaseError, Error, ExecutionOptions, ExecutionScheduling,
    OnError, PreparedStatementStorage, QueryLimits, QueryOptions, ResultFormats, ReuseState,
    Statement, StatementLimits, TcpConnection, WireLimits,
    types::{Format, Oid, Oid8, Parameter, RegDatabase},
};
use std::time::Duration;

const POLICY: OnError = OnError::RecoverExplicitly;
const SCHEDULING: ExecutionScheduling = ExecutionScheduling::Uninterrupted;
const QUERY: QueryLimits = QueryLimits {
    max_rows: 8,
    max_result_bytes: 4096,
    max_metadata_bytes: 4096,
};
const BATCH: BatchOptions = BatchOptions {
    member_limits: QUERY,
    max_requests: 3,
    max_inflight: 3,
    max_queued_request_bytes: 4096,
    max_diagnostic_bytes: 4096,
    scheduling: SCHEDULING,
};

async fn prepared(client: &mut TcpConnection, sql: &str, parameters: &[Oid]) -> Statement {
    client
        .prepare(
            sql,
            parameters,
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap()
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn ordinary_scalar_batch_contracts_on_pg19() {
    let config = live::tcp_config(
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 4096,
            max_messages_per_request: 128,
        },
        tcp_options::TCP_OPTIONS,
    );
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        compio::time::timeout(Duration::from_secs(15), async {
            let options = ClientOptions::new(
                config,
                ExecutionOptions {
                    query: QueryOptions {
                        limits: QUERY,
                        scheduling: SCHEDULING,
                    },
                    batch: Some(BATCH),
                },
                StatementLimits {
                    max_statements: 8,
                    max_metadata_bytes: 8192,
                },
            );
            let mut client = TcpConnection::connect(options).await.unwrap();
            let database = client
                .one_shot(
                    "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()",
                    &[],
                    ResultFormats::All(Format::Binary),
                )
                .one::<Oid>(POLICY)
                .await
                .unwrap();
            let types = prepared(
                &mut client,
                "SELECT $1::regdatabase, $2::oid8",
                &[Oid::REGDATABASE, Oid::OID8],
            )
            .await;
            let expected = (RegDatabase(database.0), Oid8(u64::from(u32::MAX) + 9));
            let decoded = client
                .query(
                    &types,
                    &[
                        Parameter::regdatabase(expected.0),
                        Parameter::oid8(expected.1),
                    ],
                )
                .map_provisional_one(POLICY, |row| {
                    let mut fields = row.decoder();
                    let values = (
                        fields.decode_next::<RegDatabase>()?,
                        fields.decode_next::<Oid8>()?,
                    );
                    fields.finish()?;
                    Ok(values)
                })
                .await
                .unwrap();
            assert_eq!(decoded, expected);
            let nullable = prepared(
                &mut client,
                "SELECT CASE WHEN $1=0 THEN NULL ELSE $1 END WHERE $1>=0",
                &[Oid::INT4],
            )
            .await;

            {
                let mut optional: Vec<Result<Option<Option<i32>>, DatabaseError>> =
                    Vec::with_capacity(3);
                let progress = client
                    .streaming_batch(
                        [-1, 0, 17]
                            .into_iter()
                            .map(|n| nullable.bind_one(Parameter::int4(n))),
                    )
                    .collect_zero_or_one_into_ready(&mut optional, POLICY)
                    .await
                    .unwrap();
                assert_eq!((progress.confirmed, progress.rows_delivered), (3, 2));
                assert_eq!(
                    optional.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
                    [None, Some(None), Some(Some(17))]
                );
            }

            let mut required: Vec<Result<Option<i32>, DatabaseError>> = Vec::with_capacity(6);
            let progress = client
                .streaming_batch(
                    [0, 17]
                        .into_iter()
                        .map(|n| nullable.bind_one(Parameter::int4(n))),
                )
                .collect_one_into_ready(&mut required, POLICY)
                .await
                .unwrap();
            assert_eq!((progress.confirmed, progress.rows_delivered), (2, 2));
            assert_eq!(required[0].as_ref().unwrap(), &None);
            assert_eq!(required[1].as_ref().unwrap(), &Some(17));
            let failure = client
                .streaming_batch([nullable.bind_one(Parameter::int4(-1))])
                .collect_one_into_ready(&mut required, OnError::DrainToReady)
                .await
                .unwrap_err();
            assert!(matches!(failure.source, Error::InvalidInput(_)));
            assert_eq!(failure.progress.confirmed, 1);
            assert_eq!(required.len(), 2);
            assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);

            client
                .expert()
                .query_simple_single(
                    "CREATE TEMP TABLE cpg_scalar_shape (v int4)",
                    compio_postgres::QueryOptions {
                        limits: QUERY,
                        scheduling: SCHEDULING,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            let wide_insert = prepared(
                &mut client,
                "INSERT INTO cpg_scalar_shape VALUES ($1) RETURNING v, v",
                &[Oid::INT4],
            )
            .await;
            let failure = client
                .streaming_batch([wide_insert.bind_one(Parameter::int4(91))])
                .collect_one_into_ready(&mut required, OnError::Discard)
                .await
                .unwrap_err();
            assert!(matches!(failure.source, Error::InvalidInput(_)));
            assert_eq!(failure.progress.admitted, 0);
            assert_eq!(required.len(), 2);
            let count = prepared(
                &mut client,
                "SELECT count(*)::int4 FROM cpg_scalar_shape",
                &[],
            )
            .await;
            assert_eq!(
                client.query(&count, &[]).one::<i32>(POLICY).await.unwrap(),
                0
            );

            let division = prepared(&mut client, "SELECT 100 / $1::int4", &[Oid::INT4]).await;
            let mut division_values: Vec<Result<i32, DatabaseError>> = Vec::with_capacity(3);
            let progress = client
                .streaming_batch(
                    [1, 0, 2]
                        .into_iter()
                        .map(|n| division.bind_one(Parameter::int4(n))),
                )
                .collect_one_into_ready(&mut division_values, POLICY)
                .await
                .unwrap();
            assert_eq!((progress.confirmed, progress.sql_errors), (3, 1));
            assert_eq!(division_values[0].as_ref().unwrap(), &100);
            assert_eq!(division_values[1].as_ref().unwrap_err().code(), "22012");
            assert_eq!(division_values[2].as_ref().unwrap(), &50);

            let mut tx = client.begin_transaction().await.unwrap();
            division_values.clear();
            let progress = tx
                .streaming_batch([division.bind_one(Parameter::int4(4))])
                .collect_one_into_ready(&mut division_values, POLICY)
                .await
                .unwrap();
            assert_eq!(progress.confirmed, 1);
            assert_eq!(division_values[0].as_ref().unwrap(), &25);
            tx.commit().await.unwrap();
            assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
            client.close_local().await.unwrap();
        })
        .await
        .expect("scalar PostgreSQL fixture deadline");
    });
}
