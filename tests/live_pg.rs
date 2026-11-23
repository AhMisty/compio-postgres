//! 通过 SCRAM 连接独立的 PostgreSQL 19，验证只读查询、取消与流水线。
//! 连接参数与运行命令见仓库的 `docs/testing.md`。

#[path = "support/live.rs"]
mod live;

#[path = "support/tcp_options.rs"]
mod tcp_options;

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{cell::Cell, future::Future, rc::Rc, time::Duration};

use compio_postgres::{
    AuthenticationPolicy, Error, TcpConfig, WireLimits, expert::TcpSession as TcpConnection,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const IDENTITY_SQL: &str = "SELECT $1::int4 AS result";
const SLEEP_SQL: &str = "SELECT $1::int4 AS result FROM pg_sleep(0.5)";
const WIRE: WireLimits = WireLimits {
    receive_capacity: 8192,
    max_frame_len: 8191,
    max_request_len: 8192,
    max_messages_per_request: 128,
};

fn tcp_config() -> TcpConfig {
    live::tcp_config(WIRE, tcp_options::TCP_OPTIONS)
}

#[cfg(all(feature = "uuid", feature = "time", feature = "serde_json"))]
#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn business_types_round_trip_on_a_prepared_connection() {
    use compio_postgres::{
        ClientOptions, OnError, PreparedStatementStorage, ResultFormats,
        types::{
            Format, JsonPath, Network, NumericView, Oid, Oid8, Parameter, PgMoney, encode_json,
            encode_scaled_numeric,
        },
    };
    let config = tcp_config();
    run(async {
        let mut client =
            compio_postgres::TcpConnection::connect(ClientOptions::short_queries(config))
                .await
                .unwrap();
        let statement = client
            .prepare(
                "SELECT $1::uuid, $2::timestamptz, $3::jsonb, $4::inet, $5::cidr, $6::inet,
                        $7::numeric, $8::jsonpath, $9::money, $10::oid8",
                &[
                    Oid::UUID,
                    Oid::TIMESTAMPTZ,
                    Oid::JSONB,
                    Oid::INET,
                    Oid::CIDR,
                    Oid::INET,
                    Oid::NUMERIC,
                    Oid::JSONPATH,
                    Oid::MONEY,
                    Oid::OID8,
                ],
                PreparedStatementStorage::Named,
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let id = uuid::Uuid::from_u128(123);
        let instant = time::OffsetDateTime::from_unix_timestamp(-1).unwrap();
        let json = serde_json::json!({"name": "数据库", "enabled": true});
        let encoded = encode_json(Oid::JSONB, &json, 128).unwrap();
        let amount = encode_scaled_numeric(-1_234_567, 2, 32).unwrap();
        let path = JsonPath("$");
        let money = PgMoney(-1_234_567);
        let oid8 = Oid8(u64::MAX);
        let inet = Network {
            address: "192.0.2.17".parse().unwrap(),
            prefix_len: 24,
            is_cidr: false,
        };
        let cidr = Network {
            address: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
            is_cidr: true,
        };
        let values = [
            Parameter::from(id),
            Parameter::try_from(instant).unwrap(),
            encoded.parameter(),
            Parameter::network(inet).unwrap(),
            Parameter::network(cidr).unwrap(),
            Parameter::null(Oid::INET, Format::Binary),
            amount.parameter(),
            Parameter::from(path),
            Parameter::money(money),
            Parameter::oid8(oid8),
        ];
        let received = client
            .query(&statement, &values)
            .map_provisional_one(OnError::RecoverExplicitly, |row| {
                let mut fields = row.decoder();
                let result = (
                    fields.decode_next::<uuid::Uuid>()?,
                    fields.decode_next::<time::OffsetDateTime>()?,
                    fields.decode_next::<serde_json::Value>()?,
                    fields.decode_next::<Network>()?,
                    fields.decode_next::<Network>()?,
                    fields.decode_next::<Option<Network>>()?,
                    fields.decode_next::<NumericView>()?.to_scaled_i128(2)?,
                    fields.decode_next::<JsonPath>()?.0 == path.0,
                    fields.decode_next::<PgMoney>()?,
                    fields.decode_next::<Oid8>()?,
                );
                fields.finish()?;
                Ok(result)
            })
            .await
            .unwrap();
        assert_eq!(
            received,
            (
                id, instant, json, inet, cidr, None, -1_234_567, true, money, oid8
            )
        );
        client.terminate().await.unwrap();
    });
}

fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new()
        .expect("create the Compio fixture runtime")
        .block_on(async {
            compio::time::timeout(TEST_TIMEOUT, future)
                .await
                .expect("live PostgreSQL test exceeded its overall deadline")
        })
}

async fn bounded<T>(future: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    compio::time::timeout(OPERATION_TIMEOUT, future)
        .await
        .expect("live PostgreSQL operation exceeded its deadline")
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn independent_cancel_interrupts_the_active_query_and_retires_its_session() {
    let config = tcp_config();
    run(async {
        let connection = bounded(TcpConnection::connect(config.clone()))
            .await
            .unwrap();
        let observer = bounded(TcpConnection::connect(config)).await.unwrap();
        scalar::assert_live_cancel(connection, observer).await;
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn int4_boundaries_null_and_statement_generations() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let first = bounded(connection.prepare_scalar(IDENTITY_SQL))
            .await
            .expect("prepare the int4 identity statement");
        for value in [Some(i32::MIN), Some(i32::MAX), Some(0), None] {
            assert_eq!(
                bounded(connection.query_scalar(&first, value))
                    .await
                    .expect("execute the int4 identity statement"),
                value
            );
            assert!(connection.is_usable());
        }
        bounded(connection.close_prepared(&first))
            .await
            .expect("close the first statement");
        assert!(matches!(
            bounded(connection.query_scalar(&first, Some(1))).await,
            Err(Error::InvalidInput(_))
        ));

        let second = bounded(connection.prepare_scalar("SELECT $1::int4 + 0 AS result"))
            .await
            .expect("prepare a new statement generation");
        assert!(matches!(
            bounded(connection.query_scalar(&first, Some(2))).await,
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(
            bounded(connection.query_scalar(&second, Some(123)))
                .await
                .expect("the new statement generation remains valid"),
            Some(123)
        );
        bounded(connection.close_prepared(&second))
            .await
            .expect("close the second statement");
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn wrong_scram_password_is_rejected_by_the_server() {
    let mut wrong_password = live::required("CPG_PASSWORD");
    wrong_password.push_str("-intentionally-incorrect-fixture-password");
    let config = live::tcp_config_with_authentication(
        WIRE,
        tcp_options::TCP_OPTIONS,
        AuthenticationPolicy::ScramSha256 {
            password: wrong_password,
            max_iterations: live::SCRAM_MAX_ITERATIONS,
        },
    );
    run(async {
        let result = bounded(TcpConnection::connect(config)).await;
        assert!(matches!(result, Err(Error::Database(error)) if error.code() == "28P01"));
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn authentication_ok_policy_does_not_silently_accept_scram() {
    let config = live::tcp_config_with_authentication(
        WIRE,
        tcp_options::TCP_OPTIONS,
        AuthenticationPolicy::AllowAuthenticationOk,
    );
    run(async {
        assert!(matches!(
            bounded(TcpConnection::connect(config)).await,
            Err(Error::Unsupported(_))
        ));
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn division_by_zero_recovers_at_ready_and_the_next_query_succeeds() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar("SELECT 100 / $1::int4 AS result"))
            .await
            .expect("prepare the division statement");
        let result = bounded(connection.query_scalar(&statement, Some(0))).await;
        assert!(matches!(result, Err(Error::Database(error)) if error.code() == "22012"));
        assert!(connection.is_usable());
        assert_eq!(
            connection.transaction_status(),
            compio_postgres::TransactionStatus::Idle
        );
        assert_eq!(
            bounded(connection.query_scalar(&statement, Some(1)))
                .await
                .expect("execute after the error synchronization boundary"),
            Some(100)
        );
        bounded(connection.close_prepared(&statement))
            .await
            .expect("close the division statement");
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn int8_result_layout_uses_the_general_decoder_without_discarding() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar("SELECT $1::int8 AS result"))
            .await
            .unwrap();
        let mut query = connection
            .query(
                &statement,
                &[compio_postgres::types::Parameter::int4(42)],
                compio_postgres::QueryOptions {
                    limits: scalar::limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        {
            let row = query.next_row().await.unwrap().unwrap();
            let mut fields = row.view().decoder();
            assert_eq!(fields.decode_next::<i64>().unwrap(), 42);
            fields.finish().unwrap();
        }
        query.finish().await.unwrap();
        drop(query);
        assert!(connection.is_usable());
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn another_compio_task_advances_while_postgres_sleeps() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar(SLEEP_SQL))
            .await
            .expect("prepare the sleeping SELECT");
        let query_finished = Rc::new(Cell::new(false));
        let ticks_during_query = Rc::new(Cell::new(0_u32));
        let finished_for_timer = query_finished.clone();
        let ticks_for_timer = ticks_during_query.clone();
        let owning_thread = std::thread::current().id();
        let timer = compio::runtime::spawn(async move {
            for _ in 0..4 {
                compio::time::sleep(Duration::from_millis(25)).await;
                assert_eq!(std::thread::current().id(), owning_thread);
                if !finished_for_timer.get() {
                    ticks_for_timer.set(ticks_for_timer.get() + 1);
                }
            }
        });
        let result = bounded(connection.query_scalar(&statement, Some(17))).await;
        query_finished.set(true);
        let observed_ticks = ticks_during_query.get();
        assert_eq!(result.expect("execute the sleeping SELECT"), Some(17));
        compio::time::timeout(OPERATION_TIMEOUT, timer)
            .await
            .expect("timer task exceeded its deadline")
            .expect("timer task must finish successfully");
        // 若数据库等待阻塞了这个 worker，定时器也就无法推进。
        assert!(
            observed_ticks > 0,
            "database I/O wait blocked the Compio task"
        );
        bounded(connection.close_prepared(&statement))
            .await
            .expect("close the sleeping statement");
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn timed_out_query_cannot_be_reused_as_a_completed_request() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar(SLEEP_SQL))
            .await
            .expect("prepare the sleeping SELECT");
        let result = compio::time::timeout(
            Duration::from_millis(50),
            connection.query_scalar(&statement, Some(23)),
        )
        .await;
        assert!(
            result.is_err(),
            "the deliberately slow request must time out"
        );
        assert!(!connection.is_usable());
        assert!(matches!(
            bounded(connection.query_scalar(&statement, Some(24))).await,
            Err(Error::Busy) | Err(Error::Broken)
        ));
        // 丢弃本地连接无法证明服务端已经取消或回滚 SELECT。这里使用只读查询，并限制 pg_sleep 时长。
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn pipeline_error_is_limited_to_its_own_sync_boundary() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar("SELECT 100 / $1::int4 AS result"))
            .await
            .expect("prepare the pipeline division statement");
        let values = [Some(1), Some(0), Some(2)];
        let results = compio::time::timeout(
            OPERATION_TIMEOUT,
            scalar::pipeline(
                &mut connection,
                &statement,
                &values,
                scalar::pipeline_limits(3, 16 * 1024),
            ),
        )
        .await
        .expect("pipeline operation exceeded its deadline")
        .unwrap_or_else(|error| panic!("unexpected pipeline failure: {}", error.source));
        assert!(matches!(
            scalar::values(&results).as_slice(),
            [Ok(Some(100)), Err(error), Ok(Some(50))] if error.code() == "22012"
        ));
        assert!(connection.is_usable());
        assert_eq!(
            bounded(connection.query_scalar(&statement, Some(4)))
                .await
                .expect("single request after the final pipeline boundary"),
            Some(25)
        );
        bounded(connection.close_prepared(&statement))
            .await
            .expect("close the pipeline division statement");
        connection.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn pipeline_preserves_null_and_int4_boundaries() {
    let config = tcp_config();
    run(async {
        let mut connection = bounded(TcpConnection::connect(config))
            .await
            .expect("connect with real SCRAM authentication");
        scalar::configure(&mut connection);
        let statement = bounded(connection.prepare_scalar(IDENTITY_SQL))
            .await
            .expect("prepare the pipeline int4 statement");
        let values = [Some(i32::MIN), None, Some(i32::MAX), Some(0)];
        let results = compio::time::timeout(
            OPERATION_TIMEOUT,
            scalar::pipeline(
                &mut connection,
                &statement,
                &values,
                scalar::pipeline_limits(values.len(), 16 * 1024),
            ),
        )
        .await
        .expect("pipeline operation exceeded its deadline")
        .unwrap_or_else(|error| panic!("unexpected pipeline failure: {}", error.source));
        assert_eq!(
            scalar::values(&results),
            values.into_iter().map(Ok).collect::<Vec<_>>()
        );
        assert!(connection.is_usable());
        bounded(connection.close_prepared(&statement))
            .await
            .expect("close the pipeline int4 statement");
        connection.discard();
    });
}
