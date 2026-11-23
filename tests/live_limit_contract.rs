//! 通过 TCP 连接独立 PostgreSQL 19 实例，验证普通 API 的各项限额。

#[path = "support/live.rs"]
mod live;
#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    AbandonPolicy, AllocationPolicy, BatchControl, BatchError, BatchErrorOrigin, BatchEvent,
    BatchOptions, BatchProgress, ClientOptions, DatabaseError, Error, ExecutionOptions,
    ExecutionScheduling, OnError, OwnedOutput, PreparedStatementStorage, QueryLimits, QueryOptions,
    ResultFormats, ReuseState, Statement, StatementLimits, TcpConfig, TcpConnection, WireLimits,
    types::{CodecError, Format, Oid, Parameter},
};
use std::{mem::size_of, ops::ControlFlow, time::Duration};

const MAX_MESSAGES: usize = 48;
const MAX_REQUEST: usize = 4096;
const SCHEDULING: ExecutionScheduling = ExecutionScheduling::Uninterrupted;
const QUERY_LIMITS: QueryLimits = QueryLimits {
    max_rows: 64,
    max_result_bytes: 4096,
    max_metadata_bytes: 4096,
};
const OUTPUT: OwnedOutput = OwnedOutput {
    max_bytes: 16 * 1024,
    allocation: AllocationPolicy::Grow,
};
const POLICY: OnError = OnError::RecoverExplicitly;

fn batch_options(diagnostic_bytes: usize) -> BatchOptions {
    BatchOptions {
        member_limits: QUERY_LIMITS,
        max_requests: 1,
        max_inflight: 1,
        max_queued_request_bytes: MAX_REQUEST,
        max_diagnostic_bytes: diagnostic_bytes,
        scheduling: SCHEDULING,
    }
}

fn options(config: TcpConfig, profile: BatchOptions) -> ClientOptions<TcpConfig> {
    ClientOptions::new(
        config,
        ExecutionOptions {
            query: QueryOptions {
                limits: QUERY_LIMITS,
                scheduling: SCHEDULING,
            },
            batch: Some(profile),
        },
        StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 4096,
        },
    )
}

#[derive(Clone, Copy)]
enum Mode {
    Collect,
    Visit,
    Borrow,
}

const MODES: [Mode; 3] = [Mode::Collect, Mode::Visit, Mode::Borrow];

#[derive(Default)]
struct Events {
    rows: usize,
    diagnostics: usize,
    diagnostic_bytes: usize,
}

impl Events {
    fn diagnostic(&mut self, error: &DatabaseError) {
        assert_eq!(error.code(), "22003");
        assert_eq!(error.message(), "x".repeat(256));
        self.diagnostics += 1;
        self.diagnostic_bytes = size_of::<DatabaseError>()
            + error
                .fields()
                .map(|(_, value)| value.len() + 2)
                .sum::<usize>()
            + 1;
    }
}

fn without_results(error: BatchError) -> BatchError<()> {
    BatchError {
        completed: (),
        progress: error.progress,
        source: error.source,
        reuse_state: error.reuse_state,
        origin: error.origin,
        cleanup_error: error.cleanup_error,
    }
}

async fn execute_batch(
    connection: &mut TcpConnection,
    mode: Mode,
    statement: &Statement,
    value: i32,
    profile: BatchOptions,
    events: &mut Events,
) -> Result<BatchProgress, BatchError<()>> {
    let batch = connection
        .streaming_batch([statement.bind_one(Parameter::int4(value))])
        .with_options(profile);
    match mode {
        Mode::Collect => {
            let report = batch
                .collect_ready(OUTPUT, POLICY)
                .await
                .map_err(without_results)?;
            for result in &report.results {
                match result {
                    Ok(result) => events.rows += result.rows.len(),
                    Err(error) => events.diagnostic(error),
                }
            }
            Ok(report.progress)
        }
        Mode::Visit => {
            batch
                .visit_ready(OUTPUT, POLICY, |event| {
                    match event.outcome {
                        Ok(result) => events.rows += result.rows.len(),
                        Err(error) => events.diagnostic(error),
                    }
                    Ok(ControlFlow::Continue(()))
                })
                .await
        }
        Mode::Borrow => {
            batch
                .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
                    match event {
                        BatchEvent::Row { .. } => events.rows += 1,
                        BatchEvent::Ready {
                            outcome: Err(error),
                            ..
                        } => events.diagnostic(error),
                        _ => {}
                    }
                    Ok(BatchControl::Continue)
                })
                .await
        }
    }
}

async fn setup(connection: &mut TcpConnection, sql: &str) {
    connection
        .expert()
        .query_simple_single(
            sql,
            compio_postgres::QueryOptions {
                limits: QUERY_LIMITS,
                scheduling: SCHEDULING,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
}

async fn prepare(connection: &mut TcpConnection, sql: &str) -> Statement {
    connection
        .prepare(
            sql,
            &[Oid::INT4],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap()
}

#[test]
#[ignore = "需要通过 CPG_* 配置 PostgreSQL 19 TCP 与 SCRAM 认证"]
fn ordinary_query_and_batch_limits_on_pg19() {
    let config = live::tcp_config(
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: MAX_REQUEST,
            max_messages_per_request: MAX_MESSAGES,
        },
        tcp_options::TCP_OPTIONS,
    )
    .startup_parameter("client_min_messages", "notice");
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        compio::time::timeout(Duration::from_secs(15), async {
            let profile = batch_options(4096);
            let oversized = BatchOptions {
                max_queued_request_bytes: MAX_REQUEST + 1,
                ..profile
            };
            assert!(matches!(
                TcpConnection::connect(options(config.clone(), oversized)).await,
                Err(Error::InvalidInput(_))
            ));
            let mut connection = TcpConnection::connect(options(config, profile))
                .await
                .unwrap();
            setup(
                &mut connection,
                "CREATE FUNCTION pg_temp.cpg_limit_notice(n int) RETURNS int \
                 LANGUAGE plpgsql VOLATILE AS $$ BEGIN RAISE NOTICE 'row %', n; RETURN n; END; $$",
            )
            .await;
            setup(
                &mut connection,
                "CREATE FUNCTION pg_temp.cpg_limit_failure(n int) RETURNS int \
                 LANGUAGE plpgsql VOLATILE AS $$ BEGIN RAISE EXCEPTION USING \
                 ERRCODE = '22003', MESSAGE = repeat('x', n); END; $$",
            )
            .await;
            let notices = prepare(
                &mut connection,
                "SELECT pg_temp.cpg_limit_notice(i) FROM generate_series(1, $1::int4) AS g(i)",
            )
            .await;
            let diagnostic = prepare(
                &mut connection,
                "SELECT pg_temp.cpg_limit_failure($1::int4)",
            )
            .await;

            let source = std::iter::once_with(|| -> compio_postgres::BatchRequest<'_> {
                panic!("invalid override must fail before reading input")
            });
            let error = connection
                .streaming_batch(source)
                .with_options(oversized)
                .collect_ready(OUTPUT, POLICY)
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::InvalidInput(_)));
            assert_eq!(error.progress.consumed, 0);

            // BindComplete、CommandComplete 和 ReadyForQuery 各占一条控制消息，
            // 被调用的函数还会在每行之前发出一条 NOTICE。
            for rows in [45, 46] {
                let expected_rows = usize::try_from(rows).unwrap();
                let result = connection
                    .query(&notices, &[Parameter::int4(rows)])
                    .collect_ready(AllocationPolicy::Grow, POLICY)
                    .await;
                if expected_rows + 3 == MAX_MESSAGES {
                    assert_eq!(result.unwrap().rows.len(), expected_rows);
                } else {
                    assert!(matches!(result, Err(Error::Limit(_))));
                    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
                    connection.recover_to_ready().await.unwrap();
                }
                for mode in MODES {
                    let mut events = Events::default();
                    let result =
                        execute_batch(&mut connection, mode, &notices, rows, profile, &mut events)
                            .await;
                    if expected_rows + 3 == MAX_MESSAGES {
                        assert_eq!(result.unwrap().confirmed, 1);
                        assert_eq!(events.rows, expected_rows);
                    } else {
                        let error = result.unwrap_err();
                        assert!(matches!(error.source, Error::Limit(_)));
                        assert_eq!((error.progress.admitted, error.progress.confirmed), (1, 0));
                        assert_eq!(error.reuse_state, ReuseState::NeedsRecovery);
                        connection.recover_to_ready().await.unwrap();
                    }
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                }
            }

            for mode in MODES {
                let mut events = Events::default();
                let progress = execute_batch(
                    &mut connection,
                    mode,
                    &diagnostic,
                    256,
                    profile,
                    &mut events,
                )
                .await
                .unwrap();
                assert_eq!(
                    (progress.confirmed, progress.sql_errors, events.diagnostics),
                    (1, 1, 1)
                );
                let diagnostic_bytes = events.diagnostic_bytes;
                let mut events = Events::default();
                let error = execute_batch(
                    &mut connection,
                    mode,
                    &diagnostic,
                    256,
                    batch_options(diagnostic_bytes - 1),
                    &mut events,
                )
                .await
                .unwrap_err();
                assert_eq!(error.origin, BatchErrorOrigin::Resource);
                assert!(matches!(error.source, Error::Limit(_)));
                assert_eq!(
                    (
                        error.progress.confirmed,
                        error.progress.sql_errors,
                        events.diagnostics
                    ),
                    (1, 1, 0)
                );
                connection.recover_to_ready().await.unwrap();
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }

            // 首个错误之后的排空有独立预算。通知不计入数据行和载荷字节。
            for member_limits in [
                QueryLimits {
                    max_rows: 1,
                    ..QUERY_LIMITS
                },
                QueryLimits {
                    max_result_bytes: 12,
                    ..QUERY_LIMITS
                },
            ] {
                let error = connection
                    .streaming_batch([notices.bind_one(Parameter::int4(8))])
                    .with_options(BatchOptions {
                        member_limits,
                        ..profile
                    })
                    .collect_ready(OUTPUT, OnError::DrainToReady)
                    .await
                    .unwrap_err();
                assert_eq!(error.origin, BatchErrorOrigin::Resource);
                if member_limits.max_rows == 1 {
                    assert!(matches!(
                        error.source,
                        Error::Limit("pipeline row limit exceeded")
                    ));
                } else {
                    assert!(matches!(
                        &error.source,
                        Error::Codec(source)
                            if matches!(source.as_ref(), CodecError::Limit("owned batch byte limit reached"))
                    ));
                }
                assert!(matches!(
                    error.cleanup_error.as_deref(),
                    Some(Error::Limit(_))
                ));
                assert_eq!((error.progress.admitted, error.progress.confirmed), (1, 0));
                assert_eq!(error.reuse_state, ReuseState::NeedsRecovery);
                connection
                    .recover_to_ready_with_limits(8, 4096)
                    .await
                    .unwrap();
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                assert_eq!(
                    connection
                        .query(&notices, &[Parameter::int4(1)])
                        .one::<i32>(POLICY)
                        .await
                        .unwrap(),
                    1,
                );
            }
            connection.close_local().await.unwrap();
        })
        .await
        .expect("live PostgreSQL limit test exceeded its deadline");
    });
}
