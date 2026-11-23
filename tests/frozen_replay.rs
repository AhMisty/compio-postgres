//! 冻结的重放句柄持有编码后的参数，可在原参数释放后继续使用。

#[path = "support/live.rs"]
mod live;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    ClientOptions, Error, ExecutionScheduling, OnError, PreparedStatementStorage, QueryLimits,
    ResultFormats, ReuseState, StatementLimits, TcpConfig, TcpConnection as ObserverConnection,
    TransactionStatus, WireLimits,
    expert::{
        GroupPipelineLimits, PipelineRequest, ProvisionalGroupConsumeEvent, ProvisionalGroupEvent,
        TcpSession as TcpConnection,
    },
    types::{Format, Oid, Parameter},
};
use futures_util::{
    FutureExt,
    future::{Either, select},
};
use std::{
    future::Future,
    panic::{AssertUnwindSafe, resume_unwind},
    pin::pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PACKET: usize = 16 * 1024 * 1024;
const BINARY: ResultFormats = ResultFormats::All(Format::Binary);
const OBSERVATION_INTERVAL: Duration = Duration::from_millis(10);

fn config() -> TcpConfig {
    live::tcp_config(
        WireLimits {
            receive_capacity: 2 * 1024 * 1024,
            max_frame_len: 2 * 1024 * 1024 - 1,
            max_request_len: PACKET,
            max_messages_per_request: 128,
        },
        tcp_options::TCP_OPTIONS,
    )
}

fn run(future: impl Future<Output = ()>) {
    let runtime = compio::runtime::Runtime::new().unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        runtime.driver_type().is_iouring(),
        "Linux 冻结重放测试需要 io_uring"
    );
    runtime.block_on(async {
        compio::time::timeout(Duration::from_secs(20), future)
            .await
            .expect("冻结重放验证超时")
    });
}

async fn connect() -> TcpConnection {
    let mut connection = TcpConnection::connect(config()).await.unwrap();
    connection
        .configure_statements(StatementLimits {
            max_statements: 16,
            max_metadata_bytes: 65536,
        })
        .unwrap();
    connection
}

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 8,
        max_result_bytes: 2 * 1024 * 1024,
        max_metadata_bytes: 65536,
    }
}

fn replay_limits(inflight: usize) -> GroupPipelineLimits {
    GroupPipelineLimits {
        max_requests: 64,
        max_groups: 32,
        max_rows: 128,
        max_member_result_bytes: 2 * 1024 * 1024,
        max_packet_bytes: PACKET,
        max_inflight_groups: inflight,
        scheduling: ExecutionScheduling::Uninterrupted,
    }
}

fn observer_options() -> ClientOptions<TcpConfig> {
    ClientOptions::short_queries(live::tcp_config(
        WireLimits::short_queries(),
        tcp_options::TCP_OPTIONS,
    ))
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_frozen_parameters_are_detached_and_replayed_in_bounded_windows() {
    run(async {
        let mut connection = connect().await;
        for inflight in [1, 2, 4, 8] {
            let statement = connection
                .prepare(
                    "SELECT $1::int4,$2::bytea",
                    &[Oid::INT4, Oid::BYTEA],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let mut original = vec![0, 1, 255, 7];
            let frozen = {
                let parameters = [Parameter::int4(42), Parameter::bytea(&original)];
                connection
                    .compile_frozen_group(
                        &[PipelineRequest {
                            statement: &statement,
                            parameters: &parameters,
                            limits: query_limits(),
                        }],
                        PACKET,
                    )
                    .unwrap()
            };
            let packet_len = frozen.encoded_packet_len();
            original.fill(99);
            drop(original);
            drop(statement);
            let mut rows = 0;
            let (frozen, completion) = connection
                .replay_frozen_groups_provisional_visit(
                    frozen,
                    9,
                    replay_limits(inflight),
                    |event| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            assert_eq!(index, rows);
                            let mut decoder = row.decoder();
                            assert_eq!(decoder.decode_next::<i32>()?, 42);
                            assert_eq!(decoder.decode_next::<&[u8]>()?, &[0, 1, 255, 7]);
                            decoder.finish()?;
                            rows += 1;
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!((completion.requests, completion.groups, rows), (9, 9, 9));
            assert_eq!(frozen.encoded_packet_len(), packet_len);
            let mut rows = 0;
            let (frozen, completion) = connection
                .replay_frozen_groups_provisional_consume(
                    frozen,
                    2,
                    replay_limits(inflight),
                    |event| {
                        if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                            assert_eq!(index, rows);
                            assert_eq!(row.decode_next::<i32>()?, 42);
                            assert_eq!(row.decode_next::<&[u8]>()?, &[0, 1, 255, 7]);
                            rows += 1;
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!((completion.requests, completion.groups, rows), (2, 2, 2));
            let mut transaction = connection.begin_transaction().await.unwrap();
            let (_, completion) = transaction
                .replay_frozen_groups_provisional_visit(frozen, 2, replay_limits(inflight), |_| {
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(
                completion.transaction_status,
                TransactionStatus::InTransaction
            );
            transaction.rollback().await.unwrap();
        }
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_frozen_identity_invalidation_and_zero_replay_are_explicit() {
    run(async {
        let mut first = connect().await;
        let statement = first
            .prepare("SELECT 42::int4", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let requests = [PipelineRequest {
            statement: &statement,
            parameters: &[],
            limits: query_limits(),
        }];
        let frozen = first.compile_frozen_group(&requests, PACKET).unwrap();
        let length = frozen.encoded_packet_len();
        let (frozen, completion) = first
            .replay_frozen_groups_provisional_visit(frozen, 0, replay_limits(2), |_| {
                panic!("zero replay cannot call the visitor")
            })
            .await
            .unwrap();
        assert_eq!((completion.requests, completion.groups), (0, 0));
        assert_eq!(frozen.encoded_packet_len(), length);
        let mut second = connect().await;
        assert!(matches!(
            second
                .replay_frozen_groups_provisional_visit(frozen, 1, replay_limits(2), |_| Ok(()))
                .await
                .map_err(|error| error.source),
            Err(Error::InvalidInput(_))
        ));
        assert!(second.is_usable());
        second.close_local().await.unwrap();
        let frozen = first.compile_frozen_group(&requests, PACKET).unwrap();
        first.invalidate_statements().unwrap();
        assert!(matches!(
            first
                .replay_frozen_groups_provisional_visit(frozen, 1, replay_limits(2), |_| Ok(()))
                .await
                .map_err(|error| error.source),
            Err(Error::InvalidInput(_))
        ));
        assert!(first.is_usable());
        let closed = first
            .prepare("SELECT 7::int4", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let frozen = first
            .compile_frozen_group(
                &[PipelineRequest {
                    statement: &closed,
                    parameters: &[],
                    limits: query_limits(),
                }],
                PACKET,
            )
            .unwrap();
        first.close_prepared(&closed).await.unwrap();
        assert!(matches!(
            first
                .replay_frozen_groups_provisional_visit(frozen, 1, replay_limits(2), |_| Ok(()))
                .await
                .map_err(|error| error.source),
            Err(Error::InvalidInput(_))
        ));
        assert!(first.is_usable());
        first.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn frozen_compilation_uses_the_same_snapshot_rules_inside_and_outside_a_transaction() {
    run(async {
        let mut connection = connect().await;
        let statement = connection
            .prepare("SELECT 42::int4", &[], BINARY)
            .await
            .unwrap();
        let requests = [PipelineRequest {
            statement: &statement,
            parameters: &[],
            limits: query_limits(),
        }];
        let outside = connection.compile_frozen_group(&requests, PACKET).unwrap();
        let mut transaction = connection.begin_transaction().await.unwrap();
        {
            let mut query = transaction
                .query(
                    &statement,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            let row = query.next_row().await.unwrap().unwrap();
            assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 42);
        }
        assert_eq!(transaction.reuse_state(), ReuseState::NeedsRecovery);
        let inside = transaction.compile_frozen_group(&requests, PACKET).unwrap();
        assert_eq!(inside.encoded_packet_len(), outside.encoded_packet_len());
        assert!(matches!(
            transaction
                .replay_frozen_groups_provisional_visit(outside, 1, replay_limits(1), |_| {
                    panic!("待恢复状态不能开始重放")
                })
                .await
                .map_err(|failure| failure.source),
            Err(Error::Busy)
        ));
        transaction.recover_to_ready().await.unwrap();
        let (_, completion) = transaction
            .replay_frozen_groups_provisional_visit(inside, 1, replay_limits(1), |event| {
                if let ProvisionalGroupEvent::Row { row, .. } = event {
                    assert_eq!(row.decoder().decode_next::<i32>()?, 42);
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(completion.groups, 1);
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        transaction.rollback().await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 SCRAM 实例以及在当前 schema 中创建序列的权限"]
fn live_frozen_replay_executes_each_sql_and_does_not_retry_errors() {
    run(async {
        let options = observer_options();
        let mut observer = ObserverConnection::connect(options.clone()).await.unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = format!(
            "cpg_frozen_{:x}_{nonce:x}",
            observer.server_info().process_id
        );
        let checked = AssertUnwindSafe(compio::time::timeout(Duration::from_secs(10), async {
            observer
                .one_shot(&format!("CREATE SEQUENCE {sequence} CACHE 1"), &[], BINARY)
                .command_ready(OnError::DrainToReady)
                .await
                .unwrap();
            let mut connection = connect().await;
            let pid = connection.server_info().process_id;
            let statement = connection
                .prepare(
                    &format!("SELECT 10/(2-nextval('{sequence}')::int4)"),
                    &[],
                    BINARY,
                )
                .await
                .unwrap();
            let frozen = connection
                .compile_frozen_group(
                    &[PipelineRequest {
                        statement: &statement,
                        parameters: &[],
                        limits: query_limits(),
                    }],
                    PACKET,
                )
                .unwrap();
            let mut values = Vec::new();
            // 单组在途使第二组出错时，第三组还没有接纳机会。
            let error = connection
                .replay_frozen_groups_provisional_visit(frozen, 3, replay_limits(1), |event| {
                    if let ProvisionalGroupEvent::Row { row, .. } = event {
                        values.push(row.decoder().decode_next::<i32>()?);
                    }
                    Ok(())
                })
                .await
                .unwrap_err();
            assert!(matches!(error.source, Error::Database(ref error) if error.code() == "22012"));
            assert_eq!(
                (
                    error.progress.admitted_groups,
                    error.progress.admitted_requests,
                    error.progress.ready_groups,
                    error.progress.ready_requests,
                    error.progress.last_ready_transaction_status,
                ),
                (2, 2, 1, 1, Some(TransactionStatus::Idle))
            );
            assert_eq!(values, [10]);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            connection.close_local().await.unwrap();

            let active = observer
                .prepare(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid = $1)",
                    &[Oid::INT4],
                    PreparedStatementStorage::Named,
                    BINARY,
                )
                .await
                .unwrap();
            let params = [Parameter::int4(pid)];
            while observer
                .query(&active, &params)
                .one::<bool>(OnError::DrainToReady)
                .await
                .unwrap()
            {
                compio::time::sleep(OBSERVATION_INTERVAL).await;
            }
            // 等原后端退出后检查非事务性序列，错误和回滚不会隐藏额外执行。
            let observed = observer
                .one_shot(
                    &format!("SELECT last_value, is_called FROM {sequence}"),
                    &[],
                    BINARY,
                )
                .map_provisional_one(OnError::DrainToReady, |row| {
                    let mut fields = row.decoder();
                    let value = fields.decode_next::<i64>()?;
                    let called = fields.decode_next::<bool>()?;
                    fields.finish()?;
                    Ok((value, called))
                })
                .await
                .unwrap();
            assert_eq!(observed, (2, true));
        }))
        .catch_unwind()
        .await;

        // 创建已经提交但客户端未收到 Ready 时，序列也可能存在。
        let cleanup = compio::time::timeout(Duration::from_secs(5), async {
            if observer.reuse_state() != ReuseState::ProtocolIdle
                && observer.recover_to_ready().await.is_err()
            {
                observer.close_local().await?;
                observer = ObserverConnection::connect(options).await?;
            }
            observer
                .one_shot(
                    &format!("DROP SEQUENCE IF EXISTS {sequence} RESTRICT"),
                    &[],
                    BINARY,
                )
                .command_ready(OnError::DrainToReady)
                .await?;
            observer.terminate().await
        })
        .await;
        match &cleanup {
            Ok(Err(error)) => eprintln!("清理测试序列 {sequence} 失败，{error:?}"),
            Err(_) => eprintln!("清理测试序列 {sequence} 超时"),
            Ok(Ok(())) => {}
        }
        match checked {
            Ok(result) => result.expect("未能确认原后端退出及序列推进次数"),
            Err(panic) => resume_unwind(panic),
        }
        cleanup.unwrap().unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_abandoning_frozen_replay_after_backend_execution_discards_the_session() {
    run(async {
        const LOCK_NAMESPACE: i32 = 0x4350_4746;
        let mut observer = ObserverConnection::connect(observer_options())
            .await
            .unwrap();
        let holder_pid = observer.server_info().process_id;
        let lock_params = [Parameter::int4(LOCK_NAMESPACE), Parameter::int4(holder_pid)];
        observer
            .one_shot(
                "SELECT pg_catalog.pg_advisory_lock($1::int4, $2::int4) IS NULL",
                &lock_params,
                BINARY,
            )
            .one::<bool>(OnError::DrainToReady)
            .await
            .unwrap();

        let mut connection = connect().await;
        let replay_pid = connection.server_info().process_id;
        let statement = connection
            .prepare(
                "SELECT pg_catalog.pg_advisory_xact_lock($1, $2) IS NULL",
                &[Oid::INT4, Oid::INT4],
                BINARY,
            )
            .await
            .unwrap();
        let frozen = connection
            .compile_frozen_group(
                &[PipelineRequest {
                    statement: &statement,
                    parameters: &lock_params,
                    limits: query_limits(),
                }],
                PACKET,
            )
            .unwrap();
        let blocked = observer
            .prepare(
                "SELECT $1::int4 = ANY(pg_catalog.pg_blocking_pids($2::int4))",
                &[Oid::INT4, Oid::INT4],
                PreparedStatementStorage::Named,
                BINARY,
            )
            .await
            .unwrap();
        let pids = [Parameter::int4(holder_pid), Parameter::int4(replay_pid)];
        {
            let replay = pin!(connection.replay_frozen_groups_provisional_visit(
                frozen,
                2,
                replay_limits(2),
                |_| panic!("持锁期间不能收到冻结语句的结果"),
            ));
            let wait = pin!(async {
                while !observer
                    .query(&blocked, &pids)
                    .one::<bool>(OnError::DrainToReady)
                    .await
                    .unwrap()
                {
                    compio::time::sleep(OBSERVATION_INTERVAL).await;
                }
            });
            // 后端必须已阻塞在本夹具持有的锁上，随后才放弃仍在途的等待。
            if let Either::Left((result, _)) = select(replay, wait).await {
                panic!("确认后端锁等待前重放已结束，{result:?}");
            }
        }
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
        assert!(
            observer
                .one_shot(
                    "SELECT pg_catalog.pg_advisory_unlock($1::int4, $2::int4)",
                    &lock_params,
                    BINARY
                )
                .one::<bool>(OnError::DrainToReady)
                .await
                .unwrap()
        );
        observer.terminate().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_frozen_large_requests_and_responses_keep_duplex_progress() {
    run(async {
        let mut connection = connect().await;
        let large = connection
            .prepare(
                "SELECT repeat('x',1048576)",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let input = connection
            .prepare(
                "SELECT octet_length($1::bytea)",
                &[Oid::BYTEA],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let payload = vec![0xa5; 8 * 1024 * 1024];
        let frozen = {
            let parameters = [Parameter::bytea(&payload)];
            connection
                .compile_frozen_group(
                    &[
                        PipelineRequest {
                            statement: &large,
                            parameters: &[],
                            limits: query_limits(),
                        },
                        PipelineRequest {
                            statement: &input,
                            parameters: &parameters,
                            limits: query_limits(),
                        },
                    ],
                    PACKET,
                )
                .unwrap()
        };
        drop(payload);
        let mut rows = 0;
        let (_, completion) = connection
            .replay_frozen_groups_provisional_visit(frozen, 2, replay_limits(2), |event| {
                if let ProvisionalGroupEvent::Row { index, row } = event {
                    assert_eq!(index, rows);
                    let mut decoder = row.decoder();
                    if index % 2 == 0 {
                        let value = decoder.decode_next::<&str>()?;
                        assert_eq!(value.len(), 1048576);
                        assert!(value.bytes().all(|byte| byte == b'x'));
                    } else {
                        assert_eq!(decoder.decode_next::<i32>()?, 8 * 1024 * 1024);
                    }
                    decoder.finish()?;
                    rows += 1;
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!((completion.requests, completion.groups, rows), (4, 2, 4));
        connection.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_frozen_callback_panic_discards_the_session() {
    run(async {
        let mut connection = connect().await;
        let statement = connection
            .prepare("SELECT 42::int4", &[], ResultFormats::All(Format::Binary))
            .await
            .unwrap();
        let frozen = connection
            .compile_frozen_group(
                &[PipelineRequest {
                    statement: &statement,
                    parameters: &[],
                    limits: query_limits(),
                }],
                PACKET,
            )
            .unwrap();
        let panicked = AssertUnwindSafe(connection.replay_frozen_groups_provisional_visit(
            frozen,
            2,
            replay_limits(2),
            |event| {
                if let ProvisionalGroupEvent::Row { .. } = event {
                    panic!("injected frozen callback failure");
                }
                Ok(())
            },
        ))
        .catch_unwind()
        .await;
        assert!(panicked.is_err());
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        connection.close_local().await.unwrap();
    });
}
