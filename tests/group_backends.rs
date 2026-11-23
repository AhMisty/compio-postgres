//! 验证共用一个 Sync 的借用行回调在 TCP、Unix 套接字与 TLS 传输上遵循相同约定。

#[path = "support/live.rs"]
mod live;

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    Error, ExecutionScheduling, QueryLimits, ResultFormats, ReuseState, StatementLimits, TcpConfig,
    TransactionStatus, WireLimits, WireTransport,
    expert::{
        GroupPipelineLimits, PipelineRequest, ProvisionalGroupConsumeEvent, ProvisionalGroupEvent,
        ProvisionalGroupLimits, Session,
    },
    types::{Format, Oid, Parameter},
};
use std::{future::Future, time::Duration};

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 65536,
        max_messages_per_request: 128,
    }
}

fn config() -> TcpConfig {
    live::tcp_config(limits(), tcp_options::TCP_OPTIONS)
}

fn checked(event: ProvisionalGroupEvent<'_>) -> Result<(), Error> {
    if let ProvisionalGroupEvent::Row { index, row } = event {
        let mut decoder = row.decoder();
        assert_eq!(decoder.decode_next::<i32>()?, [11, 12][index % 2]);
        assert_eq!(decoder.decode_next::<Option<&str>>()?, None);
        decoder.finish()?;
    }
    Ok(())
}

fn consuming(event: ProvisionalGroupConsumeEvent<'_, '_, '_>) -> Result<(), Error> {
    if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
        assert_eq!(row.decode_next::<i32>()?, [11, 12][index % 2]);
        assert_eq!(row.remaining(), 1);
    }
    Ok(())
}

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("group backend deadline")
    });
}

async fn exercise<T: WireTransport>(
    connection: &mut Session<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    connection.configure_statements(StatementLimits {
        max_statements: 2,
        max_metadata_bytes: 16384,
    })?;
    let statement = connection
        .prepare(
            "SELECT $1::int4,NULL::text",
            &[Oid::INT4],
            ResultFormats::All(Format::Binary),
        )
        .await?;
    let first = [Parameter::int4(11)];
    let second = [Parameter::int4(12)];
    let query_limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 32,
        max_metadata_bytes: 16384,
    };
    let requests = [
        PipelineRequest {
            statement: &statement,
            parameters: &first,
            limits: query_limits,
        },
        PipelineRequest {
            statement: &statement,
            parameters: &second,
            limits: query_limits,
        },
    ];
    for scheduling in [
        ExecutionScheduling::Uninterrupted,
        ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::MIN,
        },
    ] {
        let limits = ProvisionalGroupLimits {
            max_requests: 2,
            max_rows: 2,
            max_member_result_bytes: 4096,
            scheduling,
        };
        let mut seen = 0;
        let result = connection
            .query_group_provisional_visit(&requests, limits, |event| {
                if let ProvisionalGroupEvent::Row { index, row } = event {
                    let mut decoder = row.decoder();
                    assert_eq!(decoder.decode_next::<i32>()?, [11, 12][index]);
                    assert_eq!(decoder.decode_next::<Option<&str>>()?, None);
                    decoder.finish()?;
                    seen += 1;
                }
                Ok(())
            })
            .await?;
        assert_eq!((result.requests, result.rows_returned, seen), (2, 2, 2));
        assert_eq!(result.transaction_status, TransactionStatus::Idle);
        for inflight in [1, 2] {
            let mut source = [&requests[..1], &requests[1..]].into_iter();
            let result = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_requests: 2,
                        max_groups: 2,
                        max_rows: 2,
                        max_member_result_bytes: 4096,
                        max_packet_bytes: 65536,
                        max_inflight_groups: inflight,
                        scheduling,
                    },
                    checked,
                )
                .await?;
            assert_eq!(
                (result.requests, result.groups, result.rows_returned),
                (2, 2, 2)
            );
            assert_eq!(result.transaction_status, TransactionStatus::Idle);
        }
        let mut consumed = 0;
        connection
            .query_group_provisional_consume(&requests, limits, |event| {
                if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                    assert_eq!(row.decode_next::<i32>()?, [11, 12][index]);
                    consumed += 1;
                }
                Ok(())
            })
            .await?;
        assert_eq!(consumed, 2);
        let mut source = std::iter::repeat_n(requests.as_slice(), 2);
        let mut consumed = 0;
        connection
            .query_groups_provisional_consume(
                &mut source,
                GroupPipelineLimits {
                    max_requests: 4,
                    max_groups: 2,
                    max_rows: 4,
                    max_member_result_bytes: 4096,
                    max_packet_bytes: 65536,
                    max_inflight_groups: 2,
                    scheduling,
                },
                |event| {
                    if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                        assert_eq!(row.decode_next::<i32>()?, [11, 12][index % 2]);
                        consumed += 1;
                    }
                    Ok(())
                },
            )
            .await?;
        assert_eq!(consumed, 4);
        let replay_limits = GroupPipelineLimits {
            max_requests: 4,
            max_groups: 2,
            max_rows: 4,
            max_member_result_bytes: 4096,
            max_packet_bytes: 65536,
            max_inflight_groups: 2,
            scheduling,
        };
        let frozen = connection.compile_frozen_group(&requests, 65536)?;
        let (frozen, completion) = connection
            .replay_frozen_group_provisional_visit(frozen, limits, checked)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (2, 1, 2)
        );
        let (frozen, completion) = connection
            .replay_frozen_group_provisional_consume(frozen, limits, consuming)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (2, 1, 2)
        );
        let (frozen, completion) = connection
            .replay_frozen_groups_provisional_visit(frozen, 2, replay_limits, checked)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (4, 2, 4)
        );
        let (_, completion) = connection
            .replay_frozen_groups_provisional_consume(frozen, 2, replay_limits, consuming)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (4, 2, 4)
        );
        let mut transaction = connection.begin_transaction().await?;
        let result = transaction
            .query_group_provisional_visit(&requests, limits, checked)
            .await?;
        assert_eq!((result.requests, result.rows_returned), (2, 2));
        assert_eq!(result.transaction_status, TransactionStatus::InTransaction);
        let mut source = [&requests[..1], &requests[1..]].into_iter();
        let result = transaction
            .query_groups_provisional_visit(
                &mut source,
                GroupPipelineLimits {
                    max_requests: 2,
                    max_groups: 2,
                    max_rows: 2,
                    max_member_result_bytes: 4096,
                    max_packet_bytes: 65536,
                    max_inflight_groups: 2,
                    scheduling,
                },
                checked,
            )
            .await?;
        assert_eq!(
            (result.requests, result.groups, result.rows_returned),
            (2, 2, 2)
        );
        assert_eq!(result.transaction_status, TransactionStatus::InTransaction);
        let result = transaction
            .query_group_provisional_consume(&requests, limits, consuming)
            .await?;
        assert_eq!(
            (result.requests, result.groups, result.rows_returned),
            (2, 1, 2)
        );
        assert_eq!(result.transaction_status, TransactionStatus::InTransaction);
        let result = transaction
            .query_groups_provisional_consume(
                &mut std::iter::repeat_n(requests.as_slice(), 2),
                replay_limits,
                consuming,
            )
            .await?;
        assert_eq!(
            (result.requests, result.groups, result.rows_returned),
            (4, 2, 4)
        );
        assert_eq!(result.transaction_status, TransactionStatus::InTransaction);
        let frozen = transaction.compile_frozen_group(&requests, 65536)?;
        let (frozen, completion) = transaction
            .replay_frozen_group_provisional_visit(frozen, limits, checked)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (2, 1, 2)
        );
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        let (frozen, completion) = transaction
            .replay_frozen_group_provisional_consume(frozen, limits, consuming)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (2, 1, 2)
        );
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        let (frozen, completion) = transaction
            .replay_frozen_groups_provisional_visit(frozen, 2, replay_limits, checked)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (4, 2, 4)
        );
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        let (_, completion) = transaction
            .replay_frozen_groups_provisional_consume(frozen, 2, replay_limits, consuming)
            .await?;
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (4, 2, 4)
        );
        assert_eq!(
            completion.transaction_status,
            TransactionStatus::InTransaction
        );
        transaction.rollback().await?;
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    }
    Ok(())
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_native_group_and_transaction_keep_borrowed_frames_valid() {
    run(async {
        let config = config();
        let mut connection = compio_postgres::expert::TcpSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
#[ignore = "需要通过 CPG_UNIX_PATH、CPG_USER、CPG_DATABASE 和 CPG_PASSWORD 配置 PostgreSQL 19 Unix socket"]
fn live_unix_group_and_transaction_keep_borrowed_frames_valid() {
    run(async {
        let config = live::unix_config(limits(), compio_postgres::SendPolicy::BeforeBufferedRead);
        let mut session = compio_postgres::expert::UnixSession::connect(config)
            .await
            .unwrap();
        exercise(&mut session).await.unwrap();
        session.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要通过 CPG_UNIX_PATH、CPG_USER、CPG_DATABASE 和 CPG_PASSWORD 配置 PostgreSQL 19 Unix socket"]
fn live_unix_readiness_group_and_transaction_keep_borrowed_frames_valid() {
    run(async {
        let config = live::unix_config(limits(), compio_postgres::SendPolicy::BeforeBufferedRead);
        let mut session = compio_postgres::expert::linux::UnixReadinessSession::connect(config)
            .await
            .unwrap();
        exercise(&mut session).await.unwrap();
        session.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_readiness_group_and_transaction_keep_borrowed_frames_valid() {
    run(async {
        let config = config();
        let mut connection = compio_postgres::expert::linux::TcpReadinessSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 SCRAM-PLUS 的 PostgreSQL 19 TLS 实例及 CPG_TLS_* 证书配置"]
fn live_tls_group_and_transaction_keep_borrowed_frames_valid() {
    use compio_postgres::{TlsNegotiation, TlsVersions};
    run(async {
        let config = live::tls_config(
            limits(),
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
