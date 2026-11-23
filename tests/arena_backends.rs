//! 在 PostgreSQL 19 上验证各传输的结果缓冲复用和语句关闭。

#[path = "support/live.rs"]
mod live;

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    AllocationPolicy, Error, OwnedBatch, QueryLimits, ReadyBatchEvent, ResultFormats, ReuseState,
    StatementLimits, StatementPipelineLimits, TcpConfig, TransactionStatus, WireLimits,
    WireTransport,
    expert::{
        PipelineItem, PipelineLimits, PipelineRequest, PreparedStatement, Session, VisitLimits,
        WindowLimits, WindowParameters, WindowRequest,
    },
    types::Format,
};
use std::{future::Future, ops::ControlFlow, time::Duration};

const MEMBER_BYTES: [usize; 4] = [64, 128, 8, 64];
const USED_BYTES: [usize; 4] = [12, 10, 8, 24];

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

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("arena backend matrix deadline")
    });
}

fn requests(statements: &[PreparedStatement; 4]) -> [PipelineRequest<'_>; 4] {
    std::array::from_fn(|index| PipelineRequest {
        statement: &statements[index],
        parameters: &[],
        limits: QueryLimits {
            max_rows: if index == 0 || index == 2 { 1 } else { 2 },
            max_result_bytes: MEMBER_BYTES[index],
            max_metadata_bytes: 8192,
        },
    })
}

fn verify(
    index: usize,
    batch: &OwnedBatch,
    statements: &[PreparedStatement; 4],
    storage: AllocationPolicy,
) -> *const u8 {
    assert!(std::ptr::eq(batch.layout(), statements[index].layout()));
    assert_eq!(batch.len(), if index == 3 { 2 } else { 1 });
    assert_eq!(batch.used_bytes(), USED_BYTES[index]);
    match storage {
        AllocationPolicy::ReserveLimit => assert_eq!(batch.retained_bytes(), MEMBER_BYTES[index]),
        AllocationPolicy::Grow => {
            assert!((USED_BYTES[index]..=MEMBER_BYTES[index]).contains(&batch.retained_bytes()))
        }
    }
    let mut pointer = None;
    for (offset, row) in batch.rows().enumerate() {
        let row = row.unwrap();
        if offset == 0 {
            let field = row.fields().next().unwrap().unwrap();
            let expected = if index == 1 || index == 2 {
                Format::Text
            } else {
                Format::Binary
            };
            assert_eq!(field.format, expected);
            pointer = Some(field.bytes.unwrap().as_ptr());
        }
        let mut decoder = row.decoder();
        if index == 1 || index == 2 {
            assert_eq!(
                decoder.decode_next::<&str>().unwrap(),
                if index == 1 { "ok" } else { "" }
            );
        } else {
            assert_eq!(
                decoder.decode_next::<i32>().unwrap(),
                if index == 0 {
                    7
                } else {
                    9 + i32::try_from(offset).unwrap()
                }
            );
        }
        decoder.finish().unwrap();
    }
    pointer.unwrap()
}

fn close_limits() -> StatementPipelineLimits {
    StatementPipelineLimits {
        max_statements: 4,
        max_packet_bytes: 65536,
        max_result_bytes: 4096,
        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::MIN,
        },
    }
}

async fn exercise<T: WireTransport>(connection: &mut Session<T>) -> Result<(), Error> {
    connection.configure_statements(StatementLimits {
        max_statements: 4,
        max_metadata_bytes: 32768,
    })?;
    let statements = [
        connection
            .prepare(
                "SELECT 7::int4 AS n",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await?,
        connection
            .prepare(
                "SELECT 'ok'::text AS t",
                &[],
                ResultFormats::All(Format::Text),
            )
            .await?,
        connection
            .prepare(
                "SELECT ''::text AS t",
                &[],
                ResultFormats::All(Format::Text),
            )
            .await?,
        connection
            .prepare(
                "SELECT g::int4 AS n FROM generate_series(9,10) g ORDER BY g",
                &[],
                ResultFormats::All(Format::Binary),
            )
            .await?,
    ];
    {
        let requests = requests(&statements);
        for storage in [AllocationPolicy::ReserveLimit, AllocationPolicy::Grow] {
            for in_transaction in [false, true] {
                let expected_status = if in_transaction {
                    TransactionStatus::InTransaction
                } else {
                    TransactionStatus::Idle
                };
                let selected = PipelineLimits {
                    max_requests: 4,
                    max_rows: 5,
                    max_result_bytes: 4 * std::mem::size_of::<PipelineItem>()
                        + MEMBER_BYTES.iter().sum::<usize>(),
                    storage,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                };
                let results = if in_transaction {
                    let mut transaction = connection.begin_transaction().await?;
                    let results = transaction
                        .query_pipeline(&requests, selected)
                        .await
                        .map_err(|error| error.source)?;
                    assert_eq!(
                        transaction.transaction_status(),
                        TransactionStatus::InTransaction
                    );
                    transaction.rollback().await?;
                    results
                } else {
                    connection
                        .query_pipeline(&requests, selected)
                        .await
                        .map_err(|error| error.source)?
                };
                assert_eq!(results.len(), 4);
                let mut retained = results.capacity() * std::mem::size_of::<PipelineItem>();
                for (index, result) in results.iter().enumerate() {
                    let result = result.as_ref().unwrap();
                    verify(index, &result.rows, &statements, storage);
                    retained += result.rows.retained_bytes();
                    assert_eq!(result.completion.transaction_status, expected_status);
                    assert!(result.completion.succeeded);
                }
                assert!(retained <= selected.max_result_bytes);
                drop(results);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

                let selected = VisitLimits {
                    max_requests: 4,
                    max_rows: 5,
                    max_result_bytes: 128,
                    storage,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                };
                let mut seen = 0;
                let mut first_pointer = None;
                let mut callback = |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, seen);
                    assert_eq!(event.transaction_status, expected_status);
                    let result = event.outcome.unwrap();
                    assert_eq!(result.completion.transaction_status, expected_status);
                    let pointer = verify(event.index, result.rows, &statements, storage);
                    if seen == 0 {
                        first_pointer = Some(pointer);
                    }
                    if seen == 1 && storage == AllocationPolicy::Grow {
                        assert_eq!(first_pointer, Some(pointer));
                    }
                    seen += 1;
                    Ok(())
                };
                let completion = if in_transaction {
                    let mut transaction = connection.begin_transaction().await?;
                    let completion = transaction
                        .query_pipeline_visit(&requests, selected, &mut callback)
                        .await
                        .map_err(|error| error.source)?;
                    transaction.rollback().await?;
                    completion
                } else {
                    connection
                        .query_pipeline_visit(&requests, selected, &mut callback)
                        .await
                        .map_err(|error| error.source)?
                };
                assert_eq!(
                    (
                        seen,
                        completion.admitted,
                        completion.confirmed,
                        completion.delivered,
                        completion.sql_errors
                    ),
                    (4, 4, 4, 4, 0)
                );
                assert_eq!(completion.transaction_status, expected_status);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

                let selected = WindowLimits {
                    max_inflight: 2,
                    max_requests: 4,
                    max_rows: 5,
                    max_result_bytes: 128,
                    max_queued_request_bytes: 65536,
                    scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                        max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
                    },
                    storage,
                };
                let mut source = requests.iter().map(|request| {
                    Ok(WindowRequest {
                        statement: request.statement,
                        parameters: WindowParameters::Borrowed(&[]),
                        limits: request.limits,
                    })
                });
                let mut seen = 0;
                let mut first_pointer = None;
                let mut callback = |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, seen);
                    assert_eq!(event.transaction_status, expected_status);
                    let result = event.outcome.unwrap();
                    assert_eq!(result.completion.transaction_status, expected_status);
                    let pointer = verify(event.index, result.rows, &statements, storage);
                    if seen == 0 {
                        first_pointer = Some(pointer);
                    }
                    if seen == 1 && storage == AllocationPolicy::Grow {
                        assert_eq!(first_pointer, Some(pointer));
                    }
                    seen += 1;
                    Ok(ControlFlow::Continue(()))
                };
                let completion = if in_transaction {
                    let mut transaction = connection.begin_transaction().await?;
                    let completion = transaction
                        .query_window(
                            &mut source,
                            selected,
                            compio_postgres::OnError::RecoverExplicitly,
                            &mut callback,
                        )
                        .await
                        .map_err(|error| error.source)?;
                    transaction.rollback().await?;
                    completion
                } else {
                    connection
                        .query_window(
                            &mut source,
                            selected,
                            compio_postgres::OnError::RecoverExplicitly,
                            &mut callback,
                        )
                        .await
                        .map_err(|error| error.source)?
                };
                assert_eq!(
                    (
                        seen,
                        completion.admitted,
                        completion.confirmed,
                        completion.delivered,
                        completion.sql_errors
                    ),
                    (4, 4, 4, 4, 0)
                );
                assert_eq!(completion.transaction_status, expected_status);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    }
    let closed = connection
        .close_prepared_pipeline(&[&statements[0], &statements[2]], close_limits())
        .await
        .map_err(|error| error.source)?;
    assert_eq!(closed.len(), 2);
    assert!(closed.iter().all(Result::is_ok));
    let closed = connection
        .close_all_statements_pipeline(close_limits())
        .await
        .map_err(|error| error.source)?;
    assert_eq!(closed.len(), 2);
    assert!(closed.iter().all(Result::is_ok));
    drop(statements);
    assert_eq!(connection.reclaim_closed_statements()?, 4);

    let mut transaction = connection.begin_transaction().await?;
    let statements = [
        transaction
            .prepare("SELECT 1::int4", &[], ResultFormats::All(Format::Binary))
            .await?,
        transaction
            .prepare("SELECT 2::int4", &[], ResultFormats::All(Format::Binary))
            .await?,
        transaction
            .prepare("SELECT 3::int4", &[], ResultFormats::All(Format::Binary))
            .await?,
        transaction
            .prepare("SELECT 4::int4", &[], ResultFormats::All(Format::Binary))
            .await?,
    ];
    let closed = transaction
        .close_prepared_pipeline(&[&statements[0], &statements[2]], close_limits())
        .await
        .map_err(|error| error.source)?;
    assert_eq!(closed.len(), 2);
    assert!(closed.iter().all(Result::is_ok));
    let closed = transaction
        .close_all_statements_pipeline(close_limits())
        .await
        .map_err(|error| error.source)?;
    assert_eq!(closed.len(), 2);
    assert!(closed.iter().all(Result::is_ok));
    assert_eq!(
        transaction.transaction_status(),
        TransactionStatus::InTransaction
    );
    transaction.rollback().await?;
    drop(statements);
    assert_eq!(connection.reclaim_closed_statements()?, 4);
    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    Ok(())
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_native_owned_arenas_and_close_matrix() {
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
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_readiness_owned_arenas_and_close_matrix() {
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
fn live_unix_owned_arenas_and_close_matrix() {
    run(async {
        let config = live::unix_config(limits(), compio_postgres::SendPolicy::BeforeBufferedRead);
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
fn live_unix_readiness_owned_arenas_and_close_matrix() {
    run(async {
        let config = live::unix_config(limits(), compio_postgres::SendPolicy::BeforeBufferedRead);
        let mut connection = compio_postgres::expert::linux::UnixReadinessSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 SCRAM-PLUS 的 PostgreSQL 19 TLS 实例及 CPG_TLS_* 证书配置"]
fn live_tls_owned_arenas_and_close_matrix() {
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
