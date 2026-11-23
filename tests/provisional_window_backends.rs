//! 在真实传输后端验证独立 Sync 和借用行的生命周期。

#[path = "support/live.rs"]
mod live;

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use std::{cell::Cell, future::Future, time::Duration};

use compio_postgres::{
    AbandonPolicy, BatchControl, BatchEvent, ExecutionScheduling, QueryLimits, ResultFormats,
    ReuseState, StatementLimits, TcpConfig, TransactionStatus, WireLimits, WireTransport,
    expert::{
        ProvisionalWindowConsumeEvent, ProvisionalWindowLimits, Session, WindowParameters,
        WindowRequest,
    },
    types::{Format, Oid, Parameter},
};

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("provisional backend deadline")
    });
}

fn connection_limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 64 * 1024,
        max_messages_per_request: 128,
    }
}

fn row_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 8,
        max_result_bytes: 4096,
        max_metadata_bytes: 4096,
    }
}

fn window_limits(
    abandon: AbandonPolicy,
    scheduling: ExecutionScheduling,
) -> ProvisionalWindowLimits {
    ProvisionalWindowLimits {
        max_inflight: 3,
        max_requests: 3,
        max_rows: 16,
        max_row_bytes: 4096,
        max_queued_request_bytes: 4096,
        max_diagnostic_bytes: 4096,
        scheduling,
        abandon,
    }
}

fn config() -> TcpConfig {
    live::tcp_config(connection_limits(), tcp_options::TCP_OPTIONS)
}

async fn exercise<T: WireTransport>(connection: &mut Session<T>) {
    connection
        .configure_statements(StatementLimits {
            max_statements: 8,
            max_metadata_bytes: 32 * 1024,
        })
        .unwrap();
    let row_statement = connection
        .prepare(
            "SELECT $1::int4,NULL::text",
            &[Oid::INT4],
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap();
    let error_statement = connection
        .prepare(
            "SELECT 1/($1::int4)",
            &[Oid::INT4],
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap();
    for abandon in [
        AbandonPolicy::DiscardOnAbandon,
        AbandonPolicy::RecoverExplicitly,
    ] {
        for scheduling in [
            ExecutionScheduling::Uninterrupted,
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::MIN,
            },
        ] {
            let selected = window_limits(abandon, scheduling);
            let mut source = (11..14).map(|value| {
                Ok(WindowRequest {
                    statement: &row_statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: row_limits(),
                })
            });
            let events = Cell::new(0);
            let completed = connection
                .query_window_provisional_visit(&mut source, selected, &mut |event| {
                    let step = events.get();
                    let expected = step / 3;
                    let phase = step % 3;
                    match event {
                        BatchEvent::Row { index, row } => {
                            assert_eq!((index, phase), (expected, 0));
                            let mut decoder = row.decoder();
                            assert_eq!(
                                decoder.decode_next::<i32>()?,
                                i32::try_from(index).unwrap() + 11
                            );
                            assert_eq!(decoder.decode_next::<Option<&str>>()?, None);
                            decoder.finish()?;
                        }
                        BatchEvent::Command {
                            index,
                            rows_returned,
                            ..
                        } => {
                            assert_eq!((index, phase, rows_returned), (expected, 1, 1));
                        }
                        BatchEvent::Ready {
                            index,
                            outcome,
                            transaction_status,
                        } => {
                            assert_eq!((index, phase), (expected, 2));
                            assert_eq!(transaction_status, TransactionStatus::Idle);
                            assert!(outcome.is_ok());
                        }
                    }
                    events.set(step + 1);
                    Ok(BatchControl::Continue)
                })
                .await
                .unwrap();
            assert_eq!(
                (
                    completed.admitted,
                    completed.confirmed,
                    completed.rows_delivered,
                    events.get()
                ),
                (3, 3, 3, 9)
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

            let mut transaction = connection.begin_transaction().await.unwrap();
            let mut source = (11..14).map(|value| {
                Ok(WindowRequest {
                    statement: &row_statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: row_limits(),
                })
            });
            let events = Cell::new(0);
            let completed = transaction
                .query_window_provisional_consume(&mut source, selected, &mut |event| {
                    let step = events.get();
                    let expected = step / 3;
                    let phase = step % 3;
                    match event {
                        ProvisionalWindowConsumeEvent::Row { index, row } => {
                            assert_eq!((index, phase), (expected, 0));
                            assert_eq!(
                                row.decode_next::<i32>()?,
                                i32::try_from(index).unwrap() + 11
                            );
                            assert_eq!(row.remaining(), 1); // 驱动仍须校验未读取的 NULL 字段。
                        }
                        ProvisionalWindowConsumeEvent::Command {
                            index,
                            rows_returned,
                            ..
                        } => {
                            assert_eq!((index, phase, rows_returned), (expected, 1, 1));
                        }
                        ProvisionalWindowConsumeEvent::Ready {
                            index,
                            transaction_status,
                            outcome,
                        } => {
                            assert_eq!((index, phase), (expected, 2));
                            assert_eq!(transaction_status, TransactionStatus::InTransaction);
                            assert!(outcome.is_ok());
                        }
                    }
                    events.set(step + 1);
                    Ok(BatchControl::Continue)
                })
                .await
                .unwrap();
            assert_eq!(
                (completed.confirmed, completed.rows_delivered, events.get()),
                (3, 3, 9)
            );
            assert_eq!(
                completed.transaction_status,
                TransactionStatus::InTransaction
            );
            transaction.rollback().await.unwrap();
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);

            let mut source = [1, 0, 1].into_iter().map(|value| {
                Ok(WindowRequest {
                    statement: &error_statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: row_limits(),
                })
            });
            let mut codes = Vec::new();
            let completed = connection
                .query_window_provisional_consume(&mut source, selected, &mut |event| {
                    if let ProvisionalWindowConsumeEvent::Ready {
                        index,
                        outcome,
                        transaction_status,
                    } = event
                    {
                        assert_eq!(transaction_status, TransactionStatus::Idle);
                        codes.push((index, outcome.err().map(|error| error.code().to_owned())));
                    }
                    Ok(BatchControl::Continue)
                })
                .await
                .unwrap();
            assert_eq!(
                (
                    completed.admitted,
                    completed.confirmed,
                    completed.sql_errors
                ),
                (3, 3, 1)
            );
            assert_eq!(codes, [(0, None), (1, Some("22012".to_owned())), (2, None)]);

            let mut transaction = connection.begin_transaction().await.unwrap();
            let mut source = [0, 1, 1].into_iter().map(|value| {
                Ok(WindowRequest {
                    statement: &error_statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: row_limits(),
                })
            });
            let mut codes = Vec::new();
            let completed = transaction
                .query_window_provisional_visit(&mut source, selected, &mut |event| {
                    if let BatchEvent::Ready {
                        index,
                        outcome,
                        transaction_status,
                    } = event
                    {
                        assert_eq!(transaction_status, TransactionStatus::FailedTransaction);
                        codes.push((index, outcome.err().map(|error| error.code().to_owned())));
                    }
                    Ok(BatchControl::Continue)
                })
                .await
                .unwrap();
            assert_eq!(
                (
                    completed.admitted,
                    completed.confirmed,
                    completed.sql_errors
                ),
                (3, 3, 3)
            );
            assert!(completed.needs_transaction_decision);
            assert_eq!(
                codes,
                [
                    (0, Some("22012".to_owned())),
                    (1, Some("25P02".to_owned())),
                    (2, Some("25P02".to_owned()))
                ]
            );
            transaction.rollback().await.unwrap();
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    }
    connection.close_prepared(&row_statement).await.unwrap();
    connection.close_prepared(&error_statement).await.unwrap();

    connection
        .query_simple_single(
            "CREATE TEMP TABLE borrowed_window_events(v int4) ON COMMIT PRESERVE ROWS",
            compio_postgres::QueryOptions {
                limits: QueryLimits {
                    max_rows: 0,
                    max_result_bytes: 0,
                    max_metadata_bytes: 4096,
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    let insert = connection
        .prepare(
            "INSERT INTO pg_temp.borrowed_window_events VALUES($1::int4) RETURNING v",
            &[Oid::INT4],
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap();
    let examined = Cell::new(0);
    let callbacks = Cell::new(0);
    let mut source = (7..100).map(|value| {
        examined.set(examined.get() + 1);
        Ok(WindowRequest {
            statement: &insert,
            parameters: WindowParameters::One(Parameter::int4(value)),
            limits: row_limits(),
        })
    });
    let completed = connection
        .query_window_provisional_consume(
            &mut source,
            ProvisionalWindowLimits {
                max_requests: 100,
                max_inflight: 2,
                ..window_limits(
                    AbandonPolicy::RecoverExplicitly,
                    ExecutionScheduling::Uninterrupted,
                )
            },
            &mut |event| {
                assert!(matches!(
                    event,
                    ProvisionalWindowConsumeEvent::Row { index: 0, .. }
                ));
                callbacks.set(callbacks.get() + 1);
                Ok(BatchControl::Abort)
            },
        )
        .await
        .unwrap();
    assert!(completed.aborted);
    assert_eq!(
        (
            completed.admitted,
            completed.confirmed,
            examined.get(),
            callbacks.get()
        ),
        (2, 0, 2, 1)
    );
    assert_eq!(connection.reuse_state(), ReuseState::NeedsRecovery);
    connection.recover_to_ready().await.unwrap();
    assert_eq!((examined.get(), callbacks.get()), (2, 1));
    let mut verify = connection
        .one_shot(
            "SELECT count(*)::int8,sum(v)::int8 FROM pg_temp.borrowed_window_events",
            &[],
            ResultFormats::All(Format::Binary),
            compio_postgres::QueryOptions {
                limits: row_limits(),
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await
        .unwrap();
    let row = verify.next_row().await.unwrap().unwrap();
    let mut decoder = row.view().decoder();
    assert_eq!(decoder.decode_next::<i64>().unwrap(), 2);
    assert_eq!(decoder.decode_next::<Option<i64>>().unwrap(), Some(15));
    decoder.finish().unwrap();
    verify.finish().await.unwrap();
    connection.close_prepared(&insert).await.unwrap();
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_native_independent_sync_borrowed_windows() {
    run(async {
        let mut connection = compio_postgres::expert::TcpSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await;
        connection.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_readiness_independent_sync_borrowed_windows() {
    run(async {
        let mut connection = compio_postgres::expert::linux::TcpReadinessSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await;
        connection.close_local().await.unwrap();
    });
}

#[cfg(unix)]
fn unix_config() -> compio_postgres::UnixConfig {
    live::unix_config(
        connection_limits(),
        compio_postgres::SendPolicy::BeforeBufferedRead,
    )
}

#[cfg(unix)]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_independent_sync_borrowed_windows() {
    run(async {
        let mut connection = compio_postgres::expert::UnixSession::connect(unix_config())
            .await
            .unwrap();
        exercise(&mut connection).await;
        connection.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 PostgreSQL 19 的 Unix 套接字和 CPG_* 连接配置"]
fn live_unix_readiness_independent_sync_borrowed_windows() {
    run(async {
        let mut connection =
            compio_postgres::expert::linux::UnixReadinessSession::connect(unix_config())
                .await
                .unwrap();
        exercise(&mut connection).await;
        connection.close_local().await.unwrap();
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 TLS 和 SCRAM-PLUS 的 PostgreSQL 19，以及 CPG_TLS_* 证书配置"]
fn live_tls_independent_sync_borrowed_windows() {
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
        exercise(&mut connection).await;
        connection.close_local().await.unwrap();
    });
}
