//! 未命名语句被替换时，旧句柄必须失效，防止以旧布局执行不同的 SQL。

#[path = "support/live.rs"]
mod live;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    Error, ExecutionScheduling, PreparedStatementStorage, QueryLimits, ResultFormats,
    StatementLimits, WireLimits,
    expert::{
        CopyProtocol, PipelineRequest, PreparedStatement, ProvisionalGroupEvent,
        ProvisionalGroupLimits, TcpSession as TcpConnection,
    },
    types::{Format, Oid, Parameter},
};
use std::{future::Future, time::Duration};

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(20), future)
            .await
            .expect("unnamed statement deadline")
    });
}

async fn connect() -> TcpConnection {
    let mut session = TcpConnection::connect(live::tcp_config(
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 65536,
            max_messages_per_request: 128,
        },
        tcp_options::TCP_OPTIONS,
    ))
    .await
    .unwrap();
    session
        .configure_statements(StatementLimits {
            max_statements: 16,
            max_metadata_bytes: 65536,
        })
        .unwrap();
    session
}

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 8,
        max_result_bytes: 1024,
        max_metadata_bytes: 8192,
    }
}

async fn unnamed(session: &mut TcpConnection, sql: &str) -> PreparedStatement {
    session
        .prepare_replace_unnamed(sql, &[Oid::INT4], ResultFormats::All(Format::Binary))
        .await
        .unwrap()
}

async fn value(session: &mut TcpConnection, statement: &PreparedStatement) -> i32 {
    let parameters = [Parameter::int4(7)];
    let mut query = session
        .query(
            statement,
            &parameters,
            compio_postgres::QueryOptions {
                limits: query_limits(),
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await
        .unwrap();
    let value = {
        let row = query.next_row().await.unwrap().unwrap();
        row.view().decoder().decode_next::<i32>().unwrap()
    };
    assert_eq!(query.finish().await.unwrap().rows_returned, 1);
    value
}

fn group_limits() -> ProvisionalGroupLimits {
    ProvisionalGroupLimits {
        max_requests: 1,
        max_rows: 1,
        max_member_result_bytes: 1024,
        scheduling: ExecutionScheduling::Uninterrupted,
    }
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_unnamed_replacement_rejects_stale_queries_and_frozen_packets() {
    run(async {
        let mut session = connect().await;
        let named = session
            .prepare(
                "SELECT $1::int4 + 10",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let first = unnamed(&mut session, "SELECT $1::int4 + 20").await;
        assert_eq!(
            first.storage(),
            PreparedStatementStorage::ReplaceableUnnamed
        );
        assert_eq!(named.storage(), PreparedStatementStorage::Named);
        assert_eq!(value(&mut session, &first).await, 27);
        assert_eq!(value(&mut session, &first).await, 27);
        let parameters = [Parameter::int4(7)];
        let token = session
            .compile_frozen_group(
                &[PipelineRequest {
                    statement: &first,
                    parameters: &parameters,
                    limits: query_limits(),
                }],
                65536,
            )
            .unwrap();
        let second = unnamed(&mut session, "SELECT $1::int4 + 30").await;
        assert!(matches!(
            session
                .query(
                    &first,
                    &parameters,
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        let error = session
            .replay_frozen_group_provisional_visit(token, group_limits(), |_| {
                panic!("stale packet must not emit rows")
            })
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::InvalidInput(_)));
        assert_eq!(error.progress, Default::default());
        assert_eq!(value(&mut session, &named).await, 17);
        assert_eq!(value(&mut session, &second).await, 37);
        let mut rows = 0;
        session
            .query_group_provisional_visit(
                &[PipelineRequest {
                    statement: &second,
                    parameters: &parameters,
                    limits: query_limits(),
                }],
                group_limits(),
                |event| {
                    if let ProvisionalGroupEvent::Row { row, .. } = event {
                        assert_eq!(row.decoder().decode_next::<i32>()?, 37);
                        rows += 1;
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(rows, 1);
        session.close_prepared(&second).await.unwrap();
        assert!(matches!(
            session
                .query(
                    &second,
                    &parameters,
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        session.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_named_deallocate_all_keeps_the_independent_unnamed_statement() {
    run(async {
        let mut session = connect().await;
        let deallocate = session
            .prepare("DEALLOCATE ALL", &[], ResultFormats::All(Format::Text))
            .await
            .unwrap();
        let current = unnamed(&mut session, "SELECT $1::int4").await;
        session
            .query(
                &deallocate,
                &[],
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert_eq!(value(&mut session, &current).await, 7);
        assert!(matches!(
            session
                .query(
                    &deallocate,
                    &[],
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        session.close_local().await.unwrap();
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_unnamed_is_invalidated_by_failed_simple_and_unnamed_parse() {
    run(async {
        for one_shot in [false, true] {
            let mut session = connect().await;
            let statement = unnamed(&mut session, "SELECT $1::int4").await;
            let mut query = if one_shot {
                session
                    .one_shot(
                        "SELECT (",
                        &[],
                        ResultFormats::All(Format::Binary),
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
            } else {
                session
                    .query_simple_single(
                        "SELECT (",
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: ExecutionScheduling::Uninterrupted,
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly,
                    )
                    .await
            }
            .unwrap();
            assert!(matches!(query.finish().await, Err(Error::Database(_))));
            drop(query);
            let parameters = [Parameter::int4(7)];
            assert!(matches!(
                session
                    .query(
                        &statement,
                        &parameters,
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: ExecutionScheduling::Uninterrupted
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly
                    )
                    .await,
                Err(Error::InvalidInput(_))
            ));
            session.close_local().await.unwrap();
        }
    });
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_unnamed_transaction_api_and_copy_invalidation_are_explicit() {
    run(async {
        let mut session = connect().await;
        let before_begin = unnamed(&mut session, "SELECT $1::int4").await;
        let mut transaction = session.begin_transaction().await.unwrap();
        let parameters = [Parameter::int4(7)];
        assert!(matches!(
            transaction
                .query(
                    &before_begin,
                    &parameters,
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        let inside = transaction
            .prepare_replace_unnamed(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        transaction.savepoint("unnamed_boundary").await.unwrap();
        assert!(matches!(
            transaction
                .query(
                    &inside,
                    &parameters,
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        let before_commit = transaction
            .prepare_replace_unnamed(
                "SELECT $1::int4",
                &[Oid::INT4],
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        assert_eq!(
            transaction.commit().await.unwrap().transaction_end,
            Some(compio_postgres::TransactionEnd::Committed)
        );
        assert_eq!(session.take_transaction_end(), None);
        assert!(matches!(
            session
                .query(
                    &before_commit,
                    &parameters,
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: ExecutionScheduling::Uninterrupted
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly
                )
                .await,
            Err(Error::InvalidInput(_))
        ));
        for protocol in [CopyProtocol::SimpleSingle, CopyProtocol::Extended] {
            let before_copy = unnamed(&mut session, "SELECT $1::int4").await;
            let copy = session
                .copy_out(
                    "COPY (SELECT 42) TO STDOUT (FORMAT text)",
                    &[],
                    protocol,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let (bytes, completion) = copy
                .collect_ready(
                    compio_postgres::OwnedOutput {
                        max_bytes: 64,
                        allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                    },
                    compio_postgres::OnError::RecoverExplicitly,
                )
                .await
                .unwrap();
            assert_eq!(bytes, b"42\n");
            assert_eq!(completion.rows, 1);
            assert!(matches!(
                session
                    .query(
                        &before_copy,
                        &parameters,
                        compio_postgres::QueryOptions {
                            limits: query_limits(),
                            scheduling: ExecutionScheduling::Uninterrupted
                        },
                        compio_postgres::AbandonPolicy::RecoverExplicitly
                    )
                    .await,
                Err(Error::InvalidInput(_))
            ));
        }
        session.close_local().await.unwrap();
    });
}
