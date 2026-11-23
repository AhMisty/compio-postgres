//! 使用通用预备语句协议验证标量结果。解码失败或行数不符时，将恢复决定留给测试调用方。
#![allow(dead_code, reason = "各集成测试独立编译，只使用所需的标量操作")]

use compio_postgres::{
    Error, ExecutionScheduling, QueryLimits, ResultFormats, StatementLimits, WireTransport,
    expert::{
        PipelineError, PipelineItem, PipelineLimits, PipelineRequest, PreparedStatement, Query,
        Session, SessionTransaction as Transaction,
    },
    types::{Format, Oid, Parameter},
};

pub(crate) fn configure<T: WireTransport>(session: &mut Session<T>) {
    session
        .configure_statements(StatementLimits {
            max_statements: 8,
            max_metadata_bytes: 64 * 1024,
        })
        .expect("configure general statement storage");
}

pub(crate) fn limits() -> QueryLimits {
    QueryLimits {
        max_rows: 1024,
        max_result_bytes: 64 * 1024,
        max_metadata_bytes: 16 * 1024,
    }
}

pub(crate) fn parameter(value: Option<i32>) -> Parameter<'static> {
    value.map_or(Parameter::null(Oid::INT4, Format::Binary), Parameter::int4)
}

async fn scalar<T: WireTransport>(mut query: Query<'_, T>) -> Result<Option<i32>, Error> {
    let value = {
        let row = query
            .next_row()
            .await?
            .ok_or(Error::InvalidInput("expected one scalar row"))?;
        let mut decoder = row.view().decoder();
        let value = decoder.decode_next::<Option<i32>>()?;
        decoder.finish()?;
        value
    };
    if query.next_row().await?.is_some() {
        return Err(Error::InvalidInput("expected one scalar row"));
    }
    query.finish().await?;
    Ok(value)
}

pub(crate) trait ScalarQueries {
    async fn prepare_scalar(&mut self, sql: &str) -> Result<PreparedStatement, Error>;
    async fn query_scalar(
        &mut self,
        statement: &PreparedStatement,
        value: Option<i32>,
    ) -> Result<Option<i32>, Error>;
}

pub(crate) fn pipeline_limits(max_requests: usize, max_result_bytes: usize) -> PipelineLimits {
    PipelineLimits {
        max_requests,
        max_rows: 1024,
        max_result_bytes,
        storage: compio_postgres::AllocationPolicy::Grow,
        scheduling: ExecutionScheduling::Uninterrupted,
    }
}

pub(crate) async fn pipeline<T: WireTransport>(
    session: &mut Session<T>,
    statement: &PreparedStatement,
    values: &[Option<i32>],
    limits: PipelineLimits,
) -> Result<Vec<PipelineItem>, PipelineError> {
    let parameters: Vec<_> = values.iter().map(|value| [parameter(*value)]).collect();
    let requests: Vec<_> = parameters
        .iter()
        .map(|parameters| PipelineRequest {
            statement,
            parameters,
            limits: self::limits(),
        })
        .collect();
    session.query_pipeline(&requests, limits).await
}

pub(crate) fn values(
    items: &[PipelineItem],
) -> Vec<Result<Option<i32>, &compio_postgres::DatabaseError>> {
    items
        .iter()
        .map(|item| match item {
            Ok(result) => {
                let mut rows = result.rows.rows();
                let row = rows.next().expect("one scalar row").unwrap();
                let mut decoder = row.decoder();
                let value = decoder.decode_next::<Option<i32>>().unwrap();
                decoder.finish().unwrap();
                assert!(rows.next().is_none());
                Ok(value)
            }
            Err(error) => Err(error),
        })
        .collect()
}

impl<T: WireTransport> ScalarQueries for Session<T> {
    async fn prepare_scalar(&mut self, sql: &str) -> Result<PreparedStatement, Error> {
        self.prepare(sql, &[Oid::INT4], ResultFormats::All(Format::Binary))
            .await
    }

    async fn query_scalar(
        &mut self,
        statement: &PreparedStatement,
        value: Option<i32>,
    ) -> Result<Option<i32>, Error> {
        scalar(
            self.query(
                statement,
                &[parameter(value)],
                compio_postgres::QueryOptions {
                    limits: limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await?,
        )
        .await
    }
}

impl<T: WireTransport> ScalarQueries for Transaction<'_, T> {
    async fn prepare_scalar(&mut self, sql: &str) -> Result<PreparedStatement, Error> {
        self.prepare(sql, &[Oid::INT4], ResultFormats::All(Format::Binary))
            .await
    }

    async fn query_scalar(
        &mut self,
        statement: &PreparedStatement,
        value: Option<i32>,
    ) -> Result<Option<i32>, Error> {
        scalar(
            self.query(
                statement,
                &[parameter(value)],
                compio_postgres::QueryOptions {
                    limits: limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await?,
        )
        .await
    }
}

/// 从另一条连接观察查询进入 pg_sleep，随后验证同一后端确实返回取消错误。
pub(crate) async fn assert_live_cancel<T: WireTransport>(
    mut connection: Session<T>,
    mut observer: Session<T>,
) {
    use std::time::Duration;
    configure(&mut connection);
    configure(&mut observer);
    let active = observer
        .prepare_scalar(
            "SELECT count(*)::int4 FROM pg_stat_activity
         WHERE pid = $1::int4 AND state = 'active' AND wait_event = 'PgSleep'",
        )
        .await
        .unwrap();
    let statement = connection
        .prepare_scalar("SELECT $1::int4 FROM pg_sleep(15)")
        .await
        .unwrap();
    let process_id = connection.server_info().process_id;
    {
        let params = [Parameter::int4(42)];
        let mut query = connection
            .query(
                &statement,
                &params,
                compio_postgres::QueryOptions {
                    limits: limits(),
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        let handle = query.cancel_handle().unwrap();
        let cancel = async {
            while observer.query_scalar(&active, Some(process_id)).await? != Some(1) {
                compio::time::sleep(Duration::from_millis(10)).await;
            }
            handle.request_cancel_and_invalidate().await
        };
        let (outcome, cancellation) = compio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join(query.finish(), cancel),
        )
        .await
        .expect("未能在慢查询完成前确认服务端取消");
        cancellation.unwrap();
        assert!(matches!(outcome, Err(Error::Database(error)) if error.code() == "57014"));
    }
    assert_eq!(
        connection.reuse_state(),
        compio_postgres::ReuseState::DiscardOnly
    );
    connection.close_local().await.unwrap();
    observer.close_local().await.unwrap();
}
