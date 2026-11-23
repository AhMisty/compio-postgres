//! 预备语句、单次查询及行结果。

use super::{ApiScope, Client, OnError, Transaction, core};
use crate::{
    Error,
    row::{AllocationPolicy, ResultFormats, RowLayout},
    scheduler::ExecutionScheduling,
    transport::WireTransport,
    types::{Oid, Parameter},
};

/// 单次查询或一个批次成员的自有行数据及已确认的完成状态。
pub use core::PipelineResult as QueryResult;
pub use core::PreparedStatement as Statement;
pub use core::QueryLimits;

#[derive(Debug, Clone, Copy)]
pub struct QueryOptions {
    pub limits: QueryLimits,
    pub scheduling: ExecutionScheduling,
}

impl<T: WireTransport> Client<T> {
    /// 按所选存储方式和结果格式准备语句。
    /// 参数类型已知时可给出 OID，传入空切片可让 PostgreSQL 根据 SQL 推断类型。
    /// 返回的句柄属于当前连接。用完命名语句时调用 [`Self::close_statement`] 回收服务端资源；
    /// 已释放句柄的语句可通过 [`Self::close_all_statements`] 一并关闭。
    /// Parse 成功后如遇服务器错误、元数据超限或格式不符，确认 Ready 后关闭本次未交付的语句。
    /// 清理失败时保留两个错误。
    pub async fn prepare(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        storage: crate::PreparedStatementStorage,
        formats: ResultFormats,
    ) -> Result<Statement, Error> {
        self.inner
            .prepare_storage_scoped(sql, parameter_oids, formats, storage, false)
            .await
    }

    pub async fn close_statement(&mut self, statement: &Statement) -> Result<(), Error> {
        self.inner.close_prepared(statement).await
    }

    /// 关闭本连接的全部活动语句，包括未交付句柄的语句。
    /// 仍有外部引用的元数据会继续保留。
    pub async fn close_all_statements(
        &mut self,
        limits: crate::StatementPipelineLimits,
    ) -> Result<(), Error> {
        self.inner.close_all_statements(limits).await
    }

    /// 用本连接准备的语句构造查询。参数须按占位符顺序提供，数量和 OID 须匹配语句描述。
    /// 等待结果读取方法时才提交，例如用 [`QueryRequest::one`] 读取一个标量。
    pub fn query<'scope, 'query>(
        &'scope mut self,
        statement: &'query Statement,
        parameters: &'query [Parameter<'query>],
    ) -> QueryRequest<'scope, 'query, Self> {
        QueryRequest::new(self, statement, parameters)
    }

    /// 一个往返内用未命名语句完成 Parse、Bind、Describe、Execute 和 Sync。
    /// SQL 只允许一条语句，参数使用 `$1`、`$2` 等占位符。
    /// 原未命名语句随之失效。
    /// 校验返回布局时 SQL 可能已经执行。
    pub fn one_shot<'scope, 'query>(
        &'scope mut self,
        sql: &'query str,
        parameters: &'query [Parameter<'query>],
        formats: ResultFormats,
    ) -> OneShotRequest<'scope, 'query, Self> {
        one_shot_request(self, sql, parameters, formats)
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在事务内准备语句。
    /// 元数据或格式错误的清理方式见 [`Client::prepare`]。
    pub async fn prepare(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        storage: crate::PreparedStatementStorage,
        formats: ResultFormats,
    ) -> Result<Statement, Error> {
        self.inner
            .session_mut()
            .prepare_storage_scoped(sql, parameter_oids, formats, storage, true)
            .await
    }

    pub async fn close_statement(&mut self, statement: &Statement) -> Result<(), Error> {
        self.inner.close_prepared(statement).await
    }

    /// 关闭本连接全部活动语句，保留当前事务。
    /// 仍被引用的元数据继续保留。
    pub async fn close_all_statements(
        &mut self,
        limits: crate::StatementPipelineLimits,
    ) -> Result<(), Error> {
        self.inner.close_all_statements(limits).await
    }

    /// 编码 portal 的 Bind，在本事务第一次有界 fetch 时发送。
    pub fn portal(
        &mut self,
        statement: &Statement,
        parameters: &[Parameter<'_>],
    ) -> Result<crate::Portal<'_, T>, Error> {
        self.inner.portal(statement, parameters)
    }

    pub fn query<'scope, 'query>(
        &'scope mut self,
        statement: &'query Statement,
        parameters: &'query [Parameter<'query>],
    ) -> QueryRequest<'scope, 'query, Self> {
        QueryRequest::new(self, statement, parameters)
    }

    /// 在当前事务中执行一次性查询，见 [`Client::one_shot`]。
    pub fn one_shot<'scope, 'query>(
        &'scope mut self,
        sql: &'query str,
        parameters: &'query [Parameter<'query>],
        formats: ResultFormats,
    ) -> OneShotRequest<'scope, 'query, Self> {
        one_shot_request(self, sql, parameters, formats)
    }
}

mod sealed {
    pub trait Parameters {}
    impl Parameters for &[crate::types::Parameter<'_>] {}
    impl Parameters for super::OneShotParameters<'_> {}
}

/// 为不同查询构造方式提供静态参数校验。
#[doc(hidden)]
pub trait QueryParameters: sealed::Parameters {
    type Source<'query>;
    const KNOWN_LAYOUT: bool = true;

    fn begin<'scope, T: WireTransport>(
        self,
        session: &'scope mut core::Session<T>,
        statement: Self::Source<'_>,
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
        check_layout: impl FnOnce(&RowLayout) -> Result<Option<u16>, Error>,
    ) -> Result<core::Query<'scope, T>, Error>;
}
impl QueryParameters for &[Parameter<'_>] {
    type Source<'query> = &'query Statement;

    #[inline(always)]
    fn begin<'scope, T: WireTransport>(
        self,
        session: &'scope mut core::Session<T>,
        statement: &Statement,
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
        check_layout: impl FnOnce(&RowLayout) -> Result<Option<u16>, Error>,
    ) -> Result<core::Query<'scope, T>, Error> {
        session.query_scoped_with_layout(
            statement,
            self,
            options,
            on_error,
            in_transaction,
            check_layout,
        )
    }
}
#[doc(hidden)]
pub struct OneShotParameters<'query> {
    sql: &'query str,
    parameters: &'query [Parameter<'query>],
    formats: ResultFormats,
}

impl QueryParameters for OneShotParameters<'_> {
    type Source<'query> = ();
    const KNOWN_LAYOUT: bool = false;

    fn begin<'scope, T: WireTransport>(
        self,
        session: &'scope mut core::Session<T>,
        _: (),
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
        _check_layout: impl FnOnce(&RowLayout) -> Result<Option<u16>, Error>,
    ) -> Result<core::Query<'scope, T>, Error> {
        session.one_shot_scoped(
            self.sql,
            self.parameters,
            self.formats,
            options,
            on_error,
            in_transaction,
        )
    }
}

/// 一次往返内执行带参数的查询并通过 Describe 取得结果布局。
pub type OneShotRequest<'scope, 'query, S> =
    QueryRequest<'scope, 'query, S, OneShotParameters<'query>>;

fn one_shot_request<'scope, 'query, S: ApiScope>(
    scope: &'scope mut S,
    sql: &'query str,
    parameters: &'query [Parameter<'query>],
    formats: ResultFormats,
) -> OneShotRequest<'scope, 'query, S> {
    QueryRequest::new(
        scope,
        (),
        OneShotParameters {
            sql,
            parameters,
            formats,
        },
    )
}

/// 待执行的查询，可单独指定限额和调度策略。
#[must_use = "选择结果读取方式并等待完成后才会执行查询"]
pub struct QueryRequest<'scope, 'query, S, P: QueryParameters = &'query [Parameter<'query>]> {
    scope: &'scope mut S,
    source: P::Source<'query>,
    parameters: P,
    profile: QueryOptions,
}
impl<'scope, 'query, S: ApiScope, P: QueryParameters> QueryRequest<'scope, 'query, S, P> {
    fn new(scope: &'scope mut S, source: P::Source<'query>, parameters: P) -> Self {
        let profile = scope.profile().query;
        Self {
            scope,
            source,
            parameters,
            profile,
        }
    }
}

#[must_use = "复用连接前须读取或结束行流"]
pub struct Rows<'scope, T: WireTransport> {
    inner: core::Query<'scope, T>,
}
impl<T: WireTransport> Rows<'_, T> {
    /// 为已提交的查询创建独立的取消句柄。
    pub fn cancel_handle(&mut self) -> Result<crate::CancelHandle, Error> {
        self.inner.cancel_handle()
    }

    /// 借用当前行；释放后可读取下一行。`Ok(None)` 表示请求已收到 Ready 且本地发送完成。
    pub async fn next_row(&mut self) -> Result<Option<crate::RowLease<'_>>, Error> {
        self.inner.next_row().await
    }
    /// 丢弃未读行，等待 Ready 和本地发送完成。
    pub async fn finish(&mut self) -> Result<crate::QueryCompletion, Error> {
        self.inner.finish().await
    }
}
impl<'scope, S: ApiScope, P: QueryParameters> QueryRequest<'scope, '_, S, P> {
    pub fn with_options(mut self, profile: QueryOptions) -> Self {
        self.profile = profile;
        self
    }
    fn begin(
        self,
        on_error: OnError,
        check_layout: impl FnOnce(&RowLayout) -> Result<Option<u16>, Error>,
    ) -> Result<core::Query<'scope, S::Io>, Error> {
        let (session, in_transaction) = self.scope.access();
        self.parameters.begin(
            session,
            self.source,
            self.profile,
            on_error,
            in_transaction,
            check_layout,
        )
    }
    /// 行可在 Ready 前交付。
    /// 指定放弃已提交请求时应保留待恢复状态还是丢弃连接。
    /// 丢弃或遗忘 future 不会自动排空。
    #[expect(clippy::unused_async, reason = "只在首次轮询时提交并选择放弃策略")]
    pub async fn stream_provisional(
        self,
        abandon: crate::AbandonPolicy,
    ) -> Result<Rows<'scope, S::Io>, Error> {
        Ok(Rows {
            inner: self.begin(abandon.on_error(), |_| Ok(None))?,
        })
    }
    /// 将结果行复制到自有缓冲区，收到 Ready 并完成本地发送后返回。空结果保留列布局。
    pub async fn collect_ready(
        self,
        allocation: AllocationPolicy,
        on_error: OnError,
    ) -> Result<QueryResult, Error> {
        let (rows, completion) = self
            .begin(on_error, |_| Ok(None))?
            .collect_with_on_owner(allocation)
            .await?;
        Ok(QueryResult { rows, completion })
    }
}

impl<'scope, 'query, S, P> QueryRequest<'scope, 'query, S, P>
where
    S: ApiScope,
    P: QueryParameters<Source<'query> = &'query Statement>,
{
    /// 使用调用方的定长行缓冲，在 Ready 和本地发送完成后公布结果。
    /// 提交前检查布局身份和已保留容量是否超过本次字节限额。实际结果装不下时返回限额错误。
    /// 已提交的查询失败或被放弃时清空缓冲。
    pub async fn collect_into_ready(
        self,
        output: &mut crate::OwnedBatch,
        on_error: OnError,
    ) -> Result<crate::QueryCompletion, Error> {
        if !std::ptr::eq(output.layout(), self.source.layout()) {
            return Err(Error::InvalidInput(
                "reusable arena has a different result layout",
            ));
        }
        if output.retained_bytes() > self.profile.limits.max_result_bytes {
            return Err(Error::Limit(
                "reusable arena exceeds this query's byte limit",
            ));
        }
        self.begin(on_error, |_| Ok(None))?
            .collect_into_on_owner::<true>(output, on_error)
            .await
    }
}

mod strict_results;
