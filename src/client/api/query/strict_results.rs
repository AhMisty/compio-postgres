//! 等待 Ready 并校验结果行数或列数的终端操作。

use super::{ApiScope, OnError, QueryParameters, QueryRequest};
use crate::{
    Error,
    protocol::DataRow,
    row::{ResultShape, RowLayout, RowView, ScalarColumn},
    types::Decode,
};

impl<'scope, S: ApiScope, P: QueryParameters> QueryRequest<'scope, '_, S, P> {
    /// 要求恰好一行、一列且类型兼容。
    /// 预备语句在发送前校验布局，提交后的本地错误按 `on_error` 处理。
    pub async fn one<V>(self, on_error: OnError) -> Result<V, Error>
    where
        for<'row> V: Decode<'row>,
    {
        self.read_single::<true, true, _>(on_error, single_column::<true, V>, decode_scalar)
            .await?
            .ok_or(Error::Broken)
    }

    /// 要求一列且类型兼容，允许零行或一行。
    /// 预备语句在发送前校验。
    /// 成功表示 Ready 和本地发送均已完成。
    /// 若 `V = Option<T>`，`None` 表示无行，`Some(None)` 表示该行的值为 SQL NULL。
    pub async fn zero_or_one<V>(self, on_error: OnError) -> Result<Option<V>, Error>
    where
        for<'row> V: Decode<'row>,
    {
        self.read_single::<false, true, _>(on_error, single_column::<false, V>, decode_scalar)
            .await
    }

    /// 将任意布局的唯一一行映射成返回值。
    /// 映射函数在 Ready 前借用接收缓冲，仅在确认行数、Ready 和本地发送完成后返回映射结果。
    pub async fn map_provisional_one<V>(
        self,
        on_error: OnError,
        map: impl for<'row> FnOnce(RowView<'row, 'row>) -> Result<V, Error>,
    ) -> Result<V, Error> {
        self.map_provisional::<true, V>(on_error, map)
            .await?
            .ok_or(Error::Broken)
    }

    /// 允许零行或一行。
    /// 无行时跳过映射函数，返回边界与 [`Self::map_provisional_one`] 相同。
    pub async fn map_provisional_zero_or_one<V>(
        self,
        on_error: OnError,
        map: impl for<'row> FnOnce(RowView<'row, 'row>) -> Result<V, Error>,
    ) -> Result<Option<V>, Error> {
        self.map_provisional::<false, V>(on_error, map).await
    }

    async fn map_provisional<const EXACT: bool, V>(
        self,
        on_error: OnError,
        map: impl for<'row> FnOnce(RowView<'row, 'row>) -> Result<V, Error>,
    ) -> Result<Option<V>, Error> {
        self.read_single::<EXACT, false, _>(
            on_error,
            |_| Ok(()),
            |data, _, layout| {
                map(RowView::from_matching_layout(
                    data,
                    layout.ok_or(Error::Broken)?,
                ))
            },
        )
        .await
    }

    async fn read_single<const EXACT: bool, const SCALAR: bool, V>(
        self,
        on_error: OnError,
        check_layout: impl Fn(Option<ScalarColumn>) -> Result<(), Error>,
        map: impl FnOnce(DataRow<'_>, Option<ScalarColumn>, Option<&RowLayout>) -> Result<V, Error>,
    ) -> Result<Option<V>, Error> {
        let mut prepared_scalar = None;
        let mut query = self.begin(on_error, |layout| {
            if SCALAR {
                prepared_scalar = layout.scalar_column();
                check_layout(prepared_scalar)?;
            }
            Ok(SCALAR.then_some(1))
        })?;
        let mut shape = (SCALAR && !P::KNOWN_LAYOUT).then(ResultShape::default);

        let failure = 'rows: {
            let row = match query
                .map_result_row_on_owner(shape.as_mut(), |data, projection, extended| {
                    extended.invoke_callback(|| {
                        let scalar = match projection {
                            Some(shape) => {
                                check_layout(shape.scalar)?;
                                shape.scalar
                            }
                            None => prepared_scalar,
                        };
                        map(data, scalar, extended.query_layout())
                    })
                })
                .await
            {
                Ok(row) => row,
                Err(error @ Error::Limit(_)) => break 'rows error,
                Err(error) => return Err(error),
            };
            let Some(value) = row else {
                if let Some(shape) = shape
                    && let Err(error) = check_layout(shape.scalar)
                {
                    break 'rows error;
                }
                if EXACT {
                    break 'rows Error::InvalidInput("one requires exactly one result row");
                }
                return Ok(None);
            };
            let value = match value {
                Ok(value) => value,
                Err(error) => break 'rows error,
            };
            // 第二行已通过结构校验，判断行数超限无需再借用或解码它。
            match query
                .map_result_row_on_owner(shape.as_mut(), |_, _, _| ())
                .await
            {
                Ok(None) => return Ok(Some(value)),
                Ok(Some(_)) => Error::InvalidInput(if EXACT {
                    "one received more than one result row"
                } else {
                    "zero_or_one received more than one result row"
                }),
                Err(error @ Error::Limit(_)) => error,
                Err(error) => return Err(error),
            }
        };
        Err(query.local_failure_with(on_error, failure).await)
    }

    /// 要求零列且没有 DataRow。
    /// 预备语句在发送前校验布局。
    /// 收到数据行时按所选错误策略处理。
    /// 成功确认 Ready 和本地发送完成；事务仍需显式提交。
    pub async fn command_ready(self, on_error: OnError) -> Result<crate::QueryCompletion, Error> {
        let check_layout = |empty| {
            if empty {
                Ok(())
            } else {
                Err(Error::InvalidInput(
                    "command_ready requires a zero-column result layout",
                ))
            }
        };
        let mut query = self.begin(on_error, |layout| {
            check_layout(layout.is_empty())?;
            Ok(Some(0))
        })?;
        let mut shape = (!P::KNOWN_LAYOUT).then(ResultShape::default);
        let failure = match query
            .map_result_row_on_owner(shape.as_mut(), |_, _, _| ())
            .await
        {
            Ok(None) => {
                if let Err(error) = check_layout(shape.is_none_or(|shape| shape.columns == 0)) {
                    error
                } else {
                    return query.completion().ok_or(Error::Broken);
                }
            }
            Ok(Some(_)) => Error::InvalidInput("command_ready received a result row"),
            Err(error @ Error::Limit(_)) => error,
            Err(error) => return Err(error),
        };
        Err(query.local_failure_with(on_error, failure).await)
    }
}

fn decode_scalar<V>(
    data: DataRow<'_>,
    scalar: Option<ScalarColumn>,
    _: Option<&RowLayout>,
) -> Result<V, Error>
where
    for<'row> V: Decode<'row>,
{
    Ok(scalar.ok_or(Error::Broken)?.decode(data.scalar_field())?)
}

fn single_column<const EXACT: bool, V>(scalar: Option<ScalarColumn>) -> Result<(), Error>
where
    for<'row> V: Decode<'row>,
{
    let Some(scalar) = scalar else {
        return Err(Error::InvalidInput(if EXACT {
            "one requires exactly one result column"
        } else {
            "zero_or_one requires exactly one result column"
        }));
    };
    Ok(scalar.validate::<V>()?)
}
