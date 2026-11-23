//! COPY 输入输出、完成确认与放弃后的恢复。

use super::{Client, Statement, Transaction, core};
use crate::{Error, scheduler::ExecutionScheduling, transport::WireTransport, types::Parameter};

pub use core::{
    CopyAbort, CopyBatchCompletion, CopyBatchError, CopyBatchLimits, CopyChunk, CopyCompletion,
    CopyDataBuffer, CopyInfo, CopyInput, CopyOutput, CopyStreamLimits,
};

impl<T: WireTransport> Client<T> {
    /// COPY 独立选择调度策略，使用自己的数据限额。
    pub async fn copy_in(
        &mut self,
        statement: &Statement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'_, T>, Error> {
        self.inner
            .copy_in_prepared(statement, parameters, scheduling)
            .await
    }

    pub async fn copy_out(
        &mut self,
        statement: &Statement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'_, T>, Error> {
        self.inner
            .copy_out_prepared(statement, parameters, scheduling)
            .await
    }

    /// 拒绝遗留的 COPY IN 输入并排空原操作的响应。
    pub async fn fail_abandoned_copy(&mut self, message: &str) -> Result<CopyAbort, Error> {
        self.inner.fail_abandoned_copy(message).await
    }

    /// 丢弃遗留的 COPY OUT 数据，直到收到原操作的 Ready。
    pub async fn finish_abandoned_copy_out(&mut self) -> Result<CopyCompletion, Error> {
        self.inner.finish_abandoned_copy_out().await
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub async fn copy_in(
        &mut self,
        statement: &Statement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'_, T>, Error> {
        self.inner
            .copy_in_prepared(statement, parameters, scheduling)
            .await
    }

    pub async fn copy_out(
        &mut self,
        statement: &Statement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'_, T>, Error> {
        self.inner
            .copy_out_prepared(statement, parameters, scheduling)
            .await
    }

    pub async fn fail_abandoned_copy(&mut self, message: &str) -> Result<CopyAbort, Error> {
        self.inner.fail_abandoned_copy(message).await
    }

    pub async fn finish_abandoned_copy_out(&mut self) -> Result<CopyCompletion, Error> {
        self.inner.finish_abandoned_copy_out().await
    }
}
