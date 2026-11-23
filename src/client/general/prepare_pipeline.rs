//! 批量准备命名语句，每条独立执行 Parse/Describe/Sync。
//! 会话保留已创建语句的关闭义务。
use super::*;

pub struct PrepareRequest<'a> {
    pub sql: &'a str,
    pub parameter_oids: &'a [Oid],
    pub formats: ResultFormats,
}

pub type PrepareItem = Result<PreparedStatement, DatabaseError>;

pub struct PreparePipelineError {
    pub completed: Vec<PrepareItem>,
    pub source: Error,
    /// 包括后续已入队成员在内的语句名称都可能已经创建。
    /// Prepare 不会执行语句。
    pub may_have_created: bool,
}
impl PreparePipelineError {
    pub(in crate::client) fn before_submission(source: Error) -> Self {
        Self {
            completed: Vec::new(),
            source,
            may_have_created: false,
        }
    }
}
impl fmt::Debug for PreparePipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparePipelineError")
            .field("completed_count", &self.completed.len())
            .field("source", &self.source)
            .field("may_have_created", &self.may_have_created)
            .finish()
    }
}
impl fmt::Display for PreparePipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "statement preparation stopped after {} confirmed members: {}",
            self.completed.len(),
            self.source
        )
    }
}
impl std::error::Error for PreparePipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrepareIdentity {
    pub(super) slot: usize,
    pub(super) generation: u64,
    pub(super) epoch: u64,
}
pub(super) enum PrepareReadMode<'a> {
    Single { close_after_error: &'a mut bool },
    Pipeline(&'a mut usize),
}

impl PrepareReadMode<'_> {
    /// 此处只恢复本地元数据或请求格式错误。
    /// 传输、非法协议和服务器致命错误按各自的规则处理。
    pub(super) fn metadata_error(&mut self, error: Error) -> Error {
        let local = match &error {
            Error::Limit(_) => true,
            Error::Codec(error) => matches!(
                error.as_ref(),
                CodecError::Limit(_) | CodecError::Allocation | CodecError::Invalid(_)
            ),
            _ => false,
        };
        if local && let Self::Single { close_after_error } = self {
            **close_after_error = true;
        }
        error
    }
}
#[derive(Debug)]
pub(in crate::client) struct PrepareProgress {
    pub(super) members: Vec<PrepareIdentity>,
    pub(super) next: usize,
    pub(super) phase: PreparePhase,
    pub(super) quantum: ExecutionQuantum,
}
impl PrepareProgress {
    pub(super) fn current(&self) -> Result<PrepareIdentity, Error> {
        self.members.get(self.next).copied().ok_or(Error::Broken)
    }
    pub(super) fn advance(&mut self) -> Result<(), Error> {
        self.current()?;
        if !matches!(self.phase, PreparePhase::Complete | PreparePhase::Failed) {
            return Err(protocol_error(
                "Prepare Ready precedes its description or error",
            ));
        }
        self.next += 1;
        self.phase = PreparePhase::Parse;
        Ok(())
    }
}
struct PendingName {
    identity: PrepareIdentity,
    name: frontend::StatementName,
}

impl<T: WireTransport> Session<T> {
    /// 按输入顺序批量准备命名语句，每个成员独立 Parse/Describe/Sync，不执行 SQL。
    /// 所有输入、空槽、名称及发送大小均在提交前校验。
    /// 接收响应时核算元数据，批量准备在提交后超出此预算须丢弃连接。
    /// 普通 SQL 错误在相应的 Ready 边界返回，后续成员仍可能成功。
    ///
    /// 放弃已轮询的 future 后，会话保留各成员的协议阶段和调度预算。
    /// recover_to_ready 只排空已提交请求；调用方须用 close_all 关闭未交付句柄的已创建语句。
    pub async fn prepare_pipeline(
        &mut self,
        requests: Vec<PrepareRequest<'_>>,
        limits: StatementPipelineLimits,
    ) -> Result<Vec<PrepareItem>, PreparePipelineError> {
        self.prepare_pipeline_scoped(requests, limits, false).await
    }

    async fn prepare_pipeline_scoped(
        &mut self,
        requests: Vec<PrepareRequest<'_>>,
        limits: StatementPipelineLimits,
        in_transaction: bool,
    ) -> Result<Vec<PrepareItem>, PreparePipelineError> {
        self.check_idle_access(in_transaction)
            .map_err(PreparePipelineError::before_submission)?;
        let mut quantum = ExecutionQuantum::new(limits.scheduling);
        let count = requests.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > limits.max_statements {
            return Err(PreparePipelineError::before_submission(Error::Limit(
                "Prepare count exceeds its limit",
            )));
        }
        if limits.max_packet_bytes == 0 || limits.max_packet_bytes > self.max_request_len {
            return Err(PreparePipelineError::before_submission(
                Error::InvalidInput("Prepare packet exceeds its connection bound"),
            ));
        }
        let minimum = count
            .checked_mul(std::mem::size_of::<PrepareItem>())
            .ok_or_else(|| {
                PreparePipelineError::before_submission(Error::Limit(
                    "Prepare result size overflow",
                ))
            })?;
        if minimum > limits.max_result_bytes {
            return Err(PreparePipelineError::before_submission(Error::Limit(
                "Prepare result slots exceed their budget",
            )));
        }
        let mut completed = Vec::new();
        completed.try_reserve_exact(count).map_err(|_| {
            PreparePipelineError::before_submission(Error::Limit(
                "cannot allocate Prepare result slots",
            ))
        })?;
        let slots = completed
            .capacity()
            .checked_mul(std::mem::size_of::<PrepareItem>())
            .ok_or_else(|| {
                PreparePipelineError::before_submission(Error::Limit(
                    "Prepare result size overflow",
                ))
            })?;
        let mut diagnostics = limits.max_result_bytes.checked_sub(slots).ok_or_else(|| {
            PreparePipelineError::before_submission(Error::Limit(
                "actual Prepare result slots exceed their budget",
            ))
        })?;
        let extended = self.extended.as_deref_mut().ok_or_else(|| {
            PreparePipelineError::before_submission(Error::InvalidInput(
                "configure statement storage before preparing",
            ))
        })?;
        extended.limits.ok_or_else(|| {
            PreparePipelineError::before_submission(Error::InvalidInput(
                "statement limits are missing",
            ))
        })?;
        if extended.epoch_exhausted {
            return Err(PreparePipelineError::before_submission(Error::Limit(
                "statement schema epoch is exhausted",
            )));
        }
        extended
            .reclaim_closed()
            .inspect_err(|_| self.transport.break_connection())
            .map_err(PreparePipelineError::before_submission)?;
        if count > extended.vacant_count {
            return Err(PreparePipelineError::before_submission(Error::Limit(
                "statement slots are full; close unused statements and release their layouts",
            )));
        }
        let final_name = extended
            .next_name
            .checked_add(u64::try_from(count).map_err(|_| {
                PreparePipelineError::before_submission(Error::Limit("Prepare count overflow"))
            })?)
            .ok_or_else(|| {
                PreparePipelineError::before_submission(Error::Limit(
                    "statement name space is exhausted",
                ))
            })?;
        let mut pending = Vec::new();
        pending.try_reserve_exact(count).map_err(|_| {
            PreparePipelineError::before_submission(Error::Limit(
                "cannot allocate Prepare admission identities",
            ))
        })?;
        for (slot_index, slot) in extended.vacant_slots().take(count) {
            let generation = slot.generation.checked_add(1).ok_or_else(|| {
                PreparePipelineError::before_submission(Error::Limit(
                    "statement slot generation is exhausted",
                ))
            })?;
            let offset = u64::try_from(pending.len()).map_err(|_| {
                PreparePipelineError::before_submission(Error::Limit("Prepare offset overflow"))
            })?;
            let name = frontend::StatementName::numbered(extended.next_name + offset + 1)
                .map_err(PreparePipelineError::before_submission)?;
            pending.push(PendingName {
                identity: PrepareIdentity {
                    slot: slot_index,
                    generation,
                    epoch: extended.schema_epoch,
                },
                name,
            });
        }
        let mut identities = Vec::new();
        identities.try_reserve_exact(count).map_err(|_| {
            PreparePipelineError::before_submission(Error::Limit(
                "cannot allocate bounded Prepare recovery identities",
            ))
        })?;
        if identities.capacity() > limits.max_statements
            || pending.capacity() > limits.max_statements
        {
            return Err(PreparePipelineError::before_submission(Error::Limit(
                "Prepare identities exceed their statement bound",
            )));
        }
        let packet = self
            .transport
            .encode_send_buffer(|packet| {
                for (request, pending) in requests.iter().zip(&pending) {
                    frontend::append_prepare(
                        packet,
                        pending.name.wire(),
                        request.sql,
                        request.parameter_oids,
                        limits.max_packet_bytes,
                    )?;
                    identities.push(pending.identity);
                }
                Ok(())
            })
            .map_err(PreparePipelineError::before_submission)?;
        quantum.spend_bytes(packet.len());
        // 全部校验通过后同步登记这批语句，中间无挂起点或回调。
        let extended = self.extension();
        for pending in pending {
            let slot = extended
                .slots
                .get_mut(pending.identity.slot)
                .ok_or_else(|| PreparePipelineError::before_submission(Error::Broken))?;
            slot.generation = pending.identity.generation;
            slot.record = Some(Record {
                name: pending.name,
                data: None,
                remote: RemoteStatement::Preparing,
            });
        }
        extended.occupy_slots(count);
        extended.next_name = final_name;
        extended.work_kind = Some(WorkKind::PreparePipeline(PrepareProgress {
            members: identities,
            next: 0,
            phase: PreparePhase::Parse,
            quantum,
        }));
        self.active = true;
        self.remaining_boundaries = count;
        if let Err(source) = self.transport.begin_send(packet) {
            self.transport.break_connection();
            return Err(PreparePipelineError {
                completed,
                source,
                may_have_created: false,
            });
        }
        let result = async {
            self.execution_quantum_mut()?.yield_on_worker().await?;
            for request in requests {
                let identity = self.prepare_progress()?.current()?;
                let boundaries = self.remaining_boundaries;
                let result = self
                    .read_prepared_member(
                        request.parameter_oids,
                        request.formats,
                        identity,
                        PrepareReadMode::Pipeline(&mut diagnostics),
                    )
                    .await;
                let item = match result {
                    Ok(statement) => Ok(statement),
                    Err(Error::Database(error)) if self.remaining_boundaries + 1 == boundaries => {
                        Err(error)
                    }
                    Err(error) => return Err(error),
                };
                self.prepare_progress_mut()?.advance()?;
                completed.push(item);
                self.execution_quantum_mut()?.yield_on_worker().await?;
            }
            self.transport.finish_send_on_owner().await
        }
        .await;
        if let Err(source) = result {
            self.transport.break_connection();
            return Err(PreparePipelineError {
                completed,
                source,
                may_have_created: true,
            });
        }
        self.active = false;
        self.extension().work_kind = None;
        Ok(completed)
    }

    pub(super) fn prepare_progress(&self) -> Result<&PrepareProgress, Error> {
        match self
            .extended
            .as_ref()
            .and_then(|extended| extended.work_kind.as_ref())
        {
            Some(WorkKind::PreparePipeline(progress)) => Ok(progress),
            _ => Err(Error::Broken),
        }
    }
    pub(super) fn prepare_progress_mut(&mut self) -> Result<&mut PrepareProgress, Error> {
        match self
            .extended
            .as_mut()
            .and_then(|extended| extended.work_kind.as_mut())
        {
            Some(WorkKind::PreparePipeline(progress)) => Ok(progress),
            _ => Err(Error::Broken),
        }
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中准备独立的命名语句，每个成员独立 Sync。
    /// 单条出错后已入队成员仍可能被处理。
    /// 放弃后需显式恢复。
    pub async fn prepare_pipeline(
        &mut self,
        requests: Vec<PrepareRequest<'_>>,
        limits: StatementPipelineLimits,
    ) -> Result<Vec<PrepareItem>, PreparePipelineError> {
        self.session_mut()
            .prepare_pipeline_scoped(requests, limits, true)
            .await
    }
}
