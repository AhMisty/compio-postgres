//! 批量关闭预备语句，每条 Close 以独立的 Sync 确认；未确认的槽位由会话保留以便恢复。
use super::*;

pub type CloseItem = Result<(), DatabaseError>;

/// completed 只含已收到 Ready 的成员。
/// 较晚的错误不会撤销其他已提交的 Close。
pub struct ClosePipelineError {
    pub completed: Vec<CloseItem>,
    pub source: Error,
    pub may_have_executed: bool,
}

impl ClosePipelineError {
    fn before_submission(source: Error) -> Self {
        Self {
            completed: Vec::new(),
            source,
            may_have_executed: false,
        }
    }
}

impl fmt::Debug for ClosePipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosePipelineError")
            .field("completed_count", &self.completed.len())
            .field("source", &self.source)
            .field("may_have_executed", &self.may_have_executed)
            .finish()
    }
}

impl fmt::Display for ClosePipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "statement Close pipeline stopped after {} confirmed members: {}",
            self.completed.len(),
            self.source
        )
    }
}

impl std::error::Error for ClosePipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CloseMember {
    pub(super) slot: usize,
    pub(super) generation: u64,
}

#[derive(Debug)]
pub(in crate::client) struct CloseProgress {
    members: Vec<CloseMember>,
    next: usize,
    pub(super) phase: ClosePhase,
    pub(super) quantum: ExecutionQuantum,
}

impl CloseProgress {
    pub(super) fn current(&self) -> Result<CloseMember, Error> {
        self.members.get(self.next).copied().ok_or(Error::Broken)
    }
    pub(super) fn advance(&mut self) -> Result<(), Error> {
        self.current()?;
        self.next += 1;
        self.phase = ClosePhase::Waiting;
        Ok(())
    }
}

impl<T: WireTransport> Session<T> {
    /// 关闭仍由本会话持有的服务端语句，包括未交付句柄的已创建语句。
    /// 语句数、包长和诊断字节限额按包计算，调度额度跨包保留。
    /// 返回首个 SQL 错误前会排空同包的其余关闭操作。
    pub async fn close_all_statements(
        &mut self,
        limits: StatementPipelineLimits,
    ) -> Result<(), Error> {
        self.close_all_statements_scoped(limits, false).await
    }

    async fn close_all_statements_scoped(
        &mut self,
        limits: StatementPipelineLimits,
        in_transaction: bool,
    ) -> Result<(), Error> {
        self.check_idle_access(in_transaction)?;
        let minimum = frontend::close_sync_bytes(frontend::StatementName::UNNAMED.wire());
        if limits.max_statements == 0
            || limits.max_packet_bytes < minimum
            || limits.max_packet_bytes > self.max_request_len
        {
            return Err(Error::InvalidInput(
                "invalid bounds for closing all statements",
            ));
        }
        let mut members = Vec::new();
        let mut quantum = ExecutionQuantum::new(limits.scheduling);
        let mut next = 0;
        loop {
            let Some(extended) = self.extended.as_ref() else {
                return Ok(());
            };
            let mut live = extended
                .slots
                .iter()
                .enumerate()
                .skip(next)
                .filter_map(|(index, slot)| {
                    let record = slot.record.as_ref()?;
                    (!record.is_closed()).then_some((index, slot.generation, record.name.wire()))
                })
                .peekable();
            if live.peek().is_none() {
                return Ok(());
            }
            members.clear();
            members
                .try_reserve_exact(
                    limits
                        .max_statements
                        .min(extended.slots.len() - next)
                        .min(limits.max_packet_bytes / minimum),
                )
                .map_err(|_| Error::Limit("cannot allocate Close recovery identities"))?;
            let packet = self.transport.encode_send_buffer(|packet| {
                for (index, generation, name) in live.take(limits.max_statements) {
                    if !members.is_empty()
                        && frontend::close_sync_bytes(name) > limits.max_packet_bytes - packet.len()
                    {
                        break;
                    }
                    frontend::append_close_sync(packet, name, limits.max_packet_bytes)?;
                    members.push(CloseMember {
                        slot: index,
                        generation,
                    });
                    next = index + 1;
                }
                Ok(())
            })?;
            let mut first = None;
            let result = self
                .drive_close_packet(members, packet, quantum, limits.max_result_bytes, |item| {
                    if let Err(error) = item {
                        first = Some(Error::Database(error));
                    }
                    first.is_none()
                })
                .await
                .map_err(|(error, _)| error);
            if let Some(error) = first {
                return Err(with_cleanup_error(error, result.map(|_| ())));
            }
            (members, quantum) = result?;
        }
    }

    /// 提交前校验所有句柄，将每个成员的 Close/Sync 编入同一个包。
    /// 重复、过期或其他连接的句柄会使整批在 I/O 前失败；只有布局失效的语句仍可关闭。
    ///
    /// 普通 SQL 错误在各自的 Ready 边界交付，后续 Close 仍可能执行。
    /// 协议、I/O、存储和消息限额错误会丢弃连接并保留已确认前缀。
    /// 放弃 future 后，recover_to_ready 可按已保存的协议阶段排空已提交数据。
    /// 失败事务仍由调用方决定如何结束。
    pub async fn close_prepared_pipeline(
        &mut self,
        statements: &[&PreparedStatement],
        limits: StatementPipelineLimits,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.close_prepared_pipeline_scoped(statements, limits, false)
            .await
    }

    async fn close_prepared_pipeline_scoped(
        &mut self,
        statements: &[&PreparedStatement],
        limits: StatementPipelineLimits,
        in_transaction: bool,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.check_idle_access(in_transaction)
            .map_err(ClosePipelineError::before_submission)?;
        let quantum = ExecutionQuantum::new(limits.scheduling);
        if statements.is_empty() {
            return Ok(Vec::new());
        }
        self.check_close_pipeline_count(statements.len(), limits)
            .map_err(ClosePipelineError::before_submission)?;
        let mut members = Self::close_member_storage(statements.len(), limits)
            .map_err(ClosePipelineError::before_submission)?;
        let inline = self
            .extended
            .as_ref()
            .is_some_and(|state| state.slots.len() <= usize::BITS as usize);
        let mut seen = 0usize;
        let mut duplicate = false;
        let mut slots = Vec::new();
        if !inline {
            slots.try_reserve_exact(statements.len()).map_err(|_| {
                ClosePipelineError::before_submission(Error::Limit(
                    "cannot allocate Close identity preflight",
                ))
            })?;
            if slots.capacity() > limits.max_statements {
                return Err(ClosePipelineError::before_submission(Error::Limit(
                    "Close identity preflight exceeds its statement bound",
                )));
            }
        }
        for statement in statements {
            self.check_prepared_snapshot(statement, false)
                .map_err(ClosePipelineError::before_submission)?;
            members.push(CloseMember {
                slot: statement.slot,
                generation: statement.generation,
            });
            if inline {
                // 已核对槽有效，整个注册表可用一个机器字表示。
                let slot = 1usize << statement.slot;
                duplicate |= seen & slot != 0;
                seen |= slot;
            } else {
                slots.push(statement.slot);
            }
        }
        slots.sort_unstable();
        if duplicate || slots.array_windows().any(|[first, second]| first == second) {
            return Err(ClosePipelineError::before_submission(Error::InvalidInput(
                "Close pipeline contains a duplicate statement",
            )));
        }
        drop(slots);
        self.close_members_pipeline(members, limits, quantum).await
    }

    /// 关闭所有仍存活的服务端语句，包括未交付句柄的语句。
    /// 按注册槽快照顺序返回结果，槽复用后该顺序可能不同于准备顺序。
    /// 提交前完成选择和编码；错误、放弃和恢复行为同 close_prepared_pipeline。
    /// 仍被引用的元数据保留。
    pub async fn close_all_statements_pipeline(
        &mut self,
        limits: StatementPipelineLimits,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.close_all_statements_pipeline_scoped(limits, false)
            .await
    }

    async fn close_all_statements_pipeline_scoped(
        &mut self,
        limits: StatementPipelineLimits,
        in_transaction: bool,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.check_idle_access(in_transaction)
            .map_err(ClosePipelineError::before_submission)?;
        let quantum = ExecutionQuantum::new(limits.scheduling);
        let count = self.extended.as_ref().map_or(0, |extended| {
            if extended.first_closed.is_none() {
                // 此时每个占用的槽都对应已创建或可能已创建的服务端名称。
                return extended.slots.len() - extended.vacant_count;
            }
            extended
                .slots
                .iter()
                .filter(|slot| {
                    slot.record
                        .as_ref()
                        .is_some_and(|record| !record.is_closed())
                })
                .count()
        });
        if count == 0 {
            return Ok(Vec::new());
        }
        self.check_close_pipeline_count(count, limits)
            .map_err(ClosePipelineError::before_submission)?;
        let mut members = Self::close_member_storage(count, limits)
            .map_err(ClosePipelineError::before_submission)?;
        if let Some(extended) = self.extended.as_ref() {
            for (index, slot) in extended.slots.iter().enumerate() {
                if slot
                    .record
                    .as_ref()
                    .is_some_and(|record| !record.is_closed())
                {
                    members.push(CloseMember {
                        slot: index,
                        generation: slot.generation,
                    });
                }
            }
        }
        self.close_members_pipeline(members, limits, quantum).await
    }

    fn check_close_pipeline_count(
        &self,
        count: usize,
        limits: StatementPipelineLimits,
    ) -> Result<(), Error> {
        if count > limits.max_statements {
            return Err(Error::Limit(
                "Close pipeline statement count exceeds its limit",
            ));
        }
        if limits.max_packet_bytes == 0 || limits.max_packet_bytes > self.max_request_len {
            return Err(Error::InvalidInput(
                "Close packet capacity exceeds its connection bound",
            ));
        }
        if count
            .checked_mul(std::mem::size_of::<CloseItem>())
            .is_none_or(|bytes| bytes > limits.max_result_bytes)
        {
            return Err(Error::Limit("Close result slots exceed their budget"));
        }
        // 最短的未命名 Close 本身为七字节，另需五字节 Sync。
        if count
            .checked_mul(12)
            .is_none_or(|bytes| bytes > limits.max_packet_bytes)
        {
            return Err(Error::Limit("Close members cannot fit their packet bound"));
        }
        Ok(())
    }

    fn close_member_storage(
        count: usize,
        limits: StatementPipelineLimits,
    ) -> Result<Vec<CloseMember>, Error> {
        let mut members = Vec::new();
        members
            .try_reserve_exact(count)
            .map_err(|_| Error::Limit("cannot allocate bounded Close recovery identities"))?;
        if members.capacity() > limits.max_statements {
            return Err(Error::Limit(
                "Close recovery identities exceed their statement bound",
            ));
        }
        Ok(members)
    }

    async fn close_members_pipeline(
        &mut self,
        members: Vec<CloseMember>,
        limits: StatementPipelineLimits,
        quantum: ExecutionQuantum,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        let mut completed: Vec<CloseItem> = Vec::new();
        completed.try_reserve_exact(members.len()).map_err(|_| {
            ClosePipelineError::before_submission(Error::Limit(
                "cannot allocate Close result slots",
            ))
        })?;
        let slots = completed
            .capacity()
            .checked_mul(std::mem::size_of::<CloseItem>())
            .ok_or_else(|| {
                ClosePipelineError::before_submission(Error::Limit("Close result size overflow"))
            })?;
        let remaining = limits.max_result_bytes.checked_sub(slots).ok_or_else(|| {
            ClosePipelineError::before_submission(Error::Limit(
                "actual Close result slots exceed their budget",
            ))
        })?;
        let packet = self
            .transport
            .encode_send_buffer(|packet| {
                for member in &members {
                    let record = self
                        .extended
                        .as_ref()
                        .and_then(|extended| extended.slots.get(member.slot))
                        .and_then(|slot| slot.record.as_ref())
                        .ok_or(Error::Broken)?;
                    frontend::append_close_sync(
                        packet,
                        record.name.wire(),
                        limits.max_packet_bytes,
                    )?;
                }
                Ok(())
            })
            .map_err(ClosePipelineError::before_submission)?;
        if let Err((source, may_have_executed)) = self
            .drive_close_packet(members, packet, quantum, remaining, |item| {
                completed.push(item);
                true
            })
            .await
        {
            return Err(ClosePipelineError {
                completed,
                source,
                may_have_executed,
            });
        }
        Ok(completed)
    }

    async fn drive_close_packet(
        &mut self,
        members: Vec<CloseMember>,
        packet: Vec<u8>,
        mut quantum: ExecutionQuantum,
        mut remaining: usize,
        mut on_close: impl FnMut(CloseItem) -> bool,
    ) -> Result<(Vec<CloseMember>, ExecutionQuantum), (Error, bool)> {
        let count = members.len();
        quantum.spend_bytes(packet.len());
        self.extension().work_kind = Some(WorkKind::ClosePipeline(CloseProgress {
            members,
            next: 0,
            phase: ClosePhase::Waiting,
            quantum,
        }));
        self.active = true;
        self.remaining_boundaries = count;
        if let Err(source) = self.transport.begin_send(packet) {
            self.transport.break_connection();
            return Err((source, false));
        }
        let result = async {
            self.execution_quantum_mut()?.yield_on_worker().await?;
            let mut keep_diagnostics = true;
            for _ in 0..count {
                let item = self
                    .read_close_member::<true>(&mut remaining, keep_diagnostics)
                    .await?;
                if keep_diagnostics {
                    keep_diagnostics = on_close(item);
                }
                self.execution_quantum_mut()?.yield_on_worker().await?;
            }
            self.transport.finish_send_on_owner().await
        }
        .await;
        if let Err(source) = result {
            self.transport.break_connection();
            return Err((source, true));
        }
        let Some(WorkKind::ClosePipeline(progress)) = self.extension().work_kind.take() else {
            self.transport.break_connection();
            return Err((Error::Broken, true));
        };
        self.active = false;
        Ok((progress.members, progress.quantum))
    }

    pub(super) async fn read_close_member<const PIPELINE: bool>(
        &mut self,
        remaining: &mut usize,
        keep_diagnostics: bool,
    ) -> Result<CloseItem, Error> {
        let mut failure = None;
        let max_messages = self.max_messages;
        for frames in 1..=max_messages {
            self.transport.receive_frame_on_owner().await?;
            let frame = self.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            let message = protocol::parse_backend(frame)?;
            let ready = matches!(message, BackendMessage::ReadyForQuery(_));
            let step = match message {
                BackendMessage::ErrorResponse(error) => {
                    if is_fatal(error) {
                        return Err(terminal_database_error(error, Some(*remaining)));
                    }
                    if keep_diagnostics && failure.is_none() {
                        failure = Some(owned_error_bounded(error, remaining)?);
                    }
                    RecoveryStep::Error
                }
                BackendMessage::NoticeResponse(notice) => {
                    crate::client::observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                    RecoveryStep::Noop
                }
                _ => Self::recovery_step(self.extended.as_deref(), false, message)?,
            };
            self.apply_recovery_step(step)?;
            self.transport.consume_frame()?;
            if PIPELINE {
                let quantum = self.execution_quantum_mut()?;
                quantum.spend_bytes(work_bytes);
                if !ready && frames < max_messages {
                    quantum.yield_on_worker().await?;
                }
            }
            if ready {
                return Ok(failure.map_or(Ok(()), Err));
            }
        }
        Err(Error::Limit("Close exceeded its control message limit"))
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 分批关闭连接仍持有的服务端名称，包括已放弃的准备操作所创建的名称。
    /// 限额与 [`Session::close_all_statements`] 相同，仍有外部引用的元数据继续保留。
    pub async fn close_all_statements(
        &mut self,
        limits: StatementPipelineLimits,
    ) -> Result<(), Error> {
        self.session_mut()
            .close_all_statements_scoped(limits, true)
            .await
    }

    /// 在事务内关闭一批语句，每个成员独立 Sync；前面的错误不撤回后续已提交的 Close。
    /// 放弃后须显式恢复。
    pub async fn close_prepared_pipeline(
        &mut self,
        statements: &[&PreparedStatement],
        limits: StatementPipelineLimits,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.session_mut()
            .close_prepared_pipeline_scoped(statements, limits, true)
            .await
    }

    /// 关闭全部活动名称，保留当前事务和共享元数据。
    /// 各成员在各自的 Ready 边界报告 SQL 错误。
    /// 失败事务由调用方处置，结果按注册槽快照顺序交付。
    pub async fn close_all_statements_pipeline(
        &mut self,
        limits: StatementPipelineLimits,
    ) -> Result<Vec<CloseItem>, ClosePipelineError> {
        self.session_mut()
            .close_all_statements_pipeline_scoped(limits, true)
            .await
    }
}
