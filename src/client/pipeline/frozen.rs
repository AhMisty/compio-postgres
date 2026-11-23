//! 与连接绑定的固定参数执行包，可用于显式重复执行。

use crate::transport::WireOps;
use std::{collections::HashSet, fmt, rc::Rc, task::Poll};

use super::{
    GroupPipelineError, GroupPipelineLimits, GroupSyncCompletion, PipelineRequest,
    ProvisionalGroupConsumeEvent, ProvisionalGroupEvent, ProvisionalGroupLimits, QueryRowLimits,
    group::{
        CheckedVisitor, ConsumingVisitor, GroupAdmission, GroupDelivery, GroupGuard, GroupMember,
        GroupProgress, GroupTurn, GroupVisitor, Uninterrupted,
    },
};
use crate::{
    Error, Session,
    client::{PreparedStatement, Transaction},
    frontend,
    row::RowLayout,
    scheduler::{BatchQuantum, ExecutionScheduling},
    transport::{TransportExt, WireTransport},
};

impl ProvisionalGroupLimits {
    fn for_replay(self, packet_capacity: usize) -> GroupPipelineLimits {
        GroupPipelineLimits {
            max_requests: self.max_requests,
            max_groups: 1,
            max_rows: self.max_rows,
            max_member_result_bytes: self.max_member_result_bytes,
            max_packet_bytes: packet_capacity,
            max_inflight_groups: 1,
            scheduling: self.scheduling,
        }
    }
}

struct FrozenMember {
    layout: Rc<RowLayout>,
    limits: QueryRowLimits,
}

impl GroupMember for FrozenMember {
    fn layout(&self) -> &RowLayout {
        &self.layout
    }

    fn row_limits(&self) -> QueryRowLimits {
        self.limits
    }
}

/// 按首次出现的顺序保留语句快照。
/// 只使用一个语句的组不为句柄分配额外容器。
struct FrozenStatements {
    first: PreparedStatement,
    others: Vec<PreparedStatement>,
}

impl FrozenStatements {
    fn iter(&self) -> impl Iterator<Item = &PreparedStatement> {
        std::iter::once(&self.first).chain(&self.others)
    }
}

// 限制小组去重的快照比较次数，推迟为实际出现的稀疏槽分配索引。
const SPARSE_LINEAR_LIMIT: usize = 8;

/// 小组复用已保留的快照。出现第九个不同的跨字槽时，才为稀疏注册表建立索引。
fn insert_sparse_slot(
    index: &mut Option<HashSet<usize>>,
    slot: usize,
    first_word: usize,
    previous: impl Iterator<Item = usize> + Clone,
) -> Result<bool, Error> {
    const ALLOCATION: Error = Error::Limit("cannot allocate frozen statement snapshots");
    if let Some(seen) = index.as_mut() {
        if seen.len() == seen.capacity() {
            if seen.contains(&slot) {
                return Ok(false);
            }
            seen.try_reserve(1).map_err(|_| ALLOCATION)?;
        }
        return Ok(seen.insert(slot));
    }

    let sparse = previous.filter(|seen| seen / usize::BITS as usize != first_word);
    let mut count = 0;
    for seen in sparse.clone() {
        if seen == slot {
            return Ok(false);
        }
        count += 1;
    }
    if count < SPARSE_LINEAR_LIMIT {
        return Ok(true);
    }

    let mut seen = HashSet::new();
    seen.try_reserve(count + 1).map_err(|_| ALLOCATION)?;
    for earlier in sparse {
        seen.insert(earlier);
    }
    let new = seen.insert(slot);
    *index = Some(seen);
    Ok(new)
}

/// 已编码的 Bind/Execute 组，固定参数、结果格式及各成员的行数和字节限额。
/// 编译时检查语句元数据，重放时仍受原成员的行限额及本次选择的总限额约束。
///
/// 构建时复制一次参数。
/// 每次重放都用同一组字节重新执行 SQL；修改原输入不影响重放。
/// 语句关闭或布局失效后不能继续使用这个包。
///
/// 重放接管所有权，成功完成后返还。
/// 错误或放弃 future 会消耗这个值；已提交的包由传输持有，直到发送完成。
/// 回调可能早于最终 Sync 的确认。
pub struct FrozenEncodedGroup {
    packet: Vec<u8>,
    members: Vec<FrozenMember>,
    statements: FrozenStatements,
    connection_id: u64,
    max_member_result_bytes: usize,
}

impl FrozenEncodedGroup {
    pub fn requests(&self) -> usize {
        self.members.len()
    }

    pub fn encoded_packet_len(&self) -> usize {
        self.packet.len()
    }

    /// 编码包的实际容量，不含元数据与共享的语句布局。
    pub fn packet_capacity(&self) -> usize {
        self.packet.capacity()
    }
}

impl fmt::Debug for FrozenEncodedGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenEncodedGroup")
            .field("requests", &self.members.len())
            .field("encoded_packet_len", &self.packet.len())
            .field("packet_capacity", &self.packet.capacity())
            .finish_non_exhaustive()
    }
}

struct FrozenReplay<'members> {
    members: &'members [FrozenMember],
    statements: &'members FrozenStatements,
    repetitions: usize,
    max_inflight_groups: usize,
    packet_len: usize,
}

impl<T: WireTransport> GroupAdmission<T> for FrozenReplay<'_> {
    fn is_active(&self, progress: &GroupProgress) -> bool {
        progress.admitted_groups != self.repetitions
            && progress.admitted_groups - progress.groups != self.max_inflight_groups
    }

    fn drive(
        &mut self,
        session: &mut Session<T>,
        progress: &mut GroupProgress,
        cx: &mut std::task::Context<'_>,
    ) -> Result<Option<usize>, Error> {
        if progress.admitted_groups == self.repetitions
            || progress.admitted_groups - progress.groups == self.max_inflight_groups
        {
            return Ok(None);
        }
        // 只检查缓冲所有权，避免每个接收帧重复轮询发送。
        // Busy 表示传输仍持有缓冲，随后接收轮询会推进它并登记唤醒器。
        let packet = match session.transport.take_send_packet() {
            Ok(packet) => packet,
            Err(Error::Busy) => return Ok(None),
            Err(error) => return Err(error),
        };
        if session.take_group_statement_changes() {
            for statement in self.statements.iter() {
                session.check_prepared_snapshot(statement, true)?;
            }
        }
        // 取回的是上一次发送完成后的完整原包，此处不会夺取在途缓冲。
        if packet.len() != self.packet_len {
            return Err(Error::Broken);
        }
        session.transport.begin_send(packet)?;
        session.remaining_boundaries += 1;
        progress.admit_group(self.members.len());
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::frozen_replay(self.packet_len);
        // 新包交付后轮询一次本连接的发送，避免连续读取缓存帧时延迟发送。
        session.poll_group_send_on_owner(cx)?;
        Ok(Some(0))
    }
}

impl<T: WireTransport> Session<T> {
    /// 在本地复制并编码一个非空组。
    /// 返回的值独立于原参数缓冲，仍绑定当前连接及语句快照。
    /// 此操作不访问数据库。
    pub fn compile_frozen_group(
        &self,
        requests: &[PipelineRequest<'_>],
        max_packet_bytes: usize,
    ) -> Result<FrozenEncodedGroup, Error> {
        if self.transport.is_broken() {
            return Err(Error::Broken);
        }
        let Some(first) = requests.first() else {
            return Err(Error::InvalidInput("a frozen group must contain SQL"));
        };
        if max_packet_bytes == 0 || max_packet_bytes > self.max_request_len {
            return Err(Error::InvalidInput(
                "frozen packet capacity exceeds its connection bound",
            ));
        }
        if !frontend::group_members_fit(requests.len(), max_packet_bytes) {
            return Err(Error::Limit("frozen members cannot fit their packet bound"));
        }
        let mut packet = Vec::new();
        let mut members = Vec::new();
        let mut others: Vec<PreparedStatement> = Vec::new();
        let first_slot = first.statement.slot_index();
        let first_word = first_slot / usize::BITS as usize;
        let mut inline = 0usize;
        let mut bitmap = Vec::<usize>::new();
        let mut sparse_slots = None::<HashSet<usize>>;
        let slot_words = self
            .extended
            .as_deref()
            .map_or(0, |state| state.statement_slot_count())
            .div_ceil(usize::BITS as usize);
        members
            .try_reserve_exact(requests.len())
            .map_err(|_| Error::Limit("cannot allocate frozen group metadata"))?;
        #[cfg(feature = "diagnostics")]
        let mut copied_parameters = 0_usize;
        let mut max_member_result_bytes = 0;
        for request in requests {
            let admission =
                Self::resolve_prepared(self.id, self.extended.as_deref(), request.statement, true)?;
            admission.validate_metadata(
                request.limits.max_metadata_bytes,
                "frozen member metadata exceeds its query limit",
            )?;
            let matched = admission.parameters(
                request.parameters,
                "frozen parameters differ from their prepared statement",
            )?;
            let execution = admission.packet(
                &matched,
                crate::protocol::QueryTail::Open,
                max_packet_bytes,
                "frozen parameters differ from their prepared statement",
                || Ok(()),
            )?;
            execution.append_to(&mut packet, max_packet_bytes)?;
            #[cfg(feature = "diagnostics")]
            {
                copied_parameters = copied_parameters
                    .checked_add(execution.payload_bytes())
                    .ok_or(Error::Limit("frozen parameter byte count overflow"))?;
            }
            // 此处与 resolve_prepared 之间没有变更注册表、回调或挂起点。
            let slot = request.statement.slot_index();
            if slot != first_slot {
                let word = slot / usize::BITS as usize;
                let mask = 1usize << (slot % usize::BITS as usize);
                let new = if word == first_word {
                    let new = inline & mask == 0;
                    inline |= mask;
                    new
                } else if slot_words <= requests.len() {
                    if bitmap.is_empty() {
                        bitmap.try_reserve_exact(slot_words).map_err(|_| {
                            Error::Limit("cannot allocate frozen statement snapshots")
                        })?;
                        bitmap.resize(slot_words, 0);
                    }
                    let bits = bitmap.get_mut(word).ok_or(Error::Broken)?;
                    let new = *bits & mask == 0;
                    *bits |= mask;
                    new
                } else {
                    insert_sparse_slot(
                        &mut sparse_slots,
                        slot,
                        first_word,
                        others.iter().map(PreparedStatement::slot_index),
                    )?
                };
                if new {
                    others
                        .try_reserve(1)
                        .map_err(|_| Error::Limit("cannot allocate frozen statement snapshots"))?;
                    others.push(request.statement.clone());
                }
            }
            members.push(FrozenMember {
                layout: Rc::clone(request.statement.shared_layout()),
                limits: request.limits.into(),
            });
            max_member_result_bytes = max_member_result_bytes.max(request.limits.max_result_bytes);
        }
        frontend::append_sync(&mut packet, max_packet_bytes)?;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::frozen_compile(packet.len(), copied_parameters);
        Ok(FrozenEncodedGroup {
            packet,
            members,
            statements: FrozenStatements {
                first: first.statement.clone(),
                others,
            },
            connection_id: self.id,
            max_member_result_bytes,
        })
    }

    /// 执行冻结组一次，最终 Sync 确认且本地发送完成后才返还执行包。
    /// 出错时消耗执行包。首次发送后出错或放弃 future 还须丢弃会话。
    /// 错误保留整组接纳与 Ready 确认的进度。
    pub async fn replay_frozen_group_provisional_visit<F>(
        &mut self,
        group: FrozenEncodedGroup,
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        let packet_bound = group.packet.capacity();
        self.replay_frozen_with_visitor(
            group,
            1,
            limits.for_replay(packet_bound),
            &mut CheckedVisitor(&mut on_event),
            false,
        )
        .await
    }

    /// 逐字段校验并执行冻结组一次。
    /// 仅成功时返还执行包。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_group_provisional_consume<F>(
        &mut self,
        group: FrozenEncodedGroup,
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        let packet_bound = group.packet.capacity();
        self.replay_frozen_with_visitor(
            group,
            1,
            limits.for_replay(packet_bound),
            &mut ConsumingVisitor(&mut on_event),
            false,
        )
        .await
    }

    /// 用相同 SQL 和参数重复执行，显式限制在途组数。
    /// 每次都会执行 SQL，包括重复写入；该操作不提供幂等重试。
    ///
    /// 同一缓冲仅在本地发送完成后重新提交，等待发送时仍可接收先前响应。
    /// 每次重放无需编码、复制参数或分配成员元数据。
    /// 行和命令回调可能先于最终确认。
    /// 后续组失败前已有组可能已提交；发生错误或回调失败后，其他已提交的组仍可能执行。
    /// 错误携带已接纳和收到 Ready 的组及请求数。
    /// 成功时返还执行包。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_groups_provisional_visit<F>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.replay_frozen_with_visitor(
            group,
            repetitions,
            limits,
            &mut CheckedVisitor(&mut on_event),
            false,
        )
        .await
    }

    /// 顺序读取并校验字段的冻结组重放。
    /// 回调可能先读到有效前缀，再发现未读后缀无效。
    /// 首次发送后出错或放弃 future 须丢弃会话；其余契约见 [`Self::replay_frozen_groups_provisional_visit`]。
    pub async fn replay_frozen_groups_provisional_consume<F>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.replay_frozen_with_visitor(
            group,
            repetitions,
            limits,
            &mut ConsumingVisitor(&mut on_event),
            false,
        )
        .await
    }

    async fn replay_frozen_with_visitor<V>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        on_event: &mut V,
        in_transaction: bool,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        V: GroupVisitor,
    {
        let mut progress = GroupProgress::default();
        let result = match limits.scheduling {
            ExecutionScheduling::Uninterrupted => {
                self.replay_frozen_with_turn(
                    group,
                    repetitions,
                    limits,
                    in_transaction,
                    &mut GroupDelivery {
                        visitor: on_event,
                        turn: &mut Uninterrupted,
                    },
                    &mut progress,
                )
                .await
            }
            ExecutionScheduling::Cooperative { max_work_per_turn } => {
                let mut turn = BatchQuantum::new(max_work_per_turn);
                self.replay_frozen_with_turn(
                    group,
                    repetitions,
                    limits,
                    in_transaction,
                    &mut GroupDelivery {
                        visitor: on_event,
                        turn: &mut turn,
                    },
                    &mut progress,
                )
                .await
            }
        };
        result.map_err(|source| progress.failure(source, self.transaction_status))
    }

    async fn replay_frozen_with_turn<V: GroupVisitor, S: GroupTurn>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        in_transaction: bool,
        delivery: &mut GroupDelivery<'_, V, S>,
        progress: &mut GroupProgress,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), Error> {
        self.check_idle_access(in_transaction)?;
        if group.connection_id != self.id {
            return Err(Error::InvalidInput(
                "frozen group belongs to another connection",
            ));
        }
        if limits.max_inflight_groups == 0 {
            return Err(Error::InvalidInput(
                "frozen replay needs a positive in-flight group limit",
            ));
        }
        if limits.max_packet_bytes == 0
            || limits.max_packet_bytes > self.max_request_len
            || group.packet.len() > limits.max_packet_bytes
            || group.packet.capacity() > limits.max_packet_bytes
        {
            return Err(Error::Limit("frozen packet exceeds its replay capacity"));
        }
        let total = group
            .members
            .len()
            .checked_mul(repetitions)
            .ok_or(Error::Limit("frozen replay request count overflow"))?;
        if repetitions > limits.max_groups || total > limits.max_requests {
            return Err(Error::Limit(
                "frozen replay exceeds its group/request limit",
            ));
        }
        for statement in group.statements.iter() {
            self.check_prepared_snapshot(statement, true)?;
        }
        if group.max_member_result_bytes > limits.max_member_result_bytes {
            return Err(Error::Limit(
                "frozen member result byte limit exceeds the replay configuration",
            ));
        }
        if repetitions == 0 {
            return Ok((
                group,
                GroupSyncCompletion {
                    requests: 0,
                    groups: 0,
                    rows_returned: 0,
                    transaction_status: self.transaction_status,
                },
            ));
        }
        let FrozenEncodedGroup {
            packet,
            members,
            statements,
            connection_id,
            max_member_result_bytes,
        } = group;
        let packet_len = packet.len();
        // 初次提交已核对所有快照，后续重放仅检查运行期间的状态变化。
        self.take_group_statement_changes();
        self.transport.begin_send(packet)?;
        self.active = true;
        self.remaining_boundaries = 1;
        let mut guard = GroupGuard {
            session: self,
            finished: false,
            started: true,
        };
        progress.admit_group(members.len());
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::frozen_replay(packet_len);
        guard.session.advance_group_send().await?;
        let mut replay = FrozenReplay {
            members: &members,
            statements: &statements,
            repetitions,
            max_inflight_groups: limits.max_inflight_groups,
            packet_len,
        };
        let read_limits = limits.budgets();
        for _ in 0..repetitions {
            if progress.admitted_groups == progress.groups {
                guard
                    .session
                    .wait_protocol_on_owner(|session, cx| {
                        if let Err(error) = replay.drive(session, progress, cx) {
                            return Poll::Ready(Err(error));
                        }
                        if progress.admitted_groups > progress.groups {
                            Poll::Ready(Ok(()))
                        } else {
                            // 前一个 Ready 已消费，当前没有可推进发送的接收轮询；此处主动轮询发送并刷新唤醒器。
                            session.poll_group_send_on_owner(cx)?;
                            if let Err(error) = replay.drive(session, progress, cx) {
                                return Poll::Ready(Err(error));
                            }
                            if progress.admitted_groups > progress.groups {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        }
                    })
                    .await?;
            }
            guard
                .session
                .read_group(
                    &members,
                    read_limits,
                    delivery,
                    progress,
                    in_transaction,
                    &mut replay,
                )
                .await?;
        }
        guard.session.transport.finish_send_on_owner().await?;
        let packet = guard.session.transport.take_send_packet()?;
        if packet.len() != packet_len {
            return Err(Error::Broken);
        }
        guard.session.active = false;
        guard.finished = true;
        let completion = GroupSyncCompletion {
            requests: progress.completed_requests,
            groups: progress.groups,
            rows_returned: progress.rows,
            transaction_status: guard.session.transaction_status,
        };
        Ok((
            FrozenEncodedGroup {
                packet,
                members,
                statements,
                connection_id,
                max_member_result_bytes,
            },
            completion,
        ))
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 使用当前连接的语句快照在本地编码组。协议状态在重放时检查。
    /// 编码与快照契约见 [`Session::compile_frozen_group`]。
    pub fn compile_frozen_group(
        &self,
        requests: &[PipelineRequest<'_>],
        max_packet_bytes: usize,
    ) -> Result<FrozenEncodedGroup, Error> {
        self.session()
            .compile_frozen_group(requests, max_packet_bytes)
    }

    /// 在当前事务内重放，契约见 [`Session::replay_frozen_group_provisional_visit`]。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_group_provisional_visit<F>(
        &mut self,
        group: FrozenEncodedGroup,
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        let packet_bound = group.packet.capacity();
        self.session_mut()
            .replay_frozen_with_visitor(
                group,
                1,
                limits.for_replay(packet_bound),
                &mut CheckedVisitor(&mut on_event),
                true,
            )
            .await
    }

    /// 在当前事务内重放，契约见 [`Session::replay_frozen_group_provisional_consume`]。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_group_provisional_consume<F>(
        &mut self,
        group: FrozenEncodedGroup,
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        let packet_bound = group.packet.capacity();
        self.session_mut()
            .replay_frozen_with_visitor(
                group,
                1,
                limits.for_replay(packet_bound),
                &mut ConsumingVisitor(&mut on_event),
                true,
            )
            .await
    }

    /// 在当前事务内重放，契约见 [`Session::replay_frozen_groups_provisional_visit`]。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_groups_provisional_visit<F>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.session_mut()
            .replay_frozen_with_visitor(
                group,
                repetitions,
                limits,
                &mut CheckedVisitor(&mut on_event),
                true,
            )
            .await
    }

    /// 在当前事务内重放，契约见 [`Session::replay_frozen_groups_provisional_consume`]。首次发送后出错或放弃 future 须丢弃会话。
    pub async fn replay_frozen_groups_provisional_consume<F>(
        &mut self,
        group: FrozenEncodedGroup,
        repetitions: usize,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<(FrozenEncodedGroup, GroupSyncCompletion), GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.session_mut()
            .replay_frozen_with_visitor(
                group,
                repetitions,
                limits,
                &mut ConsumingVisitor(&mut on_event),
                true,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{SPARSE_LINEAR_LIMIT, insert_sparse_slot};

    #[test]
    fn sparse_slot_index_is_created_only_after_the_linear_limit() {
        let first_sparse = usize::BITS as usize;
        // 同一个机器字中的槽由内联位图去重，不进入稀疏索引。
        let mut previous = vec![1, 2];
        let mut index = None;
        for slot in first_sparse..first_sparse + SPARSE_LINEAR_LIMIT {
            assert!(insert_sparse_slot(&mut index, slot, 0, previous.iter().copied()).unwrap());
            previous.push(slot);
            assert!(index.is_none());
        }
        assert!(
            !insert_sparse_slot(&mut index, first_sparse, 0, previous.iter().copied()).unwrap()
        );
        assert!(index.is_none());

        let next = first_sparse + SPARSE_LINEAR_LIMIT;
        assert!(insert_sparse_slot(&mut index, next, 0, previous.iter().copied()).unwrap());
        let seen = index.as_ref().unwrap();
        assert_eq!(seen.len(), SPARSE_LINEAR_LIMIT + 1);
        assert!(seen.contains(&next));
        assert!(!seen.contains(&1));
        assert!(!insert_sparse_slot(&mut index, first_sparse, 0, std::iter::empty()).unwrap());
    }
}
