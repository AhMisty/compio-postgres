//! 整组使用一个 Sync 的有限预备语句批处理，通过回调借用暂定结果。

use crate::transport::WireOps;

use super::{PipelineRequest, QueryRowLimits, WindowQueue};
use crate::{
    Error, Session,
    client::general::{Extended, command_kind},
    client::{CommandKind, Transaction, owned_error_bounded, protocol_error, validate_parameter},
    frontend,
    protocol::{self, BackendMessage, TransactionStatus},
    row::{RowConsumer, RowLayout, RowView},
    scheduler::{BatchQuantum, ExecutionScheduling, byte_work_units},
    transport::{TransportExt, WireTransport},
};

/// 暂定执行结果。
/// 命令标签不确认事务提交；回调结束后，组内后续成员或最终 Sync 仍可能失败。
#[derive(Debug)]
pub enum ProvisionalGroupEvent<'row> {
    Row {
        index: usize,
        row: RowView<'row, 'row>,
    },
    Command {
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    },
}

/// 顺序读取并校验字段的暂定结果。
/// 回调可能先观察有效前缀，之后驱动才发现未读取的后缀无效。
/// 驱动校验全部未读字段和尾部字节；忽略一次读取或解码错误无法使该行恢复有效。
#[derive(Debug)]
pub enum ProvisionalGroupConsumeEvent<'access, 'data, 'meta> {
    Row {
        index: usize,
        row: &'access mut RowConsumer<'data, 'meta>,
    },
    Command {
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    },
}

pub(super) trait GroupVisitor {
    fn row(&mut self, index: usize, body: &[u8], layout: &RowLayout) -> Result<(), Error>;
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<(), Error>;
}

pub(super) struct CheckedVisitor<'callback, F>(pub(super) &'callback mut F);
impl<F> GroupVisitor for CheckedVisitor<'_, F>
where
    F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
{
    fn row(&mut self, index: usize, body: &[u8], layout: &RowLayout) -> Result<(), Error> {
        let data = protocol::parse_data_row(body)?;
        let row = RowView::new(data, layout)?;
        self.0(ProvisionalGroupEvent::Row { index, row })
    }
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<(), Error> {
        self.0(ProvisionalGroupEvent::Command {
            index,
            command,
            rows_affected,
            rows_returned,
        })
    }
}

pub(super) struct ConsumingVisitor<'callback, F>(pub(super) &'callback mut F);
impl<F> GroupVisitor for ConsumingVisitor<'_, F>
where
    F: for<'access, 'data, 'meta> FnMut(
        ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
    ) -> Result<(), Error>,
{
    fn row(&mut self, index: usize, body: &[u8], layout: &RowLayout) -> Result<(), Error> {
        let mut consumer = RowConsumer::from_body(body, layout)?;
        let result = self.0(ProvisionalGroupConsumeEvent::Row {
            index,
            row: &mut consumer,
        });
        consumer.finish()?;
        result
    }
    fn command(
        &mut self,
        index: usize,
        command: CommandKind,
        rows_affected: Option<u64>,
        rows_returned: usize,
    ) -> Result<(), Error> {
        self.0(ProvisionalGroupConsumeEvent::Command {
            index,
            command,
            rows_affected,
            rows_returned,
        })
    }
}

/// 收到整组 ReadyForQuery 且本地发送完成后返回。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSyncCompletion {
    pub requests: usize,
    pub groups: usize,
    pub rows_returned: usize,
    pub transaction_status: TransactionStatus,
}

/// 单组、动态组窗口或冻结重放停止时的协议进度。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GroupPipelineProgress {
    /// 已交给传输的非空组数。服务端可能尚未接收或执行这些组。
    pub admitted_groups: usize,
    /// 已交给传输的组包含的语句数。
    pub admitted_requests: usize,
    /// 已校验并消费 ReadyForQuery 的组数。等待本地发送完成期间仍保留此进度。
    /// 遇到 SQL 错误即停止读取，该组的 Ready 可能尚未被消费。
    pub ready_groups: usize,
    /// 已消费 ReadyForQuery 的组包含的语句数。
    pub ready_requests: usize,
    /// 本次流水线最后观察到的 Ready 状态。显式事务仍须确认事务结束结果。
    pub last_ready_transaction_status: Option<TransactionStatus>,
}

/// 分组执行提前结束的原因及已经观察到的进度。
/// 回调可能已交付本次失败组的暂定结果。已接纳的后续组也可能已经执行。
#[derive(Debug)]
pub struct GroupPipelineError {
    pub source: Error,
    pub progress: GroupPipelineProgress,
}

impl std::fmt::Display for GroupPipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "group pipeline stopped after {} of {} admitted groups reached Ready: {}",
            self.progress.ready_groups, self.progress.admitted_groups, self.source
        )
    }
}

impl std::error::Error for GroupPipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// 单个暂定同步组的限额。首次发送后发生错误或放弃操作时必须丢弃会话。
#[derive(Debug, Clone, Copy)]
pub struct ProvisionalGroupLimits {
    pub max_requests: usize,
    pub max_rows: usize,
    /// 每个成员可交付的行字节总数，也是单个数据库诊断的存储上限。
    pub max_member_result_bytes: usize,
    /// 编码组与处理响应时共用的协作调度策略。
    pub scheduling: ExecutionScheduling,
}

impl ProvisionalGroupLimits {
    pub(super) fn budgets(self) -> GroupBounds {
        GroupBounds {
            max_requests: self.max_requests,
            max_rows: self.max_rows,
            max_member_result_bytes: self.max_member_result_bytes,
        }
    }
}

/// 编码组及读取响应实际使用的限额。
#[derive(Debug, Clone, Copy)]
pub(super) struct GroupBounds {
    pub(super) max_requests: usize,
    pub(super) max_rows: usize,
    pub(super) max_member_result_bytes: usize,
}

/// 有限同步组序列的限额。
/// 空输入切片消耗 max_groups 的一个名额，不发送 SQL。
#[derive(Debug, Clone, Copy)]
pub struct GroupPipelineLimits {
    pub max_requests: usize,
    pub max_groups: usize,
    pub max_rows: usize,
    /// 每个成员可交付的行字节总数，也是单个数据库诊断的存储上限。
    pub max_member_result_bytes: usize,
    pub max_packet_bytes: usize,
    /// 已接纳的在途同步组数上限，包含当前组，必须为正。
    /// 保留的描述符数量还受 max_groups、max_requests 和迭代器给出的长度上界约束。
    /// 每个组仍独立 Sync。
    pub max_inflight_groups: usize,

    /// 整个输入序列共用的调度预算。
    pub scheduling: ExecutionScheduling,
}

impl GroupPipelineLimits {
    pub(super) fn budgets(self) -> GroupBounds {
        GroupBounds {
            max_requests: self.max_requests,
            max_rows: self.max_rows,
            max_member_result_bytes: self.max_member_result_bytes,
        }
    }
}

/// 静态选择让连续执行的接收路径免去每帧的调度分支和工作量计数。
pub(super) trait GroupTurn {
    async fn checkpoint(&mut self, bytes: usize) -> Result<(), Error>;
}

pub(super) struct Uninterrupted;

impl GroupTurn for Uninterrupted {
    async fn checkpoint(&mut self, _: usize) -> Result<(), Error> {
        Ok(())
    }
}

impl GroupTurn for BatchQuantum {
    async fn checkpoint(&mut self, bytes: usize) -> Result<(), Error> {
        self.spend(byte_work_units(bytes));
        self.yield_on_worker().await
    }
}

pub(super) struct GroupDelivery<'callback, V, S> {
    pub(super) visitor: &'callback mut V,
    pub(super) turn: &'callback mut S,
}

#[derive(Default)]
pub(super) struct GroupProgress {
    pub(super) admitted_requests: usize,
    pub(super) admitted_groups: usize,
    pub(super) completed_requests: usize,
    pub(super) rows: usize,
    pub(super) groups: usize,
}

impl GroupProgress {
    pub(super) fn admit_group(&mut self, requests: usize) {
        self.admitted_groups += 1;
        self.admitted_requests += requests;
    }

    pub(super) fn failure(
        self,
        source: Error,
        transaction_status: TransactionStatus,
    ) -> GroupPipelineError {
        GroupPipelineError {
            source,
            progress: GroupPipelineProgress {
                admitted_groups: self.admitted_groups,
                admitted_requests: self.admitted_requests,
                ready_groups: self.groups,
                ready_requests: self.completed_requests,
                last_ready_transaction_status: (self.groups != 0).then_some(transaction_status),
            },
        }
    }
}

struct GroupPending<'input> {
    requests: Option<&'input [PipelineRequest<'input>]>,
    packet: Vec<u8>,
    packet_limit: usize,
}

struct GroupStream<'source, 'input, I: ?Sized> {
    source: &'source mut I,
    examined: usize,
    limits: GroupPipelineLimits,
    // 只保留已提交且尚未开始读取的组，并按提交顺序读取。
    admitted: WindowQueue<&'input [PipelineRequest<'input>]>,
    pending: GroupPending<'input>,
    ended: bool,
}

pub(super) trait GroupMember {
    fn layout(&self) -> &RowLayout;
    fn row_limits(&self) -> QueryRowLimits;
}

impl GroupMember for PipelineRequest<'_> {
    fn layout(&self) -> &RowLayout {
        self.statement.shared_layout()
    }
    fn row_limits(&self) -> QueryRowLimits {
        self.limits.into()
    }
}

/// 读取当前组时可同时推进后续成员接纳。
/// drive 不能等待发送完成，以便同一轮仍可轮询接收。
/// Some(bytes) 表示已完成的一步输入、编码或提交，用于扣除共享预算。
pub(super) trait GroupAdmission<T: WireTransport> {
    fn is_active(&self, _progress: &GroupProgress) -> bool {
        true
    }
    fn drive(
        &mut self,
        session: &mut Session<T>,
        progress: &mut GroupProgress,
        cx: &mut std::task::Context<'_>,
    ) -> Result<Option<usize>, Error>;
}

pub(super) struct NoGroupAdmission;
impl<T: WireTransport> GroupAdmission<T> for NoGroupAdmission {
    fn is_active(&self, _: &GroupProgress) -> bool {
        false
    }
    fn drive(
        &mut self,
        _: &mut Session<T>,
        _: &mut GroupProgress,
        _: &mut std::task::Context<'_>,
    ) -> Result<Option<usize>, Error> {
        Ok(None)
    }
}

impl<'input, T, I> GroupAdmission<T> for GroupStream<'_, 'input, I>
where
    T: WireTransport,
    I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
{
    fn is_active(&self, progress: &GroupProgress) -> bool {
        !self.ended && progress.admitted_groups - progress.groups < self.limits.max_inflight_groups
    }
    fn drive(
        &mut self,
        session: &mut Session<T>,
        progress: &mut GroupProgress,
        cx: &mut std::task::Context<'_>,
    ) -> Result<Option<usize>, Error> {
        if !<Self as GroupAdmission<T>>::is_active(self, progress) {
            return Ok(None);
        }
        if self.pending.requests.is_some() {
            // 队列仍有空间即可接纳，不必等待当前发送完成；接收轮询会推进发送。
            if !session.try_admit_group(&mut self.pending, progress)? {
                return Ok(None);
            }
            self.admitted
                .push_back(self.pending.requests.take().ok_or(Error::Broken)?)?;
            session.poll_group_send_on_owner(cx)?;
            return Ok(Some(0));
        }
        let Some(requests) = self.source.next() else {
            self.ended = true;
            return Ok(Some(0));
        };
        if self.examined == self.limits.max_groups {
            return Err(Error::Limit("group stream exceeds its input group limit"));
        }
        self.examined += 1;
        if requests.is_empty() {
            return Ok(Some(0));
        }
        self.pending.requests = Some(requests);
        session.prepare_pending_group(&mut self.pending, progress, self.limits)?;
        Ok(Some(self.pending.packet.len()))
    }
}

async fn next_group<'input, I, S>(
    source: &mut I,
    examined: &mut usize,
    max_groups: usize,
    turn: &mut S,
) -> Result<Option<&'input [PipelineRequest<'input>]>, Error>
where
    I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
    S: GroupTurn,
{
    for requests in source {
        // 空切片也应扣除输入工作量。
        // 有界检查点置于 next() 之间。
        turn.checkpoint(0).await?;
        if *examined == max_groups {
            return Err(Error::Limit("group stream exceeds its input group limit"));
        }
        *examined += 1;
        if !requests.is_empty() {
            return Ok(Some(requests));
        }
    }
    Ok(None)
}

/// 首次提交后的异常退出，包括放弃 future 和 panic，都禁止复用。
pub(super) struct GroupGuard<'session, T: WireTransport> {
    pub(super) session: &'session mut Session<T>,
    pub(super) finished: bool,
    pub(super) started: bool,
}

impl<T: WireTransport> Drop for GroupGuard<'_, T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.started {
            self.session.transport.break_connection();
        } else {
            // 入口已确认会话没有其他活动操作，提交前最多只创建了空的私有发送队列。
            let _ = self.session.transport.disable_send_queue();
            self.session.active = false;
        }
    }
}

impl<T: WireTransport> Session<T> {
    /// 全部输入先校验并编码，整组只发送一个 Sync，逐行借用暂定结果。
    /// 成员通常共享隐式事务，显式事务仍须自行提交。
    /// DDL、事务控制等 SQL 保留 PostgreSQL 自身语义；依赖会话或 schema 变化的请求应分批提交。
    ///
    /// 回调先于最终 Ready，须立即返回且不能保留借用。
    /// 首次发送后，SQL 错误、回调失败或 panic、协议或 I/O 错误、放弃 future 均要求丢弃会话；已执行的 SQL 不会撤销。
    /// 事务句柄内应使用专用事务控制 API；在组内观察到事务控制标签会丢弃连接。
    ///
    /// 请求数与行数按整个调用累计。每个成员独立核算行字节（每行含四字节长度），单份诊断另受相同字节上限约束。
    /// 收发缓冲另行计费，不为结果或恢复分配行缓冲。
    /// 错误保留整组接纳与 Ready 确认的进度。
    pub async fn query_group_provisional_visit<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.query_group_with_visitor(requests, limits, &mut CheckedVisitor(&mut on_event), false)
            .await
    }

    /// 以一次 Sync 执行整组并逐字段校验。
    /// 回调可能读到有效前缀后，才发现尚未读取的后缀无效。
    /// 驱动在回调返回后校验剩余字段；已发生的读取或解码错误不可忽略。
    /// 提交边界、暂定交付及出错或放弃后的处置同逐行入口。
    pub async fn query_group_provisional_consume<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.query_group_with_visitor(
            requests,
            limits,
            &mut ConsumingVisitor(&mut on_event),
            false,
        )
        .await
    }

    async fn query_group_with_visitor<V>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: ProvisionalGroupLimits,
        on_event: &mut V,
        in_transaction: bool,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        V: GroupVisitor,
    {
        let mut progress = GroupProgress::default();
        let result = match limits.scheduling {
            ExecutionScheduling::Uninterrupted => {
                self.query_group_with_turn(
                    requests,
                    limits.budgets(),
                    on_event,
                    in_transaction,
                    &mut Uninterrupted,
                    &mut progress,
                )
                .await
            }
            ExecutionScheduling::Cooperative { max_work_per_turn } => {
                let mut turn = BatchQuantum::new(max_work_per_turn);
                self.query_group_with_turn(
                    requests,
                    limits.budgets(),
                    on_event,
                    in_transaction,
                    &mut turn,
                    &mut progress,
                )
                .await
            }
        };
        result.map_err(|source| progress.failure(source, self.transaction_status))
    }

    async fn query_group_with_turn<V: GroupVisitor, S: GroupTurn>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: GroupBounds,
        on_event: &mut V,
        in_transaction: bool,
        turn: &mut S,
        progress: &mut GroupProgress,
    ) -> Result<GroupSyncCompletion, Error> {
        self.check_idle_access(in_transaction)?;
        if requests.is_empty() {
            return Ok(GroupSyncCompletion {
                requests: 0,
                groups: 0,
                rows_returned: 0,
                transaction_status: self.transaction_status,
            });
        }
        if limits.max_requests == 0 || requests.len() > limits.max_requests {
            return Err(Error::Limit("group request count exceeds its limit"));
        }
        let bytes = self.transport.encode_send_buffer(|bytes| {
            Self::encode_group_into(
                self.id,
                self.extended.as_deref(),
                requests,
                limits,
                bytes,
                self.max_request_len,
            )
        })?;
        turn.checkpoint(bytes.len()).await?;
        self.active = true;
        self.remaining_boundaries = 1;
        let mut guard = GroupGuard {
            session: self,
            finished: false,
            started: true,
        };
        guard.session.transport.begin_send(bytes)?;
        progress.admit_group(requests.len());
        let transaction_status = guard
            .session
            .read_group(
                requests,
                limits,
                &mut GroupDelivery {
                    visitor: on_event,
                    turn,
                },
                progress,
                in_transaction,
                &mut NoGroupAdmission,
            )
            .await?;
        guard.session.transport.finish_send_on_owner().await?;
        guard.session.active = false;
        guard.finished = true;
        Ok(GroupSyncCompletion {
            requests: progress.completed_requests,
            groups: progress.groups,
            rows_returned: progress.rows,
            transaction_status,
        })
    }

    /// 逐步提交有限个预备语句组，每个非空切片使用一次 Sync。
    /// 最多保留 `min(max_inflight_groups, max_groups, max_requests)` 个已接纳组描述符和一个预读切片，包缓冲受 max_packet_bytes 限制。
    /// 行和命令使用跨组索引。
    /// 空切片消耗一个输入名额；超限时可能额外读取一项，但不会截断切片。
    /// 首组校验并编码成功后才预留窗口描述符。
    /// 在途、待发和私有预读的包按实际编码量增长，单包容量受 `max_packet_bytes` 限制。
    ///
    /// 成功需输入结束、全部 Ready 和本地发送完成。
    /// 后组可能在前组确认前提交；早先的组可能已提交事务，后续已接纳的组在错误后仍可能执行。
    /// 回调交付的是暂定结果。
    /// 提交后出错、panic 或放弃 future 都须丢弃会话。
    /// 涉及会话、schema 或事务转换时，请在转换前后分批执行。
    /// 整个序列共用一个协作预算。
    pub async fn query_groups_provisional_visit<'input, I, F>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.query_groups_with_visitor(source, limits, &mut CheckedVisitor(&mut on_event), false)
            .await
    }

    /// 与 [`Self::query_groups_provisional_visit`] 使用相同窗口、接纳和丢弃规则，按顺序借用字段。
    /// 回调可能观察到有效前缀；驱动检查全部未读字段，不能以忽略错误的方式接纳无效行。
    /// 不会分配字段偏移表或结果缓冲。
    pub async fn query_groups_provisional_consume<'input, I, F>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.query_groups_with_visitor(source, limits, &mut ConsumingVisitor(&mut on_event), false)
            .await
    }

    async fn query_groups_with_visitor<'input, I, V>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        on_event: &mut V,
        in_transaction: bool,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        V: GroupVisitor,
    {
        let mut progress = GroupProgress::default();
        let result = match limits.scheduling {
            ExecutionScheduling::Uninterrupted => {
                self.query_groups_with_turn(
                    source,
                    limits,
                    on_event,
                    in_transaction,
                    &mut Uninterrupted,
                    &mut progress,
                )
                .await
            }
            ExecutionScheduling::Cooperative { max_work_per_turn } => {
                let mut turn = BatchQuantum::new(max_work_per_turn);
                self.query_groups_with_turn(
                    source,
                    limits,
                    on_event,
                    in_transaction,
                    &mut turn,
                    &mut progress,
                )
                .await
            }
        };
        result.map_err(|source| progress.failure(source, self.transaction_status))
    }

    async fn query_groups_with_turn<'input, I, V, S>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        on_event: &mut V,
        in_transaction: bool,
        turn: &mut S,
        progress: &mut GroupProgress,
    ) -> Result<GroupSyncCompletion, Error>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        V: GroupVisitor,
        S: GroupTurn,
    {
        self.check_idle_access(in_transaction)?;
        if limits.max_inflight_groups == 0 {
            return Err(Error::InvalidInput(
                "group stream needs a positive in-flight group limit",
            ));
        }
        if limits.max_packet_bytes == 0 || limits.max_packet_bytes > self.max_request_len {
            return Err(Error::InvalidInput(
                "group packet capacity exceeds its connection bound",
            ));
        }
        let window = limits
            .max_inflight_groups
            .min(limits.max_groups)
            .min(limits.max_requests)
            .min(source.size_hint().1.unwrap_or(usize::MAX).max(1));
        window
            .checked_mul(std::mem::size_of::<&[PipelineRequest<'_>]>())
            .filter(|bytes| isize::try_from(*bytes).is_ok())
            .ok_or(Error::Limit("group window metadata size overflow"))?;
        let mut examined = 0;
        let Some(first) = next_group(source, &mut examined, limits.max_groups, turn).await? else {
            return Ok(GroupSyncCompletion {
                requests: 0,
                groups: 0,
                rows_returned: 0,
                transaction_status: self.transaction_status,
            });
        };
        self.active = true;
        let mut guard = GroupGuard {
            session: self,
            finished: false,
            started: false,
        };
        let packet = guard
            .session
            .transport
            .start_send_queue(limits.max_packet_bytes)?;
        let mut pending = GroupPending {
            requests: Some(first),
            packet,
            packet_limit: limits.max_packet_bytes,
        };
        let read_limits = limits.budgets();
        let mut admitted = WindowQueue::default();
        let prepared = guard
            .session
            .prepare_pending_group(&mut pending, progress, limits)
            .and_then(|()| admitted.prepare(window, window));
        if let Err(error) = prepared {
            // 首组尚未交给传输，丢弃未提交的前缀并归还暂存空间。
            pending.packet.clear();
            let _ = guard
                .session
                .transport
                .recycle_send_queue_buffer(pending.packet);
            return Err(error);
        }
        turn.checkpoint(pending.packet.len()).await?;
        guard.started = true;
        if !guard.session.try_admit_group(&mut pending, progress)? {
            return Err(Error::Broken);
        }
        admitted.push_back(pending.requests.take().ok_or(Error::Broken)?)?;
        let mut stream = GroupStream {
            source,
            examined,
            limits: GroupPipelineLimits {
                max_inflight_groups: window,
                ..limits
            },
            admitted,
            pending,
            ended: false,
        };
        loop {
            // 编码预读输入前先尝试推进当前连接发送；Pending 时仍需接收响应。
            guard.session.advance_group_send().await?;
            while let Some(bytes) = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(stream.drive(guard.session, progress, cx))
            })
            .await?
            {
                turn.checkpoint(bytes).await?;
            }
            let current = loop {
                if let Some(current) = stream.admitted.pop_front() {
                    break current;
                }
                if stream.ended {
                    guard
                        .session
                        .transport
                        .recycle_send_queue_buffer(stream.pending.packet)?;
                    guard.session.transport.finish_send_on_owner().await?;
                    guard.session.transport.disable_send_queue()?;
                    guard.session.active = false;
                    guard.finished = true;
                    return Ok(GroupSyncCompletion {
                        requests: progress.completed_requests,
                        groups: progress.groups,
                        rows_returned: progress.rows,
                        transaction_status: guard.session.transaction_status,
                    });
                }
                // 当前组已收到 Ready，等待下一个包的发送完成不会阻塞未读取的组响应。
                let bytes = guard
                    .session
                    .wait_protocol_on_owner(|session, cx| {
                        match stream.drive(session, progress, cx) {
                            Ok(Some(bytes)) => std::task::Poll::Ready(Ok(bytes)),
                            Ok(None) => {
                                // 已无当前组继续轮询接收，应在这里刷新发送唤醒器并重新检查队列空间。
                                session.poll_group_send_on_owner(cx)?;
                                match stream.drive(session, progress, cx) {
                                    Ok(Some(bytes)) => std::task::Poll::Ready(Ok(bytes)),
                                    Ok(None) => std::task::Poll::Pending,
                                    Err(error) => std::task::Poll::Ready(Err(error)),
                                }
                            }
                            Err(error) => std::task::Poll::Ready(Err(error)),
                        }
                    })
                    .await?;
                turn.checkpoint(bytes).await?;
            };
            guard
                .session
                .read_group(
                    current,
                    read_limits,
                    &mut GroupDelivery {
                        visitor: on_event,
                        turn,
                    },
                    progress,
                    in_transaction,
                    &mut stream,
                )
                .await?;
        }
    }

    fn prepare_pending_group(
        &mut self,
        pending: &mut GroupPending<'_>,
        progress: &GroupProgress,
        limits: GroupPipelineLimits,
    ) -> Result<(), Error> {
        let requests = pending.requests.ok_or(Error::Broken)?;
        if requests.len() > limits.max_requests - progress.admitted_requests {
            return Err(Error::Limit("group stream exceeds its request limit"));
        }
        Self::encode_group_into(
            self.id,
            self.extended.as_deref(),
            requests,
            limits.budgets(),
            &mut pending.packet,
            limits.max_packet_bytes,
        )?;
        // 刚核对过全部成员，只有之后观察到的服务器状态变化需要再次检查。
        self.take_group_statement_changes();
        Ok(())
    }

    fn try_admit_group(
        &mut self,
        pending: &mut GroupPending<'_>,
        progress: &mut GroupProgress,
    ) -> Result<bool, Error> {
        let Some(requests) = pending.requests else {
            return Ok(false);
        };
        // 保持一个组对应一个自有发送包。
        // 在非空缓冲后追加会复制数据并合并不同同步组。
        if self.transport.send_queue_available() != pending.packet_limit {
            return Ok(false);
        }
        if self.take_group_statement_changes() {
            for request in requests {
                self.check_prepared_snapshot(request.statement, true)?;
            }
        }
        if !self.transport.enqueue_send_packet(&mut pending.packet)? {
            return Ok(false);
        }
        self.remaining_boundaries += 1;
        progress.admit_group(requests.len());
        Ok(true)
    }

    pub(super) fn poll_group_send_on_owner(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        if let std::task::Poll::Ready(Err(error)) = self.transport.poll_finish_send_on_owner(cx) {
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn advance_group_send(&mut self) -> Result<(), Error> {
        std::future::poll_fn(|cx| std::task::Poll::Ready(self.poll_group_send_on_owner(cx))).await
    }

    async fn receive_group_frame<A: GroupAdmission<T>, S: GroupTurn>(
        &mut self,
        admission: &mut A,
        progress: &mut GroupProgress,
        turn: &mut S,
    ) -> Result<(), Error> {
        loop {
            if !admission.is_active(progress) {
                return self.transport.receive_frame_on_owner().await;
            }
            let (received, work) = self
                .wait_protocol_on_owner(|session, cx| {
                    let work = match admission.drive(session, progress, cx) {
                        Ok(work) => work,
                        Err(error) => return std::task::Poll::Ready(Err(error)),
                    };
                    match session.transport.poll_receive_frame_on_owner(cx) {
                        std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                        std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok((true, work))),
                        std::task::Poll::Pending => {
                            let work = match work {
                                Some(bytes) => Some(bytes),
                                None => match admission.drive(session, progress, cx) {
                                    Ok(work) => work,
                                    Err(error) => return std::task::Poll::Ready(Err(error)),
                                },
                            };
                            match work {
                                Some(bytes) => std::task::Poll::Ready(Ok((false, Some(bytes)))),
                                None => std::task::Poll::Pending,
                            }
                        }
                    }
                })
                .await?;
            if let Some(bytes) = work {
                turn.checkpoint(bytes).await?;
            }
            if received {
                return Ok(());
            }
        }
    }

    fn encode_group_into(
        connection_id: u64,
        extended: Option<&Extended>,
        requests: &[PipelineRequest<'_>],
        limits: GroupBounds,
        bytes: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Result<(), Error> {
        bytes.clear();
        for request in requests {
            let admission =
                Self::resolve_prepared(connection_id, extended, request.statement, true)?;
            if request.limits.max_result_bytes > limits.max_member_result_bytes {
                return Err(Error::Limit(
                    "member result byte limit exceeds the group configuration",
                ));
            }
            admission.validate_metadata(
                request.limits.max_metadata_bytes,
                "group member metadata exceeds its query limit",
            )?;
            let matched = admission.parameters(
                request.parameters,
                "group parameter count differs from its statement",
            )?;
            admission
                .packet(
                    &matched,
                    protocol::QueryTail::Open,
                    max_packet_bytes,
                    "group parameter type differs from its statement",
                    || Ok(()),
                )?
                .append_to(bytes, max_packet_bytes)?;
        }
        frontend::append_sync(bytes, max_packet_bytes)?;
        Ok(())
    }

    pub(super) async fn read_group<M, V, A, S>(
        &mut self,
        requests: &[M],
        limits: GroupBounds,
        delivery: &mut GroupDelivery<'_, V, S>,
        progress: &mut GroupProgress,
        in_transaction: bool,
        admission: &mut A,
    ) -> Result<TransactionStatus, Error>
    where
        M: GroupMember,
        V: GroupVisitor,
        A: GroupAdmission<T>,
        S: GroupTurn,
    {
        for (member_index, request) in requests.iter().enumerate() {
            let index = progress.completed_requests + member_index;
            let member_limits = request.row_limits();
            let layout = request.layout();
            let mut bound = false;
            let mut rows = 0;
            let mut row_bytes_left = member_limits.max_result_bytes;
            let mut controls = 0;
            loop {
                self.receive_group_frame(admission, progress, delivery.turn)
                    .await?;
                let frame = self.transport.frame()?;
                let work_bytes = frame.body.len().saturating_add(5);
                let mut completed = false;
                let mut path_changed = false;
                let mut statement_reset = false;
                if frame.tag == b'D' {
                    if !bound {
                        return Err(protocol_error("DataRow before group BindComplete"));
                    }
                    if rows >= member_limits.max_rows || progress.rows >= limits.max_rows {
                        return Err(Error::Limit("group row count limit exceeded"));
                    }
                    row_bytes_left = row_bytes_left
                        .checked_sub(super::data_row_record_len(frame.body)?)
                        .ok_or(Error::Limit("group member row byte limit exceeded"))?;
                    delivery.visitor.row(index, frame.body, layout)?;
                    rows += 1;
                    progress.rows += 1;
                } else {
                    if controls == self.max_messages {
                        return Err(Error::Limit(
                            "group member exceeded its control message limit",
                        ));
                    }
                    controls += 1;
                    let message = protocol::parse_backend(frame)?;
                    match message {
                        BackendMessage::BindComplete if !bound => bound = true,
                        BackendMessage::CommandComplete(tag) if bound => {
                            let (command, rows_affected) =
                                command_kind(protocol::parse_command_tag(tag)?);
                            statement_reset = matches!(
                                command,
                                CommandKind::DeallocateAll | CommandKind::DiscardAll
                            );
                            if in_transaction
                                && matches!(
                                    command,
                                    CommandKind::Begin
                                        | CommandKind::Commit
                                        | CommandKind::Rollback
                                        | CommandKind::Savepoint
                                        | CommandKind::Release
                                )
                            {
                                if command == CommandKind::Commit {
                                    self.record_query_transaction_end(command)?;
                                }
                                return Err(Error::Unsupported(
                                    "transaction controls must use the transaction methods outside a prepared group",
                                ));
                            }
                            delivery
                                .visitor
                                .command(index, command, rows_affected, rows)?;
                            completed = true;
                        }
                        BackendMessage::EmptyQueryResponse if bound => {
                            delivery
                                .visitor
                                .command(index, CommandKind::Empty, None, rows)?;
                            completed = true;
                        }
                        BackendMessage::ErrorResponse(error) => {
                            let mut budget = limits.max_member_result_bytes;
                            return Err(Error::Database(owned_error_bounded(error, &mut budget)?));
                        }
                        BackendMessage::ParameterStatus { name, value } => {
                            validate_parameter(name, value)?;
                            path_changed = name == "search_path";
                        }
                        BackendMessage::NoticeResponse(notice) => {
                            crate::client::observe_notice(notice, self.notice_handler.as_ref())
                                .finish(&mut self.transport);
                        }
                        BackendMessage::NotificationResponse { .. } => {}
                        _ => {
                            return Err(protocol_error(
                                "unexpected response in the prepared group",
                            ));
                        }
                    }
                }
                self.transport.consume_frame()?;
                if path_changed {
                    self.bump_schema_epoch()?;
                }
                if statement_reset {
                    self.note_server_statement_reset()?;
                }
                delivery.turn.checkpoint(work_bytes).await?;
                if completed {
                    break;
                }
            }
        }
        let mut controls = 0;
        loop {
            self.receive_group_frame(admission, progress, delivery.turn)
                .await?;
            let frame = self.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            let message = protocol::parse_backend(frame)?;
            if controls == self.max_messages {
                return Err(Error::Limit(
                    "group Sync exceeded its control message limit",
                ));
            }
            controls += 1;
            let mut ready = None;
            let mut path_changed = false;
            match message {
                BackendMessage::ReadyForQuery(status)
                    if status != TransactionStatus::FailedTransaction
                        && (!in_transaction || status == TransactionStatus::InTransaction) =>
                {
                    ready = Some(status)
                }
                BackendMessage::ErrorResponse(error) => {
                    let mut budget = limits.max_member_result_bytes;
                    return Err(Error::Database(owned_error_bounded(error, &mut budget)?));
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    path_changed = name == "search_path";
                }
                BackendMessage::NoticeResponse(notice) => {
                    crate::client::observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                }
                BackendMessage::NotificationResponse { .. } => {}
                _ => {
                    return Err(protocol_error(
                        "unexpected response after the prepared group",
                    ));
                }
            }
            self.transport.consume_frame()?;
            if path_changed {
                self.bump_schema_epoch()?;
            }
            if let Some(status) = ready {
                self.note_ready(status)?;
                progress.completed_requests += requests.len();
                progress.groups += 1;
                delivery.turn.checkpoint(work_bytes).await?;
                return Ok(status);
            }
            delivery.turn.checkpoint(work_bytes).await?;
        }
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务内以一个 Sync 执行整组。
    /// 行与命令回调均为暂定，成功返回后事务仍然打开。
    /// 事务控制使用专用接口。若服务器已经确认组内 SQL 提交，仍可领取该结果。
    /// 发送后出错或放弃时须丢弃会话。
    pub async fn query_group_provisional_visit<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.session_mut()
            .query_group_with_visitor(requests, limits, &mut CheckedVisitor(&mut on_event), true)
            .await
    }

    /// 在当前事务内逐步执行单 Sync 语句组。
    /// 回调结果暂定，事务控制应独立提交。
    /// 发送后出错或放弃时须丢弃会话。
    pub async fn query_groups_provisional_visit<'input, I, F>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        F: for<'row> FnMut(ProvisionalGroupEvent<'row>) -> Result<(), Error>,
    {
        self.session_mut()
            .query_groups_with_visitor(source, limits, &mut CheckedVisitor(&mut on_event), true)
            .await
    }

    /// 在事务内逐字段读取一组结果。
    /// 可能先观察到有效前缀，再发现未读后缀无效。
    /// 发送后校验错误或放弃时须丢弃会话。
    pub async fn query_group_provisional_consume<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: ProvisionalGroupLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.session_mut()
            .query_group_with_visitor(requests, limits, &mut ConsumingVisitor(&mut on_event), true)
            .await
    }

    /// 在事务内逐字段读取多个单 Sync 组。
    /// 未读后缀仍会被校验，发送后失败或放弃时丢弃会话；Sync 不会提交当前事务。
    pub async fn query_groups_provisional_consume<'input, I, F>(
        &mut self,
        source: &mut I,
        limits: GroupPipelineLimits,
        mut on_event: F,
    ) -> Result<GroupSyncCompletion, GroupPipelineError>
    where
        I: Iterator<Item = &'input [PipelineRequest<'input>]> + ?Sized,
        F: for<'access, 'data, 'meta> FnMut(
            ProvisionalGroupConsumeEvent<'access, 'data, 'meta>,
        ) -> Result<(), Error>,
    {
        self.session_mut()
            .query_groups_with_visitor(source, limits, &mut ConsumingVisitor(&mut on_event), true)
            .await
    }
}

#[cfg(test)]
mod tests;
