use crate::transport::WireOps;
use std::{collections::VecDeque, fmt, rc::Rc};
mod borrowed_window;
pub(super) use borrowed_window::ProvisionalProgress;
pub use borrowed_window::{
    AbandonPolicy, ProvisionalWindowCompletion, ProvisionalWindowConsumeEvent,
    ProvisionalWindowControl, ProvisionalWindowError, ProvisionalWindowErrorOrigin,
    ProvisionalWindowEvent, ProvisionalWindowLimits,
};
mod frozen;
pub use frozen::FrozenEncodedGroup;
mod group;
pub use group::{
    GroupPipelineError, GroupPipelineLimits, GroupPipelineProgress, GroupSyncCompletion,
    ProvisionalGroupConsumeEvent, ProvisionalGroupEvent, ProvisionalGroupLimits,
};
mod visit;
mod window;
pub use visit::{VisitCompletion, VisitError, VisitLimits};
pub use window::{WindowCompletion, WindowError, WindowLimits, WindowParameters, WindowRequest};

use super::{
    Session, Transaction,
    general::{PreparedStatement, QueryCompletion, QueryLimits, WorkKind, command_kind},
    is_fatal, owned_error_bounded, protocol_error, retain_diagnostic, terminal_database_error,
    validate_parameter,
};
use crate::{
    DatabaseError, Error,
    protocol::{self, BackendMessage},
    row::{AllocationPolicy, OwnedBatch, RowLayout, RowView, ScalarColumn},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::{TransportExt, WireTransport},
    types::Parameter,
};

/// 已确认的批次成员结果。行缓冲仅在同步回调内借用。
#[derive(Debug)]
pub struct ReadyBatchResult<'a> {
    pub rows: &'a OwnedBatch,
    pub completion: QueryCompletion,
}

/// 收到成员 Ready 后交付。诊断也仅在同步回调内借用。
/// 回调须迅速返回，自行保留的副本另计。
#[derive(Debug)]
pub struct ReadyBatchEvent<'a> {
    pub index: usize,
    pub transaction_status: protocol::TransactionStatus,
    pub outcome: Result<ReadyBatchResult<'a>, &'a DatabaseError>,
}

/// 已知输入过多时在提交前拒绝。
/// 对未知长度的输入，以第一项超额元素确认溢出，不编码或发送该项。
struct BatchInputLimit {
    maximum: usize,
    upper: Option<usize>,
}

impl BatchInputLimit {
    fn check(source: &(impl Iterator + ?Sized), maximum: usize) -> Result<Self, Error> {
        let (lower, upper) = source.size_hint();
        if lower > maximum {
            return Err(Error::Limit("batch source exceeds max_requests"));
        }
        Ok(Self { maximum, upper })
    }

    fn window_capacity(&self, configured: usize) -> usize {
        // 已读取的首项始终有一个槽。迭代器给出的上界只用于减少窗口预留。
        configured.min(self.upper.unwrap_or(configured).max(1))
    }

    fn finish(
        self,
        source: &mut (impl Iterator + ?Sized),
        admitted: usize,
        stopped: bool,
        consumed: &mut usize,
    ) -> Result<(), Error> {
        if self.upper.is_none_or(|length| length > self.maximum)
            && !stopped
            && admitted == self.maximum
            && source.next().is_some()
        {
            *consumed = consumed.saturating_add(1);
            return Err(Error::Limit("batch source exceeds max_requests"));
        }
        Ok(())
    }
}

/// 已准备的批次成员，从语句快照取得结果格式及元数据，执行时仍受该成员的查询限额约束。
pub struct PipelineRequest<'a> {
    pub statement: &'a PreparedStatement,
    pub parameters: &'a [Parameter<'a>],
    pub limits: QueryLimits,
}

/// 有限流水线的总限额。
/// 结果预算包含输出向量、自有行缓冲和成员错误；共享布局仍计入语句元数据。
/// 收发、最终错误及扩容时的临时空间另计。
/// 恢复为每个成员保留一个列数，数量受 max_requests 限制。
#[derive(Debug, Clone, Copy)]
pub struct PipelineLimits {
    pub max_requests: usize,
    /// 包含所有已观察到的 DataRow，即使该成员后来因 SQL 错误丢弃结果。
    pub max_rows: usize,
    pub max_result_bytes: usize,
    /// 按总限额和成员限额预分配或增长。
    /// 仍由调用方持有的结果各自拥有行缓冲。
    pub storage: AllocationPolicy,
    /// 编码和处理所有响应帧共用调度预算。
    pub scheduling: ExecutionScheduling,
}

#[derive(Debug)]
pub struct PipelineResult {
    pub rows: OwnedBatch,
    pub completion: QueryCompletion,
}

pub type PipelineItem = Result<PipelineResult, DatabaseError>;

enum MemberRead {
    Confirmed(PipelineItem),
    Drained { sql_error: bool },
    DiagnosticLimit(Error),
    Fatal(Error),
}

impl MemberRead {
    fn into_result(self) -> Result<PipelineItem, Error> {
        match self {
            Self::Confirmed(item) => Ok(item),
            Self::Drained { .. } => Err(Error::Broken),
            Self::DiagnosticLimit(error) | Self::Fatal(error) => Err(error),
        }
    }
}

struct MemberReadOptions {
    storage: AllocationPolicy,
    diagnostic_limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberPhase {
    Bind,
    Rows,
    Complete,
    Failed,
}

#[derive(Clone, Copy)]
pub(super) enum PipelineSignal {
    Bind,
    Row,
    Complete,
    Error,
    Ready(protocol::TransactionStatus),
    Auxiliary,
}

impl PipelineSignal {
    pub(super) fn from_message(message: BackendMessage<'_>) -> Result<Self, Error> {
        match message {
            BackendMessage::BindComplete => Ok(Self::Bind),
            BackendMessage::DataRow(_) => Ok(Self::Row),
            BackendMessage::CommandComplete(_) | BackendMessage::EmptyQueryResponse => {
                Ok(Self::Complete)
            }
            BackendMessage::ErrorResponse(_) => Ok(Self::Error),
            BackendMessage::ReadyForQuery(status) => Ok(Self::Ready(status)),
            BackendMessage::NoticeResponse(_)
            | BackendMessage::NotificationResponse { .. }
            | BackendMessage::ParameterStatus { .. } => Ok(Self::Auxiliary),
            _ => Err(protocol_error(
                "unexpected response in the prepared pipeline",
            )),
        }
    }
}

#[derive(Debug)]
struct WindowMember<L> {
    layout: L,
    limits: QueryRowLimits,
}

/// 元数据只在接纳时检查，排队后保留解码布局和行预算。
#[derive(Debug, Clone, Copy)]
struct QueryRowLimits {
    max_rows: usize,
    max_result_bytes: usize,
}

impl From<QueryLimits> for QueryRowLimits {
    fn from(limits: QueryLimits) -> Self {
        Self {
            max_rows: limits.max_rows,
            max_result_bytes: limits.max_result_bytes,
        }
    }
}

fn data_row_record_len(body: &[u8]) -> Result<usize, Error> {
    if body.len() < 2 {
        return Err(protocol_error("truncated DataRow header"));
    }
    // 结果预算以四字节记录长度替换协议中的两字节列数。
    Ok(body.len() + 2)
}

/// 空闲时只保留能复用的环。单成员槽与协议进度只在活动窗口中存在。
#[derive(Debug, Default)]
pub(super) struct WindowCaches {
    rows: VecDeque<WindowMember<Rc<RowLayout>>>,
    scalars: VecDeque<WindowMember<ScalarColumn>>,
}

#[derive(Debug)]
struct WindowMembers {
    queue: MemberQueue,
    admitted: usize,
    // 读端取走布局后，恢复仍可校验列数并核算此成员的排空预算。
    current: Option<(usize, QueryRowLimits)>,
}

#[derive(Debug)]
enum MemberQueue {
    Rows(WindowQueue<WindowMember<Rc<RowLayout>>>),
    Scalars(WindowQueue<WindowMember<ScalarColumn>>),
}

trait WindowMemberLayout: Sized {
    const SCALAR: bool;

    fn queue(queue: &mut MemberQueue) -> Result<&mut WindowQueue<WindowMember<Self>>, Error>;
    fn columns(&self) -> usize;
}

impl WindowMemberLayout for Rc<RowLayout> {
    const SCALAR: bool = false;

    fn queue(queue: &mut MemberQueue) -> Result<&mut WindowQueue<WindowMember<Self>>, Error> {
        match queue {
            MemberQueue::Rows(queue) => Ok(queue),
            MemberQueue::Scalars(_) => Err(Error::Broken),
        }
    }

    fn columns(&self) -> usize {
        self.len()
    }
}

impl WindowMemberLayout for ScalarColumn {
    const SCALAR: bool = true;

    fn queue(queue: &mut MemberQueue) -> Result<&mut WindowQueue<WindowMember<Self>>, Error> {
        match queue {
            MemberQueue::Rows(_) => Err(Error::Broken),
            MemberQueue::Scalars(queue) => Ok(queue),
        }
    }

    fn columns(&self) -> usize {
        1
    }
}

impl MemberQueue {
    fn len(&self) -> usize {
        match self {
            Self::Rows(queue) => queue.len(),
            Self::Scalars(queue) => queue.len(),
        }
    }

    fn front_columns(&self) -> Option<usize> {
        match self {
            Self::Rows(queue) => queue.front().map(|member| member.layout.len()),
            Self::Scalars(queue) => queue.front().map(|_| 1),
        }
    }

    fn discard_front(&mut self) {
        match self {
            Self::Rows(queue) => {
                queue.pop_front();
            }
            Self::Scalars(queue) => {
                queue.pop_front();
            }
        }
    }
}

/// 单成员窗口直接存放恢复描述符；只有多个在途成员才需要堆上的环。
#[derive(Debug)]
enum WindowQueue<T> {
    Single(Option<T>),
    Ring(VecDeque<T>),
}

impl<T> Default for WindowQueue<T> {
    fn default() -> Self {
        Self::Single(None)
    }
}

impl<T> WindowQueue<T> {
    fn from_cache(
        retained: &mut VecDeque<T>,
        capacity: usize,
        max_capacity: usize,
    ) -> Result<Self, Error> {
        let mut queue = if retained.capacity() == 0 {
            Self::default()
        } else {
            Self::Ring(std::mem::take(retained))
        };
        queue.prepare(capacity, max_capacity)?;
        Ok(queue)
    }

    fn into_cache(self) -> VecDeque<T> {
        match self {
            Self::Single(_) => VecDeque::new(),
            Self::Ring(mut queue) => {
                queue.clear();
                queue
            }
        }
    }

    fn prepare(&mut self, capacity: usize, max_capacity: usize) -> Result<(), Error> {
        if matches!(self, Self::Ring(queue) if queue.capacity() > max_capacity) {
            *self = Self::default();
        }
        match self {
            Self::Single(_) if capacity <= 1 => Ok(()),
            Self::Single(_) => {
                let mut queue = VecDeque::new();
                queue
                    .try_reserve_exact(capacity)
                    .map_err(|_| Error::Limit("cannot allocate bounded window metadata"))?;
                *self = Self::Ring(queue);
                Ok(())
            }
            Self::Ring(queue) => queue
                .try_reserve_exact(capacity)
                .map_err(|_| Error::Limit("cannot allocate bounded window metadata")),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Single(slot) => usize::from(slot.is_some()),
            Self::Ring(queue) => queue.len(),
        }
    }

    fn push_back(&mut self, member: T) -> Result<(), Error> {
        match self {
            Self::Single(slot @ None) => *slot = Some(member),
            Self::Ring(queue) if queue.len() < queue.capacity() => queue.push_back(member),
            _ => return Err(Error::Broken),
        }
        Ok(())
    }

    fn front(&self) -> Option<&T> {
        match self {
            Self::Single(slot) => slot.as_ref(),
            Self::Ring(queue) => queue.front(),
        }
    }

    fn pop_front(&mut self) -> Option<T> {
        match self {
            Self::Single(slot) => slot.take(),
            Self::Ring(queue) => queue.pop_front(),
        }
    }
}

impl<L> WindowQueue<WindowMember<L>> {
    fn pending_limits(&self, admitted: usize, current: (usize, usize)) -> (usize, usize) {
        let add_limits = |(rows, bytes): (usize, usize), member: &WindowMember<L>| {
            (
                rows.saturating_add(member.limits.max_rows),
                bytes.saturating_add(member.limits.max_result_bytes),
            )
        };
        match self {
            Self::Single(member) => member.iter().take(admitted).fold(current, add_limits),
            Self::Ring(queue) => queue.iter().take(admitted).fold(current, add_limits),
        }
    }
}

#[derive(Debug)]
enum PipelineMembers {
    Fixed(Vec<usize>),
    Window(WindowMembers),
}

/// 恢复需保留列数和当前协议阶段。
/// 窗口在发送包交给传输时发布成员前缀，与恢复共用同一队列。
#[derive(Debug)]
pub(super) struct PipelineProgress {
    pub(super) quantum: ExecutionQuantum,
    members: PipelineMembers,
    phase: MemberPhase,
    pub(super) on_error: Option<crate::error::OnError>,
    pub(super) started: bool,
}

impl PipelineProgress {
    fn fixed(
        mut columns: Vec<usize>,
        requests: &[PipelineRequest<'_>],
        max_requests: usize,
        quantum: ExecutionQuantum,
    ) -> Result<Self, Error> {
        if columns.capacity() > max_requests {
            columns = Vec::new();
        }
        columns
            .try_reserve_exact(requests.len())
            .map_err(|_| Error::Limit("cannot allocate pipeline recovery columns"))?;
        // 固定批次一次提交，按协议次序从向量末尾移除即可。
        columns.extend(
            requests
                .iter()
                .rev()
                .map(|request| request.statement.layout().len()),
        );
        Ok(Self::with_members(PipelineMembers::Fixed(columns), quantum))
    }

    fn window<L: WindowMemberLayout>(
        cache: &mut WindowCaches,
        capacity: usize,
        max_capacity: usize,
        quantum: ExecutionQuantum,
    ) -> Result<Self, Error> {
        // 本次输入可减少预留，但已保留的容量仍可供配置上限内的下次请求使用。
        let queue = if L::SCALAR {
            MemberQueue::Scalars(WindowQueue::from_cache(
                &mut cache.scalars,
                capacity,
                max_capacity,
            )?)
        } else {
            MemberQueue::Rows(WindowQueue::from_cache(
                &mut cache.rows,
                capacity,
                max_capacity,
            )?)
        };
        Ok(Self::with_members(
            PipelineMembers::Window(WindowMembers {
                queue,
                admitted: 0,
                current: None,
            }),
            quantum,
        ))
    }

    fn with_members(members: PipelineMembers, quantum: ExecutionQuantum) -> Self {
        Self {
            quantum,
            members,
            phase: MemberPhase::Bind,
            on_error: None,
            started: false,
        }
    }

    pub(super) fn recycle(self, fixed: &mut Vec<usize>, window: &mut WindowCaches) {
        match self.members {
            PipelineMembers::Fixed(mut columns) => {
                columns.clear();
                *fixed = columns;
            }
            PipelineMembers::Window(members) => match members.queue {
                MemberQueue::Rows(queue) => window.rows = queue.into_cache(),
                MemberQueue::Scalars(queue) => window.scalars = queue.into_cache(),
            },
        }
    }

    fn window_members_mut(&mut self) -> Result<&mut WindowMembers, Error> {
        match &mut self.members {
            PipelineMembers::Window(members) => Ok(members),
            PipelineMembers::Fixed(_) => Err(Error::Broken),
        }
    }

    pub(super) fn pending_window_limits(&self) -> Result<(usize, usize), Error> {
        let PipelineMembers::Window(members) = &self.members else {
            return Err(Error::Broken);
        };
        let current = members.current.map_or((0, 0), |(_, limits)| {
            (limits.max_rows, limits.max_result_bytes)
        });
        // 环中可能还有尚未交给传输的私有后缀，只核算已发布的成员。
        Ok(match &members.queue {
            MemberQueue::Rows(queue) => queue.pending_limits(members.admitted, current),
            MemberQueue::Scalars(queue) => queue.pending_limits(members.admitted, current),
        })
    }

    fn stage_window_member<L: WindowMemberLayout>(
        &mut self,
        layout: L,
        limits: QueryLimits,
    ) -> Result<(), Error> {
        L::queue(&mut self.window_members_mut()?.queue)?.push_back(WindowMember {
            layout,
            limits: limits.into(),
        })
    }

    fn publish_window_members(&mut self) -> Result<(), Error> {
        let members = self.window_members_mut()?;
        members.admitted = members.queue.len();
        self.started = true;
        Ok(())
    }

    fn take_window_member<L: WindowMemberLayout>(&mut self) -> Result<(L, QueryRowLimits), Error> {
        let members = self.window_members_mut()?;
        if members.admitted == 0 || members.current.is_some() {
            return Err(Error::Broken);
        }
        let Some(WindowMember { layout, limits }) = L::queue(&mut members.queue)?.pop_front()
        else {
            return Err(Error::Broken);
        };
        members.admitted -= 1;
        members.current = Some((layout.columns(), limits));
        Ok((layout, limits))
    }

    pub(super) fn columns(&self) -> Result<usize, Error> {
        let columns = match &self.members {
            PipelineMembers::Fixed(columns) => columns.last().copied(),
            PipelineMembers::Window(members) => {
                members.current.map(|(columns, _)| columns).or_else(|| {
                    if members.admitted == 0 {
                        return None;
                    }
                    members.queue.front_columns()
                })
            }
        };
        columns.ok_or(Error::Broken)
    }

    fn validate_signal(&self, signal: PipelineSignal) -> Result<(), Error> {
        let empty = match &self.members {
            PipelineMembers::Fixed(columns) => columns.is_empty(),
            PipelineMembers::Window(members) => members.current.is_none() && members.admitted == 0,
        };
        if empty {
            return Err(protocol_error(
                "pipeline response exceeds its admitted members",
            ));
        }
        self.validate_member_phase(signal)
    }

    fn validate_member_phase(&self, signal: PipelineSignal) -> Result<(), Error> {
        match signal {
            PipelineSignal::Bind if self.phase == MemberPhase::Bind => {}
            PipelineSignal::Row if self.phase == MemberPhase::Rows => {}
            PipelineSignal::Complete if self.phase == MemberPhase::Rows => {}
            // 隐式事务可能在 CommandComplete 后的 Sync 阶段提交失败，必须收到 Ready 才能授权复用。
            PipelineSignal::Error => {}
            PipelineSignal::Ready(_)
                if matches!(self.phase, MemberPhase::Complete | MemberPhase::Failed) => {}
            PipelineSignal::Auxiliary => {}
            _ => {
                return Err(protocol_error(
                    "unexpected response in the prepared pipeline",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn observe_signal(&mut self, signal: PipelineSignal) -> Result<(), Error> {
        self.validate_signal(signal)?;
        self.apply_signal(signal);
        Ok(())
    }

    /// 窗口读取当前已接纳的成员，到 Ready 即停止，成员身份只需检查一次。
    fn observe_member_signal(&mut self, signal: PipelineSignal) -> Result<(), Error> {
        self.validate_member_phase(signal)?;
        self.apply_signal(signal);
        Ok(())
    }

    fn apply_signal(&mut self, signal: PipelineSignal) {
        match signal {
            PipelineSignal::Bind => self.phase = MemberPhase::Rows,
            PipelineSignal::Complete => self.phase = MemberPhase::Complete,
            PipelineSignal::Error => self.phase = MemberPhase::Failed,
            PipelineSignal::Ready(_) => {
                match &mut self.members {
                    PipelineMembers::Fixed(columns) => {
                        columns.pop();
                    }
                    PipelineMembers::Window(members) => {
                        if members.current.take().is_none() {
                            members.queue.discard_front();
                            members.admitted -= 1;
                        }
                    }
                }
                self.phase = MemberPhase::Bind;
            }
            PipelineSignal::Row | PipelineSignal::Auxiliary => {}
        }
    }
}

/// completed 只包含已观察到 Ready 的成员。
/// 全部 Ready 后仍可能在等待本地发送完成时报错。
pub struct PipelineError {
    pub completed: Vec<PipelineItem>,
    pub source: Error,
    pub may_have_executed: bool,
}

impl PipelineError {
    pub(super) fn before_submission(source: Error) -> Self {
        Self {
            completed: Vec::new(),
            source,
            may_have_executed: false,
        }
    }
}

impl fmt::Debug for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipelineError")
            .field("completed_count", &self.completed.len())
            .field("source", &self.source)
            .field("may_have_executed", &self.may_have_executed)
            .finish()
    }
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prepared pipeline stopped after {} confirmed members: {}",
            self.completed.len(),
            self.source
        )
    }
}

impl std::error::Error for PipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl<T: WireTransport> Session<T> {
    /// 提交有限组预备语句并收集结果，每个成员独立 Sync。
    /// 普通 SQL 错误按成员返回；传输、协议结构或存储失败会丢弃会话并保留已确认前缀。
    /// 涉及会话配置或 schema 变化时，调用方须分批提交。
    pub async fn query_pipeline(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: PipelineLimits,
    ) -> Result<Vec<PipelineItem>, PipelineError> {
        self.query_pipeline_scoped(requests, limits, false).await
    }

    async fn query_pipeline_scoped(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: PipelineLimits,
        in_transaction: bool,
    ) -> Result<Vec<PipelineItem>, PipelineError> {
        self.check_idle_access(in_transaction)
            .map_err(PipelineError::before_submission)?;
        let quantum = ExecutionQuantum::new(limits.scheduling);
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        if limits.max_requests == 0 || requests.len() > limits.max_requests {
            return Err(PipelineError::before_submission(Error::Limit(
                "pipeline request count exceeds its limit",
            )));
        }
        let minimum_storage = requests
            .len()
            .checked_mul(std::mem::size_of::<PipelineItem>())
            .ok_or_else(|| {
                PipelineError::before_submission(Error::Limit("pipeline result size overflow"))
            })?;
        if minimum_storage > limits.max_result_bytes {
            return Err(PipelineError::before_submission(Error::Limit(
                "pipeline result slots exceed their budget",
            )));
        }
        let bytes = self
            .encode_pipeline(requests)
            .map_err(PipelineError::before_submission)?;
        let mut completed = Vec::new();
        completed.try_reserve_exact(requests.len()).map_err(|_| {
            PipelineError::before_submission(Error::Limit("cannot allocate pipeline result slots"))
        })?;
        let slots = completed
            .capacity()
            .checked_mul(std::mem::size_of::<PipelineItem>())
            .ok_or_else(|| {
                PipelineError::before_submission(Error::Limit("pipeline result size overflow"))
            })?;
        let mut remaining_bytes = limits.max_result_bytes.checked_sub(slots).ok_or_else(|| {
            PipelineError::before_submission(Error::Limit(
                "actual pipeline result slots exceed their budget",
            ))
        })?;
        let mut remaining_rows = limits.max_rows;
        let columns = std::mem::take(&mut self.extension().pipeline_columns);
        let mut progress = PipelineProgress::fixed(columns, requests, limits.max_requests, quantum)
            .map_err(PipelineError::before_submission)?;
        progress.quantum.spend_bytes(bytes.len());
        self.extension().work_kind = Some(WorkKind::Pipeline(progress));
        self.active = true;
        self.remaining_boundaries = requests.len();
        if let Err(source) = self.transport.begin_send(bytes) {
            self.transport.break_connection();
            return Err(PipelineError {
                completed,
                source,
                may_have_executed: false,
            });
        }
        for request in requests {
            match self
                .read_pipeline_member(
                    request,
                    &mut remaining_rows,
                    &mut remaining_bytes,
                    limits.storage,
                )
                .await
            {
                Ok(item) => completed.push(item),
                Err(source) => {
                    self.transport.break_connection();
                    return Err(PipelineError {
                        completed,
                        source,
                        may_have_executed: true,
                    });
                }
            }
        }
        if let Err(source) = self.transport.finish_send_on_owner().await {
            self.transport.break_connection();
            return Err(PipelineError {
                completed,
                source,
                may_have_executed: true,
            });
        }
        self.active = false;
        self.extension().clear_work();
        Ok(completed)
    }

    fn encode_pipeline(&mut self, requests: &[PipelineRequest<'_>]) -> Result<Vec<u8>, Error> {
        self.transport.encode_send_buffer(|buffer| {
            // 所有成员编码成功才提交包；发现无效成员时，局部编码前缀不会被发送。
            for request in requests {
                let admission = Self::resolve_prepared(
                    self.id,
                    self.extended.as_deref(),
                    request.statement,
                    true,
                )?;
                let matched = admission.parameters(
                    request.parameters,
                    "pipeline parameter count differs from its statement",
                )?;
                admission.validate_metadata(
                    request.limits.max_metadata_bytes,
                    "pipeline member metadata exceeds its query limit",
                )?;
                admission
                    .packet(
                        &matched,
                        crate::protocol::QueryTail::Sync,
                        self.max_request_len,
                        "pipeline parameter type differs from its statement",
                        || Ok(()),
                    )?
                    .append_to(buffer, self.max_request_len)?;
            }
            Ok(())
        })
    }

    async fn read_pipeline_member(
        &mut self,
        request: &PipelineRequest<'_>,
        remaining_rows: &mut usize,
        remaining_bytes: &mut usize,
        storage: AllocationPolicy,
    ) -> Result<PipelineItem, Error> {
        self.read_pipeline_member_into(
            request.statement.shared_layout(),
            request.limits.into(),
            remaining_rows,
            remaining_bytes,
            None,
            MemberReadOptions {
                storage,
                diagnostic_limit: None,
            },
        )
        .await?
        .into_result()
    }

    async fn read_pipeline_member_into(
        &mut self,
        layout: &Rc<crate::row::RowLayout>,
        limits: QueryRowLimits,
        remaining_rows: &mut usize,
        remaining_bytes: &mut usize,
        reusable: Option<OwnedBatch>,
        options: MemberReadOptions,
    ) -> Result<MemberRead, Error> {
        match options.storage {
            AllocationPolicy::ReserveLimit => {
                self.read_pipeline_member_storage::<false, true>(
                    layout,
                    limits,
                    remaining_rows,
                    remaining_bytes,
                    reusable,
                    options.diagnostic_limit,
                )
                .await
            }
            AllocationPolicy::Grow => {
                self.read_pipeline_member_storage::<true, true>(
                    layout,
                    limits,
                    remaining_rows,
                    remaining_bytes,
                    reusable,
                    options.diagnostic_limit,
                )
                .await
            }
        }
    }

    async fn drain_pipeline_member(
        &mut self,
        layout: &Rc<crate::row::RowLayout>,
        limits: QueryRowLimits,
        remaining_rows: &mut usize,
        diagnostic_limit: Option<usize>,
    ) -> Result<MemberRead, Error> {
        let mut unused_storage = 0;
        self.read_pipeline_member_storage::<false, false>(
            layout,
            limits,
            remaining_rows,
            &mut unused_storage,
            None,
            diagnostic_limit,
        )
        .await
    }

    async fn read_pipeline_member_storage<const GROW: bool, const COLLECT: bool>(
        &mut self,
        layout: &Rc<crate::row::RowLayout>,
        limits: QueryRowLimits,
        remaining_rows: &mut usize,
        remaining_bytes: &mut usize,
        reusable: Option<OwnedBatch>,
        diagnostic_limit: Option<usize>,
    ) -> Result<MemberRead, Error> {
        let Some(WorkKind::Pipeline(progress)) = self
            .extended
            .as_ref()
            .and_then(|extended| extended.work_kind.as_ref())
        else {
            return Err(Error::Broken);
        };
        // 到当前成员的 Ready 即停止。成员身份只需在开始读取时校验。
        if progress.columns()? != layout.len() {
            return Err(Error::Broken);
        }
        let capacity = limits.max_result_bytes.min(*remaining_bytes);
        let mut batch = if COLLECT {
            reusable.and_then(|batch| batch.reuse_for::<GROW>(layout, limits.max_rows, capacity))
        } else {
            None
        };
        if let Some(batch) = batch.as_mut() {
            *remaining_bytes = remaining_bytes
                .checked_sub(batch.retained_bytes())
                .ok_or(Error::Limit("reusable window arena exceeds its budget"))?;
        }
        let mut command = None;
        let mut failure = None;
        let mut sql_error = false;
        let mut member_rows_left = limits.max_rows;
        let mut discard_bytes_left = limits.max_result_bytes;
        let mut controls = 0_usize;
        self.execution_quantum_mut()?.yield_on_worker().await?;
        loop {
            self.transport.receive_frame_on_owner().await?;
            let frame = self.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            let Some(WorkKind::Pipeline(progress)) = self
                .extended
                .as_mut()
                .and_then(|extended| extended.work_kind.as_mut())
            else {
                return Err(Error::Broken);
            };
            if frame.tag == b'D' {
                let row = protocol::parse_data_row(frame.body)?;
                progress.validate_member_phase(PipelineSignal::Row)?;
                let view = RowView::new(row, layout)?;
                if member_rows_left == 0 || *remaining_rows == 0 {
                    return Err(Error::Limit("pipeline row limit exceeded"));
                }
                member_rows_left -= 1;
                *remaining_rows -= 1;
                if !COLLECT {
                    discard_bytes_left = discard_bytes_left
                        .checked_sub(row.encoded_fields().len() + 4)
                        .ok_or(Error::Limit("pipeline row byte limit exceeded"))?;
                } else {
                    if batch.is_none() {
                        let required = row.encoded_fields().len() + 4;
                        if required > capacity {
                            return Err(Error::Limit("pipeline row storage limit exceeded"));
                        }
                        let owned = OwnedBatch::new(
                            Rc::clone(layout),
                            limits.max_rows,
                            if GROW { 0 } else { capacity },
                        )?;
                        *remaining_bytes = remaining_bytes
                            .checked_sub(owned.retained_bytes())
                            .ok_or(Error::Limit("actual pipeline arena exceeds its budget"))?;
                        batch = Some(owned);
                    }
                    let output = batch.as_mut().ok_or(Error::Broken)?;
                    if GROW {
                        let before = output.retained_bytes();
                        output.push_growing(view, capacity)?;
                        let growth = output
                            .retained_bytes()
                            .checked_sub(before)
                            .ok_or(Error::Limit("pipeline arena capacity moved backwards"))?;
                        *remaining_bytes = remaining_bytes.checked_sub(growth).ok_or(
                            Error::Limit("actual pipeline arena growth exceeds its budget"),
                        )?;
                    } else {
                        output.push(view)?;
                    }
                }
                self.transport.consume_frame()?;
                // DataRow 不转换阶段，扣除额度时可沿用本成员的进度借用。
                progress.quantum.spend_bytes(work_bytes);
                progress.quantum.yield_on_worker().await?;
                continue;
            }
            let message = protocol::parse_backend(frame)?;
            if let BackendMessage::ErrorResponse(error) = message
                && is_fatal(error)
            {
                // 致命响应没有后续 Ready，超限时也必须保留致命分类。
                return Ok(MemberRead::Fatal(terminal_database_error(
                    error,
                    diagnostic_limit,
                )));
            }
            let signal = PipelineSignal::from_message(message)?;
            if controls == self.max_messages {
                // 恢复将重新观察当前帧，只校验其合法性，不提前推进协议阶段。
                progress.validate_member_phase(signal)?;
                if let BackendMessage::CommandComplete(tag) = message {
                    protocol::parse_command_tag(tag)?;
                }
                return Err(Error::Limit(
                    "pipeline member exceeded its control message limit",
                ));
            }
            controls += 1;
            progress.observe_member_signal(signal)?;
            let mut ready = None;
            let mut path_changed = false;
            let mut transaction_command = None;
            match message {
                BackendMessage::BindComplete => {}
                BackendMessage::CommandComplete(tag) => {
                    let observed = command_kind(protocol::parse_command_tag(tag)?);
                    transaction_command = Some(observed.0);
                    command = Some(observed);
                }
                BackendMessage::EmptyQueryResponse => {
                    command = Some((super::general::CommandKind::Empty, None))
                }
                BackendMessage::ErrorResponse(error) => {
                    sql_error = true;
                    if COLLECT && failure.is_none() {
                        // 失败成员不再交付暂定行。
                        // 先释放局部缓冲，再为该成员的诊断计费。
                        if let Some(owned) = batch.take() {
                            *remaining_bytes = remaining_bytes
                                .checked_add(owned.retained_bytes())
                                .ok_or(Error::Limit("pipeline result budget overflow"))?;
                            drop(owned);
                        }
                        failure = Some(if let Some(limit) = diagnostic_limit {
                            match DatabaseError::fields_len_within(error, limit) {
                                Some(fields_len) => {
                                    Ok(retain_diagnostic(error, fields_len, remaining_bytes)?)
                                }
                                None => Err(Error::Limit(
                                    "batch diagnostic exceeds its per-member bound",
                                )),
                            }
                        } else {
                            Ok(owned_error_bounded(error, remaining_bytes)?)
                        });
                    }
                }
                BackendMessage::ReadyForQuery(status) => ready = Some(status),
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    path_changed = name == "search_path";
                }
                BackendMessage::NoticeResponse(notice) => {
                    if COLLECT {
                        super::observe_notice(notice, self.notice_handler.as_ref())
                            .finish(&mut self.transport);
                    }
                }
                BackendMessage::NotificationResponse { .. } => {}
                _ => {
                    return Err(protocol_error(
                        "unexpected response in the prepared pipeline",
                    ));
                }
            }
            self.transport.consume_frame()?;
            if let Some(kind) = transaction_command {
                self.record_pipeline_transaction_end(kind)?;
            }
            if path_changed {
                self.bump_schema_epoch()?;
            }
            if let Some(status) = ready {
                self.note_ready(status)?;
            }
            let quantum = self.execution_quantum_mut()?;
            quantum.spend_bytes(work_bytes);
            quantum.yield_on_worker().await?;
            if let Some(status) = ready {
                if !COLLECT {
                    return Ok(MemberRead::Drained { sql_error });
                }
                if let Some(error) = failure {
                    return Ok(match error {
                        Ok(error) => MemberRead::Confirmed(Err(error)),
                        Err(error) => MemberRead::DiagnosticLimit(error),
                    });
                }
                let rows = match batch {
                    Some(batch) => batch,
                    None => OwnedBatch::new(Rc::clone(layout), limits.max_rows, 0)?,
                };
                return Ok(MemberRead::Confirmed(Ok(PipelineResult {
                    completion: QueryCompletion {
                        command: command.map(|(kind, _)| kind),
                        rows_affected: command.and_then(|(_, rows)| rows),
                        rows_returned: rows.len(),
                        transaction_status: status,
                        succeeded: true,
                    },
                    rows,
                })));
            }
        }
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在当前事务中一次提交全部预备成员，每条 Sync 单独报告结果。
    /// 前一条 SQL 失败后，后续成员可能收到事务已失败的错误。
    pub async fn query_pipeline(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: PipelineLimits,
    ) -> Result<Vec<PipelineItem>, PipelineError> {
        self.session_mut()
            .query_pipeline_scoped(requests, limits, true)
            .await
    }
}

#[cfg(test)]
mod window_workspace_tests {
    use super::*;
    use crate::protocol::TransactionStatus;
    use crate::row::{ResultFormats, RowLayout};
    use crate::types::Format;

    #[test]
    fn alternating_modes_keep_their_reusable_rings_without_growing_each_slot() {
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(size_of::<WindowMember<ScalarColumn>>(), 24);
            assert_eq!(size_of::<WindowMember<Rc<RowLayout>>>(), 24);
            assert_eq!(size_of::<WindowCaches>(), 2 * size_of::<VecDeque<()>>());
        }

        let mut cache = WindowCaches::default();
        let mut columns = Vec::new();
        for (row_capacity, scalar_capacity) in [(3, 4), (1, 1)] {
            let rows = PipelineProgress::window::<Rc<RowLayout>>(
                &mut cache,
                row_capacity,
                3,
                ExecutionQuantum::Uninterrupted,
            )
            .unwrap();
            rows.recycle(&mut columns, &mut cache);
            let scalars = PipelineProgress::window::<ScalarColumn>(
                &mut cache,
                scalar_capacity,
                4,
                ExecutionQuantum::Uninterrupted,
            )
            .unwrap();
            scalars.recycle(&mut columns, &mut cache);
            assert_eq!((cache.rows.capacity(), cache.scalars.capacity()), (3, 4));
        }
    }

    #[test]
    fn recovery_only_observes_published_members_and_retires_private_layouts() {
        let layout =
            Rc::new(RowLayout::new(Vec::new(), ResultFormats::All(Format::Binary)).unwrap());
        let next_layout = Rc::new(
            RowLayout::new(
                vec![crate::row::Column::new(
                    "n".to_owned(),
                    crate::types::Oid::INT4,
                )],
                ResultFormats::All(Format::Binary),
            )
            .unwrap(),
        );
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 16,
            max_metadata_bytes: 1024,
        };
        let mut cache = WindowCaches::default();
        let mut progress = PipelineProgress::window::<Rc<RowLayout>>(
            &mut cache,
            3,
            3,
            ExecutionQuantum::Uninterrupted,
        )
        .unwrap();
        progress
            .stage_window_member(Rc::clone(&layout), limits)
            .unwrap();
        assert!(progress.columns().is_err());
        assert_eq!(progress.pending_window_limits().unwrap(), (0, 0));
        progress
            .stage_window_member(Rc::clone(&next_layout), limits)
            .unwrap();
        progress.publish_window_members().unwrap();
        progress
            .stage_window_member(Rc::clone(&layout), limits)
            .unwrap();
        let (layout_in_use, _) = progress.take_window_member::<Rc<RowLayout>>().unwrap();
        assert!(Rc::ptr_eq(&layout, &layout_in_use));
        assert_eq!(progress.columns().unwrap(), 0);
        assert_eq!(progress.pending_window_limits().unwrap(), (2, 32));
        progress.observe_signal(PipelineSignal::Bind).unwrap();
        progress.observe_signal(PipelineSignal::Complete).unwrap();
        progress
            .observe_signal(PipelineSignal::Ready(TransactionStatus::Idle))
            .unwrap();
        assert_eq!(progress.columns().unwrap(), 1);
        assert_eq!(progress.pending_window_limits().unwrap(), (1, 16));
        progress.observe_signal(PipelineSignal::Bind).unwrap();
        progress.observe_signal(PipelineSignal::Complete).unwrap();
        progress
            .observe_signal(PipelineSignal::Ready(TransactionStatus::Idle))
            .unwrap();
        assert!(progress.columns().is_err());
        assert_eq!(progress.pending_window_limits().unwrap(), (0, 0));
        assert!(progress.observe_signal(PipelineSignal::Bind).is_err());
        drop(layout_in_use);

        let mut columns = Vec::new();
        progress.recycle(&mut columns, &mut cache);
        assert!(cache.rows.is_empty());
        assert_eq!(cache.rows.capacity(), 3);
        assert_eq!(Rc::strong_count(&layout), 1);
        assert_eq!(Rc::strong_count(&next_layout), 1);
        let progress = PipelineProgress::window::<Rc<RowLayout>>(
            &mut cache,
            1,
            3,
            ExecutionQuantum::Uninterrupted,
        )
        .unwrap();
        progress.recycle(&mut columns, &mut cache);
        assert_eq!(cache.rows.capacity(), 3);

        let progress = PipelineProgress::window::<Rc<RowLayout>>(
            &mut cache,
            1,
            1,
            ExecutionQuantum::Uninterrupted,
        )
        .unwrap();
        progress.recycle(&mut columns, &mut cache);
        assert_eq!(cache.rows.capacity(), 0);
    }
}
