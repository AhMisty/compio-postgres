use crate::transport::WireOps;
use std::{cell::Cell, fmt, rc::Rc};

use crate::{
    DatabaseError, Error, OnError, QueryOptions, frontend,
    protocol::{self, BackendMessage, CommandTag, Format, QueryTail, TransactionStatus},
    row::{AllocationPolicy, OwnedBatch, ResultFormats, ResultShape, RowLayout, RowView},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::{TransportExt, WireTransport},
    types::{CodecError, Oid, Parameter},
};

use super::{
    AbandonPolicy, Session, Transaction, is_fatal, owned_error, owned_error_bounded,
    protocol_error, terminal_database_error, validate_parameter,
};

mod admission;
mod close_pipeline;
mod prepare_pipeline;
pub use close_pipeline::{CloseItem, ClosePipelineError};
use close_pipeline::{CloseMember, CloseProgress};
use prepare_pipeline::{PrepareIdentity, PrepareProgress, PrepareReadMode};
pub use prepare_pipeline::{PrepareItem, PreparePipelineError, PrepareRequest};

/// 会话的预备语句槽和元数据限额。
/// 名称随槽预留，空槽和占用槽的固定存储均计入元数据限额。
/// 已关闭的语句如仍有句柄或结果持有布局，对应元数据仍计入预算。
#[derive(Debug, Clone, Copy)]
pub struct StatementLimits {
    /// 设为零时不为预备语句分配槽，仍可执行一次性查询。
    pub max_statements: usize,
    pub max_metadata_bytes: usize,
}

impl StatementLimits {
    pub(super) fn slot_storage_minimum(self) -> Result<usize, Error> {
        let minimum = std::alloc::Layout::array::<Slot>(self.max_statements)
            .map_err(|_| Error::Limit("statement slot size overflow"))?
            .size();
        if minimum > self.max_metadata_bytes {
            return Err(Error::Limit("statement slots exceed the metadata limit"));
        }
        Ok(minimum)
    }
}

/// 批量准备与关闭预备语句的限额。每条请求独立 Sync。
#[derive(Debug, Clone, Copy)]
pub struct StatementPipelineLimits {
    /// 本批语句数，也限制恢复时保留的标识数。
    pub max_statements: usize,
    pub max_packet_bytes: usize,
    /// 返回槽和数据库诊断共用此预算，语句元数据与收发缓冲单独计费。
    pub max_result_bytes: usize,
    /// 编码包和每个响应帧分别按字节计量，放弃后可沿用额度显式恢复。
    pub scheduling: ExecutionScheduling,
}

/// 结果字节数按每行四字节长度字段及编码字段累计。
/// 元数据单独限额；最终错误诊断受连接的帧大小限制。
#[derive(Debug, Clone, Copy)]
pub struct QueryLimits {
    pub max_rows: usize,
    pub max_result_bytes: usize,
    pub max_metadata_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    Select,
    Insert,
    Update,
    Delete,
    Merge,
    Move,
    Fetch,
    Copy,
    Begin,
    Commit,
    Rollback,
    Savepoint,
    Release,
    DeallocateAll,
    DiscardAll,
    Empty,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryCompletion {
    pub command: Option<CommandKind>,
    pub rows_affected: Option<u64>,
    pub rows_returned: usize,
    pub transaction_status: TransactionStatus,
    pub succeeded: bool,
}

#[derive(Debug)]
struct StatementData {
    parameters: Box<[Oid]>,
    layout: Rc<RowLayout>,
    bind_size: frontend::BindSize,
    storage: PreparedStatementStorage,
    uniform_bind_format: Option<Format>,
}

impl StatementData {
    fn new(
        name: frontend::WireName<'_>,
        parameters: Box<[Oid]>,
        layout: Rc<RowLayout>,
        storage: PreparedStatementStorage,
    ) -> Result<Self, Error> {
        // 保留公开布局；Bind 对全文本或零列编码零个格式码，对全二进制编码一个，对混合格式按列编码。
        let uniform_bind_format = match layout.formats() {
            _ if layout.is_empty() => Some(Format::Text),
            ResultFormats::All(format) => Some(*format),
            ResultFormats::PerColumn(formats) => formats.split_first().and_then(|(first, rest)| {
                rest.iter().all(|format| format == first).then_some(*first)
            }),
        };
        let bind_format_count = match uniform_bind_format {
            Some(Format::Text) => 0,
            Some(Format::Binary) => 1,
            None => layout.formats().as_slice().len(),
        };
        let bind_size = frontend::BindSize::unnamed(name, parameters.len(), bind_format_count)?;
        Ok(Self {
            parameters,
            layout,
            bind_size,
            storage,
            uniform_bind_format,
        })
    }

    fn bind_formats(&self) -> &[Format] {
        match &self.uniform_bind_format {
            Some(Format::Text) => &[],
            Some(format) => std::slice::from_ref(format),
            None => self.layout.formats().as_slice(),
        }
    }

    fn metadata_bytes(parameters: &[Oid], layout: &RowLayout) -> Result<usize, Error> {
        std::mem::size_of_val(parameters)
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(layout.retained_bytes()))
            .ok_or(Error::Limit("statement metadata size overflow"))
    }
}

/// 本次同步编码借用的语句信息。
/// 跨 I/O 后须重新校验。
pub(super) struct PreparedAdmission<'a> {
    pub(super) name: frontend::WireName<'a>,
    pub(super) parameter_oids: &'a [Oid],
    bind_size: frontend::BindSize,
    bind_formats: &'a [Format],
    pub(super) layout: &'a Rc<RowLayout>,
}

/// 准备语句时选择的服务端存储方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedStatementStorage {
    Named,
    /// 另一次未命名 Parse 会替换该语句；包括显式事务控制在内的简单查询会销毁它。
    ReplaceableUnnamed,
}

/// 预备语句标识及不可变的描述。
/// 连接独占以 `:p` 开头的服务端语句名，业务 SQL 应避开这个命名空间。
/// 释放句柄不发送 Close；布局失效后仍可显式关闭。
#[derive(Debug, Clone)]
pub struct PreparedStatement {
    connection_id: u64,
    slot: usize,
    generation: u64,
    schema_epoch: u64,
    data: Rc<StatementData>,
}

impl PreparedStatement {
    pub fn storage(&self) -> PreparedStatementStorage {
        self.data.storage
    }

    pub(in crate::client) fn slot_index(&self) -> usize {
        self.slot
    }

    pub fn parameter_oids(&self) -> &[Oid] {
        &self.data.parameters
    }
    pub fn layout(&self) -> &RowLayout {
        &self.data.layout
    }

    /// 为该语句分配一个可复用的定长行缓冲。
    pub fn new_row_buffer(
        &self,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<OwnedBatch, CodecError> {
        OwnedBatch::new(Rc::clone(&self.data.layout), max_rows, max_bytes)
    }

    pub(in crate::client) fn shared_layout(&self) -> &Rc<RowLayout> {
        &self.data.layout
    }
}

#[derive(Clone, Copy)]
enum RemoteStatement {
    Preparing,
    Created,
    Closed { next: Option<usize> },
}

struct Record {
    name: frontend::StatementName,
    data: Option<Rc<StatementData>>,
    remote: RemoteStatement,
}

impl Record {
    fn is_closed(&self) -> bool {
        matches!(self.remote, RemoteStatement::Closed { .. })
    }

    fn mark_closed(&mut self, index: usize, first_closed: &mut Option<usize>) {
        if !self.is_closed() {
            self.remote = RemoteStatement::Closed {
                next: first_closed.replace(index),
            };
        }
    }

    fn charged_bytes(&self) -> Result<usize, Error> {
        self.data.as_ref().map_or(Ok(0), |data| {
            StatementData::metadata_bytes(&data.parameters, &data.layout)
        })
    }
}

struct Slot {
    generation: u64,
    record: Option<Record>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreparePhase {
    Parse,
    Parameters,
    Description,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClosePhase {
    Waiting,
    Complete,
    Failed,
}

#[derive(Debug)]
pub(super) enum WorkKind {
    Query,
    Prepare {
        slot: usize,
        generation: u64,
        phase: PreparePhase,
    },
    PreparePipeline(PrepareProgress),
    Close {
        slot: usize,
        generation: u64,
        phase: ClosePhase,
    },
    ClosePipeline(CloseProgress),
    Pipeline(super::pipeline::PipelineProgress),
    ProvisionalWindow(super::pipeline::ProvisionalProgress),
}

pub(super) struct Extended {
    limits: Option<StatementLimits>,
    slots: Vec<Slot>,
    // 此下标之前的槽均已占用，等于 slots.len() 时没有空槽。
    first_vacant: usize,
    vacant_count: usize,
    // 已关闭记录保留在索引中，以便外部句柄和布局释放后回收。
    first_closed: Option<usize>,
    metadata_bytes: usize,
    schema_epoch: u64,
    epoch_exhausted: bool,
    // 已验证但尚未发送的执行组，须在下一次交付前核对语句身份与布局。
    group_statements_changed: bool,
    next_name: u64,
    unnamed_slot: Option<usize>,
    pub(super) window_members: super::pipeline::WindowCaches,
    pub(super) pipeline_columns: Vec<usize>,
    pub(super) work_kind: Option<WorkKind>,
    pub(super) pending_frame: bool,
    pub(super) callback_in_progress: Cell<bool>,
    query: Option<QueryState>,
}

impl Extended {
    pub(super) fn statement_slot_count(&self) -> usize {
        self.slots.len()
    }

    pub(super) fn query_cancel_requested(&self) -> bool {
        self.query
            .as_ref()
            .is_some_and(QueryState::cancel_requested)
    }

    pub(super) fn expire_query_cancel(&self) -> bool {
        if let Some(query) = self.query.as_ref() {
            query.expire_cancel();
            return query.cancel_requested();
        }
        false
    }

    pub(super) fn provisional_window_requires_discard(&self) -> bool {
        match self.work_kind.as_ref() {
            Some(WorkKind::ProvisionalWindow(progress)) => {
                progress.started
                    && progress.abandon == super::pipeline::AbandonPolicy::DiscardOnAbandon
            }
            Some(WorkKind::Pipeline(progress)) => {
                progress.started && progress.on_error == Some(crate::error::OnError::Discard)
            }
            Some(WorkKind::Query) => self
                .query
                .as_ref()
                .is_some_and(|query| query.on_error == crate::error::OnError::Discard),
            _ => false,
        }
    }

    pub(super) fn pipeline_progress_mut(
        &mut self,
    ) -> Option<&mut super::pipeline::PipelineProgress> {
        match self.work_kind.as_mut()? {
            WorkKind::Pipeline(progress) => Some(progress),
            WorkKind::ProvisionalWindow(progress) => Some(&mut progress.pipeline),
            _ => None,
        }
    }

    pub(super) fn clear_work(&mut self) {
        let progress = match self.work_kind.take() {
            Some(WorkKind::Pipeline(progress)) => progress,
            Some(WorkKind::ProvisionalWindow(progress)) => progress.pipeline,
            _ => return,
        };
        progress.recycle(&mut self.pipeline_columns, &mut self.window_members);
    }

    pub(super) fn callback_aborted(&self) -> bool {
        self.callback_in_progress.get()
    }
    pub(super) fn invoke_callback<R>(&self, callback: impl FnOnce() -> R) -> R {
        invoke_callback(&self.callback_in_progress, callback)
    }
    pub(super) fn query_layout(&self) -> Option<&RowLayout> {
        self.query.as_ref()?.layout.as_deref()
    }
    fn new() -> Self {
        Self {
            limits: None,
            slots: Vec::new(),
            first_vacant: 0,
            vacant_count: 0,
            first_closed: None,
            metadata_bytes: 0,
            schema_epoch: 0,
            epoch_exhausted: false,
            group_statements_changed: false,
            next_name: 0,
            unnamed_slot: None,
            window_members: super::pipeline::WindowCaches::default(),
            pipeline_columns: Vec::new(),
            work_kind: None,
            pending_frame: false,
            callback_in_progress: Cell::new(false),
            query: None,
        }
    }

    fn bump_epoch(&mut self) -> Result<(), Error> {
        match self.schema_epoch.checked_add(1) {
            Some(epoch) if !self.epoch_exhausted => {
                self.schema_epoch = epoch;
                self.group_statements_changed = true;
                Ok(())
            }
            _ => {
                self.epoch_exhausted = true;
                Err(Error::Limit("statement schema epoch is exhausted"))
            }
        }
    }

    fn invalidate_unnamed(&mut self) -> Result<(), Error> {
        let Some(index) = self.unnamed_slot.take() else {
            return Ok(());
        };
        let record = self
            .slots
            .get_mut(index)
            .and_then(|slot| slot.record.as_mut())
            .ok_or(Error::Broken)?;
        record.mark_closed(index, &mut self.first_closed);
        Ok(())
    }

    fn vacant_slots(&self) -> impl Iterator<Item = (usize, &Slot)> {
        self.slots
            .iter()
            .enumerate()
            .skip(self.first_vacant)
            .filter(|(_, slot)| slot.record.is_none())
    }

    fn occupy_slots(&mut self, count: usize) {
        self.vacant_count -= count;
        if self.vacant_count == 0 {
            self.first_vacant = self.slots.len();
            return;
        }
        while let Some(slot) = self.slots.get(self.first_vacant)
            && slot.record.is_some()
        {
            self.first_vacant += 1;
        }
    }

    fn reclaim_closed(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        let mut current = self.first_closed.take();
        while let Some(index) = current {
            let slot = self.slots.get_mut(index).ok_or(Error::Broken)?;
            let record = slot.record.as_mut().ok_or(Error::Broken)?;
            let RemoteStatement::Closed { next } = &mut record.remote else {
                return Err(Error::Broken);
            };
            current = *next;
            if record.data.as_ref().is_some_and(|data| {
                Rc::strong_count(data) != 1 || Rc::strong_count(&data.layout) != 1
            }) {
                *next = self.first_closed;
                self.first_closed = Some(index);
            } else {
                self.metadata_bytes = self
                    .metadata_bytes
                    .checked_sub(record.charged_bytes()?)
                    .ok_or(Error::Broken)?;
                slot.record = None;
                self.first_vacant = self.first_vacant.min(index);
                count += 1;
            }
        }
        self.vacant_count = self
            .vacant_count
            .checked_add(count)
            .filter(|vacant| *vacant <= self.slots.len())
            .ok_or(Error::Broken)?;
        Ok(count)
    }

    fn mark_named_statements_closed(&mut self) -> Result<(), Error> {
        self.group_statements_changed = true;
        if self.vacant_count == self.slots.len() {
            return Ok(());
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            // DEALLOCATE ALL 只删除命名语句。简单协议会在发送时单独使未命名槽失效。
            if Some(index) != self.unnamed_slot
                && let Some(record) = slot.record.as_mut()
            {
                record.mark_closed(index, &mut self.first_closed);
            }
        }
        self.reclaim_closed()?;
        Ok(())
    }
}

/// 回调展开 panic 时保留标记，使会话停止复用。
pub(super) fn invoke_callback<R>(state: &Cell<bool>, callback: impl FnOnce() -> R) -> R {
    state.set(true);
    let result = callback();
    state.set(false);
    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryMode {
    Prepared,
    OneShot,
    Simple,
    ResetSession,
}

impl QueryMode {
    fn is_simple(self) -> bool {
        matches!(self, Self::Simple | Self::ResetSession)
    }

    fn validate_reset_response(self, message: BackendMessage<'_>) -> Result<(), Error> {
        if self != Self::ResetSession {
            return Ok(());
        }
        match message {
            BackendMessage::CommandComplete("DISCARD ALL")
            | BackendMessage::ReadyForQuery(TransactionStatus::Idle)
            | BackendMessage::ParameterStatus { .. }
            | BackendMessage::NoticeResponse(_)
            | BackendMessage::NotificationResponse { .. } => Ok(()),
            BackendMessage::ErrorResponse(error) => Err(Error::Database(owned_error(error))),
            _ => Err(protocol_error("unexpected response to DISCARD ALL")),
        }
    }
}

/// 查询开始时已知的结果信息。标量和零列终端只需列数来恢复被放弃的请求。
enum QueryLayout {
    Shared(Rc<RowLayout>),
    Columns(u16),
    Pending(ResultFormats),
}

struct QueryState {
    cancel: Option<super::cancel::CancelFence>,
    io_started: bool,
    quantum: ExecutionQuantum,
    on_error: crate::error::OnError,
    mode: QueryMode,
    layout: Option<Rc<RowLayout>>,
    // 读取和恢复共用列数，数据行无需再经过共享布局指针。
    result_columns: usize,
    formats: Option<ResultFormats>,
    limits: QueryLimits,
    parsed: bool,
    bound: bool,
    described: bool,
    command: Option<(CommandKind, Option<u64>)>,
    rows: usize,
    result_bytes_left: usize,
    control_messages: usize,
    error_seen: bool,
    failure: Option<DatabaseError>,
    ready: Option<TransactionStatus>,
}

impl QueryState {
    fn start_io(&mut self) -> Result<(), Error> {
        if !self.io_started {
            if self.cancel_requested() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "query cancelled before its first I/O submission",
                )
                .into());
            }
            self.io_started = true;
        }
        Ok(())
    }

    fn expire_cancel(&self) {
        if let Some(fence) = self.cancel.as_ref() {
            fence.expire();
        }
    }

    fn cancel_requested(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(super::cancel::CancelFence::requested)
    }

    fn set_empty_layout(&mut self, projected: bool) -> Result<(), Error> {
        let layout =
            RowLayout::empty_from_pending(&mut self.formats, self.limits.max_metadata_bytes)
                .map_err(Error::from)
                .map_err(query_metadata_error)?;
        if !projected {
            self.layout = Some(Rc::new(layout));
        }
        Ok(())
    }
}

/// 行流。
/// 会话持有协议进度和在途缓冲，释放或遗忘行流后须按会话状态恢复或丢弃。
#[must_use = "复用会话前须读取或结束查询"]
pub struct Query<'s, T: WireTransport> {
    session: &'s mut Session<T>,
    finished: bool,
    completion: Option<QueryCompletion>,
    final_layout: Option<Rc<RowLayout>>,
}

/// 当前行的借用。
/// 行借用结束后，下一次独占访问会推进接收缓冲。
#[must_use = "读取借用行，或释放借用以跳过该行"]
pub struct RowLease<'a> {
    data: protocol::DataRow<'a>,
    layout: &'a Rc<RowLayout>,
}

impl RowLease<'_> {
    pub fn view(&self) -> RowView<'_, '_> {
        RowView::from_matching_layout(self.data, self.layout)
    }
    pub fn layout(&self) -> &RowLayout {
        self.layout
    }

    /// 保留布局，以便释放接收缓冲上的借用后构建自有行或批次。
    pub fn share_layout(&self) -> Rc<RowLayout> {
        Rc::clone(self.layout)
    }
}

impl<T: WireTransport> Session<T> {
    /// 合并同一轮询中的协议收发。首次进入沿用接纳检查，挂起后先验证所属 worker。
    pub(super) fn wait_protocol_on_owner<R>(
        &mut self,
        mut poll: impl FnMut(
            &mut Self,
            &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<R, Error>>,
    ) -> impl Future<Output = Result<R, Error>> {
        let mut suspended = false;
        std::future::poll_fn(move |cx| {
            if suspended {
                self.check_runtime_owner()?;
            }
            let result = poll(self, cx);
            suspended = result.is_pending();
            result
        })
    }

    pub(super) fn extension(&mut self) -> &mut Extended {
        self.extended
            .get_or_insert_with(|| Box::new(Extended::new()))
    }

    /// 一次性配置命名及可替换的未命名语句存储。
    /// 槽数为零时跳过配置和分配。
    pub fn configure_statements(&mut self, limits: StatementLimits) -> Result<(), Error> {
        self.check_idle()?;
        if self
            .extended
            .as_ref()
            .is_some_and(|extended| extended.limits.is_some())
        {
            return Err(Error::InvalidInput(
                "statement storage is already configured",
            ));
        }
        if limits.max_statements == 0 {
            return Ok(());
        }
        limits.slot_storage_minimum()?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.max_statements)
            .map_err(|_| Error::Limit("cannot allocate statement slots"))?;
        let actual = slots
            .capacity()
            .checked_mul(std::mem::size_of::<Slot>())
            .ok_or(Error::Limit("statement slot size overflow"))?;
        if actual > limits.max_metadata_bytes {
            return Err(Error::Limit(
                "actual statement slot storage exceeds its limit",
            ));
        }
        for _ in 0..limits.max_statements {
            slots.push(Slot {
                generation: 0,
                record: None,
            });
        }
        let extended = self.extension();
        extended.limits = Some(limits);
        extended.vacant_count = slots.len();
        extended.slots = slots;
        extended.first_vacant = 0;
        extended.metadata_bytes = actual;
        Ok(())
    }

    pub fn invalidate_statements(&mut self) -> Result<(), Error> {
        self.invalidate_statements_scoped(false)
    }

    fn invalidate_statements_scoped(&mut self, in_transaction: bool) -> Result<(), Error> {
        self.check_idle_state(in_transaction)?;
        self.bump_schema_epoch()
    }

    /// 使后续提交使用的布局失效，已提交操作仍使用原快照。
    pub(super) fn bump_schema_epoch(&mut self) -> Result<(), Error> {
        if let Some(extended) = self.extended.as_mut() {
            extended.bump_epoch()?;
        }
        Ok(())
    }

    pub(super) fn take_group_statement_changes(&mut self) -> bool {
        self.extended
            .as_mut()
            .is_some_and(|registry| std::mem::take(&mut registry.group_statements_changed))
    }

    pub(super) fn note_server_statement_reset(&mut self) -> Result<(), Error> {
        if let Some(extended) = self.extended.as_mut() {
            extended
                .mark_named_statements_closed()
                .inspect_err(|_| self.transport.break_connection())?;
        }
        Ok(())
    }

    pub(super) fn invalidate_unnamed_statement(&mut self) -> Result<(), Error> {
        if let Some(extended) = self.extended.as_mut() {
            extended.invalidate_unnamed()?;
        }
        Ok(())
    }

    pub fn reclaim_closed_statements(&mut self) -> Result<usize, Error> {
        self.reclaim_closed_statements_scoped(false)
    }

    fn reclaim_closed_statements_scoped(&mut self, in_transaction: bool) -> Result<usize, Error> {
        self.check_idle_state(in_transaction)?;
        self.extended
            .as_mut()
            .map_or(Ok(0), |extended| extended.reclaim_closed())
            .inspect_err(|_| self.transport.break_connection())
    }

    pub async fn prepare(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        formats: ResultFormats,
    ) -> Result<PreparedStatement, Error> {
        self.prepare_storage_scoped(
            sql,
            parameter_oids,
            formats,
            PreparedStatementStorage::Named,
            false,
        )
        .await
    }

    /// 在服务端未命名槽准备可重复执行的语句。
    /// 再次替换、one_shot、简单查询、未准备的 COPY 及事务控制都会使旧句柄和冻结数据包失效。
    /// 命名语句不受影响。
    ///
    /// 替换前需要空闲的元数据槽，旧布局在最后一个句柄或结果释放前仍计入预算。
    /// 可预留一个槽，或先关闭旧语句并释放其句柄和布局。
    pub async fn prepare_replace_unnamed(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        formats: ResultFormats,
    ) -> Result<PreparedStatement, Error> {
        self.prepare_storage_scoped(
            sql,
            parameter_oids,
            formats,
            PreparedStatementStorage::ReplaceableUnnamed,
            false,
        )
        .await
    }

    pub(super) async fn prepare_storage_scoped(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        formats: ResultFormats,
        storage: PreparedStatementStorage,
        in_transaction: bool,
    ) -> Result<PreparedStatement, Error> {
        self.check_idle_access(in_transaction)?;
        u16::try_from(parameter_oids.len())
            .map_err(|_| Error::Limit("too many parameter type hints"))?;
        if sql.len() > self.max_request_len
            || parameter_oids
                .len()
                .checked_mul(4)
                .is_none_or(|bytes| bytes > self.max_request_len)
        {
            return Err(Error::Limit(
                "prepare input cannot fit in the request limit",
            ));
        }
        let (index, generation, epoch, name) = {
            let extended = self.extended.as_deref_mut().ok_or(Error::InvalidInput(
                "configure statement storage before preparing",
            ))?;
            if extended.limits.is_none() {
                return Err(Error::InvalidInput(
                    "configure statement storage before preparing",
                ));
            }
            if extended.epoch_exhausted {
                return Err(Error::Limit("statement schema epoch is exhausted"));
            }
            extended
                .reclaim_closed()
                .inspect_err(|_| self.transport.break_connection())?;
            let index = extended.first_vacant;
            let slot = extended.slots.get(index).ok_or(Error::Limit(
                "statement slots are full; close unused statements and release their layouts",
            ))?;
            let generation = slot
                .generation
                .checked_add(1)
                .ok_or(Error::Limit("statement slot generation is exhausted"))?;
            let name = match storage {
                PreparedStatementStorage::Named => {
                    let name_id = extended
                        .next_name
                        .checked_add(1)
                        .ok_or(Error::Limit("statement name space is exhausted"))?;
                    frontend::StatementName::numbered(name_id)?
                }
                PreparedStatementStorage::ReplaceableUnnamed => frontend::StatementName::UNNAMED,
            };
            let budget = Self::prepared_layout_budget(Some(extended), parameter_oids.len())?;
            if std::mem::size_of::<RowLayout>() > budget {
                return Err(Error::Limit(
                    "minimum statement metadata exceeds its budget",
                ));
            }
            (index, generation, extended.schema_epoch, name)
        };

        let bytes = self.transport.encode_send_buffer(|bytes| {
            frontend::append_prepare(
                bytes,
                name.wire(),
                sql,
                parameter_oids,
                self.max_request_len,
            )
        })?;
        {
            let extended = self.extension();
            match storage {
                PreparedStatementStorage::Named => extended.next_name += 1,
                PreparedStatementStorage::ReplaceableUnnamed => {
                    extended.invalidate_unnamed()?;
                    extended.unnamed_slot = Some(index);
                }
            }
            let slot = extended.slots.get_mut(index).ok_or(Error::Broken)?;
            slot.generation = generation;
            slot.record = Some(Record {
                name,
                data: None,
                remote: RemoteStatement::Preparing,
            });
            extended.occupy_slots(1);
            // 提交任何 I/O 之前先登记服务端名称，后续才能在中断时正确关闭。
            extended.work_kind = Some(WorkKind::Prepare {
                slot: index,
                generation,
                phase: PreparePhase::Parse,
            });
        }
        self.active = true;
        self.remaining_boundaries = 1;
        if let Err(error) = self.transport.begin_send(bytes) {
            self.transport.break_connection();
            return Err(error);
        }
        let mut close_after_error = false;
        let result = self
            .read_prepared_member(
                parameter_oids,
                formats,
                PrepareIdentity {
                    slot: index,
                    generation,
                    epoch,
                },
                PrepareReadMode::Single {
                    close_after_error: &mut close_after_error,
                },
            )
            .await;
        if let Err(primary) = result {
            if !close_after_error {
                if self.active {
                    self.transport.break_connection();
                }
                return Err(primary);
            }
            let mut server_error = None;
            let cleanup = async {
                if self.active {
                    self.recover_to_ready_bounded(None, None, Some(&mut server_error))
                        .await?;
                }
                // 已确认 Ready，可通过协议 Close 释放本次未交付的语句。
                // 失败事务也允许 Close，无需隐式回滚。
                self.send_close_record(index, generation).await
            }
            .await;
            let cleanup = match server_error {
                Some(server_error) => {
                    Err(with_cleanup_error(Error::Database(server_error), cleanup))
                }
                None => cleanup,
            };
            return Err(with_cleanup_error(primary, cleanup));
        }
        result
    }

    fn prepared_layout_budget(
        extended: Option<&Extended>,
        parameter_count: usize,
    ) -> Result<usize, Error> {
        let extended = extended.ok_or(Error::Broken)?;
        let parameter_bytes = parameter_count
            .checked_mul(std::mem::size_of::<Oid>())
            .ok_or(Error::Limit("parameter metadata overflow"))?;
        let reserved = extended
            .metadata_bytes
            .checked_add(parameter_bytes)
            .and_then(|value| value.checked_add(std::mem::size_of::<StatementData>()))
            .ok_or(Error::Limit("statement metadata overflow"))?;
        extended
            .limits
            .ok_or(Error::Broken)?
            .max_metadata_bytes
            .checked_sub(reserved)
            .ok_or(Error::Limit("statement metadata budget exhausted"))
    }

    async fn read_prepared_member(
        &mut self,
        hints: &[Oid],
        formats: ResultFormats,
        identity: PrepareIdentity,
        mut mode: PrepareReadMode<'_>,
    ) -> Result<PreparedStatement, Error> {
        let PrepareIdentity {
            slot: index,
            generation,
            epoch,
        } = identity;
        let mut parsed = false;
        let mut parameters: Option<(Box<[Oid]>, usize)> = None;
        let mut layout = None;
        let mut formats = Some(formats);
        let mut failure = None;
        let max_messages = self.max_messages;
        for frames in 1..=max_messages {
            self.transport.receive_frame_on_owner().await?;
            let frame = self.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            let message = protocol::parse_backend(frame)?;
            let mut status = None;
            let mut path_changed = false;
            match message {
                BackendMessage::ParseComplete if !parsed && failure.is_none() => parsed = true,
                BackendMessage::ParameterDescription(description)
                    if parsed && parameters.is_none() && failure.is_none() =>
                {
                    let layout_budget =
                        Self::prepared_layout_budget(self.extended.as_deref(), description.len())
                            .map_err(|error| mode.metadata_error(error))?;
                    if size_of::<RowLayout>() > layout_budget {
                        return Err(mode.metadata_error(Error::Limit(
                            "minimum statement metadata exceeds its budget",
                        )));
                    }
                    let mut values = Vec::new();
                    values.try_reserve_exact(description.len()).map_err(|_| {
                        mode.metadata_error(Error::Limit("cannot allocate parameter metadata"))
                    })?;
                    for (position, oid) in description.iter().enumerate() {
                        let oid = Oid(oid);
                        if oid.0 == 0
                            || hints
                                .get(position)
                                .is_some_and(|hint| hint.0 != 0 && *hint != oid)
                        {
                            return Err(protocol_error(
                                "resolved parameter types do not match the preparation hints",
                            ));
                        }
                        values.push(oid);
                    }
                    if hints.len() > values.len() {
                        return Err(protocol_error(
                            "parameter description is shorter than the supplied hints",
                        ));
                    }
                    parameters = Some((values.into_boxed_slice(), layout_budget));
                }
                BackendMessage::RowDescription(description)
                    if parameters.is_some() && layout.is_none() && failure.is_none() =>
                {
                    let maximum = parameters.as_ref().ok_or(Error::Broken)?.1;
                    layout = Some(Rc::new(
                        RowLayout::from_description_checked::<Error>(
                            description,
                            formats.take().ok_or(Error::Broken)?,
                            Ok(maximum),
                            |description, _| {
                                if description.uniform_format() != Some(Format::Text) {
                                    return Err(protocol_error(
                                        "statement Describe has an execution format",
                                    ));
                                }
                                Ok(())
                            },
                        )
                        .map_err(|error| mode.metadata_error(error))?,
                    ));
                }
                BackendMessage::NoData
                    if parameters.is_some() && layout.is_none() && failure.is_none() =>
                {
                    let empty = RowLayout::new(Vec::new(), formats.take().ok_or(Error::Broken)?)
                        .map_err(|error| mode.metadata_error(error.into()))?;
                    let maximum = parameters.as_ref().ok_or(Error::Broken)?.1;
                    if empty.retained_bytes() > maximum {
                        return Err(mode.metadata_error(Error::Limit(
                            "empty statement layout exceeds its metadata budget",
                        )));
                    }
                    layout = Some(Rc::new(empty));
                }
                BackendMessage::ErrorResponse(error) if !is_fatal(error) => {
                    if failure.is_none() {
                        failure = Some(match &mut mode {
                            PrepareReadMode::Single { .. } => owned_error(error),
                            PrepareReadMode::Pipeline(remaining) => {
                                owned_error_bounded(error, remaining)?
                            }
                        });
                    }
                }
                BackendMessage::ErrorResponse(error) => {
                    let limit = match &mode {
                        PrepareReadMode::Single { .. } => None,
                        PrepareReadMode::Pipeline(remaining) => Some(**remaining),
                    };
                    return Err(terminal_database_error(error, limit));
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    path_changed = name == "search_path";
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ReadyForQuery(ready)
                    if failure.is_some()
                        || (parsed && parameters.is_some() && layout.is_some()) =>
                {
                    status = Some(ready)
                }
                _ => {
                    return Err(protocol_error(
                        "unexpected response while preparing a general statement",
                    ));
                }
            }
            self.transport.consume_frame()?;
            // 保存已消费的协议阶段。
            // 放弃等待后可以释放局部元数据，但恢复仍须按次序读完 Describe 的响应。
            self.update_prepare_phase(
                identity,
                if failure.is_some() {
                    PreparePhase::Failed
                } else if layout.is_some() {
                    PreparePhase::Complete
                } else if parameters.is_some() {
                    PreparePhase::Description
                } else if parsed {
                    PreparePhase::Parameters
                } else {
                    PreparePhase::Parse
                },
            )?;
            if path_changed {
                self.bump_schema_epoch()?;
            }
            if matches!(mode, PrepareReadMode::Pipeline(_)) {
                let quantum = self.execution_quantum_mut()?;
                quantum.spend_bytes(work_bytes);
                if status.is_none() && frames < max_messages {
                    quantum.yield_on_worker().await?;
                }
            }
            if let Some(status) = status {
                self.note_ready(status)?;
                // 在收到协议确认时更新状态，本地发送未完成时原 future 仍可能被放弃。
                if failure.is_some() {
                    self.retire_uncreated_prepare(index, generation)?;
                }
                if let PrepareReadMode::Single { close_after_error } = &mut mode {
                    self.transport
                        .finish_send_on_owner()
                        .await
                        .map_err(|send| send_after_diagnostic(failure.take(), send))?;
                    self.active = false;
                    self.extension().work_kind = None;
                    // Parse 已成功时，Describe 或 Sync 的错误不会关闭这个服务端名称。
                    **close_after_error = parsed && failure.is_some();
                }
                if let Some(error) = failure {
                    return Err(Error::Database(error));
                }
                let (parameters, _) = parameters.ok_or(Error::Broken)?;
                let layout = layout.ok_or(Error::Broken)?;
                let charge = StatementData::metadata_bytes(&parameters, &layout)?;
                let extended = self.extension();
                let maximum = extended.limits.ok_or(Error::Broken)?.max_metadata_bytes;
                let used = extended
                    .metadata_bytes
                    .checked_add(charge)
                    .ok_or(Error::Limit("statement metadata size overflow"))?;
                if used > maximum {
                    return Err(mode.metadata_error(Error::Limit(
                        "statement metadata exceeds its limit; close its retained remote name",
                    )));
                }
                let storage = if extended.unnamed_slot == Some(index) {
                    PreparedStatementStorage::ReplaceableUnnamed
                } else {
                    PreparedStatementStorage::Named
                };
                let record = extended
                    .slots
                    .get_mut(index)
                    .and_then(|slot| slot.record.as_mut())
                    .ok_or(Error::Broken)?;
                let data = Rc::new(StatementData::new(
                    record.name.wire(),
                    parameters,
                    layout,
                    storage,
                )?);
                record.data = Some(data.clone());
                extended.metadata_bytes = used;
                return Ok(PreparedStatement {
                    connection_id: self.id,
                    slot: index,
                    generation,
                    schema_epoch: epoch,
                    data,
                });
            }
        }
        Err(Error::Limit(
            "prepare exceeded the configured message count",
        ))
    }

    fn update_prepare_phase(
        &mut self,
        identity: PrepareIdentity,
        next: PreparePhase,
    ) -> Result<(), Error> {
        let extended = self.extended.as_mut().ok_or(Error::Broken)?;
        let phase = match extended.work_kind.as_mut().ok_or(Error::Broken)? {
            WorkKind::Prepare {
                slot,
                generation,
                phase,
            } if *slot == identity.slot && *generation == identity.generation => phase,
            WorkKind::PreparePipeline(progress) if progress.current()? == identity => {
                &mut progress.phase
            }
            _ => return Err(Error::Broken),
        };
        if *phase == PreparePhase::Parse && next == PreparePhase::Parameters {
            let slot = extended.slots.get_mut(identity.slot).ok_or(Error::Broken)?;
            if slot.generation != identity.generation {
                return Err(Error::Broken);
            }
            slot.record.as_mut().ok_or(Error::Broken)?.remote = RemoteStatement::Created;
        }
        *phase = next;
        Ok(())
    }

    fn retire_uncreated_prepare(&mut self, index: usize, generation: u64) -> Result<(), Error> {
        let extended = self.extended.as_mut().ok_or(Error::Broken)?;
        let slot = extended
            .slots
            .get_mut(index)
            .ok_or(Error::InvalidInput("statement slot is missing"))?;
        if slot.generation != generation {
            return Err(Error::InvalidInput("statement generation changed"));
        }
        let record = slot.record.as_ref().ok_or(Error::Broken)?;
        match record.remote {
            RemoteStatement::Created => return Ok(()),
            RemoteStatement::Closed { .. } => return Err(Error::Broken),
            RemoteStatement::Preparing => {}
        }
        extended.metadata_bytes = extended
            .metadata_bytes
            .checked_sub(record.charged_bytes()?)
            .ok_or(Error::Broken)?;
        slot.record = None;
        extended.first_vacant = extended.first_vacant.min(index);
        extended.vacant_count += 1;
        if extended.unnamed_slot == Some(index) {
            extended.unnamed_slot = None;
        }
        Ok(())
    }

    /// 校验语句标识和布局。
    /// 调用方已确认会话空闲，或持有当前活动窗口。
    pub(super) fn check_prepared_snapshot(
        &self,
        statement: &PreparedStatement,
        require_layout: bool,
    ) -> Result<(), Error> {
        Self::resolve_prepared(self.id, self.extended.as_deref(), statement, require_layout)
            .map(|_| ())
    }

    pub(super) fn resolve_prepared<'a>(
        connection_id: u64,
        extended: Option<&'a Extended>,
        statement: &'a PreparedStatement,
        require_layout: bool,
    ) -> Result<PreparedAdmission<'a>, Error> {
        if statement.connection_id != connection_id {
            return Err(Error::InvalidInput(
                "statement belongs to another connection",
            ));
        }
        let Some(extended) = extended else {
            return Err(Error::InvalidInput("statement registry is missing"));
        };
        let Some(slot) = extended.slots.get(statement.slot) else {
            return Err(Error::InvalidInput("statement slot is missing"));
        };
        let Some(record) = slot.record.as_ref() else {
            return Err(Error::InvalidInput("statement has been retired"));
        };
        if slot.generation != statement.generation
            || !matches!(record.remote, RemoteStatement::Created)
        {
            return Err(Error::InvalidInput("statement handle is stale"));
        }
        // 句柄只在语句准备完成后创建。会话标识和槽代次唯一确定创建时的元数据。
        let data = &statement.data;
        if require_layout
            && (extended.epoch_exhausted || statement.schema_epoch != extended.schema_epoch)
        {
            return Err(Error::InvalidInput(
                "statement metadata was invalidated; close and prepare it again",
            ));
        }
        Ok(PreparedAdmission {
            name: record.name.wire(),
            parameter_oids: &data.parameters,
            bind_size: data.bind_size,
            bind_formats: data.bind_formats(),
            layout: &data.layout,
        })
    }

    #[cfg(test)]
    fn prepared_name<'a>(&'a self, statement: &'a PreparedStatement) -> Result<&'a [u8], Error> {
        Self::resolve_prepared(self.id, self.extended.as_deref(), statement, false)
            .map(|admission| admission.name.bytes_with_nul())
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub fn invalidate_statements(&mut self) -> Result<(), Error> {
        self.session_mut().invalidate_statements_scoped(true)
    }

    /// 回收已关闭且没有句柄或结果引用的语句记录。
    /// 只检查本地注册表，不发送 Close。
    pub fn reclaim_closed_statements(&mut self) -> Result<usize, Error> {
        self.session_mut().reclaim_closed_statements_scoped(true)
    }

    pub async fn prepare(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        formats: ResultFormats,
    ) -> Result<PreparedStatement, Error> {
        self.session_mut()
            .prepare_storage_scoped(
                sql,
                parameter_oids,
                formats,
                PreparedStatementStorage::Named,
                true,
            )
            .await
    }

    /// 替换当前事务的未命名语句。
    /// 后续事务控制、one_shot、简单查询或非预备 COPY 会使旧句柄及冻结执行包失效。
    /// 替换需空闲的元数据槽，仅释放旧句柄不会关闭其服务端语句。
    pub async fn prepare_replace_unnamed(
        &mut self,
        sql: &str,
        parameter_oids: &[Oid],
        formats: ResultFormats,
    ) -> Result<PreparedStatement, Error> {
        self.session_mut()
            .prepare_storage_scoped(
                sql,
                parameter_oids,
                formats,
                PreparedStatementStorage::ReplaceableUnnamed,
                true,
            )
            .await
    }
}

impl<T: WireTransport> Session<T> {
    pub async fn close_prepared(&mut self, statement: &PreparedStatement) -> Result<(), Error> {
        self.close_prepared_scoped(statement, false).await
    }

    async fn close_prepared_scoped(
        &mut self,
        statement: &PreparedStatement,
        in_transaction: bool,
    ) -> Result<(), Error> {
        self.check_idle_access(in_transaction)?;
        self.check_prepared_snapshot(statement, false)?;
        self.send_close_record(statement.slot, statement.generation)
            .await
    }

    async fn send_close_record(&mut self, index: usize, generation: u64) -> Result<(), Error> {
        let bytes = {
            let slot = self
                .extended
                .as_ref()
                .and_then(|extended| extended.slots.get(index))
                .ok_or(Error::InvalidInput("statement slot is missing"))?;
            if slot.generation != generation {
                return Err(Error::InvalidInput("statement handle is stale"));
            }
            let record = slot
                .record
                .as_ref()
                .ok_or(Error::InvalidInput("statement is retired"))?;
            self.transport.encode_send_buffer(|bytes| {
                frontend::append_close_sync(bytes, record.name.wire(), self.max_request_len)
            })?
        };
        self.active = true;
        self.remaining_boundaries = 1;
        self.extension().work_kind = Some(WorkKind::Close {
            slot: index,
            generation,
            phase: ClosePhase::Waiting,
        });
        let result = self.close_record_inner(bytes).await;
        if result.is_err() && self.active {
            self.transport.break_connection();
        }
        result
    }

    async fn close_record_inner(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.transport.begin_send(bytes)?;
        let mut diagnostic_budget = usize::MAX;
        let result = self
            .read_close_member::<false>(&mut diagnostic_budget, true)
            .await?;
        if let Err(send) = self.transport.finish_send_on_owner().await {
            return Err(send_after_diagnostic(result.err(), send));
        }
        self.active = false;
        self.extension().work_kind = None;
        result.map_err(Error::Database)
    }

    fn mark_record_closed(&mut self, index: usize, generation: u64) -> Result<(), Error> {
        let extended = self.extension();
        let slot = extended
            .slots
            .get_mut(index)
            .ok_or(Error::InvalidInput("statement slot is missing"))?;
        if slot.generation != generation {
            return Err(Error::InvalidInput("statement generation changed"));
        }
        let record = slot
            .record
            .as_mut()
            .ok_or(Error::InvalidInput("statement is retired"))?;
        record.mark_closed(index, &mut extended.first_closed);
        if extended.unnamed_slot == Some(index) {
            extended.unnamed_slot = None;
        }
        Ok(())
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub async fn close_prepared(&mut self, statement: &PreparedStatement) -> Result<(), Error> {
        self.session_mut()
            .close_prepared_scoped(statement, true)
            .await
    }
}

impl<T: WireTransport> Session<T> {
    /// 执行已准备的语句。
    /// 所选调度预算同时覆盖结果处理、完成确认及放弃后的恢复。
    /// `abandon` 指定放弃已接纳查询后的处置策略。原始逐行读取返回本地错误时保留协议进度，
    /// 收集和回调终端可指定各自的错误策略。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn query<'s>(
        &'s mut self,
        statement: &PreparedStatement,
        parameters: &[Parameter<'_>],
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.query_scoped(statement, parameters, options, abandon, false)
    }

    fn query_scoped<'s>(
        &'s mut self,
        statement: &PreparedStatement,
        parameters: &[Parameter<'_>],
        options: QueryOptions,
        abandon: AbandonPolicy,
        in_transaction: bool,
    ) -> Result<Query<'s, T>, Error> {
        self.query_scoped_with_layout(
            statement,
            parameters,
            options,
            abandon.on_error(),
            in_transaction,
            |_| Ok(None),
        )
    }

    pub(super) fn query_scoped_with_layout<'s>(
        &'s mut self,
        statement: &PreparedStatement,
        parameters: &[Parameter<'_>],
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
        check_layout: impl FnOnce(&RowLayout) -> Result<Option<u16>, Error>,
    ) -> Result<Query<'s, T>, Error> {
        self.check_idle_access(in_transaction)?;
        let QueryOptions { limits, scheduling } = options;
        let quantum = ExecutionQuantum::new(scheduling);
        let admission = Self::resolve_prepared(self.id, self.extended.as_deref(), statement, true)?;
        let matched = admission.parameters(
            parameters,
            "parameter count differs from the prepared statement",
        )?;
        let mut projected = None;
        let packet = admission.packet(
            &matched,
            QueryTail::Sync,
            self.max_request_len,
            "parameter type differs from the prepared statement",
            || {
                admission.validate_metadata(
                    limits.max_metadata_bytes,
                    "prepared result metadata exceeds the query limit",
                )?;
                projected = check_layout(admission.layout)?;
                Ok(())
            },
        )?;
        let bytes = packet.encode_into(self.transport.take_send_buffer()?, self.max_request_len)?;
        self.admit_query(
            bytes,
            QueryMode::Prepared,
            match projected {
                Some(columns) => QueryLayout::Columns(columns),
                None => QueryLayout::Shared(Rc::clone(&statement.data.layout)),
            },
            limits,
            quantum,
            on_error,
        )
    }

    /// 一次往返内执行未命名语句并 Describe portal。
    /// 若必须先校验结果布局再执行 SQL，请先 prepare。
    /// 行读取与错误策略见 [`Self::query`]。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn one_shot<'s>(
        &'s mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        formats: ResultFormats,
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.one_shot_scoped(sql, parameters, formats, options, abandon.on_error(), false)
    }

    pub(super) fn one_shot_scoped<'s>(
        &'s mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        formats: ResultFormats,
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
    ) -> Result<Query<'s, T>, Error> {
        self.check_idle_access(in_transaction)?;
        let QueryOptions { limits, scheduling } = options;
        let quantum = ExecutionQuantum::new(scheduling);
        u16::try_from(parameters.len())
            .map_err(|_| Error::Limit("too many one-shot parameters"))?;
        if sql.len() > self.max_request_len
            || parameters
                .len()
                .checked_mul(4)
                .is_none_or(|bytes| bytes > self.max_request_len)
        {
            return Err(Error::Limit(
                "one-shot input cannot fit in the request limit",
            ));
        }
        // 未知列数时仅 All(Text) 可省略格式码。显式列列表须匹配 Describe 返回的列数。
        let bind_formats = match &formats {
            ResultFormats::All(Format::Text) => &[][..],
            formats => formats.as_slice(),
        };
        let bytes = frontend::one_shot(
            || self.transport.take_send_buffer(),
            sql,
            parameters,
            bind_formats,
            true,
            QueryTail::Sync,
            self.max_request_len,
        )?;
        self.admit_query(
            bytes,
            QueryMode::OneShot,
            QueryLayout::Pending(formats),
            limits,
            quantum,
            on_error,
        )
    }

    /// 仅适用于调用方保证的单条可信 SQL。
    /// 此入口不解析 SQL，传入的额外语句可能在客户端发现前执行。
    /// 行读取与错误策略见 [`Self::query`]。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn query_simple_single<'s>(
        &'s mut self,
        sql: &str,
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.query_simple_single_scoped(sql, options, abandon.on_error(), false)
    }

    /// 在空闲会话执行 DISCARD ALL，并使本地语句句柄失效。
    /// 已返回的结果仍可持有原布局。若服务端拒绝重置，必须丢弃连接。
    pub async fn reset_session(&mut self) -> Result<(), Error> {
        if self.transaction_status != TransactionStatus::Idle {
            self.check_idle()?;
            return Err(Error::InvalidInput(
                "session reset requires an idle transaction status",
            ));
        }
        let mut query = self.query_simple_single_scoped(
            "DISCARD ALL",
            QueryOptions {
                limits: QueryLimits {
                    max_rows: 0,
                    max_result_bytes: 0,
                    max_metadata_bytes: size_of::<RowLayout>(),
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            OnError::RecoverExplicitly,
            false,
        )?;
        query.state_mut()?.mode = QueryMode::ResetSession;
        query
            .map_result_row_on_owner(Some(&mut ResultShape::default()), |_, _, _| ())
            .await
            .map(|_| ())
            .inspect_err(|_| query.session.transport.break_connection())
    }

    fn query_simple_single_scoped<'s>(
        &'s mut self,
        sql: &str,
        options: QueryOptions,
        on_error: OnError,
        in_transaction: bool,
    ) -> Result<Query<'s, T>, Error> {
        self.check_idle_access(in_transaction)?;
        let QueryOptions { limits, scheduling } = options;
        let quantum = ExecutionQuantum::new(scheduling);
        let packet = frontend::SimpleQueryPacket::simple(sql, self.max_request_len)?;
        let buffer = self.transport.take_send_buffer()?;
        let bytes = packet.encode_into(buffer)?;
        self.admit_query(
            bytes,
            QueryMode::Simple,
            QueryLayout::Pending(ResultFormats::All(Format::Text)),
            limits,
            quantum,
            on_error,
        )
    }

    fn admit_query(
        &mut self,
        bytes: Vec<u8>,
        mode: QueryMode,
        layout: QueryLayout,
        limits: QueryLimits,
        mut quantum: ExecutionQuantum,
        on_error: OnError,
    ) -> Result<Query<'_, T>, Error> {
        if self.remaining_boundaries != 0 {
            return Err(Error::Busy);
        }
        {
            let extended = self.extension();
            if extended.pending_frame {
                return Err(Error::Busy);
            }
            quantum.spend_bytes(bytes.len());
            let (layout, result_columns, formats) = match layout {
                QueryLayout::Shared(layout) => {
                    let columns = layout.len();
                    (Some(layout), columns, None)
                }
                QueryLayout::Columns(columns) => (None, usize::from(columns), None),
                QueryLayout::Pending(formats) => (None, 0, Some(formats)),
            };
            extended.query = Some(QueryState {
                cancel: None,
                io_started: false,
                quantum,
                on_error,
                mode,
                layout,
                result_columns,
                formats,
                limits,
                parsed: mode != QueryMode::OneShot,
                bound: mode.is_simple(),
                described: mode == QueryMode::Prepared,
                command: None,
                rows: 0,
                result_bytes_left: limits.max_result_bytes,
                control_messages: 0,
                error_seen: false,
                failure: None,
                ready: None,
            });
            extended.work_kind = Some(WorkKind::Query);
        }
        self.active = true;
        self.remaining_boundaries = 1;
        if mode != QueryMode::Prepared {
            self.invalidate_unnamed_statement()?;
        }
        if let Err(error) = self.transport.begin_send(bytes) {
            self.transport.break_connection();
            return Err(error);
        }
        Ok(Query {
            session: self,
            finished: false,
            completion: None,
            final_layout: None,
        })
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 在本事务执行预备语句，行读取与错误策略见 [`Session::query`]。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn query<'s>(
        &'s mut self,
        statement: &PreparedStatement,
        parameters: &[Parameter<'_>],
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.session_mut()
            .query_scoped(statement, parameters, options, abandon, true)
    }

    /// 在本事务执行一次性查询，参见 [`Session::one_shot`]。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn one_shot<'s>(
        &'s mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        formats: ResultFormats,
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.session_mut().one_shot_scoped(
            sql,
            parameters,
            formats,
            options,
            abandon.on_error(),
            true,
        )
    }

    /// 在本事务执行调用方保证的单条可信 SQL。
    /// 此入口不解析或拆分语句，并会使未命名语句失效。
    /// 行读取与错误策略见 [`Session::query`]。
    #[expect(
        clippy::unused_async,
        reason = "请求只在首次轮询时接纳，构造 future 不修改会话"
    )]
    pub async fn query_simple_single<'s>(
        &'s mut self,
        sql: &str,
        options: QueryOptions,
        abandon: AbandonPolicy,
    ) -> Result<Query<'s, T>, Error> {
        self.session_mut()
            .query_simple_single_scoped(sql, options, abandon.on_error(), true)
    }
}

impl<T: WireTransport> Session<T> {
    /// 排空已接纳的响应直至对应的 Ready，不发送新的 Sync、不重放 SQL，也不代为提交或回滚。
    /// 消息数量达到本次上限时保留剩余进度，调用方可再次显式恢复。
    /// COPY 使用专用的结束或拒绝输入接口。
    pub async fn recover_to_ready(&mut self) -> Result<(), Error> {
        let limits = self
            .extended
            .as_ref()
            .and_then(|extended| extended.query.as_ref())
            .map(|query| (query.limits.max_rows, query.limits.max_result_bytes));
        self.recover_to_ready_bounded(limits, None, None).await
    }

    pub(super) async fn drain_window_to_ready(
        &mut self,
        max_rows: usize,
        max_row_bytes: Option<usize>,
        diagnostic_limit: Option<usize>,
    ) -> Result<(), Error> {
        let (rows, bytes) = self
            .extended
            .as_deref_mut()
            .and_then(Extended::pipeline_progress_mut)
            .ok_or(Error::Broken)?
            .pending_window_limits()?;
        let bytes = max_row_bytes.map_or(bytes, |limit| bytes.min(limit));
        self.recover_to_ready_bounded(Some((rows.min(max_rows), bytes)), diagnostic_limit, None)
            .await
    }

    /// 显式限制本次恢复可丢弃的行数与编码字节数。
    /// 恢复不保留结果，也不新建协议边界。
    pub fn recover_to_ready_with_limits(
        &mut self,
        max_rows: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<(), Error>> {
        self.recover_to_ready_bounded(Some((max_rows, max_bytes)), None, None)
    }

    async fn recover_to_ready_bounded(
        &mut self,
        limits: Option<(usize, usize)>,
        diagnostic_limit: Option<usize>,
        prepare_error: Option<&mut Option<DatabaseError>>,
    ) -> Result<(), Error> {
        if self.transport.is_broken() {
            return Err(Error::Broken);
        }
        self.check_runtime_owner()?;
        if self.copy_state.is_some() {
            return Err(Error::Unsupported(
                "COPY requires its explicit completion or abort operation",
            ));
        }
        if let Some(extended) = self.extended.as_mut() {
            if extended.callback_in_progress.get() {
                self.transport.break_connection();
                return Err(Error::Broken);
            }
            if extended.provisional_window_requires_discard() {
                self.transport.break_connection();
                return Err(Error::Unsupported(
                    "this operation selected discard after handoff",
                ));
            }
            if extended.pending_frame {
                self.transport.consume_frame()?;
                extended.pending_frame = false;
            }
        }
        let result = self
            .recover_general_inner(limits, diagnostic_limit, prepare_error)
            .await;
        if result.is_err() && !matches!(result, Err(Error::Limit(_))) {
            self.transport.break_connection();
        }
        result
    }

    async fn recover_general_inner(
        &mut self,
        limits: Option<(usize, usize)>,
        diagnostic_limit: Option<usize>,
        mut prepare_error: Option<&mut Option<DatabaseError>>,
    ) -> Result<(), Error> {
        // 即使最后一个 Ready 已消费，活动操作仍须提供可恢复的协议状态。
        if (self.active || self.remaining_boundaries != 0)
            && self.pending_transaction_control.is_none()
            && self
                .extended
                .as_ref()
                .and_then(|state| state.work_kind.as_ref())
                .is_none()
        {
            self.transport.break_connection();
            return Err(Error::Broken);
        }
        let mut controls = 0_usize;
        let mut rows = 0_usize;
        let mut bytes = 0_usize;
        let execution_scheduled = matches!(
            self.extended
                .as_ref()
                .and_then(|extended| extended.work_kind.as_ref()),
            Some(
                WorkKind::Query
                    | WorkKind::Pipeline(_)
                    | WorkKind::ProvisionalWindow(_)
                    | WorkKind::ClosePipeline(_)
                    | WorkKind::PreparePipeline(_)
            )
        );
        if execution_scheduled {
            self.execution_quantum_mut()?.yield_on_worker().await?;
        }
        if let Some(query) = self
            .extended
            .as_mut()
            .and_then(|state| state.query.as_mut())
        {
            query.start_io()?;
        }
        while self.remaining_boundaries != 0 {
            self.transport.receive_frame_on_owner().await?;
            let frame = self.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            let message = protocol::parse_backend(frame)?;
            if let BackendMessage::ErrorResponse(error) = message
                && let Some(saved) = prepare_error.as_deref_mut()
                && saved.is_none()
                && !is_fatal(error)
            {
                *saved = Some(owned_error(error));
            }
            if diagnostic_limit.is_some()
                && let BackendMessage::ErrorResponse(error) = message
                && is_fatal(error)
            {
                let error = terminal_database_error(error, diagnostic_limit);
                self.transport.break_connection();
                return Err(error);
            }
            let data = if let BackendMessage::DataRow(row) = message {
                Some(
                    row.encoded_fields()
                        .len()
                        .checked_add(4)
                        .ok_or(Error::Limit("recovery byte count overflow"))?,
                )
            } else {
                None
            };
            // 先校验本次授权再消费当前帧。
            // 达到限额时调用方可在下一次恢复中扩大预算。
            if let Some(row_bytes) = data {
                if let Some((max_rows, max_bytes)) = limits {
                    let next_rows = rows
                        .checked_add(1)
                        .ok_or(Error::Limit("recovery row count overflow"))?;
                    let next_bytes = bytes
                        .checked_add(row_bytes)
                        .ok_or(Error::Limit("recovery byte count overflow"))?;
                    if next_rows > max_rows || next_bytes > max_bytes {
                        return Err(Error::Limit("recovery reached its selected data limit"));
                    }
                    rows = next_rows;
                    bytes = next_bytes;
                }
                controls = 0;
            } else {
                if controls == self.max_messages {
                    return Err(Error::Limit(
                        "recovery reached its per-call control message limit",
                    ));
                }
                controls += 1;
            }
            let step = match Self::recovery_step(
                self.extended.as_deref(),
                self.pending_transaction_control.is_some(),
                message,
            ) {
                Ok(step) => step,
                Err(error) => {
                    self.transport.break_connection();
                    return Err(error);
                }
            };
            if let Err(error) = self.apply_recovery_step(step) {
                self.transport.break_connection();
                return Err(error);
            }
            self.transport.consume_frame()?;
            if execution_scheduled {
                let quantum = self.execution_quantum_mut()?;
                quantum.spend_bytes(work_bytes);
                quantum.yield_on_worker().await?;
            }
        }
        // 最后一个 Ready 已被原 future 消费时，只需等待本地发送完成。
        if let Err(send) = self.transport.finish_send_on_owner().await {
            let diagnostic = self
                .extended
                .as_mut()
                .and_then(|state| state.query.as_mut())
                .filter(|query| query.ready.is_some())
                .and_then(|query| query.failure.take());
            return Err(send_after_diagnostic(diagnostic, send));
        }
        self.transport.disable_send_queue()?;
        self.finish_pending_control_send()?;
        self.active = false;
        self.finish_taken_transaction_end_recovery();
        if let Some(extended) = self.extended.as_mut() {
            if extended.query_cancel_requested() {
                self.transport.break_connection();
            }
            extended.clear_work();
            extended.query = None;
        }
        Ok(())
    }

    pub(super) fn execution_quantum_mut(&mut self) -> Result<&mut ExecutionQuantum, Error> {
        let extended = self.extended.as_mut().ok_or(Error::Broken)?;
        match extended.work_kind.as_mut().ok_or(Error::Broken)? {
            WorkKind::Query => Ok(&mut extended.query.as_mut().ok_or(Error::Broken)?.quantum),
            WorkKind::Pipeline(progress) => Ok(&mut progress.quantum),
            WorkKind::ProvisionalWindow(progress) => Ok(&mut progress.pipeline.quantum),
            WorkKind::ClosePipeline(progress) => Ok(&mut progress.quantum),
            WorkKind::PreparePipeline(progress) => Ok(&mut progress.quantum),
            _ => Err(Error::Broken),
        }
    }

    fn recovery_step(
        extended: Option<&Extended>,
        pending_control: bool,
        message: BackendMessage<'_>,
    ) -> Result<RecoveryStep, Error> {
        match message {
            BackendMessage::NoticeResponse(_) | BackendMessage::NotificationResponse { .. } => {
                return Ok(RecoveryStep::Noop);
            }
            BackendMessage::ParameterStatus { name, value } => {
                validate_parameter(name, value)?;
                return Ok(RecoveryStep::Parameter(name == "search_path"));
            }
            BackendMessage::ErrorResponse(error) => {
                let resetting = extended
                    .and_then(|extended| extended.query.as_ref())
                    .is_some_and(|query| query.mode == QueryMode::ResetSession);
                return if resetting || is_fatal(error) {
                    Err(Error::Database(owned_error(error)))
                } else {
                    Ok(RecoveryStep::Error)
                };
            }
            _ => {}
        }
        if pending_control {
            return match message {
                BackendMessage::CommandComplete(tag) => Ok(RecoveryStep::TransactionCommand(
                    super::transaction::ControlKind::from_tag(protocol::parse_command_tag(tag)?)?,
                )),
                BackendMessage::ReadyForQuery(status) => Ok(RecoveryStep::Ready(status)),
                _ => Err(protocol_error(
                    "unexpected response while recovering transaction control",
                )),
            };
        }
        let extended = extended.ok_or(Error::Broken)?;
        match extended.work_kind.as_ref().ok_or(Error::Broken)? {
            WorkKind::Prepare { phase, .. } => Self::prepare_recovery_step(*phase, message),
            WorkKind::PreparePipeline(progress) => {
                progress.current()?;
                Self::prepare_recovery_step(progress.phase, message)
            }
            WorkKind::Close { phase, .. } => Self::close_recovery_step(*phase, message),
            WorkKind::ClosePipeline(progress) => {
                progress.current()?;
                Self::close_recovery_step(progress.phase, message)
            }
            WorkKind::Pipeline(progress)
            | WorkKind::ProvisionalWindow(super::pipeline::ProvisionalProgress {
                pipeline: progress,
                ..
            }) => {
                if let BackendMessage::DataRow(row) = message
                    && row.len() != progress.columns()?
                {
                    return Err(protocol_error(
                        "recovered pipeline row has the wrong column count",
                    ));
                }
                if let BackendMessage::CommandComplete(tag) = message {
                    let (kind, _) = command_kind(protocol::parse_command_tag(tag)?);
                    return Ok(RecoveryStep::PipelineCommand(kind));
                }
                Ok(RecoveryStep::Pipeline(
                    super::pipeline::PipelineSignal::from_message(message)?,
                ))
            }
            WorkKind::Query => Self::query_recovery_step(extended, message),
        }
    }

    fn close_recovery_step(
        phase: ClosePhase,
        message: BackendMessage<'_>,
    ) -> Result<RecoveryStep, Error> {
        match message {
            BackendMessage::CloseComplete if phase == ClosePhase::Waiting => {
                Ok(RecoveryStep::CloseComplete)
            }
            BackendMessage::ReadyForQuery(status)
                if matches!(phase, ClosePhase::Complete | ClosePhase::Failed) =>
            {
                Ok(RecoveryStep::Ready(status))
            }
            _ => Err(protocol_error(
                "unexpected response while closing a statement",
            )),
        }
    }

    fn prepare_recovery_step(
        phase: PreparePhase,
        message: BackendMessage<'_>,
    ) -> Result<RecoveryStep, Error> {
        match message {
            BackendMessage::ParseComplete if phase == PreparePhase::Parse => {
                Ok(RecoveryStep::Prepare(PreparePhase::Parameters))
            }
            BackendMessage::ParameterDescription(description)
                if phase == PreparePhase::Parameters =>
            {
                for oid in description.iter() {
                    if oid == 0 {
                        return Err(protocol_error(
                            "unresolved parameter type in recovered Describe",
                        ));
                    }
                }
                Ok(RecoveryStep::Prepare(PreparePhase::Description))
            }
            BackendMessage::RowDescription(description) if phase == PreparePhase::Description => {
                if description.uniform_format() != Some(Format::Text) {
                    return Err(protocol_error("statement Describe has an execution format"));
                }
                Ok(RecoveryStep::Prepare(PreparePhase::Complete))
            }
            BackendMessage::NoData if phase == PreparePhase::Description => {
                Ok(RecoveryStep::Prepare(PreparePhase::Complete))
            }
            BackendMessage::ReadyForQuery(status)
                if matches!(phase, PreparePhase::Complete | PreparePhase::Failed) =>
            {
                Ok(RecoveryStep::Ready(status))
            }
            _ => Err(protocol_error(
                "unexpected response while recovering Prepare",
            )),
        }
    }

    fn query_recovery_step(
        extended: &Extended,
        message: BackendMessage<'_>,
    ) -> Result<RecoveryStep, Error> {
        let state = extended.query.as_ref().ok_or(Error::Broken)?;
        state.mode.validate_reset_response(message)?;
        match message {
            BackendMessage::ParseComplete
                if state.mode == QueryMode::OneShot && !state.parsed && !state.error_seen =>
            {
                Ok(RecoveryStep::QueryParsed)
            }
            BackendMessage::BindComplete if state.parsed && !state.bound && !state.error_seen => {
                Ok(RecoveryStep::QueryBound)
            }
            BackendMessage::RowDescription(description)
                if state.bound
                    && !state.described
                    && state.command.is_none()
                    && !state.error_seen =>
            {
                if !state.mode.is_simple() {
                    let formats = state.formats.as_ref().ok_or(Error::Broken)?;
                    if !formats.matches_reported(description)? {
                        return Err(protocol_error(
                            "recovered portal description has the wrong result format",
                        ));
                    }
                    formats.validate(description.len())?;
                }
                // 简单查询的格式由服务端选择，例如二进制游标。排空只需行结构和列数。
                Ok(RecoveryStep::QueryDescription(description.column_count()))
            }
            BackendMessage::NoData
                if state.mode == QueryMode::OneShot
                    && state.bound
                    && !state.described
                    && state.command.is_none()
                    && !state.error_seen =>
            {
                state.formats.as_ref().ok_or(Error::Broken)?.validate(0)?;
                Ok(RecoveryStep::QueryDescription(0))
            }
            BackendMessage::DataRow(row)
                if state.bound
                    && state.described
                    && state.command.is_none()
                    && !state.error_seen =>
            {
                if row.len() != state.result_columns {
                    return Err(crate::types::CodecError::Invalid(
                        "row field count differs from its result layout",
                    )
                    .into());
                }
                Ok(RecoveryStep::Noop)
            }
            BackendMessage::CommandComplete(tag)
                if state.bound
                    && state.command.is_none()
                    && !state.error_seen
                    && (state.described || state.mode.is_simple()) =>
            {
                let (kind, rows) = command_kind(protocol::parse_command_tag(tag)?);
                Ok(RecoveryStep::QueryCommand(kind, rows))
            }
            BackendMessage::EmptyQueryResponse
                if state.bound
                    && state.command.is_none()
                    && !state.error_seen
                    && (state.described || state.mode.is_simple()) =>
            {
                Ok(RecoveryStep::QueryCommand(CommandKind::Empty, None))
            }
            BackendMessage::ReadyForQuery(status)
                if state.command.is_some() || state.error_seen =>
            {
                Ok(RecoveryStep::Ready(status))
            }
            _ => Err(protocol_error(
                "unexpected response while recovering the query",
            )),
        }
    }

    fn apply_recovery_step(&mut self, step: RecoveryStep) -> Result<(), Error> {
        match step {
            RecoveryStep::Noop | RecoveryStep::Parameter(false) => {}
            RecoveryStep::Parameter(true) => self.bump_schema_epoch()?,
            RecoveryStep::TransactionCommand(kind) => self.observe_pending_control_tag(kind)?,
            RecoveryStep::Error => {
                if self.pending_transaction_control.is_some() {
                    self.observe_pending_control_error();
                } else {
                    let extended = self.extended.as_mut().ok_or(Error::Broken)?;
                    match extended.work_kind.as_mut().ok_or(Error::Broken)? {
                        WorkKind::Query => {
                            extended.query.as_mut().ok_or(Error::Broken)?.error_seen = true
                        }
                        WorkKind::Prepare { phase, .. } => *phase = PreparePhase::Failed,
                        WorkKind::PreparePipeline(progress) => {
                            progress.current()?;
                            progress.phase = PreparePhase::Failed;
                        }
                        WorkKind::Close { phase, .. } => *phase = ClosePhase::Failed,
                        WorkKind::ClosePipeline(progress) => {
                            progress.current()?;
                            progress.phase = ClosePhase::Failed;
                        }
                        WorkKind::Pipeline(progress) => {
                            progress.observe_signal(super::pipeline::PipelineSignal::Error)?
                        }
                        WorkKind::ProvisionalWindow(progress) => progress
                            .pipeline
                            .observe_signal(super::pipeline::PipelineSignal::Error)?,
                    }
                }
            }
            RecoveryStep::Prepare(next) => {
                let identity = match self
                    .extended
                    .as_ref()
                    .and_then(|extended| extended.work_kind.as_ref())
                    .ok_or(Error::Broken)?
                {
                    WorkKind::Prepare {
                        slot, generation, ..
                    } => PrepareIdentity {
                        slot: *slot,
                        generation: *generation,
                        epoch: 0,
                    },
                    WorkKind::PreparePipeline(progress) => progress.current()?,
                    _ => return Err(Error::Broken),
                };
                self.update_prepare_phase(identity, next)?;
            }
            RecoveryStep::CloseComplete => {
                let work = self
                    .extended
                    .as_ref()
                    .and_then(|extended| extended.work_kind.as_ref())
                    .ok_or(Error::Broken)?;
                let member = match work {
                    WorkKind::Close {
                        slot, generation, ..
                    } => CloseMember {
                        slot: *slot,
                        generation: *generation,
                    },
                    WorkKind::ClosePipeline(progress) => progress.current()?,
                    _ => return Err(Error::Broken),
                };
                self.mark_record_closed(member.slot, member.generation)?;
                match self
                    .extended
                    .as_mut()
                    .and_then(|extended| extended.work_kind.as_mut())
                    .ok_or(Error::Broken)?
                {
                    WorkKind::Close { phase, .. } => *phase = ClosePhase::Complete,
                    WorkKind::ClosePipeline(progress) => progress.phase = ClosePhase::Complete,
                    _ => return Err(Error::Broken),
                }
            }
            RecoveryStep::Pipeline(signal) => {
                let progress = self
                    .extended
                    .as_deref_mut()
                    .and_then(Extended::pipeline_progress_mut)
                    .ok_or(Error::Broken)?;
                progress.observe_signal(signal)?;
                if let super::pipeline::PipelineSignal::Ready(status) = signal {
                    self.note_ready(status)?;
                }
            }
            RecoveryStep::PipelineCommand(kind) => {
                let progress = self
                    .extended
                    .as_deref_mut()
                    .and_then(Extended::pipeline_progress_mut)
                    .ok_or(Error::Broken)?;
                progress.observe_signal(super::pipeline::PipelineSignal::Complete)?;
                self.record_pipeline_transaction_end(kind)?;
            }
            RecoveryStep::Ready(status) => {
                self.observe_pending_control_ready(status)?;
                self.note_ready(status)?;
                if let Some(state) = self
                    .extended
                    .as_ref()
                    .and_then(|extended| extended.query.as_ref())
                {
                    state.expire_cancel();
                }
                match self
                    .extended
                    .as_ref()
                    .and_then(|state| state.work_kind.as_ref())
                {
                    Some(WorkKind::Prepare {
                        slot,
                        generation,
                        phase: PreparePhase::Failed,
                    }) => {
                        self.retire_uncreated_prepare(*slot, *generation)?;
                    }
                    Some(WorkKind::PreparePipeline(progress)) => {
                        if progress.phase == PreparePhase::Failed {
                            let identity = progress.current()?;
                            self.retire_uncreated_prepare(identity.slot, identity.generation)?;
                        }
                        self.prepare_progress_mut()?.advance()?;
                    }
                    _ => {}
                }
                if let Some(WorkKind::ClosePipeline(progress)) = self
                    .extended
                    .as_mut()
                    .and_then(|extended| extended.work_kind.as_mut())
                {
                    progress.advance()?;
                }
                if let Some(state) = self
                    .extended
                    .as_mut()
                    .and_then(|extended| extended.query.as_mut())
                {
                    state.ready = Some(status);
                }
            }
            RecoveryStep::QueryCommand(kind, rows) => {
                self.record_query_transaction_end(kind)?;
                self.extended
                    .as_mut()
                    .and_then(|extended| extended.query.as_mut())
                    .ok_or(Error::Broken)?
                    .command = Some((kind, rows));
            }
            RecoveryStep::QueryParsed
            | RecoveryStep::QueryBound
            | RecoveryStep::QueryDescription(_) => {
                let state = self
                    .extended
                    .as_mut()
                    .and_then(|extended| extended.query.as_mut())
                    .ok_or(Error::Broken)?;
                match step {
                    RecoveryStep::QueryParsed => state.parsed = true,
                    RecoveryStep::QueryBound => state.bound = true,
                    RecoveryStep::QueryDescription(columns) => {
                        state.result_columns = usize::from(columns);
                        state.formats = None;
                        state.described = true;
                    }
                    _ => return Err(Error::Broken),
                }
            }
        }
        Ok(())
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 排空已接纳的请求至 Ready，保留当前事务的提交或回滚决定。
    pub fn recover_to_ready(&mut self) -> impl Future<Output = Result<(), Error>> {
        self.session_mut().recover_to_ready()
    }

    /// 按本次指定的数据行数和字节限额排空。达到限额时保留进度，可再次恢复。
    pub fn recover_to_ready_with_limits(
        &mut self,
        max_rows: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<(), Error>> {
        self.session_mut()
            .recover_to_ready_with_limits(max_rows, max_bytes)
    }
}

enum RecoveryStep {
    Noop,
    Parameter(bool),
    Error,
    Prepare(PreparePhase),
    CloseComplete,
    QueryParsed,
    QueryBound,
    QueryDescription(u16),
    QueryCommand(CommandKind, Option<u64>),
    TransactionCommand(super::transaction::ControlKind),
    Pipeline(super::pipeline::PipelineSignal),
    PipelineCommand(CommandKind),
    Ready(TransactionStatus),
}
enum QueryEvent {
    Parsed,
    Bound,
    Description(Rc<RowLayout>),
    ProjectedDescription(u16),
    NoData,
    Command(CommandKind, Option<u64>),
    Error(Option<DatabaseError>),
    Parameter(bool),
    Notice,
    Ready(TransactionStatus),
}

/// 分别处理协议读取错误与回调或结果存储错误。回调也可以返回 I/O 错误。
enum RowDeliveryFailure {
    Query(Error),
    Consumer(Error),
}

impl<'s, T: WireTransport> Query<'s, T> {
    fn replace_on_error(
        &mut self,
        policy: crate::error::OnError,
    ) -> Result<crate::error::OnError, Error> {
        Ok(std::mem::replace(&mut self.state_mut()?.on_error, policy))
    }

    fn check_terminal_owner(
        &mut self,
        configured: Result<crate::error::OnError, Error>,
    ) -> Result<(), Error> {
        let previous = configured?;
        if let Err(error) = self.session.check_runtime_owner() {
            // 构建 future 即选择放弃策略；若在错误 runtime 被拒绝驱动，须恢复先前策略。
            if let Ok(state) = self.state_mut() {
                state.on_error = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    /// 本地回调或存储失败不触发 SQL 回滚或自动重试。
    pub(crate) async fn local_failure(&mut self, primary: Error) -> Error {
        let Ok(policy) = self.state().map(|state| state.on_error) else {
            return primary;
        };
        self.local_failure_with(policy, primary).await
    }

    /// Ready 可能已经释放查询状态，终端操作仍须保留原先选择的错误策略。
    pub(crate) async fn local_failure_with(
        &mut self,
        policy: crate::error::OnError,
        primary: Error,
    ) -> Error {
        if self.session.transport.is_broken() {
            return primary;
        }
        match policy {
            crate::error::OnError::RecoverExplicitly => primary,
            crate::error::OnError::Discard => {
                self.session.transport.break_connection();
                primary
            }
            crate::error::OnError::DrainToReady if self.session.active => {
                match self.session.recover_to_ready().await {
                    Ok(()) => primary,
                    Err(cleanup) => Error::Cleanup {
                        primary: Box::new(primary),
                        cleanup: Box::new(cleanup),
                    },
                }
            }
            crate::error::OnError::DrainToReady => primary,
        }
    }

    pub fn completion(&self) -> Option<QueryCompletion> {
        self.completion
    }

    pub fn layout(&self) -> Option<&RowLayout> {
        self.layout_owner().map(Rc::as_ref)
    }

    /// 有布局后可独立持有，包括零行结果。
    pub fn share_layout(&self) -> Option<Rc<RowLayout>> {
        self.layout_owner().cloned()
    }

    fn layout_owner(&self) -> Option<&Rc<RowLayout>> {
        self.final_layout.as_ref().or_else(|| {
            self.session
                .extended
                .as_ref()?
                .query
                .as_ref()?
                .layout
                .as_ref()
        })
    }

    fn state(&self) -> Result<&QueryState, Error> {
        match self
            .session
            .extended
            .as_ref()
            .and_then(|ext| ext.query.as_ref())
        {
            Some(state) => Ok(state),
            None => Err(Error::Broken),
        }
    }

    fn state_mut(&mut self) -> Result<&mut QueryState, Error> {
        match self
            .session
            .extended
            .as_mut()
            .and_then(|ext| ext.query.as_mut())
        {
            Some(state) => Ok(state),
            None => Err(Error::Broken),
        }
    }

    /// 在查询收到 Ready 前获取当前 worker 的取消句柄。
    /// 创建句柄不影响复用；一旦驱动取消请求，即使取消发送失败也禁止原连接复用。
    pub fn cancel_handle(&mut self) -> Result<super::CancelHandle, Error> {
        if self.finished || self.state()?.ready.is_some() || self.session.transport.is_broken() {
            return Err(Error::InvalidInput(
                "cancellation requires an unfinished query",
            ));
        }
        if let Some(cancel) = self.state()?.cancel.as_ref() {
            return Ok(cancel.handle());
        }
        let fence = super::cancel::CancelFence::new(self.session)?;
        let handle = fence.handle();
        self.state_mut()?.cancel = Some(fence);
        Ok(handle)
    }

    /// 行读取遇到本地限额时保留待恢复进度。
    /// 收集或回调终端只处理一次 OnError，避免每行内嵌排空逻辑。
    pub async fn next_row(&mut self) -> Result<Option<RowLease<'_>>, Error> {
        self.session.check_runtime_owner()?;
        self.next_row_on_owner().await
    }

    async fn next_row_on_owner(&mut self) -> Result<Option<RowLease<'_>>, Error> {
        let descriptor = self
            .map_result_row_on_owner(None, |data, _, _| data.descriptor())
            .await?;
        let Some(descriptor) = descriptor else {
            return Ok(None);
        };
        let extended = self.session.extended.as_deref().ok_or(Error::Broken)?;
        let layout = extended
            .query
            .as_ref()
            .and_then(|state| state.layout.as_ref())
            .ok_or(Error::Broken)?;
        let data = descriptor.reborrow(self.session.transport.frame()?)?;
        Ok(Some(RowLease { data, layout }))
    }

    /// 在当前帧内访问下一个已校验的 DataRow，或完成 Ready 和本地发送。
    /// 标量一次性查询只保留列类型、格式和恢复所需的列数。
    /// 首次轮询须紧跟归属校验或已校验的同步推进；挂起后由此操作重新验证。
    pub(in crate::client) async fn map_result_row_on_owner<R>(
        &mut self,
        projection: Option<&mut ResultShape>,
        map: impl FnOnce(protocol::DataRow<'_>, Option<&ResultShape>, &Extended) -> R,
    ) -> Result<Option<R>, Error> {
        if self.finished {
            return self.finished_completion().map(|_| None);
        }
        let row = self
            .advance_rows_on_owner::<false, _>(projection, map)
            .await?;
        if row.is_none() {
            self.retire_result()?;
        }
        Ok(row)
    }

    async fn deliver_row_on_owner(
        &mut self,
        deliver: impl FnOnce(RowView<'_, '_>, &Rc<RowLayout>, &Extended) -> Result<(), Error>,
    ) -> Result<Option<()>, RowDeliveryFailure> {
        self.map_result_row_on_owner(None, |data, _, extended| {
            let layout = extended
                .query
                .as_ref()
                .and_then(|state| state.layout.as_ref())
                .ok_or(RowDeliveryFailure::Query(Error::Broken))?;
            let view = RowView::from_matching_layout(data, layout);
            deliver(view, layout, extended).map_err(RowDeliveryFailure::Consumer)
        })
        .await
        .map_err(RowDeliveryFailure::Query)?
        .transpose()
    }

    async fn delivery_failure(&mut self, failure: RowDeliveryFailure) -> Error {
        match failure {
            RowDeliveryFailure::Query(error) if !matches!(error, Error::Limit(_)) => error,
            RowDeliveryFailure::Query(error) | RowDeliveryFailure::Consumer(error) => {
                self.local_failure(error).await
            }
        }
    }

    fn finished_completion(&self) -> Result<QueryCompletion, Error> {
        self.completion
            .filter(|completion| completion.succeeded)
            .ok_or(Error::InvalidInput(
                "the failed query's diagnostic was already delivered",
            ))
    }

    fn retire_result(&mut self) -> Result<QueryCompletion, Error> {
        let Some(extended) = self.session.extended.as_mut() else {
            return Err(Error::Broken);
        };
        let Some(state) = extended.query.take() else {
            return Err(Error::Broken);
        };
        extended.work_kind = None;
        let Some(transaction_status) = state.ready else {
            return Err(Error::Broken);
        };
        let completion = QueryCompletion {
            command: state.command.map(|command| command.0),
            rows_affected: state.command.and_then(|command| command.1),
            rows_returned: state.rows,
            transaction_status,
            succeeded: !state.error_seen,
        };
        self.finished = true;
        self.final_layout = state.layout;
        self.completion = Some(completion);
        state
            .failure
            .map_or(Ok(completion), |error| Err(Error::Database(error)))
    }

    async fn advance_rows_on_owner<const DISCARD: bool, R>(
        &mut self,
        projection: Option<&mut ResultShape>,
        map: impl FnOnce(protocol::DataRow<'_>, Option<&ResultShape>, &Extended) -> R,
    ) -> Result<Option<R>, Error> {
        let result = self
            .advance_to_row_on_owner::<DISCARD, _>(projection, map)
            .await;
        if let Err(error) = &result
            && !matches!(error, Error::Busy | Error::Limit(_))
        {
            self.session.transport.break_connection();
        }
        result
    }

    async fn advance_to_row_on_owner<const DISCARD: bool, R>(
        &mut self,
        mut projection: Option<&mut ResultShape>,
        map: impl FnOnce(protocol::DataRow<'_>, Option<&ResultShape>, &Extended) -> R,
    ) -> Result<Option<R>, Error> {
        const CONTROL_LIMIT: Error = Error::Limit("query exceeded its control message limit");
        let max_controls = self.session.max_messages;
        {
            let Some(extended) = self.session.extended.as_mut() else {
                return Err(Error::Broken);
            };
            if extended.callback_in_progress.get() {
                return Err(Error::Broken);
            }
            if extended.pending_frame {
                self.session.transport.consume_frame()?;
                extended.pending_frame = false;
            }
        }
        let state = self.state_mut()?;
        state.quantum.yield_on_worker().await?;
        state.start_io()?;
        let mut ready = state.ready.is_some();
        while !ready {
            self.session.transport.receive_frame_on_owner().await?;
            let Some(extended) = self.session.extended.as_mut() else {
                return Err(Error::Broken);
            };
            let Some(state) = extended.query.as_mut() else {
                return Err(Error::Broken);
            };
            let frame = self.session.transport.frame()?;
            let work_bytes = frame.body.len().saturating_add(5);
            if frame.tag == b'D' {
                let row = protocol::parse_data_row(frame.body)?;
                if !state.bound || !state.described || state.command.is_some() || state.error_seen {
                    return Err(protocol_error("unexpected response in the general query"));
                }
                if row.len() != state.result_columns {
                    return Err(CodecError::Invalid(
                        "row field count differs from its result layout",
                    )
                    .into());
                }
                // 字段载荷属于已验证帧，增计四字节记录长度不会溢出 usize。
                let record_bytes = row.encoded_fields().len() + 4;
                if state.rows == state.limits.max_rows || record_bytes > state.result_bytes_left {
                    return Err(Error::Limit(
                        "query result exceeds its selected row or byte limit",
                    ));
                }
                state.rows += 1;
                state.result_bytes_left -= record_bytes;
                state.quantum.spend_bytes(work_bytes);
                if !DISCARD {
                    extended.pending_frame = true;
                    return Ok(Some(map(row, projection.as_deref(), extended)));
                }
                self.session.transport.consume_frame()?;
                state.quantum.yield_on_worker().await?;
                continue;
            }
            let message = protocol::parse_backend(frame)?;
            state.mode.validate_reset_response(message)?;
            let event = match message {
                BackendMessage::ParseComplete
                    if state.mode == QueryMode::OneShot && !state.parsed && !state.error_seen =>
                {
                    QueryEvent::Parsed
                }
                BackendMessage::BindComplete
                    if state.parsed && !state.bound && !state.error_seen =>
                {
                    QueryEvent::Bound
                }
                BackendMessage::RowDescription(description)
                    if state.bound
                        && !state.described
                        && state.command.is_none()
                        && !state.error_seen =>
                {
                    // 仅在成功构建布局时取走待用格式。
                    if state.control_messages >= max_controls {
                        return Err(CONTROL_LIMIT);
                    }
                    if state.mode.is_simple() {
                        QueryEvent::Description(Rc::new(
                            RowLayout::from_reported_description(
                                description,
                                state.limits.max_metadata_bytes,
                            )
                            .map_err(query_metadata_error)?,
                        ))
                    } else {
                        let formats = state.formats.as_ref().ok_or(Error::Broken)?;
                        if !formats.matches_reported(description)? {
                            return Err(protocol_error(
                                "portal description does not match the requested result formats",
                            ));
                        }
                        if let Some(projected) = projection.as_deref_mut() {
                            RowLayout::check_description_budget(
                                description,
                                Some(formats),
                                state.limits.max_metadata_bytes,
                            )
                            .map_err(Error::from)
                            .map_err(query_metadata_error)?;
                            *projected = ResultShape::from_description(description);
                            QueryEvent::ProjectedDescription(projected.columns)
                        } else {
                            let layout = RowLayout::from_pending_description::<Error>(
                                description,
                                &mut state.formats,
                                Ok(state.limits.max_metadata_bytes),
                                |_, _| Ok(()),
                            )
                            .map_err(query_metadata_error)?;
                            QueryEvent::Description(Rc::new(layout))
                        }
                    }
                }
                BackendMessage::NoData
                    if state.mode == QueryMode::OneShot
                        && state.bound
                        && !state.described
                        && state.command.is_none()
                        && !state.error_seen =>
                {
                    QueryEvent::NoData
                }
                BackendMessage::CommandComplete(tag)
                    if state.bound
                        && state.command.is_none()
                        && !state.error_seen
                        && (state.described || state.mode.is_simple()) =>
                {
                    let (kind, affected) = command_kind(protocol::parse_command_tag(tag)?);
                    QueryEvent::Command(kind, affected)
                }
                BackendMessage::EmptyQueryResponse
                    if state.bound
                        && state.command.is_none()
                        && !state.error_seen
                        && (state.described || state.mode.is_simple()) =>
                {
                    QueryEvent::Command(CommandKind::Empty, None)
                }
                BackendMessage::ErrorResponse(error) if !is_fatal(error) => {
                    if state.control_messages >= max_controls {
                        return Err(CONTROL_LIMIT);
                    }
                    QueryEvent::Error(state.failure.is_none().then(|| owned_error(error)))
                }
                BackendMessage::ErrorResponse(error) => {
                    return Err(Error::Database(owned_error(error)));
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    QueryEvent::Parameter(name == "search_path")
                }
                BackendMessage::NoticeResponse(notice) => {
                    if state.control_messages >= max_controls {
                        return Err(CONTROL_LIMIT);
                    }
                    super::observe_notice(notice, self.session.notice_handler.as_ref())
                        .finish(&mut self.session.transport);
                    QueryEvent::Notice
                }
                BackendMessage::NotificationResponse { .. } => QueryEvent::Notice,
                BackendMessage::ReadyForQuery(status)
                    if state.command.is_some() || state.error_seen =>
                {
                    QueryEvent::Ready(status)
                }
                _ => return Err(protocol_error("unexpected response in the general query")),
            };
            if state.control_messages >= max_controls {
                return Err(CONTROL_LIMIT);
            }
            state.control_messages += 1;
            self.session.transport.consume_frame()?;
            state.quantum.spend_bytes(work_bytes);
            let state = match event {
                QueryEvent::Parsed => {
                    state.parsed = true;
                    state
                }
                QueryEvent::Bound => {
                    state.bound = true;
                    state
                }
                QueryEvent::Description(layout) => {
                    state.result_columns = layout.len();
                    state.layout = Some(layout);
                    state.described = true;
                    state
                }
                QueryEvent::ProjectedDescription(columns) => {
                    state.result_columns = usize::from(columns);
                    state.described = true;
                    state.formats = None;
                    state
                }
                QueryEvent::NoData => {
                    // 即使元数据不足，NoData 帧也已被消费。
                    state.described = true;
                    state.set_empty_layout(projection.is_some())?;
                    state
                }
                QueryEvent::Command(kind, affected) => {
                    state.command = Some((kind, affected));
                    let state = if matches!(
                        kind,
                        CommandKind::Commit
                            | CommandKind::Rollback
                            | CommandKind::DeallocateAll
                            | CommandKind::DiscardAll
                    ) {
                        self.session.record_query_transaction_end(kind)?;
                        self.state_mut()?
                    } else {
                        state
                    };
                    if state.layout.is_none()
                        && !(state.described
                            && (projection.is_some() || state.mode == QueryMode::Prepared))
                    {
                        state.set_empty_layout(projection.is_some())?;
                        state.described = true;
                    }
                    state
                }
                QueryEvent::Error(error) => {
                    state.error_seen = true;
                    if let Some(error) = error {
                        state.failure = Some(error);
                    }
                    state
                }
                QueryEvent::Parameter(true) => {
                    self.session.bump_schema_epoch()?;
                    self.state_mut()?
                }
                QueryEvent::Ready(status) => {
                    self.session.note_ready(status)?;
                    let state = self.state_mut()?;
                    state.expire_cancel();
                    state.ready = Some(status);
                    ready = true;
                    state
                }
                QueryEvent::Parameter(false) | QueryEvent::Notice => state,
            };
            state.quantum.yield_on_worker().await?;
        }
        let retire = self.state()?.cancel_requested();
        if let Err(send) = self.session.transport.finish_send_on_owner().await {
            return Err(send_after_diagnostic(
                self.state_mut()?.failure.take(),
                send,
            ));
        }
        if retire {
            self.session.transport.break_connection();
        }
        self.session.active = false;
        Ok(None)
    }

    pub async fn finish(&mut self) -> Result<QueryCompletion, Error> {
        self.session.check_runtime_owner()?;
        if self.finished {
            return self.finished_completion();
        }
        let _ = self
            .advance_rows_on_owner::<true, _>(None, |_, _, _| ())
            .await?;
        self.retire_result()
    }

    /// 创建 future 时即确定回调或本地限额失败的处理策略。
    pub fn for_each_row(
        &mut self,
        sink: &mut (impl for<'a> FnMut(RowView<'a, 'a>) -> Result<(), Error> + ?Sized),
        on_error: crate::error::OnError,
    ) -> impl std::future::Future<Output = Result<QueryCompletion, Error>> {
        let configured = self.replace_on_error(on_error);
        async move {
            self.check_terminal_owner(configured)?;
            loop {
                match self
                    .deliver_row_on_owner(|row, _, extended| extended.invoke_callback(|| sink(row)))
                    .await
                {
                    Ok(Some(())) => {}
                    Ok(None) => return self.completion.ok_or(Error::Broken),
                    Err(failure) => return Err(self.delivery_failure(failure).await),
                }
            }
        }
    }

    /// 按指定分配策略收集结果。
    /// ReserveLimit 在首行按字节上限预分配；Grow 按需扩容，扩容时可能短暂保留新旧两块存储。
    /// 返回的批次容量固定，空结果不分配行存储。
    /// 需要跨查询复用缓冲时可用 collect_into。
    pub fn collect_with(
        mut self,
        allocation: AllocationPolicy,
        on_error: crate::error::OnError,
    ) -> impl std::future::Future<Output = Result<(OwnedBatch, QueryCompletion), Error>> {
        let configured = self.replace_on_error(on_error);
        async move {
            self.check_terminal_owner(configured)?;
            self.collect_with_on_owner(allocation).await
        }
    }

    /// 由已确认 runtime 和错误策略的调用方在同一次轮询中开始收集。
    pub(in crate::client) async fn collect_with_on_owner(
        self,
        allocation: AllocationPolicy,
    ) -> Result<(OwnedBatch, QueryCompletion), Error> {
        match allocation {
            AllocationPolicy::ReserveLimit => self.collect_inner::<false>().await,
            AllocationPolicy::Grow => self.collect_inner::<true>().await,
        }
    }

    async fn collect_inner<const GROW: bool>(
        mut self,
    ) -> Result<(OwnedBatch, QueryCompletion), Error> {
        let limits = self.state()?.limits;
        let mut batch = None;
        loop {
            match self
                .deliver_row_on_owner(|row, layout, _| {
                    let output = match batch.as_mut() {
                        Some(output) => output,
                        None => batch.insert(OwnedBatch::new(
                            Rc::clone(layout),
                            limits.max_rows,
                            if GROW { 0 } else { limits.max_result_bytes },
                        )?),
                    };
                    if GROW {
                        output
                            .push_growing(row, limits.max_result_bytes)
                            .map_err(Error::from)
                    } else {
                        output.push(row).map_err(Error::from)
                    }
                })
                .await
            {
                Ok(Some(())) => {}
                Ok(None) => break,
                Err(failure) => return Err(self.delivery_failure(failure).await),
            }
        }
        let batch = match batch {
            Some(batch) => batch,
            None => OwnedBatch::new(self.final_layout.take().ok_or(Error::Broken)?, 0, 0)?,
        };
        Ok((batch, self.completion.ok_or(Error::Broken)?))
    }

    /// 将结果写入调用方的定长缓冲，要求上一轮借用已经结束且容量符合本查询字节限额。
    /// 仅在 Ready 和本地发送完成后公布结果，失败或放弃时清空缓冲。
    pub fn collect_into(
        mut self,
        batch: &mut OwnedBatch,
        on_error: crate::error::OnError,
    ) -> impl std::future::Future<Output = Result<QueryCompletion, Error>> {
        let configured = self.replace_on_error(on_error);
        async move {
            self.check_terminal_owner(configured)?;
            self.collect_into_on_owner::<false>(batch, on_error).await
        }
    }

    /// 普通入口在接纳预备查询前已核对固定缓冲的布局和保留容量。
    pub(in crate::client) async fn collect_into_on_owner<const ARENA_VALIDATED: bool>(
        mut self,
        batch: &mut OwnedBatch,
        on_error: crate::error::OnError,
    ) -> Result<QueryCompletion, Error> {
        let byte_limit = if ARENA_VALIDATED {
            None
        } else {
            Some(self.state()?.limits.max_result_bytes)
        };
        let mut staged = batch.stage();
        if byte_limit.is_some_and(|limit| staged.retained_bytes() > limit) {
            return Err(self
                .local_failure(Error::Limit(
                    "reusable result arena exceeds this query's byte limit",
                ))
                .await);
        }
        loop {
            match self
                .deliver_row_on_owner(|row, _, _| staged.push(row).map_err(Error::from))
                .await
            {
                Ok(Some(())) => {}
                Ok(None) => break,
                Err(failure) => return Err(self.delivery_failure(failure).await),
            }
        }
        if !ARENA_VALIDATED {
            let layout = self.layout().ok_or(Error::Broken)?;
            if !std::ptr::eq(layout, staged.layout()) {
                return Err(self
                    .local_failure_with(
                        on_error,
                        Error::InvalidInput("reusable arena has a different result layout"),
                    )
                    .await);
            }
        }
        let completion = self.completion.ok_or(Error::Broken)?;
        staged.publish();
        Ok(completion)
    }
}

/// Ready 已确认，但本地发送或 TLS 刷新失败时，保留已持有的服务器诊断。
#[cold]
pub(super) fn send_after_diagnostic(diagnostic: Option<DatabaseError>, send: Error) -> Error {
    match diagnostic {
        Some(primary) => with_cleanup_error(Error::Database(primary), Err(send)),
        None => send,
    }
}

fn with_cleanup_error(primary: Error, cleanup: Result<(), Error>) -> Error {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => Error::Cleanup {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        },
    }
}

fn query_metadata_error(error: Error) -> Error {
    match error {
        Error::Codec(error) => match error.as_ref() {
            crate::types::CodecError::Limit(message) => Error::Limit(message),
            crate::types::CodecError::Allocation => Error::Limit("cannot allocate query metadata"),
            _ => Error::Codec(error),
        },
        error => error,
    }
}

pub(super) fn command_kind(tag: CommandTag<'_>) -> (CommandKind, Option<u64>) {
    match tag {
        CommandTag::Select(rows) => (CommandKind::Select, Some(rows)),
        CommandTag::Insert(rows) => (CommandKind::Insert, Some(rows)),
        CommandTag::Update(rows) => (CommandKind::Update, Some(rows)),
        CommandTag::Delete(rows) => (CommandKind::Delete, Some(rows)),
        CommandTag::Merge(rows) => (CommandKind::Merge, Some(rows)),
        CommandTag::Move(rows) => (CommandKind::Move, Some(rows)),
        CommandTag::Fetch(rows) => (CommandKind::Fetch, Some(rows)),
        CommandTag::Copy(rows) => (CommandKind::Copy, Some(rows)),
        CommandTag::Begin => (CommandKind::Begin, None),
        CommandTag::Commit => (CommandKind::Commit, None),
        CommandTag::Rollback => (CommandKind::Rollback, None),
        CommandTag::Savepoint => (CommandKind::Savepoint, None),
        CommandTag::Release => (CommandKind::Release, None),
        CommandTag::Other("DEALLOCATE ALL") => (CommandKind::DeallocateAll, None),
        CommandTag::Other("DISCARD ALL") => (CommandKind::DiscardAll, None),
        CommandTag::Other(_) => (CommandKind::Other, None),
    }
}

#[cfg(test)]
mod tests;
