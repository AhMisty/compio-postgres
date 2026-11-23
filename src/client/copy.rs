//! COPY IN 与 COPY OUT 的输入、输出和完成边界。
//! 析构不启动协议操作。
//!
//! 一次 COPY 共用一个调度预算，包括请求、每个 CopyData 及服务端控制帧。
//! 每 KiB 计一个工作单元，每帧至少一个，按含五字节帧头的长度计算。
//! 批量发送按各帧计费，空数据块也占用预算。
//! 让出执行权前先释放借用。
//! 包编码、单次输入轮询、单块分配或复制、同步回调均不可中断；重新创建 future 不会恢复额度。
//! 消息限额、字节限额和截止时间需单独设置。

use crate::transport::{
    WireOps,
    sealed::{CopyDataSink, CopyOutFrame},
};
use futures_util::Stream;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use super::{
    NoticePolicy, Session, Transaction, TransportExt, WireTransport, is_fatal, owned_error,
    protocol_error, validate_parameter,
};
use crate::{
    DatabaseError, Error, OnError, OwnedOutput, frontend,
    protocol::{self, BackendMessage, CommandTag, Format, QueryTail, TransactionStatus},
    row::{AllocationPolicy, ResultFormats},
    scheduler::{ExecutionQuantum, ExecutionScheduling, byte_work_units},
    types::Parameter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyProtocol {
    /// 用扩展查询协议解析一条 COPY 语句并绑定参数。
    Extended,
    /// 通过简单查询协议发送一条无参数的可信 COPY。
    /// 调用方须保证只有一条语句；客户端发现响应异常前，服务器可能已经执行后续语句。
    SimpleSingle,
}

/// 一个发送包内多个独立 CopyData 帧的限额。
#[derive(Debug, Clone, Copy)]
pub struct CopyBatchLimits {
    /// 输入切片数的正上限，空数据块也计入。
    pub max_chunks: usize,
    /// 含所有帧头的编码包及其缓冲容量上限。
    /// 至少容纳五字节帧头，且不超过连接的请求限额。
    pub max_packet_bytes: usize,
}

/// 本地传输完成情况；数据库的行数与提交结果须由服务端另行确认。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyBatchCompletion {
    pub chunks: usize,
    pub payload_bytes: usize,
}

/// 批量发送 CopyData 失败。
/// 可能已有部分数据送达，不能据此确定重试位置。
#[derive(Debug)]
pub struct CopyBatchError {
    pub source: Error,
    /// 新包已交给 begin_send，可能已有部分字节发送。
    /// false 仅指本批次。
    pub may_have_been_sent: bool,
}

impl CopyBatchError {
    fn before_send(source: Error) -> Self {
        Self {
            source,
            may_have_been_sent: false,
        }
    }
}

impl std::fmt::Display for CopyBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "COPY batch transmission failed: {}", self.source)
    }
}

impl std::error::Error for CopyBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// 一次 COPY 输入流的总量限额。
/// 空块计入块数。驱动读取首个超限块以确认超额，该块不会发送。
/// 源和回调的分配另计；每个发送包仍受连接请求字节限额约束。
#[derive(Debug, Clone, Copy)]
pub struct CopyStreamLimits {
    pub max_chunks: usize,
    pub max_payload_bytes: usize,
}

impl CopyStreamLimits {
    fn charge_payload(&mut self, bytes: usize) -> Result<(), StreamSendError> {
        self.max_payload_bytes = self
            .max_payload_bytes
            .checked_sub(bytes)
            .ok_or(StreamSendError::StreamLimit)?;
        Ok(())
    }
}

enum StreamSendError {
    StreamLimit,
    Send(Error),
}

impl From<Error> for StreamSendError {
    fn from(error: Error) -> Self {
        Self::Send(error)
    }
}

const EMPTY_COPY_DATA: &[u8; 5] = b"d\0\0\0\x04";
const COPY_DATA_HEADER_BYTES: usize = EMPTY_COPY_DATA.len();

/// 固定容量的 CopyData 包。
/// 生产者直接写入五字节预留帧头后的空间，发送完成后取回原缓冲，可重放或清空后重新填充。
pub struct CopyDataBuffer {
    // 构造与发送回收均验证帧头，之后的调整始终保留前五字节。
    encoded: Vec<u8>,
}
impl std::fmt::Debug for CopyDataBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyDataBuffer")
            .field("payload_bytes", &self.payload().len())
            .field("payload_capacity", &self.payload_capacity())
            .finish()
    }
}

impl CopyDataBuffer {
    pub fn new(max_payload: usize) -> Result<Self, Error> {
        let capacity = max_payload
            .checked_add(COPY_DATA_HEADER_BYTES)
            .ok_or(Error::Limit("COPY packet capacity overflow"))?;
        i32::try_from(capacity - 1)
            .map_err(|_| Error::Limit("COPY packet exceeds its wire length"))?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Limit("cannot allocate COPY packet"))?;
        if encoded.capacity() > capacity {
            return Err(Error::Limit(
                "COPY packet backing exceeds its capacity limit",
            ));
        }
        encoded.extend_from_slice(EMPTY_COPY_DATA);
        Ok(Self { encoded })
    }
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.encoded.capacity() - self.encoded.len() {
            return Err(Error::Limit("COPY payload exceeds its packet capacity"));
        }
        self.encoded.extend_from_slice(bytes);
        Ok(())
    }
    pub fn payload(&self) -> &[u8] {
        self.encoded.split_at(COPY_DATA_HEADER_BYTES).1
    }
    /// 直接修改已初始化的载荷。回收固定长度的包时可原地重填。
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.encoded.split_at_mut(COPY_DATA_HEADER_BYTES).1
    }

    /// 在固定容量内调整载荷长度并借出写入空间。增长的字节初始化为零。
    pub fn resize_payload(&mut self, len: usize) -> Result<&mut [u8], Error> {
        let end = len
            .checked_add(COPY_DATA_HEADER_BYTES)
            .filter(|&end| end <= self.encoded.capacity())
            .ok_or(Error::Limit("COPY payload exceeds its packet capacity"))?;
        self.encoded.resize(end, 0);
        Ok(self.payload_mut())
    }

    pub fn payload_capacity(&self) -> usize {
        self.encoded.capacity() - COPY_DATA_HEADER_BYTES
    }
    pub fn retained_bytes(&self) -> usize {
        self.encoded.capacity()
    }
    pub fn clear(&mut self) {
        self.encoded.truncate(COPY_DATA_HEADER_BYTES);
    }
    fn into_packet(mut self, max_request: usize) -> Result<Vec<u8>, Error> {
        if self.encoded.capacity() > max_request {
            return Err(Error::Limit(
                "owned COPY packet exceeds the connection request bound",
            ));
        }
        let encoded_len = self.encoded.len();
        let Some([_, encoded_length @ ..]) =
            self.encoded.first_chunk_mut::<COPY_DATA_HEADER_BYTES>()
        else {
            return Err(Error::Broken);
        };
        let length = i32::try_from(encoded_len - 1)
            .map_err(|_| Error::Limit("COPY packet exceeds its wire length"))?;
        *encoded_length = length.to_be_bytes();
        Ok(self.encoded)
    }
    fn recycled(encoded: Vec<u8>) -> Result<Self, Error> {
        if matches!(
            encoded.first_chunk::<COPY_DATA_HEADER_BYTES>(),
            Some([b'd', ..])
        ) {
            Ok(Self { encoded })
        } else {
            Err(Error::Broken)
        }
    }
}

/// 服务端报告的 COPY 总体格式与列格式。同格式的列共享一个格式值。
#[derive(Debug, Clone)]
pub struct CopyInfo {
    pub format: Format,
    column_count: usize,
    formats: ResultFormats,
}

impl CopyInfo {
    fn from_response(response: protocol::CopyResponse<'_>) -> Result<Self, Error> {
        let formats = if let Some(format) = response.uniform_format() {
            ResultFormats::All(format)
        } else {
            let mut columns = Vec::new();
            columns
                .try_reserve_exact(response.len())
                .map_err(|_| Error::Limit("cannot allocate COPY format metadata"))?;
            columns.extend(response.column_formats());
            ResultFormats::PerColumn(columns.into_boxed_slice())
        };
        Ok(Self {
            format: response.format,
            column_count: response.len(),
            formats,
        })
    }

    pub fn len(&self) -> usize {
        self.column_count
    }

    pub fn is_empty(&self) -> bool {
        self.column_count == 0
    }

    /// 按列查看格式时，仅使用小于 `len()` 的索引。
    pub fn formats(&self) -> &ResultFormats {
        &self.formats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyCompletion {
    pub rows: u64,
    pub transaction_status: TransactionStatus,
}

enum CopyFinish {
    Ready(CopyCompletion),
    OutputFailure(Error),
}

trait CopyOutputSink: CopyDataSink {
    fn frame_completed(&mut self, payload_len: usize) -> Result<(), Error>;
}

impl CopyOutputSink for () {
    fn frame_completed(&mut self, _: usize) -> Result<(), Error> {
        Ok(())
    }
}

/// 主动终止 COPY IN 后在 Ready 边界确认的结果。
#[derive(Debug)]
pub enum CopyAbort {
    /// 服务端确认查询已取消。诊断保留服务端给出的实际原因。
    Aborted {
        diagnostic: DatabaseError,
        transaction_status: TransactionStatus,
    },
    /// 接管输入时已发送完成消息，服务端随后确认 COPY 成功。
    AlreadyCompleted(CopyCompletion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    In,
    Out,
}

impl Direction {
    fn extended_query_tail(self) -> QueryTail {
        match self {
            // COPY IN 期间服务器忽略 Sync，必须先结束输入。
            Self::In => QueryTail::Flush,
            // 服务器在 COPY OUT 结束后处理这个 Sync。
            Self::Out => QueryTail::Sync,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputEnd {
    Done,
    Rejected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopySend {
    Startup,
    Data,
    Idle,
}

#[derive(PartialEq, Eq)]
enum CopyStartup {
    Parse,
    Bind,
    Response,
}

pub(super) struct CopyState {
    protocol: CopyProtocol,
    direction: Direction,
    established: bool,
    error: Option<DatabaseError>,
    input_end: Option<InputEnd>,
    // 已放弃的等待方可能留下在途 CopyData。
    send: CopySend,
    backend_done: bool,
    discard_on_abandon: bool,
    command_rows: Option<u64>,
    /// 等待释放的数据块所占协议字节数；空闲时为零。
    pending_chunk_bytes: usize,
    quantum: ExecutionQuantum,
    ready: Option<TransactionStatus>,
    control_messages: usize,
}
impl CopyState {
    pub(super) fn can_finish_abandoned(&self) -> bool {
        self.established && !self.discard_on_abandon
    }

    fn check_control_limit(&self, maximum: usize) -> Result<(), Error> {
        if self.control_messages >= maximum {
            return Err(Error::Limit("COPY exceeded its control-message limit"));
        }
        Ok(())
    }

    fn invoke_callback<R>(&mut self, callback: impl FnOnce() -> R) -> R {
        // 回调 panic 时丢弃 COPY 会话；正常返回时恢复已选的处置策略。
        let previous = std::mem::replace(&mut self.discard_on_abandon, true);
        let result = callback();
        self.discard_on_abandon = previous;
        result
    }
}

/// 首次 COPY 才分配，确认结束后保留空槽供此连接复用。
#[derive(Default)]
pub(super) struct CopyWorkspace(Option<Box<Option<CopyState>>>);

impl CopyWorkspace {
    pub(super) fn as_ref(&self) -> Option<&CopyState> {
        self.0.as_deref().and_then(Option::as_ref)
    }

    pub(super) fn is_some(&self) -> bool {
        self.as_ref().is_some()
    }

    fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }

    fn as_mut(&mut self) -> Option<&mut CopyState> {
        self.0.as_deref_mut().and_then(Option::as_mut)
    }

    fn start(&mut self, state: CopyState) {
        **self.0.get_or_insert_with(|| Box::new(None)) = Some(state);
    }

    fn take(&mut self) -> Option<CopyState> {
        self.0.as_deref_mut().and_then(Option::take)
    }
}

/// 借用当前 CopyData 的载荷。
/// 一个块可能只包含 CSV、文本或 JSON 记录的一部分。
pub struct CopyChunk<'a> {
    bytes: &'a [u8],
}
impl CopyChunk<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
#[must_use = "复用连接前须完成或拒绝 COPY IN"]
pub struct CopyInput<'a, T: WireTransport> {
    session: &'a mut Session<T>,
    info: CopyInfo,
}
#[must_use = "复用连接前须完成 COPY OUT"]
pub struct CopyOutput<'a, T: WireTransport> {
    session: &'a mut Session<T>,
    info: CopyInfo,
}

struct CopyOutputBuffer<const GROW: bool> {
    bytes: Vec<u8>,
    max_bytes: usize,
    frame_error: Option<Error>,
}

impl<const GROW: bool> CopyOutputBuffer<GROW> {
    fn reserve_payload(&mut self, payload_len: usize) -> Result<(), Error> {
        if payload_len > self.max_bytes - self.bytes.len() {
            return Err(Error::Limit("COPY output exceeds its collection limit"));
        }
        let required = self.bytes.len() + payload_len;
        if GROW && required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.max_bytes);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| Error::Limit("cannot grow COPY output storage"))?;
            if self.bytes.capacity() > self.max_bytes {
                return Err(Error::Limit("COPY output backing exceeds its limit"));
            }
        }
        Ok(())
    }
}

impl<const GROW: bool> CopyDataSink for CopyOutputBuffer<GROW> {
    fn begin(&mut self, payload_len: usize) {
        self.frame_error = self.reserve_payload(payload_len).err();
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.frame_error.is_none() {
            self.bytes.extend_from_slice(bytes);
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::copy_out_copy(bytes.len());
        }
    }
}

impl<const GROW: bool> CopyOutputSink for CopyOutputBuffer<GROW> {
    fn frame_completed(&mut self, _payload_len: usize) -> Result<(), Error> {
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::copy_out_chunk(_payload_len);
        // 保留完整帧的错误边界。若收包先失败，传输错误优先。
        self.frame_error.take().map_or(Ok(()), Err)
    }
}

impl<T: WireTransport> Session<T> {
    /// 复用本次 COPY 前已准备的命名语句，省去 Parse 和 portal Describe。
    /// 扩展协议仍须在输入结束或出错时发送对应的 Sync。
    pub async fn copy_in_prepared(
        &mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'_, T>, Error> {
        self.copy_in_prepared_scoped(statement, parameters, scheduling, false)
            .await
    }
    async fn copy_in_prepared_scoped(
        &mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyInput<'_, T>, Error> {
        let info = self
            .start_prepared_copy(
                statement,
                parameters,
                Direction::In,
                scheduling,
                in_transaction,
            )
            .await?;
        Ok(CopyInput {
            session: self,
            info,
        })
    }
    pub async fn copy_out_prepared(
        &mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'_, T>, Error> {
        self.copy_out_prepared_scoped(statement, parameters, scheduling, false)
            .await
    }
    async fn copy_out_prepared_scoped(
        &mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyOutput<'_, T>, Error> {
        let info = self
            .start_prepared_copy(
                statement,
                parameters,
                Direction::Out,
                scheduling,
                in_transaction,
            )
            .await?;
        Ok(CopyOutput {
            session: self,
            info,
        })
    }
    async fn start_prepared_copy(
        &mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        direction: Direction,
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyInfo, Error> {
        self.check_idle_access(in_transaction)?;
        let quantum = ExecutionQuantum::new(scheduling);
        let admission = Self::resolve_prepared(self.id, self.extended.as_deref(), statement, true)?;
        let mut matched = admission.parameters(
            parameters,
            "prepared COPY parameter count differs from its statement",
        )?;
        matched.use_default_result_formats();
        let packet = frontend::PreparedExecution::checked(
            &matched,
            direction.extended_query_tail(),
            self.max_request_len,
            "prepared COPY parameter type differs from its statement",
            || Ok(()),
        )?;
        let bytes = packet.encode_into(self.transport.take_send_buffer()?, self.max_request_len)?;
        let result = self
            .start_copy_packet(bytes, CopyProtocol::Extended, direction, true, quantum)
            .await;
        if result.is_err() && self.active {
            self.transport.break_connection();
        }
        result
    }
    pub async fn copy_in(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'_, T>, Error> {
        self.copy_in_scoped(sql, parameters, protocol, scheduling, false)
            .await
    }
    async fn copy_in_scoped(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyInput<'_, T>, Error> {
        let info = self
            .start_copy(
                sql,
                parameters,
                protocol,
                Direction::In,
                scheduling,
                in_transaction,
            )
            .await?;
        Ok(CopyInput {
            session: self,
            info,
        })
    }
    pub async fn copy_out(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'_, T>, Error> {
        self.copy_out_scoped(sql, parameters, protocol, scheduling, false)
            .await
    }
    async fn copy_out_scoped(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyOutput<'_, T>, Error> {
        let info = self
            .start_copy(
                sql,
                parameters,
                protocol,
                Direction::Out,
                scheduling,
                in_transaction,
            )
            .await?;
        Ok(CopyOutput {
            session: self,
            info,
        })
    }

    async fn start_copy(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        direction: Direction,
        scheduling: ExecutionScheduling,
        in_transaction: bool,
    ) -> Result<CopyInfo, Error> {
        self.check_idle_access(in_transaction)?;
        let quantum = ExecutionQuantum::new(scheduling);
        let result = self
            .start_copy_inner(sql, parameters, protocol, direction, quantum)
            .await;
        if result.is_err() && self.active {
            self.transport.break_connection();
        }
        result
    }

    async fn start_copy_inner(
        &mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        direction: Direction,
        quantum: ExecutionQuantum,
    ) -> Result<CopyInfo, Error> {
        let bytes = match protocol {
            CopyProtocol::SimpleSingle => {
                if !parameters.is_empty() {
                    return Err(Error::InvalidInput(
                        "Simple Query COPY does not bind parameters",
                    ));
                }
                let packet = frontend::SimpleQueryPacket::simple(sql, self.max_request_len)?;
                let buffer = self.transport.take_send_buffer()?;
                packet.encode_into(buffer)?
            }
            CopyProtocol::Extended => frontend::one_shot(
                || self.transport.take_send_buffer(),
                sql,
                parameters,
                &[],
                false,
                direction.extended_query_tail(),
                self.max_request_len,
            )?,
        };
        self.start_copy_packet(bytes, protocol, direction, false, quantum)
            .await
    }

    async fn start_copy_packet(
        &mut self,
        bytes: Vec<u8>,
        protocol: CopyProtocol,
        direction: Direction,
        prepared: bool,
        quantum: ExecutionQuantum,
    ) -> Result<CopyInfo, Error> {
        let encoded_bytes = bytes.len();
        self.copy_state.start(CopyState {
            protocol,
            direction,
            established: false,
            error: None,
            input_end: None,
            send: CopySend::Startup,
            backend_done: false,
            discard_on_abandon: false,
            command_rows: None,
            pending_chunk_bytes: 0,
            quantum,
            ready: None,
            control_messages: 0,
        });
        self.active = true;
        self.remaining_boundaries = 1;
        if !prepared {
            self.invalidate_unnamed_statement()?;
        }
        if let Err(error) = self.transport.begin_send(bytes) {
            self.transport.break_connection();
            return Err(error);
        }
        self.copy_state
            .as_mut()
            .ok_or(Error::Broken)?
            .quantum
            .spend_bytes(encoded_bytes);
        self.copy_checkpoint().await?;
        let mut startup = match (protocol, prepared) {
            (CopyProtocol::SimpleSingle, _) => CopyStartup::Response,
            (CopyProtocol::Extended, true) => CopyStartup::Bind,
            (CopyProtocol::Extended, false) => CopyStartup::Parse,
        };
        loop {
            self.transport.receive_frame_on_owner().await?;
            self.check_copy_control_limit()?;
            let frame = self.transport.frame()?;
            let wire_bytes = frame.body.len().saturating_add(5);
            let message = protocol::parse_backend(frame)?;
            let mut response = None;
            let mut failure = None;
            let schema_changed = matches!(&message, BackendMessage::ParameterStatus { name, .. } if *name == "search_path");
            match message {
                BackendMessage::ParseComplete if startup == CopyStartup::Parse => {
                    startup = CopyStartup::Bind;
                }
                BackendMessage::BindComplete if startup == CopyStartup::Bind => {
                    startup = CopyStartup::Response;
                }
                BackendMessage::CopyInResponse(info)
                    if direction == Direction::In && startup == CopyStartup::Response =>
                {
                    response = Some(CopyInfo::from_response(info)?)
                }
                BackendMessage::CopyOutResponse(info)
                    if direction == Direction::Out && startup == CopyStartup::Response =>
                {
                    response = Some(CopyInfo::from_response(info)?)
                }
                BackendMessage::CopyInResponse(_)
                | BackendMessage::CopyOutResponse(_)
                | BackendMessage::CopyBothResponse(_) => {
                    self.transport.break_connection();
                    return Err(Error::Unsupported(
                        "COPY direction differs from the explicitly selected operation",
                    ));
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ParameterStatus { name, value } => validate_parameter(name, value)?,
                BackendMessage::ErrorResponse(error) => {
                    if is_fatal(error) {
                        let error = owned_error(error);
                        self.transport.break_connection();
                        return Err(Error::Database(error));
                    }
                    failure = Some(owned_error(error));
                }
                _ => {
                    self.transport.break_connection();
                    return Err(protocol_error("unexpected response before COPY startup"));
                }
            }
            self.consume_copy_frame(wire_bytes, true)?;
            if let Some(info) = response {
                let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
                state.established = true;
                self.copy_checkpoint().await?;
                return Ok(info);
            }
            if schema_changed {
                self.bump_schema_epoch()?;
            }
            if let Some(error) = failure {
                self.copy_state.as_mut().ok_or(Error::Broken)?.error = Some(error);
                return match self.finish_copy_on_owner(None, NoticePolicy::Deliver).await {
                    Err(error) => Err(error),
                    Ok(_) => Err(protocol_error(
                        "failed COPY startup unexpectedly completed successfully",
                    )),
                };
            }
            self.copy_checkpoint().await?;
        }
    }

    /// 拒绝遗留输入：先完成已接纳的帧，再发送 CopyFail，扩展协议还会补发原操作的 Sync。
    pub async fn fail_abandoned_copy(&mut self, message: &str) -> Result<CopyAbort, Error> {
        let state = self
            .copy_state
            .as_ref()
            .ok_or(Error::InvalidInput("there is no active COPY"))?;
        if state.discard_on_abandon {
            return Err(Error::Broken);
        }
        if state.direction != Direction::In || !state.established {
            return Err(Error::Unsupported(
                "only an established COPY IN can be failed and drained",
            ));
        }
        self.abort_copy(message, NoticePolicy::Drain).await
    }

    async fn abort_copy(
        &mut self,
        message: &str,
        notices: NoticePolicy,
    ) -> Result<CopyAbort, Error> {
        let input_end = self.copy_state.as_ref().ok_or(Error::Broken)?.input_end;
        match self.finish_copy(Some(message), notices).await {
            Err(Error::Database(diagnostic))
                if self.copy_state.is_none() && diagnostic.code() == "57014" =>
            {
                Ok(CopyAbort::Aborted {
                    diagnostic,
                    transaction_status: self.transaction_status,
                })
            }
            Ok(completion) if input_end == Some(InputEnd::Done) => {
                Ok(CopyAbort::AlreadyCompleted(completion))
            }
            Ok(_) => {
                self.transport.break_connection();
                Err(protocol_error("COPY completed successfully after CopyFail"))
            }
            Err(error) => Err(error),
        }
    }

    /// 排空遗留的 COPY OUT 至原操作的完成边界。
    /// 此操作不会重试 SQL 或回滚事务。
    pub async fn finish_abandoned_copy_out(&mut self) -> Result<CopyCompletion, Error> {
        let state = self
            .copy_state
            .as_ref()
            .ok_or(Error::InvalidInput("there is no active COPY"))?;
        if state.discard_on_abandon {
            return Err(Error::Broken);
        }
        if state.direction != Direction::Out || !state.established {
            return Err(Error::Unsupported(
                "only an established COPY OUT can be drained",
            ));
        }
        self.finish_copy(None, NoticePolicy::Drain).await
    }

    fn choose_copy_error_policy(&mut self, on_error: OnError) -> Result<bool, Error> {
        let state = self
            .copy_state
            .as_mut()
            .ok_or(Error::InvalidInput("the COPY scope has finished"))?;
        Ok(std::mem::replace(
            &mut state.discard_on_abandon,
            on_error == OnError::Discard,
        ))
    }

    fn invoke_copy_callback<R>(&mut self, callback: impl FnOnce() -> R) -> Result<R, Error> {
        let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
        Ok(state.invoke_callback(callback))
    }

    fn check_copy_terminal_owner(&mut self, configured: Result<bool, Error>) -> Result<(), Error> {
        let previous = configured?;
        if let Err(error) = self.check_runtime_owner() {
            // 未经轮询的 future 仍遵从原放弃策略；在错误 runtime 上驱动失败时恢复旧策略。
            if let Some(state) = self.copy_state.as_mut() {
                state.discard_on_abandon = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    async fn copy_local_failure(
        &mut self,
        on_error: OnError,
        primary: Error,
        copy_fail_message: Option<&str>,
    ) -> Error {
        if self.transport.is_broken() {
            return primary;
        }
        match on_error {
            OnError::RecoverExplicitly => primary,
            OnError::Discard => {
                self.transport.break_connection();
                primary
            }
            OnError::DrainToReady => {
                let expecting_copy_fail = copy_fail_message.is_some()
                    && self.copy_state.as_ref().is_some_and(|state| {
                        state.direction == Direction::In
                            && state.input_end.is_none()
                            && state.error.is_none()
                    });
                match self
                    .finish_copy(copy_fail_message, NoticePolicy::Drain)
                    .await
                {
                    Ok(_) => primary,
                    // 只有观察到原操作 Ready 且本地发送完成后，才能把 QueryCanceled 作为 CopyFail 的确认。
                    Err(Error::Database(error))
                        if expecting_copy_fail
                            && self.copy_state.is_none()
                            && error.code() == "57014" =>
                    {
                        primary
                    }
                    Err(cleanup) => Error::Cleanup {
                        primary: Box::new(primary),
                        cleanup: Box::new(cleanup),
                    },
                }
            }
        }
    }

    async fn copy_checkpoint(&mut self) -> Result<(), Error> {
        let Some(state) = self.copy_state.as_mut() else {
            return Err(Error::InvalidInput("the COPY scope has finished"));
        };
        state.quantum.yield_on_worker().await
    }

    fn poll_copy_checkpoint(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let state = match self.copy_state.as_mut() {
            Some(state) => state,
            None => return Poll::Ready(Err(Error::InvalidInput("the COPY scope has finished"))),
        };
        state.quantum.poll_yield_on_worker(cx)
    }

    fn check_copy_control_limit(&mut self) -> Result<(), Error> {
        self.copy_state
            .as_ref()
            .ok_or(Error::Broken)?
            .check_control_limit(self.max_messages)
            .inspect_err(|_| self.transport.break_connection())
    }

    fn consume_copy_frame(&mut self, wire_bytes: usize, control: bool) -> Result<(), Error> {
        self.transport.consume_frame()?;
        let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
        state.control_messages += usize::from(control);
        state.quantum.spend_bytes(wire_bytes);
        Ok(())
    }

    fn consume_pending_copy_chunk(&mut self) -> Result<(), Error> {
        let Some(state) = self.copy_state.as_mut() else {
            return Err(Error::InvalidInput("the COPY scope has finished"));
        };
        if state.pending_chunk_bytes != 0 {
            self.transport.consume_frame()?;
            state.quantum.spend_bytes(state.pending_chunk_bytes);
            state.pending_chunk_bytes = 0;
        }
        Ok(())
    }

    /// 收到服务器错误时返回 true。等待发送时，如果发送已完成且没有待处理的响应，则返回 false。
    fn poll_copy_input_on_owner<const SENDING: bool>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<bool, Error>> {
        match self.poll_copy_checkpoint(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if self
            .copy_state
            .as_ref()
            .is_some_and(|state| state.error.is_some())
        {
            return Poll::Ready(Ok(true));
        }
        loop {
            let (received, sent) = if SENDING {
                self.transport
                    .poll_receive_frame_with_send_status_on_owner(cx, false)?
            } else {
                (self.transport.poll_receive_frame_on_owner(cx)?, false)
            };
            if received.is_pending() {
                return if sent {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Pending
                };
            }
            self.check_copy_control_limit()?;
            let (message, wire_bytes) = match self.transport.frame().and_then(|frame| {
                let wire_bytes = frame.body.len().saturating_add(5);
                Ok((protocol::parse_backend(frame)?, wire_bytes))
            }) {
                Ok(parsed) => parsed,
                Err(error) => {
                    self.transport.break_connection();
                    return Poll::Ready(Err(error));
                }
            };
            let schema_changed = matches!(&message, BackendMessage::ParameterStatus { name, .. } if *name == "search_path");
            let error = match message {
                BackendMessage::ErrorResponse(error) => {
                    if is_fatal(error) {
                        let error = owned_error(error);
                        self.transport.break_connection();
                        return Poll::Ready(Err(Error::Database(error)));
                    }
                    Some(owned_error(error))
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.notice_handler.as_ref())
                        .finish(&mut self.transport);
                    None
                }
                BackendMessage::NotificationResponse { .. } => None,
                BackendMessage::ParameterStatus { name, value } => {
                    if let Err(error) = validate_parameter(name, value) {
                        self.transport.break_connection();
                        return Poll::Ready(Err(error));
                    }
                    None
                }
                _ => {
                    self.transport.break_connection();
                    return Poll::Ready(Err(protocol_error(
                        "unexpected message during COPY input",
                    )));
                }
            };
            if let Err(error) = self.consume_copy_frame(wire_bytes, true) {
                return Poll::Ready(Err(error));
            }
            if schema_changed && let Err(error) = self.bump_schema_epoch() {
                self.transport.break_connection();
                return Poll::Ready(Err(error));
            }
            if let Some(error) = error {
                let Some(state) = self.copy_state.as_mut() else {
                    return Poll::Ready(Err(Error::Broken));
                };
                if state.error.is_none() {
                    state.error = Some(error);
                }
                match self.poll_copy_checkpoint(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                return Poll::Ready(Ok(true));
            }
            match self.poll_copy_checkpoint(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// 优先观察服务端错误和调度额度，再向生产者索取输入。两者的错误分别由协议和输入流处理。
    async fn next_copy_input<I>(
        &mut self,
        source: &mut (impl Stream<Item = I> + Unpin + ?Sized),
    ) -> Result<Option<I>, Error> {
        self.wait_protocol_on_owner(|session, cx| {
            match session.poll_copy_input_on_owner::<false>(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(true)) => return Poll::Ready(Ok(None)),
                Poll::Pending
                    if session
                        .copy_state
                        .as_ref()
                        .is_some_and(|state| state.quantum.is_exhausted()) =>
                {
                    return Poll::Pending;
                }
                _ => {}
            }
            session
                .invoke_copy_callback(|| Pin::new(&mut *source).poll_next(cx))?
                .map(Ok)
        })
        .await
    }

    fn copy_input_open(&self) -> Result<bool, Error> {
        let state = self
            .copy_state
            .as_ref()
            .ok_or(Error::InvalidInput("the COPY scope has finished"))?;
        if state.direction != Direction::In || state.input_end.is_some() {
            return Err(Error::InvalidInput(
                "COPY input is no longer accepting data",
            ));
        }
        if state.send == CopySend::Data {
            return Err(Error::Busy);
        }
        Ok(state.error.is_none())
    }
    async fn send_copy_data(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.copy_checkpoint().await?;
        if !self.copy_input_open()? {
            return self
                .finish_copy_on_owner(None, NoticePolicy::Deliver)
                .await
                .map(|_| ());
        }
        let chunks = [bytes];
        let plan = frontend::CopyDataBatch::new(&chunks, self.max_request_len)?;
        self.retire_copy_startup_on_owner().await?;
        let work = plan.work_units();
        let packet = plan.encode_into(self.transport.take_send_buffer()?)?;
        self.begin_copy_data_packet(packet, work)?;
        self.finish_copy_packet().await
    }
    async fn send_copy_packet(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        self.copy_checkpoint().await?;
        self.retire_copy_startup_on_owner().await?;
        let work = byte_work_units(packet.len());
        self.begin_copy_data_packet(packet, work)?;
        self.finish_copy_packet().await
    }

    async fn retire_copy_startup_on_owner(&mut self) -> Result<(), Error> {
        let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
        // COPY 已收到响应时，本地 I/O 仍可能持有启动包。此后由各个数据包确认自己的发送。
        if state.send == CopySend::Startup {
            self.transport.finish_send_on_owner().await?;
            state.send = CopySend::Idle;
        }
        Ok(())
    }

    fn begin_copy_data_packet(&mut self, packet: Vec<u8>, work: usize) -> Result<(), Error> {
        let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
        self.transport.begin_send(packet)?;
        state.send = CopySend::Data;
        state.quantum.spend_units(work);
        Ok(())
    }

    async fn finish_copy_packet(&mut self) -> Result<(), Error> {
        let server_error = self
            .wait_protocol_on_owner(Self::poll_copy_input_on_owner::<true>)
            .await?;
        if server_error {
            self.finish_copy_on_owner(None, NoticePolicy::Deliver)
                .await?;
        } else {
            self.copy_state.as_mut().ok_or(Error::Broken)?.send = CopySend::Idle;
        }
        Ok(())
    }

    async fn finish_copy(
        &mut self,
        local_failure: Option<&str>,
        notices: NoticePolicy,
    ) -> Result<CopyCompletion, Error> {
        self.check_runtime_owner()?;
        self.finish_copy_on_owner(local_failure, notices).await
    }

    async fn finish_copy_on_owner(
        &mut self,
        local_failure: Option<&str>,
        notices: NoticePolicy,
    ) -> Result<CopyCompletion, Error> {
        match self
            .finish_copy_with_sink(local_failure, notices, &mut ())
            .await?
        {
            CopyFinish::Ready(completion) => Ok(completion),
            CopyFinish::OutputFailure(error) => Err(error),
        }
    }

    async fn finish_copy_with_sink(
        &mut self,
        local_failure: Option<&str>,
        notices: NoticePolicy,
        sink: &mut impl CopyOutputSink,
    ) -> Result<CopyFinish, Error> {
        let result = self.finish_copy_inner(local_failure, notices, sink).await;
        if matches!(
            result,
            Err(Error::Protocol(_) | Error::Io(_) | Error::Broken)
        ) {
            self.transport.break_connection();
        }
        result
    }

    /// 上一包写入受背压时仍接收服务器响应，直到能够按 TCP 顺序追加输入结束帧。
    async fn receive_copy_completion_frame(
        &mut self,
        local_failure: Option<&str>,
        sink: &mut impl CopyDataSink,
    ) -> Result<CopyOutFrame, Error> {
        let state = self.copy_state.as_ref().ok_or(Error::Broken)?;
        if state.direction == Direction::Out && state.error.is_none() && !state.backend_done {
            return self
                .wait_protocol_on_owner(|session, cx| {
                    session.transport.poll_copy_out_frame_on_owner(cx, sink)
                })
                .await;
        }
        if state.direction != Direction::In || state.input_end.is_some() {
            self.transport.receive_frame_on_owner().await?;
            return Ok(CopyOutFrame::Control);
        }
        if state.error.is_none() || state.protocol == CopyProtocol::Extended {
            let send_retired = self
                .wait_protocol_on_owner(|session, cx| {
                    let (received, sent) = session
                        .transport
                        .poll_receive_frame_with_send_status_on_owner(cx, true)?;
                    match (received, sent) {
                        (Poll::Ready(()), _) => Poll::Ready(Ok(false)),
                        // 接收轮询可收回原发送包。若已发送完毕，立即追加结束帧。
                        (Poll::Pending, true) => Poll::Ready(Ok(true)),
                        (Poll::Pending, false) => Poll::Pending,
                    }
                })
                .await?;
            if !send_retired {
                return Ok(CopyOutFrame::Control);
            }
        }
        let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
        let tail = if state.protocol == CopyProtocol::Extended {
            QueryTail::Sync
        } else {
            QueryTail::Open
        };
        let bytes = if state.error.is_some() {
            if tail == QueryTail::Sync {
                frontend::sync(self.transport.take_send_buffer()?, self.max_request_len)?
            } else {
                Vec::new()
            }
        } else {
            let plan = frontend::CopyEnd::new(local_failure, tail, self.max_request_len)?;
            plan.encode_into(self.transport.take_send_buffer()?)?
        };
        state.input_end = Some(if state.error.is_some() || local_failure.is_some() {
            InputEnd::Rejected
        } else {
            InputEnd::Done
        });
        if !bytes.is_empty() {
            let encoded_bytes = bytes.len();
            self.transport.begin_send(bytes)?;
            state.quantum.spend_bytes(encoded_bytes);
            self.copy_checkpoint().await?;
        }
        self.transport.receive_frame_on_owner().await?;
        Ok(CopyOutFrame::Control)
    }

    async fn finish_copy_inner(
        &mut self,
        local_failure: Option<&str>,
        notices: NoticePolicy,
        sink: &mut impl CopyOutputSink,
    ) -> Result<CopyFinish, Error> {
        if self.transport.is_broken() {
            return Err(Error::Broken);
        }
        self.consume_pending_copy_chunk()?;
        loop {
            self.copy_checkpoint().await?;
            if let Some(status) = self.copy_state.as_ref().and_then(|state| state.ready) {
                return self.complete_copy(status).await.map(CopyFinish::Ready);
            }
            if let CopyOutFrame::Data(payload_len) = self
                .receive_copy_completion_frame(local_failure, sink)
                .await?
            {
                self.copy_state
                    .as_mut()
                    .ok_or(Error::Broken)?
                    .quantum
                    .spend_bytes(payload_len.saturating_add(COPY_DATA_HEADER_BYTES));
                if let Err(error) = sink.frame_completed(payload_len) {
                    return Ok(CopyFinish::OutputFailure(error));
                }
                continue;
            }
            let frame = self.transport.frame()?;
            let wire_bytes = frame.body.len().saturating_add(5);
            if frame.tag == b'd' {
                return Err(protocol_error("unexpected COPY data while finishing"));
            }
            let state = self.copy_state.as_mut().ok_or(Error::Broken)?;
            if let Err(error) = state.check_control_limit(self.max_messages) {
                self.transport.break_connection();
                return Err(error);
            }
            let message = protocol::parse_backend(frame)?;
            let mut ready = None;
            let schema_changed = matches!(&message, BackendMessage::ParameterStatus { name, .. } if *name == "search_path");
            match message {
                BackendMessage::CopyDone
                    if state.direction == Direction::Out
                        && state.error.is_none()
                        && !state.backend_done =>
                {
                    state.backend_done = true
                }
                BackendMessage::CommandComplete(tag)
                    if state.error.is_none()
                        && state.command_rows.is_none()
                        && (state.input_end == Some(InputEnd::Done) || state.backend_done) =>
                {
                    let CommandTag::Copy(rows) = protocol::parse_command_tag(tag)? else {
                        self.transport.break_connection();
                        return Err(protocol_error("COPY returned a non-COPY completion tag"));
                    };
                    state.command_rows = Some(rows);
                }
                BackendMessage::ErrorResponse(error) => {
                    if is_fatal(error) {
                        let error = owned_error(error);
                        self.transport.break_connection();
                        return Err(Error::Database(error));
                    }
                    if state.error.is_none() {
                        state.error = Some(owned_error(error));
                    }
                }
                BackendMessage::ReadyForQuery(status)
                    if (state.error.is_some() || state.command_rows.is_some())
                        && (state.direction == Direction::Out
                            || state.protocol == CopyProtocol::SimpleSingle
                            || state.input_end.is_some()) =>
                {
                    ready = Some(status)
                }
                BackendMessage::NoticeResponse(notice) => {
                    if notices == NoticePolicy::Deliver {
                        super::observe_notice(notice, self.notice_handler.as_ref())
                            .finish(&mut self.transport);
                    }
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ParameterStatus { name, value } => {
                    if let Err(error) = validate_parameter(name, value) {
                        self.transport.break_connection();
                        return Err(error);
                    }
                }
                _ => {
                    self.transport.break_connection();
                    return Err(protocol_error("unexpected COPY completion response"));
                }
            }
            self.consume_copy_frame(wire_bytes, true)?;
            if schema_changed {
                self.bump_schema_epoch()?;
            }
            if let Some(status) = ready {
                self.note_ready(status)?;
                self.copy_state.as_mut().ok_or(Error::Broken)?.ready = Some(status);
            }
        }
    }

    async fn complete_copy(&mut self, status: TransactionStatus) -> Result<CopyCompletion, Error> {
        if let Err(send) = self.transport.finish_send_on_owner().await {
            self.transport.break_connection();
            let diagnostic = self
                .copy_state
                .as_mut()
                .and_then(|state| state.error.take());
            return Err(super::general::send_after_diagnostic(diagnostic, send));
        }
        self.active = false;
        let state = self.copy_state.take().ok_or(Error::Broken)?;
        if let Some(error) = state.error {
            return Err(Error::Database(error));
        }
        Ok(CopyCompletion {
            rows: state
                .command_rows
                .ok_or_else(|| protocol_error("missing COPY command completion"))?,
            transaction_status: status,
        })
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    pub async fn copy_in_prepared<'s>(
        &'s mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'s, T>, Error> {
        self.session_mut()
            .copy_in_prepared_scoped(statement, parameters, scheduling, true)
            .await
    }

    pub async fn copy_out_prepared<'s>(
        &'s mut self,
        statement: &super::PreparedStatement,
        parameters: &[Parameter<'_>],
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'s, T>, Error> {
        self.session_mut()
            .copy_out_prepared_scoped(statement, parameters, scheduling, true)
            .await
    }

    pub async fn copy_in<'s>(
        &'s mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
    ) -> Result<CopyInput<'s, T>, Error> {
        self.session_mut()
            .copy_in_scoped(sql, parameters, protocol, scheduling, true)
            .await
    }

    pub async fn copy_out<'s>(
        &'s mut self,
        sql: &str,
        parameters: &[Parameter<'_>],
        protocol: CopyProtocol,
        scheduling: ExecutionScheduling,
    ) -> Result<CopyOutput<'s, T>, Error> {
        self.session_mut()
            .copy_out_scoped(sql, parameters, protocol, scheduling, true)
            .await
    }

    /// 显式拒绝本次事务中遗留的 COPY IN 并确认服务端结果；失败事务仍须由调用方结束。
    pub async fn fail_abandoned_copy(&mut self, message: &str) -> Result<CopyAbort, Error> {
        self.session_mut().fail_abandoned_copy(message).await
    }

    /// 排空本次事务中遗留的 COPY OUT，保留事务的控制权。
    pub async fn finish_abandoned_copy_out(&mut self) -> Result<CopyCompletion, Error> {
        self.session_mut().finish_abandoned_copy_out().await
    }
}

impl<T: WireTransport> CopyInput<'_, T> {
    pub fn info(&self) -> &CopyInfo {
        &self.info
    }
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.session.check_runtime_owner()?;
        self.session.send_copy_data(bytes).await
    }

    /// 将多个独立 CopyData 帧编码成一个有界包。
    /// 全部输入先通过校验才交给传输。
    /// 成功确认本地发送和 TLS 刷新；COPY 的结果由 finish 确认。
    /// 错误可能发生在部分字节送达后。
    /// 放弃 future 会留下协议进度和在途缓冲，需显式拒绝、排空或丢弃。
    pub async fn send_batch(
        &mut self,
        chunks: &[&[u8]],
        limits: CopyBatchLimits,
    ) -> Result<CopyBatchCompletion, CopyBatchError> {
        self.session
            .check_runtime_owner()
            .map_err(CopyBatchError::before_send)?;
        if limits.max_chunks == 0
            || limits.max_packet_bytes < 5
            || limits.max_packet_bytes > self.session.max_request_len
        {
            return Err(CopyBatchError::before_send(Error::InvalidInput(
                "invalid COPY batch bounds",
            )));
        }
        if chunks.len() > limits.max_chunks {
            return Err(CopyBatchError::before_send(Error::Limit(
                "COPY batch exceeds its chunk limit",
            )));
        }
        self.session
            .copy_checkpoint()
            .await
            .map_err(CopyBatchError::before_send)?;
        if !self
            .session
            .copy_input_open()
            .map_err(CopyBatchError::before_send)?
        {
            self.session
                .finish_copy_on_owner(None, NoticePolicy::Deliver)
                .await
                .map_err(CopyBatchError::before_send)?;
            return Err(CopyBatchError::before_send(Error::InvalidInput(
                "COPY input already finished",
            )));
        }
        let plan = frontend::CopyDataBatch::new(chunks, limits.max_packet_bytes)
            .map_err(CopyBatchError::before_send)?;
        let completion = CopyBatchCompletion {
            chunks: chunks.len(),
            payload_bytes: plan.payload_bytes(),
        };
        if chunks.is_empty() {
            return Ok(completion);
        }
        self.session
            .retire_copy_startup_on_owner()
            .await
            .map_err(CopyBatchError::before_send)?;
        let buffer = self
            .session
            .transport
            .take_send_buffer()
            .map_err(CopyBatchError::before_send)?;
        let work = plan.work_units();
        let packet = plan
            .encode_into(buffer)
            .map_err(CopyBatchError::before_send)?;
        self.session
            .begin_copy_data_packet(packet, work)
            .map_err(CopyBatchError::before_send)?;
        self.session
            .finish_copy_packet()
            .await
            .map_err(|source| CopyBatchError {
                source,
                may_have_been_sent: true,
            })?;
        Ok(completion)
    }

    /// 在 `limits` 内从输入流借用各块字节并编码进发送缓冲。
    /// 输入错误及流或包超限按 `on_error` 处置。
    pub fn send_stream<B: AsRef<[u8]>>(
        self,
        source: &mut (impl Stream<Item = Result<B, Error>> + Unpin + ?Sized),
        limits: CopyStreamLimits,
        on_error: OnError,
    ) -> impl std::future::Future<Output = Result<CopyCompletion, Error>> {
        self.transfer_stream(
            source,
            limits,
            on_error,
            async |copy, bytes: B, limits| {
                let payload = copy.session.invoke_copy_callback(|| bytes.as_ref())?;
                limits.charge_payload(payload.len())?;
                copy.session
                    .send_copy_data(payload)
                    .await
                    .map_err(StreamSendError::Send)
            },
            |_, ()| Ok(()),
        )
    }

    /// 在 `limits` 内直接发送输入流提供的完整 CopyData 包。
    /// 每包等待本地发送与 TLS 刷新，最后一个缓冲可用于编码结束消息。
    /// 输入错误及流或包超限按 `on_error` 处置。
    pub fn send_owned_stream(
        self,
        source: &mut (impl Stream<Item = Result<CopyDataBuffer, Error>> + Unpin + ?Sized),
        limits: CopyStreamLimits,
        on_error: OnError,
    ) -> impl std::future::Future<Output = Result<CopyCompletion, Error>> {
        self.transfer_stream(
            source,
            limits,
            on_error,
            async |copy, packet, limits| copy.send_owned_stream_packet(packet, limits).await,
            |_, ()| Ok(()),
        )
    }

    /// 按限额发送输入流，本地发送及 TLS 刷新后将原包归还回调。
    /// 输入、包、总量和回调错误按 `on_error` 处理。DrainToReady 发送 CopyFail 并等待 Ready；
    /// 清理失败时保留两个错误。生产者或回调 panic 后须丢弃会话。
    pub fn send_owned_stream_recycling<F>(
        self,
        source: &mut (impl Stream<Item = Result<CopyDataBuffer, Error>> + Unpin + ?Sized),
        limits: CopyStreamLimits,
        mut on_recycled: F,
        on_error: OnError,
    ) -> impl std::future::Future<Output = Result<CopyCompletion, Error>>
    where
        F: FnMut(CopyDataBuffer) -> Result<(), Error>,
    {
        self.transfer_stream(
            source,
            limits,
            on_error,
            async |copy, packet, limits| {
                copy.send_owned_stream_packet(packet, limits).await?;
                copy.take_sent_copy_data().map_err(StreamSendError::Send)
            },
            move |session, packet| session.invoke_copy_callback(|| on_recycled(packet))?,
        )
    }

    fn transfer_stream<P, R>(
        mut self,
        source: &mut (impl Stream<Item = Result<P, Error>> + Unpin + ?Sized),
        mut limits: CopyStreamLimits,
        on_error: OnError,
        mut send: impl AsyncFnMut(&mut Self, P, &mut CopyStreamLimits) -> Result<R, StreamSendError>,
        mut retire: impl FnMut(&mut Session<T>, R) -> Result<(), Error>,
    ) -> impl std::future::Future<Output = Result<CopyCompletion, Error>> {
        let configured = self.session.choose_copy_error_policy(on_error);
        async move {
            self.session.check_copy_terminal_owner(configured)?;
            loop {
                let input = match self.session.next_copy_input(source).await? {
                    Some(Ok(input)) => input,
                    Some(Err(error)) => {
                        return Err(self
                            .session
                            .copy_local_failure(on_error, error, Some("input source failed"))
                            .await);
                    }
                    None => {
                        return self
                            .session
                            .finish_copy_on_owner(None, NoticePolicy::Deliver)
                            .await;
                    }
                };
                let result = if let Some(chunks_left) = limits.max_chunks.checked_sub(1) {
                    limits.max_chunks = chunks_left;
                    send(&mut self, input, &mut limits).await
                } else {
                    Err(StreamSendError::StreamLimit)
                };
                let sent = match result {
                    Ok(sent) => sent,
                    Err(StreamSendError::StreamLimit) => {
                        return Err(self
                            .session
                            .copy_local_failure(
                                on_error,
                                Error::Limit("COPY stream exceeds its chunk or payload limit"),
                                Some("input stream exceeded its bounds"),
                            )
                            .await);
                    }
                    Err(StreamSendError::Send(error @ Error::Limit(_))) => {
                        return Err(self
                            .session
                            .copy_local_failure(
                                on_error,
                                error,
                                Some("input packet exceeded its bounds"),
                            )
                            .await);
                    }
                    Err(StreamSendError::Send(error)) => return Err(error),
                };
                if let Err(error) = retire(self.session, sent) {
                    return Err(self
                        .session
                        .copy_local_failure(on_error, error, Some("recycle callback failed"))
                        .await);
                }
            }
        }
    }

    /// 接手完整 CopyData 包，在本地发送及 TLS 刷新完成后交回原缓冲。
    pub async fn send_owned(&mut self, packet: CopyDataBuffer) -> Result<CopyDataBuffer, Error> {
        self.session.check_runtime_owner()?;
        self.send_owned_packet_on_owner(packet).await?;
        self.take_sent_copy_data()
    }

    async fn send_owned_stream_packet(
        &mut self,
        packet: CopyDataBuffer,
        limits: &mut CopyStreamLimits,
    ) -> Result<(), StreamSendError> {
        limits.charge_payload(packet.payload().len())?;
        self.send_owned_packet_on_owner(packet)
            .await
            .map_err(StreamSendError::Send)
    }

    async fn send_owned_packet_on_owner(&mut self, packet: CopyDataBuffer) -> Result<(), Error> {
        if !self.session.copy_input_open()? {
            self.session
                .finish_copy_on_owner(None, NoticePolicy::Deliver)
                .await?;
            return Err(Error::InvalidInput("COPY input already finished"));
        }
        let packet = packet.into_packet(self.session.max_request_len)?;
        self.session.send_copy_packet(packet).await
    }

    fn take_sent_copy_data(&mut self) -> Result<CopyDataBuffer, Error> {
        CopyDataBuffer::recycled(self.session.transport.take_send_packet()?)
    }
    pub async fn finish(self) -> Result<CopyCompletion, Error> {
        self.session.finish_copy(None, NoticePolicy::Deliver).await
    }
    /// 拒绝继续输入，等待服务端确认取消及最终事务状态。
    pub async fn fail(self, message: &str) -> Result<CopyAbort, Error> {
        self.session
            .abort_copy(message, NoticePolicy::Deliver)
            .await
    }
}

impl<T: WireTransport> CopyOutput<'_, T> {
    pub fn info(&self) -> &CopyInfo {
        &self.info
    }
    pub async fn next_chunk(&mut self) -> Result<Option<CopyChunk<'_>>, Error> {
        self.session.check_runtime_owner()?;
        self.session.consume_pending_copy_chunk()?;
        if self.map_chunk_on_owner::<true, _>(|_| ()).await?.is_none() {
            return Ok(None);
        }
        Ok(Some(CopyChunk {
            bytes: self.session.transport.frame()?.body,
        }))
    }

    // 在消费或替换当前帧之前使用载荷，无需再次取得该帧。
    async fn map_chunk_on_owner<const RETAIN_FRAME: bool, R>(
        &mut self,
        map: impl FnOnce(&[u8]) -> R,
    ) -> Result<Option<R>, Error> {
        self.session.copy_checkpoint().await?;
        let Some(state) = self.session.copy_state.as_ref() else {
            return Err(Error::InvalidInput("the COPY scope has finished"));
        };
        // 上一个 future 可能在让出执行权前已记录错误或 Ready。
        if state.error.is_some() {
            return self
                .session
                .finish_copy_on_owner(None, NoticePolicy::Deliver)
                .await
                .map(|_| None);
        }
        if state.backend_done {
            return Ok(None);
        }
        loop {
            self.session.transport.receive_frame_on_owner().await?;
            let frame = self.session.transport.frame()?;
            if frame.tag == b'd' {
                let wire_bytes = frame.body.len().saturating_add(5);
                let state = self.session.copy_state.as_mut().ok_or(Error::Broken)?;
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::copy_out_chunk(frame.body.len());
                let value = if RETAIN_FRAME {
                    map(frame.body)
                } else {
                    state.invoke_callback(|| map(frame.body))
                };
                if RETAIN_FRAME {
                    state.pending_chunk_bytes = wire_bytes;
                } else {
                    self.session.transport.consume_frame()?;
                    state.quantum.spend_bytes(wire_bytes);
                }
                return Ok(Some(value));
            }
            let wire_bytes = frame.body.len().saturating_add(5);
            let state = self.session.copy_state.as_ref().ok_or(Error::Broken)?;
            if let Err(error) = state.check_control_limit(self.session.max_messages) {
                self.session.transport.break_connection();
                return Err(error);
            }
            let message = match protocol::parse_backend(frame) {
                Ok(message) => message,
                Err(error) => {
                    self.session.transport.break_connection();
                    return Err(error.into());
                }
            };
            let schema_changed = matches!(&message, BackendMessage::ParameterStatus { name, .. } if *name == "search_path");
            match message {
                BackendMessage::CopyDone => {
                    self.session
                        .copy_state
                        .as_mut()
                        .ok_or(Error::Broken)?
                        .backend_done = true;
                    self.session.consume_copy_frame(wire_bytes, true)?;

                    self.session.copy_checkpoint().await?;
                    return Ok(None);
                }
                BackendMessage::ErrorResponse(error) => {
                    let fatal = is_fatal(error);
                    let error = owned_error(error);
                    self.session.consume_copy_frame(wire_bytes, true)?;

                    if fatal {
                        self.session.transport.break_connection();
                        return Err(Error::Database(error));
                    }
                    self.session.copy_state.as_mut().ok_or(Error::Broken)?.error = Some(error);
                    return self
                        .session
                        .finish_copy_on_owner(None, NoticePolicy::Deliver)
                        .await
                        .map(|_| None);
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.session.notice_handler.as_ref())
                        .finish(&mut self.session.transport);
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ParameterStatus { name, value } => {
                    if let Err(error) = validate_parameter(name, value) {
                        self.session.transport.break_connection();
                        return Err(error);
                    }
                }
                _ => {
                    self.session.transport.break_connection();
                    return Err(protocol_error("unexpected COPY output response"));
                }
            }
            self.session.consume_copy_frame(wire_bytes, true)?;

            if schema_changed {
                self.session.bump_schema_epoch()?;
            }
            self.session.copy_checkpoint().await?;
        }
    }

    /// 丢弃剩余输出并确认命令完成及 Ready。
    pub async fn finish(self) -> Result<CopyCompletion, Error> {
        self.session.finish_copy(None, NoticePolicy::Deliver).await
    }

    /// 在同步回调中逐块借用暂定数据。成功时确认命令完成、本地发送和 Ready。
    /// 回调错误按 `on_error` 处置。回调须尽快返回，panic 后须丢弃会话。
    pub fn visit_provisional(
        self,
        on_error: OnError,
        visit: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> impl std::future::Future<Output = Result<CopyCompletion, Error>> {
        let configured = self.session.choose_copy_error_policy(on_error);
        async move {
            self.session.check_copy_terminal_owner(configured)?;
            self.consume_output(on_error, visit).await
        }
    }

    /// 收集到 Ready 并完成本地发送。输出限额同时限制长度和保留容量。
    /// Grow 按需扩容，扩容时可能短暂保留新旧缓冲。
    /// 容量和分配错误按 on_error 处理。DrainToReady 可能读取大量剩余数据。
    /// 失败或放弃时丢弃部分输出，析构不启动 I/O。
    pub fn collect_ready(
        self,
        output: OwnedOutput,
        on_error: OnError,
    ) -> impl std::future::Future<Output = Result<(Vec<u8>, CopyCompletion), Error>> {
        let configured = self.session.choose_copy_error_policy(on_error);
        async move {
            self.session.check_copy_terminal_owner(configured)?;
            match output.allocation {
                AllocationPolicy::ReserveLimit => {
                    self.collect_scheduled::<false>(output.max_bytes, on_error)
                        .await
                }
                AllocationPolicy::Grow => {
                    self.collect_scheduled::<true>(output.max_bytes, on_error)
                        .await
                }
            }
        }
    }

    async fn output_failure(&mut self, primary: Error, on_error: OnError) -> Error {
        self.session
            .copy_local_failure(on_error, primary, None)
            .await
    }

    async fn collect_scheduled<const GROW: bool>(
        mut self,
        max_bytes: usize,
        on_error: OnError,
    ) -> Result<(Vec<u8>, CopyCompletion), Error> {
        let mut output = Vec::new();
        if !GROW {
            if output.try_reserve_exact(max_bytes).is_err() {
                return Err(self
                    .output_failure(
                        Error::Limit("cannot allocate COPY output storage"),
                        on_error,
                    )
                    .await);
            }
            if output.capacity() > max_bytes {
                return Err(self
                    .output_failure(
                        Error::Limit("COPY output backing exceeds its limit"),
                        on_error,
                    )
                    .await);
            }
        }
        let mut output = CopyOutputBuffer::<GROW> {
            bytes: output,
            max_bytes,
            frame_error: None,
        };
        match self
            .session
            .finish_copy_with_sink(None, NoticePolicy::Deliver, &mut output)
            .await?
        {
            CopyFinish::Ready(completion) => Ok((output.bytes, completion)),
            CopyFinish::OutputFailure(error) => Err(self.output_failure(error, on_error).await),
        }
    }

    async fn consume_output(
        mut self,
        on_error: OnError,
        mut visit: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<CopyCompletion, Error> {
        self.session.consume_pending_copy_chunk()?;
        while let Some(result) = self.map_chunk_on_owner::<false, _>(&mut visit).await? {
            if let Err(error) = result {
                return Err(self.output_failure(error, on_error).await);
            }
        }
        self.session
            .finish_copy_on_owner(None, NoticePolicy::Deliver)
            .await
    }
}

#[cfg(test)]
mod tests;
