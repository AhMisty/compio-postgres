use std::{
    collections::TryReserveError,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use compio::runtime::{Runtime, Submit, submit};
use compio::{
    BufResult,
    buf::{IntoInner, IoBuf, Slice},
    driver::{
        ErrorExt, SharedFd, ToSharedFd,
        op::{Recv, RecvFlags, Send, SendFlags},
    },
    net::TcpStream,
};
use socket2::Socket;

use crate::{
    Error,
    protocol::{Frame, frame_header},
};

/// 排队请求发送与缓存响应交付的顺序。各传输分别确认原生 I/O 或 TLS 刷新完成；该策略不承诺内核提交、网络送达或特定吞吐。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPolicy {
    /// 返回每个已缓冲的 PostgreSQL 帧前，先推进发送。
    BeforeBufferedRead,
    /// 在已有完整响应时暂缓后续请求，以增加合并发送的机会。
    ///
    /// 有完整缓冲帧时先推进当前发送，本次轮询暂缓下一排队包。当前发送挂起时仍可交付已缓存响应；
    /// 发送错误优先返回。需要读取新数据时一并推进收发，显式等待发送完成时排空队列。
    ///
    /// 借用式原生流水线可选用此策略。交付一帧不表示全部发送已完成，显式恢复义务仍然有效。
    CoalesceBuffered,
}

/// 空闲发送窗口中就绪缓冲区与暂存缓冲区的保留策略。
///
/// 策略在窗口结束后生效。在途请求限额、普通发送包和套接字内存分别管理；显式裁剪会释放全部空闲发送存储。
#[cfg(feature = "window-cache")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WindowSendCache {
    /// 默认保留清空的窗口缓冲区供下一窗口使用；开始普通发送时释放。
    #[default]
    ReleaseOnOrdinarySend,
    /// 窗口结束后立即释放单独的窗口缓冲区。
    ReleaseAfterWindow,
    /// 允许跨普通发送复用空闲缓冲区，总容量须在上限内；只能保留一个时优先保留就绪缓冲区。新窗口可释放与其额度不符的旧存储。
    RetainUntilTrim { max_retained_bytes: usize },
}

pub(crate) fn validate_buffers(
    receive_capacity: usize,
    max_frame_len: usize,
    max_request_len: usize,
) -> Result<(), Error> {
    if receive_capacity < 5
        || max_frame_len < 4
        || i32::try_from(max_frame_len).is_err()
        || max_request_len < 5
    {
        return Err(Error::InvalidInput(
            "invalid connection buffer or message limits",
        ));
    }
    Ok(())
}

pub(crate) fn new_receive_buffer(
    receive_capacity: usize,
    max_frame_len: usize,
    max_request_len: usize,
) -> Result<Vec<u8>, Error> {
    validate_buffers(receive_capacity, max_frame_len, max_request_len)?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(receive_capacity)
        .map_err(|_| Error::Limit("cannot allocate the receive buffer"))?;
    buffer.resize(receive_capacity, 0);
    Ok(buffer)
}

/// 使用 `FrameCache::parse` 已检查的帧头准备接收存储。能在原位置接收完整帧时直接追加。
/// 合法的大帧提前取得连续容量。增长时在帧上限内预留余量，只初始化本次接收需要的字节。
pub(crate) fn prepare_receive_buffer(
    buffer: &mut Vec<u8>,
    start: &mut usize,
    end: &mut usize,
    frame_cache: &mut FrameCache,
    max_frame_len: usize,
) -> Result<(), Error> {
    if *start == *end {
        *start = 0;
        *end = 0;
        return Ok(());
    }
    let needed = frame_cache.extent.end.saturating_sub(*start).max(5);
    let available = buffer.len().checked_sub(*start).ok_or(Error::Broken)?;
    if needed <= available {
        #[cfg(feature = "diagnostics")]
        if *start != 0 {
            crate::diagnostics::compaction_skipped(*end - *start);
        }
        return Ok(());
    }
    let capacity = buffer.capacity();
    // 帧长不含标签。配置和帧头校验已保证 needed 位于总字节上限内。
    let reserve = |storage: &mut Vec<u8>| {
        reserve_receive_capacity(storage, capacity, needed, max_frame_len + 1)
            .map_err(|_| Error::Limit("cannot grow the receive buffer for this frame"))
    };
    if *start != 0 {
        let suffix = buffer.get(*start..*end).ok_or(Error::Broken)?;
        #[cfg(feature = "diagnostics")]
        let copied = suffix.len();
        if needed > capacity {
            // 重新分配时只复制未消费的字节，避开已退休前缀。
            let mut grown = Vec::new();
            reserve(&mut grown)?;
            grown.extend_from_slice(suffix);
            *buffer = grown;
        } else {
            // 已在上面检查源范围；移动后的区间总是落在缓冲区起点。
            buffer.copy_within(*start..*end, 0);
        }
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::compact(copied);
        *end -= *start;
        frame_cache.extent.end = frame_cache.extent.end.saturating_sub(*start);
        *start = 0;
    } else if needed > capacity {
        reserve(buffer)?;
    }
    if needed > buffer.len() {
        buffer.resize(needed, 0);
    }
    Ok(())
}

/// 扩容时在已校验的上限内保留余量。搬移到新存储时，增长依据是原容量。
pub(crate) fn reserve_receive_capacity(
    buffer: &mut Vec<u8>,
    previous_capacity: usize,
    needed: usize,
    limit: usize,
) -> Result<(), TryReserveError> {
    let capacity = needed.max(previous_capacity.saturating_mul(2).min(limit));
    // 预留余量失败时仍尝试容纳当前帧。
    match buffer.try_reserve_exact(capacity - buffer.len()) {
        Err(_) if capacity > needed => buffer.try_reserve_exact(needed - buffer.len()),
        result => result,
    }
}

/// 已验证的帧头坐标，帧结束位置可在已收到的数据之外。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FrameExtent {
    pub(crate) tag: u8,
    pub(crate) end: usize,
}

/// 有效帧的结束偏移至少为 5，零表示没有缓存。
#[derive(Debug, Default)]
pub(crate) struct FrameCache {
    extent: FrameExtent,
}

/// 以驱动的唤醒目标区分同一线程上的不同 runtime。构造时只保留身份，不延长执行器的生命周期。
#[derive(Debug, Default)]
pub(crate) struct IoOwner(Option<Waker>);

impl IoOwner {
    pub(crate) fn current() -> Self {
        Self(Runtime::try_with_current(Runtime::waker).ok())
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        Self::check_waker(self.waker())
    }

    /// 同一次同步轮询内，对该连接的连续读写只验证一次。
    #[inline]
    pub(crate) fn check_once(&self, checked: &mut bool) -> Result<(), Error> {
        if !*checked {
            self.check()?;
            *checked = true;
        }
        Ok(())
    }

    pub(crate) fn waker(&self) -> Option<&Waker> {
        self.0.as_ref()
    }

    pub(crate) fn check_waker(waker: Option<&Waker>) -> Result<(), Error> {
        if let Some(owner) = waker
            && !Runtime::try_with_current(|runtime| owner.will_wake(&runtime.waker()))
                .unwrap_or(false)
        {
            return Err(Error::InvalidInput(
                "the operation must run inside the owning Compio runtime",
            ));
        }
        Ok(())
    }
}

impl FrameCache {
    pub(crate) fn clear(&mut self) {
        self.extent.end = 0;
    }

    pub(crate) fn parse(
        &mut self,
        buffer: &[u8],
        start: usize,
        end: usize,
        max_frame_len: usize,
    ) -> Result<Option<FrameExtent>, crate::protocol::ProtocolError> {
        self.read_header(buffer, start, end, max_frame_len)?;
        Ok(self.complete(end))
    }

    fn complete(&self, end: usize) -> Option<FrameExtent> {
        (self.extent.end != 0 && self.extent.end <= end).then_some(self.extent)
    }

    // 只有接收轮询解析帧头。借用和消费均使用同一份已验证的帧边界。
    pub(crate) fn borrow<'a>(
        &self,
        buffer: &'a [u8],
        start: usize,
        end: usize,
        poisoned: bool,
    ) -> Result<Frame<'a>, Error> {
        if poisoned {
            return Err(Error::Broken);
        }
        let frame = self.complete(end).ok_or(Error::Busy)?;
        Ok(Frame {
            tag: frame.tag,
            body: buffer.get(start + 5..frame.end).ok_or(Error::Broken)?,
        })
    }

    pub(crate) fn consume(
        &mut self,
        start: &mut usize,
        end: usize,
        poisoned: bool,
    ) -> Result<(), Error> {
        if poisoned {
            return Err(Error::Broken);
        }
        *start = self.complete(end).ok_or(Error::Busy)?.end;
        self.clear();
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::frame();
        Ok(())
    }

    fn read_header(
        &mut self,
        buffer: &[u8],
        start: usize,
        end: usize,
        max_frame_len: usize,
    ) -> Result<(), crate::protocol::ProtocolError> {
        use crate::protocol::ProtocolError;

        if self.extent.end == 0 {
            let input = buffer.get(start..end).ok_or(ProtocolError::UnexpectedEnd)?;
            if let Some((tag, length)) = frame_header(input, max_frame_len)? {
                self.extent = FrameExtent {
                    tag,
                    end: start
                        .checked_add(length)
                        .ok_or(ProtocolError::LengthOverflow)?,
                };
            }
        }
        Ok(())
    }
}

// 原生操作只持有 Compio 已注册的共享描述符，关闭仍由原流等待在途操作退出。
type Receive = Submit<Recv<Slice<Vec<u8>>, SharedFd<Socket>>>;
type Transmit = Submit<Send<Slice<Vec<u8>>, SharedFd<Socket>>>;

/// 当前发送包之后最多保留一个有界的就绪包。必须先完成当前包的部分写入，再接手下一包，以维持 TCP 字节顺序。空暂存缓冲可跨窗口复用；
/// 普通发送默认释放两份空缓存。
#[derive(Default)]
#[doc(hidden)]
pub struct SendQueue {
    ready: Option<Vec<u8>>,
    committed: usize,
    scratch: Option<Vec<u8>>,
    limit: usize,
    storage: sealed::WindowStorage,
    // 首包借用普通发送缓冲时记录其容量，以便在提交前回收未扩容的缓冲。
    borrowed_completed_capacity: usize,
    #[cfg(feature = "window-cache")]
    cache_policy: WindowSendCache,
}
impl SendQueue {
    pub(crate) fn validate_limit(limit: usize, max_request: usize) -> Result<(), Error> {
        if limit == 0 || limit > max_request {
            return Err(Error::InvalidInput(
                "send queue capacity must fit one connection request bound",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn enable(&mut self, limit: usize, max_request: usize) -> Result<(), Error> {
        self.start(
            limit,
            max_request,
            sealed::WindowStorage::InPlace,
            &mut None,
        )
    }

    /// 原位窗口编码到 ready；独立所有权的组编码到 scratch。两者均按实际编码量增长。
    pub(crate) fn start(
        &mut self,
        limit: usize,
        max_request: usize,
        storage: sealed::WindowStorage,
        completed: &mut Option<Vec<u8>>,
    ) -> Result<(), Error> {
        Self::validate_limit(limit, max_request)?;
        if self.has_data() {
            return Err(Error::Busy);
        }
        if self
            .ready
            .as_ref()
            .is_some_and(|packet| packet.capacity() > limit)
        {
            self.ready.take();
        }
        if self
            .scratch
            .as_ref()
            .is_some_and(|packet| packet.capacity() > limit)
        {
            self.scratch.take();
        }
        if completed
            .as_ref()
            .is_some_and(|packet| packet.capacity() > limit)
        {
            completed.take();
        }
        self.borrowed_completed_capacity = 0;
        match storage {
            sealed::WindowStorage::InPlace => {
                self.borrowed_completed_capacity =
                    Self::prefer_completed(&mut self.ready, completed);
                self.ready.get_or_insert_default().clear();
            }
            sealed::WindowStorage::OwnedPackets => {
                if self.ready.as_ref().map_or(0, Vec::capacity)
                    > self.scratch.as_ref().map_or(0, Vec::capacity)
                {
                    std::mem::swap(&mut self.ready, &mut self.scratch);
                }
                self.borrowed_completed_capacity =
                    Self::prefer_completed(&mut self.scratch, completed);
                self.ready.get_or_insert_default().clear();
            }
        }
        self.storage = storage;
        self.limit = limit;
        Ok(())
    }

    fn prefer_completed(target: &mut Option<Vec<u8>>, completed: &mut Option<Vec<u8>>) -> usize {
        let capacity = completed.as_ref().map_or(0, Vec::capacity);
        if capacity > target.as_ref().map_or(0, Vec::capacity) {
            std::mem::swap(target, completed);
            capacity
        } else {
            0
        }
    }

    pub(crate) fn take_scratch(&mut self) -> Result<Vec<u8>, Error> {
        if self.limit == 0 {
            return Err(Error::InvalidInput("send queue is not enabled"));
        }
        let mut packet = self.scratch.take().unwrap_or_default();
        packet.clear();
        Ok(packet)
    }

    pub(crate) fn recycle_scratch(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        if self.limit == 0 || !packet.is_empty() {
            return Err(Error::InvalidInput(
                "only an empty scratch packet can return to an enabled send queue",
            ));
        }
        if packet.capacity() > self.limit {
            return Err(Error::Limit(
                "send scratch backing exceeds its capacity bound",
            ));
        }
        if self.scratch.is_some() {
            return Err(Error::Busy);
        }
        self.scratch = Some(packet);
        Ok(())
    }
    pub(crate) fn has_data(&self) -> bool {
        self.committed != 0
    }
    pub(crate) fn available(&self) -> usize {
        if self.limit == 0 {
            return 0;
        }
        self.ready
            .as_ref()
            .map_or(0, |ready| self.limit - ready.len())
    }

    /// 将尚未公布的编码追加在已提交前缀之后。编码器中止时，恢复流程只能发送已提交前缀。
    pub(crate) fn staging_buffer(&mut self) -> Result<&mut Vec<u8>, Error> {
        if self.limit == 0 {
            return Err(Error::InvalidInput("send queue is not enabled"));
        }
        self.ready.as_mut().ok_or(Error::Broken)
    }

    pub(crate) fn publish_staged(&mut self) -> Result<(), Error> {
        self.committed = self.staging_buffer()?.len();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn enqueue(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        if self.limit == 0 {
            return Err(Error::InvalidInput("send queue is not enabled"));
        }
        let ready = self
            .ready
            .as_mut()
            .ok_or(Error::InvalidInput("send queue is not enabled"))?;
        if ready.len() != self.committed {
            return Err(Error::Busy);
        }
        if bytes.len() > self.limit {
            return Err(Error::Limit("execution cannot fit the bounded send queue"));
        }
        if bytes.len() > self.limit - ready.len() {
            return Ok(false);
        }
        ready
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Limit("cannot extend the test send queue"))?;
        ready.extend_from_slice(bytes);
        self.committed = ready.len();
        Ok(true)
    }

    pub(crate) fn enqueue_packet(&mut self, packet: &mut Vec<u8>) -> Result<bool, Error> {
        if self.limit == 0 {
            return Err(Error::InvalidInput("send queue is not enabled"));
        }
        if packet.len() > self.limit || packet.capacity() > self.limit {
            return Err(Error::Limit("send packet exceeds its queue capacity bound"));
        }
        if packet.len() > self.available() {
            return Ok(false);
        }
        if Vec::is_empty(packet) {
            return Ok(true);
        }
        let ready = self.ready.as_mut().ok_or(Error::Broken)?;
        if ready.len() != self.committed {
            return Err(Error::Busy);
        }
        if !Vec::is_empty(ready) {
            return Ok(false);
        }
        std::mem::swap(ready, packet);
        self.committed = ready.len();
        self.borrowed_completed_capacity = 0;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::queued_packet_move();
        Ok(true)
    }
    pub(crate) fn next(&mut self, spare: Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
        if !self.has_data() {
            return Err(Error::Broken);
        }
        let ready = self.ready.as_mut().ok_or(Error::Broken)?;
        let mut spare = spare.unwrap_or_default();
        debug_assert!(spare.capacity() <= self.limit);
        spare.clear();
        ready.truncate(self.committed);
        std::mem::swap(ready, &mut spare);
        self.committed = 0;
        self.borrowed_completed_capacity = 0;
        Ok(spare)
    }
    #[cfg(feature = "window-cache")]
    pub(crate) fn cache_policy(&self) -> WindowSendCache {
        self.cache_policy
    }

    #[cfg(feature = "window-cache")]
    pub(crate) fn set_idle_cache_policy(&mut self, policy: WindowSendCache) -> Result<(), Error> {
        if self.limit != 0 || self.has_data() {
            return Err(Error::Busy);
        }
        self.cache_policy = policy;
        self.prune_idle_cache();
        Ok(())
    }

    pub(crate) fn begin_ordinary_send(&mut self) {
        debug_assert!(!self.has_data());
        self.borrowed_completed_capacity = 0;
        self.limit = 0;
        // 普通发送路径没有额外窗口缓冲区时，直接返回，无需核算缓存容量。
        if self.ready.is_none() && self.scratch.is_none() {
            return;
        }
        #[cfg(feature = "window-cache")]
        if matches!(self.cache_policy, WindowSendCache::RetainUntilTrim { .. }) {
            return;
        }
        self.ready = None;
        self.scratch = None;
    }

    #[cfg(feature = "window-cache")]
    fn prune_idle_cache(&mut self) {
        debug_assert_eq!(self.limit, 0);
        let mut remaining = match self.cache_policy {
            WindowSendCache::ReleaseOnOrdinarySend => return,
            WindowSendCache::ReleaseAfterWindow => 0,
            WindowSendCache::RetainUntilTrim { max_retained_bytes } => max_retained_bytes,
        };
        if let Some(ready) = &self.ready {
            if ready.capacity() <= remaining {
                remaining -= ready.capacity();
            } else {
                self.ready = None;
            }
        }
        if self
            .scratch
            .as_ref()
            .is_some_and(|scratch| scratch.capacity() > remaining)
        {
            self.scratch = None;
        }
    }

    pub(crate) fn finish_window(&mut self, completed: &mut Option<Vec<u8>>) -> Result<(), Error> {
        // 输入为空或暂存失败时归还未扩容的借用缓冲；窗口扩容所得的容量按窗口缓存策略处理。
        if self.borrowed_completed_capacity != 0 && !self.has_data() {
            let backing = match self.storage {
                sealed::WindowStorage::OwnedPackets => &mut self.scratch,
                _ => &mut self.ready,
            };
            if let Some(packet) = backing.as_mut()
                && packet.capacity() <= self.borrowed_completed_capacity
            {
                packet.clear();
                std::mem::swap(backing, completed);
            }
            self.borrowed_completed_capacity = 0;
        }
        self.disable()
    }

    pub(crate) fn disable(&mut self) -> Result<(), Error> {
        if self.has_data() {
            return Err(Error::Busy);
        }
        if let Some(ready) = self.ready.as_mut() {
            ready.clear();
        }
        self.limit = 0;
        #[cfg(feature = "window-cache")]
        self.prune_idle_cache();
        Ok(())
    }

    pub(crate) fn retained_capacity(&self) -> Result<usize, Error> {
        self.ready
            .as_ref()
            .map_or(0, Vec::capacity)
            .checked_add(self.scratch.as_ref().map_or(0, Vec::capacity))
            .ok_or(Error::Limit("send queue retained capacity overflow"))
    }

    pub(crate) fn trim_idle_buffers(
        &mut self,
        completed: &mut Option<Vec<u8>>,
    ) -> Result<usize, Error> {
        if self.has_data() {
            return Err(Error::Busy);
        }
        let bytes = self
            .retained_capacity()?
            .checked_add(completed.as_ref().map_or(0, Vec::capacity))
            .ok_or(Error::Limit("retained TX capacity overflow"))?;
        completed.take();
        self.ready.take();
        self.scratch.take();
        self.borrowed_completed_capacity = 0;
        self.limit = 0;
        Ok(bytes)
    }
}

#[cfg(any(target_os = "linux", all(unix, feature = "tls")))]
pub(crate) mod unix_readiness;

mod socket_sealed {
    pub trait Sealed {}
    impl Sealed for compio::net::TcpStream {}
    #[cfg(unix)]
    impl Sealed for compio::net::UnixStream {}
}

/// 完成式传输共用的本地套接字所有权和关闭接口。
#[doc(hidden)]
pub trait NativeStream: socket_sealed::Sealed + ToSharedFd<Socket> + Unpin + 'static {
    fn close_native(self) -> impl Future<Output = io::Result<()>>;
}

impl NativeStream for TcpStream {
    fn close_native(self) -> impl Future<Output = io::Result<()>> {
        self.close()
    }
}

#[cfg(unix)]
impl NativeStream for compio::net::UnixStream {
    fn close_native(self) -> impl Future<Output = io::Result<()>> {
        self.close()
    }
}

/// 独立持有原生操作，单个等待方退出后仍可接着驱动。
pub struct Transport<S: NativeStream = TcpStream> {
    socket: S,
    owner: IoOwner,
    receive: Option<Receive>,
    transmit: Option<Transmit>,
    read_buffer: Option<Vec<u8>>,
    write_buffer: Option<Vec<u8>>,
    read_start: usize,
    read_end: usize,
    frame_cache: FrameCache,
    write_offset: usize,
    write_end: usize,
    max_frame_len: usize,
    max_request_len: usize,
    poisoned: bool,
    send_policy: SendPolicy,
    send_queue: SendQueue,
}

impl<S: NativeStream> Transport<S> {
    pub(crate) fn new(
        socket: S,
        receive_capacity: usize,
        max_frame_len: usize,
        max_request_len: usize,
    ) -> Result<Self, Error> {
        let read_buffer = new_receive_buffer(receive_capacity, max_frame_len, max_request_len)?;
        Ok(Self {
            socket,
            owner: IoOwner::current(),
            receive: None,
            transmit: None,
            read_buffer: Some(read_buffer),
            write_buffer: None,
            read_start: 0,
            read_end: 0,
            frame_cache: FrameCache::default(),
            write_offset: 0,
            write_end: 0,
            max_frame_len,
            max_request_len,
            poisoned: false,
            send_policy: SendPolicy::BeforeBufferedRead,
            send_queue: SendQueue::default(),
        })
    }

    pub(crate) fn is_broken(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn set_send_policy(&mut self, policy: SendPolicy) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        self.send_policy = policy;
        Ok(())
    }

    pub(crate) fn break_connection(&mut self) {
        self.poisoned = true;
    }

    /// 接手发送包后可立即返回。接收响应时也会推进这次发送。
    pub(crate) fn begin_send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        if bytes.is_empty() || bytes.len() > self.max_request_len {
            return Err(Error::Limit(
                "the encoded request exceeds its configured limit",
            ));
        }
        self.send_queue.begin_ordinary_send();
        self.write_offset = 0;
        self.write_end = bytes.len();
        self.write_buffer = Some(bytes);
        Ok(())
    }

    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_send_with_queue::<true>(cx, &mut false)
    }

    fn poll_send_with_queue<const PROMOTE_QUEUE: bool>(
        &mut self,
        cx: &mut Context<'_>,
        owner_checked: &mut bool,
    ) -> Poll<Result<(), Error>> {
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::native_send_poll();
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        if self.write_offset != self.write_end || (PROMOTE_QUEUE && self.send_queue.has_data()) {
            self.owner.check_once(owner_checked)?;
        }
        loop {
            if self.write_offset == self.write_end {
                // 完成事件会先移除在途操作，再推进写游标至包尾。
                debug_assert!(self.transmit.is_none());
                if !PROMOTE_QUEUE || !self.send_queue.has_data() {
                    return Poll::Ready(Ok(()));
                }
                self.poisoned = true;
                let next = self.send_queue.next(self.write_buffer.take())?;
                self.write_offset = 0;
                self.write_end = next.len();
                self.write_buffer = Some(next);
                self.poisoned = false;
            }
            // 创建和轮询 Submit 均可能进入 runtime。转移所有权期间保留故障标记。
            self.poisoned = true;
            if self.transmit.is_none() {
                let Some(buffer) = self.write_buffer.take() else {
                    return Poll::Ready(Err(Error::Broken));
                };
                let flags = send_flags();
                let operation = Send::new(
                    self.socket.to_shared_fd(),
                    buffer.slice(self.write_offset..self.write_end),
                    flags,
                );
                self.transmit = Some(submit(operation));
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::send_attempt();
            }
            // runtime 或 waker 回调 panic 时必须保留故障标记，以防继续复用状态未知的连接。
            let Some(operation) = self.transmit.as_mut() else {
                return Poll::Ready(Err(Error::Broken));
            };
            let completed = match Pin::new(operation).poll(cx) {
                Poll::Pending => {
                    #[cfg(feature = "diagnostics")]
                    crate::diagnostics::native_send_pending_poll();
                    self.poisoned = false;
                    return Poll::Pending;
                }
                Poll::Ready(result) => result,
            };
            let BufResult(result, operation) = completed;
            self.transmit.take();
            let count = match result {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "PostgreSQL socket returned a zero-length write",
                    )
                    .into()));
                }
                Ok(count) if count <= self.write_end - self.write_offset => count,
                Ok(_) => {
                    return Poll::Ready(Err(Error::InvalidInput(
                        "the transport returned an invalid write length",
                    )));
                }
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && !error.is_cancelled() =>
                {
                    self.write_buffer = Some(operation.into_inner().into_inner());
                    self.poisoned = false;
                    continue;
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            self.write_offset += count;
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::sent(count);
            let buffer = operation.into_inner().into_inner();
            // 最多保留一份已完成且容量合规的发送包，超限存储在原生操作完成后释放。
            self.write_buffer = if self.write_offset == self.write_end
                && buffer.capacity() > self.max_request_len
            {
                None
            } else {
                Some(buffer)
            };
            self.poisoned = false;
        }
    }

    #[cfg(test)]
    pub(crate) async fn receive_frame(&mut self) -> Result<(), Error> {
        poll_fn(|cx| self.poll_frame(cx, false)).await
    }

    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        mut owner_checked: bool,
    ) -> Poll<Result<(), Error>> {
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::native_frame_poll();
        loop {
            if self.poisoned {
                return Poll::Ready(Err(Error::Broken));
            }
            let queued = self.send_queue.has_data();
            let sending = self.write_offset != self.write_end || queued;
            let coalescing = queued && self.send_policy == SendPolicy::CoalesceBuffered;
            // 在途发送仍持有非空后缀，读写游标相等且队列为空时无需轮询发送。
            if sending {
                if coalescing && self.frame_range()?.is_some() {
                    // 只收回当前发送操作，不启动下一排队包。
                    if let Poll::Ready(Err(error)) =
                        self.poll_send_with_queue::<false>(cx, &mut owner_checked)
                    {
                        return Poll::Ready(Err(error));
                    }
                    return Poll::Ready(Ok(()));
                }
                // 发送受背压时仍推进接收，任一方向的进展都可能解除对端阻塞。
                if let Poll::Ready(Err(error)) =
                    self.poll_send_with_queue::<true>(cx, &mut owner_checked)
                {
                    return Poll::Ready(Err(error));
                }
            }
            if !coalescing && self.frame_range()?.is_some() {
                return Poll::Ready(Ok(()));
            }
            // 发送、接收和处理分片都使用同一次轮询的归属检查。
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::native_receive_poll();
            self.owner.check_once(&mut owner_checked)?;
            match self.poll_receive_on_owner(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn frame_range(&mut self) -> Result<Option<FrameExtent>, Error> {
        let Some(buffer) = self.read_buffer.as_ref() else {
            return Ok(None);
        };
        match self
            .frame_cache
            .parse(buffer, self.read_start, self.read_end, self.max_frame_len)
        {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.poisoned = true;
                self.frame_cache.clear();
                Err(error.into())
            }
        }
    }

    pub(crate) fn frame(&mut self) -> Result<Frame<'_>, Error> {
        self.frame_cache.borrow(
            self.read_buffer.as_deref().unwrap_or_default(),
            self.read_start,
            self.read_end,
            self.poisoned,
        )
    }

    pub(crate) fn consume_frame(&mut self) -> Result<(), Error> {
        self.frame_cache
            .consume(&mut self.read_start, self.read_end, self.poisoned)
    }

    fn poll_receive_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        self.poisoned = true;
        if self.receive.is_none() {
            let Some(mut buffer) = self.read_buffer.take() else {
                return Poll::Ready(Err(Error::Broken));
            };
            prepare_receive_buffer(
                &mut buffer,
                &mut self.read_start,
                &mut self.read_end,
                &mut self.frame_cache,
                self.max_frame_len,
            )?;
            if self.read_end == buffer.len() {
                self.read_buffer = Some(buffer);
                return Poll::Ready(Err(Error::Limit(
                    "the receive buffer cannot hold this frame",
                )));
            }
            let end = buffer.len();
            let operation = Recv::new(
                self.socket.to_shared_fd(),
                buffer.slice(self.read_end..end),
                RecvFlags::empty(),
            );
            self.receive = Some(submit(operation));
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::receive_attempt();
        }
        let Some(operation) = self.receive.as_mut() else {
            return Poll::Ready(Err(Error::Broken));
        };
        let completed = match Pin::new(operation).poll(cx) {
            Poll::Pending => {
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::native_receive_pending_poll();
                self.poisoned = false;
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };
        let BufResult(result, operation) = completed;
        self.receive.take();
        let count = match result {
            Ok(0) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "PostgreSQL closed the connection before the protocol boundary",
                )
                .into()));
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && !error.is_cancelled() => {
                self.read_buffer = Some(operation.into_inner().into_inner());
                self.poisoned = false;
                return Poll::Ready(Ok(()));
            }
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        let buffer = operation.into_inner().into_inner();
        let capacity = buffer.len() - self.read_end;
        if count > capacity {
            return Poll::Ready(Err(Error::InvalidInput(
                "the transport returned an invalid receive length",
            )));
        }
        self.read_end += count;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::received(count);
        self.read_buffer = Some(buffer);
        self.poisoned = false;
        Poll::Ready(Ok(()))
    }
}

pub(crate) mod sealed {
    use super::WireOps;

    // 公开泛型仅约束传输类型，协议操作由会话持有的关联类型提供。
    pub trait Backend {
        type Io: WireOps;
    }

    impl<T: WireOps> Backend for T {
        type Io = T;
    }

    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    pub enum WindowStorage {
        #[default]
        InPlace,
        OwnedPackets,
    }

    pub enum CopyOutFrame {
        /// 控制帧仍可通过 frame 借用，调用方负责消费。
        Control,
        /// 已消费的 CopyData 载荷字节数。
        Data(usize),
    }

    /// 处理已经校验长度并获准接收的 CopyData。错误由接收方保留，直到帧接收完成。
    pub trait CopyDataSink {
        fn begin(&mut self, payload_len: usize);
        fn append(&mut self, bytes: &[u8]);
    }

    impl CopyDataSink for () {
        fn begin(&mut self, _payload_len: usize) {}
        fn append(&mut self, _bytes: &[u8]) {}
    }
}

/// 由驱动提供的传输类型，可用于编写 TCP、Unix 套接字和 TLS 通用的客户端代码。
pub trait WireTransport: sealed::Backend {}

impl<T: WireOps> WireTransport for T {}

/// 会话独占的协议 I/O，按传输类型静态派发。
pub trait WireOps {
    fn owner_waker(&self) -> Option<&Waker>;

    fn start_window_send_queue(
        &mut self,
        _bytes: usize,
        _storage: sealed::WindowStorage,
    ) -> Result<(), Error> {
        Err(Error::Broken)
    }

    fn window_send_queue(&mut self) -> Result<&mut SendQueue, Error> {
        Err(Error::Broken)
    }

    fn send_policy(&self) -> SendPolicy {
        SendPolicy::BeforeBufferedRead
    }
    fn set_send_policy(&mut self, _policy: SendPolicy) -> Result<(), Error> {
        Err(Error::Unsupported(
            "this transport has no selectable send policy",
        ))
    }
    #[cfg(feature = "window-cache")]
    fn window_send_cache(&self) -> WindowSendCache {
        WindowSendCache::default()
    }
    #[cfg(feature = "window-cache")]
    fn set_window_send_cache(&mut self, _policy: WindowSendCache) -> Result<(), Error> {
        Err(Error::Unsupported(
            "this transport has no selectable window send cache",
        ))
    }
    fn is_broken(&self) -> bool;
    fn break_connection(&mut self);
    fn begin_send(&mut self, bytes: Vec<u8>) -> Result<(), Error>;
    /// 取出最后完成的发送缓冲供有界复用。在途操作仍持有原缓冲时返回错误。
    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error>;
    fn take_send_buffer(&mut self) -> Result<Vec<u8>, Error> {
        let mut buffer = self.take_send_packet()?;
        buffer.clear();
        Ok(buffer)
    }
    /// 所有成员编码成功后才移交发送包。若本地预检失败，清除私有前缀并交还已借出的缓冲。
    fn encode_send_buffer(
        &mut self,
        encode: impl FnOnce(&mut Vec<u8>) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let mut buffer = self.take_send_buffer()?;
        if let Err(error) = encode(&mut buffer) {
            buffer.clear();
            self.retain_unused_send_buffer(buffer);
            return Err(error);
        }
        Ok(buffer)
    }

    /// 本地编码失败或放弃尚未绑定的 portal 时，归还已清空且尚未提交的发送缓冲。
    fn retain_unused_send_buffer(&mut self, _buffer: Vec<u8>) {}

    /// 启动分组发送队列并借出空暂存包，编码时按需增长。
    fn start_send_queue(&mut self, bytes: usize) -> Result<Vec<u8>, Error> {
        self.start_window_send_queue(bytes, sealed::WindowStorage::OwnedPackets)?;
        self.window_send_queue()?.take_scratch()
    }
    #[cfg(test)]
    fn enable_send_queue(&mut self, bytes: usize) -> Result<(), Error> {
        self.start_window_send_queue(bytes, sealed::WindowStorage::InPlace)
    }
    fn send_queue_available(&self) -> usize;
    #[cfg(test)]
    fn enqueue_send(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        self.window_send_queue()?.enqueue(bytes)
    }
    /// 移交有界的完整数据包。就绪槽已占用时保留调用方的包。
    fn enqueue_send_packet(&mut self, packet: &mut Vec<u8>) -> Result<bool, Error> {
        self.window_send_queue()?.enqueue_packet(packet)
    }
    /// 空暂存缓冲可以跨窗口复用。
    fn recycle_send_queue_buffer(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        self.window_send_queue()?.recycle_scratch(packet)
    }
    /// 发送队列排空后关闭接纳，具体传输按策略保留空窗口缓冲区。
    fn disable_send_queue(&mut self) -> Result<(), Error>;
    /// 具有额外空闲缓存的传输需要一并释放这些缓存。
    fn trim_send_buffers(&mut self) -> Result<usize, Error> {
        let packet = self.take_send_packet()?;
        self.disable_send_queue()?;
        Ok(packet.capacity())
    }
    fn poll_finish_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>>;
    fn poll_receive_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>>;
    /// 调用方已在本次同步轮询中验证该连接的 runtime 归属。
    fn poll_finish_send_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_finish_send(cx)
    }
    /// 调用方已在本次同步轮询中验证该连接的 runtime 归属。
    fn poll_receive_frame_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_receive_frame(cx)
    }
    /// 接收 COPY OUT 帧。仅在协议允许接收 CopyData 时调用。
    /// 重建已部分收取数据的等待方时，从原位置继续，只可丢弃剩余数据。
    fn poll_copy_out_frame_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        sink: &mut impl sealed::CopyDataSink,
    ) -> Poll<Result<sealed::CopyOutFrame, Error>> {
        std::task::ready!(self.poll_receive_frame_on_owner(cx))?;
        Poll::Ready(self.consume_ready_copy_out_frame(sink))
    }

    fn consume_ready_copy_out_frame(
        &mut self,
        sink: &mut impl sealed::CopyDataSink,
    ) -> Result<sealed::CopyOutFrame, Error> {
        let frame = self.frame()?;
        if frame.tag != b'd' {
            return Ok(sealed::CopyOutFrame::Control);
        }
        let len = frame.body.len();
        sink.begin(len);
        if len != 0 {
            sink.append(frame.body);
        }
        self.consume_frame()?;
        Ok(sealed::CopyOutFrame::Data(len))
    }
    /// 推进双向 I/O，同时报告本地发送是否已完成。
    /// 调用方已验证本次轮询的位置。`stop_when_sent` 允许尾帧发送在接收前继续。
    fn poll_receive_frame_with_send_status_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        stop_when_sent: bool,
    ) -> Result<(Poll<()>, bool), Error> {
        let sent = self.poll_finish_send_on_owner(cx)?.is_ready();
        if sent && stop_when_sent {
            return Ok((Poll::Pending, true));
        }
        let received = self.poll_receive_frame_on_owner(cx)?;
        let sent =
            sent || (received.is_pending() && self.poll_finish_send_on_owner(cx)?.is_ready());
        Ok((received, sent))
    }
    /// 接收轮询就绪后，可借用已校验边界的帧，直至调用 `consume_frame`。
    fn frame(&mut self) -> Result<Frame<'_>, Error>;
    fn consume_frame(&mut self) -> Result<(), Error>;
    fn close(self) -> impl Future<Output = Result<(), Error>>
    where
        Self: Sized;
}

impl<S: NativeStream> WireOps for Transport<S> {
    fn owner_waker(&self) -> Option<&Waker> {
        self.owner.waker()
    }

    fn start_window_send_queue(
        &mut self,
        bytes: usize,
        storage: sealed::WindowStorage,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        self.send_queue
            .start(bytes, self.max_request_len, storage, &mut self.write_buffer)
    }

    fn window_send_queue(&mut self) -> Result<&mut SendQueue, Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        Ok(&mut self.send_queue)
    }

    fn send_policy(&self) -> SendPolicy {
        self.send_policy
    }
    fn set_send_policy(&mut self, policy: SendPolicy) -> Result<(), Error> {
        self.set_send_policy(policy)
    }
    #[cfg(feature = "window-cache")]
    fn window_send_cache(&self) -> WindowSendCache {
        self.send_queue.cache_policy()
    }

    #[cfg(feature = "window-cache")]
    fn set_window_send_cache(&mut self, policy: WindowSendCache) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end {
            return Err(Error::Busy);
        }
        self.send_queue.set_idle_cache_policy(policy)
    }

    fn is_broken(&self) -> bool {
        self.is_broken()
    }
    fn break_connection(&mut self) {
        self.break_connection();
    }
    fn begin_send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.begin_send(bytes)
    }
    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        Ok(self.write_buffer.take().unwrap_or_default())
    }
    fn retain_unused_send_buffer(&mut self, buffer: Vec<u8>) {
        if buffer.capacity() <= self.max_request_len {
            self.write_buffer = Some(buffer);
        }
    }

    fn send_queue_available(&self) -> usize {
        self.send_queue.available()
    }
    fn disable_send_queue(&mut self) -> Result<(), Error> {
        self.send_queue.finish_window(&mut self.write_buffer)
    }
    fn trim_send_buffers(&mut self) -> Result<usize, Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end {
            return Err(Error::Busy);
        }
        self.send_queue.trim_idle_buffers(&mut self.write_buffer)
    }
    fn poll_finish_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_send(cx)
    }
    fn poll_receive_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_frame(cx, false)
    }
    fn poll_finish_send_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_send_with_queue::<true>(cx, &mut true)
    }
    fn poll_receive_frame_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_frame(cx, true)
    }
    fn poll_receive_frame_with_send_status_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        stop_when_sent: bool,
    ) -> Result<(Poll<()>, bool), Error> {
        let sent = |transport: &Self| {
            transport.write_offset == transport.write_end && !transport.send_queue.has_data()
        };
        if stop_when_sent && sent(self) {
            return if self.poisoned {
                Err(Error::Broken)
            } else {
                Ok((Poll::Pending, true))
            };
        }
        let received = self.poll_frame(cx, true)?;
        Ok((received, sent(self)))
    }
    fn frame(&mut self) -> Result<Frame<'_>, Error> {
        self.frame()
    }
    fn consume_frame(&mut self) -> Result<(), Error> {
        self.consume_frame()
    }
    async fn close(self) -> Result<(), Error> {
        let Self {
            socket,
            receive,
            transmit,
            ..
        } = self;
        drop(receive);
        drop(transmit);
        socket.close_native().await?;
        Ok(())
    }
}

pub(crate) trait TransportExt: WireOps {
    async fn send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.begin_send(bytes)?;
        poll_fn(|cx| self.poll_finish_send(cx)).await
    }
    #[cfg(test)]
    fn finish_send(&mut self) -> impl Future<Output = Result<(), Error>> {
        poll_fn(|cx| self.poll_finish_send(cx))
    }
    fn receive_frame(&mut self) -> impl Future<Output = Result<(), Error>> {
        poll_fn(|cx| self.poll_receive_frame(cx))
    }
    fn finish_send_on_owner(&mut self) -> impl Future<Output = Result<(), Error>> {
        self.wait_io_on_owner(Self::poll_finish_send_on_owner)
    }
    fn receive_frame_on_owner(&mut self) -> impl Future<Output = Result<(), Error>> {
        self.wait_io_on_owner(Self::poll_receive_frame_on_owner)
    }
    /// 首次轮询沿用调用方的归属验证，从 Pending 恢复时验证后再继续这个 I/O。
    fn wait_io_on_owner(
        &mut self,
        poll_io: impl Fn(&mut Self, &mut Context<'_>) -> Poll<Result<(), Error>>,
    ) -> impl Future<Output = Result<(), Error>> {
        let mut suspended = false;
        poll_fn(move |cx| {
            if suspended {
                IoOwner::check_waker(self.owner_waker())?;
            }
            let result = poll_io(self, cx);
            suspended = result.is_pending();
            result
        })
    }
}

impl<T: WireOps> TransportExt for T {}

pub(crate) const fn send_flags() -> SendFlags {
    cfg_select! {
        // Apple 套接字由 Compio 设置 SO_NOSIGPIPE。其余分支沿用 rustix 的标志可用范围。
        any(target_vendor = "apple", windows, target_os = "redox", target_os = "vita") => {
            SendFlags::empty()
        }
        _ => {
            SendFlags::NOSIGNAL
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        io::{self, Read, Write},
        net::{TcpListener, TcpStream as StdTcpStream},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        task::Poll,
        thread,
        time::{Duration, Instant},
    };

    use compio::{driver::ToSharedFd, net::TcpStream, runtime::Runtime, time::timeout};

    use super::{SendPolicy, SendQueue, Transport, TransportExt, WireOps};
    use crate::Error;

    fn pair(runtime: &Runtime, capacity: usize) -> (Transport, StdTcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test socket");
        let socket = StdTcpStream::connect(listener.local_addr().expect("test address"))
            .expect("connect test socket");
        let (peer, _) = listener.accept().expect("accept test socket");
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set test read timeout");
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set test write timeout");
        let transport = runtime.block_on(async {
            Transport::new(
                TcpStream::from_std(socket).expect("attach test socket"),
                capacity,
                capacity - 1,
                128,
            )
            .expect("create test transport")
        });
        (transport, peer)
    }

    #[test]
    fn rejected_packet_encoding_keeps_the_retired_allocation_and_drops_the_private_prefix() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let mut packet = Vec::with_capacity(128);
            packet.extend_from_slice(b"first");
            let backing = packet.as_ptr();
            transport.begin_send(packet).unwrap();
            assert!(matches!(
                transport.encode_send_buffer(|_| panic!("send is in flight")),
                Err(Error::Busy)
            ));
            transport.finish_send().await.unwrap();
            let rejected = transport.encode_send_buffer(|packet| {
                assert_eq!(packet.as_ptr(), backing);
                packet.extend_from_slice(b"rejected prefix");
                Err(Error::InvalidInput("bad next member"))
            });
            assert!(matches!(
                rejected,
                Err(Error::InvalidInput("bad next member"))
            ));
            let next = transport
                .encode_send_buffer(|packet| {
                    assert!(packet.is_empty());
                    assert_eq!(packet.as_ptr(), backing);
                    packet.extend_from_slice(b"next");
                    Ok(())
                })
                .unwrap();
            transport.begin_send(next).unwrap();
            transport.finish_send().await.unwrap();
            transport.close().await.unwrap();
        });
        let mut sent = Vec::new();
        peer.read_to_end(&mut sent).unwrap();
        assert_eq!(sent, b"firstnext");
    }

    #[test]
    fn coalescing_rejects_an_invalid_buffered_header_before_promoting_queued_sql() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            transport.read_buffer.as_mut().unwrap()[..5].copy_from_slice(b"Z\0\0\0\x03");
            transport.read_end = 5;
            WireOps::set_send_policy(&mut transport, SendPolicy::CoalesceBuffered).unwrap();
            transport.enable_send_queue(64).unwrap();
            assert!(transport.enqueue_send(b"request").unwrap());
            assert!(matches!(
                crate::transport::TransportExt::receive_frame(&mut transport).await,
                Err(crate::Error::Protocol(
                    crate::protocol::ProtocolError::InvalidLength(3)
                ))
            ));
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn receive_preparation_moves_only_frames_that_cannot_fit_in_place() {
        let suffix = [b'D', 0, 0, 0, 12, 1, 2, 3];
        let mut room = vec![0; 32];
        room[8..16].copy_from_slice(&suffix);
        let mut tight = vec![0; 20];
        tight[8..16].copy_from_slice(&suffix);
        let (mut room_start, mut room_end) = (8, 16);
        let (mut tight_start, mut tight_end) = (8, 16);
        let mut cache = super::FrameCache::default();
        #[cfg(feature = "diagnostics")]
        let before = crate::diagnostics::snapshot();
        assert!(
            cache
                .parse(&room, room_start, room_end, 31)
                .unwrap()
                .is_none()
        );
        super::prepare_receive_buffer(&mut room, &mut room_start, &mut room_end, &mut cache, 31)
            .unwrap();
        assert_eq!(cache.extent.end, 21);
        cache.clear();
        assert!(cache.parse(&tight, 8, 16, 19).unwrap().is_none());
        super::prepare_receive_buffer(&mut tight, &mut tight_start, &mut tight_end, &mut cache, 19)
            .unwrap();
        assert_eq!((room_start, room_end), (8, 16));
        assert_eq!(&room[8..16], &suffix);
        assert_eq!((tight_start, tight_end), (0, 8));
        assert_eq!(&tight[..8], &suffix);
        assert_eq!(cache.extent.end, 13);
        assert!(cache.parse(&tight, 0, 12, 19).unwrap().is_none());
        let complete = cache.parse(&tight, 0, 13, 19).unwrap().unwrap();
        assert_eq!((complete.tag, complete.end), (b'D', 13));
        #[cfg(feature = "diagnostics")]
        {
            let counters = crate::diagnostics::snapshot().delta(before).unwrap();
            assert_eq!(counters.rx_suffix_bytes_compacted, 8);
            assert_eq!(counters.rx_compactions_skipped, 1);
            assert_eq!(counters.rx_suffix_bytes_retained_in_place, 8);
        }
    }

    #[test]
    fn receive_growth_checks_the_frame_limit_and_keeps_only_the_unconsumed_prefix() {
        let mut bytes = Vec::from(*b"abcD\0\0\0\x0cx");
        let (mut start, mut end) = (3, bytes.len());
        let mut cache = super::FrameCache::default();
        assert!(matches!(
            cache.parse(&bytes, start, end, 11),
            Err(crate::protocol::ProtocolError::FrameTooLarge { .. })
        ));
        assert_eq!((start, end, bytes.len()), (3, 9, 9));
        assert!(cache.parse(&bytes, start, end, 12).unwrap().is_none());
        super::prepare_receive_buffer(&mut bytes, &mut start, &mut end, &mut cache, 12).unwrap();
        assert_eq!((start, end, bytes.len()), (0, 6, 13));
        assert_eq!(&bytes[..end], b"D\0\0\0\x0cx");
    }

    #[test]
    fn receive_growth_is_ready_for_the_whole_frame_before_reading_its_body() {
        let mut buffer = vec![0; 8];
        buffer[..5].copy_from_slice(b"D\0\0\0\x0c");
        let (mut start, mut end) = (0, 5);
        let mut cache = super::FrameCache::default();
        assert!(cache.parse(&buffer, start, end, 12).unwrap().is_none());
        super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, 12).unwrap();
        assert_eq!((start, end, buffer.len()), (0, 5, 13));
        assert_eq!(&buffer[..end], b"D\0\0\0\x0c");
    }

    #[test]
    fn increasing_frame_sizes_reuse_spare_capacity_after_compaction() {
        const LIMIT: usize = 35;
        let mut buffer = vec![0; 24];
        buffer[..7].copy_from_slice(b"D\0\0\0\x18ab");
        let (mut start, mut end) = (0, 7);
        let mut cache = super::FrameCache::default();
        assert!(cache.parse(&buffer, start, end, LIMIT).unwrap().is_none());
        super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, LIMIT)
            .unwrap();
        assert_eq!(buffer.len(), 25);
        let capacity = buffer.capacity();
        let backing = buffer.as_ptr();
        assert!(capacity > buffer.len());

        for wire_len in [25_u8, 30, 35] {
            let prefix = [b'D', 0, 0, 0, wire_len, b'a', b'b'];
            end = buffer.len();
            start = end - prefix.len();
            buffer[start..end].copy_from_slice(&prefix);
            cache.clear();
            assert!(cache.parse(&buffer, start, end, LIMIT).unwrap().is_none());
            super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, LIMIT)
                .unwrap();
            assert_eq!((start, end), (0, prefix.len()));
            assert_eq!(&buffer[..end], &prefix);
            assert_eq!(buffer.len(), usize::from(wire_len) + 1);
            assert_eq!(cache.extent.end, buffer.len());
            assert_eq!(buffer.capacity(), capacity);
            assert_eq!(buffer.as_ptr(), backing);
        }
    }

    #[test]
    fn receive_preparation_handles_split_headers_empty_buffers_and_maximum_frames() {
        let mut cache = super::FrameCache::default();
        for header_bytes in 1..5 {
            let mut buffer = vec![0; 16];
            let start = buffer.len() - header_bytes;
            buffer[start..].copy_from_slice(&b"D\0\0\0\x0f"[..header_bytes]);
            let (mut start, mut end) = (start, buffer.len());
            assert!(cache.parse(&buffer, start, end, 15).unwrap().is_none());
            super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, 15)
                .unwrap();
            assert_eq!((start, end), (0, header_bytes));
            assert_eq!(&buffer[..header_bytes], &b"D\0\0\0\x0f"[..header_bytes]);
        }
        let mut buffer = vec![0; 16];
        buffer[6..11].copy_from_slice(b"D\0\0\0\x0f");
        let (mut start, mut end) = (6, 11);
        assert!(cache.parse(&buffer, start, end, 15).unwrap().is_none());
        super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, 15).unwrap();
        assert_eq!((start, end), (0, 5));
        assert_eq!(&buffer[..5], b"D\0\0\0\x0f");
        cache.clear();
        (start, end) = (16, 16);
        assert!(cache.parse(&buffer, start, end, 15).unwrap().is_none());
        super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, 15).unwrap();
        assert_eq!((start, end), (0, 0));
        buffer[6..10].copy_from_slice(b"D\0\0\0");
        (start, end) = (6, 10);
        assert!(cache.parse(&buffer, start, end, 15).unwrap().is_none());
        super::prepare_receive_buffer(&mut buffer, &mut start, &mut end, &mut cache, 15).unwrap();
        assert_eq!((start, end), (6, 10));
    }

    fn receive(runtime: &Runtime, transport: &mut Transport) -> Result<(), Error> {
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.receive_frame())
                .await
                .expect("receive must finish before the test deadline")
        })
    }

    #[test]
    fn changing_send_policy_preserves_busy_bytes_and_idle_backing() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        assert_eq!(transport.send_policy, SendPolicy::BeforeBufferedRead);
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        assert_eq!(transport.send_policy, SendPolicy::CoalesceBuffered);
        transport.begin_send(b"current".to_vec()).unwrap();
        let current_pointer = transport.write_buffer.as_ref().unwrap().as_ptr();
        assert!(matches!(
            transport.set_send_policy(SendPolicy::BeforeBufferedRead),
            Err(Error::Busy)
        ));
        assert_eq!(transport.send_policy, SendPolicy::CoalesceBuffered);
        assert_eq!(transport.write_offset, 0);
        assert_eq!(transport.write_end, b"current".len());
        assert_eq!(transport.write_buffer.as_ref().unwrap(), b"current");
        assert_eq!(
            transport.write_buffer.as_ref().unwrap().as_ptr(),
            current_pointer
        );
        transport.send_queue.enable(64, 128).unwrap();
        assert!(transport.send_queue.enqueue(b"queued").unwrap());
        let queued_pointer = transport.send_queue.ready.as_ref().unwrap().as_ptr();
        assert!(matches!(
            transport.set_send_policy(SendPolicy::BeforeBufferedRead),
            Err(Error::Busy)
        ));
        assert_eq!(transport.send_policy, SendPolicy::CoalesceBuffered);
        assert_eq!(transport.send_queue.limit, 64);
        assert_eq!(transport.send_queue.ready.as_ref().unwrap(), b"queued");
        assert_eq!(
            transport.send_queue.ready.as_ref().unwrap().as_ptr(),
            queued_pointer
        );
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut received = [0; 13];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"currentqueued");
        let current_pointer = transport.write_buffer.as_ref().unwrap().as_ptr();
        let queued_pointer = transport.send_queue.ready.as_ref().unwrap().as_ptr();
        let retained = transport.send_queue.retained_capacity().unwrap();
        transport
            .set_send_policy(SendPolicy::BeforeBufferedRead)
            .unwrap();
        assert_eq!(transport.send_policy, SendPolicy::BeforeBufferedRead);
        assert_eq!(transport.send_queue.limit, 64);
        assert_eq!(
            transport.write_buffer.as_ref().unwrap().as_ptr(),
            current_pointer
        );
        assert_eq!(
            transport.send_queue.ready.as_ref().unwrap().as_ptr(),
            queued_pointer
        );
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), retained);
        transport.break_connection();
        assert!(matches!(
            transport.set_send_policy(SendPolicy::CoalesceBuffered),
            Err(Error::Broken)
        ));
        assert_eq!(transport.send_policy, SendPolicy::BeforeBufferedRead);
    }

    #[test]
    fn staged_bytes_share_the_ready_backing_and_recovery_sends_only_committed_bytes() {
        let mut queue = SendQueue::default();
        let mut completed = Some(Vec::with_capacity(32));
        queue
            .start(
                32,
                64,
                super::sealed::WindowStorage::InPlace,
                &mut completed,
            )
            .unwrap();
        let pointer = queue.staging_buffer().unwrap().as_ptr();
        queue.staging_buffer().unwrap().extend_from_slice(b"first");
        assert!(!queue.has_data());
        queue.publish_staged().unwrap();
        queue.staging_buffer().unwrap().extend_from_slice(b"second");
        assert_eq!(queue.staging_buffer().unwrap().as_ptr(), pointer);
        queue.publish_staged().unwrap();
        queue
            .staging_buffer()
            .unwrap()
            .extend_from_slice(b"private");

        let packet = queue.next(None).unwrap();
        assert_eq!(packet.as_ptr(), pointer);
        assert_eq!(packet, b"firstsecond");
        assert_eq!(queue.available(), 32);
        queue.staging_buffer().unwrap().extend_from_slice(b"orphan");
        queue.disable().unwrap();
        queue.enable(32, 64).unwrap();
        assert!(!queue.has_data());
        assert!(queue.staging_buffer().unwrap().is_empty());
    }

    #[test]
    fn small_in_place_windows_reuse_the_last_send_without_reserving_the_byte_limit() {
        let mut queue = SendQueue::default();
        let mut completed = Some(Vec::with_capacity(128));
        let original = completed.as_ref().unwrap().as_ptr();
        for _ in 0..3 {
            queue
                .start(
                    65536,
                    65536,
                    super::sealed::WindowStorage::InPlace,
                    &mut completed,
                )
                .unwrap();
            let ready = queue.staging_buffer().unwrap();
            assert_eq!(ready.as_ptr(), original);
            ready.extend_from_slice(b"Bind Execute Sync");
            queue.publish_staged().unwrap();
            completed = Some(queue.next(completed.take()).unwrap());
            assert_eq!(completed.as_ref().unwrap().as_ptr(), original);
            assert_eq!(completed.as_deref().unwrap(), b"Bind Execute Sync");
            assert_eq!(queue.retained_capacity().unwrap(), 0);
            queue.disable().unwrap();
            queue.begin_ordinary_send();
            let packet = completed.as_mut().unwrap();
            packet.clear();
            packet.extend_from_slice(b"direct");
        }
        queue
            .start(
                64,
                65536,
                super::sealed::WindowStorage::InPlace,
                &mut completed,
            )
            .unwrap();
        assert_eq!(queue.retained_capacity().unwrap(), 0);
        assert!(completed.is_none());
    }

    #[test]
    fn empty_and_unpublished_windows_return_the_ordinary_backing() {
        let mut completed = Some(vec![1; 128]);
        let pointer = completed.as_ref().unwrap().as_ptr();
        let mut queue = SendQueue::default();
        for suffix in [&b""[..], &b"unpublished"[..]] {
            queue
                .start(
                    8192,
                    8192,
                    super::sealed::WindowStorage::InPlace,
                    &mut completed,
                )
                .unwrap();
            queue.staging_buffer().unwrap().extend_from_slice(suffix);
            queue.finish_window(&mut completed).unwrap();
            queue.begin_ordinary_send();
            let packet = completed.as_ref().unwrap();
            assert_eq!(packet.as_ptr(), pointer);
            assert!(packet.is_empty());
            assert!(!queue.has_data());
            assert_eq!(queue.retained_capacity().unwrap(), 0);
        }
    }

    #[cfg(feature = "window-cache")]
    #[test]
    fn unpublished_growth_stays_under_the_window_retention_policy() {
        use super::WindowSendCache::{ReleaseAfterWindow, ReleaseOnOrdinarySend, RetainUntilTrim};

        const PAYLOAD: usize = 64 * 1024;
        const WINDOW: usize = 1024 * 1024;
        for (policy, keep_after_window, keep_after_ordinary) in [
            (ReleaseAfterWindow, false, false),
            (ReleaseOnOrdinarySend, true, false),
            (
                RetainUntilTrim {
                    max_retained_bytes: 128,
                },
                false,
                false,
            ),
            (
                RetainUntilTrim {
                    max_retained_bytes: WINDOW,
                },
                true,
                true,
            ),
        ] {
            let mut queue = SendQueue::default();
            let mut completed = Some(vec![1; 128]);
            queue.set_idle_cache_policy(policy).unwrap();
            queue
                .start(
                    WINDOW,
                    WINDOW,
                    super::sealed::WindowStorage::InPlace,
                    &mut completed,
                )
                .unwrap();
            let staging = queue.staging_buffer().unwrap();
            staging.resize(PAYLOAD, 0);
            let grown = staging.capacity();
            queue.finish_window(&mut completed).unwrap();
            assert!(!queue.has_data());
            assert!(completed.is_none());
            assert_eq!(
                queue.retained_capacity().unwrap(),
                if keep_after_window { grown } else { 0 }
            );
            queue.begin_ordinary_send();
            assert_eq!(
                queue.retained_capacity().unwrap(),
                if keep_after_ordinary { grown } else { 0 }
            );
        }
    }

    #[test]
    fn packet_backing_and_admission_rejections_leave_the_queue_and_input_unchanged() {
        let mut queue = SendQueue::default();
        queue
            .start(
                8,
                128,
                super::sealed::WindowStorage::OwnedPackets,
                &mut None,
            )
            .unwrap();
        let mut oversized = Vec::with_capacity(9);
        oversized.extend_from_slice(b"x");
        let pointer = oversized.as_ptr();
        assert!(matches!(
            queue.enqueue_packet(&mut oversized),
            Err(Error::Limit(_))
        ));
        assert_eq!(oversized.as_ptr(), pointer);
        assert_eq!(oversized, b"x");
        assert!(!queue.has_data());
        assert!(matches!(
            queue.recycle_scratch(b"unadmitted".to_vec()),
            Err(Error::InvalidInput(_))
        ));
        assert!(queue.scratch.is_none());
        let mut full = Vec::from(*b"12345678");
        assert!(queue.enqueue_packet(&mut full).unwrap());
        let mut waiting = Vec::from(*b"xy");
        let waiting_pointer = waiting.as_ptr();
        assert!(!queue.enqueue_packet(&mut waiting).unwrap());
        assert_eq!(waiting.as_ptr(), waiting_pointer);
        assert_eq!(waiting, b"xy");
        assert_eq!(queue.ready.as_ref().unwrap(), b"12345678");
        let sent = queue.next(None).unwrap();
        assert_eq!(sent, b"12345678");
        queue.disable().unwrap();
        assert_eq!(queue.available(), 0);
        assert!(matches!(queue.enqueue(&[]), Err(Error::InvalidInput(_))));
        assert!(matches!(
            queue.enqueue_packet(&mut full),
            Err(Error::InvalidInput(_))
        ));
        assert!(full.is_empty());
    }

    #[test]
    fn owned_packet_queue_moves_small_packets_and_never_appends_a_second_group() {
        use super::sealed::WindowStorage::OwnedPackets;

        let mut queue = SendQueue::default();
        let mut completed = Some(Vec::with_capacity(16));
        let original = completed.as_ref().unwrap().as_ptr();
        const LIMIT: usize = 1024 * 1024;
        queue
            .start(LIMIT, LIMIT, OwnedPackets, &mut completed)
            .unwrap();
        let mut packet = queue.take_scratch().unwrap();
        assert_eq!(packet.as_ptr(), original);
        assert_eq!(queue.retained_capacity().unwrap(), 0);
        #[cfg(feature = "diagnostics")]
        let before = crate::diagnostics::snapshot();
        packet.extend_from_slice(b"first");
        assert!(queue.enqueue_packet(&mut packet).unwrap());
        assert_eq!(queue.retained_capacity().unwrap(), 16);

        packet.extend_from_slice(b"second");
        let second = packet.as_ptr();
        assert!(!queue.enqueue_packet(&mut packet).unwrap());
        assert_eq!(packet, b"second");
        assert_eq!(packet.as_ptr(), second);
        let first = queue.next(completed.take()).unwrap();
        assert_eq!(first.as_ptr(), original);
        assert_eq!(first, b"first");

        assert!(queue.enqueue_packet(&mut packet).unwrap());
        let next = queue.next(Some(first)).unwrap();
        assert_eq!(next.as_ptr(), second);
        assert_eq!(next, b"second");
        assert_eq!(queue.retained_capacity().unwrap(), 16);
        assert!(next.capacity() < LIMIT);
        #[cfg(feature = "diagnostics")]
        assert_eq!(
            crate::diagnostics::snapshot()
                .delta(before)
                .unwrap()
                .tx_queue_packets_moved,
            2
        );
    }

    #[test]
    fn unpublished_owned_packet_returns_the_unchanged_ordinary_backing() {
        let mut queue = SendQueue::default();
        let mut completed = Some(Vec::with_capacity(32));
        let original = completed.as_ref().unwrap().as_ptr();
        queue
            .start(
                64,
                64,
                super::sealed::WindowStorage::OwnedPackets,
                &mut completed,
            )
            .unwrap();
        let mut private = queue.take_scratch().unwrap();
        assert_eq!(private.as_ptr(), original);
        private.extend_from_slice(b"partial group");
        private.clear();
        queue.recycle_scratch(private).unwrap();
        queue.finish_window(&mut completed).unwrap();
        let restored = completed.unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.as_ptr(), original);
        assert_eq!(queue.retained_capacity().unwrap(), 0);
    }

    #[cfg(feature = "window-cache")]
    #[test]
    fn window_cache_policy_changes_only_idle_backing() {
        use super::WindowSendCache;

        let mut queue = SendQueue::default();
        let retain = WindowSendCache::RetainUntilTrim {
            max_retained_bytes: 64,
        };
        queue.set_idle_cache_policy(retain).unwrap();
        queue.ready = Some(Vec::with_capacity(32));
        queue.scratch = Some(Vec::with_capacity(32));
        queue.enable(32, 128).unwrap();
        let scratch = queue.take_scratch().unwrap();
        queue.recycle_scratch(scratch).unwrap();
        assert!(matches!(
            queue.set_idle_cache_policy(WindowSendCache::ReleaseAfterWindow),
            Err(Error::Busy)
        ));
        assert_eq!(queue.cache_policy(), retain);
        assert_eq!(queue.retained_capacity().unwrap(), 64);
        queue.disable().unwrap();

        queue.begin_ordinary_send();
        assert_eq!(queue.available(), 0);
        assert_eq!(queue.retained_capacity().unwrap(), 64);
        let ready = queue.ready.as_ref().unwrap().as_ptr();
        queue
            .set_idle_cache_policy(WindowSendCache::RetainUntilTrim {
                max_retained_bytes: 63,
            })
            .unwrap();
        assert_eq!(queue.retained_capacity().unwrap(), 32);
        assert_eq!(queue.ready.as_ref().unwrap().as_ptr(), ready);
        assert!(queue.scratch.is_none());

        queue
            .set_idle_cache_policy(WindowSendCache::ReleaseAfterWindow)
            .unwrap();
        queue.ready = Some(Vec::with_capacity(32));
        queue.scratch = Some(Vec::with_capacity(32));
        queue.enable(32, 128).unwrap();
        let scratch = queue.take_scratch().unwrap();
        queue.recycle_scratch(scratch).unwrap();
        assert_eq!(queue.retained_capacity().unwrap(), 64);
        queue.disable().unwrap();
        assert_eq!(queue.retained_capacity().unwrap(), 0);

        queue
            .set_idle_cache_policy(WindowSendCache::RetainUntilTrim {
                max_retained_bytes: 0,
            })
            .unwrap();
        queue.enable(32, 128).unwrap();
        queue.disable().unwrap();
        assert_eq!(queue.retained_capacity().unwrap(), 0);
    }

    #[cfg(feature = "window-cache")]
    #[test]
    fn native_opt_in_cache_reuses_window_backing_after_ordinary_and_keeps_trim_explicit() {
        use super::WindowSendCache;

        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        let policy = WindowSendCache::RetainUntilTrim {
            max_retained_bytes: 128,
        };
        transport.set_window_send_cache(policy).unwrap();
        let mut scratch = transport.start_send_queue(64).unwrap();
        scratch.try_reserve_exact(32).unwrap();
        scratch.extend_from_slice(b"first");
        assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        scratch.try_reserve_exact(16).unwrap();
        scratch.extend_from_slice(b"second");
        assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
        scratch.try_reserve_exact(8).unwrap();
        transport.recycle_send_queue_buffer(scratch).unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        transport.disable_send_queue().unwrap();
        let ready = transport.send_queue.ready.as_ref().unwrap().as_ptr();
        let scratch = transport.send_queue.scratch.as_ref().unwrap().as_ptr();
        let mut buffer = transport.take_send_buffer().unwrap();
        buffer.extend_from_slice(b"normal");
        transport.begin_send(buffer).unwrap();
        assert!(matches!(
            transport.set_window_send_cache(WindowSendCache::ReleaseAfterWindow),
            Err(Error::Busy)
        ));
        assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
        assert_eq!(transport.send_queue.available(), 0);

        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut bytes = [0; 17];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"firstsecondnormal");
        let packet = transport.start_send_queue(64).unwrap();
        assert_eq!(
            transport.send_queue.ready.as_ref().unwrap().as_ptr(),
            scratch
        );
        assert_eq!(packet.as_ptr(), ready);
        transport.recycle_send_queue_buffer(packet).unwrap();
        transport.disable_send_queue().unwrap();
        assert_eq!(transport.trim_send_buffers().unwrap(), 32 + 16 + 8);
        assert_eq!(transport.trim_send_buffers().unwrap(), 0);
        assert_eq!(transport.window_send_cache(), policy);
    }

    #[test]
    fn repeated_single_packet_windows_reuse_only_one_backing() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        let mut previous = None;
        for _ in 0..8 {
            let mut scratch = transport.start_send_queue(64).unwrap();
            scratch.extend_from_slice(b"packet");
            let pointer = scratch.as_ptr();
            let capacity = scratch.capacity();
            assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
            transport.recycle_send_queue_buffer(scratch).unwrap();
            runtime.block_on(async {
                timeout(Duration::from_secs(5), transport.finish_send())
                    .await
                    .unwrap()
                    .unwrap();
            });
            transport.disable_send_queue().unwrap();
            let mut received = [0; 6];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"packet");
            let completed = transport.write_buffer.as_ref().unwrap();
            assert_eq!(completed.as_ptr(), pointer);
            assert_eq!(completed.capacity(), capacity);
            if let Some(previous) = previous {
                assert_eq!(pointer, previous);
            }
            previous = Some(pointer);
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
        }
        let capacity = transport.write_buffer.as_ref().unwrap().capacity();
        assert!(capacity < 64);
        assert_eq!(transport.trim_send_buffers().unwrap(), capacity);
        assert_eq!(transport.trim_send_buffers().unwrap(), 0);
        assert!(transport.write_buffer.is_none());
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
    }

    #[test]
    fn smaller_windows_trim_oversize_roles_and_ordinary_sends_clear_queue_caches() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        for capacity in [128, 32] {
            let mut scratch = transport.start_send_queue(capacity).unwrap();
            assert_eq!(scratch.capacity(), 0);
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
            assert!(transport.write_buffer.is_none());
            scratch.resize(capacity, b'p');
            assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
            transport.recycle_send_queue_buffer(scratch).unwrap();
            runtime.block_on(async {
                timeout(Duration::from_secs(5), transport.finish_send())
                    .await
                    .unwrap()
                    .unwrap();
            });
            transport.disable_send_queue().unwrap();
            let mut received = vec![0; capacity];
            peer.read_exact(&mut received).unwrap();
            assert!(received.iter().all(|&byte| byte == b'p'));
            assert_eq!(
                transport.write_buffer.as_ref().unwrap().capacity(),
                capacity
            );
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
        }
        assert!(matches!(
            transport.begin_send(Vec::new()),
            Err(Error::Limit(_))
        ));
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
        transport.begin_send(b"normal".to_vec()).unwrap();
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
        assert_eq!(transport.send_queue.available(), 0);
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut received = [0; 6];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"normal");
    }

    #[test]
    fn retained_receive_requires_the_original_runtime_on_every_io_poll() {
        let owner = Runtime::new().unwrap();
        let foreign = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&owner, 64);
        owner.block_on(poll_fn(|cx| {
            assert!(transport.poll_frame(cx, false).is_pending());
            Poll::Ready(())
        }));
        foreign.block_on(poll_fn(|cx| {
            assert!(matches!(
                transport.poll_frame(cx, false),
                Poll::Ready(Err(Error::InvalidInput(_)))
            ));
            Poll::Ready(())
        }));
        assert!(transport.receive.is_some());
        assert!(!transport.is_broken());
        peer.write_all(b"Z\0\0\0\x05I").unwrap();
        receive(&owner, &mut transport).unwrap();
        assert_eq!(transport.frame().unwrap().body, b"I");
        owner.block_on(WireOps::close(transport)).unwrap();
    }

    #[test]
    fn pending_receive_keeps_its_native_operation_after_waiter_drop() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);

        runtime.block_on(async {
            let mut waiter = Box::pin(transport.receive_frame());
            poll_fn(|cx| {
                assert!(waiter.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        });
        assert!(transport.receive.is_some());
        assert!(transport.read_buffer.is_none());
        assert!(!transport.is_broken());

        peer.write_all(b"Z\0\0\0\x05I")
            .expect("write test response");
        receive(&runtime, &mut transport).expect("resume original receive");
        let frame = transport.frame().expect("received frame");
        assert_eq!(frame.tag, b'Z');
        assert_eq!(frame.body, b"I");
        assert!(transport.receive.is_none());
        assert_eq!(
            transport
                .read_buffer
                .as_ref()
                .expect("returned buffer")
                .len(),
            64
        );
    }

    #[test]
    fn an_old_native_token_can_cancel_the_retained_receive_after_waiter_replacement() {
        use compio::runtime::{CancelToken, FutureExt};
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, _peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let old_token = CancelToken::new();
            {
                let mut waiter = Box::pin(transport.receive_frame().with_cancel(old_token.clone()));
                poll_fn(|cx| {
                    assert!(waiter.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(transport.receive.is_some());
            old_token.cancel();
            // 新的等待方没有令牌；原操作仍使用第一次注册的取消上下文。
            let result = timeout(Duration::from_secs(5), transport.receive_frame())
                .await
                .expect("native cancellation must complete");
            assert!(matches!(result, Err(Error::Io(_))));
            assert!(transport.is_broken());
            assert!(matches!(
                transport.receive_frame().await,
                Err(Error::Broken)
            ));
            super::WireOps::close(transport)
                .await
                .expect("retire cancelled local socket");
        });
    }

    #[test]
    fn partial_frame_survives_consumption_and_compaction() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 12);
        peer.write_all(b"Z\0\0\0\x05ID\0\0\0")
            .expect("write first frame and partial header");
        receive(&runtime, &mut transport).expect("receive first frame");
        assert_eq!(transport.frame().expect("first frame").body, b"I");
        transport.consume_frame().expect("consume first frame");

        peer.write_all(b"\x08abcd").expect("finish partial frame");
        receive(&runtime, &mut transport).expect("receive second frame");
        let frame = transport.frame().expect("second frame");
        assert_eq!(frame.tag, b'D');
        assert_eq!(frame.body, b"abcd");
        transport.consume_frame().expect("consume second frame");
        assert_eq!(
            transport
                .read_buffer
                .as_ref()
                .expect("returned buffer")
                .len(),
            12
        );
        assert!(!transport.is_broken());
    }

    #[test]
    fn cached_frame_is_retired_before_the_next_header_error() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        peer.write_all(b"Z\0\0\0\x05IZ\0\0\0\x05TD\0\0\0\x40")
            .expect("write two frames and an oversized next header");
        for body in [b"I", b"T"] {
            receive(&runtime, &mut transport).expect("receive complete frame");
            assert_eq!(transport.frame().expect("first view").body, body);
            assert_eq!(transport.frame().expect("second view").body, body);
            transport.consume_frame().expect("consume cached frame");
        }
        assert!(matches!(
            receive(&runtime, &mut transport),
            Err(Error::Protocol(
                crate::protocol::ProtocolError::FrameTooLarge { .. }
            ))
        ));
        assert!(transport.is_broken());
        assert!(matches!(transport.frame(), Err(Error::Broken)));
        runtime
            .block_on(WireOps::close(transport))
            .expect("close poisoned transport");
    }

    #[test]
    fn native_send_preserves_the_owned_request() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        let bytes = b"P\0\0\0\x04S\0\0\0\x04";
        #[cfg(feature = "diagnostics")]
        let observed_before = crate::diagnostics::snapshot();
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.send(bytes.to_vec()))
                .await
                .expect("send must finish before the test deadline")
                .expect("send request");
        });
        let mut received = [0; 10];
        peer.read_exact(&mut received).expect("read request");
        assert_eq!(&received, bytes);
        assert!(transport.transmit.is_none());
        let retained = super::WireOps::take_send_buffer(&mut transport)
            .expect("completed TX can transfer its allocation");
        assert!(retained.is_empty());
        assert!(retained.capacity() >= bytes.len());
        assert!(transport.write_buffer.is_none());
        assert!(!transport.is_broken());
        #[cfg(feature = "diagnostics")]
        {
            let observed = crate::diagnostics::snapshot()
                .delta(observed_before)
                .expect("same-thread counters must remain exact");
            assert!(observed.native_send_attempts >= 1);
            assert_eq!(
                observed.native_send_attempts,
                observed.native_send_successes
            );
            assert_eq!(
                observed.native_bytes_sent,
                u64::try_from(bytes.len()).unwrap()
            );
        }
    }

    #[test]
    fn receiving_a_reply_progresses_while_the_request_is_backpressured() {
        // 发送量大于两端初始套接字窗口，以便稳定观察全双工背压。
        const REQUEST_LEN: usize = 512 * 1024;
        const QUEUED_MARKER: &[u8] = b"queued-after-partial-send";
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        transport.max_request_len = REQUEST_LEN;
        let peer_options = runtime.block_on(async {
            transport
                .socket
                .to_shared_fd()
                // 按平台配置缓冲以触发背压，随后以发送尚未完成的断言确认。
                .set_send_buffer_size(if cfg!(windows) { 0 } else { 64 * 1024 })
                .expect("limit native socket buffering");
            let peer_options =
                TcpStream::from_std(peer.try_clone().expect("clone test peer options handle"))
                    .expect("attach test peer options handle");
            peer_options
                .to_shared_fd()
                .set_recv_buffer_size(16 * 1024)
                .expect("limit peer receive buffering");
            peer_options
        });
        // Compio 为就绪模式套接字设置选项时可能启用 O_NONBLOCK；这个对端只在自己的线程中使用阻塞 I/O。
        peer.set_nonblocking(false)
            .expect("restore blocking test peer");
        let (reply_seen, wait_for_reply) = mpsc::channel();
        let peer_progress = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let worker_progress = peer_progress.clone();
        let worker = thread::spawn(move || -> io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut first = [0];
            peer.read_exact(&mut first)?;
            worker_progress.0.store(1, Ordering::Relaxed);
            worker_progress.1.store(1, Ordering::Relaxed);
            if first != [42] {
                return Err(io::Error::other("invalid initial request byte"));
            }
            peer.write_all(b"Z\0\0\0\x05I")?;
            worker_progress.0.store(2, Ordering::Relaxed);
            // 对端暂停读取请求，直到客户端收到此响应；若客户端先等待整个请求发送完，两端将互相等待。
            wait_for_reply
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "reply was not consumed"))?;
            worker_progress.0.store(3, Ordering::Relaxed);
            let mut remaining = REQUEST_LEN - 1;
            let mut buffer = [0; 8192];
            while remaining != 0 {
                let budget = deadline.saturating_duration_since(Instant::now());
                if budget.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "bulk drain deadline",
                    ));
                }
                peer.set_read_timeout(Some(budget.min(Duration::from_secs(5))))?;
                let length = remaining.min(buffer.len());
                let count = peer.read(&mut buffer[..length])?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "request was truncated",
                    ));
                }
                if buffer[..count].iter().any(|byte| *byte != 42) {
                    return Err(io::Error::other(
                        "request bytes changed during transmission",
                    ));
                }
                remaining -= count;
                worker_progress.1.fetch_add(count, Ordering::Relaxed);
            }
            let mut marker = vec![0; QUEUED_MARKER.len()];
            peer.read_exact(&mut marker)?;
            if marker != QUEUED_MARKER {
                return Err(io::Error::other(
                    "queued bytes overtook a partial native send",
                ));
            }
            worker_progress.0.store(4, Ordering::Relaxed);
            Ok(())
        });
        let mut client_phase = 0;
        let result = runtime.block_on(async {
            timeout(Duration::from_secs(5), async {
                let mut queued = transport.start_send_queue(REQUEST_LEN)?;
                queued.resize(REQUEST_LEN, 42);
                if !transport.enqueue_send_packet(&mut queued)? {
                    return Err(Error::Broken);
                }
                client_phase = 1;
                transport.receive_frame().await?;
                client_phase = 2;
                let frame = transport.frame()?;
                if frame.tag != b'Z' || frame.body != b"I" {
                    return Err(Error::InvalidInput(
                        "the expected early reply was not received",
                    ));
                }
                if transport.write_offset == transport.write_end {
                    return Err(Error::InvalidInput(
                        "the fixture did not create TX backpressure",
                    ));
                }
                transport.consume_frame()?;
                assert!(matches!(
                    transport.start_send_queue(64 * 1024),
                    Err(Error::Busy)
                ));
                assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
                queued.extend_from_slice(QUEUED_MARKER);
                if !transport.enqueue_send_packet(&mut queued)? {
                    return Err(Error::Broken);
                }
                assert!(queued.is_empty());
                // 已从提前送达的响应确认双向进展，恢复正常窗口以完成余下的数据传输。
                transport
                    .socket
                    .to_shared_fd()
                    .set_send_buffer_size(256 * 1024)?;
                peer_options
                    .to_shared_fd()
                    .set_recv_buffer_size(1024 * 1024)?;
                reply_seen.send(()).map_err(|_| {
                    io::Error::other("test peer stopped before receiving the signal")
                })?;
                client_phase = 3;
                Ok::<(), Error>(())
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "early duplex reply deadline")
            })??;
            // 单独限制发送排空的等待时间，并核对对端收到的字节。
            timeout(Duration::from_secs(10), transport.finish_send())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "duplex drain deadline"))??;
            client_phase = 4;
            Ok::<(), Error>(())
        });
        drop(transport);
        let peer_result = worker.join().expect("test peer panicked");
        match (result, peer_result) {
            (Ok(()), Ok(())) => {}
            (client_result, peer_result) => {
                panic!(
                    "duplex fixture failed: client={client_result:?}, peer={peer_result:?}, client_phase={client_phase}, peer_phase={}, peer_received={}",
                    peer_progress.0.load(Ordering::Relaxed),
                    peer_progress.1.load(Ordering::Relaxed)
                )
            }
        }
    }

    #[test]
    fn cached_rx_does_not_hide_cancellation_of_a_pending_native_send() {
        use compio::runtime::{CancelToken, FutureExt};

        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, peer) = pair(&runtime, 64);
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        transport.max_request_len = 512 * 1024;
        let _peer_options = runtime.block_on(async {
            transport
                .socket
                .to_shared_fd()
                .set_send_buffer_size(if cfg!(windows) { 0 } else { 4096 })
                .unwrap();
            let options = TcpStream::from_std(peer.try_clone().unwrap()).unwrap();
            options
                .to_shared_fd()
                .set_recv_buffer_size(16 * 1024)
                .unwrap();
            options
        });
        runtime.block_on(async {
            struct SendWake(std::sync::atomic::AtomicBool);
            impl std::task::Wake for SendWake {
                fn wake(self: Arc<Self>) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let token = CancelToken::new();
            transport
                .begin_send(vec![b'A'; transport.max_request_len])
                .unwrap();
            let stalled = timeout(
                Duration::from_millis(50),
                transport.finish_send().with_cancel(token.clone()),
            )
            .await;
            assert!(stalled.is_err(), "expected TX backpressure: {stalled:?}");
            assert!(transport.transmit.is_some());
            assert!(transport.write_offset < transport.write_end);
            assert!(matches!(transport.start_send_queue(64), Err(Error::Busy)));
            assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
            assert!(matches!(
                transport.set_send_policy(SendPolicy::BeforeBufferedRead),
                Err(Error::Busy)
            ));
            assert_eq!(transport.send_policy, SendPolicy::CoalesceBuffered);
            let signal = Arc::new(SendWake(std::sync::atomic::AtomicBool::new(false)));
            let waker = std::task::Waker::from(signal.clone());
            let mut context = std::task::Context::from_waker(&waker);
            {
                let pending = poll_fn(|cx| transport.poll_send(cx)).with_cancel(token.clone());
                let mut pending = std::pin::pin!(pending);
                assert!(pending.as_mut().poll(&mut context).is_pending());
            }
            let frame = b"Z\0\0\0\x05I";
            transport.read_buffer.as_mut().unwrap()[..frame.len()].copy_from_slice(frame);
            transport.read_end = frame.len();
            transport
                .send_queue
                .enable(64, transport.max_request_len)
                .unwrap();
            let mut queued = Vec::with_capacity(64);
            queued.extend_from_slice(b"queued");
            assert!(transport.enqueue_send_packet(&mut queued).unwrap());
            assert!(queued.is_empty());
            token.cancel();
            runtime.flush();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !signal.0.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "cancelled send did not wake");
                runtime.poll_with(Some(Duration::from_millis(10)));
            }
            let result = timeout(Duration::from_secs(5), transport.receive_frame())
                .await
                .unwrap();
            assert!(matches!(result, Err(Error::Io(_))));
            assert!(transport.is_broken());
        });
    }

    #[test]
    fn coalescing_retires_the_current_native_send_without_promoting_its_queue() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        transport.begin_send(b"current".to_vec()).unwrap();
        transport.send_queue.enable(64, 128).unwrap();
        assert!(transport.send_queue.enqueue(b"queued").unwrap());
        let reply = b"Z\0\0\0\x05I";
        transport.read_buffer.as_mut().unwrap()[..reply.len()].copy_from_slice(reply);
        transport.read_end = reply.len();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            receive(&runtime, &mut transport).unwrap();
            assert_eq!(transport.frame().unwrap().body, b"I");
            assert_eq!(transport.write_end, b"current".len());
            assert!(
                transport.send_queue.has_data(),
                "retirement promoted the next packet"
            );
            if transport.transmit.is_none() && transport.write_offset == transport.write_end {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "current native send did not retire"
            );
            runtime.flush();
            runtime.poll_with(Some(Duration::from_millis(10)));
        }
        let mut current = [0; 7];
        peer.read_exact(&mut current).unwrap();
        assert_eq!(&current, b"current");
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.set_nonblocking(false).unwrap();

        assert!(transport.send_queue.enqueue(b"later").unwrap());
        transport.consume_frame().unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut queued = [0; 11];
        peer.read_exact(&mut queued).unwrap();
        assert_eq!(&queued, b"queuedlater");
        assert!(!transport.send_queue.has_data());
        assert!(transport.transmit.is_none());
        runtime.block_on(WireOps::close(transport)).unwrap();
    }

    #[test]
    fn buffered_frames_coalesce_queued_requests_before_the_next_native_send() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        let frames = b"Z\0\0\0\x05IZ\0\0\0\x05I";
        transport.read_buffer.as_mut().unwrap()[..frames.len()].copy_from_slice(frames);
        transport.read_end = frames.len();
        transport.send_queue.enable(64, 128).unwrap();
        assert!(transport.send_queue.enqueue(b"first").unwrap());

        receive(&runtime, &mut transport).unwrap();
        assert!(transport.transmit.is_none());
        assert_eq!(transport.write_end, 0);
        transport.consume_frame().unwrap();
        assert!(transport.send_queue.enqueue(b"second").unwrap());
        receive(&runtime, &mut transport).unwrap();
        assert_eq!(transport.write_end, 0);
        transport.consume_frame().unwrap();

        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut bytes = [0; 11];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"firstsecond");
        assert!(!transport.send_queue.has_data());
        assert!(transport.transmit.is_none());
    }

    #[test]
    fn default_policy_starts_queued_tx_before_delivering_a_cached_frame() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        let frame = b"Z\0\0\0\x05I";
        transport.read_buffer.as_mut().unwrap()[..frame.len()].copy_from_slice(frame);
        transport.read_end = frame.len();
        transport.send_queue.enable(64, 128).unwrap();
        assert!(transport.send_queue.enqueue(b"first").unwrap());

        receive(&runtime, &mut transport).unwrap();
        assert_eq!(transport.write_end, 5);
        assert!(!transport.send_queue.has_data());
        transport.consume_frame().unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(5), transport.finish_send())
                .await
                .unwrap()
                .unwrap();
        });
        let mut bytes = [0; 5];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"first");
    }

    #[test]
    fn an_incomplete_frame_that_fits_keeps_its_receive_offset() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 32);
        transport.read_buffer.as_mut().unwrap()[6..13].copy_from_slice(b"D\0\0\0\x08ab");
        transport.read_start = 6;
        transport.read_end = 13;
        peer.write_all(b"cd").unwrap();
        receive(&runtime, &mut transport).unwrap();
        assert_eq!(transport.read_start, 6);
        assert_eq!(transport.frame().unwrap().body, b"abcd");
        transport.consume_frame().unwrap();
        runtime.block_on(WireOps::close(transport)).unwrap();
    }

    #[test]
    fn eof_permanently_breaks_the_transport() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, peer) = pair(&runtime, 64);
        drop(peer);
        assert!(matches!(
            receive(&runtime, &mut transport),
            Err(Error::Io(_))
        ));
        assert!(transport.is_broken());
        assert!(matches!(
            receive(&runtime, &mut transport),
            Err(Error::Broken)
        ));
    }

    #[test]
    fn invalid_frame_permanently_breaks_the_transport() {
        let runtime = Runtime::new().expect("create runtime");
        let (mut transport, mut peer) = pair(&runtime, 64);
        peer.write_all(b"Z\0\0\0\x03").expect("write invalid frame");
        assert!(matches!(
            receive(&runtime, &mut transport),
            Err(Error::Protocol(_))
        ));
        assert!(transport.is_broken());
        assert!(matches!(transport.frame(), Err(Error::Broken)));
    }
}
