//! 为 PostgreSQL 会话提供基于 Linux 就绪通知的明文传输。
//!
//! 与原生完成式传输共用套接字配置、初始化的接收缓冲区、有序发送队列和帧校验。
//! 非阻塞 recv/send 遇到 WouldBlock 时通过 PollFd 等待就绪。

use std::{
    io,
    task::{Context, Poll},
};

use compio::net::TcpStream;

#[cfg(feature = "window-cache")]
use crate::transport::WindowSendCache;
use crate::{
    Error,
    protocol::Frame,
    transport::{
        FrameCache, FrameExtent, IoOwner, NativeStream, SendPolicy, SendQueue, WireOps,
        prepare_receive_buffer, sealed, unix_readiness::UnixReadiness,
    },
};

/// 在连接所属 Compio runtime 上执行非阻塞 I/O，并跨轮询保留就绪注册。协议和 Sync 边界与其他传输相同。
#[doc(hidden)]
pub struct ReadinessTransport<S: NativeStream = TcpStream> {
    owner: IoOwner,
    readiness: UnixReadiness<S>,
    read_buffer: Vec<u8>,
    write_buffer: Option<Vec<u8>>,
    read_start: usize,
    read_end: usize,
    frame_cache: FrameCache,
    write_offset: usize,
    write_end: usize,
    max_frame_len: usize,
    max_request_len: usize,
    poisoned: bool,
    send_queue: SendQueue,
    send_policy: SendPolicy,
}

impl<S: NativeStream> ReadinessTransport<S> {
    pub(crate) fn new(
        socket: S,
        receive_capacity: usize,
        max_frame_len: usize,
        max_request_len: usize,
    ) -> Result<Self, Error> {
        let read_buffer =
            crate::transport::new_receive_buffer(receive_capacity, max_frame_len, max_request_len)?;
        let readiness = UnixReadiness::new(socket)?;
        Ok(Self {
            owner: IoOwner::current(),
            readiness,
            read_buffer,
            write_buffer: None,
            read_start: 0,
            read_end: 0,
            frame_cache: FrameCache::default(),
            write_offset: 0,
            write_end: 0,
            max_frame_len,
            max_request_len,
            poisoned: false,
            send_queue: SendQueue::default(),
            send_policy: SendPolicy::BeforeBufferedRead,
        })
    }

    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_send_with_queue::<true>(cx, &mut false)
    }

    fn poll_send_with_queue<const PROMOTE_QUEUE: bool>(
        &mut self,
        cx: &mut Context<'_>,
        owner_checked: &mut bool,
    ) -> Poll<Result<(), Error>> {
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        if self.write_offset != self.write_end || (PROMOTE_QUEUE && self.send_queue.has_data()) {
            self.owner.check_once(owner_checked)?;
        }
        loop {
            if self.write_offset == self.write_end {
                // 可写等待只在未发送的后缀上注册，写入完成前已消费等待结果。
                #[cfg(test)]
                debug_assert!(!self.readiness.is_write_waiting());
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

            // 先收回原可写等待的结果，再尝试发送。
            self.poisoned = true;
            let Some(buffer) = self.write_buffer.as_ref() else {
                return Poll::Ready(Err(Error::Broken));
            };
            let bytes = buffer
                .get(self.write_offset..self.write_end)
                .ok_or(Error::Broken)?;
            let result = self.readiness.poll_write_with(cx, |socket| {
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::readiness_send_attempt();
                let result = socket
                    .send_with_flags(bytes, crate::transport::send_flags().bits().cast_signed());
                #[cfg(feature = "diagnostics")]
                match &result {
                    Ok(count) => crate::diagnostics::readiness_sent(*count),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        crate::diagnostics::readiness_send_would_block()
                    }
                    Err(_) => {}
                }
                result
            });
            let result = match result {
                Poll::Pending => {
                    self.poisoned = false;
                    return Poll::Pending;
                }
                Poll::Ready(result) => result,
            };
            let count = match result {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "PostgreSQL socket returned a zero-length write",
                    )
                    .into()));
                }
                Ok(count) if count <= bytes.len() => count,
                Ok(_) => {
                    return Poll::Ready(Err(Error::InvalidInput(
                        "the transport returned an invalid write length",
                    )));
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            self.write_offset += count;
            if self.write_offset == self.write_end
                && self
                    .write_buffer
                    .as_ref()
                    .is_some_and(|buffer| buffer.capacity() > self.max_request_len)
            {
                self.write_buffer.take();
            }
            self.poisoned = false;
        }
    }

    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        mut owner_checked: bool,
    ) -> Poll<Result<(), Error>> {
        loop {
            if self.poisoned {
                return Poll::Ready(Err(Error::Broken));
            }
            let queued = self.send_queue.has_data();
            let sending = self.write_offset != self.write_end || queued;
            let coalescing = queued && self.send_policy == SendPolicy::CoalesceBuffered;
            // 已有完整缓冲响应时只推进当前发送，让窗口继续合并排队数据。
            if coalescing && self.frame_range()?.is_some() {
                if let Poll::Ready(Err(error)) =
                    self.poll_send_with_queue::<false>(cx, &mut owner_checked)
                {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(()));
            }
            // 对端的响应缓冲区可能已满并因此暂停接收请求。发送等待期间仍须推进接收，两个方向保留各自的就绪注册并使用本次调用的 waker。
            if sending
                && let Poll::Ready(Err(error)) =
                    self.poll_send_with_queue::<true>(cx, &mut owner_checked)
            {
                return Poll::Ready(Err(error));
            }
            if !coalescing && self.frame_range()?.is_some() {
                return Poll::Ready(Ok(()));
            }
            self.owner.check_once(&mut owner_checked)?;
            match self.poll_receive_on_owner(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn frame_range(&mut self) -> Result<Option<FrameExtent>, Error> {
        match self.frame_cache.parse(
            &self.read_buffer,
            self.read_start,
            self.read_end,
            self.max_frame_len,
        ) {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.poisoned = true;
                self.frame_cache.clear();
                Err(error.into())
            }
        }
    }

    fn poll_receive_on_owner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        self.poisoned = true;
        // 读取前先收回原就绪等待的结果。
        prepare_receive_buffer(
            &mut self.read_buffer,
            &mut self.read_start,
            &mut self.read_end,
            &mut self.frame_cache,
            self.max_frame_len,
        )?;
        let bytes = self
            .read_buffer
            .get_mut(self.read_end..)
            .ok_or(Error::Broken)?;
        let free = bytes.len();
        if free == 0 {
            return Poll::Ready(Err(Error::Limit(
                "the receive buffer cannot hold this frame",
            )));
        }
        let result = self.readiness.poll_read_with(cx, |mut socket| {
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::readiness_receive_attempt();
            let result = io::Read::read(&mut socket, bytes);
            #[cfg(feature = "diagnostics")]
            match &result {
                Ok(count) => crate::diagnostics::readiness_received(*count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    crate::diagnostics::readiness_receive_would_block()
                }
                Err(_) => {}
            }
            result
        });
        let count = match result {
            Poll::Pending => {
                self.poisoned = false;
                return Poll::Pending;
            }
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "PostgreSQL closed the connection before the protocol boundary",
                )
                .into()));
            }
            Poll::Ready(Ok(count)) if count <= free => count,
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(Error::InvalidInput(
                    "the transport returned an invalid receive length",
                )));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
        };
        self.read_end += count;
        self.poisoned = false;
        Poll::Ready(Ok(()))
    }
}

impl<S: NativeStream> WireOps for ReadinessTransport<S> {
    fn owner_waker(&self) -> Option<&std::task::Waker> {
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
        if self.poisoned {
            return Err(Error::Broken);
        }
        if self.write_offset != self.write_end || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        self.send_policy = policy;
        Ok(())
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
        self.poisoned
    }

    fn break_connection(&mut self) {
        self.poisoned = true;
    }

    fn begin_send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
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
        self.frame_cache.borrow(
            &self.read_buffer,
            self.read_start,
            self.read_end,
            self.poisoned,
        )
    }

    fn consume_frame(&mut self) -> Result<(), Error> {
        self.frame_cache
            .consume(&mut self.read_start, self.read_end, self.poisoned)
    }

    async fn close(self) -> Result<(), Error> {
        // 先释放就绪注册，再等待仍由驱动持有的描述符引用退出。
        self.readiness.into_stream().close_native().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        io::{Read, Write},
        net::{TcpListener, TcpStream as StdTcpStream},
        os::unix::net::UnixStream as StdUnixStream,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        task::{Wake, Waker},
        thread,
        time::{Duration, Instant},
    };

    use crate::transport::TransportExt;
    use compio::{
        driver::ErrorExt,
        net::UnixStream,
        runtime::{CancelToken, FutureExt, Runtime},
    };

    fn pair(runtime: &Runtime, capacity: usize) -> (ReadinessTransport, StdTcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let transport = runtime.block_on(async {
            ReadinessTransport::new(
                TcpStream::from_std(socket).unwrap(),
                capacity,
                capacity - 1,
                2 * 1024 * 1024,
            )
            .unwrap()
        });
        (transport, peer)
    }

    fn backpressured_pair(runtime: &Runtime) -> (ReadinessTransport<UnixStream>, StdUnixStream) {
        let (socket, peer) = StdUnixStream::pair().unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&socket, 4096).unwrap();
        let transport = runtime.enter(|| {
            ReadinessTransport::new(UnixStream::from_std(socket).unwrap(), 64, 63, 512 * 1024)
                .unwrap()
        });
        (transport, peer)
    }

    async fn receive<S: NativeStream>(transport: &mut ReadinessTransport<S>) -> Result<(), Error> {
        compio::time::timeout(
            Duration::from_secs(4),
            poll_fn(|cx| transport.poll_frame(cx, false)),
        )
        .await
        .expect("readiness receive deadline")
    }

    struct CompletionWake(AtomicBool);

    impl Wake for CompletionWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn pending_readiness_stays_on_the_runtime_that_registered_it() {
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
        peer.write_all(b"Z\0\0\0\x05I").unwrap();
        owner.block_on(receive(&mut transport)).unwrap();
        assert_eq!(transport.frame().unwrap().body, b"I");
        owner.block_on(WireOps::close(transport)).unwrap();
    }

    #[test]
    fn coalescing_rejects_an_invalid_buffered_header_before_promoting_queued_sql() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            transport.read_buffer[..5].copy_from_slice(b"Z\0\0\0\x03");
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
    fn buffered_replies_defer_queued_bytes_until_final_send_finishes() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        let replies = b"Z\0\0\0\x05IZ\0\0\0\x05T";
        transport.read_buffer[..replies.len()].copy_from_slice(replies);
        transport.read_end = replies.len();
        transport.write_buffer = Some(Vec::with_capacity(64));
        runtime.block_on(async {
            #[cfg(feature = "diagnostics")]
            let before = crate::diagnostics::snapshot();
            transport
                .start_window_send_queue(64, sealed::WindowStorage::InPlace)
                .unwrap();
            let packet_pointer = transport.send_queue.staging_buffer().unwrap().as_ptr();
            assert!(transport.enqueue_send(b"first").unwrap());
            receive(&mut transport).await.unwrap();
            assert_eq!(transport.frame().unwrap().body, b"I");
            transport.consume_frame().unwrap();
            assert!(transport.enqueue_send(b"second").unwrap());
            receive(&mut transport).await.unwrap();
            assert_eq!(transport.frame().unwrap().body, b"T");
            transport.consume_frame().unwrap();

            // 对端在两次读取完整缓冲响应后均未收到排队的请求。
            peer.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            peer.set_nonblocking(false).unwrap();
            assert!(transport.send_queue.has_data());
            assert!(matches!(transport.take_send_packet(), Err(Error::Busy)));

            transport.finish_send().await.unwrap();
            let mut sent = [0; 11];
            peer.read_exact(&mut sent).unwrap();
            assert_eq!(&sent, b"firstsecond");
            assert!(!transport.send_queue.has_data());
            assert_eq!(transport.write_offset, transport.write_end);
            assert!(!transport.readiness.is_write_waiting());
            assert_eq!(
                transport.write_buffer.as_ref().unwrap().as_ptr(),
                packet_pointer
            );
            #[cfg(feature = "diagnostics")]
            {
                let observed = crate::diagnostics::snapshot().delta(before).unwrap();
                assert_eq!(observed.tx_queue_packets_moved, 0);
            }
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn default_send_policy_advances_queued_bytes_before_a_cached_reply() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        assert_eq!(transport.send_policy(), SendPolicy::BeforeBufferedRead);
        let reply = b"Z\0\0\0\x05I";
        transport.read_buffer[..reply.len()].copy_from_slice(reply);
        transport.read_end = reply.len();
        runtime.block_on(async {
            transport.enable_send_queue(64).unwrap();
            assert!(transport.enqueue_send(b"request").unwrap());
            assert!(matches!(
                transport.set_send_policy(SendPolicy::CoalesceBuffered),
                Err(Error::Busy)
            ));
            receive(&mut transport).await.unwrap();
            let mut bytes = [0; 7];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"request");
            assert_eq!(transport.frame().unwrap().body, b"I");
            transport.consume_frame().unwrap();
            transport.finish_send().await.unwrap();
            transport
                .set_send_policy(SendPolicy::CoalesceBuffered)
                .unwrap();
            assert_eq!(transport.send_policy(), SendPolicy::CoalesceBuffered);
            transport.break_connection();
            assert!(matches!(
                transport.set_send_policy(SendPolicy::BeforeBufferedRead),
                Err(Error::Broken)
            ));
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn an_incomplete_frame_that_fits_keeps_its_receive_offset() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 32);
        transport.read_buffer[6..13].copy_from_slice(b"D\0\0\0\x08ab");
        transport.read_start = 6;
        transport.read_end = 13;
        runtime.block_on(async {
            peer.write_all(b"cd").unwrap();
            receive(&mut transport).await.unwrap();
            assert_eq!(transport.read_start, 6);
            assert_eq!(transport.frame().unwrap().body, b"abcd");
            transport.consume_frame().unwrap();
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn owned_packets_reuse_the_same_backing_until_the_window_bound_shrinks() {
        const CAPACITY: usize = 128;
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let mut backing = None;
            for _ in 0..12 {
                let mut packet = transport.start_send_queue(CAPACITY).unwrap();
                assert!(packet.is_empty());
                packet.try_reserve_exact(96).unwrap();
                packet.extend_from_slice(b"packet");
                let encoded_pointer = packet.as_ptr();
                assert_eq!(packet.capacity(), 96);
                if let Some(previous) = backing {
                    assert_eq!(encoded_pointer, previous);
                }
                backing = Some(encoded_pointer);
                assert!(transport.enqueue_send_packet(&mut packet).unwrap());
                assert!(packet.is_empty());
                assert_eq!(packet.capacity(), 0);
                assert_eq!(transport.send_queue.retained_capacity().unwrap(), 96);
                transport.recycle_send_queue_buffer(packet).unwrap();
                transport.finish_send().await.unwrap();
                transport.disable_send_queue().unwrap();
                assert_eq!(transport.send_queue_available(), 0);
                assert_eq!(
                    transport.write_buffer.as_ref().unwrap().as_ptr(),
                    encoded_pointer
                );
                assert_eq!(transport.write_buffer.as_ref().unwrap().capacity(), 96);
                assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
                let mut bytes = [0; 6];
                peer.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"packet");
            }
            let mut packet = transport.start_send_queue(32).unwrap();
            assert!(transport.write_buffer.is_none());
            assert_eq!(packet.capacity(), 0);
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
            packet.extend_from_slice(b"small");
            let capacity = packet.capacity();
            assert!(transport.enqueue_send_packet(&mut packet).unwrap());
            transport.recycle_send_queue_buffer(packet).unwrap();
            transport.finish_send().await.unwrap();
            transport.disable_send_queue().unwrap();
            assert_eq!(
                transport.write_buffer.as_ref().unwrap().capacity(),
                capacity
            );
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
            let mut bytes = [0; 5];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"small");

            assert_eq!(transport.trim_send_buffers().unwrap(), capacity);
            assert_eq!(transport.trim_send_buffers().unwrap(), 0);
            assert!(transport.write_buffer.is_none());
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn ordinary_send_releases_the_window_ready_and_scratch_caches() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let mut packet = transport.start_send_queue(64).unwrap();
            for bytes in [b"first".as_slice(), b"second"] {
                packet.extend_from_slice(bytes);
                assert!(transport.enqueue_send_packet(&mut packet).unwrap());
                transport.finish_send().await.unwrap();
            }
            packet.try_reserve_exact(16).unwrap();
            transport.recycle_send_queue_buffer(packet).unwrap();
            transport.disable_send_queue().unwrap();
            assert!((17..128).contains(&transport.send_queue.retained_capacity().unwrap()));
            let mut window = [0; 11];
            peer.read_exact(&mut window).unwrap();
            assert_eq!(&window, b"firstsecond");

            let ordinary = b"ordinary".to_vec();
            let pointer = ordinary.as_ptr();
            let capacity = ordinary.capacity();
            transport.begin_send(ordinary).unwrap();
            assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
            assert_eq!(transport.send_queue_available(), 0);
            assert_eq!(transport.write_buffer.as_ref().unwrap().as_ptr(), pointer);
            assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
            transport.finish_send().await.unwrap();
            let mut bytes = [0; 8];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ordinary");
            assert_eq!(transport.trim_send_buffers().unwrap(), capacity);
            assert_eq!(transport.trim_send_buffers().unwrap(), 0);
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn completed_send_retires_oversized_backing_without_a_provider_flush() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let mut packet = Vec::with_capacity(transport.max_request_len + 1);
            packet.extend_from_slice(b"short");
            transport.begin_send(packet).unwrap();
            transport.finish_send().await.unwrap();
            assert_eq!(transport.write_offset, transport.write_end);
            assert!(!transport.readiness.is_write_waiting());
            assert!(transport.write_buffer.is_none());
            let mut received = [0; 5];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"short");
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn need_more_rx_flushes_a_full_small_queue_before_waiting_for_the_peer() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        let worker = thread::spawn(move || {
            for (expected, status) in [(b"PING", b'I'), (b"PONG", b'T')] {
                let mut bytes = [0; 4];
                peer.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, expected);
                let mut response = *b"Z\0\0\0\x05I";
                response[5] = status;
                peer.write_all(&response).unwrap();
            }
        });
        runtime.block_on(async {
            transport.enable_send_queue(4).unwrap();
            for (request, status) in [(b"PING", b'I'), (b"PONG", b'T')] {
                assert!(transport.enqueue_send(request).unwrap());
                assert_eq!(transport.send_queue_available(), 0);
                assert!(!transport.enqueue_send(b"!").unwrap());
                receive(&mut transport).await.unwrap();
                assert_eq!(transport.frame().unwrap().body, &[status]);
                transport.consume_frame().unwrap();
                assert_eq!(transport.send_queue_available(), 4);
            }
            transport.finish_send().await.unwrap();
            WireOps::close(transport).await.unwrap();
        });
        worker.join().unwrap();
    }

    #[test]
    fn a_cancelled_old_write_wait_is_harvested_before_a_buffered_reply() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, _peer) = backpressured_pair(&runtime);
        runtime.block_on(async {
            transport.begin_send(vec![42; 512 * 1024]).unwrap();
            let old = CancelToken::new();
            let completion = Arc::new(CompletionWake(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&completion));
            {
                let mut waiter =
                    Box::pin(poll_fn(|cx| transport.poll_send(cx)).with_cancel(old.clone()));
                assert!(
                    waiter
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            assert!(transport.readiness.is_write_waiting());
            assert!(transport.write_offset < transport.write_end);
            assert!(matches!(transport.start_send_queue(64), Err(Error::Busy)));
            assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
            let reply = b"Z\0\0\0\x05I";
            transport.read_buffer[..reply.len()].copy_from_slice(reply);
            transport.read_end = reply.len();
            old.cancel();
            // 对端保持背压，等待原注册的完成通知后再轮询缓存响应。
            runtime.flush();
            let deadline = Instant::now() + Duration::from_secs(4);
            while !completion.0.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "取消的可写等待未唤醒");
                runtime.poll_with(Some(Duration::from_millis(10)));
            }
            let result = receive(&mut transport).await;
            assert!(matches!(result, Err(Error::Io(error)) if error.is_cancelled()));
            assert_eq!(transport.read_start, 0);
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn invalid_buffered_header_keeps_the_original_protocol_error_and_tx_order() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        let invalid = b"Z\0\0\0\x03";
        transport.read_buffer[..invalid.len()].copy_from_slice(invalid);
        transport.read_end = invalid.len();
        runtime.block_on(async {
            transport.enable_send_queue(64).unwrap();
            assert!(transport.enqueue_send(b"request").unwrap());
            assert!(matches!(
                receive(&mut transport).await,
                Err(Error::Protocol(
                    crate::protocol::ProtocolError::InvalidLength(3)
                ))
            ));
            let mut sent = [0; 7];
            peer.read_exact(&mut sent).unwrap();
            assert_eq!(&sent, b"request");
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn a_poisoned_transport_never_delivers_a_complete_buffered_reply() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, _peer) = pair(&runtime, 64);
        let reply = b"Z\0\0\0\x05I";
        transport.read_buffer[..reply.len()].copy_from_slice(reply);
        transport.read_end = reply.len();
        transport.break_connection();
        runtime.block_on(async {
            assert!(matches!(receive(&mut transport).await, Err(Error::Broken)));
            assert_eq!(transport.read_start, 0);
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn abandoned_waiter_keeps_readiness_registration_and_original_token() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, _peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let old = CancelToken::new();
            {
                let mut first = Box::pin(receive(&mut transport).with_cancel(old.clone()));
                poll_fn(|cx| {
                    assert!(first.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            old.cancel();
            assert!(matches!(
                receive(&mut transport).await,
                Err(Error::Io(error)) if error.is_cancelled()
            ));
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn successful_read_retires_old_registration_before_the_next_wait() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            let old = CancelToken::new();
            {
                let mut first = Box::pin(receive(&mut transport).with_cancel(old.clone()));
                poll_fn(|cx| {
                    assert!(first.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            peer.write_all(b"Z\0\0\0\x05I").unwrap();
            receive(&mut transport).await.unwrap();
            transport.consume_frame().unwrap();
            let next_token = CancelToken::new();
            let mut next = Box::pin(receive(&mut transport).with_cancel(next_token));
            poll_fn(|cx| {
                assert!(next.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            old.cancel();
            peer.write_all(b"Z\0\0\0\x05I").unwrap();
            next.await.unwrap();
            transport.consume_frame().unwrap();
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn partial_frame_survives_compaction_and_short_nonblocking_reads() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 12);
        runtime.block_on(async {
            peer.write_all(b"Z\0\0\0\x05ID\0\0\0").unwrap();
            receive(&mut transport).await.unwrap();
            assert_eq!(transport.frame().unwrap().body, b"I");
            transport.consume_frame().unwrap();
            peer.write_all(b"\x08abcd").unwrap();
            receive(&mut transport).await.unwrap();
            assert_eq!(transport.frame().unwrap().tag, b'D');
            assert_eq!(transport.frame().unwrap().body, b"abcd");
            transport.consume_frame().unwrap();
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn cached_frames_do_not_hide_the_next_oversized_header() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            peer.write_all(b"Z\0\0\0\x05IZ\0\0\0\x05TD\0\0\0\x40")
                .unwrap();
            for body in [b"I", b"T"] {
                receive(&mut transport).await.unwrap();
                assert_eq!(transport.frame().unwrap().body, body);
                assert_eq!(transport.frame().unwrap().body, body);
                transport.consume_frame().unwrap();
            }
            assert!(matches!(
                receive(&mut transport).await,
                Err(Error::Protocol(
                    crate::protocol::ProtocolError::FrameTooLarge { .. }
                ))
            ));
            assert!(transport.is_broken());
            assert!(matches!(transport.frame(), Err(Error::Broken)));
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn abandoned_write_wait_keeps_its_original_cancellation_context() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, _peer) = backpressured_pair(&runtime);
        runtime.block_on(async {
            transport.begin_send(vec![42; 512 * 1024]).unwrap();
            let old = CancelToken::new();
            {
                let mut first =
                    Box::pin(poll_fn(|cx| transport.poll_send(cx)).with_cancel(old.clone()));
                poll_fn(|cx| {
                    assert!(first.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(transport.readiness.is_write_waiting());
            assert!(transport.write_offset < transport.write_end);
            assert!(matches!(transport.start_send_queue(64), Err(Error::Busy)));
            assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
            old.cancel();
            let result = compio::time::timeout(
                Duration::from_secs(4),
                poll_fn(|cx| transport.poll_send(cx)),
            )
            .await
            .unwrap();
            assert!(matches!(result, Err(Error::Io(error)) if error.is_cancelled()));
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn eof_before_a_frame_boundary_poisons_the_transport() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, peer) = pair(&runtime, 64);
        drop(peer);
        runtime.block_on(async {
            assert!(matches!(receive(&mut transport).await, Err(Error::Io(_))));
            assert!(transport.is_broken());
            WireOps::close(transport).await.unwrap();
        });
    }

    #[test]
    fn close_retires_a_pending_readiness_wait_before_reporting_success() {
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        runtime.block_on(async {
            {
                let mut waiter = Box::pin(receive(&mut transport));
                poll_fn(|cx| {
                    assert!(waiter.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            compio::time::timeout(Duration::from_secs(4), WireOps::close(transport))
                .await
                .unwrap()
                .unwrap();
        });
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn queued_packet_waits_for_partial_send_and_rx_can_progress_under_backpressure() {
        const LENGTH: usize = 512 * 1024;
        let runtime = Runtime::new().unwrap();
        let (mut transport, mut peer) = pair(&runtime, 64);
        rustix::net::sockopt::set_socket_send_buffer_size(transport.readiness.socket(), 4096)
            .unwrap();
        let (release, allowed) = mpsc::channel();
        let worker = thread::spawn(move || {
            peer.write_all(b"Z\0\0\0\x05I").unwrap();
            allowed.recv_timeout(Duration::from_secs(4)).unwrap();
            let mut bytes = vec![0; LENGTH + 3];
            peer.read_exact(&mut bytes).unwrap();
            assert!(bytes[..LENGTH].iter().all(|byte| *byte == 42));
            assert_eq!(&bytes[LENGTH..], b"END");
        });
        runtime.block_on(async {
            let mut packet = transport.start_send_queue(LENGTH).unwrap();
            packet.resize(LENGTH, 42);
            assert!(transport.enqueue_send_packet(&mut packet).unwrap());
            receive(&mut transport).await.unwrap();
            assert!(transport.readiness.is_write_waiting());

            packet.extend_from_slice(b"END");
            let pointer = packet.as_ptr();
            assert!(transport.enqueue_send_packet(&mut packet).unwrap());
            assert!(packet.is_empty());
            transport.recycle_send_queue_buffer(packet).unwrap();
            assert!(matches!(transport.take_send_packet(), Err(Error::Busy)));
            assert!(matches!(transport.start_send_queue(64), Err(Error::Busy)));
            assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
            release.send(()).unwrap();
            compio::time::timeout(
                Duration::from_secs(4),
                poll_fn(|cx| transport.poll_send(cx)),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!transport.readiness.is_write_waiting());
            assert_eq!(transport.write_offset, transport.write_end);
            let returned = transport.take_send_packet().unwrap();
            assert_eq!(returned.as_ptr(), pointer);
            assert_eq!(returned, b"END");
            WireOps::close(transport).await.unwrap();
        });
        worker.join().unwrap();
    }
}
