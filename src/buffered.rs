//! 经验证 TLS 使用的 futures I/O 缓冲传输。

use futures_util::io::AsyncWrite;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "window-cache")]
use crate::transport::WindowSendCache;
use crate::{
    Error,
    protocol::{Frame, frame_header},
    transport::{
        IoOwner, SendPolicy, SendQueue, WireOps, reserve_receive_capacity, sealed, validate_buffers,
    },
};
use sealed::{CopyDataSink, CopyOutFrame};

const FRAME_HEADER_BYTES: usize = 5;

#[derive(Clone, Copy)]
enum PlaintextFrame {
    Start,
    Header {
        bytes: [u8; FRAME_HEADER_BYTES],
        used: u8,
    },
    AwaitingBody {
        tag: u8,
        body_len: usize,
    },
    // 帧头已通过校验，缓冲只预留帧体的字节数。
    Stitching {
        tag: u8,
        body_len: usize,
    },
    Borrowed {
        tag: u8,
        end: usize,
    },
    BorrowedBody {
        tag: u8,
        body_len: usize,
    },
    Stitched {
        tag: u8,
    },
    CopyData {
        body_len: usize,
        remaining: usize,
    },
    CopyDataComplete {
        body_len: usize,
    },
}

/// 等待方挂起或被丢弃时，连接继续持有流。缓冲区限额只覆盖本库分配的内存。
#[doc(hidden)]
pub struct BufferedTransport<S> {
    stream: S,
    owner: IoOwner,
    read_buffer: Vec<u8>,
    plaintext_frame: PlaintextFrame,
    write_buffer: Option<Vec<u8>>,
    write_offset: usize,
    write_complete: bool,
    max_frame_len: usize,
    max_request_len: usize,
    poisoned: bool,
    send_queue: SendQueue,
    send_policy: SendPolicy,
}

#[doc(hidden)]
pub trait ManagedStream: AsyncWrite + Unpin {
    fn plaintext(&mut self) -> io::Result<&[u8]>;
    fn consume_plaintext(&mut self, bytes: usize) -> Result<(), Error>;
    fn poll_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>>;
    fn dispose(self) -> impl std::future::Future<Output = Result<(), Error>>;
}

impl ManagedStream for crate::tls::TlsSession {
    fn plaintext(&mut self) -> io::Result<&[u8]> {
        crate::tls::TlsSession::plaintext(self)
    }

    fn consume_plaintext(&mut self, bytes: usize) -> Result<(), Error> {
        crate::tls::TlsSession::consume_plaintext(self, bytes);
        Ok(())
    }

    fn poll_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        crate::tls::TlsSession::poll_plaintext(self, cx)
    }

    async fn dispose(self) -> Result<(), Error> {
        crate::tls::TlsSession::dispose(self).await
    }
}

impl<S: ManagedStream> BufferedTransport<S> {
    pub(crate) fn new(
        stream: S,
        receive_capacity: usize,
        max_frame_len: usize,
        max_request_len: usize,
    ) -> Result<Self, Error> {
        validate_buffers(receive_capacity, max_frame_len, max_request_len)?;
        Ok(Self {
            stream,
            owner: IoOwner::current(),
            read_buffer: Vec::new(),
            plaintext_frame: PlaintextFrame::Start,
            write_buffer: None,
            write_offset: 0,
            write_complete: true,
            max_frame_len,
            max_request_len,
            poisoned: false,
            send_queue: SendQueue::default(),
            send_policy: SendPolicy::BeforeBufferedRead,
        })
    }

    pub(crate) fn stream(&self) -> &S {
        &self.stream
    }

    /// 借用完整帧或位于同一明文块的帧体。跨块的帧头定长暂存，只有帧体跨块才分配。
    fn cache_plaintext_frame<const STREAM_COPY_DATA: bool>(
        &mut self,
        sink: &mut impl CopyDataSink,
    ) -> Result<bool, Error> {
        if STREAM_COPY_DATA
            && let PlaintextFrame::Stitching {
                tag: b'd',
                body_len,
            } = self.plaintext_frame
        {
            // 上一个借用等待方可能已暂存部分数据。终结前先处理这个前缀。
            let remaining = body_len
                .checked_sub(self.read_buffer.len())
                .ok_or(Error::Broken)?;
            sink.begin(body_len);
            sink.append(&self.read_buffer);
            self.read_buffer.clear();
            self.plaintext_frame = PlaintextFrame::CopyData {
                body_len,
                remaining,
            };
        }
        while !matches!(
            self.plaintext_frame,
            PlaintextFrame::Borrowed { .. }
                | PlaintextFrame::BorrowedBody { .. }
                | PlaintextFrame::Stitched { .. }
                | PlaintextFrame::CopyDataComplete { .. }
        ) {
            let plaintext = match self.stream.plaintext() {
                Ok([]) => return Err(tls_eof()),
                Ok(plaintext) => plaintext,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            let mut suffix = plaintext;
            let body = match self.plaintext_frame {
                PlaintextFrame::Start => match frame_header(plaintext, self.max_frame_len)? {
                    Some((tag, end)) if end <= plaintext.len() => {
                        self.plaintext_frame = PlaintextFrame::Borrowed { tag, end };
                        #[cfg(feature = "diagnostics")]
                        crate::diagnostics::tls_plaintext_borrowed(end);
                        return Ok(true);
                    }
                    Some((tag, end)) => {
                        suffix = plaintext.get(FRAME_HEADER_BYTES..).ok_or(Error::Broken)?;
                        Some((tag, end - FRAME_HEADER_BYTES))
                    }
                    None => {
                        let mut bytes = [0; FRAME_HEADER_BYTES];
                        let mut used = 0;
                        suffix = append_header(&mut bytes, &mut used, plaintext)?;
                        self.plaintext_frame = PlaintextFrame::Header { bytes, used };
                        None
                    }
                },
                PlaintextFrame::Header {
                    mut bytes,
                    mut used,
                } => {
                    suffix = append_header(&mut bytes, &mut used, plaintext)?;
                    if usize::from(used) == FRAME_HEADER_BYTES {
                        let (tag, end) =
                            frame_header(&bytes, self.max_frame_len)?.ok_or(Error::Broken)?;
                        Some((tag, end - FRAME_HEADER_BYTES))
                    } else {
                        self.plaintext_frame = PlaintextFrame::Header { bytes, used };
                        None
                    }
                }
                PlaintextFrame::AwaitingBody { tag, body_len } => Some((tag, body_len)),
                PlaintextFrame::Stitching { tag, body_len } => {
                    (self.plaintext_frame, suffix) =
                        stitch_body(&mut self.read_buffer, suffix, tag, body_len)?;
                    None
                }
                PlaintextFrame::CopyData {
                    body_len,
                    remaining,
                } if STREAM_COPY_DATA => {
                    let count = remaining.min(plaintext.len());
                    let (chunk, rest) = plaintext.split_at(count);
                    sink.append(chunk);
                    self.plaintext_frame = if count == remaining {
                        PlaintextFrame::CopyDataComplete { body_len }
                    } else {
                        PlaintextFrame::CopyData {
                            body_len,
                            remaining: remaining - count,
                        }
                    };
                    suffix = rest;
                    None
                }
                PlaintextFrame::CopyData { .. } => return Err(Error::Broken),
                PlaintextFrame::Borrowed { .. }
                | PlaintextFrame::BorrowedBody { .. }
                | PlaintextFrame::Stitched { .. }
                | PlaintextFrame::CopyDataComplete { .. } => {
                    return Ok(true);
                }
            };
            if let Some((tag, body_len)) = body {
                self.plaintext_frame = if body_len == 0 {
                    PlaintextFrame::Stitched { tag }
                } else if suffix.len() >= body_len {
                    #[cfg(feature = "diagnostics")]
                    crate::diagnostics::tls_plaintext_borrowed(body_len);
                    PlaintextFrame::BorrowedBody { tag, body_len }
                } else if suffix.is_empty() {
                    PlaintextFrame::AwaitingBody { tag, body_len }
                } else if STREAM_COPY_DATA && tag == b'd' {
                    sink.begin(body_len);
                    sink.append(suffix);
                    let remaining = body_len - suffix.len();
                    suffix = &[];
                    PlaintextFrame::CopyData {
                        body_len,
                        remaining,
                    }
                } else {
                    let capacity = self.read_buffer.capacity();
                    if body_len > capacity {
                        // 帧长包含四字节长度字段，拼接缓冲只保存帧体。
                        reserve_receive_capacity(
                            &mut self.read_buffer,
                            capacity,
                            body_len,
                            self.max_frame_len - 4,
                        )
                        .map_err(|_| Error::Limit("cannot assemble a TLS frame"))?;
                    }
                    let (stitching, remaining) =
                        stitch_body(&mut self.read_buffer, suffix, tag, body_len)?;
                    suffix = remaining;
                    stitching
                };
            }
            let consumed = plaintext.len() - suffix.len();
            if consumed != 0 {
                self.stream.consume_plaintext(consumed)?;
            }
        }
        Ok(true)
    }

    fn has_plaintext_frame<const STREAM_COPY_DATA: bool>(
        &mut self,
        sink: &mut impl CopyDataSink,
    ) -> Result<bool, Error> {
        if STREAM_COPY_DATA {
            // 处理输出时发生 panic，不允许重放已经交付的片段。
            self.poisoned = true;
            let result = self.cache_plaintext_frame::<true>(sink);
            self.poisoned = result.is_err();
            result
        } else {
            self.cache_plaintext_frame::<false>(sink).inspect_err(|_| {
                self.poisoned = true;
            })
        }
    }

    fn poll_send_with_queue<const PROMOTE_QUEUE: bool>(
        &mut self,
        cx: &mut Context<'_>,
        owner_checked: &mut bool,
    ) -> Poll<Result<(), Error>> {
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        if !self.write_complete || (PROMOTE_QUEUE && self.send_queue.has_data()) {
            self.owner.check_once(owner_checked)?;
        }
        loop {
            if self.write_complete {
                if !PROMOTE_QUEUE || !self.send_queue.has_data() {
                    return Poll::Ready(Ok(()));
                }
                self.poisoned = true;
                let next = self.send_queue.next(self.write_buffer.take())?;
                self.write_buffer = Some(next);
                self.write_offset = 0;
                self.write_complete = false;
                self.poisoned = false;
            }
            let Some(buffer) = self.write_buffer.as_ref() else {
                self.poisoned = true;
                return Poll::Ready(Err(Error::Broken));
            };
            self.poisoned = true;
            while self.write_offset < buffer.len() {
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::tls_write_poll();
                let bytes = buffer.get(self.write_offset..).ok_or(Error::Broken)?;
                match Pin::new(&mut self.stream).poll_write(cx, bytes) {
                    Poll::Pending => {
                        self.poisoned = false;
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "TLS accepted no request bytes",
                        )
                        .into()));
                    }
                    Poll::Ready(Ok(n)) if n <= bytes.len() => {
                        #[cfg(feature = "diagnostics")]
                        crate::diagnostics::tls_written(n);
                        self.write_offset += n
                    }
                    Poll::Ready(Ok(_)) => {
                        return Poll::Ready(Err(Error::InvalidInput(
                            "TLS returned an invalid accepted byte count",
                        )));
                    }
                }
            }
            // TLS 接受明文后还要排空加密输出，才能回收发送缓冲区。
            match Pin::new(&mut self.stream).poll_flush(cx) {
                Poll::Pending => {
                    self.poisoned = false;
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(())) => {
                    self.write_complete = true;
                    if self
                        .write_buffer
                        .as_ref()
                        .is_some_and(|buffer| buffer.capacity() > self.max_request_len)
                    {
                        self.write_buffer.take();
                    }
                    self.poisoned = false;
                }
            }
        }
    }
    fn poll_frame(&mut self, cx: &mut Context<'_>, owner_checked: bool) -> Poll<Result<(), Error>> {
        self.poll_frame_with::<false>(cx, owner_checked, &mut ())
    }

    fn poll_frame_with<const STREAM_COPY_DATA: bool>(
        &mut self,
        cx: &mut Context<'_>,
        mut owner_checked: bool,
        sink: &mut impl CopyDataSink,
    ) -> Poll<Result<(), Error>> {
        if self.poisoned {
            return Poll::Ready(Err(Error::Broken));
        }
        loop {
            let queued = self.send_queue.has_data();
            let sending = !self.write_complete || queued;
            let coalescing = queued && self.send_policy == SendPolicy::CoalesceBuffered;
            if coalescing && self.has_plaintext_frame::<STREAM_COPY_DATA>(sink)? {
                if let Poll::Ready(Err(error)) =
                    self.poll_send_with_queue::<false>(cx, &mut owner_checked)
                {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(()));
            }
            if sending
                && let Poll::Ready(Err(error)) =
                    self.poll_send_with_queue::<true>(cx, &mut owner_checked)
            {
                return Poll::Ready(Err(error));
            }
            if !coalescing && self.has_plaintext_frame::<STREAM_COPY_DATA>(sink)? {
                return Poll::Ready(Ok(()));
            }
            self.owner.check_once(&mut owner_checked)?;
            self.poisoned = true;
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::tls_read_poll();
            match self.stream.poll_plaintext(cx) {
                Poll::Pending => {
                    self.poisoned = false;
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(bytes)) => {
                    #[cfg(feature = "diagnostics")]
                    crate::diagnostics::tls_received(bytes);
                    let _ = bytes;
                    self.poisoned = false;
                }
            }
        }
    }
}

fn append_header<'a>(
    header: &mut [u8; FRAME_HEADER_BYTES],
    used: &mut u8,
    plaintext: &'a [u8],
) -> Result<&'a [u8], Error> {
    let free = header.get_mut(usize::from(*used)..).ok_or(Error::Broken)?;
    let count = free.len().min(plaintext.len());
    let (prefix, suffix) = plaintext.split_at_checked(count).ok_or(Error::Broken)?;
    free.get_mut(..count)
        .ok_or(Error::Broken)?
        .copy_from_slice(prefix);
    *used += u8::try_from(count).map_err(|_| Error::Broken)?;
    #[cfg(feature = "diagnostics")]
    crate::diagnostics::tls_plaintext_copied(count);
    Ok(suffix)
}

fn stitch_body<'a>(
    buffer: &mut Vec<u8>,
    plaintext: &'a [u8],
    tag: u8,
    body_len: usize,
) -> Result<(PlaintextFrame, &'a [u8]), Error> {
    let remaining = body_len.checked_sub(buffer.len()).ok_or(Error::Broken)?;
    let (prefix, suffix) = plaintext
        .split_at_checked(remaining.min(plaintext.len()))
        .ok_or(Error::Broken)?;
    if !prefix.is_empty() {
        buffer.extend_from_slice(prefix);
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::tls_plaintext_copied(prefix.len());
    }
    let state = if buffer.len() == body_len {
        PlaintextFrame::Stitched { tag }
    } else {
        PlaintextFrame::Stitching { tag, body_len }
    };
    Ok((state, suffix))
}

fn tls_eof() -> Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "TLS closed before the PostgreSQL boundary",
    )
    .into()
}

impl<S: ManagedStream> WireOps for BufferedTransport<S> {
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
        if !self.write_complete || self.send_queue.has_data() {
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
        if !self.write_complete || self.send_queue.has_data() {
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
        if !self.write_complete {
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
        if !self.write_complete || self.send_queue.has_data() {
            return Err(Error::Busy);
        }
        if bytes.is_empty() || bytes.len() > self.max_request_len {
            return Err(Error::Limit("the TLS request exceeds its configured limit"));
        }
        self.send_queue.begin_ordinary_send();
        self.write_buffer = Some(bytes);
        self.write_offset = 0;
        self.write_complete = false;
        Ok(())
    }

    fn poll_finish_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_send_with_queue::<true>(cx, &mut false)
    }

    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        if !self.write_complete || self.send_queue.has_data() {
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
        if !self.write_complete {
            return Err(Error::Busy);
        }
        self.send_queue.trim_idle_buffers(&mut self.write_buffer)
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

    fn poll_copy_out_frame_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        sink: &mut impl CopyDataSink,
    ) -> Poll<Result<CopyOutFrame, Error>> {
        std::task::ready!(self.poll_frame_with::<true>(cx, true, sink))?;
        if let PlaintextFrame::CopyDataComplete { body_len } = self.plaintext_frame {
            self.plaintext_frame = PlaintextFrame::Start;
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::frame();
            return Poll::Ready(Ok(CopyOutFrame::Data(body_len)));
        }
        Poll::Ready(self.consume_ready_copy_out_frame(sink))
    }

    fn poll_receive_frame_with_send_status_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        stop_when_sent: bool,
    ) -> Result<(Poll<()>, bool), Error> {
        let sent = |transport: &Self| transport.write_complete && !transport.send_queue.has_data();
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
        if self.poisoned {
            return Err(Error::Broken);
        }
        match self.plaintext_frame {
            PlaintextFrame::Borrowed { tag, end } => Ok(Frame {
                tag,
                body: self
                    .stream
                    .plaintext()?
                    .get(FRAME_HEADER_BYTES..end)
                    .ok_or(Error::Broken)?,
            }),
            PlaintextFrame::BorrowedBody { tag, body_len } => Ok(Frame {
                tag,
                body: self
                    .stream
                    .plaintext()?
                    .get(..body_len)
                    .ok_or(Error::Broken)?,
            }),
            PlaintextFrame::Stitched { tag } => Ok(Frame {
                tag,
                body: &self.read_buffer,
            }),
            _ => Err(Error::Busy),
        }
    }

    fn consume_frame(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Broken);
        }
        match self.plaintext_frame {
            PlaintextFrame::Borrowed { end, .. }
            | PlaintextFrame::BorrowedBody { body_len: end, .. } => {
                self.stream.consume_plaintext(end).inspect_err(|_| {
                    self.poisoned = true;
                })?;
            }
            PlaintextFrame::Stitched { .. } => self.read_buffer.clear(),
            _ => return Err(Error::Busy),
        }
        self.plaintext_frame = PlaintextFrame::Start;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::frame();
        Ok(())
    }
    async fn close(self) -> Result<(), Error> {
        self.stream.dispose().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc, task::Waker};

    struct FragmentedStream {
        bytes: &'static [u8],
        offset: usize,
        end: usize,
        read_steps: std::slice::Iter<'static, MockRead>,
    }

    enum MockRead {
        Chunk(usize),
        EmptyRecord,
        Pending,
    }

    impl AsyncWrite for FragmentedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl ManagedStream for FragmentedStream {
        fn plaintext(&mut self) -> io::Result<&[u8]> {
            if self.offset == self.bytes.len() || self.offset < self.end {
                Ok(&self.bytes[self.offset..self.end])
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        fn consume_plaintext(&mut self, bytes: usize) -> Result<(), Error> {
            assert!((1..=self.end - self.offset).contains(&bytes));
            self.offset += bytes;
            Ok(())
        }

        fn poll_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
            assert_eq!(self.offset, self.end);
            let limit = match self.read_steps.next() {
                Some(MockRead::Chunk(limit)) => *limit,
                Some(MockRead::EmptyRecord) => return Poll::Ready(Ok(0)),
                Some(MockRead::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                None => 4,
            };
            let count = (self.bytes.len() - self.end).min(limit);
            self.end += count;
            Poll::Ready(Ok(count))
        }

        async fn dispose(self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CopyCapture {
        lengths: Vec<usize>,
        chunks: Vec<Vec<u8>>,
    }

    impl CopyDataSink for CopyCapture {
        fn begin(&mut self, payload_len: usize) {
            self.lengths.push(payload_len);
        }

        fn append(&mut self, bytes: &[u8]) {
            self.chunks.push(bytes.to_vec());
        }
    }

    #[test]
    fn copy_out_streams_fragments_without_stitching_and_keeps_the_next_frame() {
        const REPLY: &[u8] = b"d\0\0\0\x0cabcdefghZ\0\0\0\x05I";
        static RECORDS: [MockRead; 6] = [
            MockRead::Pending,
            MockRead::Chunk(2),
            MockRead::Pending,
            MockRead::Chunk(2),
            MockRead::Pending,
            MockRead::Chunk(REPLY.len()),
        ];
        let mut transport = BufferedTransport::new(
            FragmentedStream {
                bytes: REPLY,
                offset: 0,
                end: 5,
                read_steps: RECORDS.iter(),
            },
            8,
            12,
            64,
        )
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let mut capture = CopyCapture::default();
        #[cfg(feature = "diagnostics")]
        let before = crate::diagnostics::snapshot();
        assert!(
            transport
                .poll_copy_out_frame_on_owner(&mut cx, &mut capture)
                .is_pending()
        );
        assert!(capture.lengths.is_empty());
        assert!(capture.chunks.is_empty());
        for count in 1..=2 {
            assert!(
                transport
                    .poll_copy_out_frame_on_owner(&mut cx, &mut capture)
                    .is_pending()
            );
            assert_eq!(capture.lengths, [8]);
            assert_eq!(capture.chunks.len(), count);
            assert_eq!(transport.read_buffer.capacity(), 0);
        }
        assert!(matches!(
            transport.poll_copy_out_frame_on_owner(&mut cx, &mut capture),
            Poll::Ready(Ok(CopyOutFrame::Data(8)))
        ));
        assert_eq!(capture.chunks, [b"ab".as_slice(), b"cd", b"efgh"]);
        assert_eq!(transport.read_buffer.capacity(), 0);
        assert!(matches!(
            transport.poll_copy_out_frame_on_owner(&mut cx, &mut capture),
            Poll::Ready(Ok(CopyOutFrame::Control))
        ));
        let frame = transport.frame().unwrap();
        assert_eq!((frame.tag, frame.body), (b'Z', b"I".as_slice()));
        transport.consume_frame().unwrap();
        #[cfg(feature = "diagnostics")]
        {
            let counters = crate::diagnostics::snapshot().delta(before).unwrap();
            assert_eq!(counters.tls_plaintext_bytes_copied, 0);
            assert_eq!(counters.backend_frames, 2);
        }
    }

    #[test]
    fn copy_out_can_resume_without_the_original_sink_or_accepting_truncation() {
        for (reply, complete) in [
            (b"d\0\0\0\x08abcdZ\0\0\0\x05I".as_slice(), true),
            (b"d\0\0\0\x08abc".as_slice(), false),
        ] {
            let mut transport = BufferedTransport::new(
                FragmentedStream {
                    bytes: reply,
                    offset: 0,
                    end: 7,
                    read_steps: [MockRead::Pending, MockRead::Chunk(64)].iter(),
                },
                8,
                12,
                64,
            )
            .unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            {
                let mut capture = CopyCapture::default();
                assert!(
                    transport
                        .poll_copy_out_frame_on_owner(&mut cx, &mut capture)
                        .is_pending()
                );
                assert_eq!(capture.lengths, [4]);
                assert_eq!(capture.chunks, [b"ab"]);
            }
            let result = transport.poll_copy_out_frame_on_owner(&mut cx, &mut ());
            if complete {
                assert!(matches!(result, Poll::Ready(Ok(CopyOutFrame::Data(4)))));
                assert!(matches!(
                    transport.poll_receive_frame(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(transport.frame().unwrap().body, b"I");
            } else {
                assert!(
                    matches!(result, Poll::Ready(Err(Error::Io(error))) if error.kind() == io::ErrorKind::UnexpectedEof)
                );
                assert!(transport.is_broken());
            }
            assert_eq!(transport.read_buffer.capacity(), 0);
        }
    }

    #[test]
    fn copy_out_streaming_reuses_the_prefix_left_by_a_borrow_waiter() {
        let mut transport = BufferedTransport::new(
            FragmentedStream {
                bytes: b"d\0\0\0\x08abcdZ\0\0\0\x05I",
                offset: 0,
                end: 7,
                read_steps: [MockRead::Pending, MockRead::Chunk(64)].iter(),
            },
            8,
            12,
            64,
        )
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(transport.poll_receive_frame(&mut cx).is_pending());
        assert_eq!(transport.read_buffer, b"ab");
        let mut capture = CopyCapture::default();
        assert!(matches!(
            transport.poll_copy_out_frame_on_owner(&mut cx, &mut capture),
            Poll::Ready(Ok(CopyOutFrame::Data(4)))
        ));
        assert_eq!(capture.lengths, [4]);
        assert_eq!(capture.chunks, [b"ab", b"cd"]);
        assert!(transport.read_buffer.is_empty());
        assert!(matches!(
            transport.poll_copy_out_frame_on_owner(&mut cx, &mut capture),
            Poll::Ready(Ok(CopyOutFrame::Control))
        ));
        assert_eq!(transport.frame().unwrap().body, b"I");
    }

    #[test]
    fn coalescing_rejects_an_invalid_buffered_header_before_promoting_queued_sql() {
        let writes = Rc::new(Cell::new(0));
        let stream = FlushGate {
            pending: Rc::new(Cell::new(false)),
            writes: writes.clone(),
            plaintext: b"Z\0\0\0\x03",
        };
        let mut transport = BufferedTransport::new(stream, 64, 63, 64).unwrap();
        transport
            .set_send_policy(SendPolicy::CoalesceBuffered)
            .unwrap();
        transport.enable_send_queue(64).unwrap();
        assert!(transport.enqueue_send(b"request").unwrap());
        assert!(matches!(
            transport.poll_receive_frame(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(Error::Protocol(
                crate::protocol::ProtocolError::InvalidLength(3)
            )))
        ));
        assert!(transport.is_broken());
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn split_tls_frames_are_assembled_and_the_next_header_is_validated() {
        let stream = FragmentedStream {
            bytes: b"Z\0\0\0\x05ID\0\0\0\x08abcdD\0\0\0\x0C",
            offset: 0,
            end: 0,
            read_steps: [].iter(),
        };
        let mut transport = BufferedTransport::new(stream, 12, 11, 64).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        for (tag, body) in [(b'Z', &b"I"[..]), (b'D', &b"abcd"[..])] {
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            for _ in 0..2 {
                let frame = transport.frame().unwrap();
                assert_eq!(frame.tag, tag);
                assert_eq!(frame.body, body);
            }
            transport.consume_frame().unwrap();
        }
        assert!(matches!(
            transport.poll_receive_frame(&mut context),
            Poll::Ready(Err(Error::Protocol(
                crate::protocol::ProtocolError::FrameTooLarge { .. }
            )))
        ));
        assert!(transport.is_broken());
        assert!(matches!(transport.frame(), Err(Error::Broken)));
    }

    #[test]
    fn split_header_needs_no_heap_before_completion_even_without_plaintext_progress() {
        for split in 1..FRAME_HEADER_BYTES {
            let mut transport = BufferedTransport::new(
                FragmentedStream {
                    bytes: b"1\0\0\0\x04Z\0\0\0\x05I",
                    offset: 0,
                    end: split,
                    read_steps: [MockRead::EmptyRecord, MockRead::Pending].iter(),
                },
                12,
                11,
                64,
            )
            .unwrap();
            let mut context = Context::from_waker(Waker::noop());
            #[cfg(feature = "diagnostics")]
            let before = crate::diagnostics::snapshot();
            assert!(transport.poll_receive_frame(&mut context).is_pending());
            assert_eq!(transport.read_buffer.capacity(), 0);
            assert!(matches!(transport.frame(), Err(Error::Busy)));
            assert!(matches!(transport.consume_frame(), Err(Error::Busy)));
            for (tag, body) in [(b'1', &b""[..]), (b'Z', &b"I"[..])] {
                assert!(matches!(
                    transport.poll_receive_frame(&mut context),
                    Poll::Ready(Ok(()))
                ));
                let frame = transport.frame().unwrap();
                assert_eq!((frame.tag, frame.body), (tag, body));
                assert_eq!(transport.read_buffer.capacity(), 0);
                transport.consume_frame().unwrap();
            }
            #[cfg(feature = "diagnostics")]
            {
                let counts = crate::diagnostics::snapshot().delta(before).unwrap();
                assert_eq!(counts.tls_plaintext_bytes_copied, 10);
                assert_eq!(counts.tls_plaintext_bytes_borrowed, 1);
            }
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Err(Error::Io(error))) if error.kind() == io::ErrorKind::UnexpectedEof
            ));
        }
    }

    #[test]
    fn a_split_frame_only_stitches_a_body_spread_across_records() {
        const REPLY: &[u8] = b"D\0\0\0\x08abcd1\0\0\0\x04";
        static READ_STEPS: [MockRead; 2] = [MockRead::Pending, MockRead::Chunk(REPLY.len())];
        for split in 1..FRAME_HEADER_BYTES + 4 {
            let stitches_body = split > FRAME_HEADER_BYTES;
            let capacity = if stitches_body { 4 } else { 0 };
            let mut transport = BufferedTransport::new(
                FragmentedStream {
                    bytes: REPLY,
                    offset: 0,
                    end: split,
                    read_steps: READ_STEPS.iter(),
                },
                8,
                8,
                64,
            )
            .unwrap();
            let mut context = Context::from_waker(Waker::noop());
            #[cfg(feature = "diagnostics")]
            let before = crate::diagnostics::snapshot();
            assert!(transport.poll_receive_frame(&mut context).is_pending());
            assert_eq!(transport.read_buffer.capacity(), capacity);
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            for _ in 0..2 {
                let frame = transport.frame().unwrap();
                assert_eq!((frame.tag, frame.body), (b'D', b"abcd".as_slice()));
                assert_eq!(
                    frame.body.as_ptr() != REPLY[FRAME_HEADER_BYTES..].as_ptr(),
                    stitches_body,
                );
            }
            transport.consume_frame().unwrap();
            #[cfg(feature = "diagnostics")]
            {
                let counts = crate::diagnostics::snapshot().delta(before).unwrap();
                let header_copied = usize::from(split < FRAME_HEADER_BYTES) * FRAME_HEADER_BYTES;
                assert_eq!(
                    counts.tls_plaintext_bytes_copied,
                    u64::try_from(capacity + header_copied).unwrap()
                );
                assert_eq!(
                    counts.tls_plaintext_bytes_borrowed,
                    if stitches_body { 0 } else { 4 }
                );
            }
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            let frame = transport.frame().unwrap();
            assert_eq!((frame.tag, frame.body), (b'1', b"".as_slice()));
            transport.consume_frame().unwrap();
            assert_eq!(transport.read_buffer.capacity(), capacity);
        }
    }

    #[test]
    fn increasing_fragmented_frames_reuse_the_bounded_stitch_buffer() {
        const FRAMES: &[u8] = b"D\0\0\0\x08abcdD\0\0\0\x09abcdeD\0\0\0\x0aabcdef\
                               D\0\0\0\x0babcdefgD\0\0\0\x0cabcdefgh";
        static RECORDS: [MockRead; 10] = [
            MockRead::Chunk(6),
            MockRead::Chunk(3),
            MockRead::Chunk(6),
            MockRead::Chunk(4),
            MockRead::Chunk(6),
            MockRead::Chunk(5),
            MockRead::Chunk(6),
            MockRead::Chunk(6),
            MockRead::Chunk(6),
            MockRead::Chunk(7),
        ];
        let mut transport = BufferedTransport::new(
            FragmentedStream {
                bytes: FRAMES,
                offset: 0,
                end: 0,
                read_steps: RECORDS.iter(),
            },
            12,
            12,
            128,
        )
        .unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let mut backing = None;
        for body_len in 4..=8 {
            assert!(matches!(
                transport.poll_receive_frame(&mut cx),
                Poll::Ready(Ok(()))
            ));
            let frame = transport.frame().unwrap();
            assert_eq!(frame.tag, b'D');
            assert_eq!(frame.body, &b"abcdefgh"[..body_len]);
            transport.consume_frame().unwrap();
            let allocation = (
                transport.read_buffer.as_ptr(),
                transport.read_buffer.capacity(),
            );
            if body_len == 5 {
                assert!(allocation.1 >= 8);
                backing = Some(allocation);
            } else if let Some(backing) = backing {
                assert_eq!(allocation, backing);
            }
        }
    }

    #[test]
    fn split_header_errors_precede_receive_buffer_allocation() {
        use crate::protocol::ProtocolError;

        for (bytes, expected) in [
            (b"D\0\0\0\x03", ProtocolError::InvalidLength(3)),
            (
                b"D\0\0\0\x0c",
                ProtocolError::FrameTooLarge {
                    length: 12,
                    limit: 11,
                },
            ),
        ] {
            for split in 1..FRAME_HEADER_BYTES {
                let mut transport = BufferedTransport::new(
                    FragmentedStream {
                        bytes,
                        offset: 0,
                        end: split,
                        read_steps: [].iter(),
                    },
                    12,
                    11,
                    64,
                )
                .unwrap();
                let mut context = Context::from_waker(Waker::noop());
                assert!(matches!(
                    transport.poll_receive_frame(&mut context),
                    Poll::Ready(Err(Error::Protocol(error))) if error == expected
                ));
                assert_eq!(transport.read_buffer.capacity(), 0);
                assert!(transport.is_broken());
            }
        }
    }

    struct FlushGate {
        pending: Rc<Cell<bool>>,
        writes: Rc<Cell<usize>>,
        plaintext: &'static [u8],
    }

    #[test]
    fn a_pending_flush_cannot_be_repolled_on_a_foreign_runtime() {
        let owner = compio::runtime::Runtime::new().unwrap();
        let foreign = compio::runtime::Runtime::new().unwrap();
        let pending = Rc::new(Cell::new(true));
        let writes = Rc::new(Cell::new(0));
        let mut transport = owner
            .enter(|| {
                BufferedTransport::new(
                    FlushGate {
                        pending: pending.clone(),
                        writes: writes.clone(),
                        plaintext: b"",
                    },
                    5,
                    63,
                    64,
                )
            })
            .unwrap();
        transport.begin_send(vec![42]).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            owner
                .enter(|| transport.poll_receive_frame(&mut context))
                .is_pending()
        );
        assert_eq!(writes.get(), 1);
        pending.set(false);
        assert!(matches!(
            foreign.enter(|| transport.poll_receive_frame(&mut context)),
            Poll::Ready(Err(Error::InvalidInput(_)))
        ));
        assert!(matches!(
            foreign.enter(|| transport.poll_finish_send(&mut context)),
            Poll::Ready(Err(Error::InvalidInput(_)))
        ));
        assert!(!transport.write_complete);
        assert!(matches!(
            owner.enter(|| transport.poll_finish_send(&mut context)),
            Poll::Ready(Ok(()))
        ));
        assert!(
            owner
                .enter(|| transport.poll_receive_frame(&mut context))
                .is_pending()
        );
        assert!(matches!(
            foreign.enter(|| transport.poll_receive_frame(&mut context)),
            Poll::Ready(Err(Error::InvalidInput(_)))
        ));
    }
    impl AsyncWrite for FlushGate {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.set(self.writes.get() + 1);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.pending.get() {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }
    impl ManagedStream for FlushGate {
        fn plaintext(&mut self) -> io::Result<&[u8]> {
            if self.plaintext.is_empty() {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(self.plaintext)
            }
        }

        fn consume_plaintext(&mut self, bytes: usize) -> Result<(), Error> {
            self.plaintext = self.plaintext.get(bytes..).ok_or(Error::Broken)?;
            Ok(())
        }

        fn poll_plaintext(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        async fn dispose(self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn send_policy_controls_cached_replies_without_releasing_pending_flushes() {
        for policy in [SendPolicy::BeforeBufferedRead, SendPolicy::CoalesceBuffered] {
            let pending = Rc::new(Cell::new(false));
            let writes = Rc::new(Cell::new(0));
            let reply = b"Z\0\0\0\x05I";
            let mut transport = BufferedTransport::new(
                FlushGate {
                    pending: pending.clone(),
                    writes: writes.clone(),
                    plaintext: reply,
                },
                64,
                63,
                128,
            )
            .unwrap();
            assert_eq!(transport.send_policy(), SendPolicy::BeforeBufferedRead);
            transport.set_send_policy(policy).unwrap();
            transport.enable_send_queue(128).unwrap();
            assert!(transport.enqueue_send(b"first").unwrap());
            assert!(matches!(
                transport.set_send_policy(SendPolicy::BeforeBufferedRead),
                Err(Error::Busy)
            ));
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(transport.frame().unwrap().body, b"I");
            assert_eq!(
                writes.get(),
                usize::from(policy == SendPolicy::BeforeBufferedRead)
            );
            transport.consume_frame().unwrap();
            pending.set(true);
            assert!(transport.enqueue_send(b"second").unwrap());
            assert!(transport.poll_finish_send(&mut context).is_pending());
            let written = writes.get();
            assert!(!transport.write_complete);
            assert!(transport.enqueue_send(b"third").unwrap());
            transport.stream.plaintext = reply;
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(writes.get(), written);
            assert!(!transport.write_complete);
            assert!(transport.send_queue.has_data());
            assert!(matches!(transport.take_send_packet(), Err(Error::Busy)));
            pending.set(false);
            assert!(matches!(
                transport.poll_receive_frame(&mut context),
                Poll::Ready(Ok(()))
            ));
            let coalescing = policy == SendPolicy::CoalesceBuffered;
            assert_eq!(transport.send_queue.has_data(), coalescing);
            assert_eq!(writes.get(), written + usize::from(!coalescing));
            assert!(matches!(
                transport.poll_finish_send(&mut context),
                Poll::Ready(Ok(()))
            ));
            transport
                .set_send_policy(SendPolicy::CoalesceBuffered)
                .unwrap();
            transport.break_connection();
            assert!(matches!(
                transport.set_send_policy(SendPolicy::BeforeBufferedRead),
                Err(Error::Broken)
            ));
        }
    }

    #[test]
    fn a_complete_tls_frame_borrows_from_the_current_plaintext_chunk() {
        let reply = b"D\0\0\0\x08abcd";
        let mut transport = BufferedTransport::new(
            FragmentedStream {
                bytes: reply,
                offset: 0,
                end: reply.len(),
                read_steps: [].iter(),
            },
            32,
            31,
            128,
        )
        .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            transport.poll_receive_frame(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(transport.read_buffer.capacity(), 0);
        let frame = transport.frame().unwrap();
        assert_eq!(frame.body, b"abcd");
        assert_eq!(frame.body.as_ptr(), reply[5..].as_ptr());
    }
    #[test]
    fn accepted_plaintext_cannot_be_reused_until_flush_retires() {
        let pending = Rc::new(Cell::new(true));
        let writes = Rc::new(Cell::new(0));
        let mut transport = BufferedTransport::new(
            FlushGate {
                pending: pending.clone(),
                writes: writes.clone(),
                plaintext: b"",
            },
            64,
            63,
            1024,
        )
        .unwrap();
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"hello");
        let pointer = bytes.as_ptr();
        transport.begin_send(bytes).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(transport.poll_finish_send(&mut context).is_pending());
        assert!(matches!(transport.take_send_buffer(), Err(Error::Busy)));
        assert!(matches!(transport.start_send_queue(128), Err(Error::Busy)));
        assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
        assert!(matches!(transport.begin_send(vec![1]), Err(Error::Busy)));
        pending.set(false);
        assert!(matches!(
            transport.poll_finish_send(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            transport.poll_finish_send(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(writes.get(), 1);
        let reused = transport.take_send_buffer().unwrap();
        assert_eq!(reused.as_ptr(), pointer);
        assert!(reused.is_empty());
        assert_eq!(reused.capacity(), 128);
    }
    #[test]
    fn queued_plaintext_waits_for_the_previous_flush_before_promotion() {
        let pending = Rc::new(Cell::new(true));
        let writes = Rc::new(Cell::new(0));
        let mut transport = BufferedTransport::new(
            FlushGate {
                pending: pending.clone(),
                writes: writes.clone(),
                plaintext: b"",
            },
            64,
            63,
            1024,
        )
        .unwrap();
        transport.enable_send_queue(128).unwrap();
        assert!(transport.enqueue_send(b"first").unwrap());
        let mut context = Context::from_waker(Waker::noop());
        assert!(transport.poll_finish_send(&mut context).is_pending());
        assert_eq!(writes.get(), 1);
        assert!(transport.enqueue_send(b"second").unwrap());
        assert!(transport.poll_finish_send(&mut context).is_pending());
        assert_eq!(writes.get(), 1);
        pending.set(false);
        assert!(matches!(
            transport.poll_finish_send(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(writes.get(), 2);
        transport.disable_send_queue().unwrap();
        assert_eq!(transport.take_send_packet().unwrap(), b"second");
    }

    #[test]
    fn moved_window_packets_remain_owned_until_flush_and_trim_releases_all_backings() {
        let pending = Rc::new(Cell::new(true));
        let writes = Rc::new(Cell::new(0));
        let mut transport = BufferedTransport::new(
            FlushGate {
                pending: pending.clone(),
                writes: writes.clone(),
                plaintext: b"",
            },
            64,
            63,
            1024,
        )
        .unwrap();
        let mut scratch = transport.start_send_queue(128).unwrap();
        assert_eq!(scratch.capacity(), 0);
        scratch.extend_from_slice(b"first");
        let first_pointer = scratch.as_ptr();
        let first_capacity = scratch.capacity();
        assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
        assert!(scratch.is_empty());
        let mut context = Context::from_waker(Waker::noop());
        assert!(transport.poll_finish_send(&mut context).is_pending());
        assert_eq!(
            transport.write_buffer.as_ref().unwrap().as_ptr(),
            first_pointer
        );
        assert_eq!(writes.get(), 1);
        assert!(matches!(transport.start_send_queue(128), Err(Error::Busy)));
        assert!(matches!(transport.trim_send_buffers(), Err(Error::Busy)));
        scratch.extend_from_slice(b"second");
        let second_pointer = scratch.as_ptr();
        let second_capacity = scratch.capacity();
        assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
        transport.recycle_send_queue_buffer(scratch).unwrap();
        assert!(transport.poll_finish_send(&mut context).is_pending());
        assert_eq!(writes.get(), 1);
        assert_eq!(
            transport.write_buffer.as_ref().unwrap().as_ptr(),
            first_pointer
        );
        pending.set(false);
        assert!(matches!(
            transport.poll_finish_send(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(writes.get(), 2);
        assert_eq!(
            transport.write_buffer.as_ref().unwrap().as_ptr(),
            second_pointer
        );
        assert_eq!(transport.write_buffer.as_ref().unwrap(), b"second");
        transport.disable_send_queue().unwrap();
        assert_eq!(
            transport.trim_send_buffers().unwrap(),
            first_capacity + second_capacity
        );
        assert_eq!(transport.trim_send_buffers().unwrap(), 0);
        assert!(transport.write_buffer.is_none());
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
    }

    #[test]
    fn ordinary_buffered_send_retires_window_only_caches() {
        let writes = Rc::new(Cell::new(0));
        let mut transport = BufferedTransport::new(
            FlushGate {
                pending: Rc::new(Cell::new(false)),
                writes,
                plaintext: b"",
            },
            64,
            63,
            1024,
        )
        .unwrap();
        let mut scratch = transport.start_send_queue(64).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        for bytes in [b"first".as_slice(), b"second"] {
            scratch.extend_from_slice(bytes);
            assert!(transport.enqueue_send_packet(&mut scratch).unwrap());
            assert!(matches!(
                transport.poll_finish_send(&mut context),
                Poll::Ready(Ok(()))
            ));
        }
        scratch.try_reserve_exact(16).unwrap();
        transport.recycle_send_queue_buffer(scratch).unwrap();
        transport.disable_send_queue().unwrap();
        assert!((17..128).contains(&transport.send_queue.retained_capacity().unwrap()));
        transport.begin_send(b"normal".to_vec()).unwrap();
        assert_eq!(transport.send_queue.retained_capacity().unwrap(), 0);
        assert_eq!(transport.send_queue.available(), 0);
    }
}
