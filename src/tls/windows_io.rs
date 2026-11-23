//! 用 Compio 完成式操作持有 Windows TLS 密文缓冲区。

use std::{
    future::Future,
    io::{self, IoSlice},
    net::Shutdown,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{
    BufResult,
    buf::{IntoInner, Slice},
    driver::{
        ErrorExt, SharedFd, ToSharedFd,
        op::{Recv, RecvFlags, Send, SendFlags},
    },
    net::TcpStream,
    runtime::{Submit, submit},
};
use futures_util::io::{AsyncRead, AsyncWrite};
use socket2::Socket;

// TLS 1.2 密文长度的上限为 2^14 + 2048，另有 5 字节记录头。
const BUFFER_BYTES: usize = 16 * 1024 + 2048 + 5;

type ReadOperation = Submit<Recv<Vec<u8>, SharedFd<Socket>>>;
type WriteOperation = Submit<Send<Slice<Vec<u8>>, SharedFd<Socket>>>;

pub(super) struct WindowsTlsIo {
    socket: TcpStream,
    reads: Option<ReadOperation>,
    read_buffer: Option<Vec<u8>>,
    read_offset: usize,
    read_end: usize,
    eof: bool,
    writes: Option<WriteOperation>,
    write_buffer: Option<Vec<u8>>,
    write_offset: usize,
    write_closed: bool,
}

impl WindowsTlsIo {
    pub(super) fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            reads: None,
            read_buffer: None,
            read_offset: 0,
            read_end: 0,
            eof: false,
            writes: None,
            write_buffer: None,
            write_offset: 0,
            write_closed: false,
        }
    }

    pub(super) fn into_stream(self) -> TcpStream {
        self.socket
    }

    fn poll_write_slices<'a>(
        &mut self,
        cx: &mut Context<'_>,
        buffers: impl Iterator<Item = &'a [u8]>,
    ) -> Poll<io::Result<usize>> {
        let mut buffers = buffers.filter(|bytes| !bytes.is_empty()).peekable();
        if buffers.peek().is_none() {
            return Poll::Ready(Ok(0));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.writes.is_some()
            || self
                .write_buffer
                .as_ref()
                .is_some_and(|buffer| buffer.len() == BUFFER_BYTES)
        {
            ready!(Pin::new(&mut *self).poll_flush(cx))?;
        }
        if self.write_buffer.is_none() {
            self.write_buffer = Some(allocate_buffer()?);
        }
        let buffer = self
            .write_buffer
            .as_mut()
            .ok_or(io::ErrorKind::InvalidData)?;
        let start = buffer.len();
        for bytes in buffers {
            let available = BUFFER_BYTES - buffer.len();
            buffer.extend_from_slice(bytes.get(..available).unwrap_or(bytes));
            if buffer.len() == BUFFER_BYTES {
                break;
            }
        }
        let copied = buffer.len() - start;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::tls_ciphertext_write_copied(copied);
        Poll::Ready(Ok(copied))
    }
}

impl AsyncRead for WindowsTlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 握手层可能已交出整批密文并转为读等待。继续发送短写尾部，同时保留接收进展。
        if self.writes.is_some()
            && let Poll::Ready(Err(error)) = self.as_mut().poll_flush(cx)
        {
            return Poll::Ready(Err(error));
        }
        if self.eof {
            return Poll::Ready(Ok(0));
        }
        while self.read_offset == self.read_end {
            if self.reads.is_none() {
                let buffer = match self.read_buffer.take() {
                    Some(buffer) => buffer,
                    None => {
                        let mut buffer = allocate_buffer()?;
                        buffer.resize(BUFFER_BYTES, 0);
                        buffer
                    }
                };
                self.reads = Some(submit(Recv::new(
                    self.socket.to_shared_fd(),
                    buffer,
                    RecvFlags::empty(),
                )));
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::receive_attempt();
            }
            let operation = self.reads.as_mut().ok_or(io::ErrorKind::InvalidData)?;
            let BufResult(result, operation) = ready!(Pin::new(operation).poll(cx));
            self.reads.take();
            let buffer = operation.into_inner();
            let count = match result {
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && !error.is_cancelled() =>
                {
                    self.read_buffer = Some(buffer);
                    continue;
                }
                result => result?,
            };
            if count > buffer.len() {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.read_buffer = Some(buffer);
            self.read_offset = 0;
            self.read_end = count;
            self.eof = count == 0;
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::received(count);
        }
        let buffer = self
            .read_buffer
            .as_ref()
            .ok_or(io::ErrorKind::InvalidData)?;
        let remaining = buffer
            .get(self.read_offset..self.read_end)
            .ok_or(io::ErrorKind::InvalidData)?;
        let count = remaining.len().min(output.len());
        let input = remaining.get(..count).ok_or(io::ErrorKind::InvalidData)?;
        let output = output.get_mut(..count).ok_or(io::ErrorKind::InvalidData)?;
        output.copy_from_slice(input);
        self.read_offset += count;
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::tls_ciphertext_read_copied(count);
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for WindowsTlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, std::iter::once(bytes))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_slices(cx, buffers.iter().map(|bytes| &**bytes))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.writes.is_none() {
                let Some(mut buffer) = self.write_buffer.take() else {
                    return Poll::Ready(Ok(()));
                };
                let end = buffer.len();
                if self.write_offset == end {
                    buffer.clear();
                    self.write_buffer = Some(buffer);
                    self.write_offset = 0;
                    return Poll::Ready(Ok(()));
                }
                self.writes = Some(submit(Send::new(
                    self.socket.to_shared_fd(),
                    compio::buf::IoBuf::slice(buffer, self.write_offset..end),
                    SendFlags::empty(),
                )));
                #[cfg(feature = "diagnostics")]
                crate::diagnostics::send_attempt();
            }
            let operation = self.writes.as_mut().ok_or(io::ErrorKind::InvalidData)?;
            let BufResult(result, operation) = ready!(Pin::new(operation).poll(cx));
            self.writes.take();
            let buffer = operation.into_inner().into_inner();
            let count = match result {
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && !error.is_cancelled() =>
                {
                    self.write_buffer = Some(buffer);
                    continue;
                }
                result => result?,
            };
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            if count > buffer.len() - self.write_offset {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.write_offset += count;
            self.write_buffer = Some(buffer);
            #[cfg(feature = "diagnostics")]
            crate::diagnostics::sent(count);
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        if !self.write_closed {
            self.socket.to_shared_fd().shutdown(Shutdown::Write)?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

fn allocate_buffer() -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(BUFFER_BYTES)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::{
        runtime::{CancelToken, FutureExt, Runtime},
        time::timeout,
    };
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use std::{
        future::poll_fn,
        io::{Read, Write},
        net::{TcpListener, TcpStream as StdTcpStream},
        time::Duration,
    };

    fn pair() -> (StdTcpStream, StdTcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        (client, peer)
    }

    #[test]
    fn dropping_the_read_waiter_keeps_its_original_compio_cancel_token() {
        let (socket, mut peer) = pair();
        Runtime::new().unwrap().block_on(async {
            let mut io = WindowsTlsIo::new(TcpStream::from_std(socket).unwrap());
            let mut output = [0];
            let token = CancelToken::new();
            {
                let mut waiter = std::pin::pin!(io.read(&mut output).with_cancel(token.clone()));
                poll_fn(|cx| {
                    assert!(waiter.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(io.reads.is_some());
            assert!(io.read_buffer.is_none());
            token.cancel();
            let result = timeout(Duration::from_secs(2), io.read(&mut output))
                .await
                .unwrap();
            assert!(
                matches!(&result, Err(error) if compio::driver::ErrorExt::is_cancelled(error)),
                "{result:?}"
            );
            assert!(io.reads.is_none());
            peer.write_all(b"x").unwrap();
            timeout(Duration::from_secs(2), io.read_exact(&mut output))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(output, *b"x");
        });
    }

    #[test]
    fn taking_the_stream_retires_its_pending_receive_before_close() {
        let (socket, mut peer) = pair();
        Runtime::new().unwrap().block_on(async {
            let mut io = WindowsTlsIo::new(TcpStream::from_std(socket).unwrap());
            {
                let mut byte = [0];
                let mut read = std::pin::pin!(io.read(&mut byte));
                poll_fn(|cx| {
                    assert!(read.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(io.reads.is_some());
            timeout(Duration::from_secs(2), io.into_stream().close())
                .await
                .unwrap()
                .unwrap();
        });
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn bounded_ciphertext_writes_preserve_every_byte_across_partial_acceptance() {
        let (socket, mut peer) = pair();
        let input = vec![7; 2 * BUFFER_BYTES + 3];
        let received = std::thread::spawn(move || {
            let mut output = vec![0; 2 * BUFFER_BYTES + 3];
            peer.read_exact(&mut output).unwrap();
            output
        });
        Runtime::new().unwrap().block_on(async {
            let mut io = WindowsTlsIo::new(TcpStream::from_std(socket).unwrap());
            timeout(Duration::from_secs(2), io.write_all(&input))
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(2), io.flush())
                .await
                .unwrap()
                .unwrap();
            assert!(io.writes.is_none());
            assert!(io.write_buffer.as_ref().unwrap().is_empty());
        });
        assert_eq!(received.join().unwrap(), input);
    }

    #[test]
    fn a_read_progresses_an_incomplete_handshake_write() {
        let (socket, mut peer) = pair();
        let expected = b"client handshake flight";
        let worker = std::thread::spawn(move || {
            let mut flight = [0; 23];
            peer.read_exact(&mut flight).unwrap();
            assert_eq!(&flight, expected);
            peer.write_all(b"s").unwrap();
        });
        Runtime::new().unwrap().block_on(async {
            let mut io = WindowsTlsIo::new(TcpStream::from_std(socket).unwrap());
            // 只提交首字节，使完成结果确定短于这次写入的完整缓冲区。
            let prefix = compio::buf::IoBuf::slice(expected.to_vec(), ..1);
            io.writes = Some(submit(Send::new(
                io.socket.to_shared_fd(),
                prefix,
                SendFlags::empty(),
            )));
            let mut response = [0];
            timeout(Duration::from_secs(2), io.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, *b"s");
            assert!(io.writes.is_none());
            assert!(io.write_buffer.as_ref().unwrap().is_empty());
        });
        worker.join().unwrap();
    }
}
