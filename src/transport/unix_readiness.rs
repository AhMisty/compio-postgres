use std::{
    io,
    task::{Context, Poll, ready},
};

use compio::runtime::fd::PollFd;

use super::NativeStream;
use socket2::Socket;

/// 直接套接字 I/O 保留原就绪注册，直到消费其结果。
pub(crate) struct UnixReadiness<S: NativeStream> {
    stream: S,
    fd: PollFd<Socket>,
    read_waiting: bool,
    write_waiting: bool,
}

impl<S: NativeStream> UnixReadiness<S> {
    pub(crate) fn new(stream: S) -> io::Result<Self> {
        let socket = stream.to_shared_fd();
        socket.set_nonblocking(true)?;
        Ok(Self {
            stream,
            fd: PollFd::from_shared_fd(socket)?,
            read_waiting: false,
            write_waiting: false,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn socket(&self) -> &S {
        &self.stream
    }

    #[cfg(feature = "tls")]
    pub(crate) fn poll_shutdown_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::io::AsyncWrite::poll_close(std::pin::Pin::new(&mut self.fd), cx)
    }

    #[cfg(any(target_os = "linux", feature = "tls"))]
    pub(crate) fn into_stream(self) -> S {
        self.stream
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn is_write_waiting(&self) -> bool {
        self.write_waiting
    }

    pub(crate) fn poll_read_with<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut read: impl FnMut(&Socket) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        poll_with(
            &mut self.read_waiting,
            cx,
            |cx| self.fd.poll_read_ready(cx),
            || read(&self.fd),
        )
    }

    pub(crate) fn poll_write_with<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut write: impl FnMut(&Socket) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        poll_with(
            &mut self.write_waiting,
            cx,
            |cx| self.fd.poll_write_ready(cx),
            || write(&self.fd),
        )
    }
}

fn poll_with<R>(
    waiting: &mut bool,
    cx: &mut Context<'_>,
    mut poll_ready: impl FnMut(&mut Context<'_>) -> Poll<io::Result<()>>,
    mut operate: impl FnMut() -> io::Result<R>,
) -> Poll<io::Result<R>> {
    loop {
        if *waiting {
            match ready!(poll_ready(cx)) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            }
            *waiting = false;
        }
        match operate() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => *waiting = true,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return Poll::Ready(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::{net::UnixStream, runtime::Runtime};
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    #[test]
    fn retries_interruptions_without_losing_the_registered_wait() {
        let mut waiting = false;
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut readiness = [
            Poll::Ready(Err(io::ErrorKind::Interrupted.into())),
            Poll::Pending,
            Poll::Ready(Ok(())),
        ]
        .into_iter();
        let mut operations = [
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::ErrorKind::WouldBlock.into()),
            Ok(7),
        ]
        .into_iter();
        let mut ready = |_: &mut Context<'_>| readiness.next().unwrap();
        let mut operate = || operations.next().unwrap();
        assert!(poll_with(&mut waiting, &mut context, &mut ready, &mut operate).is_pending());
        assert!(waiting);
        assert!(matches!(
            poll_with(&mut waiting, &mut context, ready, operate),
            Poll::Ready(Ok(7))
        ));
        assert!(!waiting);
    }

    #[test]
    fn pending_registration_delivers_its_error_before_another_read_or_write() {
        let mut waiting = false;
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut attempts = 0;
        let mut operation = || -> io::Result<()> {
            attempts += 1;
            if attempts == 1 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        };
        assert!(
            poll_with(
                &mut waiting,
                &mut context,
                |_| Poll::Pending,
                &mut operation
            )
            .is_pending()
        );
        let result = poll_with(
            &mut waiting,
            &mut context,
            |_| Poll::Ready(Err(io::ErrorKind::PermissionDenied.into())),
            &mut operation,
        );
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert_eq!(attempts, 1);
    }

    #[test]
    fn new_enables_nonblocking_on_the_same_socket() {
        let runtime = Runtime::new().unwrap();
        runtime.enter(|| {
            let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let stream = UnixStream::from_std(socket).unwrap();
            let fd = std::os::fd::AsFd::as_fd(&stream);
            let flags = fcntl_getfl(fd).unwrap() - OFlags::NONBLOCK;
            fcntl_setfl(fd, flags).unwrap();

            let _readiness = UnixReadiness::new(stream.clone()).unwrap();

            assert_eq!(fcntl_getfl(fd).unwrap(), flags | OFlags::NONBLOCK);
        });
    }
}
