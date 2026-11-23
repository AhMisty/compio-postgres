//! PostgreSQL 的 TLS 握手、套接字适配与连接关闭。

use super::{
    CertificateDigest, POSTGRES_ALPN, TlsConfig, TlsInfo, TlsNegotiation, TlsVersion,
    certificate_digest,
};
use crate::Error;
#[cfg(unix)]
use crate::transport::unix_readiness::UnixReadiness;
use compio::net::TcpStream;
use futures_rustls::{TlsConnector, client::TlsStream};
use futures_util::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use std::{
    fmt, io,
    io::BufRead,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

// Windows 使用持有套接字引用的原生操作，关闭时等待这些引用释放。Unix 使用非阻塞就绪通知。
#[cfg(windows)]
#[path = "windows_io.rs"]
mod windows_io;

#[cfg(windows)]
use windows_io::WindowsTlsIo as TlsIo;

#[cfg(unix)]
type TlsIo = UnixReadiness<TcpStream>;

#[cfg(unix)]
impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_with(cx, |mut socket| io::Read::read(&mut socket, buf))
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_with(cx, |mut socket| io::Read::read_vectored(&mut socket, bufs))
    }
}

#[cfg(unix)]
impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_with(cx, |socket| {
            socket.send_with_flags(buf, crate::transport::send_flags().bits().cast_signed())
        })
    }

    #[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // 单段密文可直接发送，避免构造并传递 sendmsg 的消息头和向量。
        if let [buffer] = bufs {
            return self.poll_write(cx, buffer);
        }
        self.poll_write_with(cx, |socket| {
            socket
                .send_vectored_with_flags(bufs, crate::transport::send_flags().bits().cast_signed())
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_write(cx)
    }
}

const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

/// 数据库连接和取消通道共用的已验证 TLS 流。
pub struct TlsSession {
    stream: TlsStream<TlsIo>,
    info: TlsInfo,
    binding_digest: Option<CertificateDigest>,
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl TlsSession {
    pub(crate) fn info(&self) -> &TlsInfo {
        &self.info
    }

    pub(crate) fn plaintext(&mut self) -> io::Result<&[u8]> {
        self.stream.get_mut().1.reader().into_first_chunk()
    }

    pub(crate) fn consume_plaintext(&mut self, bytes: usize) {
        self.stream.get_mut().1.reader().consume(bytes);
    }

    /// 仅在已解密的字节已取尽时推进密文输入；记录通过认证后才可借用其明文。
    pub(crate) fn poll_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let (io, session) = self.stream.get_mut();
        match session.read_tls(&mut CiphertextRead { io, cx }) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
            Ok(_) => {}
        }
        match session.process_new_packets() {
            Ok(state) => Poll::Ready(Ok(state.plaintext_bytes_to_read())),
            Err(error) => {
                // 保留认证失败作为主错误，同时尽力发出 rustls 生成的告警。
                let _ = Pin::new(&mut self.stream).poll_flush(cx);
                Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)))
            }
        }
    }

    pub(crate) fn channel_binding(&self) -> Result<Vec<u8>, Error> {
        let digest = self.binding_digest.ok_or(Error::Broken)?;
        let leaf = self
            .stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(Error::Broken)?;
        digest.digest(leaf.as_ref())
    }

    /// 在共享的原生引用退出后关闭套接字。此路径也用于已损坏的会话，不发送 TLS close_notify。
    pub(crate) async fn dispose(self) -> Result<(), Error> {
        let (io, session) = self.stream.into_inner();
        drop(session);
        io.into_stream().close().await?;
        Ok(())
    }
}

struct CiphertextRead<'a, 'b, 'cx> {
    io: &'a mut TlsIo,
    cx: &'b mut Context<'cx>,
}

impl io::Read for CiphertextRead<'_, '_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_read(self.cx, buffer) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

pub(crate) async fn connect(socket: TcpStream, config: &TlsConfig) -> Result<TlsSession, Error> {
    let socket = prepare_io(socket, config.options.negotiation).await?;
    let stream = TlsConnector::from(config.config.clone())
        .connect_with(config.server_name.clone(), socket, |session| {
            session.set_buffer_limit(config.options.send_buffer_limit.map(NonZeroUsize::get));
        })
        .await?;
    let session = stream.get_ref().1;
    if config.options.negotiation == TlsNegotiation::Direct {
        validate_direct_alpn(session.alpn_protocol())?;
    }
    let version = match session.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => TlsVersion::Tls12,
        Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
        _ => {
            return Err(Error::Unsupported(
                "the negotiated TLS version is unsupported",
            ));
        }
    };
    let cipher_suite = session.negotiated_cipher_suite().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the TLS handshake has no cipher suite",
        )
    })?;
    let binding_digest = session
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| certificate_digest(certificate.as_ref()))
        .transpose()?
        .flatten();
    let info = TlsInfo {
        version,
        negotiation: config.options.negotiation,
        cipher_suite: cipher_suite.suite(),
        channel_binding_available: binding_digest.is_some(),
    };
    Ok(TlsSession {
        stream,
        info,
        binding_digest,
    })
}

#[cfg(windows)]
async fn prepare_io(mut socket: TcpStream, negotiation: TlsNegotiation) -> Result<TlsIo, Error> {
    if negotiation == TlsNegotiation::SslRequest {
        // 建立缓冲适配器前只读取一个协商响应字节，避免消耗后续 TLS 记录。
        let compio::BufResult(result, _) =
            compio::io::AsyncWriteExt::write_all(&mut socket, SSL_REQUEST).await;
        result?;
        let compio::BufResult(result, response) =
            compio::io::AsyncRead::read(&mut socket, [0; 1]).await;
        if result? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing SSLRequest response",
            )
            .into());
        }
        validate_ssl_response(response[0])?;
    }
    Ok(TlsIo::new(socket))
}

#[cfg(unix)]
async fn prepare_io(socket: TcpStream, negotiation: TlsNegotiation) -> Result<TlsIo, Error> {
    // 进入就绪模式前没有在途原生接收。SSLRequest 响应只读一个字节，后续握手数据留给 TLS 层。
    let mut socket = TlsIo::new(socket)?;
    if negotiation == TlsNegotiation::SslRequest {
        socket.write_all(&SSL_REQUEST).await?;
        let mut response = [0];
        socket.read_exact(&mut response).await?;
        validate_ssl_response(response[0])?;
    }
    Ok(socket)
}

impl AsyncRead for TlsSession {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for TlsSession {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 接受明文后仍须 poll_flush 完成传输的发送边界。
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}

fn validate_ssl_response(response: u8) -> Result<(), Error> {
    match response {
        b'S' => Ok(()),
        b'N' => Err(Error::Unsupported(
            "the endpoint refused the requested TLS connection",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid unauthenticated TLS negotiation response",
        )
        .into()),
    }
}

fn validate_direct_alpn(selected: Option<&[u8]>) -> Result<(), Error> {
    if selected != Some(POSTGRES_ALPN) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Direct TLS did not negotiate PostgreSQL ALPN",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tls_socket_uses_scalar_and_vectored_writes_and_reports_epipe() {
        use std::io::Read;
        use std::time::Duration;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let runtime = compio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let socket = TcpStream::from_std(client).unwrap();
            let mut io = TlsIo::new(socket).unwrap();
            io.write_all(b"a").await.unwrap();
            let single = [io::IoSlice::new(b"b")];
            assert_eq!(io.write_vectored(&single).await.unwrap(), 1);
            let iov = [io::IoSlice::new(b"c"), io::IoSlice::new(b"d")];
            assert_eq!(io.write_vectored(&iov).await.unwrap(), 2);
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"abcd");

            rustix::net::shutdown(io.socket(), rustix::net::Shutdown::Write).unwrap();
            assert_eq!(
                io.write(b"e").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                io.write_vectored(&single).await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe,
            );
            assert_eq!(
                io.write_vectored(&iov).await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe,
            );
        });
    }

    #[test]
    fn ssl_request_accepts_only_the_affirmative_single_byte() {
        assert!(validate_ssl_response(b'S').is_ok());
        assert!(matches!(
            validate_ssl_response(b'N'),
            Err(Error::Unsupported(_))
        ));
        for response in [b'E', b'G', 0, 255] {
            assert!(matches!(validate_ssl_response(response), Err(Error::Io(_))));
        }
    }

    #[test]
    fn direct_tls_requires_the_exact_postgresql_alpn() {
        assert!(validate_direct_alpn(Some(b"postgresql")).is_ok());
        assert!(validate_direct_alpn(None).is_err());
        assert!(validate_direct_alpn(Some(b"h2")).is_err());
        assert!(validate_direct_alpn(Some(b"postgresql\0")).is_err());
    }
}
