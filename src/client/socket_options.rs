//! TCP 数据连接的 socket 设置。

use std::net::SocketAddr;

use compio::net::TcpStream;
#[cfg(target_os = "linux")]
use compio::{driver::ToSharedFd, net::TcpSocket};

use crate::{Error, transport::SendPolicy};

/// 用于 TCP 数据连接的 socket 和传输配置。
/// 独立取消连接使用系统 socket 设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpOptions {
    pub send_policy: SendPolicy,
    pub no_delay: TcpNoDelay,
    #[cfg(target_os = "linux")]
    pub(crate) receive_buffer: TcpReceiveBufferPolicy,
}

impl TcpOptions {
    pub const fn new(no_delay: TcpNoDelay) -> Self {
        Self {
            send_policy: SendPolicy::BeforeBufferedRead,
            no_delay,
            #[cfg(target_os = "linux")]
            receive_buffer: TcpReceiveBufferPolicy::SystemManaged,
        }
    }

    pub const fn with_send_policy(mut self, policy: SendPolicy) -> Self {
        self.send_policy = policy;
        self
    }
}

/// Linux 数据连接的内核接收缓冲设置，仅在显式引入专家扩展时可用。
#[cfg(target_os = "linux")]
pub trait TcpOptionsExt {
    /// 在 TCP 握手前应用该策略。独立取消连接仍使用系统默认设置。
    fn with_receive_buffer(self, policy: TcpReceiveBufferPolicy) -> Self;
}

#[cfg(target_os = "linux")]
impl TcpOptionsExt for TcpOptions {
    fn with_receive_buffer(mut self, policy: TcpReceiveBufferPolicy) -> Self {
        self.receive_buffer = policy;
        self
    }
}

/// 指定数据连接上 TCP_NODELAY 的设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpNoDelay {
    /// 沿用 socket 当前配置。
    SystemManaged,
    Enabled,
    Disabled,
}

impl TcpNoDelay {
    fn apply(self, socket: &TcpStream) -> Result<(), Error> {
        match self {
            Self::SystemManaged => {}
            Self::Enabled => socket.set_nodelay(true)?,
            Self::Disabled => socket.set_nodelay(false)?,
        }
        Ok(())
    }
}

pub(super) struct ConnectedTcp {
    pub(super) stream: TcpStream,
    #[cfg(target_os = "linux")]
    pub(super) receive_buffer_snapshot: Option<TcpReceiveBufferSnapshot>,
}

pub(super) async fn connect_tcp(
    endpoint: SocketAddr,
    no_delay: TcpNoDelay,
    #[cfg(target_os = "linux")] receive_buffer: TcpReceiveBufferPolicy,
) -> Result<ConnectedTcp, Error> {
    #[cfg(target_os = "linux")]
    let (stream, receive_buffer_snapshot) = receive_buffer.connect(endpoint).await?;
    #[cfg(not(target_os = "linux"))]
    let stream = TcpStream::connect(endpoint).await?;
    no_delay.apply(&stream)?;
    Ok(ConnectedTcp {
        stream,
        #[cfg(target_os = "linux")]
        receive_buffer_snapshot,
    })
}

#[cfg(test)]
pub(super) const TEST_TCP_OPTIONS: TcpOptions = TcpOptions::new(TcpNoDelay::Enabled);

#[cfg(test)]
#[test]
fn tcp_no_delay_changes_the_socket_only_when_requested() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        for (policy, enabled) in [(TcpNoDelay::Enabled, true), (TcpNoDelay::Disabled, false)] {
            policy.apply(&socket).unwrap();
            assert_eq!(socket.nodelay().unwrap(), enabled);
            TcpNoDelay::SystemManaged.apply(&socket).unwrap();
            assert_eq!(socket.nodelay().unwrap(), enabled);
        }
        socket.close().await.unwrap();
    });
}

/// Linux TCP 数据连接的 `SO_RCVBUF` 设置，在 TCP 握手前应用一次。
/// 应用层的 [`crate::WireLimits::receive_capacity`] 独立生效，取消连接使用系统默认设置。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpReceiveBufferPolicy {
    /// 沿用内核当前设置，Linux 可以按自动调优策略增大接收缓冲。
    SystemManaged,
    /// 通过 `SO_RCVBUF` 请求指定字节数，范围为 `1..=i32::MAX`。
    /// Linux 会关闭此 socket 的自动调优，并可能限幅；内核读回值通常包含双倍记账，可通过快照查看。
    /// 它不是实际 TCP 通告窗口或进程 RSS 上限。
    RequestBytes { bytes: usize },
}

/// 显式设置 TCP 接收缓冲后、TLS 与 PostgreSQL startup 前的内核读回值。
/// `actual_bytes_before_startup` 包含内核记账，快照不持有 socket。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpReceiveBufferSnapshot {
    pub requested_bytes: usize,
    pub actual_bytes_before_startup: usize,
}

#[cfg(target_os = "linux")]
impl TcpReceiveBufferPolicy {
    pub(super) fn validate(self) -> Result<(), Error> {
        if let Self::RequestBytes { bytes } = self {
            Self::socket_request(bytes)?;
        }
        Ok(())
    }

    fn socket_request(bytes: usize) -> Result<u32, Error> {
        i32::try_from(bytes)
            .ok()
            .filter(|bytes| *bytes > 0)
            .map(i32::cast_unsigned)
            .ok_or(Error::InvalidInput(
                "TCP receive-buffer request must be within 1..=i32::MAX bytes",
            ))
    }

    async fn connect(
        self,
        endpoint: SocketAddr,
    ) -> Result<(TcpStream, Option<TcpReceiveBufferSnapshot>), Error> {
        let Self::RequestBytes { bytes } = self else {
            return Ok((TcpStream::connect(endpoint).await?, None));
        };
        let bytes_for_socket = Self::socket_request(bytes)?;
        let socket = if endpoint.is_ipv4() {
            TcpSocket::new_v4().await?
        } else {
            TcpSocket::new_v6().await?
        };
        // TCP 握手前设置缓冲区，使内核能据此选择窗口缩放。
        socket.set_recv_buffer_size(bytes_for_socket)?;
        let stream = socket.connect(endpoint).await?;
        let snapshot = TcpReceiveBufferSnapshot {
            requested_bytes: bytes,
            actual_bytes_before_startup: stream.to_shared_fd().recv_buffer_size()?,
        };
        Ok((stream, Some(snapshot)))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::client::{
        AuthenticationPolicy, TcpConfig, TcpConnection, TcpReadinessConnection, WireLimits,
    };
    use std::{io::Read, net::TcpListener, time::Duration};

    #[test]
    fn requests_reject_zero_and_integer_overflow_without_a_socket() {
        assert!(TcpReceiveBufferPolicy::SystemManaged.validate().is_ok());
        assert!(
            TcpReceiveBufferPolicy::RequestBytes { bytes: 1 }
                .validate()
                .is_ok()
        );
        assert!(
            TcpReceiveBufferPolicy::RequestBytes {
                bytes: usize::try_from(i32::MAX).unwrap(),
            }
            .validate()
            .is_ok()
        );
        for bytes in [0, usize::try_from(i32::MAX).unwrap() + 1, usize::MAX] {
            assert!(matches!(
                TcpReceiveBufferPolicy::RequestBytes { bytes }.validate(),
                Err(Error::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn invalid_requests_fail_before_native_readiness_or_tls_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let limits = WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 128,
        };
        let check = async {
            for bytes in [0, usize::try_from(i32::MAX).unwrap() + 1] {
                let policy = TcpReceiveBufferPolicy::RequestBytes { bytes };
                let config = TcpConfig::plaintext(
                    endpoint,
                    "test",
                    "test",
                    AuthenticationPolicy::AllowAuthenticationOk,
                    limits,
                    TEST_TCP_OPTIONS.with_receive_buffer(policy),
                );
                assert!(matches!(
                    TcpConnection::connect(config.clone()).await,
                    Err(Error::InvalidInput(_))
                ));
                assert!(matches!(
                    TcpReadinessConnection::connect(config).await,
                    Err(Error::InvalidInput(_))
                ));
                #[cfg(feature = "tls")]
                {
                    use crate::tls::{
                        TlsConfig, TlsNegotiation, TlsOptions, TlsResumption, TlsVersions,
                    };
                    let tls = TlsConfig::from_ca_pem(
                        "localhost",
                        include_bytes!("../../tests/fixtures/tls/sha256.pem"),
                        TlsOptions {
                            negotiation: TlsNegotiation::SslRequest,
                            versions: TlsVersions::Tls13,
                            resumption: TlsResumption::Disabled,
                            send_buffer_limit: None,
                        },
                    )
                    .unwrap();
                    let secure = TcpConfig::tls(
                        endpoint,
                        "test",
                        "test",
                        AuthenticationPolicy::AllowAuthenticationOk,
                        limits,
                        tls,
                        TEST_TCP_OPTIONS.with_receive_buffer(policy),
                    );
                    assert!(matches!(
                        crate::client::TlsConnection::connect(secure).await,
                        Err(Error::InvalidInput(_))
                    ));
                }
            }
        };
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(compio::time::timeout(
                std::time::Duration::from_secs(5),
                check,
            ))
            .expect("无效接收缓冲配置应在建连前返回");
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn policy_readback_preserves_system_default_and_does_not_retain_a_socket_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).unwrap(), 0);
            }
        });
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let system = connect_tcp(
                endpoint,
                TcpNoDelay::SystemManaged,
                TcpReceiveBufferPolicy::SystemManaged,
            )
            .await
            .unwrap();
            assert!(system.receive_buffer_snapshot.is_none());
            system.stream.close().await.unwrap();
            let configured = connect_tcp(
                endpoint,
                TcpNoDelay::Enabled,
                TcpReceiveBufferPolicy::RequestBytes { bytes: 256 * 1024 },
            )
            .await
            .unwrap();
            let explicit = configured.receive_buffer_snapshot.unwrap();
            assert!(configured.stream.nodelay().unwrap());
            assert_eq!(explicit.requested_bytes, 256 * 1024);
            assert_eq!(
                explicit.actual_bytes_before_startup,
                configured.stream.to_shared_fd().recv_buffer_size().unwrap()
            );
            assert_ne!(explicit.actual_bytes_before_startup, 0);
            // 保持快照存活再关闭连接，验证快照不阻碍 FD 释放。
            compio::time::timeout(Duration::from_secs(5), configured.stream.close())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(explicit.requested_bytes, 256 * 1024);
        });
        peer.join().unwrap();
    }
}
