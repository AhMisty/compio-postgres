use crate::transport::WireOps;
use std::{
    cell::Cell,
    rc::{Rc, Weak},
    task::Waker,
};

use compio::{
    BufResult,
    buf::IoBuf,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    runtime::Runtime,
};

use super::{Endpoint, Session, protocol, protocol_error};
use crate::{
    Error,
    transport::{NativeStream, WireTransport},
};

struct CancelRequest {
    endpoint: Endpoint,
    owner: Option<Waker>,
    process_id: i32,
    key: Rc<[u8]>,
    state: Cell<CancelState>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CancelState {
    Available,
    Requested,
    Expired,
}

/// 同一 worker 内针对一个已提交查询的取消句柄。
/// 查询可继续执行；观察到 Ready 或释放会话时，尚未使用的句柄失效。
pub struct CancelHandle(Weak<CancelRequest>);

impl CancelHandle {
    /// 永久禁止原连接复用，通过独立连接发送取消请求。
    /// 成功表示取消连接已收到对端 EOF。原套接字仍由会话持有者负责关闭。
    /// 若原查询尚未开始 I/O，随后驱动它会在本地返回 Interrupted；已开始 I/O 的查询仍须观察其结果。
    pub async fn request_cancel_and_invalidate(self) -> Result<(), Error> {
        let request = self.0.upgrade().ok_or(stale_request())?;
        super::poll_on_worker(
            std::pin::pin!(async {
                if request.state.get() != CancelState::Available {
                    return Err(stale_request());
                }
                request.state.set(CancelState::Requested);
                request
                    .endpoint
                    .send_cancel(request.process_id, &request.key)
                    .await
            }),
            || require_runtime(request.owner.as_ref()),
        )
        .await
    }
}

pub(super) struct CancelFence(Rc<CancelRequest>);

impl CancelFence {
    pub(super) fn new<T: WireTransport>(session: &Session<T>) -> Result<Self, Error> {
        let key = session
            .cancel_key
            .as_ref()
            .ok_or(protocol::ProtocolError::InvalidCancelKeyLength(0))?;
        Ok(Self(Rc::new(CancelRequest {
            endpoint: session.endpoint.clone(),
            owner: session.transport.owner_waker().cloned(),
            process_id: session.info.process_id,
            key: Rc::clone(key),
            state: Cell::new(CancelState::Available),
        })))
    }

    pub(super) fn handle(&self) -> CancelHandle {
        CancelHandle(Rc::downgrade(&self.0))
    }

    pub(super) fn expire(&self) {
        if self.0.state.get() == CancelState::Available {
            self.0.state.set(CancelState::Expired);
        }
    }

    pub(super) fn requested(&self) -> bool {
        self.0.state.get() == CancelState::Requested
    }
}

fn require_runtime(owner: Option<&Waker>) -> Result<(), Error> {
    if Runtime::try_with_current(|runtime| {
        owner.is_none_or(|owner| owner.will_wake(&runtime.waker()))
    })
    .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(Error::InvalidInput(
            "cancel must run inside the owning Compio runtime",
        ))
    }
}

fn stale_request() -> Error {
    Error::InvalidInput("the query has completed or cancellation was already requested")
}

impl Endpoint {
    async fn send_cancel(&self, process_id: i32, secret_key: &[u8]) -> Result<(), Error> {
        let header = protocol::cancel_header(process_id, secret_key)?;
        let mut packet = [0; protocol::CANCEL_HEADER_BYTES + protocol::MAX_CANCEL_KEY_LEN];
        let (header_bytes, payload) = packet.split_at_mut(header.len());
        let payload = payload.get_mut(..secret_key.len()).ok_or(Error::Broken)?;
        header_bytes.copy_from_slice(&header);
        payload.copy_from_slice(secret_key);
        let length = header.len() + secret_key.len();
        let packet = packet.slice(..length);
        match self {
            Self::Tcp(endpoint) => {
                send_native_cancel(TcpStream::connect(endpoint).await?, packet).await
            }
            #[cfg(unix)]
            Self::Unix(path) => {
                send_native_cancel(compio::net::UnixStream::connect(path).await?, packet).await
            }
            #[cfg(feature = "tls")]
            Self::Tls(endpoint, config) => {
                use futures_util::io::{AsyncReadExt, AsyncWriteExt};

                let socket = TcpStream::connect(endpoint).await?;
                let mut stream = crate::tls::connect(socket, config).await?;
                stream.write_all(&packet).await?;
                stream.flush().await?;
                check_cancel_eof(stream.read(&mut [0]).await?)?;
                stream.dispose().await
            }
        }
    }
}

async fn send_native_cancel<S: NativeStream + AsyncRead + AsyncWrite>(
    mut socket: S,
    packet: impl IoBuf,
) -> Result<(), Error> {
    let BufResult(result, _) = socket.write_all(packet).await;
    result?;
    let BufResult(result, _) = socket.read([0]).await;
    check_cancel_eof(result?)?;
    socket.close_native().await?;
    Ok(())
}

fn check_cancel_eof(bytes_read: usize) -> Result<(), Error> {
    if bytes_read == 0 {
        Ok(())
    } else {
        Err(protocol_error(
            "the cancellation route returned unexpected data",
        ))
    }
}

pub(crate) struct CancelRetirement {
    pub(crate) request: Result<(), Error>,
    pub(crate) retirement: Result<(), Error>,
}

impl CancelRetirement {
    pub(crate) fn into_result(self) -> Result<(), Error> {
        match (self.request, self.retirement) {
            (request, Err(retirement)) => Err(Error::CancelRetirement {
                request: request.err().map(Box::new),
                retirement: Box::new(retirement),
            }),
            (request, Ok(())) => request.map_err(|error| Error::CancelRequest(Box::new(error))),
        }
    }
}

impl<T: WireTransport> Session<T> {
    /// 经原端点发送取消并释放原连接。
    /// 成功表示取消连接收到 EOF，原 socket 已在本地释放。
    /// [`Error::CancelRequest`] 表示发送失败但原 socket 已释放，[`Error::CancelRetirement`] 表示释放未确认。
    /// SQL 的结果仍须单独判断。
    pub async fn request_cancel_and_discard(self) -> Result<(), Error> {
        self.cancel_and_retire().await?.into_result()
    }

    pub(crate) async fn cancel_and_retire(self) -> Result<CancelRetirement, Error> {
        let owner = self.transport.owner_waker().cloned();
        super::poll_on_worker(std::pin::pin!(self.cancel_and_retire_inner()), || {
            require_runtime(owner.as_ref())
        })
        .await
    }

    async fn cancel_and_retire_inner(mut self) -> Result<CancelRetirement, Error> {
        self.transport.break_connection();
        let request = if self
            .extended
            .as_ref()
            .is_some_and(|state| state.expire_query_cancel())
        {
            Err(stale_request())
        } else {
            self.endpoint
                .send_cancel(
                    self.info.process_id,
                    self.cancel_key.as_deref().unwrap_or_default(),
                )
                .await
        };
        let retirement = self.transport.close().await;
        Ok(CancelRetirement {
            request,
            retirement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_cancellation_preserves_both_failure_phases() {
        let outcome = CancelRetirement {
            request: Err(Error::Busy),
            retirement: Err(Error::Broken),
        };
        assert!(matches!(
            outcome.into_result(),
            Err(Error::CancelRetirement {
                request: Some(request),
                retirement,
            }) if matches!(*request, Error::Busy) && matches!(*retirement, Error::Broken)
        ));
    }
}
