use super::{Session, is_fatal, owned_error, protocol_error, validate_parameter};
use crate::transport::WireOps;
use crate::{
    Error, WireTransport,
    frontend::SimpleQueryPacket,
    protocol::{self, BackendMessage, TransactionStatus},
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::TransportExt,
};
use std::{
    fmt,
    future::poll_fn,
    task::{Context, Poll, ready},
};

/// 从监听连接接收缓冲借用的一条通知。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Notification<'a> {
    pub process_id: i32,
    pub channel: &'a str,
    pub payload: &'a str,
}

impl fmt::Debug for Notification<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notification")
            .field("process_id", &self.process_id)
            .field("channel_bytes", &self.channel.len())
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// 由调用方驱动的 PostgreSQL 专用监听连接。订阅请求、响应和通知共用所选调度额度。
pub struct Listener<T: WireTransport> {
    session: Session<T>,
    delivering: bool,
    quantum: ExecutionQuantum,
}

impl<T: WireTransport> Session<T> {
    /// 将协议空闲的会话转为通知监听器。
    pub fn into_listener(self, scheduling: ExecutionScheduling) -> Result<Listener<T>, Error> {
        match self.reuse_state() {
            super::ReuseState::ProtocolIdle => Ok(Listener {
                session: self,
                delivering: false,
                quantum: ExecutionQuantum::new(scheduling),
            }),
            super::ReuseState::DiscardOnly => Err(Error::Broken),
            _ => Err(Error::Busy),
        }
    }
}

impl<T: WireTransport> Listener<T> {
    /// 订阅并等待 Ready，期间到达的通知交给回调。
    pub async fn listen(
        &mut self,
        channel: &str,
        on_notification: impl FnMut(Notification<'_>),
    ) -> Result<(), Error> {
        self.configure("LISTEN", channel, on_notification).await
    }

    /// 取消订阅并等待 Ready，期间到达的通知交给回调。
    pub async fn unlisten(
        &mut self,
        channel: &str,
        on_notification: impl FnMut(Notification<'_>),
    ) -> Result<(), Error> {
        self.configure("UNLISTEN", channel, on_notification).await
    }

    /// 等待通知，在借用有效时映射字段。
    /// 放弃 future 后，在途接收仍由监听器持有。
    /// 启用协作调度时，通知与控制消息共用额度，每帧按字节数计费。
    pub async fn next_notification<R>(
        &mut self,
        map: impl FnOnce(Notification<'_>) -> R,
    ) -> Result<R, Error> {
        self.check_idle()?;
        let mut map = Some(map);
        let mut suspended = false;
        poll_fn(|cx| {
            if suspended {
                self.session.check_runtime_owner()?;
            }
            let result = self.poll_notification(cx, &mut map);
            suspended = result.is_pending();
            if matches!(result, Poll::Ready(Err(_))) {
                self.session.transport.break_connection();
            }
            result
        })
        .await
    }

    /// 释放本地连接。
    /// 若已提交的订阅命令被放弃，须关闭连接；丢弃 future 不启动 I/O。
    pub async fn close_local(self) -> Result<(), Error> {
        self.session.close_local().await
    }

    fn check_idle(&self) -> Result<(), Error> {
        if self.delivering {
            return Err(Error::Broken);
        }
        self.session.check_idle_access(false)
    }

    async fn configure(
        &mut self,
        command: &'static str,
        channel: &str,
        on_notification: impl FnMut(Notification<'_>),
    ) -> Result<(), Error> {
        self.check_idle()?;
        let packet =
            SimpleQueryPacket::quoted_identifier(command, channel, self.session.max_request_len)?;
        let buffer = self.session.transport.take_send_buffer()?;
        let packet = packet.encode_into(buffer)?;
        self.session.invalidate_unnamed_statement()?;
        self.session.active = true;
        self.session.remaining_boundaries = 1;
        let result = self.configure_inner(command, packet, on_notification).await;
        if self.session.active && result.is_err() {
            self.session.transport.break_connection();
        }
        result
    }

    async fn configure_inner(
        &mut self,
        command: &str,
        packet: Vec<u8>,
        mut on_notification: impl FnMut(Notification<'_>),
    ) -> Result<(), Error> {
        let packet_bytes = packet.len();
        self.session.transport.begin_send(packet)?;
        self.quantum.spend_bytes(packet_bytes);
        let mut complete = false;
        let mut failure = None;
        for _ in 0..self.session.max_messages {
            self.quantum.yield_on_worker().await?;
            self.session.transport.receive_frame_on_owner().await?;
            let frame = self.session.transport.frame()?;
            let frame_bytes = frame.body.len().saturating_add(5);
            let mut schema_changed = false;
            let ready = match protocol::parse_backend(frame)? {
                BackendMessage::CommandComplete(tag)
                    if tag == command && !complete && failure.is_none() =>
                {
                    complete = true;
                    false
                }
                BackendMessage::ErrorResponse(error) if !complete && failure.is_none() => {
                    let fatal = is_fatal(error);
                    let error = owned_error(error);
                    if fatal {
                        return Err(Error::Database(error));
                    }
                    failure = Some(error);
                    false
                }
                BackendMessage::ReadyForQuery(TransactionStatus::Idle)
                    if complete || failure.is_some() =>
                {
                    true
                }
                BackendMessage::NotificationResponse {
                    process_id,
                    channel,
                    payload,
                } => {
                    self.delivering = true;
                    on_notification(Notification {
                        process_id,
                        channel,
                        payload,
                    });
                    self.delivering = false;
                    false
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.session.notice_handler.as_ref())
                        .finish(&mut self.session.transport);
                    false
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    schema_changed = name == "search_path";
                    false
                }
                _ => {
                    return Err(protocol_error(
                        "unexpected response to a subscription command",
                    ));
                }
            };
            self.session.transport.consume_frame()?;
            self.quantum.spend_bytes(frame_bytes);
            if schema_changed {
                self.session.bump_schema_epoch()?;
            }
            if ready {
                self.session.note_ready(TransactionStatus::Idle)?;
                self.session
                    .transport
                    .finish_send_on_owner()
                    .await
                    .map_err(|send| super::general::send_after_diagnostic(failure.take(), send))?;
                self.session.active = false;
                return failure.map_or(Ok(()), |error| Err(Error::Database(error)));
            }
        }
        Err(Error::Limit(
            "subscription command exceeded its control-message limit",
        ))
    }

    fn poll_notification<R>(
        &mut self,
        cx: &mut Context<'_>,
        map: &mut Option<impl FnOnce(Notification<'_>) -> R>,
    ) -> Poll<Result<R, Error>> {
        loop {
            ready!(self.quantum.poll_yield_if_exhausted(cx));
            ready!(self.session.transport.poll_receive_frame_on_owner(cx))?;
            let frame = self.session.transport.frame()?;
            let frame_bytes = frame.body.len().saturating_add(5);
            let mut schema_changed = false;
            match protocol::parse_backend(frame)? {
                BackendMessage::NotificationResponse {
                    process_id,
                    channel,
                    payload,
                } => {
                    let map = map.take().ok_or(Error::Broken)?;
                    self.delivering = true;
                    let result = map(Notification {
                        process_id,
                        channel,
                        payload,
                    });
                    self.session.transport.consume_frame()?;
                    self.delivering = false;
                    self.quantum.spend_bytes(frame_bytes);
                    return Poll::Ready(Ok(result));
                }
                BackendMessage::NoticeResponse(notice) => {
                    super::observe_notice(notice, self.session.notice_handler.as_ref())
                        .finish(&mut self.session.transport);
                }
                BackendMessage::ParameterStatus { name, value } => {
                    validate_parameter(name, value)?;
                    schema_changed = name == "search_path";
                }
                BackendMessage::ErrorResponse(error) => {
                    return Poll::Ready(Err(Error::Database(owned_error(error))));
                }
                _ => {
                    return Poll::Ready(Err(protocol_error(
                        "unexpected response on an idle listener",
                    )));
                }
            }
            self.session.transport.consume_frame()?;
            if schema_changed {
                self.session.bump_schema_epoch()?;
            }
            self.quantum.spend_bytes(frame_bytes);
        }
    }
}
