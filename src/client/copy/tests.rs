use super::*;
use crate::{AuthenticationPolicy, ReuseState, TcpConfig, WireLimits};
use futures_util::stream;
use std::{cell::Cell, rc::Rc};
use std::{cell::RefCell, collections::VecDeque};

enum Mode {
    In,
    Out(Vec<Vec<u8>>),
}

/// 夹具中的帧均立即就绪。
/// COPY IN 每个数据包没有独立的服务器应答，可据此检查发送完成是否错误地依赖数据库往返。
struct ReadyCopy {
    mode: Mode,
    frames: VecDeque<(u8, Vec<u8>)>,
    sent: Vec<Vec<u8>>,
    packet: Vec<u8>,
    rows: usize,
    consumed: usize,
    data_frame_reads: usize,
    data_packet_takes: usize,
    finish_polls: usize,
    blocked: bool,
    finish_after_frame: usize,
    fail_final_send: bool,
    block_data: bool,
    retire_data_in_duplex: bool,
    reject_data: bool,
    broken: bool,
}

impl crate::transport::WireOps for ReadyCopy {
    fn owner_waker(&self) -> Option<&std::task::Waker> {
        None
    }

    fn is_broken(&self) -> bool {
        self.broken
    }
    fn break_connection(&mut self) {
        self.broken = true;
    }
    fn begin_send(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if self.blocked || self.consumed < self.finish_after_frame {
            return Err(Error::Busy);
        }
        self.sent.push(bytes.clone());
        match bytes.first().copied() {
            Some(b'P') if matches!(self.mode, Mode::In) => {
                self.frames.extend([
                    (b'1', Vec::new()),
                    (b'2', Vec::new()),
                    (b'G', vec![0, 0, 1, 0, 0]),
                ]);
            }
            Some(b'S') => self.frames.push_back((b'Z', vec![b'I'])),
            Some(b'Q') => match &mut self.mode {
                Mode::In => self.frames.push_back((b'G', vec![0, 0, 1, 0, 0])),
                Mode::Out(chunks) => {
                    self.frames.push_back((b'H', vec![0, 0, 1, 0, 0]));
                    for chunk in std::mem::take(chunks) {
                        self.frames.push_back((b'd', chunk));
                    }
                    self.frames.push_back((b'c', Vec::new()));
                    self.frames
                        .push_back((b'C', format!("COPY {}\0", self.rows).into_bytes()));
                    self.frames.push_back((b'Z', vec![b'I']));
                }
            },
            Some(b'd') => {
                self.blocked = self.block_data;
                if self.reject_data {
                    self.frames
                        .push_back((b'E', b"SERROR\0C22000\0Mrejected input\0\0".to_vec()));
                    self.frames.push_back((b'Z', vec![b'I']));
                }
            }
            Some(b'c') => {
                self.frames
                    .push_back((b'C', format!("COPY {}\0", self.rows).into_bytes()));
                self.frames.push_back((b'Z', vec![b'I']));
            }
            Some(b'f') => {
                self.frames
                    .push_back((b'E', b"SERROR\0C57014\0Mexplicit failure\0\0".to_vec()));
                self.frames.push_back((b'Z', vec![b'I']));
            }
            _ => return Err(Error::Broken),
        }
        self.packet = bytes;
        Ok(())
    }
    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
        if self.blocked || self.consumed < self.finish_after_frame {
            return Err(Error::Busy);
        }
        self.data_packet_takes += usize::from(self.packet.first() == Some(&b'd'));
        Ok(std::mem::take(&mut self.packet))
    }
    fn send_queue_available(&self) -> usize {
        0
    }
    fn disable_send_queue(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn poll_finish_send(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.finish_polls += 1;
        if self.fail_final_send && self.frames.is_empty() {
            return Poll::Ready(Err(std::io::Error::other("late COPY write failure").into()));
        }
        if self.blocked || self.consumed < self.finish_after_frame {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_receive_frame(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.frames.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_receive_frame_with_send_status_on_owner(
        &mut self,
        cx: &mut Context<'_>,
        stop_when_sent: bool,
    ) -> Result<(Poll<()>, bool), Error> {
        let sent = self.poll_finish_send(cx)?.is_ready();
        if sent && stop_when_sent {
            return Ok((Poll::Pending, true));
        }
        let received = self.poll_receive_frame(cx)?;
        if self.retire_data_in_duplex && self.blocked {
            self.blocked = false;
            return Ok((received, true));
        }
        Ok((received, sent))
    }
    fn frame(&mut self) -> Result<protocol::Frame<'_>, Error> {
        let (tag, body) = self.frames.front().ok_or(Error::Busy)?;
        self.data_frame_reads += usize::from(*tag == b'd');
        Ok(protocol::Frame { tag: *tag, body })
    }
    fn consume_frame(&mut self) -> Result<(), Error> {
        self.frames.pop_front().ok_or(Error::Busy)?;
        self.consumed += 1;
        Ok(())
    }
    async fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

async fn session(mode: Mode, rows: usize) -> Session<ReadyCopy> {
    let mut key = Vec::from(11_i32.to_be_bytes());
    key.extend_from_slice(&[0; 8]);
    let frames = VecDeque::from([
        (b'R', 0_i32.to_be_bytes().to_vec()),
        (b'S', b"server_version\x0019.0\0".to_vec()),
        (b'S', b"client_encoding\0UTF8\0".to_vec()),
        (b'K', key),
        (b'Z', vec![b'I']),
    ]);
    let config = TcpConfig::plaintext(
        "127.0.0.1:1".parse().unwrap(),
        "test",
        "test",
        AuthenticationPolicy::AllowAuthenticationOk,
        WireLimits {
            receive_capacity: 8192,
            max_frame_len: 8191,
            max_request_len: 8192,
            max_messages_per_request: 128,
        },
        crate::client::socket_options::TEST_TCP_OPTIONS,
    );
    let (mut session, settings) = Session::from_transport(
        ReadyCopy {
            mode,
            frames,
            sent: Vec::new(),
            packet: Vec::new(),
            rows,
            consumed: 0,
            data_frame_reads: 0,
            data_packet_takes: 0,
            finish_polls: 0,
            blocked: false,
            finish_after_frame: 0,
            fail_final_send: false,
            block_data: false,
            retire_data_in_duplex: false,
            reject_data: false,
            broken: false,
        },
        config,
        1,
    );
    session
        .startup(&settings.authentication, None)
        .await
        .unwrap();
    session
}

fn batch_limits() -> CopyBatchLimits {
    CopyBatchLimits {
        max_chunks: 8,
        max_packet_bytes: 128,
    }
}
fn stream_limits() -> CopyStreamLimits {
    CopyStreamLimits {
        max_chunks: 8,
        max_payload_bytes: 128,
    }
}

fn run_with_deadline(test: impl Future<Output = ()>) {
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        compio::time::timeout(std::time::Duration::from_secs(5), test)
            .await
            .expect("COPY 单元测试超时")
    });
}

#[test]
fn explicit_copy_completion_delivers_notices_and_recovery_only_validates_them() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    run_with_deadline(async {
        let notice = || (b'N', b"SNOTICE\0C00000\0Mfixture\0\0".to_vec());
        for recover in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            for mode in [Mode::In, Mode::Out(Vec::new())] {
                let input = matches!(mode, Mode::In);
                let mut owner = session(mode, 0).await;
                let seen = Arc::clone(&calls);
                owner.notice_handler = Some(Arc::new(move |n| {
                    assert_eq!(n.message, "fixture");
                    seen.fetch_add(1, Ordering::Relaxed);
                }));
                if input {
                    let copy = owner
                        .copy_in(
                            "copy-in",
                            &[],
                            CopyProtocol::SimpleSingle,
                            ExecutionScheduling::Uninterrupted,
                        )
                        .await
                        .unwrap();
                    copy.session.transport.frames.push_front(notice());
                    let result = if recover {
                        drop(copy);
                        owner.fail_abandoned_copy("stop").await
                    } else {
                        copy.fail("stop").await
                    };
                    assert!(
                        matches!(result, Ok(CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014")
                    );
                } else {
                    let copy = owner
                        .copy_out(
                            "copy-out",
                            &[],
                            CopyProtocol::SimpleSingle,
                            ExecutionScheduling::Uninterrupted,
                        )
                        .await
                        .unwrap();
                    copy.session.transport.frames.push_front(notice());
                    let result = if recover {
                        drop(copy);
                        owner.finish_abandoned_copy_out().await
                    } else {
                        copy.finish().await
                    };
                    assert_eq!(result.unwrap().rows, 0);
                }
                assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
            }
            assert_eq!(calls.load(Ordering::Relaxed), if recover { 0 } else { 2 });
        }
        for malformed in [false, true] {
            let mut owner = session(Mode::Out(vec![b"x".to_vec()]), 1).await;
            owner.notice_handler = Some(Arc::new(|_| panic!("清理不得调用应用回调")));
            let copy = owner
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            copy.session.transport.frames.insert(
                1,
                if malformed {
                    (b'N', b"SNOTICE\0C00000\0Mbad".to_vec())
                } else {
                    notice()
                },
            );
            let error = copy
                .collect_ready(
                    OwnedOutput {
                        max_bytes: 0,
                        allocation: AllocationPolicy::Grow,
                    },
                    OnError::DrainToReady,
                )
                .await
                .unwrap_err();
            if malformed {
                assert!(
                    matches!(error, Error::Cleanup { primary, cleanup } if matches!(*primary, Error::Limit(_)) && matches!(*cleanup, Error::Protocol(_)))
                );
                assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
            } else {
                assert!(matches!(error, Error::Limit(_)));
                assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    });
}

#[test]
fn server_rejection_during_copy_input_preserves_notice_delivery() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    run_with_deadline(async {
        let mut owner = session(Mode::In, 0).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        owner.notice_handler = Some(Arc::new(move |notice| {
            assert_eq!(notice.message, "rejecting");
            seen.fetch_add(1, Ordering::Relaxed);
        }));
        let copy = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        copy.session.transport.frames.extend([
            (b'E', b"SERROR\0C22000\0Mserver rejected input\0\0".to_vec()),
            (b'N', b"SNOTICE\0C00000\0Mrejecting\0\0".to_vec()),
            (b'Z', vec![b'I']),
        ]);
        let error = copy
            .send_stream(
                &mut stream::pending::<Result<&[u8], Error>>(),
                stream_limits(),
                OnError::DrainToReady,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Database(error) if error.code() == "22000"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn final_copy_send_failure_preserves_the_confirmed_sql_diagnostic() {
    run_with_deadline(async {
        for rejected in [false, true] {
            let mut owner = session(Mode::Out(Vec::new()), 0).await;
            let output = owner
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            output.session.transport.fail_final_send = true;
            if rejected {
                output.session.transport.frames = VecDeque::from([
                    (b'E', b"SERROR\0C22000\0Moutput rejected\0\0".to_vec()),
                    (b'Z', vec![b'I']),
                ]);
            }
            let error = output.finish().await.unwrap_err();
            if rejected {
                assert!(matches!(error, Error::Cleanup {primary, cleanup}
                    if matches!(*primary, Error::Database(ref error) if error.code() == "22000")
                    && matches!(*cleanup, Error::Io(_))));
            } else {
                assert!(matches!(error, Error::Io(_)));
            }
            assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
        }
    });
}

#[test]
fn finishing_copy_out_drains_responses_before_waiting_for_a_stalled_send() {
    run_with_deadline(async {
        for abandoned in [false, true] {
            let mut owner =
                session(Mode::Out(vec![b"first".to_vec(), b"second".to_vec()]), 2).await;
            let output = owner
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            output.session.transport.finish_after_frame = output.session.transport.consumed + 1;
            let mut context = Context::from_waker(std::task::Waker::noop());
            let outcome = if abandoned {
                drop(output);
                std::pin::pin!(owner.finish_abandoned_copy_out())
                    .as_mut()
                    .poll(&mut context)
            } else {
                std::pin::pin!(output.finish()).as_mut().poll(&mut context)
            };
            assert!(matches!(
                outcome,
                Poll::Ready(Ok(CopyCompletion { rows: 2, .. }))
            ));
            assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn abandoned_copy_out_completion_keeps_ready_until_the_local_send_retires() {
    run_with_deadline(async {
        let mut owner = session(Mode::Out(vec![b"row".to_vec()]), 1).await;
        let output = owner
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        output.session.transport.finish_after_frame = usize::MAX;
        assert!(
            std::pin::pin!(output.finish())
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        assert_eq!(
            owner.copy_state.as_ref().unwrap().ready,
            Some(TransactionStatus::Idle)
        );
        assert_eq!(owner.reuse_state(), ReuseState::NeedsCopyCompletion);
        owner.transport.finish_after_frame = 0;
        assert_eq!(owner.finish_abandoned_copy_out().await.unwrap().rows, 1);
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn rejected_extended_copy_in_reuses_the_retired_packet_for_sync() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 0).await;
        let mut input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::Extended,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let storage = input.session.transport.packet.as_ptr();
        input
            .session
            .transport
            .frames
            .push_back((b'E', b"SERROR\0C22000\0Mrejected input\0\0".to_vec()));
        let error = input.send(b"x").await.unwrap_err();
        assert!(matches!(error, Error::Database(ref error) if error.code() == "22000"));
        assert_eq!(input.session.transport.packet, b"S\0\0\0\x04");
        assert_eq!(input.session.transport.packet.as_ptr(), storage);
        drop(input);
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn finishing_copy_in_reads_server_controls_while_its_previous_send_is_pending() {
    run_with_deadline(async {
        for reject in [false, true] {
            let mut owner = session(Mode::In, 1).await;
            let mut input = owner
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            input.session.transport.block_data = true;
            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(
                std::pin::pin!(input.send(b"1\n"))
                    .as_mut()
                    .poll(&mut context)
                    .is_pending()
            );
            assert!(input.session.transport.blocked);
            // 已提交的数据包在收到下一个服务端帧后才能写完。
            input.session.transport.blocked = false;
            input
                .session
                .transport
                .frames
                .push_back((b'N', b"SNOTICE\0C00000\0Mreading input\0\0".to_vec()));
            input.session.transport.finish_after_frame = input.session.transport.consumed + 1;
            if reject {
                drop(input);
                assert!(matches!(
                    std::pin::pin!(owner.fail_abandoned_copy("stop"))
                        .as_mut()
                        .poll(&mut context),
                    Poll::Ready(Ok(CopyAbort::Aborted { .. }))
                ));
            } else {
                assert!(matches!(
                    std::pin::pin!(input.finish()).as_mut().poll(&mut context),
                    Poll::Ready(Ok(CopyCompletion { rows: 1, .. }))
                ));
            }
            assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn copy_out_rejects_data_and_copy_done_after_a_server_error() {
    run_with_deadline(async {
        for tag in *b"dc" {
            let mut owner = session(Mode::Out(Vec::new()), 0).await;
            let output = owner
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            output.session.transport.frames = VecDeque::from([
                (b'E', b"SERROR\0C22000\0Moutput failed\0\0".to_vec()),
                (tag, Vec::new()),
                (b'Z', vec![b'I']),
            ]);
            assert!(matches!(output.finish().await, Err(Error::Protocol(_))));
            assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
        }
    });
}

#[test]
fn empty_owned_copy_packet_keeps_its_header_and_rejects_growth() {
    let mut packet = CopyDataBuffer::new(0).unwrap();
    assert_eq!(packet.payload_capacity(), 0);
    assert_eq!(packet.retained_bytes(), COPY_DATA_HEADER_BYTES);
    assert!(packet.payload().is_empty());
    assert!(packet.payload_mut().is_empty());
    assert!(matches!(
        packet.resize_payload(usize::MAX),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        packet.extend_from_slice(b"x"),
        Err(Error::Limit(_))
    ));
    packet.clear();
    let encoded = packet.into_packet(COPY_DATA_HEADER_BYTES).unwrap();
    assert_eq!(encoded, EMPTY_COPY_DATA);
    let packet = CopyDataBuffer::recycled(encoded).unwrap();
    assert_eq!(packet.payload_capacity(), 0);
    assert!(packet.payload().is_empty());
    assert!(matches!(
        CopyDataBuffer::recycled(vec![b'd']),
        Err(Error::Broken)
    ));
    assert!(matches!(
        CopyDataBuffer::recycled(b"c\0\0\0\x04".to_vec()),
        Err(Error::Broken)
    ));
}

#[test]
fn owned_copy_payload_can_be_filled_and_rewritten_in_its_packet() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 2).await;
        let mut input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let mut packet = CopyDataBuffer::new(8).unwrap();
        let backing = packet.payload().as_ptr();
        let payload = packet.resize_payload(4).unwrap();
        assert_eq!(payload, [0; 4]);
        payload.copy_from_slice(b"1\n2\n");
        assert!(matches!(packet.resize_payload(9), Err(Error::Limit(_))));
        assert_eq!(packet.payload(), b"1\n2\n");
        #[cfg(feature = "diagnostics")]
        let before = crate::diagnostics::snapshot();
        let mut packet = input.send_owned(packet).await.unwrap();
        assert_eq!(packet.payload().as_ptr(), backing);
        packet.payload_mut().copy_from_slice(b"3\n4\n");
        packet.resize_payload(2).unwrap();
        let packet = input.send_owned(packet).await.unwrap();
        assert_eq!(packet.payload().as_ptr(), backing);
        assert_eq!(
            input.session.transport.sent.last().unwrap(),
            b"d\0\0\0\x063\n"
        );
        assert_eq!(input.finish().await.unwrap().rows, 2);
        #[cfg(feature = "diagnostics")]
        assert_eq!(
            crate::diagnostics::snapshot()
                .delta(before)
                .unwrap()
                .copy_in_payload_bytes_copied,
            0
        );
    });
}

#[test]
fn successive_copy_directions_reuse_the_workspace_after_retirement() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 1).await;
        assert!(owner.copy_state.0.is_none());
        let (packet, address) = {
            let mut input = owner
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let mut packet = CopyDataBuffer::new(16).unwrap();
            packet.resize_payload(2).unwrap().copy_from_slice(b"1\n");
            let packet = input.send_owned(packet).await.unwrap();
            let address = std::ptr::from_ref(input.session.copy_state.as_ref().unwrap());
            assert_eq!(input.finish().await.unwrap().rows, 1);
            (packet, address)
        };
        assert!(owner.copy_state.0.is_some());
        assert!(!owner.copy_state.is_some());
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
        owner.transport.mode = Mode::Out(vec![packet.payload().to_vec()]);
        let mut output = owner
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        assert_eq!(
            std::ptr::from_ref(output.session.copy_state.as_ref().unwrap()),
            address
        );
        assert_eq!(output.next_chunk().await.unwrap().unwrap().bytes(), b"1\n");
        assert_eq!(output.finish().await.unwrap().rows, 1);
        assert!(owner.copy_state.0.is_some());
        assert!(owner.copy_state.is_none());
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_data_finishes_when_duplex_reports_send_retired_and_receive_pending() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 1).await;
        owner.transport.block_data = true;
        owner.transport.retire_data_in_duplex = true;
        let mut input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            std::pin::pin!(input.send(b"1\n")).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(input.session.transport.frames.is_empty());
        assert_eq!(input.finish().await.unwrap().rows, 1);
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn borrowed_sends_reuse_retired_capacity_and_batches_keep_exact_frame_boundaries() {
    run_with_deadline(async {
        let mut connection = session(Mode::In, 3).await;
        {
            let mut copy = connection
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let finish_polls = copy.session.transport.finish_polls;
            #[cfg(feature = "diagnostics")]
            let copy_counters = crate::diagnostics::snapshot();
            copy.send(b"first\n").await.unwrap();
            assert_eq!(copy.session.transport.finish_polls, finish_polls + 2);
            let pointer = copy.session.transport.packet.as_ptr();
            let capacity = copy.session.transport.packet.capacity();
            copy.send(b"next\n").await.unwrap();
            assert_eq!(copy.session.transport.finish_polls, finish_polls + 3);
            assert_eq!(copy.session.transport.packet.as_ptr(), pointer);
            assert_eq!(copy.session.transport.packet.capacity(), capacity);
            let before = copy.session.transport.sent.len();
            let bad = copy
                .send_batch(
                    &[b"a", b"b"],
                    CopyBatchLimits {
                        max_packet_bytes: 11,
                        ..batch_limits()
                    },
                )
                .await
                .unwrap_err();
            assert!(!bad.may_have_been_sent);
            assert_eq!(copy.session.transport.sent.len(), before);
            let empty = copy.send_batch(&[], batch_limits()).await.unwrap();
            assert_eq!(
                empty,
                CopyBatchCompletion {
                    chunks: 0,
                    payload_bytes: 0
                }
            );
            assert_eq!(copy.session.transport.sent.len(), before);
            let completion = copy
                .send_batch(&[b"a", b"", b"bc"], batch_limits())
                .await
                .unwrap();
            assert_eq!(copy.session.transport.finish_polls, finish_polls + 4);
            assert_eq!(
                completion,
                CopyBatchCompletion {
                    chunks: 3,
                    payload_bytes: 3
                }
            );
            assert_eq!(copy.session.transport.sent.len(), before + 1);
            let mut bytes = copy.session.transport.packet.as_slice();
            for expected in [b"a".as_slice(), b"", b"bc"] {
                let protocol::FrameParse::Complete { frame, consumed } =
                    protocol::parse_frame(bytes, 8191).unwrap()
                else {
                    panic!("complete CopyData");
                };
                assert_eq!(frame.tag, b'd');
                assert_eq!(frame.body, expected);
                bytes = &bytes[consumed..];
            }
            assert!(bytes.is_empty());
            // 上述每次数据发送都无需读取服务器帧。
            assert!(copy.session.transport.frames.is_empty());
            let data_backing = copy.session.transport.packet.as_ptr();
            assert_eq!(copy.finish().await.unwrap().rows, 3);
            assert_eq!(connection.transport.packet.as_ptr(), data_backing);
            #[cfg(feature = "diagnostics")]
            assert_eq!(
                crate::diagnostics::snapshot()
                    .delta(copy_counters)
                    .unwrap()
                    .copy_in_payload_bytes_copied,
                u64::try_from(b"first\nnext\nabc".len()).unwrap(),
            );
        }
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

struct PoolSource {
    pool: Rc<RefCell<Vec<CopyDataBuffer>>>,
    produced: Rc<Cell<usize>>,
    count: usize,
}
impl Stream for PoolSource {
    type Item = Result<CopyDataBuffer, Error>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.produced.get() == self.count {
            return Poll::Ready(None);
        }
        let Some(mut packet) = self.pool.borrow_mut().pop() else {
            return Poll::Pending;
        };
        packet.clear();
        packet.extend_from_slice(b"x\n").unwrap();
        self.produced.set(self.produced.get() + 1);
        Poll::Ready(Some(Ok(packet)))
    }
}

#[test]
fn owned_stream_recycles_one_allocation_and_enforces_limits_before_extra_send() {
    run_with_deadline(async {
        for (bound, max_payload_bytes, accepted, observed, succeeds) in [
            (8, 128, 3, 3, true),
            (2, 128, 2, 3, false),
            (8, 3, 1, 2, false),
        ] {
            let mut connection = session(Mode::In, 3).await;
            let packet = CopyDataBuffer::new(32).unwrap();
            let pointer = packet.payload().as_ptr();
            let pool = Rc::new(RefCell::new(vec![packet]));
            let produced = Rc::new(Cell::new(0));
            let mut source = PoolSource {
                pool: pool.clone(),
                produced: produced.clone(),
                count: 3,
            };
            let source: &mut (dyn Stream<Item = Result<CopyDataBuffer, Error>> + Unpin) =
                &mut source;
            let returned = pool.clone();
            let recycled = Cell::new(0);
            let result = connection
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap()
                .send_owned_stream_recycling(
                    source,
                    CopyStreamLimits {
                        max_chunks: bound,
                        max_payload_bytes,
                    },
                    |packet| {
                        assert_eq!(packet.payload().as_ptr(), pointer);
                        recycled.set(recycled.get() + 1);
                        returned.borrow_mut().push(packet);
                        Ok(())
                    },
                    OnError::DrainToReady,
                )
                .await;
            assert_eq!(produced.get(), observed);
            assert_eq!(
                connection
                    .transport
                    .sent
                    .iter()
                    .filter(|packet| packet.first() == Some(&b'd'))
                    .count(),
                accepted
            );
            if succeeds {
                assert_eq!(result.unwrap().rows, 3);
            } else {
                assert!(matches!(result, Err(Error::Limit(_))));
            }
            assert_eq!(recycled.get(), accepted);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn copied_and_owned_streams_limit_total_input_before_sending_an_extra_chunk() {
    struct Payload<'a> {
        bytes: &'static [u8],
        borrows: &'a Cell<usize>,
    }

    impl AsRef<[u8]> for Payload<'_> {
        fn as_ref(&self) -> &[u8] {
            self.borrows.set(self.borrows.get() + 1);
            self.bytes
        }
    }

    run_with_deadline(async {
        let payloads: [&[u8]; 3] = [b"", b"x\n", b"y\n"];
        for owned in [false, true] {
            for (max_chunks, max_payload_bytes, accepted) in
                [(3, 4, 3), (1, 4, 1), (3, 2, 2), (0, 4, 0)]
            {
                for on_error in [
                    OnError::DrainToReady,
                    OnError::RecoverExplicitly,
                    OnError::Discard,
                ] {
                    let mut connection = session(Mode::In, payloads.len()).await;
                    let copy = connection
                        .copy_in(
                            "copy-in",
                            &[],
                            CopyProtocol::SimpleSingle,
                            ExecutionScheduling::Uninterrupted,
                        )
                        .await
                        .unwrap();
                    let limits = CopyStreamLimits {
                        max_chunks,
                        max_payload_bytes,
                    };
                    let produced = Cell::new(0);
                    let borrows = Cell::new(0);
                    let chunks = payloads
                        .into_iter()
                        .inspect(|_| produced.set(produced.get() + 1));
                    let result = if owned {
                        let mut source = stream::iter(chunks.map(|bytes| {
                            let mut packet = CopyDataBuffer::new(bytes.len()).unwrap();
                            packet.extend_from_slice(bytes).unwrap();
                            Ok(packet)
                        }));
                        copy.send_owned_stream(&mut source, limits, on_error).await
                    } else {
                        let mut source = stream::iter(chunks.map(|bytes| {
                            Ok(Payload {
                                bytes,
                                borrows: &borrows,
                            })
                        }));
                        copy.send_stream(&mut source, limits, on_error).await
                    };
                    let succeeds = accepted == payloads.len();
                    assert_eq!(produced.get(), accepted + usize::from(!succeeds));
                    if !owned {
                        let extra_payload = !succeeds && accepted < max_chunks;
                        assert_eq!(borrows.get(), accepted + usize::from(extra_payload));
                    }
                    let sent = connection
                        .transport
                        .sent
                        .iter()
                        .filter(|packet| packet.first() == Some(&b'd'))
                        .map(|packet| &packet[COPY_DATA_HEADER_BYTES..])
                        .collect::<Vec<_>>();
                    assert_eq!(sent, &payloads[..accepted]);
                    if succeeds {
                        assert_eq!(result.unwrap().rows, u64::try_from(accepted).unwrap());
                    } else {
                        assert!(matches!(
                            result,
                            Err(Error::Limit(
                                "COPY stream exceeds its chunk or payload limit"
                            ))
                        ));
                        if on_error == OnError::RecoverExplicitly {
                            assert_eq!(connection.reuse_state(), ReuseState::NeedsCopyCompletion);
                            assert!(matches!(
                                connection.fail_abandoned_copy("stop input").await,
                                Ok(CopyAbort::Aborted { .. })
                            ));
                        }
                    }
                    let disposable = !succeeds && on_error == OnError::Discard;
                    assert_eq!(
                        connection.reuse_state(),
                        if disposable {
                            ReuseState::DiscardOnly
                        } else {
                            ReuseState::ProtocolIdle
                        }
                    );
                    if owned {
                        // 最终 CopyDone 或 CopyFail 可取用最后一个缓冲。数据包发送之间不回收缓冲。
                        assert_eq!(
                            connection.transport.data_packet_takes,
                            usize::from(!disposable && accepted != 0)
                        );
                    }
                }
            }
        }
    });
}

#[test]
fn panicking_copy_source_or_recycle_callback_prevents_reuse() {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    run_with_deadline(async {
        for policy in [OnError::RecoverExplicitly, OnError::DrainToReady] {
            for source_panics in [false, true] {
                let mut connection = session(Mode::In, 1).await;
                let mut packet = CopyDataBuffer::new(8).unwrap();
                packet.extend_from_slice(b"x\n").unwrap();
                let mut packet = Some(packet);
                let mut source = stream::poll_fn(|_| {
                    if source_panics {
                        panic!("COPY source panicked");
                    }
                    Poll::Ready(packet.take().map(Ok))
                });
                let copy = connection
                    .copy_in(
                        "copy-in",
                        &[],
                        CopyProtocol::SimpleSingle,
                        ExecutionScheduling::Uninterrupted,
                    )
                    .await
                    .unwrap();
                let recycled = Cell::new(false);
                let transfer = copy.send_owned_stream_recycling(
                    &mut source,
                    stream_limits(),
                    |_| {
                        recycled.set(true);
                        panic!("COPY recycle callback panicked");
                    },
                    policy,
                );
                assert!(AssertUnwindSafe(transfer).catch_unwind().await.is_err());
                assert_eq!(recycled.get(), !source_panics);
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
                assert!(matches!(
                    connection.fail_abandoned_copy("input aborted").await,
                    Err(Error::Broken)
                ));
            }
        }
    });
}

#[test]
fn panicking_copy_payload_borrow_prevents_reuse_without_sending_data() {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    struct Panics;
    impl AsRef<[u8]> for Panics {
        fn as_ref(&self) -> &[u8] {
            panic!("注入 COPY 载荷借用错误");
        }
    }

    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        let copy = connection
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let mut source = stream::iter([Ok(Panics)]);
        let send = copy.send_stream(&mut source, stream_limits(), OnError::DrainToReady);
        let panic = AssertUnwindSafe(send).catch_unwind().await.unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"注入 COPY 载荷借用错误")
        );
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        assert_eq!(connection.transport.sent.len(), 1);
    });
}

#[test]
fn abort_reports_a_previously_sent_copy_done_as_completed() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 2).await;
        let input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        {
            let mut finishing = std::pin::pin!(input.finish());
            assert!(
                finishing
                    .as_mut()
                    .poll(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(
            owner.copy_state.as_ref().unwrap().input_end,
            Some(InputEnd::Done)
        );
        assert!(matches!(
            owner.fail_abandoned_copy("stop input").await,
            Ok(CopyAbort::AlreadyCompleted(CopyCompletion {
                rows: 2,
                transaction_status: TransactionStatus::Idle
            }))
        ));
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn abandoned_copy_fail_rejects_a_later_success_tag() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 0).await;
        let input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        {
            let mut abort = std::pin::pin!(input.fail("stop input"));
            assert!(
                abort
                    .as_mut()
                    .poll(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(
            owner.copy_state.as_ref().unwrap().input_end,
            Some(InputEnd::Rejected)
        );
        owner.transport.frames =
            VecDeque::from([(b'C', b"COPY 0\0".to_vec()), (b'Z', b"I".to_vec())]);
        assert!(matches!(
            owner.fail_abandoned_copy("resume").await,
            Err(Error::Protocol(_))
        ));
        assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn a_pending_copy_source_restores_the_selected_recovery_policy() {
    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        let mut source = stream::pending();
        let copy = connection
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let mut transfer = Box::pin(copy.send_owned_stream_recycling(
            &mut source,
            stream_limits(),
            |_| panic!("pending source cannot recycle a packet"),
            OnError::RecoverExplicitly,
        ));
        std::future::poll_fn(|cx| {
            assert!(transfer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(transfer);
        assert_eq!(connection.reuse_state(), ReuseState::NeedsCopyCompletion);
        assert!(matches!(
            connection.fail_abandoned_copy("input cancelled").await,
            Ok(CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014"
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_input_drains_after_source_or_recycle_errors() {
    run_with_deadline(async {
        for callback_error in [false, true] {
            let mut connection = session(Mode::In, 1).await;
            let mut packet = CopyDataBuffer::new(8).unwrap();
            packet.extend_from_slice(b"x\n").unwrap();
            let mut source = stream::iter([Ok(packet), Err(Error::InvalidInput("source failed"))]);
            let callbacks = Cell::new(0);
            let error = connection
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap()
                .send_owned_stream_recycling(
                    &mut source,
                    stream_limits(),
                    |_| {
                        callbacks.set(callbacks.get() + 1);
                        if callback_error {
                            Err(Error::InvalidInput("callback failed"))
                        } else {
                            Ok(())
                        }
                    },
                    OnError::DrainToReady,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::InvalidInput(message) if message == if callback_error { "callback failed" } else { "source failed" })
            );
            assert_eq!(callbacks.get(), 1);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn copy_stream_stops_polling_and_recycling_after_server_rejection() {
    use futures_util::StreamExt;

    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        connection.transport.reject_data = true;
        let mut packet = CopyDataBuffer::new(8).unwrap();
        packet.extend_from_slice(b"bad\n").unwrap();
        let produced = Cell::new(0);
        let recycled = Cell::new(0);
        let mut source = stream::iter([Ok(packet), Err(Error::InvalidInput("extra input"))])
            .inspect(|_| produced.set(produced.get() + 1));
        let error = connection
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap()
            .send_owned_stream_recycling(
                &mut source,
                stream_limits(),
                |_| {
                    recycled.set(recycled.get() + 1);
                    Ok(())
                },
                OnError::DrainToReady,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Database(ref error) if error.code() == "22000"));
        assert_eq!((produced.get(), recycled.get()), (1, 0));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_batch_reports_server_rejection_after_handoff() {
    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        connection.transport.reject_data = true;
        {
            let mut copy = connection
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let error = copy
                .send_batch(&[b"bad", b"queued"], batch_limits())
                .await
                .unwrap_err();
            assert!(error.may_have_been_sent);
            assert!(matches!(error.source, Error::Database(ref error) if error.code() == "22000"));
        }
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn dropped_batch_keeps_pending_packet_until_explicit_failure_finishes_it() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        connection.transport.block_data = true;
        {
            let mut copy = connection
                .copy_in(
                    "copy-in",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let chunks = [b"first".as_slice(), b"second".as_slice()];
            let mut future = Box::pin(copy.send_batch(&chunks, batch_limits()));
            let mut context = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut context).is_pending());
            drop(future);
            assert!(copy.session.transport.blocked);
            assert_eq!(copy.session.transport.packet.first(), Some(&b'd'));
            assert_eq!(copy.session.reuse_state(), ReuseState::NeedsCopyCompletion);
            assert!(matches!(
                copy.send(b"do not append").await,
                Err(Error::Busy)
            ));
            copy.session.transport.blocked = false;
            assert!(
                matches!(copy.fail("explicitly abandon").await, Ok(CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014")
            );
        }
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn scheduled_copy_collect_preserves_bytes_bounds_and_ready_task_fairness() {
    run_with_deadline(async {
        for allocation in [AllocationPolicy::ReserveLimit, AllocationPolicy::Grow] {
            let payloads = vec![b"abcdefgh".to_vec(); 8];
            let mut connection = session(Mode::Out(payloads), 8).await;
            let copy = connection
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Cooperative {
                        max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
                    },
                )
                .await
                .unwrap();
            let ran = Rc::new(Cell::new(false));
            let other = ran.clone();
            let task = compio::runtime::spawn(async move {
                other.set(true);
            });
            let (bytes, completion) = copy
                .collect_ready(
                    OwnedOutput {
                        max_bytes: 4096,
                        allocation,
                    },
                    OnError::RecoverExplicitly,
                )
                .await
                .unwrap();
            assert!(ran.get());
            assert_eq!(bytes, b"abcdefgh".repeat(8));
            assert_eq!(completion.rows, 8);
            assert_eq!(
                bytes.capacity(),
                if allocation == AllocationPolicy::ReserveLimit {
                    4096
                } else {
                    64
                }
            );
            task.await.unwrap();
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
        let mut connection = session(Mode::Out(vec![b"too much".to_vec()]), 1).await;
        let copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        assert!(matches!(
            copy.collect_ready(
                OwnedOutput {
                    max_bytes: 1,
                    allocation: AllocationPolicy::Grow,
                },
                OnError::Discard
            )
            .await,
            Err(Error::Limit(_))
        ));
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn dropping_collector_after_a_consumed_chunk_leaves_drainable_state() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::Out(vec![b"x".to_vec(); 4]), 4).await;
        let copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        let mut future = Box::pin(copy.collect_ready(
            OwnedOutput {
                max_bytes: 8,
                allocation: AllocationPolicy::Grow,
            },
            OnError::RecoverExplicitly,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        drop(future);
        assert_eq!(connection.transport.consumed, 7); // 启动、响应和第一块数据。
        assert_eq!(connection.reuse_state(), ReuseState::NeedsCopyCompletion);
        assert_eq!(
            connection.finish_abandoned_copy_out().await.unwrap().rows,
            4
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn separate_input_sends_share_one_scope_allowance() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        let mut copy = connection
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
                },
            )
            .await
            .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut first = Box::pin(copy.send(b"a"));
        assert!(matches!(
            first.as_mut().poll(&mut context),
            Poll::Ready(Ok(()))
        ));
        drop(first);
        let mut second = Box::pin(copy.send(b"b"));
        assert!(second.as_mut().poll(&mut context).is_pending());
        drop(second);
        assert!(
            copy.session
                .copy_state
                .as_ref()
                .unwrap()
                .quantum
                .is_exhausted()
        );
        drop(copy);
        assert!(matches!(
            connection.fail_abandoned_copy("stop").await,
            Ok(CopyAbort::Aborted { .. })
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn batched_empty_frames_spend_each_frame_not_only_packet_bytes() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::In, 0).await;
        let mut copy = connection
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::new(10).unwrap(),
                },
            )
            .await
            .unwrap();
        let chunks: [&[u8]; 9] = [b""; 9];
        let mut future = Box::pin(copy.send_batch(
            &chunks,
            CopyBatchLimits {
                max_chunks: 9,
                max_packet_bytes: 45,
            },
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        drop(future);
        assert!(
            copy.session
                .copy_state
                .as_ref()
                .unwrap()
                .quantum
                .is_exhausted()
        );
        assert_eq!(
            copy.session.transport.sent.last().unwrap(),
            &b"d\0\0\0\x04".repeat(9)
        );
        drop(copy);
        assert!(matches!(
            connection.fail_abandoned_copy("stop").await,
            Ok(CopyAbort::Aborted { .. })
        ));
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn output_chunk_bytes_are_charged_after_its_loan_is_retired() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::Out(vec![vec![b'x'; 3000]]), 1).await;
        let mut copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
                },
            )
            .await
            .unwrap();
        let chunk = copy.next_chunk().await.unwrap().unwrap();
        assert_eq!(chunk.bytes().len(), 3000);

        let mut future = Box::pin(copy.next_chunk());
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        drop(future);
        let state = copy.session.copy_state.as_ref().unwrap();
        assert_eq!(state.pending_chunk_bytes, 0);
        assert!(state.quantum.is_exhausted());
        assert_eq!(copy.session.transport.consumed, 7);
        drop(copy);
        assert_eq!(
            connection.finish_abandoned_copy_out().await.unwrap().rows,
            1
        );
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn final_ready_and_scheduling_pending_survive_rebuilt_finish_futures() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::Out(Vec::new()), 0).await;
        let copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut finish = Box::pin(copy.finish());
        assert!(finish.as_mut().poll(&mut context).is_pending());
        drop(finish);
        assert_eq!(connection.transport.consumed, 7);
        for expected in [8, 9] {
            let mut finish = Box::pin(connection.finish_abandoned_copy_out());
            assert!(finish.as_mut().poll(&mut context).is_pending());
            drop(finish);
            assert_eq!(connection.transport.consumed, expected);
        }
        assert_eq!(
            connection.copy_state.as_ref().unwrap().ready,
            Some(TransactionStatus::Idle)
        );
        assert_eq!(connection.remaining_boundaries, 0);
        assert!(connection.active);
        let mut finish = Box::pin(connection.finish_abandoned_copy_out());
        assert!(matches!(
            finish.as_mut().poll(&mut context),
            Poll::Ready(Ok(CopyCompletion { rows: 0, .. }))
        ));
        drop(finish);
        assert_eq!(connection.transport.consumed, 9);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_out_resumes_error_completion_after_waiter_drop() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::Out(Vec::new()), 0).await;
        let mut copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        copy.session.transport.frames = VecDeque::from([
            (b'E', b"SERROR\0C22000\0Mfailed output\0\0".to_vec()),
            (b'Z', vec![b'I']),
        ]);
        let mut context = Context::from_waker(Waker::noop());
        for expected_ready in [None, Some(TransactionStatus::Idle)] {
            let mut next = Box::pin(copy.next_chunk());
            assert!(next.as_mut().poll(&mut context).is_pending());
            drop(next);
            let state = copy.session.copy_state.as_ref().unwrap();
            assert!(state.error.is_some());
            assert_eq!(state.ready, expected_ready);
        }
        assert!(matches!(
            copy.next_chunk().await,
            Err(Error::Database(error)) if error.code() == "22000"
        ));
        drop(copy);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_input_does_not_reset_the_control_limit_when_sending_data() {
    run_with_deadline(async {
        let mut owner = session(Mode::In, 1).await;
        owner.max_messages = 3;
        let mut input = owner
            .copy_in(
                "copy-in",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        for _ in 0..2 {
            input
                .session
                .transport
                .frames
                .push_back((b'N', b"SNOTICE\0C00000\0Mnotice\0\0".to_vec()));
            input.send(b"data").await.unwrap();
        }
        assert!(matches!(input.finish().await, Err(Error::Limit(_))));
        assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn copy_out_charges_startup_notices_and_completion_but_excludes_data() {
    run_with_deadline(async {
        for (read_chunk, limit) in [(false, 6), (false, 7), (true, 6), (true, 7)] {
            let mut connection = session(Mode::Out(vec![b"row".to_vec()]), 1).await;
            let mut copy = connection
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            copy.session.max_messages = limit;
            for _ in 0..3 {
                copy.session
                    .transport
                    .frames
                    .push_front((b'N', b"SNOTICE\0C00000\0Mnotice\0\0".to_vec()));
            }
            if read_chunk {
                let chunk = copy.next_chunk().await.unwrap().unwrap();
                assert_eq!(chunk.bytes(), b"row");

                if limit == 7 {
                    assert!(copy.next_chunk().await.unwrap().is_none());
                }
            }
            let result = copy.finish().await;
            if limit == 7 {
                assert_eq!(result.unwrap().rows, 1);
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Limit("COPY exceeded its control-message limit"))
                ));
                assert_eq!(
                    connection.transport.frames.front().map(|(tag, _)| *tag),
                    Some(b'Z')
                );
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            }
        }
    });
}

#[test]
fn control_message_bound_is_not_replenished_by_scheduling_or_rebuilt_waiters() {
    use std::task::Waker;
    run_with_deadline(async {
        let mut connection = session(Mode::Out(Vec::new()), 0).await;
        let mut copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Cooperative {
                    max_work_per_turn: std::num::NonZeroUsize::MIN,
                },
            )
            .await
            .unwrap();
        copy.session.max_messages = 3;
        for _ in 0..3 {
            copy.session
                .transport
                .frames
                .push_front((b'N', b"SNOTICE\0C00000\0Mnotice\0\0".to_vec()));
        }
        let mut context = Context::from_waker(Waker::noop());
        for expected in [7, 8] {
            let mut next = Box::pin(copy.next_chunk());
            assert!(next.as_mut().poll(&mut context).is_pending());
            drop(next);
            assert_eq!(copy.session.transport.consumed, expected);
        }
        let mut next = Box::pin(copy.next_chunk());
        assert!(matches!(
            next.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::Limit(_)))
        ));
        drop(next);
        assert_eq!(copy.session.transport.consumed, 8);
        drop(copy);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[cfg(feature = "diagnostics")]
#[test]
fn copy_output_counts_each_collected_chunk_payload_once() {
    run_with_deadline(async {
        for allocation in [AllocationPolicy::ReserveLimit, AllocationPolicy::Grow] {
            let mut connection = session(Mode::Out(vec![b"abcdefgh".to_vec(); 4]), 4).await;
            let copy = connection
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let before = crate::diagnostics::snapshot();
            let (bytes, _) = copy
                .collect_ready(
                    OwnedOutput {
                        max_bytes: 64,
                        allocation,
                    },
                    OnError::RecoverExplicitly,
                )
                .await
                .unwrap();
            let counters = crate::diagnostics::snapshot().delta(before).unwrap();
            assert_eq!(bytes.len(), 32);
            assert_eq!(connection.transport.data_frame_reads, 4);
            assert_eq!(counters.copy_out_chunks_delivered, 4);
            assert_eq!(counters.copy_out_payload_bytes_delivered, 32);
            assert_eq!(counters.copy_out_payload_bytes_copied, 32);
        }
    });
}

#[test]
fn visiting_copy_output_reads_each_frame_once_and_confirms_completion() {
    run_with_deadline(async {
        for lend_first in [false, true] {
            let mut connection = session(Mode::Out(vec![b"abcdefgh".to_vec(); 4]), 4).await;
            let mut copy = connection
                .copy_out(
                    "copy-out",
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            if lend_first {
                assert_eq!(
                    copy.next_chunk().await.unwrap().unwrap().bytes(),
                    b"abcdefgh"
                );
            }
            let mut visited = 0;
            let completion = copy
                .visit_provisional(OnError::RecoverExplicitly, |bytes| {
                    assert_eq!(bytes, b"abcdefgh");
                    visited += 1;
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(visited, 4 - usize::from(lend_first));
            assert_eq!(completion.rows, 4);
            assert_eq!(
                connection.transport.data_frame_reads,
                4 + usize::from(lend_first)
            );
        }
    });
}

#[test]
fn visited_copy_output_marks_the_session_unusable_if_the_callback_panics() {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    run_with_deadline(async {
        let mut connection = session(Mode::Out(vec![b"x".to_vec()]), 1).await;
        let copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let result = AssertUnwindSafe(copy.visit_provisional(OnError::DrainToReady, |bytes| {
            assert_eq!(bytes, b"x");
            panic!("COPY output callback");
        }))
        .catch_unwind()
        .await;
        assert_eq!(
            result.unwrap_err().downcast_ref::<&str>(),
            Some(&"COPY output callback")
        );
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn copy_output_callback_error_can_drain_to_ready() {
    run_with_deadline(async {
        let mut connection = session(Mode::Out(vec![b"x".to_vec(); 2]), 2).await;
        let copy = connection
            .copy_out(
                "copy-out",
                &[],
                CopyProtocol::SimpleSingle,
                ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap();
        let mut visited = 0;
        let result = copy
            .visit_provisional(OnError::DrainToReady, |_| {
                visited += 1;
                Err(Error::InvalidInput("bad value"))
            })
            .await;
        assert!(matches!(result, Err(Error::InvalidInput("bad value"))));
        assert_eq!(visited, 1);
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[test]
fn copy_metadata_uses_inline_formats_for_uniform_columns() {
    for (body, format, count) in [
        (&[0, 0, 0][..], Format::Text, 0),
        (&[0, 0, 2, 0, 0, 0, 0][..], Format::Text, 2),
        (&[1, 0, 2, 0, 1, 0, 1][..], Format::Binary, 2),
        (&[1, 0, 2, 0, 0, 0, 0][..], Format::Text, 2),
    ] {
        let BackendMessage::CopyInResponse(response) =
            protocol::parse_backend(protocol::Frame { tag: b'G', body }).unwrap()
        else {
            panic!("expected CopyInResponse");
        };
        let info = CopyInfo::from_response(response).unwrap();
        assert_eq!(info.len(), count);
        assert_eq!(info.is_empty(), count == 0);
        assert_eq!(info.formats(), &ResultFormats::All(format));
    }

    let BackendMessage::CopyOutResponse(response) = protocol::parse_backend(protocol::Frame {
        tag: b'H',
        body: &[1, 0, 2, 0, 0, 0, 1],
    })
    .unwrap() else {
        panic!("expected CopyOutResponse");
    };
    let info = CopyInfo::from_response(response).unwrap();
    assert_eq!(info.len(), 2);
    assert_eq!(info.formats().as_slice(), [Format::Text, Format::Binary]);
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn uniform_copy_metadata_does_not_allocate() {
    let body = [1, 0, 2, 0, 1, 0, 1];
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    let BackendMessage::CopyInResponse(response) = protocol::parse_backend(protocol::Frame {
        tag: b'G',
        body: &body,
    })
    .unwrap() else {
        panic!("expected CopyInResponse");
    };
    let info = CopyInfo::from_response(response).unwrap();
    let result = region.change();
    assert_eq!(info.formats(), &ResultFormats::All(Format::Binary));
    assert_eq!(result.allocations, 0);
    assert_eq!(result.reallocations, 0);
}

#[cfg(all(feature = "tls", feature = "diagnostics"))]
mod tls_copy_out {
    use super::*;
    use crate::buffered::{BufferedTransport, ManagedStream};
    use futures_util::io::AsyncWrite;
    use std::{future::Future, io, task::Waker};

    struct PlaintextChunks {
        chunks: VecDeque<Vec<u8>>,
        offset: usize,
        visible: Rc<Cell<usize>>,
    }

    impl AsyncWrite for PlaintextChunks {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl ManagedStream for PlaintextChunks {
        fn plaintext(&mut self) -> io::Result<&[u8]> {
            if self.visible.get() == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let bytes = self.chunks.front().unwrap();
            Ok(&bytes[self.offset..])
        }

        fn consume_plaintext(&mut self, bytes: usize) -> Result<(), Error> {
            self.offset += bytes;
            let end = self.chunks.front().unwrap().len();
            assert!(self.offset <= end);
            if self.offset == end {
                self.chunks.pop_front();
                self.visible.set(self.visible.get() - 1);
                self.offset = 0;
            }
            Ok(())
        }

        fn poll_plaintext(&mut self, _: &mut Context<'_>) -> Poll<io::Result<usize>> {
            match self.plaintext() {
                Ok(bytes) => Poll::Ready(Ok(bytes.len())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            }
        }

        async fn dispose(self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    async fn split_output(
        visible: usize,
    ) -> (Session<BufferedTransport<PlaintextChunks>>, Rc<Cell<usize>>) {
        let startup = [
            frame(b'R', &0_i32.to_be_bytes()),
            frame(b'S', b"server_version\x0019.0\0"),
            frame(b'S', b"client_encoding\0UTF8\0"),
            frame(b'K', &[0; 12]),
            frame(b'Z', b"I"),
        ]
        .concat();
        let mut head = frame(b'd', b"abcdef");
        let mut tail = head.split_off(COPY_DATA_HEADER_BYTES + 2);
        tail.extend(frame(b'd', b"xy"));
        tail.extend(frame(b'c', &[]));
        tail.extend(frame(b'C', b"COPY 2\0"));
        tail.extend(frame(b'Z', b"I"));
        let visible = Rc::new(Cell::new(visible));
        let stream = PlaintextChunks {
            chunks: VecDeque::from([startup, frame(b'H', &[0, 0, 1, 0, 0]), head, tail]),
            offset: 0,
            visible: Rc::clone(&visible),
        };
        let limits = WireLimits::short_queries();
        let config = TcpConfig::plaintext(
            "127.0.0.1:1".parse().unwrap(),
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            limits,
            crate::client::socket_options::TEST_TCP_OPTIONS,
        );
        let transport = BufferedTransport::new(
            stream,
            limits.receive_capacity,
            limits.max_frame_len,
            limits.max_request_len,
        )
        .unwrap();
        let (mut session, settings) = Session::from_transport(transport, config, 1);
        session
            .startup(&settings.authentication, None)
            .await
            .unwrap();
        (session, visible)
    }

    #[test]
    fn collect_writes_split_payload_once_and_drains_after_a_whole_frame_limit() {
        run_with_deadline(async {
            for (allocation, max_bytes) in [
                (AllocationPolicy::ReserveLimit, 8),
                (AllocationPolicy::Grow, 8),
                (AllocationPolicy::Grow, 2),
            ] {
                let (mut owner, _) = split_output(4).await;
                let copy = owner
                    .copy_out(
                        "COPY fixture TO STDOUT",
                        &[],
                        CopyProtocol::SimpleSingle,
                        ExecutionScheduling::Uninterrupted,
                    )
                    .await
                    .unwrap();
                let baseline = crate::diagnostics::snapshot();
                let result = copy
                    .collect_ready(
                        OwnedOutput {
                            allocation,
                            max_bytes,
                        },
                        OnError::DrainToReady,
                    )
                    .await;
                let counters = crate::diagnostics::snapshot().delta(baseline).unwrap();
                assert_eq!(counters.tls_plaintext_bytes_copied, 0);
                if max_bytes == 8 {
                    let (bytes, done) = result.unwrap();
                    assert_eq!(bytes, b"abcdefxy");
                    assert_eq!(done.rows, 2);
                    assert_eq!(counters.copy_out_chunks_delivered, 2);
                    assert_eq!(counters.copy_out_payload_bytes_copied, 8);
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::Limit("COPY output exceeds its collection limit"))
                    ));
                    assert_eq!(counters.copy_out_chunks_delivered, 1);
                    assert_eq!(counters.copy_out_payload_bytes_copied, 0);
                }
                assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
            }
        });
    }

    #[test]
    fn finish_skips_the_rest_of_a_partially_received_payload_after_abandonment() {
        run_with_deadline(async {
            for borrowed in [false, true] {
                let (mut owner, visible) = split_output(3).await;
                let mut copy = owner
                    .copy_out(
                        "COPY fixture TO STDOUT",
                        &[],
                        CopyProtocol::SimpleSingle,
                        ExecutionScheduling::Uninterrupted,
                    )
                    .await
                    .unwrap();
                let mut cx = Context::from_waker(Waker::noop());
                let baseline = crate::diagnostics::snapshot();
                if borrowed {
                    {
                        let mut next = std::pin::pin!(copy.next_chunk());
                        assert!(next.as_mut().poll(&mut cx).is_pending());
                    }
                    visible.set(1);
                    assert_eq!(copy.finish().await.unwrap().rows, 2);
                } else {
                    {
                        let mut collect = std::pin::pin!(copy.collect_ready(
                            OwnedOutput {
                                max_bytes: 8,
                                allocation: AllocationPolicy::Grow
                            },
                            OnError::RecoverExplicitly,
                        ));
                        assert!(collect.as_mut().poll(&mut cx).is_pending());
                    }
                    assert_eq!(owner.reuse_state(), ReuseState::NeedsCopyCompletion);
                    visible.set(1);
                    assert_eq!(owner.finish_abandoned_copy_out().await.unwrap().rows, 2);
                }
                let counters = crate::diagnostics::snapshot().delta(baseline).unwrap();
                // 借用流仅在放弃前拼接了两字节，排空不复制剩余载荷。
                assert_eq!(counters.tls_plaintext_bytes_copied, 2 * u64::from(borrowed));
                assert_eq!(
                    counters.copy_out_payload_bytes_copied,
                    2 * u64::from(!borrowed)
                );
                assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
            }
        });
    }
}
