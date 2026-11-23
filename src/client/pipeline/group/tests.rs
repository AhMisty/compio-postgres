use super::*;
use crate::{
    AuthenticationPolicy, QueryLimits, ReuseState, StatementLimits, TcpConfig, WireLimits,
    protocol::{Frame, FrameParse},
    row::ResultFormats,
    types::Format,
};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::Future,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

fn run_with_deadline(test: impl Future<Output = ()>) {
    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(compio::time::timeout(
            std::time::Duration::from_secs(5),
            test,
        ))
        .expect("分组用例未在截止时间内完成");
}

/// 夹具缓存所有响应，直到当前窗口已接纳指定数量才开始交付。
struct ReadyTransport {
    frames: VecDeque<Vec<u8>>,
    packet: Vec<u8>,
    spare_packet: Vec<u8>,
    queue_limit: usize,
    hold_after: Option<(usize, usize)>,
    consumed: usize,
    broken: bool,
    group_packets: Vec<Vec<u8>>,
    capture_packets: bool,
    completed_groups: Rc<Cell<usize>>,
    peak_inflight: usize,
    receive_gate: usize,
    block_send: Rc<Cell<bool>>,
    fail_send: Rc<Cell<bool>>,
    send_waiter: Rc<RefCell<Option<Waker>>>,
    send_polls: Rc<Cell<usize>>,
}

impl ReadyTransport {
    fn awaiting_group_boundary(&self) -> bool {
        self.hold_after.is_some_and(|(groups, frames)| {
            self.group_packets.len() >= groups && self.consumed < frames
        })
    }

    fn record_packet(&mut self, packet: &[u8]) {
        if packet.first() == Some(&b'B') {
            self.group_packets.push(if self.capture_packets {
                packet.to_vec()
            } else {
                Vec::new()
            });
            self.peak_inflight = self
                .peak_inflight
                .max(self.group_packets.len() - self.completed_groups.get());
        }
    }
}

impl crate::transport::WireOps for ReadyTransport {
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
        self.record_packet(&bytes);
        self.packet = bytes;
        Ok(())
    }
    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
        if self.block_send.get() || self.awaiting_group_boundary() {
            return Err(Error::Busy);
        }
        Ok(std::mem::take(&mut self.packet))
    }
    fn start_send_queue(&mut self, bytes: usize) -> Result<Vec<u8>, Error> {
        let packet = self.take_send_buffer()?;
        self.queue_limit = bytes;
        if self.spare_packet.capacity() <= bytes {
            self.packet = std::mem::take(&mut self.spare_packet);
        } else {
            self.spare_packet = Vec::new();
        }
        Ok(if packet.capacity() <= bytes {
            packet
        } else {
            Vec::new()
        })
    }
    fn send_queue_available(&self) -> usize {
        if self.awaiting_group_boundary() {
            return 0;
        }
        self.queue_limit
    }
    fn enqueue_send_packet(&mut self, packet: &mut Vec<u8>) -> Result<bool, Error> {
        self.record_packet(packet);
        self.packet.clear();
        std::mem::swap(&mut self.packet, packet);
        Ok(true)
    }
    fn recycle_send_queue_buffer(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        if !packet.is_empty() {
            return Err(Error::InvalidInput("send scratch packet is not empty"));
        }
        self.spare_packet = packet;
        Ok(())
    }
    fn disable_send_queue(&mut self) -> Result<(), Error> {
        self.queue_limit = 0;
        Ok(())
    }
    fn poll_finish_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.send_polls.set(self.send_polls.get() + 1);
        if self.fail_send.get() {
            return Poll::Ready(Err(std::io::Error::other("late group TX failure").into()));
        }
        if self.block_send.get() {
            *self.send_waiter.borrow_mut() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_receive_frame(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.group_packets.len() < self.receive_gate && self.completed_groups.get() == 0 {
            return Poll::Pending;
        }
        if self.frames.is_empty() {
            return Poll::Ready(Err(
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()
            ));
        }
        Poll::Ready(self.frame().map(|_| ()))
    }
    fn frame(&mut self) -> Result<Frame<'_>, Error> {
        let bytes = self.frames.front().ok_or(Error::Broken)?;
        match protocol::parse_frame(bytes, 8191)? {
            FrameParse::Complete { frame, .. } => Ok(frame),
            FrameParse::NeedMore => Err(Error::Broken),
        }
    }
    fn consume_frame(&mut self) -> Result<(), Error> {
        let frame = self.frames.pop_front().ok_or(Error::Broken)?;
        if frame.first() == Some(&b'Z') && !self.group_packets.is_empty() {
            self.completed_groups.set(self.completed_groups.get() + 1);
        }
        self.consumed += 1;
        Ok(())
    }
    async fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

async fn session(groups: usize, rows: usize) -> Session<ReadyTransport> {
    session_with_slots(groups, rows, 1).await
}

async fn session_with_slots(groups: usize, rows: usize, slots: usize) -> Session<ReadyTransport> {
    let mut description = Vec::from(1_u16.to_be_bytes());
    description.extend_from_slice(b"n\0");
    description.extend_from_slice(&0_u32.to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    description.extend_from_slice(&23_u32.to_be_bytes());
    description.extend_from_slice(&4_i16.to_be_bytes());
    description.extend_from_slice(&(-1_i32).to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    let mut key = Vec::from(11_i32.to_be_bytes());
    key.extend_from_slice(&[0; 8]);
    let mut frames = VecDeque::from([
        frame(b'R', &0_i32.to_be_bytes()),
        frame(b'S', b"server_version\x0019.0\0"),
        frame(b'S', b"client_encoding\0UTF8\0"),
        frame(b'K', &key),
        frame(b'Z', b"I"),
        frame(b'1', &[]),
        frame(b't', &[0, 0]),
        frame(b'T', &description),
        frame(b'Z', b"I"),
    ]);
    for _ in 0..groups {
        frames.push_back(frame(b'2', &[]));
        for value in 0..rows {
            let mut body = Vec::from(1_u16.to_be_bytes());
            body.extend_from_slice(&4_i32.to_be_bytes());
            body.extend_from_slice(&i32::try_from(value).unwrap().to_be_bytes());
            frames.push_back(frame(b'D', &body));
        }
        frames.push_back(frame(b'C', format!("SELECT {rows}\0").as_bytes()));
        frames.push_back(frame(b'Z', b"I"));
    }
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
        ReadyTransport {
            frames,
            packet: Vec::new(),
            spare_packet: Vec::new(),
            queue_limit: 0,
            hold_after: None,
            consumed: 0,
            broken: false,
            group_packets: Vec::new(),
            capture_packets: true,
            completed_groups: Rc::new(Cell::new(0)),
            peak_inflight: 0,
            receive_gate: 0,
            block_send: Rc::new(Cell::new(false)),
            fail_send: Rc::new(Cell::new(false)),
            send_waiter: Rc::new(RefCell::new(None)),
            send_polls: Rc::new(Cell::new(0)),
        },
        config,
        1,
    );
    session
        .startup(&settings.authentication, None)
        .await
        .unwrap();
    session
        .configure_statements(StatementLimits {
            max_statements: slots,
            max_metadata_bytes: 8192,
        })
        .unwrap();
    session
}

fn limits(scheduling: ExecutionScheduling) -> ProvisionalGroupLimits {
    ProvisionalGroupLimits {
        max_requests: 8,
        max_rows: 64,
        max_member_result_bytes: 8192,
        scheduling,
    }
}

fn stream_limits(scheduling: ExecutionScheduling) -> GroupPipelineLimits {
    GroupPipelineLimits {
        max_requests: 8,
        max_groups: 8,
        max_rows: 64,
        max_member_result_bytes: 8192,
        max_packet_bytes: 8192,
        max_inflight_groups: 2,

        scheduling,
    }
}

async fn prepared(session: &mut Session<ReadyTransport>) -> crate::PreparedStatement {
    session
        .prepare("SELECT n", &[], ResultFormats::All(Format::Binary))
        .await
        .unwrap()
}

fn request(statement: &crate::PreparedStatement) -> PipelineRequest<'_> {
    PipelineRequest {
        statement,
        parameters: &[],
        limits: QueryLimits {
            max_rows: 64,
            max_result_bytes: 8192,
            max_metadata_bytes: 8192,
        },
    }
}

struct WakeProbe(AtomicUsize);
impl Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn frozen_busy_packet_wait_after_ready_advances_tx_and_refreshes_its_waker() {
    run_with_deadline(async {
        for fail in [false, true] {
            let mut connection = session(2, 1).await;
            let statement = prepared(&mut connection).await;
            let requests = [request(&statement)];
            let group = connection.compile_frozen_group(&requests, 8192).unwrap();
            let packet_len = group.encoded_packet_len();
            let blocked = Rc::clone(&connection.transport.block_send);
            let failed = Rc::clone(&connection.transport.fail_send);
            let waiter = Rc::clone(&connection.transport.send_waiter);
            let send_polls = Rc::clone(&connection.transport.send_polls);
            send_polls.set(0);
            blocked.set(true);
            let first_probe = Arc::new(WakeProbe(AtomicUsize::new(0)));
            let second_probe = Arc::new(WakeProbe(AtomicUsize::new(0)));
            let first_waker = Waker::from(Arc::clone(&first_probe));
            let second_waker = Waker::from(Arc::clone(&second_probe));
            let rows = Cell::new(0);
            let mut future = Box::pin(connection.replay_frozen_groups_provisional_visit(
                group,
                2,
                GroupPipelineLimits {
                    max_inflight_groups: 1,

                    ..stream_limits(ExecutionScheduling::Uninterrupted)
                },
                |event| {
                    if let ProvisionalGroupEvent::Row { row, .. } = event {
                        assert_eq!(row.decoder().decode_next::<i32>()?, 0);
                        rows.set(rows.get() + 1);
                    }
                    Ok(())
                },
            ));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            assert_eq!(rows.get(), 1);
            // 首次发送轮询后仅需一次纯发送等待，检查缓冲所有权不会导致每帧重复轮询。
            assert_eq!(send_polls.get(), 2);
            assert!(waiter.borrow().as_ref().unwrap().will_wake(&first_waker));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            assert_eq!(send_polls.get(), 3);
            assert!(waiter.borrow().as_ref().unwrap().will_wake(&second_waker));
            waiter.borrow().as_ref().unwrap().wake_by_ref();
            assert_eq!(first_probe.0.load(Ordering::Relaxed), 0);
            assert_eq!(second_probe.0.load(Ordering::Relaxed), 1);
            if fail {
                failed.set(true);
            } else {
                blocked.set(false);
            }
            let Poll::Ready(result) = future
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker))
            else {
                panic!("retired or failed TX must resolve the replay wait")
            };
            drop(future);
            if fail {
                let error = result.unwrap_err();
                assert!(matches!(error.source, Error::Io(_)));
                assert_eq!(
                    error.progress,
                    GroupPipelineProgress {
                        admitted_groups: 1,
                        admitted_requests: 1,
                        ready_groups: 1,
                        ready_requests: 1,
                        last_ready_transaction_status: Some(TransactionStatus::Idle),
                    }
                );
                assert_eq!(rows.get(), 1);
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            } else {
                let (token, completion) = result.unwrap();
                assert_eq!(token.encoded_packet_len(), packet_len);
                assert_eq!(
                    (completion.groups, completion.requests, rows.get()),
                    (2, 2, 2)
                );
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    });
}

#[test]
fn first_frozen_send_failure_preserves_handed_off_requests_before_ready() {
    run_with_deadline(async {
        let mut connection = session(0, 0).await;
        let statement = prepared(&mut connection).await;
        let group = connection
            .compile_frozen_group(&[request(&statement), request(&statement)], 8192)
            .unwrap();
        connection.transport.fail_send.set(true);
        let error = connection
            .replay_frozen_groups_provisional_visit(
                group,
                2,
                stream_limits(ExecutionScheduling::Uninterrupted),
                |_| panic!("发送出错前没有结果"),
            )
            .await
            .unwrap_err();
        assert!(matches!(error.source, Error::Io(_)));
        assert_eq!(
            error.progress,
            GroupPipelineProgress {
                admitted_groups: 1,
                admitted_requests: 2,
                ..GroupPipelineProgress::default()
            }
        );
        assert_eq!(connection.transport.group_packets.len(), 1);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn arbitrary_group_windows_fill_before_responses_without_merging_syncs() {
    run_with_deadline(async {
        for frozen in [false, true] {
            for consume in [false, true] {
                for window in [1, 3, 8, usize::MAX] {
                    let groups = 9;
                    let mut connection = session(groups, 1).await;
                    let statement = prepared(&mut connection).await;
                    connection.transport.receive_gate = window.min(groups);
                    let requests = [request(&statement)];
                    let selected = GroupPipelineLimits {
                        max_requests: groups,
                        max_groups: groups,
                        max_inflight_groups: window,
                        ..stream_limits(ExecutionScheduling::Uninterrupted)
                    };
                    let mut indices = Vec::new();
                    let mut checked = |event: ProvisionalGroupEvent<'_>| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            assert_eq!(row.decoder().decode_next::<i32>()?, 0);
                            indices.push(index);
                        }
                        Ok(())
                    };
                    let mut consumed = Vec::new();
                    let mut consuming = |event: ProvisionalGroupConsumeEvent<'_, '_, '_>| {
                        if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                            assert_eq!(row.decode_next::<i32>()?, 0);
                            consumed.push(index);
                        }
                        Ok(())
                    };
                    let completion = if frozen {
                        let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                        if consume {
                            connection
                                .replay_frozen_groups_provisional_consume(
                                    group,
                                    groups,
                                    selected,
                                    &mut consuming,
                                )
                                .await
                                .unwrap()
                                .1
                        } else {
                            connection
                                .replay_frozen_groups_provisional_visit(
                                    group,
                                    groups,
                                    selected,
                                    &mut checked,
                                )
                                .await
                                .unwrap()
                                .1
                        }
                    } else {
                        let mut source = std::iter::repeat_n(requests.as_slice(), groups);
                        if consume {
                            connection
                                .query_groups_provisional_consume(
                                    &mut source,
                                    selected,
                                    &mut consuming,
                                )
                                .await
                                .unwrap()
                        } else {
                            connection
                                .query_groups_provisional_visit(&mut source, selected, &mut checked)
                                .await
                                .unwrap()
                        }
                    };
                    assert_eq!(completion.groups, groups);
                    assert_eq!(completion.requests, groups);
                    assert_eq!(
                        if consume { consumed } else { indices },
                        (0..groups).collect::<Vec<_>>()
                    );
                    assert_eq!(connection.transport.peak_inflight, window.min(groups));
                    assert_eq!(connection.transport.group_packets.len(), groups);
                    for packet in &connection.transport.group_packets {
                        let mut bytes = packet.as_slice();
                        let mut tags = Vec::new();
                        while !bytes.is_empty() {
                            let FrameParse::Complete { frame, consumed } =
                                protocol::parse_frame(bytes, 8191).unwrap()
                            else {
                                panic!("truncated group packet")
                            };
                            tags.push(frame.tag);
                            bytes = &bytes[consumed..];
                        }
                        assert_eq!(tags, b"BES");
                    }
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                }
            }
        }
    });
}

#[test]
fn state_changes_revalidate_only_the_locally_encoded_group() {
    run_with_deadline(async {
        for (change, before_command, unnamed, in_tx) in [
            ("SET", true, false, false),
            ("SET", false, false, false),
            ("SET", true, false, true),
            ("SET", false, false, true),
            ("DEALLOCATE ALL", false, false, false),
            ("DEALLOCATE ALL", false, false, true),
            ("DEALLOCATE ALL", false, true, false),
        ] {
            let mut owner = session_with_slots(0, 0, 2).await;
            let format = ResultFormats::All(Format::Binary);
            let data = if unnamed {
                owner
                    .prepare_replace_unnamed("SELECT 1", &[], format.clone())
                    .await
                    .unwrap()
            } else {
                owner
                    .prepare("SELECT 1", &[], format.clone())
                    .await
                    .unwrap()
            };
            owner.transport.frames.extend([
                frame(b'1', &[]),
                frame(b't', &[0, 0]),
                frame(b'n', &[]),
                frame(b'Z', b"I"),
            ]);
            let sql = if change == "SET" {
                "SET search_path TO public"
            } else {
                change
            };
            let changing = owner.prepare(sql, &[], format).await.unwrap();
            let status = if in_tx { b"T" } else { b"I" };
            if in_tx {
                owner
                    .transport
                    .frames
                    .extend([frame(b'C', b"BEGIN\0"), frame(b'Z', status)]);
            }
            let ordinary = || {
                [
                    frame(b'2', &[]),
                    frame(b'C', b"SELECT 0\0"),
                    frame(b'Z', status),
                ]
            };
            owner.transport.frames.extend(ordinary());
            owner.transport.frames.push_back(frame(b'2', &[]));
            let path = || frame(b'S', b"search_path\0public\0");
            if before_command {
                owner.transport.frames.push_back(path());
            }
            owner
                .transport
                .frames
                .push_back(frame(b'C', format!("{change}\0").as_bytes()));
            if change == "SET" && !before_command {
                owner.transport.frames.push_back(path());
            }
            owner.transport.frames.push_back(frame(b'Z', status));
            // 前两组可以提交；第三组直到第二个 Ready 才有发送空间，期间只允许预读和编码。
            owner.transport.hold_after =
                Some((2, owner.transport.consumed + owner.transport.frames.len()));
            owner.transport.frames.extend(ordinary());
            let data_group = [request(&data)];
            let control_group = [request(&changing)];
            let mut pulled = 0;
            let mut input = [
                data_group.as_slice(),
                control_group.as_slice(),
                data_group.as_slice(),
            ]
            .into_iter()
            .inspect(|_| pulled += 1);
            let mut commands = Vec::new();
            let settings = GroupPipelineLimits {
                max_inflight_groups: 3,
                ..stream_limits(ExecutionScheduling::Uninterrupted)
            };
            let collect = |event: ProvisionalGroupEvent<'_>| {
                if let ProvisionalGroupEvent::Command { index, .. } = event {
                    commands.push(index);
                }
                Ok(())
            };
            let result = if in_tx {
                let mut tx = owner.begin_transaction().await.unwrap();
                tx.query_groups_provisional_visit(&mut input, settings, collect)
                    .await
            } else {
                owner
                    .query_groups_provisional_visit(&mut input, settings, collect)
                    .await
            };
            assert_eq!(pulled, 3);
            if unnamed {
                // 命名 DEALLOCATE ALL 不使这个未命名语句失效。
                assert_eq!(result.unwrap().groups, 3);
                assert_eq!(commands, [0, 1, 2]);
                assert_eq!(owner.transport.group_packets.len(), 3);
                assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
            } else {
                let expected = if change == "SET" {
                    "statement metadata was invalidated; close and prepare it again"
                } else {
                    "statement handle is stale"
                };
                let error = result.unwrap_err();
                assert!(matches!(error.source, Error::InvalidInput(reason) if reason == expected));
                assert_eq!(
                    error.progress,
                    GroupPipelineProgress {
                        admitted_groups: 2,
                        admitted_requests: 2,
                        ready_groups: 2,
                        ready_requests: 2,
                        last_ready_transaction_status: Some(if in_tx {
                            TransactionStatus::InTransaction
                        } else {
                            TransactionStatus::Idle
                        }),
                    }
                );
                assert_eq!(commands, [0, 1]);
                assert_eq!(owner.transport.completed_groups.get(), 2);
                assert_eq!(owner.transport.group_packets.len(), 2);
                assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
                assert!(matches!(owner.recover_to_ready().await, Err(Error::Broken)));
            }
        }
    });
}

#[test]
fn frozen_replay_rechecks_after_an_observed_change_before_sending_another_group() {
    run_with_deadline(async {
        let mut owner = session(0, 0).await;
        let statement = prepared(&mut owner).await;
        let group = owner
            .compile_frozen_group(&[request(&statement)], 8192)
            .unwrap();
        for changes in [false, true] {
            owner.transport.frames.push_back(frame(b'2', &[]));
            owner.transport.frames.push_back(frame(b'C', b"SELECT 0\0"));
            if changes {
                owner
                    .transport
                    .frames
                    .push_back(frame(b'S', b"search_path\0public\0"));
            }
            owner.transport.frames.push_back(frame(b'Z', b"I"));
        }
        owner.transport.hold_after =
            Some((2, owner.transport.consumed + owner.transport.frames.len()));
        let mut delivered = Vec::new();
        let result = owner
            .replay_frozen_groups_provisional_visit(
                group,
                3,
                GroupPipelineLimits {
                    max_inflight_groups: 3,
                    ..stream_limits(ExecutionScheduling::Uninterrupted)
                },
                |event| {
                    if let ProvisionalGroupEvent::Command { index, .. } = event {
                        delivered.push(index);
                    }
                    Ok(())
                },
            )
            .await;
        let error = result.unwrap_err();
        assert!(matches!(
            error.source,
            Error::InvalidInput("statement metadata was invalidated; close and prepare it again")
        ));
        assert_eq!(
            error.progress,
            GroupPipelineProgress {
                admitted_groups: 2,
                admitted_requests: 2,
                ready_groups: 2,
                ready_requests: 2,
                last_ready_transaction_status: Some(TransactionStatus::Idle),
            }
        );
        assert_eq!(delivered, [0, 1]);
        assert_eq!(owner.transport.completed_groups.get(), 2);
        assert_eq!(owner.transport.group_packets.len(), 2);
        assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
    });
}

#[test]
fn invalid_group_window_is_rejected_before_source_or_packet_handoff() {
    run_with_deadline(async {
        let oversized_window =
            (isize::MAX as usize) / std::mem::size_of::<&[PipelineRequest<'_>]>() + 1;
        for (window, packet_bytes) in [
            (0, 8192),
            (8, 0),
            (8, 8193),
            (oversized_window, 8192),
            (usize::MAX, 8192),
        ] {
            let mut connection = session(0, 0).await;
            let _statement = prepared(&mut connection).await;
            let mut source = std::iter::from_fn(|| -> Option<&[PipelineRequest<'_>]> {
                panic!("invalid window must be rejected before examining input")
            });
            let result = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_requests: usize::MAX,
                        max_groups: usize::MAX,
                        max_inflight_groups: window,
                        max_packet_bytes: packet_bytes,
                        ..stream_limits(ExecutionScheduling::Uninterrupted)
                    },
                    |_| panic!("invalid window cannot deliver rows"),
                )
                .await;
            let error = result.unwrap_err();
            assert!(matches!(
                error.source,
                Error::InvalidInput(_) | Error::Limit(_)
            ));
            assert_eq!(error.progress, GroupPipelineProgress::default());
            assert!(connection.transport.group_packets.is_empty());
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn known_input_bounds_group_window_metadata_even_for_unlimited_group_bounds() {
    run_with_deadline(async {
        for max_requests in [1, usize::MAX] {
            let mut connection = session(1, 1).await;
            let statement = prepared(&mut connection).await;
            let requests = [request(&statement)];
            let completion = connection
                .query_groups_provisional_visit(
                    &mut std::iter::once(requests.as_slice()),
                    GroupPipelineLimits {
                        max_requests,
                        max_groups: usize::MAX,
                        max_inflight_groups: usize::MAX,
                        ..stream_limits(ExecutionScheduling::Uninterrupted)
                    },
                    |_| Ok(()),
                )
                .await
                .unwrap();
            assert_eq!((completion.requests, completion.groups), (1, 1));
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn group_error_stops_admission_and_preserves_discard_failure_policy() {
    run_with_deadline(async {
        for frozen in [false, true] {
            let mut connection = session(8, 1).await;
            let statement = prepared(&mut connection).await;
            connection.transport.frames[1] = frame(b'E', b"SERROR\0C22012\0Mdivision by zero\0\0");
            connection.transport.receive_gate = 4;
            let requests = [request(&statement)];
            let selected = GroupPipelineLimits {
                max_inflight_groups: 4,
                ..stream_limits(ExecutionScheduling::Uninterrupted)
            };
            let examined = Cell::new(0);
            let mut source = std::iter::repeat_n(requests.as_slice(), 8)
                .inspect(|_| examined.set(examined.get() + 1));
            let result = if frozen {
                let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                connection
                    .replay_frozen_groups_provisional_visit(group, 8, selected, |_| {
                        panic!("failed group cannot deliver a successful row")
                    })
                    .await
                    .map(|(_, completion)| completion)
            } else {
                connection
                    .query_groups_provisional_visit(&mut source, selected, |_| {
                        panic!("failed group cannot deliver a successful row")
                    })
                    .await
            };
            let error = result.unwrap_err();
            assert!(matches!(error.source, Error::Database(_)));
            assert_eq!(
                error.progress,
                GroupPipelineProgress {
                    admitted_groups: 4,
                    admitted_requests: 4,
                    ..GroupPipelineProgress::default()
                }
            );
            assert_eq!(connection.transport.group_packets.len(), 4);
            assert_eq!(connection.transport.completed_groups.get(), 0);
            assert_eq!(examined.get(), if frozen { 0 } else { 4 });
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        }
    });
}

#[test]
fn admitted_groups_outlast_the_last_validated_ready_on_terminal_failures() {
    #[derive(Clone, Copy)]
    enum Ending {
        SqlError,
        FatalError,
        Eof,
        InvalidReady,
    }

    run_with_deadline(async {
        for ending in [
            Ending::SqlError,
            Ending::FatalError,
            Ending::Eof,
            Ending::InvalidReady,
        ] {
            for in_transaction in [false, true] {
                let mut connection = session(0, 0).await;
                let statement = prepared(&mut connection).await;
                let (expected_status, ready_body) = if in_transaction {
                    connection
                        .transport
                        .frames
                        .extend([frame(b'C', b"BEGIN\0"), frame(b'Z', b"T")]);
                    (TransactionStatus::InTransaction, b"T")
                } else {
                    (TransactionStatus::Idle, b"I")
                };
                connection.transport.frames.extend([
                    frame(b'2', &[]),
                    frame(b'C', b"SELECT 0\0"),
                    frame(b'2', &[]),
                    frame(b'C', b"SELECT 0\0"),
                    frame(b'Z', ready_body),
                    frame(b'2', &[]),
                    frame(b'C', b"SELECT 0\0"),
                ]);
                match ending {
                    Ending::SqlError => connection.transport.frames.extend([
                        frame(b'E', b"SERROR\0C40001\0Mfixture serialization failure\0\0"),
                        frame(b'Z', ready_body),
                    ]),
                    Ending::FatalError => connection.transport.frames.extend([
                        frame(b'E', b"SFATAL\0C57P01\0Mfixture shutdown\0\0"),
                        frame(b'Z', ready_body),
                    ]),
                    Ending::Eof => {}
                    Ending::InvalidReady => {
                        connection.transport.frames.push_back(frame(b'Z', b"?"))
                    }
                }

                let first = [request(&statement), request(&statement)];
                let second = [request(&statement)];
                let third = [
                    request(&statement),
                    request(&statement),
                    request(&statement),
                ];
                let mut source =
                    [first.as_slice(), second.as_slice(), third.as_slice()].into_iter();
                let limits = GroupPipelineLimits {
                    max_inflight_groups: 3,
                    ..stream_limits(ExecutionScheduling::Uninterrupted)
                };
                let mut commands = Vec::new();
                let error = if in_transaction {
                    let mut transaction = connection.begin_transaction().await.unwrap();
                    transaction
                        .query_groups_provisional_consume(&mut source, limits, |event| {
                            if let ProvisionalGroupConsumeEvent::Command { index, .. } = event {
                                commands.push(index);
                            }
                            Ok(())
                        })
                        .await
                        .unwrap_err()
                } else {
                    connection
                        .query_groups_provisional_visit(&mut source, limits, |event| {
                            if let ProvisionalGroupEvent::Command { index, .. } = event {
                                commands.push(index);
                            }
                            Ok(())
                        })
                        .await
                        .unwrap_err()
                };
                match ending {
                    Ending::SqlError => assert!(
                        matches!(error.source, Error::Database(ref error) if error.code() == "40001")
                    ),
                    Ending::FatalError => assert!(
                        matches!(error.source, Error::Database(ref error) if error.code() == "57P01")
                    ),
                    Ending::Eof => assert!(
                        matches!(error.source, Error::Io(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
                    ),
                    Ending::InvalidReady => assert!(matches!(error.source, Error::Protocol(_))),
                }
                assert_eq!(
                    error.progress,
                    GroupPipelineProgress {
                        admitted_groups: 3,
                        admitted_requests: 6,
                        ready_groups: 1,
                        ready_requests: 2,
                        last_ready_transaction_status: Some(expected_status),
                    }
                );
                assert_eq!(commands, [0, 1, 2]);
                assert_eq!(connection.transport.peak_inflight, 3);
                assert_eq!(connection.transport.completed_groups.get(), 1);
                assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
            }
        }
    });
}

#[test]
fn failure_after_the_final_ready_preserves_harvested_progress() {
    enum Execution {
        Single,
        Window,
        Frozen,
    }

    run_with_deadline(async {
        let foreign = compio::runtime::Runtime::new().unwrap();
        for (execution, resume_on_foreign) in [
            (Execution::Single, false),
            (Execution::Single, true),
            (Execution::Window, false),
            (Execution::Window, true),
            (Execution::Frozen, false),
            (Execution::Frozen, true),
        ] {
            let mut connection = session(1, 0).await;
            let statement = prepared(&mut connection).await;
            let completed = Rc::clone(&connection.transport.completed_groups);
            let fail_send = Rc::clone(&connection.transport.fail_send);
            let requests = [request(&statement)];
            let scheduling = ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::MIN,
            };
            let error = {
                let mut pending = std::pin::pin!(async {
                    match execution {
                        Execution::Single => {
                            connection
                                .query_group_provisional_visit(
                                    &requests,
                                    limits(scheduling),
                                    |_| Ok(()),
                                )
                                .await
                        }
                        Execution::Window => {
                            connection
                                .query_groups_provisional_visit(
                                    &mut std::iter::once(requests.as_slice()),
                                    stream_limits(scheduling),
                                    |_| Ok(()),
                                )
                                .await
                        }
                        Execution::Frozen => {
                            let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                            connection
                                .replay_frozen_group_provisional_consume(
                                    group,
                                    limits(scheduling),
                                    |_| Ok(()),
                                )
                                .await
                                .map(|(_, completion)| completion)
                        }
                    }
                });
                let mut cx = Context::from_waker(Waker::noop());
                for _ in (0..16).take_while(|_| completed.get() == 0) {
                    assert!(pending.as_mut().poll(&mut cx).is_pending());
                }
                assert_eq!(completed.get(), 1);
                let result = if resume_on_foreign {
                    foreign.enter(|| pending.as_mut().poll(&mut cx))
                } else {
                    fail_send.set(true);
                    pending.as_mut().poll(&mut cx)
                };
                let Poll::Ready(Err(error)) = result else {
                    panic!("Ready 后的错误须结束等待");
                };
                error
            };
            if resume_on_foreign {
                assert!(matches!(error.source, Error::InvalidInput(_)));
            } else {
                assert!(matches!(error.source, Error::Io(_)));
            }
            assert_eq!(
                error.progress,
                GroupPipelineProgress {
                    admitted_groups: 1,
                    admitted_requests: 1,
                    ready_groups: 1,
                    ready_requests: 1,
                    last_ready_transaction_status: Some(TransactionStatus::Idle),
                }
            );
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        }
    });
}

#[test]
fn frozen_window_zero_and_request_overflow_fail_before_packet_handoff() {
    run_with_deadline(async {
        for overflow in [false, true] {
            let mut connection = session(0, 0).await;
            let statement = prepared(&mut connection).await;
            let requests = [request(&statement), request(&statement)];
            let group = connection.compile_frozen_group(&requests, 8192).unwrap();
            let selected = GroupPipelineLimits {
                max_inflight_groups: if overflow { 4 } else { 0 },
                max_requests: usize::MAX,
                max_groups: usize::MAX,
                ..stream_limits(ExecutionScheduling::Uninterrupted)
            };
            let result = connection
                .replay_frozen_groups_provisional_visit(
                    group,
                    if overflow { usize::MAX } else { 0 },
                    selected,
                    |_| panic!("invalid replay cannot deliver rows"),
                )
                .await;
            let error = result.unwrap_err();
            assert!(matches!(
                error.source,
                Error::InvalidInput(_) | Error::Limit(_)
            ));
            assert_eq!(error.progress, GroupPipelineProgress::default());
            assert!(connection.transport.group_packets.is_empty());
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn cached_responses_share_one_allowance_across_dynamic_and_frozen_groups() {
    run_with_deadline(async {
        for frozen in [false, true] {
            for multiple in [false, true] {
                for scheduling in [
                    ExecutionScheduling::Uninterrupted,
                    ExecutionScheduling::Cooperative {
                        max_work_per_turn: std::num::NonZeroUsize::new(if multiple {
                            6
                        } else {
                            4
                        })
                        .unwrap(),
                    },
                ] {
                    let groups = if multiple { 3 } else { 1 };
                    let rows_per_group = if multiple { 1 } else { 8 };
                    let mut connection = session(groups, rows_per_group).await;
                    let statement = prepared(&mut connection).await;
                    let requests = [request(&statement)];
                    let rows = Rc::new(Cell::new(0));
                    let observed = Rc::new(Cell::new(None));
                    let task = RefCell::new(None);
                    let mut visitor = |event: ProvisionalGroupEvent<'_>| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            assert_eq!(index, rows.get() / rows_per_group);
                            assert_eq!(
                                row.decoder().decode_next::<i32>()?,
                                i32::try_from(rows.get() % rows_per_group).unwrap()
                            );
                            rows.set(rows.get() + 1);
                            if task.borrow().is_none() {
                                let rows = rows.clone();
                                let observed = observed.clone();
                                *task.borrow_mut() = Some(compio::runtime::spawn(async move {
                                    observed.set(Some(rows.get()));
                                }));
                            }
                        }
                        Ok(())
                    };
                    let completion = if frozen {
                        let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                        if multiple {
                            connection
                                .replay_frozen_groups_provisional_visit(
                                    group,
                                    groups,
                                    stream_limits(scheduling),
                                    &mut visitor,
                                )
                                .await
                                .unwrap()
                                .1
                        } else {
                            connection
                                .replay_frozen_group_provisional_visit(
                                    group,
                                    limits(scheduling),
                                    &mut visitor,
                                )
                                .await
                                .unwrap()
                                .1
                        }
                    } else if multiple {
                        connection
                            .query_groups_provisional_visit(
                                &mut std::iter::repeat_n(requests.as_slice(), groups),
                                stream_limits(scheduling),
                                &mut visitor,
                            )
                            .await
                            .unwrap()
                    } else {
                        connection
                            .query_group_provisional_visit(
                                &requests,
                                limits(scheduling),
                                &mut visitor,
                            )
                            .await
                            .unwrap()
                    };
                    let expected_rows = groups * rows_per_group;
                    assert_eq!(completion.rows_returned, expected_rows);
                    match scheduling {
                        ExecutionScheduling::Uninterrupted => assert_eq!(observed.get(), None),
                        ExecutionScheduling::Cooperative { .. } => {
                            assert!(observed.get().is_some_and(|count| count < expected_rows));
                        }
                    }
                    task.into_inner().unwrap().await.unwrap();
                    assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
                }
            }
        }
    });
}

#[test]
fn a_forgotten_provisional_group_cannot_be_recovered_after_ready() {
    run_with_deadline(async {
        let mut connection = session(1, 0).await;
        let statement = prepared(&mut connection).await;
        let requests = [request(&statement)];
        let scheduling = ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::MIN,
        };
        let mut future = Box::pin(connection.query_group_provisional_visit(
            &requests,
            limits(scheduling),
            |_| Ok(()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        // 编码包、BindComplete、CommandComplete 和 Ready 各有一个调度点。
        for _ in 0..4 {
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        std::mem::forget(future);
        assert_eq!(connection.remaining_boundaries, 0);
        assert_eq!(connection.transport.completed_groups.get(), 1);
        assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        assert!(matches!(
            connection.recover_to_ready().await,
            Err(Error::Broken)
        ));
        assert!(connection.transport.is_broken());
    });
}

#[test]
fn dropping_at_a_consumed_row_checkpoint_discards_dynamic_and_frozen_sessions() {
    run_with_deadline(async {
        for frozen in [false, true] {
            let mut connection = session(1, 8).await;
            let statement = prepared(&mut connection).await;
            let requests = [request(&statement)];
            let scheduling = ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::MIN,
            };
            let consumed = connection.transport.consumed;
            let rows = Cell::new(0);
            let visitor = |event: ProvisionalGroupConsumeEvent<'_, '_, '_>| {
                if let ProvisionalGroupConsumeEvent::Row { row, .. } = event {
                    assert_eq!(row.decode_next::<i32>()?, 0);
                    rows.set(rows.get() + 1);
                }
                Ok(())
            };
            if frozen {
                let group = connection.compile_frozen_group(&requests, 8192).unwrap();
                let mut future = Box::pin(connection.replay_frozen_group_provisional_consume(
                    group,
                    limits(scheduling),
                    visitor,
                ));
                let mut cx = Context::from_waker(Waker::noop());
                for _ in (0..16).take_while(|_| rows.get() == 0) {
                    assert!(future.as_mut().poll(&mut cx).is_pending());
                }
                drop(future);
            } else {
                let mut future = Box::pin(connection.query_group_provisional_consume(
                    &requests,
                    limits(scheduling),
                    visitor,
                ));
                let mut cx = Context::from_waker(Waker::noop());
                for _ in (0..16).take_while(|_| rows.get() == 0) {
                    assert!(future.as_mut().poll(&mut cx).is_pending());
                }
                drop(future);
            }
            assert_eq!(rows.get(), 1);
            assert_eq!(connection.transport.consumed, consumed + 2);
            assert_eq!(connection.reuse_state(), ReuseState::DiscardOnly);
        }
    });
}

struct CountedSource<'input> {
    entries: std::vec::IntoIter<&'input [PipelineRequest<'input>]>,
    consumed: Rc<Cell<usize>>,
    polls: Rc<Cell<usize>>,
}

impl<'input> Iterator for CountedSource<'input> {
    type Item = &'input [PipelineRequest<'input>];

    fn next(&mut self) -> Option<Self::Item> {
        self.polls.set(self.polls.get() + 1);
        let entry = self.entries.next()?;
        self.consumed.set(self.consumed.get() + 1);
        Some(entry)
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn window_storage_allocates_once_only_for_multiple_inflight_items() {
    for width in [1, 2, 8] {
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let mut groups = WindowQueue::<&[PipelineRequest<'_>]>::default();
        groups.prepare(width, width).unwrap();
        for _ in 0..32 {
            for _ in 0..width {
                groups.push_back(std::hint::black_box(&[])).unwrap();
            }
            for _ in 0..width {
                assert!(std::hint::black_box(groups.pop_front()).is_some());
            }
            assert!(groups.pop_front().is_none());
        }
        let stats = region.change();
        assert_eq!(stats.allocations, usize::from(width > 1));
        assert_eq!(stats.reallocations, 0);
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn empty_group_stream_does_not_allocate_window_metadata() {
    run_with_deadline(async {
        let mut connection = session(0, 0).await;
        for width in [1, 8, 256, 4096] {
            for empty_entries in [0, 3] {
                let mut polls = 0;
                let mut source = std::iter::from_fn(|| {
                    polls += 1;
                    (polls <= empty_entries).then_some(&[][..])
                });
                let options = GroupPipelineLimits {
                    max_groups: width.max(empty_entries),
                    max_requests: width,
                    max_inflight_groups: width,
                    ..stream_limits(ExecutionScheduling::Uninterrupted)
                };
                let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
                let result = connection
                    .query_groups_provisional_visit(&mut source, options, |_| {
                        panic!("an empty stream cannot deliver results")
                    })
                    .await
                    .unwrap();
                let stats = region.change();
                assert_eq!((stats.allocations, stats.reallocations), (0, 0));
                assert_eq!(
                    (result.requests, result.groups, result.rows_returned),
                    (0, 0, 0)
                );
                assert_eq!(polls, empty_entries + 1);
                assert!(connection.transport.group_packets.is_empty());
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    });
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn rejected_first_group_does_not_allocate_window_storage() {
    run_with_deadline(async {
        let mut connection = session(0, 0).await;
        let statement = prepared(&mut connection).await;
        let parameters = [crate::types::Parameter::int4(1)];
        let invalid = [PipelineRequest {
            parameters: &parameters,
            ..request(&statement)
        }];
        let mut source = std::iter::repeat_n(invalid.as_slice(), 8);
        let limits = GroupPipelineLimits {
            max_inflight_groups: 8,
            ..stream_limits(ExecutionScheduling::Uninterrupted)
        };
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let result = connection
            .query_groups_provisional_visit(&mut source, limits, |_| {
                unreachable!("无效的首组不能交付结果")
            })
            .await;
        let stats = region.change();
        let error = result.unwrap_err();
        assert!(matches!(error.source, Error::InvalidInput(_)));
        assert_eq!(error.progress, GroupPipelineProgress::default());
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
        assert!(connection.transport.group_packets.is_empty());
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
    });
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn warmed_group_stream_only_allocates_window_metadata() {
    run_with_deadline(async {
        for width in [1, 2, 3, 8] {
            let mut connection = session(width * 2, 1).await;
            let statement = prepared(&mut connection).await;
            connection.transport.capture_packets = false;
            connection.transport.group_packets.reserve_exact(width * 2);
            let requests = [request(&statement)];
            let limits = GroupPipelineLimits {
                max_inflight_groups: width,
                ..stream_limits(ExecutionScheduling::Uninterrupted)
            };
            connection
                .query_groups_provisional_visit(
                    &mut std::iter::repeat_n(requests.as_slice(), width),
                    limits,
                    |_| Ok(()),
                )
                .await
                .unwrap();

            // 预热后只测组描述符；发送包和记录槽均沿用已有存储。
            let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
            let mut next_index = 0;
            let completion = connection
                .query_groups_provisional_consume(
                    &mut std::iter::repeat_n(requests.as_slice(), width),
                    limits,
                    |event| {
                        if let ProvisionalGroupConsumeEvent::Row { index, row } = event {
                            assert_eq!(index, next_index);
                            assert_eq!(row.decode_next::<i32>()?, 0);
                            next_index += 1;
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            let stats = region.change();
            assert_eq!(
                (stats.allocations, stats.reallocations),
                (usize::from(width > 1), 0)
            );
            assert_eq!(
                (
                    completion.groups,
                    completion.requests,
                    completion.rows_returned,
                    next_index
                ),
                (width, width, width, width)
            );
            assert_eq!(connection.transport.peak_inflight, width);
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}

#[test]
fn empty_input_entries_yield_without_changing_limit_or_eof_consumption() {
    run_with_deadline(async {
        for scheduling in [
            ExecutionScheduling::Uninterrupted,
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
            },
        ] {
            for (entries, max_groups, succeeds, expected_consumed, expected_polls) in [
                (64, 64, true, 64, 65),
                (64, 2, false, 3, 3),
                (64, 0, false, 1, 1),
                (0, 0, true, 0, 1),
            ] {
                let mut connection = session(0, 0).await;
                let _statement = prepared(&mut connection).await;
                let empty: &[PipelineRequest<'_>] = &[];
                let consumed = Rc::new(Cell::new(0));
                let polls = Rc::new(Cell::new(0));
                let mut source = CountedSource {
                    entries: vec![empty; entries].into_iter(),
                    consumed: consumed.clone(),
                    polls: polls.clone(),
                };
                let observed = Rc::new(Cell::new(None));
                let competitor_consumed = consumed.clone();
                let competitor_observed = observed.clone();
                let task = compio::runtime::spawn(async move {
                    competitor_observed.set(Some(competitor_consumed.get()));
                });
                let result = connection
                    .query_groups_provisional_visit(
                        &mut source,
                        GroupPipelineLimits {
                            max_groups,
                            ..stream_limits(scheduling)
                        },
                        |_| panic!("empty entries cannot execute SQL"),
                    )
                    .await;
                if succeeds {
                    let completion = result.unwrap();
                    assert_eq!(
                        (
                            completion.requests,
                            completion.groups,
                            completion.rows_returned
                        ),
                        (0, 0, 0)
                    );
                } else {
                    let error = result.unwrap_err();
                    assert!(matches!(error.source, Error::Limit(_)));
                    assert_eq!(error.progress, GroupPipelineProgress::default());
                }
                assert_eq!(consumed.get(), expected_consumed);
                assert_eq!(polls.get(), expected_polls);
                if entries == 64 && max_groups == 64 {
                    match scheduling {
                        ExecutionScheduling::Uninterrupted => assert_eq!(observed.get(), None),
                        ExecutionScheduling::Cooperative { .. } => {
                            assert_eq!(observed.get(), Some(2))
                        }
                    }
                }
                task.await.unwrap();
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    });
}

#[test]
fn interruption_while_reading_the_first_group_keeps_the_session_idle() {
    run_with_deadline(async {
        let mut connection = session(1, 1).await;
        let statement = prepared(&mut connection).await;
        let requests = [request(&statement)];
        {
            let mut source = std::iter::once(requests.as_slice());
            let options = stream_limits(ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::MIN,
            });
            let mut future =
                Box::pin(
                    connection.query_groups_provisional_visit(&mut source, options, |_| Ok(())),
                );
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(future);
            assert!(source.next().is_none());
        }
        let options = stream_limits(ExecutionScheduling::Uninterrupted);
        {
            let mut source = std::iter::from_fn(|| -> Option<&[PipelineRequest<'_>]> {
                panic!("source panic before admission")
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let future =
                    connection.query_groups_provisional_visit(&mut source, options, |_| Ok(()));
                std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop()))
            }));
            assert!(result.is_err());
        }
        assert!(connection.transport.group_packets.is_empty());
        assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        let completion = connection
            .query_groups_provisional_visit(
                &mut std::iter::once(requests.as_slice()),
                options,
                |_| Ok(()),
            )
            .await
            .unwrap();
        assert_eq!(
            (
                completion.requests,
                completion.groups,
                completion.rows_returned
            ),
            (1, 1, 1)
        );
    });
}

#[test]
fn empty_entries_between_real_groups_share_the_response_work_allowance() {
    run_with_deadline(async {
        for scheduling in [
            ExecutionScheduling::Uninterrupted,
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(8).unwrap(),
            },
        ] {
            let mut connection = session(2, 1).await;
            let statement = prepared(&mut connection).await;
            let requests = [request(&statement)];
            let empty: &[PipelineRequest<'_>] = &[];
            let mut entries = vec![requests.as_slice()];
            entries.extend(std::iter::repeat_n(empty, 32));
            entries.push(requests.as_slice());
            entries.extend(std::iter::repeat_n(empty, 32));
            let consumed = Rc::new(Cell::new(0));
            let polls = Rc::new(Cell::new(0));
            let mut source = CountedSource {
                entries: entries.into_iter(),
                consumed: consumed.clone(),
                polls: polls.clone(),
            };
            let rows = Rc::new(Cell::new(0));
            let observed = Rc::new(Cell::new(None));
            let mut task = None;
            let completion = connection
                .query_groups_provisional_visit(
                    &mut source,
                    GroupPipelineLimits {
                        max_groups: 66,
                        max_inflight_groups: 1,
                        ..stream_limits(scheduling)
                    },
                    |event| {
                        if let ProvisionalGroupEvent::Row { index, row } = event {
                            assert_eq!(index, rows.get());
                            assert_eq!(row.decoder().decode_next::<i32>()?, 0);
                            rows.set(rows.get() + 1);
                            if task.is_none() {
                                let consumed = consumed.clone();
                                let observed = observed.clone();
                                let rows = rows.clone();
                                task = Some(compio::runtime::spawn(async move {
                                    observed.set(Some((rows.get(), consumed.get())));
                                }));
                            }
                        }
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                (
                    completion.requests,
                    completion.groups,
                    completion.rows_returned
                ),
                (2, 2, 2)
            );
            assert_eq!((consumed.get(), polls.get()), (66, 67));
            match scheduling {
                ExecutionScheduling::Uninterrupted => assert_eq!(observed.get(), None),
                ExecutionScheduling::Cooperative { .. } => {
                    assert_eq!(observed.get(), Some((1, 3)));
                }
            }
            task.unwrap().await.unwrap();
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    });
}
