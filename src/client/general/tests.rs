//! 查询、预备语句与流水线的协议状态、恢复和协作调度测试。
use super::*;
use crate::{
    PipelineLimits, PipelineRequest, ReuseState, protocol::Frame, row::Column, transport::WireOps,
};
use std::{
    future::Future,
    io,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

type EncodedFrame = (u8, Vec<u8>);

#[derive(Clone, Copy)]
enum FinishState {
    Ready,
    Pending,
    Failed,
}

struct ReadyFrames {
    owner: Option<Waker>,
    owner_checks: Cell<usize>,
    close_polls: Option<Rc<Cell<usize>>>,
    send_buffer_takes: usize,
    notice_frame_reads: usize,
    row_frame_reads: usize,
    frames: Vec<EncodedFrame>,
    pause_before: Option<usize>,
    consumed: Rc<Cell<usize>>,
    broken: bool,
    send_queue: crate::transport::SendQueue,
    retired_packet: Option<Vec<u8>>,
    finish: Rc<Cell<FinishState>>,
}

impl WireOps for ReadyFrames {
    fn owner_waker(&self) -> Option<&Waker> {
        self.owner_checks.set(self.owner_checks.get() + 1);
        self.owner.as_ref()
    }

    fn window_send_queue(&mut self) -> Result<&mut crate::transport::SendQueue, Error> {
        Ok(&mut self.send_queue)
    }

    fn is_broken(&self) -> bool {
        self.broken
    }
    fn break_connection(&mut self) {
        self.broken = true;
    }
    fn begin_send(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        if let Some(retired) = &mut self.retired_packet {
            *retired = packet;
        }
        Ok(())
    }
    fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
        self.send_buffer_takes += 1;
        Ok(self
            .retired_packet
            .as_mut()
            .map_or_else(Vec::new, std::mem::take))
    }
    fn start_window_send_queue(
        &mut self,
        bytes: usize,
        storage: crate::transport::sealed::WindowStorage,
    ) -> Result<(), Error> {
        self.send_queue
            .start(bytes, usize::MAX, storage, &mut self.retired_packet)
    }
    fn send_queue_available(&self) -> usize {
        self.send_queue.available()
    }
    fn disable_send_queue(&mut self) -> Result<(), Error> {
        self.send_queue.disable()
    }
    fn poll_finish_send(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.finish.get() {
            FinishState::Ready => {
                if self.send_queue.has_data() {
                    self.send_queue.next(None)?;
                }
                Poll::Ready(Ok(()))
            }
            FinishState::Pending => Poll::Pending,
            FinishState::Failed => {
                Poll::Ready(Err(io::Error::other("late fake TX failure").into()))
            }
        }
    }
    fn poll_receive_frame(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.send_queue.has_data() {
            self.send_queue.next(None)?;
        }
        if self.pause_before == Some(self.consumed.get()) {
            return Poll::Pending;
        }
        Poll::Ready(if self.consumed.get() < self.frames.len() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        })
    }
    fn frame(&mut self) -> Result<Frame<'_>, Error> {
        let (tag, body) = self.frames.get(self.consumed.get()).ok_or(Error::Busy)?;
        self.notice_frame_reads += usize::from(*tag == b'N');
        self.row_frame_reads += usize::from(*tag == b'D');
        Ok(Frame { tag: *tag, body })
    }
    fn consume_frame(&mut self) -> Result<(), Error> {
        if self.consumed.get() == self.frames.len() {
            return Err(Error::Busy);
        }
        self.consumed.set(self.consumed.get() + 1);
        Ok(())
    }
    async fn close(self) -> Result<(), Error> {
        if let Some(polls) = self.close_polls {
            return std::future::poll_fn(|_| {
                let previous = polls.get();
                polls.set(previous + 1);
                if previous == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            })
            .await;
        }
        Ok(())
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn counter() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("the fixture operation should finish without yielding"),
    }
}

fn session(frames: Vec<EncodedFrame>) -> (Session<ReadyFrames>, Rc<Cell<usize>>) {
    let consumed = Rc::new(Cell::new(0));
    (
        Session {
            transport: ReadyFrames {
                owner: None,
                owner_checks: Cell::new(0),
                close_polls: None,
                send_buffer_takes: 0,
                notice_frame_reads: 0,
                row_frame_reads: 0,
                frames,
                pause_before: None,
                consumed: Rc::clone(&consumed),
                broken: false,
                send_queue: crate::transport::SendQueue::default(),
                retired_packet: None,
                finish: Rc::new(Cell::new(FinishState::Ready)),
            },
            id: crate::client::allocate_connection_id().unwrap(),
            active: false,
            transaction_status: TransactionStatus::Idle,
            info: crate::ServerInfo {
                version: "19".to_owned(),
                process_id: 0,
                cancel_key_length: 0,
            },
            cancel_key: None,
            max_messages: 8,
            max_request_len: 1024 * 1024,
            endpoint: crate::client::Endpoint::Tcp("127.0.0.1:1".parse().unwrap()),
            notice_handler: None,
            #[cfg(target_os = "linux")]
            tcp_receive_buffer_snapshot: None,
            remaining_boundaries: 0,
            transaction_lease: false,
            transaction_end: None,
            transaction_end_retirement: crate::client::TransactionEndRetirement::None,
            pending_transaction_control: None,
            extended: None,
            copy_state: Default::default(),
        },
        consumed,
    )
}

#[test]
fn local_close_and_terminate_reject_a_foreign_runtime_after_suspending() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    for (terminate, primary_failed) in [(false, false), (true, false), (true, true)] {
        let (mut session, _) = session(Vec::new());
        let polls = Rc::new(Cell::new(0));
        session.transport.owner = Some(owner.waker());
        session.transport.close_polls = Some(Rc::clone(&polls));
        if primary_failed {
            session.transport.finish.set(FinishState::Failed);
        }
        let mut closing = pin!(async move {
            if terminate {
                session.terminate().await
            } else {
                session.close_local().await
            }
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(owner.enter(|| closing.as_mut().poll(&mut cx)).is_pending());
        assert_eq!(polls.get(), 1);
        let result = foreign.enter(|| closing.as_mut().poll(&mut cx));
        if primary_failed {
            assert!(matches!(
                result,
                Poll::Ready(Err(Error::Cleanup { primary, cleanup }))
                    if matches!(primary.as_ref(), Error::Io(_))
                        && matches!(cleanup.as_ref(), Error::InvalidInput(_))
            ));
        } else {
            assert!(matches!(result, Poll::Ready(Err(Error::InvalidInput(_)))));
        }
        assert_eq!(polls.get(), 1);
    }
}

fn assert_ready_and_send_error(error: Error) {
    let Error::Cleanup { primary, cleanup } = error else {
        panic!("缺少服务器或本地发送错误")
    };
    assert!(matches!(*primary, Error::Database(error) if error.code() == "23505"));
    assert!(matches!(*cleanup, Error::Io(error) if error.to_string() == "late fake TX failure"));
}

#[test]
fn single_request_failures_preserve_the_diagnostic_only_after_ready_when_local_send_fails() {
    use std::num::NonZeroU32;
    let diagnostic = || (b'E', b"SERROR\0C23505\0Mdatabase failure\0\0".to_vec());
    let ready_frame = |status| (b'Z', vec![status]);

    // 收到错误但没有 Ready 就断开，不使用最终发送阶段的错误表示。
    let (mut unconfirmed, _) = session(vec![(b'2', vec![]), diagnostic()]);
    unconfirmed.transport.finish.set(FinishState::Failed);
    assert!(
        matches!(ready(query_scheduled(&mut unconfirmed, Oid::INT4, ExecutionScheduling::Uninterrupted).finish()),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(unconfirmed.reuse_state(), ReuseState::DiscardOnly);

    for abandon_after_ready in [false, true] {
        let (mut owner, consumed) = session(vec![(b'2', vec![]), diagnostic(), ready_frame(b'I')]);
        let finish = Rc::clone(&owner.transport.finish);
        let mut query = query_scheduled(&mut owner, Oid::INT4, ExecutionScheduling::Uninterrupted);
        let error = if abandon_after_ready {
            finish.set(FinishState::Pending);
            {
                let mut op = pin!(query.finish());
                assert!(
                    op.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert_eq!(consumed.get(), 3);
            drop(query);
            finish.set(FinishState::Failed);
            ready(owner.recover_to_ready()).unwrap_err()
        } else {
            finish.set(FinishState::Failed);
            ready(query.finish()).unwrap_err()
        };
        assert_ready_and_send_error(error);
        assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
    }

    let (mut preparing, _) = session(vec![(b'1', vec![]), diagnostic(), ready_frame(b'I')]);
    preparing
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    preparing.transport.finish.set(FinishState::Failed);
    assert_ready_and_send_error(
        ready(preparing.prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))).unwrap_err(),
    );
    assert_eq!(preparing.reuse_state(), ReuseState::DiscardOnly);

    let mut frames = prepare_response();
    frames.extend([diagnostic(), ready_frame(b'I')]);
    let (mut closing, _) = session(frames);
    let statement = prepare(&mut closing);
    closing.transport.finish.set(FinishState::Failed);
    assert_ready_and_send_error(ready(closing.close_prepared(&statement)).unwrap_err());
    assert_eq!(closing.reuse_state(), ReuseState::DiscardOnly);

    for is_portal in [false, true] {
        let mut frames = prepare_response();
        frames.extend([
            (b'C', b"BEGIN\0".to_vec()),
            ready_frame(b'T'),
            diagnostic(),
            ready_frame(if is_portal { b'E' } else { b'I' }),
        ]);
        let (mut owner, _) = session(frames);
        let statement = prepare(&mut owner);
        let finish = Rc::clone(&owner.transport.finish);
        let mut transaction = ready(owner.begin_transaction()).unwrap();
        finish.set(FinishState::Failed);
        let error = if is_portal {
            let mut portal = transaction.portal(&statement, &[]).unwrap();
            ready(portal.fetch_provisional(
                crate::PortalFetchLimits {
                    max_rows: NonZeroU32::MIN,
                    max_result_bytes: 64,
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                |_| panic!("失败的 portal 不应产生行"),
            ))
            .unwrap_err()
        } else {
            ready(transaction.commit()).unwrap_err()
        };
        assert_ready_and_send_error(error);
        assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
    }

    let (owner, _) = session(vec![diagnostic(), ready_frame(b'I')]);
    owner.transport.finish.set(FinishState::Failed);
    let mut listener = owner
        .into_listener(crate::ExecutionScheduling::Uninterrupted)
        .unwrap();
    assert_ready_and_send_error(ready(listener.listen("channel", |_| {})).unwrap_err());
    assert!(matches!(
        ready(listener.listen("channel", |_| {})),
        Err(Error::Broken)
    ));
}

#[test]
fn failed_begin_and_failed_commit_to_idle_leave_no_transaction_lease() {
    let (mut session, consumed) = session(vec![
        (b'E', b"SERROR\0C0A000\0Mread-only standby\0\0".to_vec()),
        (b'Z', vec![b'I']),
        (b'C', b"BEGIN\0".to_vec()),
        (b'Z', vec![b'T']),
        (b'E', b"SERROR\0C23505\0Mdeferred uniqueness\0\0".to_vec()),
        (b'Z', vec![b'I']),
    ]);
    assert!(matches!(
        ready(session.begin_transaction_with(crate::TransactionOptions {
            access: Some(crate::TransactionAccess::ReadWrite),
            ..crate::TransactionOptions::default()
        })),
        Err(Error::Database(error)) if error.code() == "0A000"
    ));
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(session.take_transaction_end(), None);

    let transaction = ready(session.begin_transaction()).unwrap();
    assert!(matches!(
        ready(transaction.commit()),
        Err(Error::Database(error)) if error.code() == "23505"
    ));
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(session.take_transaction_end(), None);
    assert_eq!(consumed.get(), 6);
}

#[test]
fn a_transaction_control_rechecks_owner_and_keeps_the_diagnostic_after_ready() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    let (mut session, consumed) = session(vec![
        (b'C', b"BEGIN\0".to_vec()),
        (b'Z', vec![b'T']),
        (b'E', b"SERROR\0C23505\0Mdeferred uniqueness\0\0".to_vec()),
        (b'Z', vec![b'I']),
    ]);
    session.transport.owner = Some(owner.waker());
    let finish = Rc::clone(&session.transport.finish);
    let transaction = owner.enter(|| ready(session.begin_transaction())).unwrap();
    finish.set(FinishState::Pending);
    let mut commit = Box::pin(transaction.commit());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(owner.enter(|| commit.as_mut().poll(&mut cx)).is_pending());
    assert_eq!(consumed.get(), 4);
    assert!(matches!(
        foreign.enter(|| commit.as_mut().poll(&mut cx)),
        Poll::Ready(Err(Error::Cleanup { primary, cleanup }))
            if matches!(primary.as_ref(), Error::Database(error) if error.code() == "23505")
                && matches!(cleanup.as_ref(), Error::InvalidInput(_))
    ));
    drop(commit);
    assert_eq!(session.transport.owner_checks.get(), 3);
    assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
}

#[test]
fn failed_control_recovery_observes_idle_before_releasing_the_lease() {
    use super::super::transaction::{ControlRequest, PendingTransactionControl};

    for request in [
        ControlRequest::Begin,
        ControlRequest::Commit { chain: false },
    ] {
        let (mut session, consumed) = session(vec![
            (
                b'E',
                b"SERROR\0C40001\0Mtransaction control failed\0\0".to_vec(),
            ),
            (b'Z', vec![b'I']),
        ]);
        if request != ControlRequest::Begin {
            session.transaction_status = TransactionStatus::InTransaction;
        }
        session.transaction_lease = true;
        session.active = true;
        session.remaining_boundaries = 1;
        session.pending_transaction_control = Some(PendingTransactionControl::Waiting(request));
        session.transport.finish.set(FinishState::Pending);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);

        let mut recovery = Box::pin(session.recover_to_ready());
        assert!(
            recovery
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(recovery);
        assert_eq!(consumed.get(), 2);
        assert!(session.transaction_lease);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);

        session.transport.finish.set(FinishState::Ready);
        ready(session.recover_to_ready()).unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(session.take_transaction_end(), None);
        assert_eq!(consumed.get(), 2);
    }
}

#[test]
fn dropped_or_forgotten_commit_after_ready_remains_recoverable() {
    for forget in [false, true] {
        for succeeds in [false, true] {
            let terminal = if succeeds {
                (b'C', b"COMMIT\0".to_vec())
            } else {
                (b'E', b"SERROR\0C23505\0Mdeferred uniqueness\0\0".to_vec())
            };
            let (mut session, consumed) = session(vec![
                (b'C', b"BEGIN\0".to_vec()),
                (b'Z', vec![b'T']),
                terminal,
                (b'Z', vec![b'I']),
            ]);
            let finish = Rc::clone(&session.transport.finish);
            let transaction = ready(session.begin_transaction()).unwrap();
            finish.set(FinishState::Pending);
            let mut commit = Box::pin(transaction.commit());
            assert!(
                commit
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if forget {
                std::mem::forget(commit);
            } else {
                drop(commit);
            }

            assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
            assert_eq!(session.remaining_boundaries, 0);
            assert_eq!(consumed.get(), 4);
            assert_eq!(
                session.take_transaction_end(),
                succeeds.then_some(crate::TransactionEnd::Committed)
            );

            finish.set(FinishState::Ready);
            ready(session.recover_to_ready()).unwrap();
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            assert_eq!(session.take_transaction_end(), None);
            assert_eq!(consumed.get(), 4);
        }
    }
}

#[test]
fn failed_commit_with_failed_ready_preserves_the_rollback_obligation() {
    let (mut session, consumed) = session(vec![
        (b'C', b"BEGIN\0".to_vec()),
        (b'Z', vec![b'T']),
        (b'E', b"SERROR\0C57014\0Mstatement cancelled\0\0".to_vec()),
        (b'Z', vec![b'E']),
        (b'C', b"ROLLBACK\0".to_vec()),
        (b'Z', vec![b'I']),
    ]);
    let transaction = ready(session.begin_transaction()).unwrap();
    assert!(matches!(
        ready(transaction.commit()),
        Err(Error::Database(error)) if error.code() == "57014"
    ));
    assert_eq!(session.reuse_state(), ReuseState::NeedsTransactionDecision);
    assert_eq!(session.take_transaction_end(), None);
    assert_eq!(
        ready(session.recover_and_rollback())
            .unwrap()
            .transaction_end,
        Some(crate::TransactionEnd::RolledBack)
    );
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(consumed.get(), 6);
}

fn row(value: &[u8]) -> EncodedFrame {
    let mut body = Vec::from(1_u16.to_be_bytes());
    body.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
    body.extend_from_slice(value);
    (b'D', body)
}

fn result(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<EncodedFrame> {
    let mut frames = vec![(b'2', Vec::new())];
    let mut rows = 0;
    for value in values {
        frames.push(row(&value));
        rows += 1;
    }
    frames.push((b'C', format!("SELECT {rows}\0").into_bytes()));
    frames.push((b'Z', vec![b'I']));
    frames
}

fn scalar_result(rows: i32) -> Vec<EncodedFrame> {
    result((0..rows).map(|value| value.to_be_bytes().to_vec()))
}

#[test]
fn scalar_window_copies_mixed_column_metadata_without_retaining_layouts() {
    use crate::{
        BatchOptions, Client, ExecutionOptions,
        types::{Decode, RawValue},
    };

    #[derive(Debug, PartialEq, Eq)]
    struct Signed(i64);

    impl Decode<'_> for Signed {
        fn accepts(oid: Oid, format: Format) -> bool {
            matches!(
                (oid, format),
                (Oid::INT4, Format::Binary) | (Oid::INT8, Format::Text)
            )
        }

        fn decode(value: RawValue<'_>) -> Result<Self, CodecError> {
            match (value.oid, value.format) {
                (Oid::INT4, Format::Binary) => value.decode::<i32>().map(i64::from).map(Self),
                (Oid::INT8, Format::Text) => value.decode::<i64>().map(Self),
                _ => Err(CodecError::WrongType {
                    oid: value.oid,
                    format: value.format,
                }),
            }
        }
    }

    let mut frames = prepare_response();
    frames.extend(prepare_response_with_type(Oid::INT8, 8));
    frames.extend(result([42_i32.to_be_bytes().to_vec()]));
    frames.extend(result([b"8589934592".to_vec()]));
    let (mut session, _) = session(frames);
    session
        .configure_statements(StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    let binary =
        ready(session.prepare("SELECT 42::int4", &[], ResultFormats::All(Format::Binary))).unwrap();
    let text = ready(session.prepare(
        "SELECT 8589934592::int8",
        &[],
        ResultFormats::All(Format::Text),
    ))
    .unwrap();
    let owners = || {
        [
            Rc::strong_count(binary.shared_layout()),
            Rc::strong_count(text.shared_layout()),
        ]
    };
    let before = owners();
    let limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 64,
        max_metadata_bytes: 4096,
    };
    let scheduling = ExecutionScheduling::Cooperative {
        max_work_per_turn: std::num::NonZeroUsize::MIN,
    };
    let mut client = Client::with_test_session(
        session,
        ExecutionOptions {
            query: QueryOptions { limits, scheduling },
            batch: Some(BatchOptions {
                member_limits: limits,
                max_requests: 2,
                max_inflight: 2,
                max_queued_request_bytes: 128,
                max_diagnostic_bytes: 128,
                scheduling,
            }),
        },
    );
    let mut output = Vec::with_capacity(2);
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let mut batch = pin!(
            client
                .streaming_batch([binary.bind(&[]), text.bind(&[])])
                .collect_one_into_ready(&mut output, OnError::RecoverExplicitly)
        );
        for _ in 0..2 {
            // 首两次轮询各编码一个成员，并在发布前让出。
            assert!(
                batch
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(owners(), before);
        }
        assert_eq!(batch.await.unwrap().confirmed, 2);
    });
    assert!(matches!(
        output.as_slice(),
        [Ok(Signed(42)), Ok(Signed(8_589_934_592))]
    ));
    assert_eq!(owners(), before);
    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn a_panicking_scalar_decoder_discards_direct_and_batch_connections() {
    use crate::{
        BatchOptions, Client, ExecutionOptions,
        types::{Decode, RawValue},
    };
    use std::panic::{AssertUnwindSafe, catch_unwind};

    struct Panics;
    impl Decode<'_> for Panics {
        fn accepts(oid: Oid, format: Format) -> bool {
            <i32 as Decode<'_>>::accepts(oid, format)
        }

        fn decode(_: RawValue<'_>) -> Result<Self, CodecError> {
            panic!("注入解码失败");
        }
    }

    let limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 128,
        max_metadata_bytes: 4096,
    };
    let scheduling = ExecutionScheduling::Uninterrupted;
    for batch in [false, true] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        let (mut session, _) = session(frames);
        let statement = prepare(&mut session);
        let mut client = Client::with_test_session(
            session,
            ExecutionOptions {
                query: QueryOptions { limits, scheduling },
                batch: Some(BatchOptions {
                    member_limits: limits,
                    max_requests: 1,
                    max_inflight: 1,
                    max_queued_request_bytes: 4096,
                    max_diagnostic_bytes: 4096,
                    scheduling,
                }),
            },
        );
        let mut output = Vec::with_capacity(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if batch {
                let _ = ready(
                    client
                        .streaming_batch([statement.bind(&[])])
                        .collect_one_into_ready::<Panics>(&mut output, OnError::RecoverExplicitly),
                );
            } else {
                let _ = ready(
                    client
                        .query(&statement, &[])
                        .one::<Panics>(OnError::RecoverExplicitly),
                );
            }
        }));
        assert!(result.is_err());
        assert!(output.is_empty());
        assert_eq!(client.reuse_state(), ReuseState::DiscardOnly);
    }
}

#[test]
fn panicking_layout_checks_discard_after_wire_admission() {
    use crate::{
        BatchOptions, Client, ExecutionOptions,
        types::{Decode, RawValue},
    };
    use std::panic::{AssertUnwindSafe, catch_unwind};

    thread_local! {
        static ADMISSIONS: Cell<usize> = const { Cell::new(0) };
    }

    struct Panics;
    impl Decode<'_> for Panics {
        fn accepts(oid: Oid, format: Format) -> bool {
            ADMISSIONS.with(|calls| {
                assert_eq!(calls.replace(1), 0, "注入布局校验失败");
            });
            <i32 as Decode<'_>>::accepts(oid, format)
        }

        fn decode(value: RawValue<'_>) -> Result<Self, CodecError> {
            value.decode::<i32>().map(|_| Self)
        }
    }

    let limits = QueryLimits {
        max_rows: 2,
        max_result_bytes: 128,
        max_metadata_bytes: 4096,
    };
    let scheduling = ExecutionScheduling::Uninterrupted;
    let defaults = ExecutionOptions {
        query: QueryOptions { limits, scheduling },
        batch: Some(BatchOptions {
            member_limits: limits,
            max_requests: 2,
            max_inflight: 1,
            max_queued_request_bytes: 128,
            max_diagnostic_bytes: 128,
            scheduling,
        }),
    };
    let (session, _) = session(projected_frames(1));
    let mut client = Client::with_test_session(session, defaults);
    ADMISSIONS.with(|calls| calls.set(1));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = ready(
            client
                .one_shot("SELECT 1", &[], ResultFormats::All(Format::Binary))
                .one::<Panics>(OnError::RecoverExplicitly),
        );
    }));
    assert!(result.is_err());
    assert_eq!(client.reuse_state(), ReuseState::DiscardOnly);

    let mut frames = prepare_response();
    frames.extend(scalar_result(1));
    let (mut session, _) = self::session(frames);
    let statement = prepare(&mut session);
    let mut client = Client::with_test_session(session, defaults);
    let mut output = Vec::with_capacity(2);
    ADMISSIONS.with(|calls| calls.set(0));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = ready(
            client
                .streaming_batch([statement.bind(&[]), statement.bind(&[])])
                .collect_one_into_ready::<Panics>(&mut output, OnError::RecoverExplicitly),
        );
    }));
    assert!(result.is_err());
    assert!(output.is_empty());
    assert_eq!(client.reuse_state(), ReuseState::DiscardOnly);
}

#[test]
fn notice_delivery_reads_each_frame_once_and_recovery_suppresses_callbacks() {
    for (recover, malformed) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut frames = scalar_result(1);
        let body: &[u8] = if malformed {
            b"SNOTICE\0C00000\0Mno terminator"
        } else {
            b"SNOTICE\0C00000\0Mfixture\0\0"
        };
        frames.insert(2, (b'N', body.to_vec()));
        let (mut owner, _) = session(frames);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        owner.notice_handler = Some(Arc::new(move |notice| {
            assert_eq!(notice.message, "fixture");
            observed.fetch_add(1, Ordering::Relaxed);
        }));
        let mut query = query_scheduled(&mut owner, Oid::INT4, ExecutionScheduling::Uninterrupted);
        let _ = ready(query.next_row()).unwrap().unwrap();
        let result = if recover {
            drop(query);
            ready(owner.recover_to_ready())
        } else {
            ready(query.finish()).map(|_| ())
        };
        assert_eq!(result.is_ok(), !malformed);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(!recover && !malformed)
        );
        assert_eq!(owner.transport.notice_frame_reads, 1);
        assert_eq!(owner.transport.is_broken(), malformed);
    }
}

#[test]
fn recovery_rollback_suppresses_the_rollback_notice() {
    for recover in [false, true] {
        let frames = vec![
            (b'C', b"BEGIN\0".to_vec()),
            (b'Z', vec![b'T']),
            (b'N', b"SNOTICE\0C00000\0Mrollback\0\0".to_vec()),
            (b'C', b"ROLLBACK\0".to_vec()),
            (b'Z', vec![b'I']),
        ];
        let (mut owner, _) = session(frames);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        owner.notice_handler = Some(Arc::new(move |msg| {
            assert_eq!(msg.message, "rollback");
            seen.fetch_add(1, Ordering::Relaxed);
        }));
        let tx = ready(owner.begin_transaction()).unwrap();
        let result = if recover {
            drop(tx);
            ready(owner.recover_and_rollback())
        } else {
            ready(tx.rollback())
        };
        assert_eq!(result.unwrap().transaction_status, TransactionStatus::Idle);
        assert_eq!(owner.transport.notice_frame_reads, 1);
        assert_eq!(calls.load(Ordering::Relaxed), usize::from(!recover));
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    }
}

fn query(session: &mut Session<ReadyFrames>, oid: Oid) -> Query<'_, ReadyFrames> {
    query_scheduled(
        session,
        oid,
        ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(256).unwrap(),
        },
    )
}

fn query_scheduled(
    session: &mut Session<ReadyFrames>,
    oid: Oid,
    scheduling: ExecutionScheduling,
) -> Query<'_, ReadyFrames> {
    let layout = Rc::new(
        RowLayout::new(
            vec![Column::new("n".to_owned(), oid)],
            ResultFormats::All(Format::Binary),
        )
        .unwrap(),
    );
    session
        .admit_query(
            Vec::new(),
            QueryMode::Prepared,
            QueryLayout::Shared(layout),
            QueryLimits {
                max_rows: 1024,
                max_result_bytes: 1024 * 1024,
                max_metadata_bytes: 4096,
            },
            ExecutionQuantum::new(scheduling),
            crate::OnError::RecoverExplicitly,
        )
        .unwrap()
}

fn prepare_response() -> Vec<EncodedFrame> {
    prepare_response_with_type(Oid::INT4, 4)
}

fn prepare_response_with_type(oid: Oid, width: i16) -> Vec<EncodedFrame> {
    let mut description = Vec::from(1_u16.to_be_bytes());
    description.extend_from_slice(b"n\0");
    description.extend_from_slice(&0_u32.to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    description.extend_from_slice(&oid.0.to_be_bytes());
    description.extend_from_slice(&width.to_be_bytes());
    description.extend_from_slice(&(-1_i32).to_be_bytes());
    description.extend_from_slice(&0_i16.to_be_bytes());
    vec![
        (b'1', Vec::new()),
        (b't', vec![0, 0]),
        (b'T', description),
        (b'Z', vec![b'I']),
    ]
}

fn prepare(session: &mut Session<ReadyFrames>) -> PreparedStatement {
    session
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    ready(session.prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))).unwrap()
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn statement_names_need_no_heap_storage_beyond_the_reserved_slots() {
    let mut reference = None;
    for ordinal in [None, Some(1_u64), Some(999_999), Some(u64::MAX)] {
        let (mut session, _) = session(prepare_response());
        session
            .configure_statements(StatementLimits {
                max_statements: 3,
                max_metadata_bytes: 4096,
            })
            .unwrap();
        let reserved = session.extension().metadata_bytes;
        assert_eq!(
            reserved,
            session.extension().slots.capacity() * size_of::<Slot>()
        );
        let formats = ResultFormats::All(Format::Binary);
        session.extension().next_name = ordinal.map_or(0, |id| id - 1);
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let statement = if ordinal.is_some() {
            ready(session.prepare("SELECT 42", &[], formats))
        } else {
            ready(session.prepare_replace_unnamed("SELECT 42", &[], formats))
        }
        .unwrap();
        let stats = region.change();
        let allocations = (stats.allocations, stats.reallocations);
        assert_eq!(allocations, *reference.get_or_insert(allocations));
        let payload = StatementData::metadata_bytes(&[], statement.layout()).unwrap();
        assert_eq!(session.extension().metadata_bytes, reserved + payload);
    }
}

#[test]
fn strict_prepared_terminals_retain_only_the_checked_column_count_during_recovery() {
    use crate::{Client, ExecutionOptions, OnError, QueryOptions};
    for (columns, full_row, malformed) in [
        (1_u16, false, false),
        (1, false, true),
        (0, false, false),
        (1, true, false),
    ] {
        let mut frames = prepare_response();
        let mut response = if columns == 0 {
            frames[2] = (b'n', Vec::new());
            vec![
                (b'2', Vec::new()),
                (b'C', b"UPDATE 0\0".to_vec()),
                (b'Z', vec![b'I']),
            ]
        } else {
            scalar_result(1)
        };
        if malformed {
            response[1] = (b'D', vec![0, 2, 255, 255, 255, 255, 255, 255, 255, 255]);
        }
        let pause_before = frames.len();
        frames.extend(response);
        let (mut session, _) = session(frames);
        let statement = prepare(&mut session);
        let before = Rc::strong_count(statement.shared_layout());
        session.transport.pause_before = Some(pause_before);
        let mut client = Client::with_test_session(
            session,
            ExecutionOptions::direct(QueryOptions {
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 64,
                    max_metadata_bytes: 4096,
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            }),
        );
        {
            let mut waiting = pin!(async {
                let request = client.query(&statement, &[]);
                let policy = OnError::RecoverExplicitly;
                if full_row {
                    request.map_provisional_one(policy, |_| Ok(())).await
                } else if columns == 0 {
                    request.command_ready(policy).await.map(|_| ())
                } else {
                    request.one::<i32>(policy).await.map(|_| ())
                }
            });
            assert!(
                waiting
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(
                Rc::strong_count(statement.shared_layout()),
                before + usize::from(full_row)
            );
        }
        let session = client.expert();
        let pending = session.extended.as_ref().unwrap().query.as_ref().unwrap();
        assert_eq!(pending.layout.is_some(), full_row);
        assert_eq!(pending.result_columns, usize::from(columns));
        session.transport.pause_before = None;
        if malformed {
            assert!(matches!(
                ready(session.recover_to_ready()),
                Err(Error::Codec(_))
            ));
            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        } else {
            ready(session.recover_to_ready()).unwrap();
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            assert_eq!(Rc::strong_count(statement.shared_layout()), before);
        }
    }
}

#[test]
fn one_shot_uses_zero_result_codes_for_the_text_default_only() {
    let sql = "SELECT 1";
    // Parse 17 字节、Bind 13 字节、Describe 7 字节、Execute 10 字节、Sync 5 字节。
    for (formats, limit, fits) in [
        (ResultFormats::All(Format::Text), 52, true),
        (ResultFormats::All(Format::Text), 51, false),
        (ResultFormats::All(Format::Binary), 52, false),
        (
            ResultFormats::PerColumn(vec![Format::Text; 2].into()),
            52,
            false,
        ),
        (
            ResultFormats::PerColumn(vec![Format::Text; 2].into()),
            56,
            true,
        ),
    ] {
        let (mut owner, _) = session(vec![]);
        owner.max_request_len = limit;
        let result = ready(owner.one_shot(
            sql,
            &[],
            formats,
            crate::QueryOptions {
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 64,
                    max_metadata_bytes: 1024,
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            crate::AbandonPolicy::RecoverExplicitly,
        ));
        if fits {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::Limit(_))));
        }
    }
}

#[test]
fn rejected_queries_preserve_the_idle_buffer_and_parameter_error_priority() {
    let mut frames = prepare_response();
    const COUNT: u16 = 257;
    let mut types = Vec::from(COUNT.to_be_bytes());
    for _ in 0..COUNT {
        types.extend_from_slice(&Oid::BYTEA.0.to_be_bytes());
    }
    frames[1] = (b't', types);
    let (mut owner, _) = session(frames);
    let statement = prepare(&mut owner);
    owner.max_request_len = 100;
    let initial_takes = owner.transport.send_buffer_takes;
    let limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 128,
        max_metadata_bytes: 4096,
    };
    let metadata_limit = QueryLimits {
        max_metadata_bytes: 0,
        ..limits
    };
    let schedule = ExecutionScheduling::Uninterrupted;
    let bytes = [0; 128];
    let mut input = vec![Parameter::bytea(&[]); usize::from(COUNT)];
    input[0] = Parameter::text(Oid::BYTEA, "");
    input[1] = Parameter::bytea(&bytes);
    let mut wrong = input.clone();
    wrong[usize::from(COUNT) - 1] = Parameter::int4(1);
    assert!(matches!(
        ready(owner.query(
            &statement,
            &wrong[..2],
            crate::QueryOptions {
                limits: metadata_limit,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::InvalidInput(
            "parameter count differs from the prepared statement"
        ))
    ));
    assert!(matches!(
        ready(owner.query(
            &statement,
            &wrong,
            crate::QueryOptions {
                limits: metadata_limit,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::InvalidInput(
            "parameter type differs from the prepared statement"
        ))
    ));
    assert!(matches!(
        ready(owner.query(
            &statement,
            &input,
            crate::QueryOptions {
                limits: metadata_limit,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::Limit(
            "prepared result metadata exceeds the query limit"
        ))
    ));
    assert!(matches!(
        owner.query_scoped_with_layout(
            &statement,
            &input,
            crate::QueryOptions {
                limits,
                scheduling: schedule
            },
            crate::OnError::RecoverExplicitly,
            false,
            |_| Err(Error::InvalidInput("layout mismatch"))
        ),
        Err(Error::InvalidInput("layout mismatch"))
    ));
    assert!(matches!(
        ready(owner.query(
            &statement,
            &input,
            crate::QueryOptions {
                limits,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::Limit(_))
    ));
    let format = ResultFormats::All(Format::Binary);
    assert!(matches!(
        ready(owner.one_shot(
            "SELECT\0",
            &[],
            format.clone(),
            crate::QueryOptions {
                limits,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        ready(owner.one_shot(
            "SELECT $1",
            &input[..2],
            format.clone(),
            crate::QueryOptions {
                limits,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        ready(owner.one_shot(
            &"x".repeat(60),
            &[],
            format,
            crate::QueryOptions {
                limits,
                scheduling: schedule
            },
            crate::AbandonPolicy::RecoverExplicitly
        )),
        Err(Error::Limit(_))
    ));
    assert_eq!(owner.transport.send_buffer_takes, initial_takes);
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn frozen_compile_keeps_one_snapshot_per_live_slot_and_checks_every_member() {
    let mut frames = prepare_response();
    frames.extend(prepare_response());
    frames.extend([(b'3', Vec::new()), (b'Z', vec![b'I'])]);
    let (mut owner, _) = session(frames);
    owner
        .configure_statements(StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    let formats = ResultFormats::All(Format::Binary);
    let first = ready(owner.prepare("SELECT 42", &[], formats.clone())).unwrap();
    let second = ready(owner.prepare("SELECT 42", &[], formats)).unwrap();
    let (mut other, _) = session(prepare_response());
    let foreign = prepare(&mut other);
    assert_eq!(first.slot, foreign.slot);
    let request = |statement| PipelineRequest {
        statement,
        parameters: &[],
        limits: QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        },
    };
    let originals = (
        Rc::strong_count(&first.data),
        Rc::strong_count(&second.data),
    );
    let repeated = [
        request(&second),
        request(&first),
        request(&second),
        request(&first),
    ];
    let frozen = owner.compile_frozen_group(&repeated, 4096).unwrap();
    assert_eq!(frozen.requests(), repeated.len());
    assert_eq!(Rc::strong_count(&first.data), originals.0 + 1);
    assert_eq!(Rc::strong_count(&second.data), originals.1 + 1);
    drop(frozen);
    assert_eq!(
        (
            Rc::strong_count(&first.data),
            Rc::strong_count(&second.data)
        ),
        originals
    );
    let invalid = [request(&first), request(&foreign)];
    assert!(matches!(
        owner.compile_frozen_group(&invalid, 4096),
        Err(Error::InvalidInput(
            "statement belongs to another connection"
        ))
    ));
    ready(owner.close_prepared(&first)).unwrap();
    assert!(matches!(
        owner.compile_frozen_group(&repeated, 4096),
        Err(Error::InvalidInput("statement handle is stale"))
    ));
    assert_eq!(Rc::strong_count(&second.data), originals.1);
}

#[test]
#[cfg_attr(
    feature = "diagnostics",
    ignore = "分配诊断须单独运行，以隔离进程级计数"
)]
fn frozen_packet_rejects_impossible_member_counts_before_allocating_metadata() {
    let (mut owner, _) = session(prepare_response());
    let statement = prepare(&mut owner);
    let requests = [PipelineRequest {
        statement: &statement,
        parameters: &[],
        limits: QueryLimits {
            max_rows: 1,
            max_result_bytes: 32,
            max_metadata_bytes: 4096,
        },
    }];
    #[cfg(feature = "diagnostics")]
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    assert!(matches!(
        owner.compile_frozen_group(&requests, 27),
        Err(Error::Limit("frozen members cannot fit their packet bound"))
    ));
    #[cfg(feature = "diagnostics")]
    {
        let counts = region.change();
        assert_eq!((counts.allocations, counts.reallocations), (0, 0));
    }
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn reserve_limit_opens_owned_batch_storage_only_for_nonempty_input_before_sending() {
    use crate::{
        BatchOptions, Client, ExecutionOptions, OnError, OwnedOutput, QueryOptions, ReadyResult,
    };
    let mut frames = prepare_response();
    frames.extend(scalar_result(1));
    frames.extend(scalar_result(1));
    let (mut other, _) = session(prepare_response());
    let foreign = prepare(&mut other);
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let scheduling = ExecutionScheduling::Uninterrupted;
    let member_limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 64,
        max_metadata_bytes: 4096,
    };
    let mut client = Client::with_test_session(
        session,
        ExecutionOptions::direct(QueryOptions {
            limits: member_limits,
            scheduling,
        }),
    );
    let budget = BatchOptions {
        member_limits,
        max_inflight: 2,
        max_requests: 32,
        max_queued_request_bytes: 128,
        max_diagnostic_bytes: 256,
        scheduling,
    };
    let output = OwnedOutput {
        max_bytes: 8192,
        allocation: AllocationPolicy::ReserveLimit,
    };
    let policy = OnError::RecoverExplicitly;
    let known = ready(
        client
            .streaming_batch(std::iter::empty::<crate::BatchRequest<'_>>())
            .with_options(budget)
            .collect_ready(output, policy),
    )
    .unwrap();
    assert_eq!(known.results.capacity(), 0);
    let mut pulls = 0;
    let unknown = std::iter::from_fn(|| {
        pulls += 1;
        None::<crate::BatchRequest<'_>>
    });
    let report = ready(
        client
            .streaming_batch(unknown)
            .with_options(budget)
            .collect_ready(output, policy),
    )
    .unwrap();
    assert_eq!(pulls, 1);
    assert_eq!(report.results.capacity(), 0);
    assert_eq!((report.progress.consumed, report.progress.admitted), (0, 0));
    let rejected = ready(
        client
            .streaming_batch(std::iter::once_with(|| -> crate::BatchRequest<'_> {
                panic!("invalid output budget read the source")
            }))
            .with_options(budget)
            .collect_ready(
                OwnedOutput {
                    max_bytes: 1,
                    ..output
                },
                policy,
            ),
    )
    .unwrap_err();
    assert!(matches!(rejected.source, Error::Limit(_)));
    assert_eq!(
        (rejected.progress.consumed, rejected.progress.admitted),
        (0, 0)
    );
    // 输入没有长度上界。数量通过 usize 预算检查，但描述符缓冲超过 Rust 的 isize::MAX 对象上限。
    let too_large = BatchOptions {
        max_requests: usize::MAX / size_of::<ReadyResult>(),
        ..budget
    };
    let error = ready(
        client
            .streaming_batch(std::iter::from_fn(|| Some(statement.bind(&[]))))
            .with_options(too_large)
            .collect_ready(
                OwnedOutput {
                    max_bytes: usize::MAX,
                    ..output
                },
                policy,
            ),
    )
    .unwrap_err();
    assert!(matches!(
        error.source,
        Error::Limit("cannot allocate owned batch descriptors")
    ));
    assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
    assert_eq!(consumed.get(), 4);
    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
    for (first, bytes, reason) in [
        (&foreign, 128, "statement belongs to another connection"),
        (
            &statement,
            1,
            "window execution cannot fit its ready byte capacity",
        ),
    ] {
        let error = ready(
            client
                .streaming_batch([first.bind(&[])])
                .with_options(BatchOptions {
                    max_queued_request_bytes: bytes,
                    ..budget
                })
                .collect_ready(output, policy),
        )
        .unwrap_err();
        assert!(
            matches!(error.source, Error::InvalidInput(text) | Error::Limit(text) if text == reason)
        );
        assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
        assert_eq!(error.completed.capacity(), 0);
        assert_eq!(consumed.get(), 4);
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
    }
    let report = ready(
        client
            .streaming_batch([statement.bind(&[])])
            .with_options(budget)
            .collect_ready(output, policy),
    )
    .unwrap();
    assert_eq!((report.results.len(), report.progress.confirmed), (1, 1));
    assert_eq!(report.results.capacity(), 1);
    let error = ready(
        client
            .streaming_batch([statement.bind(&[]), foreign.bind(&[])])
            .with_options(BatchOptions {
                max_inflight: 1,
                ..budget
            })
            .collect_ready(output, policy),
    )
    .unwrap_err();
    assert!(matches!(
        error.source,
        Error::InvalidInput("statement belongs to another connection")
    ));
    assert_eq!(
        (
            error.progress.consumed,
            error.progress.admitted,
            error.progress.confirmed
        ),
        (2, 1, 1)
    );
    assert_eq!(error.completed.len(), 1);
    assert_eq!(error.completed.capacity(), 2);
    assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
    ready(client.recover_to_ready()).unwrap();
    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn empty_owned_batches_allocate_neither_output_nor_window_storage() {
    use crate::{BatchOptions, Client, ExecutionOptions, OnError, OwnedOutput, QueryOptions};
    let (session, _) = session(Vec::new());
    let scheduling = ExecutionScheduling::Uninterrupted;
    let member_limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 64,
        max_metadata_bytes: 1024,
    };
    let budget = BatchOptions {
        member_limits,
        max_inflight: 8,
        max_requests: 8,
        max_queued_request_bytes: 1024,
        max_diagnostic_bytes: 128,
        scheduling,
    };
    let mut client = Client::with_test_session(
        session,
        ExecutionOptions::direct(QueryOptions {
            limits: member_limits,
            scheduling,
        }),
    );
    for allocation in [AllocationPolicy::Grow, AllocationPolicy::ReserveLimit] {
        let output = OwnedOutput {
            max_bytes: 8192,
            allocation,
        };
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let unknown = std::iter::from_fn(|| None::<crate::BatchRequest<'_>>);
        let empty = ready(
            client
                .streaming_batch(unknown)
                .with_options(budget)
                .collect_ready(output, OnError::RecoverExplicitly),
        )
        .unwrap();
        let stats = region.change();
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
        assert_eq!(empty.results.capacity(), 0);
        assert!(client.expert().extended.is_none());
    }
    let (mut other, _) = self::session(prepare_response());
    let foreign = prepare(&mut other);
    let output = OwnedOutput {
        max_bytes: 8192,
        allocation: AllocationPolicy::ReserveLimit,
    };
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    let error = ready(
        client
            .streaming_batch([foreign.bind(&[])])
            .with_options(budget)
            .collect_ready(output, OnError::RecoverExplicitly),
    )
    .unwrap_err();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(error.completed.capacity(), 0);
    assert!(client.expert().extended.is_none());
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    let mut source = std::iter::once(Ok(crate::WindowRequest {
        statement: &foreign,
        parameters: crate::WindowParameters::Borrowed(&[]),
        limits: member_limits,
    }));
    let error = ready(client.expert().query_window_provisional_visit(
        &mut source,
        crate::ProvisionalWindowLimits {
            max_requests: 8,
            max_inflight: 8,
            max_rows: 1,
            max_row_bytes: 64,
            max_queued_request_bytes: 1024,
            max_diagnostic_bytes: 128,
            scheduling,
            abandon: crate::AbandonPolicy::RecoverExplicitly,
        },
        &mut |_| unreachable!(),
    ))
    .unwrap_err();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
    assert!(client.expert().extended.is_none());
}

#[test]
fn panicking_before_the_first_window_request_leaves_the_session_idle() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let (mut owner, consumed) = session(Vec::new());
    let scheduling = ExecutionScheduling::Uninterrupted;
    let mut source = std::iter::from_fn(|| -> Option<Result<crate::WindowRequest<'_>, Error>> {
        panic!("注入输入迭代器错误")
    });
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        ready(owner.query_window(
            &mut source,
            crate::WindowLimits {
                max_requests: 1,
                max_inflight: 1,
                max_rows: 1,
                max_result_bytes: 1,
                max_queued_request_bytes: 128,
                storage: AllocationPolicy::Grow,
                scheduling,
            },
            OnError::RecoverExplicitly,
            &mut |_| unreachable!(),
        ))
    }));
    assert!(outcome.is_err());
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        ready(owner.query_window_provisional_visit(
            &mut source,
            crate::ProvisionalWindowLimits {
                max_requests: 1,
                max_inflight: 1,
                max_rows: 1,
                max_row_bytes: 1,
                max_queued_request_bytes: 128,
                max_diagnostic_bytes: 8,
                scheduling,
                abandon: crate::AbandonPolicy::DiscardOnAbandon,
            },
            &mut |_| unreachable!(),
        ))
    }));
    assert!(outcome.is_err());
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    assert!(owner.extended.is_none());
    assert_eq!(consumed.get(), 0);
}

#[test]
fn empty_windows_do_not_allocate_for_the_maximum_inflight_limit() {
    let (mut owner, _) = session(Vec::new());
    let scheduling = ExecutionScheduling::Uninterrupted;
    let limits = crate::WindowLimits {
        max_requests: usize::MAX,
        max_inflight: usize::MAX,
        max_rows: 1,
        max_result_bytes: 1,
        max_queued_request_bytes: 128,
        storage: AllocationPolicy::Grow,
        scheduling,
    };
    assert_eq!(
        ready(owner.query_window(
            &mut std::iter::empty(),
            limits,
            OnError::RecoverExplicitly,
            &mut |_| unreachable!()
        ))
        .unwrap()
        .admitted,
        0
    );
    let limits = crate::ProvisionalWindowLimits {
        max_requests: usize::MAX,
        max_inflight: usize::MAX,
        max_rows: 1,
        max_row_bytes: 1,
        max_queued_request_bytes: 128,
        max_diagnostic_bytes: 8,
        scheduling,
        abandon: crate::AbandonPolicy::RecoverExplicitly,
    };
    assert_eq!(
        ready(owner.query_window_provisional_visit(
            &mut std::iter::empty(),
            limits,
            &mut |_| unreachable!()
        ))
        .unwrap()
        .admitted,
        0
    );
    assert!(owner.extended.is_none());
    let (mut other, _) = session(prepare_response());
    let foreign = prepare(&mut other);
    let request = crate::WindowRequest {
        statement: &foreign,
        parameters: crate::WindowParameters::Borrowed(&[]),
        limits: QueryLimits {
            max_rows: 1,
            max_result_bytes: 64,
            max_metadata_bytes: 4096,
        },
    };
    let error = ready(owner.query_window_provisional_visit(
        &mut std::iter::once(Ok(request)),
        limits,
        &mut |_| unreachable!(),
    ))
    .unwrap_err();
    assert!(matches!(
        error.source,
        Error::InvalidInput("statement belongs to another connection")
    ));
    assert_eq!(error.origin, crate::ProvisionalWindowErrorOrigin::Input);
    assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
    assert!(!error.may_have_executed);
    assert!(owner.extended.is_none());
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
    for (cap, reason) in [
        (1, "provisional execution cannot fit its ready packet"),
        (128, "cannot allocate bounded window metadata"),
    ] {
        let request = crate::WindowRequest {
            statement: &foreign,
            parameters: crate::WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 64,
                max_metadata_bytes: 4096,
            },
        };
        let error = ready(other.query_window_provisional_visit(
            &mut std::iter::once(Ok(request)),
            crate::ProvisionalWindowLimits {
                max_queued_request_bytes: cap,
                ..limits
            },
            &mut |_| unreachable!(),
        ))
        .unwrap_err();
        assert!(matches!(error.source, Error::Limit(message) if message == reason));
        assert_eq!(error.origin, crate::ProvisionalWindowErrorOrigin::Resource);
        assert_eq!((error.progress.consumed, error.progress.admitted), (1, 0));
        assert_eq!(other.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(other.transport.send_queue_available(), 0);
    }
}

#[test]
fn frozen_compile_deduplicates_across_registry_words_and_sparse_slots() {
    let word = usize::BITS as usize;
    let mut frames = Vec::new();
    for _ in 0..=word * 2 {
        frames.extend(prepare_response());
    }
    let (mut owner, _) = session(frames);
    // 注册槽占五个机器字，覆盖内联、堆分配和稀疏的成员组合。
    owner
        .configure_statements(StatementLimits {
            max_statements: word * 4 + 1,
            max_metadata_bytes: (word * 4 + 1) * 2048,
        })
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..=word * 2 {
        handles.push(
            ready(owner.prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))).unwrap(),
        );
    }
    for slots in [
        &[0, 2, 2][..],
        &[0, word, word + 1, 2 * word, word, 2 * word],
        &[0, 2 * word, 2 * word],
        &[0, word, 2 * word, word],
    ] {
        let original = handles
            .iter()
            .map(|s| Rc::strong_count(&s.data))
            .collect::<Vec<_>>();
        let requests = slots
            .iter()
            .map(|&slot| PipelineRequest {
                statement: &handles[slot],
                parameters: &[],
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 128,
                    max_metadata_bytes: 4096,
                },
            })
            .collect::<Vec<_>>();
        let group = owner.compile_frozen_group(&requests, 4096).unwrap();
        for (slot, statement) in handles.iter().enumerate() {
            assert_eq!(
                Rc::strong_count(&statement.data),
                original[slot] + usize::from(slots.contains(&slot))
            );
        }
        drop(group);
        assert!(
            handles
                .iter()
                .zip(&original)
                .all(|(s, &n)| Rc::strong_count(&s.data) == n)
        );
    }
}

#[test]
fn prepare_cursor_reuses_retired_slots_in_single_and_pipeline_admission() {
    let mut frames = prepare_response();
    frames.extend(prepare_response());
    frames.extend([(b'3', Vec::new()), (b'Z', vec![b'I'])]);
    frames.extend(prepare_response());
    frames.extend(prepare_response());
    frames.push((b'E', b"SERROR\0C42601\0Msyntax error\0\0".to_vec()));
    frames.push((b'Z', vec![b'I']));
    frames.extend(prepare_response());
    let (mut session, consumed) = session(frames);
    session
        .configure_statements(StatementLimits {
            max_statements: 0,
            max_metadata_bytes: 0,
        })
        .unwrap();
    assert!(session.extended.is_none());
    session
        .configure_statements(StatementLimits {
            max_statements: 4,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    let formats = ResultFormats::All(Format::Binary);
    let first = ready(session.prepare("SELECT 1", &[], formats.clone())).unwrap();
    let second = ready(session.prepare("SELECT 2", &[], formats.clone())).unwrap();
    assert_eq!((first.slot, second.slot), (0, 1));
    ready(session.close_prepared(&first)).unwrap();
    assert_eq!(session.reclaim_closed_statements().unwrap(), 0);
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 2);
    drop(first);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 0);

    let pipeline = ["SELECT 3", "SELECT 4"]
        .into_iter()
        .map(|sql| PrepareRequest {
            sql,
            parameter_oids: &[],
            formats: formats.clone(),
        })
        .collect();
    let statements = ready(session.prepare_pipeline(
        pipeline,
        StatementPipelineLimits {
            max_statements: 2,
            max_packet_bytes: 4096,
            max_result_bytes: 4096,
            scheduling: ExecutionScheduling::Uninterrupted,
        },
    ))
    .unwrap();
    let reused = statements[0].as_ref().unwrap();
    let fresh = statements[1].as_ref().unwrap();
    assert_eq!((reused.slot, reused.generation), (0, 2));
    assert_eq!((fresh.slot, fresh.generation), (2, 1));
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 3);
    assert!(matches!(
        ready(session.prepare("SELECT \0", &[], formats.clone())),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(consumed.get(), 18);
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 3);
    assert!(matches!(
        ready(session.prepare("SELECT broken", &[], formats.clone())),
        Err(Error::Database(_))
    ));
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 3);
    let last = ready(session.prepare("SELECT 5", &[], formats)).unwrap();
    assert_eq!((last.slot, last.generation), (3, 2));
    assert_eq!(session.extended.as_ref().unwrap().first_vacant, 4);
}

#[test]
fn abandoned_single_prepare_retires_only_uncreated_names_at_ready() {
    for parsed in [false, true] {
        for pause_before_ready in [false, true] {
            let mut frames = Vec::new();
            if parsed {
                frames.push((b'1', Vec::new()));
            }
            frames.push((b'E', b"SERROR\0C42601\0Mfixture failure\0\0".to_vec()));
            let ready_index = frames.len();
            frames.push((b'Z', vec![b'I']));
            if parsed {
                frames.extend([(b'3', Vec::new()), (b'Z', vec![b'I'])]);
            }
            frames.extend(prepare_response());
            let (mut s, consumed) = session(frames);
            s.configure_statements(StatementLimits {
                max_statements: 1,
                max_metadata_bytes: 8192,
            })
            .unwrap();
            if pause_before_ready {
                s.transport.pause_before = Some(ready_index);
            } else {
                s.transport.finish.set(FinishState::Pending);
            }
            let fmt = ResultFormats::All(Format::Binary);
            let mut op = Box::pin(s.prepare("SELECT 1", &[], fmt.clone()));
            assert!(
                op.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(op);
            assert_eq!(
                consumed.get(),
                ready_index + usize::from(!pause_before_ready)
            );
            s.transport.pause_before = None;
            s.transport.finish.set(FinishState::Ready);
            ready(s.recover_to_ready()).unwrap();
            if parsed {
                assert!(matches!(
                    ready(s.prepare("SELECT 1", &[], fmt.clone())),
                    Err(Error::Limit(_))
                ));
                ready(s.close_all_statements(super::StatementPipelineLimits {
                    max_statements: 1,
                    max_packet_bytes: 1024,
                    max_result_bytes: 4096,
                    scheduling: crate::ExecutionScheduling::Uninterrupted,
                }))
                .unwrap();
            }
            let reused = ready(s.prepare("SELECT 1", &[], fmt)).unwrap();
            assert_eq!((reused.slot, reused.generation), (0, 2));
        }
    }
}

#[test]
fn reclamation_tracks_pinned_closed_records_and_full_slot_reuse() {
    let mut frames = Vec::new();
    for _ in 0..4 {
        frames.extend(prepare_response());
    }
    for _ in 0..3 {
        frames.extend([(b'3', Vec::new()), (b'Z', vec![b'I'])]);
    }
    frames.extend(prepare_response());
    let (mut session, _) = session(frames);
    session
        .configure_statements(StatementLimits {
            max_statements: 4,
            max_metadata_bytes: 8192,
        })
        .unwrap();
    let make = |c: &mut Session<ReadyFrames>| {
        ready(c.prepare("SELECT 1", &[], ResultFormats::All(Format::Binary))).unwrap()
    };
    let pinned = make(&mut session);
    let _live = make(&mut session);
    let released = make(&mut session);
    let pinned_high = make(&mut session);
    for statement in [&pinned, &pinned_high, &released] {
        ready(session.close_prepared(statement)).unwrap();
    }
    drop(released);
    let reused = make(&mut session);
    assert_eq!(reused.slot, 2);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 0);
    drop(pinned_high);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
    let extended = session.extended.as_ref().unwrap();
    assert_eq!(extended.first_vacant, 3);
    assert_eq!(extended.vacant_count, 1);
    assert_eq!(extended.first_closed, Some(0));
    drop(pinned);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
    let extended = session.extended.as_ref().unwrap();
    assert_eq!(extended.first_vacant, 0);
    assert_eq!(extended.vacant_count, 2);
    assert_eq!(extended.first_closed, None);
}

#[test]
fn close_pipeline_and_rebuilt_recovery_share_the_frame_budget() {
    let mut frames = Vec::new();
    for _ in 0..5 {
        frames.extend(prepare_response());
    }
    let mut notice = b"SNOTICE\0VNOTICE\0C00000\0M".to_vec();
    notice.extend(std::iter::repeat_n(b'x', 2048));
    notice.extend([0, 0]);
    frames.push((b'N', notice));
    for _ in 0..5 {
        frames.push((b'3', Vec::new()));
        frames.push((b'Z', vec![b'I']));
    }
    let (mut session, consumed) = session(frames);
    session
        .configure_statements(StatementLimits {
            max_statements: 5,
            max_metadata_bytes: 65536,
        })
        .unwrap();
    let mut statements = Vec::new();
    for _ in 0..5 {
        statements.push(
            ready(session.prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))).unwrap(),
        );
    }
    let requests: Vec<_> = statements.iter().collect();
    let (wakes, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    let mut closing = Box::pin(session.close_prepared_pipeline(
        &requests,
        StatementPipelineLimits {
            max_statements: 5,
            max_packet_bytes: 128,
            max_result_bytes: 128,
            scheduling: ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(5).unwrap(),
            },
        },
    ));
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    // 整包一单位、Notice 三单位、CloseComplete 一单位，还没有收到 Ready。
    assert_eq!(consumed.get(), 22);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    drop(closing);
    assert_eq!(session.remaining_boundaries, 5);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(recovery.as_mut().poll(&mut cx).is_pending());
    assert_eq!(consumed.get(), 27);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
    drop(recovery);
    assert_eq!(session.remaining_boundaries, 2);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 31);
    assert!(session.is_usable());
    drop(statements);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 5);
}

#[test]
fn prepare_pipeline_drop_preserves_created_names_and_the_packet_budget() {
    let mut frames = Vec::new();
    for _ in 0..5 {
        frames.extend(prepare_response());
    }
    for _ in 0..5 {
        frames.push((b'3', Vec::new()));
        frames.push((b'Z', vec![b'I']));
    }
    let (mut session, consumed) = session(frames);
    session
        .configure_statements(StatementLimits {
            max_statements: 5,
            max_metadata_bytes: 65536,
        })
        .unwrap();
    let sql = format!("SELECT 42 /*{}*/", " ".repeat(1024));
    let requests = (0..5)
        .map(|_| PrepareRequest {
            sql: &sql,
            parameter_oids: &[],
            formats: ResultFormats::All(Format::Binary),
        })
        .collect();
    let (wakes, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    let mut preparing = Box::pin(session.prepare_pipeline(
        requests,
        StatementPipelineLimits {
            max_statements: 5,
            max_packet_bytes: 8192,
            max_result_bytes: 1024,
            scheduling: ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(7).unwrap(),
            },
        },
    ));
    assert!(preparing.as_mut().poll(&mut cx).is_pending());
    // 五条长 SQL 合为六单位的包，本轮只能再消费第一条 ParseComplete。
    assert_eq!(consumed.get(), 1);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    drop(preparing);
    assert_eq!(session.remaining_boundaries, 5);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(recovery.as_mut().poll(&mut cx).is_pending());
    assert_eq!(consumed.get(), 8);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
    drop(recovery);
    assert_eq!(session.remaining_boundaries, 3);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(recovery.as_mut().poll(&mut cx).is_pending());
    assert_eq!(consumed.get(), 15);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 3);
    drop(recovery);
    assert_eq!(session.remaining_boundaries, 2);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 20);
    assert!(session.is_usable());
    assert_eq!(
        ready(
            session.close_all_statements_pipeline(StatementPipelineLimits {
                max_statements: 5,
                max_packet_bytes: 1024,
                max_result_bytes: 1024,
                scheduling: ExecutionScheduling::Uninterrupted,
            })
        )
        .unwrap()
        .len(),
        5
    );
    assert_eq!(session.reclaim_closed_statements().unwrap(), 5);
}

#[test]
fn startup_computes_binding_only_for_a_scram_plus_exchange() {
    use crate::AuthenticationPolicy;

    fn binding(_: &ReadyFrames) -> Result<Vec<u8>, Error> {
        Err(Error::Limit("cannot allocate TLS channel binding"))
    }
    let (mut trusted, _) = session(vec![
        (b'R', 0_i32.to_be_bytes().to_vec()),
        (b'S', b"client_encoding\0UTF8\0".to_vec()),
        (b'K', vec![0; 8]),
        (b'Z', vec![b'I']),
    ]);
    ready(trusted.startup(&AuthenticationPolicy::AllowAuthenticationOk, Some(binding))).unwrap();

    let policy = AuthenticationPolicy::ScramSha256Plus {
        password: String::new(),
        max_iterations: 4096,
    };
    for (mechanism, offered) in [("SCRAM-SHA-256", false), ("SCRAM-SHA-256-PLUS", true)] {
        let mut authentication = 10_i32.to_be_bytes().to_vec();
        authentication.extend_from_slice(mechanism.as_bytes());
        authentication.extend_from_slice(&[0, 0]);
        let (mut client, _) = session(vec![(b'R', authentication)]);
        let error = ready(client.startup(&policy, Some(binding))).unwrap_err();
        if offered {
            assert!(matches!(
                error,
                Error::Limit("cannot allocate TLS channel binding")
            ));
        } else {
            assert!(matches!(error, Error::Unsupported(_)));
        }
    }
}

fn configure_replacement_slots(session: &mut Session<ReadyFrames>) {
    session
        .configure_statements(StatementLimits {
            max_statements: 4,
            max_metadata_bytes: 16384,
        })
        .unwrap();
}

fn prepare_unnamed(session: &mut Session<ReadyFrames>) -> PreparedStatement {
    ready(session.prepare_replace_unnamed("SELECT 42", &[], ResultFormats::All(Format::Binary)))
        .unwrap()
}

#[test]
fn unnamed_replacement_invalidates_only_its_snapshot_and_retains_metadata_charges() {
    let mut frames = prepare_response();
    frames.extend(prepare_response());
    frames.extend(prepare_response());
    let (mut session, _) = session(frames);
    configure_replacement_slots(&mut session);
    let named =
        ready(session.prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))).unwrap();
    let first = prepare_unnamed(&mut session);
    let second = prepare_unnamed(&mut session);
    assert_eq!(named.storage(), PreparedStatementStorage::Named);
    assert_eq!(
        first.storage(),
        PreparedStatementStorage::ReplaceableUnnamed
    );
    assert_eq!(session.prepared_name(&second).unwrap(), b"\0");
    assert!(session.check_prepared_snapshot(&first, true).is_err());
    session.check_prepared_snapshot(&named, true).unwrap();
    session.check_prepared_snapshot(&second, true).unwrap();
    let charged = session.extended.as_ref().unwrap().metadata_bytes;
    assert_eq!(session.reclaim_closed_statements().unwrap(), 0);
    drop(first);
    assert_eq!(session.reclaim_closed_statements().unwrap(), 1);
    assert!(session.extended.as_ref().unwrap().metadata_bytes < charged);
}

#[test]
fn unnamed_preflight_failure_keeps_the_previous_snapshot_live() {
    let (mut session, _) = session(prepare_response());
    configure_replacement_slots(&mut session);
    let statement = prepare_unnamed(&mut session);
    assert!(matches!(
        ready(session.prepare_replace_unnamed(
            "SELECT\0 42",
            &[],
            ResultFormats::All(Format::Binary),
        )),
        Err(Error::InvalidInput(_))
    ));
    session.check_prepared_snapshot(&statement, true).unwrap();
}

#[test]
fn unnamed_replacement_without_a_spare_registry_slot_preserves_the_previous_handle() {
    let (mut session, _) = session(prepare_response());
    session
        .configure_statements(StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        })
        .unwrap();
    let statement = prepare_unnamed(&mut session);
    assert!(matches!(
        ready(session.prepare_replace_unnamed(
            "SELECT 99",
            &[],
            ResultFormats::All(Format::Binary),
        )),
        Err(Error::Limit(_))
    ));
    session.check_prepared_snapshot(&statement, true).unwrap();
}

#[test]
fn failed_unnamed_parse_still_invalidates_the_replaced_snapshot() {
    let mut frames = prepare_response();
    frames.push((b'E', b"SERROR\0C42601\0Msyntax error\0\0".to_vec()));
    frames.push((b'Z', vec![b'I']));
    let (mut session, _) = session(frames);
    configure_replacement_slots(&mut session);
    let statement = prepare_unnamed(&mut session);
    assert!(matches!(
        ready(
            session.prepare_replace_unnamed("SELECT (", &[], ResultFormats::All(Format::Binary),)
        ),
        Err(Error::Database(_))
    ));
    assert!(session.check_prepared_snapshot(&statement, true).is_err());
    assert_eq!(session.extended.as_ref().unwrap().unnamed_slot, None);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn simple_and_one_shot_admission_invalidate_unnamed_before_receiving_responses() {
    for mode in [QueryMode::Simple, QueryMode::OneShot] {
        let (mut session, _) = session(prepare_response());
        configure_replacement_slots(&mut session);
        let statement = prepare_unnamed(&mut session);
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        };
        let query = match mode {
            QueryMode::Simple => ready(session.query_simple_single(
                "SELECT 42",
                crate::QueryOptions {
                    limits,
                    scheduling: crate::scheduler::ExecutionScheduling::Uninterrupted,
                },
                crate::AbandonPolicy::RecoverExplicitly,
            )),
            QueryMode::OneShot => ready(session.one_shot(
                "SELECT 42",
                &[],
                ResultFormats::All(Format::Binary),
                crate::QueryOptions {
                    limits,
                    scheduling: crate::scheduler::ExecutionScheduling::Uninterrupted,
                },
                crate::AbandonPolicy::RecoverExplicitly,
            )),
            QueryMode::Prepared | QueryMode::ResetSession => unreachable!(),
        }
        .unwrap();
        drop(query);
        assert!(session.check_prepared_snapshot(&statement, true).is_err());
    }
}

#[test]
fn transaction_begin_invalidates_only_the_unnamed_statement() {
    let mut frames = prepare_response();
    frames.extend(prepare_response());
    frames.push((b'C', b"BEGIN\0".to_vec()));
    frames.push((b'Z', vec![b'T']));
    let (mut session, _) = session(frames);
    configure_replacement_slots(&mut session);
    let named =
        ready(session.prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))).unwrap();
    let unnamed = prepare_unnamed(&mut session);
    let transaction = ready(session.begin_transaction()).unwrap();
    drop(transaction);
    session.check_prepared_snapshot(&named, true).unwrap();
    assert!(session.check_prepared_snapshot(&unnamed, true).is_err());
}

#[test]
fn a_scalar_query_finishes_without_an_extra_wake() {
    let (mut session, consumed) = session(scalar_result(1));
    let mut query = query(&mut session, Oid::INT4);
    let (count, waker) = counter();
    let mut future = pin!(query.finish());
    let Poll::Ready(Ok(completion)) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("a scalar query must finish in the current poll");
    };
    assert_eq!(completion.rows_returned, 1);
    assert_eq!(consumed.get(), 4);
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
}

#[test]
fn a_cached_scalar_checks_its_runtime_only_at_admission() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let mut frames = prepare_response();
    frames.extend(scalar_result(1));
    let (mut session, _) = session(frames);
    session.transport.owner = Some(owner.waker());
    let statement = owner.enter(|| prepare(&mut session));
    let mut client = crate::Client::with_test_session(
        session,
        crate::ExecutionOptions::direct(QueryOptions {
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 64,
                max_metadata_bytes: 4096,
            },
            scheduling: ExecutionScheduling::Uninterrupted,
        }),
    );
    let before = client.expert().transport.owner_checks.get();
    let value = owner
        .enter(|| {
            ready(
                client
                    .query(&statement, &[])
                    .one::<i32>(OnError::RecoverExplicitly),
            )
        })
        .unwrap();
    assert_eq!(value, 0);
    assert_eq!(client.expert().transport.owner_checks.get(), before + 1);
    assert_eq!(client.expert().transport.row_frame_reads, 1);
}

#[test]
fn collectors_and_visitor_fetch_each_row_frame_once() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let mut frames = prepare_response();
    frames.extend(scalar_result(1));
    frames.extend(scalar_result(1));
    frames.extend(scalar_result(1));
    let (mut session, _) = session(frames);
    session.transport.owner = Some(owner.waker());
    let statement = owner.enter(|| prepare(&mut session));
    let options = QueryOptions {
        limits: QueryLimits {
            max_rows: 1,
            max_result_bytes: 64,
            max_metadata_bytes: 4096,
        },
        scheduling: ExecutionScheduling::Uninterrupted,
    };
    let mut client =
        crate::Client::with_test_session(session, crate::ExecutionOptions::direct(options));
    let before = client.expert().transport.owner_checks.get();
    let owned = owner
        .enter(|| {
            ready(
                client
                    .query(&statement, &[])
                    .collect_ready(AllocationPolicy::Grow, OnError::RecoverExplicitly),
            )
        })
        .unwrap();
    assert_eq!(owned.rows.len(), 1);
    assert_eq!(client.expert().transport.owner_checks.get(), before + 1);
    assert_eq!(client.expert().transport.row_frame_reads, 1);

    let mut output = statement.new_row_buffer(1, 64).unwrap();
    let completion = owner
        .enter(|| {
            ready(
                client
                    .query(&statement, &[])
                    .collect_into_ready(&mut output, OnError::RecoverExplicitly),
            )
        })
        .unwrap();
    assert_eq!(completion.rows_returned, 1);
    assert_eq!(output.len(), 1);
    assert_eq!(client.expert().transport.owner_checks.get(), before + 2);
    assert_eq!(client.expert().transport.row_frame_reads, 2);

    let mut visited = 0;
    let completion = owner
        .enter(|| {
            let mut query = ready(client.expert().query(
                &statement,
                &[],
                options,
                crate::AbandonPolicy::RecoverExplicitly,
            ))
            .unwrap();
            ready(query.for_each_row(
                &mut |_| {
                    visited += 1;
                    Ok(())
                },
                OnError::RecoverExplicitly,
            ))
        })
        .unwrap();
    assert_eq!(completion.rows_returned, 1);
    assert_eq!(visited, 1);
    assert_eq!(client.expert().transport.row_frame_reads, 3);
}

#[test]
fn a_row_can_keep_its_layout_after_the_query_finishes() {
    let (mut session, _) = session(scalar_result(1));
    let mut query = query(&mut session, Oid::INT4);
    let owned = {
        let row = ready(query.next_row()).unwrap().unwrap();
        crate::row::OwnedRow::copy_from(row.view(), row.share_layout(), 8).unwrap()
    };
    ready(query.finish()).unwrap();
    assert!(std::ptr::eq(query.layout().unwrap(), owned.layout()));
    let shared = owned.share_layout();
    assert!(Rc::ptr_eq(&query.share_layout().unwrap(), &shared));
    drop(query);
    assert_eq!(owned.view().decoder().decode_next::<i32>().unwrap(), 0);
}

#[test]
fn an_always_ready_query_yields_with_no_row_loan_and_a_rebuilt_waiter_keeps_its_place() {
    let (mut session, consumed) = session(scalar_result(300));
    let mut query = query(&mut session, Oid::INT4);
    let (count, waker) = counter();
    let mut future = Box::pin(query.finish());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 255);
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    drop(future);
    let state = query.state().unwrap();
    assert_eq!(state.rows, 254);
    assert!(!query.session.extended.as_ref().unwrap().pending_frame);
    let row = ready(query.next_row()).unwrap().unwrap();
    assert_eq!(row.view().decoder().decode_next::<i32>().unwrap(), 254);

    assert_eq!(ready(query.finish()).unwrap().rows_returned, 300);
    assert_eq!(consumed.get(), 303);
}

#[test]
fn a_byte_heavy_query_yields_before_the_row_quantum() {
    let value = vec![0; 128 * 1024];
    let (mut session, consumed) = session(result([value.clone(), value, vec![0]]));
    let mut query = query(&mut session, Oid::BYTEA);
    let (count, waker) = counter();
    let mut future = pin!(query.finish());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 3);
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    let Poll::Ready(Ok(completion)) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("the remaining small row must finish in the next poll");
    };
    assert_eq!(completion.rows_returned, 3);
}

#[test]
fn dropping_query_and_recovery_waiters_at_yield_keeps_exact_protocol_progress() {
    let (mut session, consumed) = session(scalar_result(600));
    let mut query = query(&mut session, Oid::INT4);
    let (count, waker) = counter();
    let mut future = Box::pin(query.finish());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(future);
    drop(query);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(
        recovery
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 511);
    drop(recovery);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 603);
    assert_eq!(session.remaining_boundaries, 0);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 2);
}

#[test]
fn a_large_pipeline_member_yields_and_can_be_recovered_after_the_waiter_is_dropped() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(600));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let requests = [PipelineRequest {
        statement: &statement,
        parameters: &[],
        limits: QueryLimits {
            max_rows: 600,
            max_result_bytes: 7200,
            max_metadata_bytes: 4096,
        },
    }];
    let (count, waker) = counter();
    let mut pipeline = Box::pin(session.query_pipeline(
        &requests,
        PipelineLimits {
            max_requests: 1,
            max_rows: 600,
            max_result_bytes: 16384,
            storage: crate::AllocationPolicy::ReserveLimit,
            scheduling: crate::scheduler::ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(256).unwrap(),
            },
        },
    ));
    assert!(
        pipeline
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 259);
    drop(pipeline);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(
        recovery
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(recovery);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 607);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 2);
}

#[test]
fn pipeline_members_share_a_quantum_and_unbounded_recovery_counts_data_separately() {
    let mut frames = prepare_response();
    for _ in 0..600 {
        frames.extend(scalar_result(1));
    }
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let requests: Vec<_> = (0..600)
        .map(|_| PipelineRequest {
            statement: &statement,
            parameters: &[],
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 12,
                max_metadata_bytes: 4096,
            },
        })
        .collect();
    let (count, waker) = counter();
    let mut pipeline = Box::pin(session.query_pipeline(
        &requests,
        PipelineLimits {
            max_requests: 600,
            max_rows: 600,
            max_result_bytes: 1024 * 1024,
            storage: crate::AllocationPolicy::ReserveLimit,
            scheduling: crate::scheduler::ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(256).unwrap(),
            },
        },
    ));
    assert!(
        pipeline
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    // 编码完整数据包和处理全部响应帧共用一次调度预算。
    let first_yield = consumed.get();
    assert!((5..260).contains(&first_yield));
    drop(pipeline);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(
        recovery
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), first_yield + 256);
    drop(recovery);
    loop {
        let before = consumed.get();
        let mut recovery = Box::pin(session.recover_to_ready());
        match recovery.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(result) => {
                result.unwrap();
                break;
            }
            Poll::Pending => assert_eq!(consumed.get(), before + 256),
        }
        drop(recovery);
    }
    assert_eq!(consumed.get(), 2404);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 9);
}

#[test]
fn uninterrupted_query_has_no_implicit_row_or_control_quantum() {
    let (mut session, consumed) = session(scalar_result(600));
    let mut query = query_scheduled(&mut session, Oid::INT4, ExecutionScheduling::Uninterrupted);
    let (count, waker) = counter();
    let mut future = pin!(query.finish());
    let Poll::Ready(Ok(completion)) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("uninterrupted cached responses must not add scheduling Pending");
    };
    assert_eq!(completion.rows_returned, 600);
    assert_eq!(consumed.get(), 603);
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
}

#[test]
fn one_shot_row_description_metadata_limit_obeys_each_recovery_policy() {
    metadata_description_policy_case(false, false);
    metadata_description_policy_case(false, true);
}

#[test]
fn one_shot_no_data_metadata_limit_obeys_each_recovery_policy() {
    metadata_description_policy_case(true, false);
}

#[test]
fn an_unretained_no_data_layout_keeps_its_limit_when_the_query_is_polled_again() {
    let (mut session, consumed) = session(vec![
        (b'1', Vec::new()),
        (b'2', Vec::new()),
        (b'n', Vec::new()),
        (b'C', b"UPDATE 0\0".to_vec()),
        (b'Z', vec![b'I']),
    ]);
    let mut query = ready(session.one_shot(
        "UPDATE items SET value = 0",
        &[],
        ResultFormats::All(Format::Binary),
        crate::QueryOptions {
            limits: QueryLimits {
                max_rows: 0,
                max_result_bytes: 0,
                max_metadata_bytes: 0,
            },
            scheduling: ExecutionScheduling::Uninterrupted,
        },
        crate::AbandonPolicy::RecoverExplicitly,
    ))
    .unwrap();
    for count in [3, 4] {
        assert!(matches!(
            ready(query.next_row()),
            Err(Error::Limit("query metadata exceeds its limit"))
        ));
        assert_eq!(consumed.get(), count);
    }
    assert_eq!(ready(query.finish()).unwrap().rows_affected, Some(0));
    assert_eq!(consumed.get(), 5);
}

fn projected_frames(second_row_columns: u16) -> Vec<EncodedFrame> {
    let (_, mut description) = prepare_response()
        .into_iter()
        .find(|(tag, _)| *tag == b'T')
        .unwrap();
    let end = description.len();
    description[end - 2..].copy_from_slice(&1_i16.to_be_bytes());
    let mut second = Vec::from(second_row_columns.to_be_bytes());
    for _ in 0..second_row_columns {
        second.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    vec![
        (b'1', vec![]),
        (b'2', vec![]),
        (b'T', description),
        row(&42_i32.to_be_bytes()),
        (b'D', second),
        (b'C', b"SELECT 2\0".to_vec()),
        (b'Z', vec![b'I']),
    ]
}

#[test]
fn abandoning_a_projected_one_shot_checks_the_remaining_row_shapes() {
    for columns in [1, 2] {
        let (mut session, _) = session(projected_frames(columns));
        {
            let mut query = ready(session.one_shot(
                "SELECT 42",
                &[],
                ResultFormats::All(Format::Binary),
                crate::QueryOptions {
                    limits: QueryLimits {
                        max_rows: 2,
                        max_result_bytes: 64,
                        max_metadata_bytes: 4096,
                    },
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                crate::AbandonPolicy::RecoverExplicitly,
            ))
            .unwrap();
            let mut shape = ResultShape::default();
            let value = ready(
                query.map_result_row_on_owner(Some(&mut shape), |data, shape, _| {
                    shape
                        .unwrap()
                        .scalar
                        .unwrap()
                        .decode::<i32>(data.scalar_field())
                }),
            );
            assert_eq!(shape.columns, 1);
            assert_eq!(value.unwrap().unwrap().unwrap(), 42);
            assert!(query.layout().is_none());
        }
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        let result = ready(session.recover_to_ready());
        if columns == 1 {
            result.unwrap();
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        } else {
            assert!(matches!(result, Err(Error::Codec(_))));
            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        }
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn projected_one_shot_reads_describe_and_rows_without_allocating() {
    let (mut session, _) = session(projected_frames(1));
    let mut query = ready(session.one_shot(
        "SELECT 42",
        &[],
        ResultFormats::All(Format::Binary),
        crate::QueryOptions {
            limits: QueryLimits {
                max_rows: 2,
                max_result_bytes: 64,
                max_metadata_bytes: 4096,
            },
            scheduling: ExecutionScheduling::Uninterrupted,
        },
        crate::AbandonPolicy::RecoverExplicitly,
    ))
    .unwrap();
    let mut shape = ResultShape::default();
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    assert_eq!(
        ready(
            query.map_result_row_on_owner(Some(&mut shape), |data, shape, _| {
                shape
                    .unwrap()
                    .scalar
                    .unwrap()
                    .decode::<i32>(data.scalar_field())
            })
        )
        .unwrap()
        .unwrap()
        .unwrap(),
        42
    );
    assert_eq!(
        ready(
            query.map_result_row_on_owner(Some(&mut shape), |data, shape, _| {
                shape
                    .unwrap()
                    .scalar
                    .unwrap()
                    .decode::<Option<i32>>(data.scalar_field())
            })
        )
        .unwrap()
        .unwrap()
        .unwrap(),
        None
    );
    assert!(
        ready(query.map_result_row_on_owner(Some(&mut shape), |_, _, _| ()))
            .unwrap()
            .is_none()
    );
    let change = region.change();
    assert_eq!((change.allocations, change.reallocations), (0, 0));
}

fn metadata_description_policy_case(no_data: bool, simple: bool) {
    use crate::OnError;

    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let mut frames = if simple {
            Vec::new()
        } else {
            vec![(b'1', Vec::new()), (b'2', Vec::new())]
        };
        if no_data {
            frames.push((b'n', Vec::new()));
            frames.push((b'C', b"UPDATE 1\0".to_vec()));
        } else {
            let (_, mut description) = prepare_response()
                .into_iter()
                .find(|(tag, _)| *tag == b'T')
                .unwrap();
            let end = description.len();
            description[end - 2..].copy_from_slice(&1_i16.to_be_bytes());
            frames.push((b'T', description));
            frames.push(row(&42_i32.to_be_bytes()));
            let command: &[u8] = if simple { b"FETCH 1\0" } else { b"SELECT 1\0" };
            frames.push((b'C', command.to_vec()));
        }
        frames.push((b'Z', vec![b'I']));
        let frame_count = frames.len();
        let (mut session, consumed) = session(frames);
        let limits = QueryLimits {
            max_rows: 8,
            max_result_bytes: 128,
            max_metadata_bytes: 0,
        };
        let query = if simple {
            ready(session.query_simple_single(
                "FETCH NEXT FROM binary_cursor",
                crate::QueryOptions {
                    limits,
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                crate::AbandonPolicy::RecoverExplicitly,
            ))
        } else {
            ready(session.one_shot(
                "SELECT 42",
                &[],
                ResultFormats::All(Format::Binary),
                crate::QueryOptions {
                    limits,
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                crate::AbandonPolicy::RecoverExplicitly,
            ))
        }
        .unwrap();
        let error = ready(query.collect_with(AllocationPolicy::Grow, policy)).unwrap_err();
        assert!(
            matches!(error, Error::Limit(_)),
            "policy {policy:?}, no_data={no_data}, simple={simple}: {error:?}"
        );
        match policy {
            OnError::DrainToReady => {
                assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle)
            }
            OnError::RecoverExplicitly => {
                assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                ready(session.recover_to_ready()).unwrap();
                assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            }
            OnError::Discard => {
                assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
                continue;
            }
        }
        assert_eq!(consumed.get(), frame_count);
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn warmed_ordinary_one_shot_scalar_needs_no_heap_allocation() {
    let projected_result = || {
        let mut frames = projected_frames(1);
        frames.remove(4);
        frames[4] = (b'C', b"SELECT 1\0".to_vec());
        frames
    };
    let (mut session, consumed) = session([projected_result(), projected_result()].concat());
    session.transport.retired_packet = Some(Vec::new());
    let mut client = crate::Client::with_test_session(
        session,
        crate::ExecutionOptions::direct(QueryOptions {
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 64,
                max_metadata_bytes: 4096,
            },
            scheduling: ExecutionScheduling::Uninterrupted,
        }),
    );
    let execute = |client: &mut crate::Client<ReadyFrames>| {
        ready(
            client
                .one_shot("SELECT 42", &[], ResultFormats::All(Format::Binary))
                .one::<i32>(OnError::RecoverExplicitly),
        )
    };
    assert_eq!(execute(&mut client).unwrap(), 42);
    assert!(
        client
            .expert()
            .transport
            .retired_packet
            .as_ref()
            .is_some_and(|packet| !packet.is_empty())
    );

    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    let value = execute(&mut client).unwrap();
    let counters = region.change();
    assert_eq!(value, 42);
    assert_eq!((counters.allocations, counters.reallocations), (0, 0));
    assert_eq!(consumed.get(), 12);
    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn metadata_free_recovery_still_rejects_rows_with_the_wrong_column_count() {
    use crate::OnError;

    for policy in [OnError::DrainToReady, OnError::RecoverExplicitly] {
        let (_, mut description) = prepare_response()
            .into_iter()
            .find(|(tag, _)| *tag == b'T')
            .unwrap();
        let end = description.len();
        description[end - 2..].copy_from_slice(&1_i16.to_be_bytes());
        let mut bad_row = Vec::from(2_u16.to_be_bytes());
        bad_row.extend_from_slice(&(-1_i32).to_be_bytes());
        bad_row.extend_from_slice(&(-1_i32).to_be_bytes());
        let (mut session, consumed) = session(vec![
            (b'1', Vec::new()),
            (b'2', Vec::new()),
            (b'T', description),
            (b'D', bad_row),
            (b'C', b"SELECT 1\0".to_vec()),
            (b'Z', vec![b'I']),
        ]);
        let query = ready(session.one_shot(
            "SELECT 42",
            &[],
            ResultFormats::All(Format::Binary),
            crate::QueryOptions {
                limits: QueryLimits {
                    max_rows: 8,
                    max_result_bytes: 128,
                    max_metadata_bytes: 0,
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            crate::AbandonPolicy::RecoverExplicitly,
        ))
        .unwrap();
        let error = ready(query.collect_with(AllocationPolicy::Grow, policy)).unwrap_err();
        let cleanup = match policy {
            OnError::DrainToReady => {
                let Error::Cleanup { primary, cleanup } = error else {
                    panic!("malformed rows must prevent cleanup");
                };
                assert!(matches!(*primary, Error::Limit(_)));
                *cleanup
            }
            OnError::RecoverExplicitly => {
                assert!(matches!(error, Error::Limit(_)));
                ready(session.recover_to_ready()).unwrap_err()
            }
            OnError::Discard => unreachable!(),
        };
        assert!(
            matches!(cleanup, Error::Codec(error) if matches!(*error, crate::types::CodecError::Invalid("row field count differs from its result layout")))
        );
        assert_eq!(consumed.get(), 3);
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
    }
}

#[test]
fn expert_query_keeps_its_selected_policy_after_a_local_row_limit() {
    for abandon in [
        AbandonPolicy::RecoverExplicitly,
        AbandonPolicy::DiscardOnAbandon,
    ] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(2));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let mut query = ready(session.query(
            &statement,
            &[],
            QueryOptions {
                limits: QueryLimits {
                    max_rows: 0,
                    max_result_bytes: 128,
                    max_metadata_bytes: 4096,
                },
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            abandon,
        ))
        .unwrap();
        assert!(matches!(ready(query.next_row()), Err(Error::Limit(_))));
        assert_eq!(consumed.get(), 5);
        assert!(!query.session.transport.is_broken());
        drop(query);
        if abandon == AbandonPolicy::DiscardOnAbandon {
            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
            assert!(matches!(
                ready(session.recover_to_ready_with_limits(2, 128)),
                Err(Error::Unsupported(_))
            ));
        } else {
            assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
            ready(session.recover_to_ready_with_limits(2, 128)).unwrap();
            assert_eq!(consumed.get(), 9);
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        }
    }
}

#[test]
fn owned_terminals_apply_row_limits_once_and_preserve_bounded_cleanup_failure() {
    use crate::OnError;

    for terminal in 0..3 {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            let (mut session, consumed) = session(scalar_result(2));
            let mut query =
                query_scheduled(&mut session, Oid::INT4, ExecutionScheduling::Uninterrupted);
            query.state_mut().unwrap().limits.max_rows = 0;
            let mut arena = OwnedBatch::new(query.share_layout().unwrap(), 1, 0).unwrap();
            let callbacks = Cell::new(0);
            let error = match terminal {
                0 => ready(query.collect_with(AllocationPolicy::Grow, policy)).unwrap_err(),
                1 => ready(query.collect_into(&mut arena, policy)).unwrap_err(),
                2 => {
                    let mut callback = |_: RowView<'_, '_>| {
                        callbacks.set(callbacks.get() + 1);
                        Ok(())
                    };
                    let error = ready(query.for_each_row(&mut callback, policy)).unwrap_err();
                    drop(query);
                    error
                }
                _ => unreachable!(),
            };
            assert_eq!(consumed.get(), 1);
            assert_eq!(callbacks.get(), 0);
            assert!(arena.is_empty());
            match policy {
                OnError::DrainToReady => {
                    let Error::Cleanup { primary, cleanup } = error else {
                        panic!("bounded drain failure must retain both errors");
                    };
                    assert!(matches!(
                        *primary,
                        Error::Limit("query result exceeds its selected row or byte limit")
                    ));
                    assert!(matches!(
                        *cleanup,
                        Error::Limit("recovery reached its selected data limit")
                    ));
                }
                OnError::RecoverExplicitly | OnError::Discard => {
                    assert!(matches!(
                        error,
                        Error::Limit("query result exceeds its selected row or byte limit")
                    ));
                }
            }
            if policy == OnError::Discard {
                assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
            } else {
                assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                ready(session.recover_to_ready_with_limits(2, 128)).unwrap();
                assert_eq!(consumed.get(), 5);
                assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
            }
        }
    }
}

#[test]
fn row_callback_io_error_is_local_while_ready_database_error_is_not() {
    use crate::OnError;

    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let (mut callback_session, consumed) = session(scalar_result(1));
        let mut query = query_scheduled(
            &mut callback_session,
            Oid::INT4,
            ExecutionScheduling::Uninterrupted,
        );
        let callbacks = Cell::new(0);
        let mut callback = |_: RowView<'_, '_>| {
            callbacks.set(callbacks.get() + 1);
            Err(Error::Io(io::Error::other("local row callback failure")))
        };
        assert!(matches!(
            ready(query.for_each_row(&mut callback, policy)),
            Err(Error::Io(_))
        ));
        drop(query);
        assert_eq!(callbacks.get(), 1);
        match policy {
            OnError::DrainToReady => {
                assert_eq!(consumed.get(), 4);
                assert_eq!(callback_session.reuse_state(), ReuseState::ProtocolIdle);
            }
            OnError::RecoverExplicitly => {
                assert_eq!(consumed.get(), 1);
                assert_eq!(callback_session.reuse_state(), ReuseState::NeedsRecovery);
                ready(callback_session.recover_to_ready()).unwrap();
                assert_eq!(consumed.get(), 4);
            }
            OnError::Discard => {
                assert_eq!(consumed.get(), 1);
                assert_eq!(callback_session.reuse_state(), ReuseState::DiscardOnly);
            }
        }
        for terminal in 0..3 {
            let (mut session, consumed) = session(vec![
                (b'2', Vec::new()),
                (b'E', b"SERROR\0C22012\0Mserver row failure\0\0".to_vec()),
                (b'Z', vec![b'I']),
            ]);
            let mut query =
                query_scheduled(&mut session, Oid::INT4, ExecutionScheduling::Uninterrupted);
            let mut arena = OwnedBatch::new(query.share_layout().unwrap(), 1, 128).unwrap();
            let error = match terminal {
                0 => ready(query.collect_with(AllocationPolicy::Grow, policy)).unwrap_err(),
                1 => ready(query.collect_into(&mut arena, policy)).unwrap_err(),
                2 => {
                    let mut callback =
                        |_: RowView<'_, '_>| panic!("server error has no row callback");
                    let error = ready(query.for_each_row(&mut callback, policy)).unwrap_err();
                    drop(query);
                    error
                }
                _ => unreachable!(),
            };
            assert!(matches!(error, Error::Database(_)));
            assert_eq!(consumed.get(), 3);
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        }
    }
}

#[test]
fn reset_requires_discard_all_and_idle_even_during_recovery() {
    for recover in [false, true] {
        for (tag, body, status) in [
            (b'C', &b"DEALLOCATE ALL\0"[..], b'I'),
            (b'C', &b"DISCARD ALL\0"[..], b'T'),
            (b'E', &b"SERROR\0C42501\0Mreset rejected\0\0"[..], b'I'),
        ] {
            let (mut owner, _) = session(vec![(tag, body.to_vec()), (b'Z', vec![status])]);
            let result = if recover {
                owner.transport.pause_before = Some(0);
                let mut reset = Box::pin(owner.reset_session());
                assert!(
                    reset
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                drop(reset);
                owner.transport.pause_before = None;
                ready(owner.recover_to_ready())
            } else {
                ready(owner.reset_session())
            };
            if tag == b'E' {
                assert!(matches!(result, Err(Error::Database(error)) if error.code() == "42501"));
            } else {
                assert!(matches!(result, Err(Error::Protocol(_))));
            }
            assert_eq!(owner.reuse_state(), ReuseState::DiscardOnly);
        }
    }
}

#[test]
fn reset_session_retains_live_layouts_and_recovers_abandoned_completion() {
    for pause_before_ready in [true, false] {
        let mut frames = prepare_response();
        frames.extend([(b'C', b"DISCARD ALL\0".to_vec()), (b'Z', vec![b'I'])]);
        let (mut owner, consumed) = session(frames);
        let statement = prepare(&mut owner);
        let retained = Rc::clone(statement.shared_layout());
        if pause_before_ready {
            owner.transport.pause_before = Some(5);
        } else {
            owner.transport.finish.set(FinishState::Pending);
        }
        {
            let mut reset = pin!(owner.reset_session());
            assert!(
                reset
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(consumed.get(), if pause_before_ready { 5 } else { 6 });
        assert_eq!(owner.reuse_state(), ReuseState::NeedsRecovery);
        assert!(matches!(
            owner.check_prepared_snapshot(&statement, true),
            Err(Error::InvalidInput("statement handle is stale"))
        ));
        owner.transport.pause_before = None;
        owner.transport.finish.set(FinishState::Ready);
        ready(owner.recover_to_ready()).unwrap();
        assert_eq!(consumed.get(), 6);
        assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
        drop(statement);
        assert_eq!(owner.reclaim_closed_statements().unwrap(), 0);
        assert_eq!(retained.len(), 1);
        drop(retained);
        assert_eq!(owner.reclaim_closed_statements().unwrap(), 1);
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn reset_session_only_allocates_the_send_packet() {
    let (mut owner, consumed) =
        session(vec![(b'C', b"DISCARD ALL\0".to_vec()), (b'Z', vec![b'I'])]);
    owner
        .configure_statements(StatementLimits {
            max_statements: 16,
            max_metadata_bytes: 4096,
        })
        .unwrap();

    let reset = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    ready(owner.reset_session()).unwrap();
    let actual = reset.change();
    assert_eq!(
        (
            actual.allocations,
            actual.reallocations,
            actual.bytes_allocated
        ),
        (1, 0, 5 + b"DISCARD ALL\0".len()),
    );
    assert_eq!(consumed.get(), 2);
    assert_eq!(owner.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn every_batch_terminal_preserves_an_unclaimed_transaction_end() {
    use crate::{
        BatchError, BatchErrorOrigin, BatchOptions, Client, ExecutionOptions, OwnedOutput,
    };

    fn check<Completed>(error: BatchError<Completed>) {
        assert!(matches!(error.source, Error::Unsupported(_)));
        assert_eq!(error.origin, BatchErrorOrigin::Input);
        assert_eq!(error.reuse_state, ReuseState::NeedsTransactionDecision);
        assert_eq!(error.progress.transaction_status, TransactionStatus::Idle);
        assert_eq!(error.progress.admitted, 0);
        assert!(error.progress.needs_transaction_decision);
    }

    let (session, _) = session(vec![
        (b'C', b"BEGIN\0".to_vec()),
        (b'Z', vec![b'T']),
        (b'C', b"COMMIT\0".to_vec()),
        (b'Z', vec![b'I']),
    ]);
    let limits = QueryLimits {
        max_rows: 1,
        max_result_bytes: 64,
        max_metadata_bytes: 4096,
    };
    let scheduling = ExecutionScheduling::Uninterrupted;
    let query = QueryOptions { limits, scheduling };
    let batch = BatchOptions {
        member_limits: limits,
        max_requests: 1,
        max_inflight: 1,
        max_queued_request_bytes: 128,
        max_diagnostic_bytes: 128,
        scheduling,
    };
    let mut client = Client::with_test_session(
        session,
        ExecutionOptions {
            query,
            batch: Some(batch),
        },
    );
    let mut tx = ready(client.begin_transaction()).unwrap();
    let mut commit = ready(tx.expert().query_simple_single(
        "COMMIT",
        crate::QueryOptions { limits, scheduling },
        crate::AbandonPolicy::RecoverExplicitly,
    ))
    .unwrap();
    assert_eq!(
        ready(commit.finish()).unwrap().command,
        Some(CommandKind::Commit)
    );
    drop(commit);

    let source = || {
        std::iter::once_with(|| -> crate::BatchRequest<'static> {
            panic!("事务结束后不能读取批次输入")
        })
    };
    let output = OwnedOutput {
        max_bytes: 1024,
        allocation: AllocationPolicy::Grow,
    };
    let on_error = OnError::RecoverExplicitly;
    check(ready(tx.streaming_batch(source()).collect_ready(output, on_error)).unwrap_err());
    check(
        ready(
            tx.streaming_batch(source())
                .visit_ready(output, on_error, |_| unreachable!()),
        )
        .unwrap_err(),
    );
    check(
        ready(
            tx.streaming_batch(source())
                .visit_provisional(crate::AbandonPolicy::RecoverExplicitly, |_| unreachable!()),
        )
        .unwrap_err(),
    );
    let mut scalars = Vec::with_capacity(1);
    check(
        ready(
            tx.streaming_batch(source())
                .collect_one_into_ready::<i32>(&mut scalars, on_error),
        )
        .unwrap_err(),
    );
    assert!(scalars.is_empty());
    assert_eq!(
        tx.take_transaction_end(),
        Some(crate::TransactionEnd::Committed)
    );
}

#[test]
fn simple_metadata_limit_preserves_consumed_command_and_transaction_end_for_recovery() {
    use crate::OnError;

    for (sql, tag, body, transaction_end) in [
        ("UPDATE values SET v = 1", b'C', &b"UPDATE 0\0"[..], None),
        ("", b'I', &b""[..], None),
        (
            "COMMIT",
            b'C',
            &b"COMMIT\0"[..],
            Some(crate::TransactionEnd::Committed),
        ),
        (
            "ROLLBACK",
            b'C',
            &b"ROLLBACK\0"[..],
            Some(crate::TransactionEnd::RolledBack),
        ),
    ] {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            let (mut session, consumed) = session(vec![(tag, body.to_vec()), (b'Z', vec![b'I'])]);
            let in_transaction = transaction_end.is_some();
            if in_transaction {
                session.transaction_lease = true;
                session.transaction_status = TransactionStatus::InTransaction;
            }
            let mut query = session
                .query_simple_single_scoped(
                    sql,
                    crate::QueryOptions {
                        limits: QueryLimits {
                            max_rows: 1,
                            max_result_bytes: 64,
                            max_metadata_bytes: 0,
                        },
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    crate::OnError::RecoverExplicitly,
                    in_transaction,
                )
                .unwrap();
            let mut callback = |_: RowView<'_, '_>| panic!("empty commands have no row callback");
            assert!(matches!(
                ready(query.for_each_row(&mut callback, policy)),
                Err(Error::Limit("query metadata exceeds its limit"))
            ));
            drop(query);
            let observed_end = if consumed.get() == 1
                && transaction_end == Some(crate::TransactionEnd::RolledBack)
            {
                None
            } else {
                transaction_end
            };
            assert_eq!(session.transaction_end, observed_end);
            match policy {
                OnError::DrainToReady => {
                    assert_eq!(consumed.get(), 2);
                    assert!(!session.active);
                    assert_eq!(session.remaining_boundaries, 0);
                }
                OnError::RecoverExplicitly => {
                    assert_eq!(consumed.get(), 1);
                    assert!(session.active);
                    ready(session.recover_to_ready()).unwrap();
                    assert_eq!(consumed.get(), 2);
                    assert_eq!(session.remaining_boundaries, 0);
                }
                OnError::Discard => {
                    assert_eq!(consumed.get(), 1);
                    assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
                    continue;
                }
            }
            assert_eq!(session.transaction_end, transaction_end);
            assert_eq!(
                session.reuse_state(),
                if in_transaction {
                    ReuseState::NeedsTransactionDecision
                } else {
                    ReuseState::ProtocolIdle
                }
            );
        }
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn unused_cancel_handles_allocate_one_fence_and_no_cancel_packet() {
    fn verify(endpoint: crate::client::Endpoint) {
        let (mut session, _) = session([scalar_result(1), scalar_result(1)].concat());
        session.endpoint = endpoint;
        session.cancel_key = Some(Rc::from([17; 32]));
        session.info.cancel_key_length = 32;
        session.extension();
        let layout = Rc::new(
            RowLayout::new(
                vec![Column::new("n".into(), Oid::INT4)],
                ResultFormats::All(Format::Binary),
            )
            .unwrap(),
        );
        for with_handles in [false, true] {
            let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
            let mut query = session
                .admit_query(
                    Vec::new(),
                    QueryMode::Prepared,
                    QueryLayout::Shared(Rc::clone(&layout)),
                    QueryLimits {
                        max_rows: 1,
                        max_result_bytes: 4096,
                        max_metadata_bytes: 4096,
                    },
                    ExecutionQuantum::Uninterrupted,
                    crate::OnError::RecoverExplicitly,
                )
                .unwrap();
            let handles = with_handles.then(|| {
                (
                    query.cancel_handle().unwrap(),
                    query.cancel_handle().unwrap(),
                )
            });
            assert_eq!(ready(query.finish()).unwrap().rows_returned, 1);
            let stats = region.change();
            assert_eq!(stats.allocations, usize::from(with_handles));
            assert_eq!(stats.reallocations, 0);
            drop(handles);
        }
    }
    verify(crate::client::Endpoint::Tcp("127.0.0.1:1".parse().unwrap()));
    #[cfg(unix)]
    {
        let config = crate::UnixConfig::plaintext(
            "/tmp/.s.PGSQL.5432",
            "test",
            "test",
            crate::AuthenticationPolicy::AllowAuthenticationOk,
            crate::WireLimits::short_queries(),
            crate::SendPolicy::BeforeBufferedRead,
        )
        .unwrap();
        let cloned = config.clone();
        assert!(std::sync::Arc::ptr_eq(&config.path, &cloned.path));
        verify(crate::client::Endpoint::Unix(cloned.path));
    }
}

#[test]
fn pending_query_rechecks_runtime_before_resuming_receive_or_final_send() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    for waiting_for_send in [false, true] {
        let (mut session, consumed) = session(scalar_result(1));
        session.transport.owner = Some(owner.waker());
        if waiting_for_send {
            session.transport.finish.set(FinishState::Pending);
        } else {
            session.transport.pause_before = Some(1);
        }
        let mut query =
            query_scheduled(&mut session, Oid::INT4, ExecutionScheduling::Uninterrupted);
        let mut waiting = Box::pin(query.finish());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(owner.enter(|| waiting.as_mut().poll(&mut cx)).is_pending());
        let expected_frames = if waiting_for_send { 4 } else { 1 };
        assert_eq!(consumed.get(), expected_frames);
        assert!(matches!(
            foreign.enter(|| waiting.as_mut().poll(&mut cx)),
            Poll::Ready(Err(Error::InvalidInput(_)))
        ));
        drop(waiting);
        assert_eq!(consumed.get(), expected_frames);
        assert!(query.completion().is_none());
        drop(query);
        assert_eq!(session.transport.owner_checks.get(), 2);
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
    }
}

#[test]
fn a_foreign_runtime_preserves_the_sql_error_only_after_the_final_send_waits() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    for (scheduling, send_pending) in [
        (ExecutionScheduling::Uninterrupted, true),
        (
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
            },
            false,
        ),
    ] {
        let (mut session, consumed) = session(vec![
            (b'2', Vec::new()),
            (b'E', b"SERROR\0C23505\0Mdatabase failure\0\0".to_vec()),
            (b'Z', vec![b'I']),
        ]);
        session.transport.owner = Some(owner.waker());
        session.transport.finish.set(FinishState::Pending);
        let mut query = query_scheduled(&mut session, Oid::INT4, scheduling);
        let mut waiting = Box::pin(query.finish());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(owner.enter(|| waiting.as_mut().poll(&mut cx)).is_pending());
        assert_eq!(consumed.get(), 3);
        let error = foreign.enter(|| waiting.as_mut().poll(&mut cx));
        if send_pending {
            assert!(matches!(
                error,
                Poll::Ready(Err(Error::Cleanup { primary, cleanup }))
                    if matches!(primary.as_ref(), Error::Database(error) if error.code() == "23505")
                        && matches!(cleanup.as_ref(), Error::InvalidInput(_))
            ));
        } else {
            assert!(matches!(error, Poll::Ready(Err(Error::InvalidInput(_)))));
        }
        drop(waiting);
        drop(query);
        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
    }
}

#[test]
fn cached_row_callback_cannot_move_to_another_runtime_after_yield() {
    let owner = compio::runtime::Runtime::new().unwrap();
    let foreign = compio::runtime::Runtime::new().unwrap();
    let (mut session, consumed) = session(scalar_result(1));
    session.transport.owner = Some(owner.waker());
    let mut query = query_scheduled(
        &mut session,
        Oid::INT4,
        ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
        },
    );
    let calls = Cell::new(0);
    let mut callback = |_: RowView<'_, '_>| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let mut future = pin!(query.for_each_row(&mut callback, crate::OnError::RecoverExplicitly));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(owner.enter(|| future.as_mut().poll(&mut cx)).is_pending());
    assert_eq!(consumed.get(), 1);
    assert!(matches!(
        foreign.enter(|| future.as_mut().poll(&mut cx)),
        Poll::Ready(Err(Error::InvalidInput(_)))
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(consumed.get(), 1);
}

#[test]
fn an_empty_query_charges_controls_and_recovery_keeps_the_final_ready_checkpoint() {
    let (mut session, consumed) = session(scalar_result(0));
    let mut query = query_scheduled(
        &mut session,
        Oid::INT4,
        ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(2).unwrap(),
        },
    );
    let (count, waker) = counter();
    let mut future = Box::pin(query.finish());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 1); // 编码和 BindComplete 已用完本轮额度。
    drop(future);
    let mut future = Box::pin(query.finish());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 3); // CommandComplete 和 Ready 各消耗工作额度。
    drop(future);
    assert_eq!(query.session.remaining_boundaries, 0);
    assert!(query.session.active);
    drop(query);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 3);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 2);
}

#[test]
fn a_query_can_resume_after_both_the_ready_checkpoint_and_pending_final_send() {
    for fail in [false, true] {
        let (mut session, consumed) = session(scalar_result(0));
        let finish = Rc::clone(&session.transport.finish);
        finish.set(FinishState::Pending);
        let mut query = query_scheduled(
            &mut session,
            Oid::INT4,
            ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
            },
        );
        let (wakes, waker) = counter();
        // 第一次在 Ready 后让出；重建的等待方跳过收包，第二次停在尚未完成的本地发送。
        for _ in 0..2 {
            assert!(
                pin!(query.finish())
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(consumed.get(), 3);
            assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        }
        if fail {
            finish.set(FinishState::Failed);
            assert!(matches!(ready(query.finish()), Err(Error::Io(_))));
            drop(query);
            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
        } else {
            finish.set(FinishState::Ready);
            assert_eq!(ready(query.finish()).unwrap().rows_returned, 0);
            drop(query);
            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        }
        assert_eq!(consumed.get(), 3);
    }
}

#[test]
fn an_empty_pipeline_yields_and_recovery_does_not_reset_the_control_allowance() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(0));
    frames.extend(scalar_result(0));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let requests: Vec<_> = (0..2)
        .map(|_| PipelineRequest {
            statement: &statement,
            parameters: &[],
            limits: QueryLimits {
                max_rows: 0,
                max_result_bytes: 0,
                max_metadata_bytes: 4096,
            },
        })
        .collect();
    let limits = PipelineLimits {
        max_requests: 2,
        max_rows: 0,
        max_result_bytes: 4096,
        storage: crate::AllocationPolicy::ReserveLimit,
        scheduling: ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(3).unwrap(),
        },
    };
    let (count, waker) = counter();
    let mut future = Box::pin(session.query_pipeline(&requests, limits));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 6); // 四个准备响应帧，加上 Bind 和命令响应。
    drop(future);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(
        recovery
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 9);
    drop(recovery);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 10);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 2);
}

#[test]
fn an_empty_visitor_pipeline_checks_controls_before_delivering_ready_results() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(0));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let requests = [PipelineRequest {
        statement: &statement,
        parameters: &[],
        limits: QueryLimits {
            max_rows: 0,
            max_result_bytes: 0,
            max_metadata_bytes: 4096,
        },
    }];
    let delivered = Cell::new(0);
    let limits = crate::VisitLimits {
        max_requests: 1,
        max_rows: 0,
        max_result_bytes: 4096,
        storage: crate::AllocationPolicy::ReserveLimit,
        scheduling: ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(3).unwrap(),
        },
    };
    let (_, waker) = counter();
    let mut future = Box::pin(session.query_pipeline_visit(&requests, limits, |_| {
        delivered.set(delivered.get() + 1);
        Ok(())
    }));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 6);
    assert_eq!(delivered.get(), 0);
    let Poll::Ready(Ok(completion)) = future.as_mut().poll(&mut Context::from_waker(&waker)) else {
        panic!("the remaining Ready should finish this visitor");
    };
    assert_eq!(completion.delivered, 1);
    assert_eq!(delivered.get(), 1);
}

#[test]
fn owned_window_sink_retains_results_or_returns_the_same_arena_for_reuse() {
    for retain in [false, true] {
        let mut frames = prepare_response();
        frames.extend(result([11_i32.to_be_bytes().to_vec()]));
        frames.extend(result([22_i32.to_be_bytes().to_vec()]));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let mut source = (0..2).map(|_| {
            Ok(crate::WindowRequest {
                statement: &statement,
                parameters: crate::WindowParameters::Borrowed(&[]),
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 64,
                    max_metadata_bytes: 4096,
                },
            })
        });
        let limits = crate::WindowLimits {
            max_inflight: 2,
            max_requests: 2,
            max_rows: 2,
            max_result_bytes: 64,
            storage: AllocationPolicy::ReserveLimit,
            max_queued_request_bytes: 4096,
            scheduling: ExecutionScheduling::Uninterrupted,
        };
        let mut retained = Vec::new();
        let mut addresses = Vec::new();
        let mut values = Vec::new();
        let completion = ready(session.query_window_owned_scoped(
            &mut source,
            limits,
            &mut |index, status, outcome| {
                let result = outcome.unwrap();
                assert_eq!(index, addresses.len());
                assert_eq!(status, TransactionStatus::Idle);
                let mut decoder = result.rows.rows().next().unwrap().unwrap().decoder();
                let raw = decoder.next_raw().unwrap();
                addresses.push(raw.bytes.unwrap().as_ptr());
                values.push(raw.decode::<i32>().unwrap());
                decoder.finish().unwrap();
                let reusable = if retain {
                    retained.push(result);
                    None
                } else {
                    Some(result.rows)
                };
                Ok((std::ops::ControlFlow::Continue(()), reusable))
            },
            false,
            OnError::RecoverExplicitly,
        ))
        .unwrap();
        assert_eq!(values, [11, 22]);
        assert_eq!(completion.confirmed, 2);
        assert_eq!(completion.delivered, 2);
        assert_eq!(consumed.get(), 12);
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        if retain {
            assert_ne!(addresses[0], addresses[1]);
            for (index, result) in retained.iter().enumerate() {
                let row = result.rows.rows().next().unwrap().unwrap();
                let field = row.fields().next().unwrap().unwrap();
                assert_eq!(field.bytes.unwrap().as_ptr(), addresses[index]);
                assert_eq!(field.decode::<i32>().unwrap(), values[index]);
            }
        } else {
            assert_eq!(addresses[0], addresses[1]);
        }
    }
}

#[test]
fn window_recovery_uses_the_same_admission_and_control_turn() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(0));
    frames.extend(scalar_result(0));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let mut source = (0..2).map(|_| {
        Ok(crate::WindowRequest {
            statement: &statement,
            parameters: crate::WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 0,
                max_result_bytes: 0,
                max_metadata_bytes: 4096,
            },
        })
    });
    let limits = crate::WindowLimits {
        max_inflight: 2,
        max_requests: 2,
        max_rows: 0,
        max_result_bytes: 4096,
        storage: crate::AllocationPolicy::ReserveLimit,
        max_queued_request_bytes: 4096,
        scheduling: ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
        },
    };
    let delivered = Cell::new(0);
    let mut visitor = |_: crate::ReadyBatchEvent<'_>| {
        delivered.set(delivered.get() + 1);
        Ok(std::ops::ControlFlow::Continue(()))
    };
    let (count, waker) = counter();
    let mut future = Box::pin(session.query_window(
        &mut source,
        limits,
        OnError::RecoverExplicitly,
        &mut visitor,
    ));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 6); // 两次接纳，加上 Bind 和命令响应。
    assert_eq!(delivered.get(), 0);
    drop(future);
    let mut recovery = Box::pin(session.recover_to_ready());
    assert!(
        recovery
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 10);
    drop(recovery);
    ready(session.recover_to_ready()).unwrap();
    assert_eq!(consumed.get(), 10);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(count.0.load(Ordering::Relaxed), 2);
}

#[test]
fn expert_ready_window_applies_each_error_policy_without_reading_new_input() {
    for policy in [
        OnError::DrainToReady,
        OnError::RecoverExplicitly,
        OnError::Discard,
    ] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        frames.extend(scalar_result(2));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let member_limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 12,
            max_metadata_bytes: 4096,
        };
        let mut source = (0..3).map(|index| {
            assert!(index < 2, "失败后的排空不得读取新输入");
            Ok(crate::WindowRequest {
                statement: &statement,
                parameters: crate::WindowParameters::Borrowed(&[]),
                limits: member_limits,
            })
        });
        let mut callbacks = 0;
        let error = ready(session.query_window(
            &mut source,
            crate::WindowLimits {
                max_inflight: 2,
                max_requests: 3,
                max_rows: 2,
                max_result_bytes: 12,
                storage: AllocationPolicy::Grow,
                max_queued_request_bytes: 4096,
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            policy,
            &mut |_| {
                callbacks += 1;
                Err(Error::InvalidInput("window callback rejected the result"))
            },
        ))
        .unwrap_err();
        assert!(matches!(
            error.source,
            Error::InvalidInput("window callback rejected the result")
        ));
        assert_eq!(
            (
                error.consumed,
                error.admitted,
                error.confirmed,
                error.delivered
            ),
            (2, 2, 1, 0)
        );
        assert_eq!(callbacks, 1);
        match policy {
            OnError::DrainToReady => {
                assert!(matches!(
                    error.cleanup_error.as_deref(),
                    Some(Error::Limit(_))
                ));
                assert_eq!(consumed.get(), 10);
                assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                ready(session.recover_to_ready_with_limits(1, 12)).unwrap();
            }
            OnError::RecoverExplicitly => {
                assert!(error.cleanup_error.is_none());
                assert_eq!(consumed.get(), 8);
                assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                ready(session.recover_to_ready_with_limits(2, 24)).unwrap();
            }
            OnError::Discard => {
                assert!(error.cleanup_error.is_none());
                assert_eq!(consumed.get(), 8);
                assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
                continue;
            }
        }
        assert_eq!(consumed.get(), 13);
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
    }
}

#[test]
fn scalar_batch_bounded_cleanup_includes_the_member_whose_decoder_failed() {
    use crate::{BatchOptions, Client, ExecutionOptions};

    for row_limit in [false, true] {
        let mut frames = prepare_response();
        frames.extend(result([
            vec![0; 3],
            1_i32.to_be_bytes().to_vec(),
            2_i32.to_be_bytes().to_vec(),
        ]));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let member_limits = QueryLimits {
            max_rows: if row_limit { 1 } else { 4 },
            max_result_bytes: if row_limit { 64 } else { 12 },
            max_metadata_bytes: 4096,
        };
        let scheduling = ExecutionScheduling::Uninterrupted;
        let mut client = Client::with_test_session(
            session,
            ExecutionOptions {
                query: QueryOptions {
                    limits: member_limits,
                    scheduling,
                },
                batch: Some(BatchOptions {
                    member_limits,
                    max_requests: 1,
                    max_inflight: 1,
                    max_queued_request_bytes: 128,
                    max_diagnostic_bytes: 128,
                    scheduling,
                }),
            },
        );
        let mut output = Vec::with_capacity(1);
        let error = ready(
            client
                .streaming_batch([statement.bind(&[])])
                .collect_one_into_ready::<i32>(&mut output, OnError::DrainToReady),
        )
        .unwrap_err();
        assert!(matches!(error.source, Error::Codec(_)));
        assert!(matches!(
            error.cleanup_error.as_deref(),
            Some(Error::Limit("recovery reached its selected data limit"))
        ));
        assert_eq!((error.progress.admitted, error.progress.confirmed), (1, 0));
        assert_eq!(error.reuse_state, ReuseState::NeedsRecovery);
        assert!(output.is_empty());
        assert_eq!(consumed.get(), 7);
        ready(client.recover_to_ready_with_limits(1, 12)).unwrap();
        assert_eq!(consumed.get(), 10);
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
    }
}

#[test]
fn a_provisional_last_ready_checkpoint_survives_drop_and_forget_without_delivery_replay() {
    for forget in [false, true] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let pulled = Cell::new(0);
        let mut source = std::iter::from_fn(|| {
            pulled.set(pulled.get() + 1);
            Some(Ok(crate::WindowRequest {
                statement: &statement,
                parameters: crate::WindowParameters::Borrowed(&[]),
                limits: QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 128,
                    max_metadata_bytes: 4096,
                },
            }))
        });
        let ready_callbacks = Cell::new(0);
        let mut visitor = |event: crate::ProvisionalWindowEvent<'_>| {
            if matches!(event, crate::ProvisionalWindowEvent::Ready { .. }) {
                ready_callbacks.set(ready_callbacks.get() + 1);
            }
            Ok(crate::ProvisionalWindowControl::Continue)
        };
        let limits = crate::ProvisionalWindowLimits {
            max_inflight: 1,
            max_requests: 1,
            max_rows: 1,
            max_row_bytes: 128,
            max_queued_request_bytes: 4096,
            max_diagnostic_bytes: 4096,
            scheduling: ExecutionScheduling::Cooperative {
                max_work_per_turn: std::num::NonZeroUsize::new(5).unwrap(),
            },
            abandon: crate::AbandonPolicy::RecoverExplicitly,
        };
        let (wakes, waker) = counter();
        let mut future =
            Box::pin(session.query_window_provisional_visit(&mut source, limits, &mut visitor));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(consumed.get(), 8); // 准备阶段，以及 Bind、行、命令和 Ready 响应。
        assert_eq!(ready_callbacks.get(), 0);
        if forget {
            std::mem::forget(future);
        } else {
            drop(future);
        }
        assert_eq!(session.remaining_boundaries, 0);
        assert!(session.active);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        ready(session.recover_to_ready()).unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(consumed.get(), 8);
        assert_eq!(ready_callbacks.get(), 0);
        assert_eq!(pulled.get(), 1);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn rebuilding_provisional_recovery_waiters_preserves_the_frame_allowance() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(20));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    let pulled = Cell::new(0);
    let mut source = std::iter::from_fn(|| {
        pulled.set(pulled.get() + 1);
        Some(Ok(crate::WindowRequest {
            statement: &statement,
            parameters: crate::WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 32,
                max_result_bytes: 4096,
                max_metadata_bytes: 4096,
            },
        }))
    });
    let callbacks = Cell::new(0);
    let mut visitor = |_: crate::ProvisionalWindowEvent<'_>| {
        callbacks.set(callbacks.get() + 1);
        Ok(crate::ProvisionalWindowControl::Continue)
    };
    let limits = crate::ProvisionalWindowLimits {
        max_inflight: 1,
        max_requests: 10,
        max_rows: 320,
        max_row_bytes: 40960,
        max_queued_request_bytes: 4096,
        max_diagnostic_bytes: 4096,
        scheduling: ExecutionScheduling::Cooperative {
            max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
        },
        abandon: crate::AbandonPolicy::RecoverExplicitly,
    };
    let (wakes, waker) = counter();
    let mut original =
        Box::pin(session.query_window_provisional_visit(&mut source, limits, &mut visitor));
    assert!(
        original
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(consumed.get(), 7);
    assert_eq!(callbacks.get(), 2);
    drop(original);
    let mut yields = 0;
    loop {
        let before = consumed.get();
        let mut recovery = Box::pin(session.recover_to_ready());
        match recovery.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                assert_eq!(consumed.get(), before + 4);
                yields += 1;
            }
            Poll::Ready(result) => {
                result.unwrap();
                break;
            }
        }
        drop(recovery);
    }
    assert_eq!(yields, 5);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 6);
    assert_eq!(consumed.get(), 27);
    assert_eq!(callbacks.get(), 2);
    assert_eq!(pulled.get(), 1);
    assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
}

#[test]
fn collect_into_ready_publishes_rows_only_after_local_tx_retires() {
    use crate::{BatchOptions, Client, ExecutionOptions, OnError, QueryOptions};

    for (forget, settlement) in [
        (false, None),
        (true, None),
        (false, Some(FinishState::Failed)),
        (false, Some(FinishState::Ready)),
    ] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let finish = Rc::clone(&session.transport.finish);
        finish.set(FinishState::Pending);
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        };
        let scheduling = ExecutionScheduling::Uninterrupted;
        let mut client = Client::with_test_session(
            session,
            ExecutionOptions {
                query: QueryOptions { limits, scheduling },
                batch: Some(BatchOptions {
                    member_limits: limits,
                    max_requests: 1,
                    max_inflight: 1,
                    max_queued_request_bytes: 4096,
                    max_diagnostic_bytes: 4096,
                    scheduling,
                }),
            },
        );
        let mut output = statement.new_row_buffer(1, 128).unwrap();
        let (tag, body) = row(&(-1_i32).to_be_bytes());
        let BackendMessage::DataRow(data) =
            protocol::parse_backend(Frame { tag, body: &body }).unwrap()
        else {
            panic!("fixture must contain a row");
        };
        let seed = RowView::new(data, statement.layout()).unwrap();
        output.push(seed).unwrap();
        let pointer = |batch: &OwnedBatch| {
            batch
                .rows()
                .next()
                .unwrap()
                .unwrap()
                .decoder()
                .next_raw()
                .unwrap()
                .bytes
                .unwrap()
                .as_ptr()
        };
        let original = pointer(&output);
        let mut future = Box::pin(
            client
                .query(&statement, &[])
                .collect_into_ready(&mut output, OnError::RecoverExplicitly),
        );
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(consumed.get(), 8); // 一行和 Ready 已完整到达，本地发送仍待完成。

        match settlement {
            None => {
                if forget {
                    std::mem::forget(future);
                } else {
                    drop(future);
                }
                assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
            }
            Some(FinishState::Failed) => {
                finish.set(FinishState::Failed);
                assert!(matches!(ready(future), Err(Error::Io(_))));
                assert_eq!(client.reuse_state(), ReuseState::DiscardOnly);
            }
            Some(FinishState::Ready) => {
                finish.set(FinishState::Ready);
                assert_eq!(ready(future).unwrap().rows_returned, 1);
                assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
                let row = output.rows().next().unwrap().unwrap();
                assert_eq!(row.decoder().decode_next::<i32>().unwrap(), 0);
                assert_eq!(pointer(&output), original);
                continue;
            }
            Some(FinishState::Pending) => unreachable!(),
        }
        assert!(output.is_empty());
        assert!(output.rows().next().is_none());
        assert_eq!(output.used_bytes(), 0);
        assert_eq!(output.retained_bytes(), 128);
        output.push(seed).unwrap();
        assert_eq!(pointer(&output), original);
        let row = output.rows().next().unwrap().unwrap();
        assert_eq!(row.decoder().decode_next::<i32>().unwrap(), -1);
    }
}

#[test]
fn scalar_batch_keeps_output_staged_until_local_tx_retirement() {
    use crate::{BatchOptions, Client, ExecutionOptions, OnError, QueryOptions};

    for final_state in [None, Some(FinishState::Ready), Some(FinishState::Failed)] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let finish = Rc::clone(&session.transport.finish);
        finish.set(FinishState::Pending);
        let limits = QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        };
        let scheduling = ExecutionScheduling::Uninterrupted;
        let mut client = Client::with_test_session(
            session,
            ExecutionOptions {
                query: QueryOptions { limits, scheduling },
                batch: Some(BatchOptions {
                    member_limits: limits,
                    max_requests: 1,
                    max_inflight: 1,
                    max_queued_request_bytes: 4096,
                    max_diagnostic_bytes: 4096,
                    scheduling,
                }),
            },
        );
        let mut output = Vec::with_capacity(2);
        output.push(Ok(-1));
        let original = output.as_ptr();
        let mut future = Box::pin(
            client
                .streaming_batch([statement.bind(&[])])
                .collect_one_into_ready::<i32>(&mut output, OnError::RecoverExplicitly),
        );
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(consumed.get(), 8); // 已收到 Ready，本地发送仍待完成。

        match final_state {
            None => {
                drop(future);
                assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
                assert!(matches!(output.as_slice(), [Ok(-1)]));
            }
            Some(FinishState::Failed) => {
                finish.set(FinishState::Failed);
                let error = ready(future).unwrap_err();
                assert!(matches!(error.source, Error::Io(_)));
                assert_eq!(error.progress.confirmed, 1);
                assert_eq!(client.reuse_state(), ReuseState::DiscardOnly);
                assert!(matches!(output.as_slice(), [Ok(-1)]));
            }
            Some(FinishState::Ready) => {
                finish.set(FinishState::Ready);
                let progress = ready(future).unwrap();
                assert_eq!(progress.confirmed, 1);
                assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
                assert!(matches!(output.as_slice(), [Ok(-1), Ok(0)]));
            }
            Some(FinishState::Pending) => unreachable!(),
        }
        assert_eq!(output.as_ptr(), original);
        assert_eq!(consumed.get(), 8);
    }
}

#[test]
fn owned_last_ready_preserves_error_policy_until_tx_retirement_after_drop_or_forget() {
    use crate::OnError;

    for batch in [false, true] {
        for policy in [
            OnError::DrainToReady,
            OnError::RecoverExplicitly,
            OnError::Discard,
        ] {
            for forget in [false, true] {
                for late_failure in [false, true] {
                    let mut frames = prepare_response();
                    frames.extend(scalar_result(1));
                    let (mut session, consumed) = session(frames);
                    let statement = prepare(&mut session);
                    let finish = Rc::clone(&session.transport.finish);
                    finish.set(FinishState::Pending);
                    let pulled = Cell::new(0);
                    let callbacks = Cell::new(0);
                    let limits = QueryLimits {
                        max_rows: 1,
                        max_result_bytes: 128,
                        max_metadata_bytes: 4096,
                    };
                    if batch {
                        let mut source = std::iter::from_fn(|| {
                            pulled.set(pulled.get() + 1);
                            Some(Ok(crate::WindowRequest {
                                statement: &statement,
                                parameters: crate::WindowParameters::Borrowed(&[]),
                                limits,
                            }))
                        });
                        let mut visitor =
                            |index, status, outcome: super::super::pipeline::PipelineItem| {
                                assert_eq!(index, 0);
                                assert_eq!(status, TransactionStatus::Idle);
                                assert_eq!(outcome.unwrap().rows.len(), 1);
                                callbacks.set(callbacks.get() + 1);
                                Ok((std::ops::ControlFlow::Continue(()), None))
                            };
                        let mut future = Box::pin(session.query_window_owned_scoped(
                            &mut source,
                            crate::WindowLimits {
                                max_inflight: 1,
                                max_requests: 1,
                                max_rows: 1,
                                max_result_bytes: 128,
                                storage: AllocationPolicy::Grow,
                                max_queued_request_bytes: 4096,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            &mut visitor,
                            false,
                            policy,
                        ));
                        assert!(
                            future
                                .as_mut()
                                .poll(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                        assert_eq!(callbacks.get(), 1);
                        if forget {
                            std::mem::forget(future);
                        } else {
                            drop(future);
                        }
                    } else {
                        let mut query = ready(session.query(
                            &statement,
                            &[],
                            crate::QueryOptions {
                                limits,
                                scheduling: ExecutionScheduling::Uninterrupted,
                            },
                            crate::AbandonPolicy::RecoverExplicitly,
                        ))
                        .unwrap();
                        query.replace_on_error(policy).unwrap();
                        let mut future = Box::pin(async move { query.finish().await });
                        assert!(
                            future
                                .as_mut()
                                .poll(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                        if forget {
                            std::mem::forget(future);
                        } else {
                            drop(future);
                        }
                    }
                    assert_eq!(consumed.get(), 8);
                    assert_eq!(session.remaining_boundaries, 0);
                    assert!(session.active);
                    if policy == OnError::Discard {
                        assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
                        assert!(matches!(
                            ready(session.recover_to_ready()),
                            Err(Error::Unsupported(_))
                        ));
                        assert!(session.transport.is_broken());
                    } else {
                        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                        let mut recovery = Box::pin(session.recover_to_ready());
                        assert!(
                            recovery
                                .as_mut()
                                .poll(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                        drop(recovery);
                        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
                        finish.set(if late_failure {
                            FinishState::Failed
                        } else {
                            FinishState::Ready
                        });
                        let result = ready(session.recover_to_ready());
                        if late_failure {
                            assert!(matches!(result, Err(Error::Io(_))));
                            assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
                        } else {
                            result.unwrap();
                            assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
                        }
                    }
                    assert_eq!(consumed.get(), 8);
                    assert_eq!(pulled.get(), usize::from(batch));
                    assert_eq!(callbacks.get(), usize::from(batch));
                }
            }
        }
    }
}

#[test]
fn provisional_ready_delivery_and_abort_do_not_retire_a_pending_send() {
    for abort in [false, true] {
        let mut frames = prepare_response();
        frames.extend(scalar_result(1));
        let (mut session, consumed) = session(frames);
        let statement = prepare(&mut session);
        let finish = Rc::clone(&session.transport.finish);
        finish.set(FinishState::Pending);
        let mut source = std::iter::once(Ok(crate::WindowRequest {
            statement: &statement,
            parameters: crate::WindowParameters::Borrowed(&[]),
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 128,
                max_metadata_bytes: 4096,
            },
        }));
        let ready_callbacks = Cell::new(0);
        let mut visitor = |event: crate::ProvisionalWindowEvent<'_>| {
            if matches!(event, crate::ProvisionalWindowEvent::Ready { .. }) {
                ready_callbacks.set(ready_callbacks.get() + 1);
                if abort {
                    return Ok(crate::ProvisionalWindowControl::Abort);
                }
            }
            Ok(crate::ProvisionalWindowControl::Continue)
        };
        let limits = crate::ProvisionalWindowLimits {
            max_inflight: 1,
            max_requests: 1,
            max_rows: 1,
            max_row_bytes: 128,
            max_queued_request_bytes: 4096,
            max_diagnostic_bytes: 4096,
            scheduling: ExecutionScheduling::Uninterrupted,
            abandon: crate::AbandonPolicy::RecoverExplicitly,
        };
        let (_, waker) = counter();
        let mut future =
            Box::pin(session.query_window_provisional_visit(&mut source, limits, &mut visitor));
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(result) if abort => assert!(result.unwrap().aborted),
            Poll::Pending if !abort => {}
            _ => panic!("only explicit Abort may return before the send retires"),
        }
        assert_eq!(consumed.get(), 8);
        assert_eq!(ready_callbacks.get(), 1);
        drop(future);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        let mut recovery = Box::pin(session.recover_to_ready());
        assert!(
            recovery
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(recovery);
        assert_eq!(session.reuse_state(), ReuseState::NeedsRecovery);
        assert_eq!(consumed.get(), 8);
        finish.set(FinishState::Ready);
        ready(session.recover_to_ready()).unwrap();
        assert_eq!(session.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(ready_callbacks.get(), 1);
    }
}

#[test]
fn provisional_final_send_error_keeps_confirmed_progress_but_discards_reuse() {
    let mut frames = prepare_response();
    frames.extend(scalar_result(1));
    let (mut session, consumed) = session(frames);
    let statement = prepare(&mut session);
    session.transport.finish.set(FinishState::Failed);
    let mut source = std::iter::once(Ok(crate::WindowRequest {
        statement: &statement,
        parameters: crate::WindowParameters::Borrowed(&[]),
        limits: QueryLimits {
            max_rows: 1,
            max_result_bytes: 128,
            max_metadata_bytes: 4096,
        },
    }));
    let callbacks = Cell::new(0);
    let mut visitor = |_: crate::ProvisionalWindowEvent<'_>| {
        callbacks.set(callbacks.get() + 1);
        Ok(crate::ProvisionalWindowControl::Continue)
    };
    let error = ready(session.query_window_provisional_visit(
        &mut source,
        crate::ProvisionalWindowLimits {
            max_inflight: 1,
            max_requests: 1,
            max_rows: 1,
            max_row_bytes: 128,
            max_queued_request_bytes: 4096,
            max_diagnostic_bytes: 4096,
            scheduling: ExecutionScheduling::Uninterrupted,
            abandon: crate::AbandonPolicy::RecoverExplicitly,
        },
        &mut visitor,
    ))
    .unwrap_err();
    assert_eq!(error.origin, crate::ProvisionalWindowErrorOrigin::Transport);
    assert_eq!(error.progress.admitted, 1);
    assert_eq!(error.progress.confirmed, 1);
    assert_eq!(error.progress.events_delivered, 3);
    assert_eq!(callbacks.get(), 3);
    assert_eq!(consumed.get(), 8);
    assert!(error.may_have_executed);
    assert_eq!(session.reuse_state(), ReuseState::DiscardOnly);
}
