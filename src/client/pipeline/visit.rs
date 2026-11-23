//! 有限流水线先提交全体成员，再按 Ready 次序借用一个可复用的结果缓冲。

use super::{
    MemberReadOptions, PipelineProgress, PipelineRequest, PipelineResult, ReadyBatchEvent,
    ReadyBatchResult,
};
use crate::transport::WireOps;
use crate::{
    Error, Session,
    client::Transaction,
    client::general::WorkKind,
    protocol::TransactionStatus,
    row::AllocationPolicy,
    scheduler::{ExecutionQuantum, ExecutionScheduling},
    transport::{TransportExt, WireTransport},
};
use std::fmt;

/// 一次有限访问的限额。
/// 收发、恢复列数、语句元数据、终端错误及回调自行保留的副本另计；致命诊断受连接帧上限约束。
#[derive(Debug, Clone, Copy)]
pub struct VisitLimits {
    pub max_requests: usize,
    /// 全部已观察到的数据行，含后来因 SQL 错误丢弃的行。
    pub max_rows: usize,
    /// 当前成员的行缓冲或普通 SQL 诊断的容量。
    /// 须容纳该成员的结果限额及可能的诊断头和文本。
    pub max_result_bytes: usize,
    /// 回调返回后控制缓冲扩容及复用。
    /// 清空存储后才绑定本成员的布局。
    pub storage: AllocationPolicy,
    /// 整个操作共用的调度预算。
    pub scheduling: ExecutionScheduling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisitCompletion {
    pub admitted: usize,
    pub confirmed: usize,
    /// 成功返回的回调数。
    /// 返回错误或 panic 的回调也可能已经产生外部副作用。
    pub delivered: usize,
    pub sql_errors: usize,
    pub transaction_status: TransactionStatus,
}

/// 回调或本地发送失败时仍保留进度。
/// 已确认但回调失败的成员不计入已交付；错误不保留已借用结果的副本。
/// 计数无法证明回调没有对外产生影响。
pub struct VisitError {
    pub admitted: usize,
    pub confirmed: usize,
    pub delivered: usize,
    pub sql_errors: usize,
    pub source: Error,
    pub may_have_executed: bool,
}

impl VisitError {
    pub(in crate::client) fn before_admission(source: Error) -> Self {
        Self {
            admitted: 0,
            confirmed: 0,
            delivered: 0,
            sql_errors: 0,
            source,
            may_have_executed: false,
        }
    }
}

impl fmt::Debug for VisitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VisitError")
            .field("admitted", &self.admitted)
            .field("confirmed", &self.confirmed)
            .field("delivered", &self.delivered)
            .field("sql_errors", &self.sql_errors)
            .field("source", &self.source)
            .field("may_have_executed", &self.may_have_executed)
            .finish()
    }
}

impl fmt::Display for VisitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prepared pipeline visit stopped after {} confirmed and {} delivered members: {}",
            self.confirmed, self.delivered, self.source
        )
    }
}

impl std::error::Error for VisitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Default)]
struct Counts {
    admitted: usize,
    confirmed: usize,
    delivered: usize,
    sql_errors: usize,
}

impl<T: WireTransport> Session<T> {
    /// 预检全部请求并编码成一个包，每个成员独立 Sync，再依次访问已确认的结果。
    /// 因已全部提交，回调不能撤销已接纳的 SQL。
    /// 涉及会话或 schema 变更时应分批执行。
    ///
    /// 回调须迅速返回，自行保留的副本另行计费。
    /// 可复用容量合适的缓冲，异构成员或 SQL 错误可能另行分配。
    /// 回调报错或 panic 时须丢弃会话，之前已交付的结果仍有效。
    /// 成功返回也确认本地发送完成；放弃 future 后仍须恢复已接纳的协议进度。
    pub async fn query_pipeline_visit<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: VisitLimits,
        mut on_result: F,
    ) -> Result<VisitCompletion, VisitError>
    where
        F: for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<(), Error>,
    {
        self.query_pipeline_visit_scoped(requests, limits, &mut on_result, false)
            .await
    }

    async fn query_pipeline_visit_scoped<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: VisitLimits,
        on_result: &mut F,
        in_transaction: bool,
    ) -> Result<VisitCompletion, VisitError>
    where
        F: for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<(), Error>,
    {
        self.check_idle_access(in_transaction)
            .map_err(VisitError::before_admission)?;
        let mut counts = Counts::default();
        let result = self
            .pipeline_visit_inner(requests, limits, on_result, &mut counts)
            .await;
        if let Err(source) = result {
            if counts.admitted != 0 {
                self.transport.break_connection();
            }
            return Err(VisitError {
                admitted: counts.admitted,
                confirmed: counts.confirmed,
                delivered: counts.delivered,
                sql_errors: counts.sql_errors,
                source,
                may_have_executed: counts.admitted != 0,
            });
        }
        Ok(VisitCompletion {
            admitted: counts.admitted,
            confirmed: counts.confirmed,
            delivered: counts.delivered,
            sql_errors: counts.sql_errors,
            transaction_status: self.transaction_status,
        })
    }

    async fn pipeline_visit_inner<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: VisitLimits,
        on_result: &mut F,
        counts: &mut Counts,
    ) -> Result<(), Error>
    where
        F: for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<(), Error>,
    {
        let quantum = ExecutionQuantum::new(limits.scheduling);
        if requests.is_empty() {
            return Ok(());
        }
        if limits.max_requests == 0 || requests.len() > limits.max_requests {
            return Err(Error::Limit(
                "pipeline visit request count exceeds its limit",
            ));
        }
        for request in requests {
            if request.limits.max_result_bytes > limits.max_result_bytes {
                return Err(Error::Limit(
                    "pipeline visit member arena exceeds its capacity domain",
                ));
            }
        }
        let bytes = self.encode_pipeline(requests)?;
        let columns = std::mem::take(&mut self.extension().pipeline_columns);
        let mut progress =
            PipelineProgress::fixed(columns, requests, limits.max_requests, quantum)?;
        progress.quantum.spend_bytes(bytes.len());
        self.extension().work_kind = Some(WorkKind::Pipeline(progress));
        self.active = true;
        self.remaining_boundaries = requests.len();
        if let Err(error) = self.transport.begin_send(bytes) {
            self.transport.break_connection();
            return Err(error);
        }
        counts.admitted = requests.len();
        let mut remaining_rows = limits.max_rows;
        let mut reusable = None;
        for request in requests {
            let mut remaining_bytes = limits.max_result_bytes;
            let result = self
                .read_pipeline_member_into(
                    request.statement.shared_layout(),
                    request.limits.into(),
                    &mut remaining_rows,
                    &mut remaining_bytes,
                    reusable.take(),
                    MemberReadOptions {
                        storage: limits.storage,
                        diagnostic_limit: None,
                    },
                )
                .await?
                .into_result()?;
            let index = counts.confirmed;
            counts.confirmed += 1;
            if result.is_err() {
                counts.sql_errors += 1;
            }
            let transaction_status = self.transaction_status;
            self.extension().invoke_callback(|| {
                on_result(ReadyBatchEvent {
                    index,
                    transaction_status,
                    outcome: match &result {
                        Ok(PipelineResult { rows, completion }) => Ok(ReadyBatchResult {
                            rows,
                            completion: *completion,
                        }),
                        Err(error) => Err(error),
                    },
                })
            })?;
            counts.delivered += 1;
            reusable = result.ok().map(|result| result.rows);
        }
        self.transport.finish_send_on_owner().await?;
        self.extension().clear_work();
        self.active = false;
        Ok(())
    }
}

impl<T: WireTransport> Transaction<'_, T> {
    /// 预检整个有限批次，再按 Ready 次序交付结果。
    /// 回调期间持续持有事务。
    pub async fn query_pipeline_visit<F>(
        &mut self,
        requests: &[PipelineRequest<'_>],
        limits: VisitLimits,
        mut on_result: F,
    ) -> Result<VisitCompletion, VisitError>
    where
        F: for<'row> FnMut(ReadyBatchEvent<'row>) -> Result<(), Error>,
    {
        self.session_mut()
            .query_pipeline_visit_scoped(requests, limits, &mut on_result, true)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StatementLimits, protocol::Frame, row::ResultFormats, types::Format};
    use std::{
        io,
        task::{Context, Poll},
    };

    struct LateSendFailure {
        frames: Vec<(u8, Vec<u8>)>,
        next: usize,
        sends: usize,
        broken: bool,
    }

    impl crate::transport::WireOps for LateSendFailure {
        fn owner_waker(&self) -> Option<&std::task::Waker> {
            None
        }

        fn is_broken(&self) -> bool {
            self.broken
        }
        fn break_connection(&mut self) {
            self.broken = true;
        }
        fn begin_send(&mut self, _: Vec<u8>) -> Result<(), Error> {
            if self.broken {
                return Err(Error::Broken);
            }
            self.sends += 1;
            Ok(())
        }
        fn take_send_packet(&mut self) -> Result<Vec<u8>, Error> {
            Ok(Vec::new())
        }
        fn send_queue_available(&self) -> usize {
            0
        }
        fn disable_send_queue(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn poll_finish_send(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
            if self.sends == 2 && self.next == self.frames.len() {
                return Poll::Ready(Err(io::Error::other("late TX completion failure").into()));
            }
            Poll::Ready(Ok(()))
        }
        fn poll_receive_frame(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
            if self.next < self.frames.len() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()))
            }
        }
        fn frame(&mut self) -> Result<Frame<'_>, Error> {
            let (tag, body) = self.frames.get(self.next).ok_or(Error::Busy)?;
            Ok(Frame { tag: *tag, body })
        }
        fn consume_frame(&mut self) -> Result<(), Error> {
            if self.next == self.frames.len() {
                return Err(Error::Busy);
            }
            self.next += 1;
            Ok(())
        }
        async fn close(self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn every_ready_and_delivery_still_requires_final_tx_harvesting() {
        let mut description = Vec::from(1_u16.to_be_bytes());
        description.extend_from_slice(b"n\0");
        description.extend_from_slice(&0_u32.to_be_bytes());
        description.extend_from_slice(&0_i16.to_be_bytes());
        description.extend_from_slice(&23_u32.to_be_bytes());
        description.extend_from_slice(&4_i16.to_be_bytes());
        description.extend_from_slice(&(-1_i32).to_be_bytes());
        description.extend_from_slice(&0_i16.to_be_bytes());
        let mut frames = vec![
            (b'1', Vec::new()),
            (b't', vec![0, 0]),
            (b'T', description),
            (b'Z', vec![b'I']),
        ];
        for value in [41_i32, 42] {
            let mut row = Vec::from(1_u16.to_be_bytes());
            row.extend_from_slice(&4_i32.to_be_bytes());
            row.extend_from_slice(&value.to_be_bytes());
            frames.extend([
                (b'2', Vec::new()),
                (b'D', row),
                (b'C', b"SELECT 1\0".to_vec()),
                (b'Z', vec![b'I']),
            ]);
        }
        let mut session = Session::<LateSendFailure> {
            transport: LateSendFailure {
                frames,
                next: 0,
                sends: 0,
                broken: false,
            },
            id: crate::client::allocate_connection_id().unwrap(),
            active: false,
            transaction_status: TransactionStatus::Idle,
            info: crate::client::ServerInfo {
                version: "19.0".to_owned(),
                process_id: 0,
                cancel_key_length: 0,
            },
            cancel_key: None,
            max_messages: 128,
            max_request_len: 8192,
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
        };
        let runtime = compio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            session
                .configure_statements(StatementLimits {
                    max_statements: 1,
                    max_metadata_bytes: 16384,
                })
                .unwrap();
            let statement = session
                .prepare("SELECT 42", &[], ResultFormats::All(Format::Binary))
                .await
                .unwrap();
            let request = || PipelineRequest {
                statement: &statement,
                parameters: &[],
                limits: crate::QueryLimits {
                    max_rows: 1,
                    max_result_bytes: 12,
                    max_metadata_bytes: 16384,
                },
            };
            let mut values = Vec::new();
            let error = session
                .query_pipeline_visit(
                    &[request(), request()],
                    VisitLimits {
                        storage: crate::AllocationPolicy::ReserveLimit,
                        max_requests: 2,
                        max_rows: 2,
                        max_result_bytes: 4096,
                        scheduling: crate::scheduler::ExecutionScheduling::Uninterrupted,
                    },
                    |event: ReadyBatchEvent<'_>| {
                        let rows = event.outcome.unwrap().rows;
                        values.push(
                            rows.rows()
                                .next()
                                .unwrap()
                                .unwrap()
                                .decoder()
                                .decode_next::<i32>()
                                .unwrap(),
                        );
                        Ok(())
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(values, [41, 42]);
            assert_eq!(
                (
                    error.admitted,
                    error.confirmed,
                    error.delivered,
                    error.sql_errors
                ),
                (2, 2, 2, 0)
            );
            assert!(matches!(error.source, Error::Io(_)));
            assert!(error.may_have_executed);
            assert!(session.active);
            assert_eq!(session.reuse_state(), crate::ReuseState::DiscardOnly);
            assert_eq!(session.transport.sends, 2);
        });
    }
}
