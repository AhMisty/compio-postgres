//! 在三种传输上验证 COPY 的批量发送、缓冲回收和结果收集。

#[path = "support/live.rs"]
mod live;

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

use compio_postgres::{
    AllocationPolicy, CopyBatchLimits, CopyDataBuffer, CopyStreamLimits, Error, OwnedOutput,
    QueryLimits, ReuseState, TcpConfig, TransactionStatus, WireLimits, WireTransport,
    expert::{CopyProtocol, Session},
};
use futures_util::Stream;
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 65536,
        max_messages_per_request: 128,
    }
}

fn config() -> TcpConfig {
    live::tcp_config(limits(), tcp_options::TCP_OPTIONS)
}

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("optimized COPY matrix deadline")
    });
}

async fn execute<T: WireTransport>(connection: &mut Session<T>, sql: &str) -> Result<(), Error> {
    connection
        .query_simple_single(
            sql,
            compio_postgres::QueryOptions {
                limits: QueryLimits {
                    max_rows: 0,
                    max_result_bytes: 0,
                    max_metadata_bytes: 8192,
                },
                scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
            },
            compio_postgres::AbandonPolicy::RecoverExplicitly,
        )
        .await?
        .finish()
        .await?;
    Ok(())
}

struct RecycledSource {
    pool: Rc<RefCell<Vec<CopyDataBuffer>>>,
    produced: Rc<Cell<usize>>,
}
impl Stream for RecycledSource {
    type Item = Result<CopyDataBuffer, Error>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.produced.get() == 3 {
            return Poll::Ready(None);
        }
        let Some(mut packet) = self.pool.borrow_mut().pop() else {
            return Poll::Pending;
        };
        packet.clear();
        packet.extend_from_slice(b"4\n").unwrap();
        self.produced.set(self.produced.get() + 1);
        Poll::Ready(Some(Ok(packet)))
    }
}

async fn exercise<T: WireTransport>(connection: &mut Session<T>) -> Result<(), Error> {
    execute(connection, "CREATE TEMP TABLE cpg_optimized_copy(v int4)").await?;
    for protocol in [CopyProtocol::SimpleSingle, CopyProtocol::Extended] {
        for in_transaction in [false, true] {
            for storage in [AllocationPolicy::ReserveLimit, AllocationPolicy::Grow] {
                execute(connection, "TRUNCATE cpg_optimized_copy").await?;
                let selected = OwnedOutput {
                    max_bytes: 64,
                    allocation: storage,
                };
                let batch = CopyBatchLimits {
                    max_chunks: 3,
                    max_packet_bytes: 65536,
                };
                let (bytes, status) = if in_transaction {
                    let mut transaction = connection.begin_transaction().await?;
                    let mut input = transaction
                        .copy_in(
                            "COPY cpg_optimized_copy FROM STDIN",
                            &[],
                            protocol,
                            compio_postgres::ExecutionScheduling::Uninterrupted,
                        )
                        .await?;
                    let sent = input
                        .send_batch(&[b"1\n2", b"\n", b"3\n"], batch)
                        .await
                        .map_err(|error| error.source)?;
                    assert_eq!((sent.chunks, sent.payload_bytes), (3, 6));
                    let completed = input.finish().await?;
                    assert_eq!(completed.rows, 3);
                    assert_eq!(
                        completed.transaction_status,
                        TransactionStatus::InTransaction
                    );
                    let output = transaction
                        .copy_out(
                            "COPY (SELECT v FROM cpg_optimized_copy ORDER BY v) TO STDOUT",
                            &[],
                            protocol,
                            compio_postgres::ExecutionScheduling::Uninterrupted,
                        )
                        .await?;
                    let (bytes, completion) = output
                        .collect_ready(selected, compio_postgres::OnError::RecoverExplicitly)
                        .await?;
                    assert_eq!(completion.rows, 3);
                    transaction.rollback().await?;
                    (bytes, completion.transaction_status)
                } else {
                    let mut input = connection
                        .copy_in(
                            "COPY cpg_optimized_copy FROM STDIN",
                            &[],
                            protocol,
                            compio_postgres::ExecutionScheduling::Uninterrupted,
                        )
                        .await?;
                    let sent = input
                        .send_batch(&[b"1\n2", b"\n", b"3\n"], batch)
                        .await
                        .map_err(|error| error.source)?;
                    assert_eq!((sent.chunks, sent.payload_bytes), (3, 6));
                    let completed = input.finish().await?;
                    assert_eq!(completed.rows, 3);
                    assert_eq!(completed.transaction_status, TransactionStatus::Idle);
                    let output = connection
                        .copy_out(
                            "COPY (SELECT v FROM cpg_optimized_copy ORDER BY v) TO STDOUT",
                            &[],
                            protocol,
                            compio_postgres::ExecutionScheduling::Uninterrupted,
                        )
                        .await?;
                    let (bytes, completion) = output
                        .collect_ready(selected, compio_postgres::OnError::RecoverExplicitly)
                        .await?;
                    assert_eq!(completion.rows, 3);
                    (bytes, completion.transaction_status)
                };
                assert_eq!(bytes, b"1\n2\n3\n");
                assert_eq!(
                    status,
                    if in_transaction {
                        TransactionStatus::InTransaction
                    } else {
                        TransactionStatus::Idle
                    }
                );
                assert!(bytes.capacity() <= selected.max_bytes);
                if storage == AllocationPolicy::ReserveLimit {
                    assert_eq!(bytes.capacity(), selected.max_bytes);
                }
                assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
            }

            execute(connection, "TRUNCATE cpg_optimized_copy").await?;
            let packet = CopyDataBuffer::new(32)?;
            let pointer = packet.payload().as_ptr();
            let pool = Rc::new(RefCell::new(vec![packet]));
            let produced = Rc::new(Cell::new(0));
            let mut source = RecycledSource {
                pool: pool.clone(),
                produced: produced.clone(),
            };
            let recycled = Cell::new(0);
            let mut callback = |packet: CopyDataBuffer| {
                assert_eq!(packet.payload().as_ptr(), pointer);
                assert_eq!(packet.payload(), b"4\n");
                recycled.set(recycled.get() + 1);
                pool.borrow_mut().push(packet);
                Ok(())
            };
            let selected = CopyStreamLimits {
                max_chunks: 3,
                max_payload_bytes: 6,
            };
            let completion = if in_transaction {
                let mut transaction = connection.begin_transaction().await?;
                let completion = transaction
                    .copy_in(
                        "COPY cpg_optimized_copy FROM STDIN",
                        &[],
                        protocol,
                        compio_postgres::ExecutionScheduling::Uninterrupted,
                    )
                    .await?
                    .send_owned_stream_recycling(
                        &mut source,
                        selected,
                        &mut callback,
                        compio_postgres::OnError::DrainToReady,
                    )
                    .await?;
                transaction.rollback().await?;
                completion
            } else {
                connection
                    .copy_in(
                        "COPY cpg_optimized_copy FROM STDIN",
                        &[],
                        protocol,
                        compio_postgres::ExecutionScheduling::Uninterrupted,
                    )
                    .await?
                    .send_owned_stream_recycling(
                        &mut source,
                        selected,
                        &mut callback,
                        compio_postgres::OnError::DrainToReady,
                    )
                    .await?
            };
            assert_eq!(completion.rows, 3);
            assert_eq!(
                completion.transaction_status,
                if in_transaction {
                    TransactionStatus::InTransaction
                } else {
                    TransactionStatus::Idle
                }
            );
            assert_eq!(
                (produced.get(), recycled.get(), pool.borrow().len()),
                (3, 3, 1)
            );
            assert_eq!(connection.reuse_state(), ReuseState::ProtocolIdle);
        }
    }
    Ok(())
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_native_copy_batch_collect_and_recycle() {
    run(async {
        let mut connection = compio_postgres::expert::TcpSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn live_readiness_copy_batch_collect_and_recycle() {
    run(async {
        let mut connection = compio_postgres::expert::linux::TcpReadinessSession::connect(config())
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 SCRAM-PLUS 的 PostgreSQL 19 TLS 实例及 CPG_TLS_* 证书配置"]
fn live_tls_copy_batch_collect_and_recycle() {
    use compio_postgres::{TlsNegotiation, TlsVersions};
    run(async {
        let config = live::tls_config(
            limits(),
            tcp_options::TCP_OPTIONS,
            tls_options::fixture_tls_options(TlsNegotiation::SslRequest, TlsVersions::Tls12Or13),
        );
        let mut connection = compio_postgres::expert::TlsSession::connect(config)
            .await
            .unwrap();
        exercise(&mut connection).await.unwrap();
        connection.close_local().await.unwrap();
    });
}
