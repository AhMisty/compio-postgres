//! 真实 COPY 测试用 `CPG_*` 指定独立数据库，使用会话临时表与有限等待。
//! 常规测试对端按脚本交换协议消息，直接返回 AuthenticationOk。

#[path = "support/live.rs"]
mod live;

#[path = "support/peer.rs"]
mod peer;
use peer::{Peer, eof, frame, handshake, read_tag};

use std::{
    future::Future,
    io::{self, Write},
    net::TcpStream,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use compio_postgres::{
    CopyStreamLimits, Error, QueryLimits, ResultFormats, TcpConfig, TransactionStatus, WireLimits,
    expert::{CopyProtocol, TcpSession as TcpConnection},
    types::Format,
};
use futures_util::{Stream, stream};

const MODES: [CopyProtocol; 2] = [CopyProtocol::Extended, CopyProtocol::SimpleSingle];

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn owned_copy_packets_preserve_payload_for_replay_and_return_the_same_allocation() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .unwrap();
            execute(&mut session, "CREATE TEMP TABLE cpg_owned_values(v int4)").await;
            let mut copy = bounded(session.copy_in(
                "COPY cpg_owned_values FROM STDIN (FORMAT text)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .unwrap();
            let mut packet = compio_postgres::CopyDataBuffer::new(32).unwrap();
            packet.extend_from_slice(b"1\n2\n").unwrap();
            let pointer = packet.payload().as_ptr();
            let packet = bounded(copy.send_owned(packet)).await.unwrap();
            assert_eq!(packet.payload(), b"1\n2\n");
            assert_eq!(packet.payload().as_ptr(), pointer);
            let packet = bounded(copy.send_owned(packet)).await.unwrap();
            assert_eq!(packet.payload(), b"1\n2\n");
            assert_eq!(packet.payload().as_ptr(), pointer);
            assert_eq!(bounded(copy.finish()).await.unwrap().rows, 4);
            let mut query = session
                .query_simple_single(
                    "SELECT sum(v)::int8 FROM cpg_owned_values",
                    compio_postgres::QueryOptions {
                        limits: query_limits(),
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            {
                let row = query.next_row().await.unwrap().unwrap();
                assert_eq!(row.view().decoder().decode_next::<i64>().unwrap(), 6);
            }
            query.finish().await.unwrap();
            drop(query);
            session.close_local().await.unwrap();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn prepared_copy_reuses_named_input_and_output_across_transactions() {
    use compio_postgres::{ResultFormats, StatementLimits};
    let config = live_config();
    run(async {
        let mut session = bounded(TcpConnection::connect(config)).await.unwrap();
        session
            .configure_statements(StatementLimits {
                max_statements: 2,
                max_metadata_bytes: 32768,
            })
            .unwrap();
        execute(&mut session, "CREATE TEMP TABLE cpg_prepared_copy(v int4)").await;
        let input = session
            .prepare(
                "COPY cpg_prepared_copy FROM STDIN (FORMAT text)",
                &[],
                ResultFormats::All(Format::Text),
            )
            .await
            .unwrap();
        let output = session
            .prepare(
                "COPY (SELECT v FROM cpg_prepared_copy ORDER BY v) TO STDOUT (FORMAT text)",
                &[],
                ResultFormats::All(Format::Text),
            )
            .await
            .unwrap();
        for _ in 0..2 {
            let mut transaction = session.begin_transaction().await.unwrap();
            let mut copy = transaction
                .copy_in_prepared(
                    &input,
                    &[],
                    compio_postgres::ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let mut packet = compio_postgres::CopyDataBuffer::new(16).unwrap();
            packet.extend_from_slice(b"1\n2\n").unwrap();
            let _packet = copy.send_owned(packet).await.unwrap();
            assert_eq!(copy.finish().await.unwrap().rows, 2);
            transaction.commit().await.unwrap();
        }
        let (bytes, completion) = session
            .copy_out_prepared(
                &output,
                &[],
                compio_postgres::ExecutionScheduling::Uninterrupted,
            )
            .await
            .unwrap()
            .collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 64,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            )
            .await
            .unwrap();
        assert_eq!(bytes, b"1\n1\n2\n2\n");
        assert_eq!(completion.rows, 4);
        session.close_prepared(&input).await.unwrap();
        session.close_prepared(&output).await.unwrap();
        session.close_local().await.unwrap();
    });
}

fn live_config() -> TcpConfig {
    live::tcp_config(connection_limits(), peer::TCP_OPTIONS)
}

fn connection_limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 65_536,
        max_messages_per_request: 256,
    }
}

fn query_limits() -> QueryLimits {
    QueryLimits {
        max_rows: 32,
        max_result_bytes: 65_536,
        max_metadata_bytes: 16_384,
    }
}

fn run<T>(future: impl Future<Output = T>) -> T {
    compio::runtime::Runtime::new()
        .expect("COPY fixture runtime")
        .block_on(async {
            compio::time::timeout(Duration::from_secs(30), future)
                .await
                .expect("COPY fixture deadline")
        })
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    compio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("COPY operation deadline")
}

async fn execute(session: &mut TcpConnection, sql: &str) {
    let mut query = bounded(session.one_shot(
        sql,
        &[],
        ResultFormats::All(Format::Binary),
        compio_postgres::QueryOptions {
            limits: query_limits(),
            scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
        },
        compio_postgres::AbandonPolicy::RecoverExplicitly,
    ))
    .await
    .expect("execute fixture SQL");
    bounded(query.finish())
        .await
        .expect("finish fixture SQL at its boundary");
}

async fn assert_empty_table(session: &mut TcpConnection, protocol: CopyProtocol) {
    let copy = bounded(session.copy_out(
        "COPY (SELECT count(*) FROM cpg_copy_values) TO STDOUT (FORMAT text)",
        &[],
        protocol,
        compio_postgres::ExecutionScheduling::Uninterrupted,
    ))
    .await
    .expect("start count COPY");
    let (bytes, completion) = bounded(copy.collect_ready(
        compio_postgres::OwnedOutput {
            max_bytes: 64,
            allocation: compio_postgres::AllocationPolicy::ReserveLimit,
        },
        compio_postgres::OnError::RecoverExplicitly,
    ))
    .await
    .expect("collect count COPY");
    assert_eq!(bytes, b"0\n");
    assert_eq!(completion.rows, 1);
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn text_copy_handles_fragmented_input_null_and_zero_rows_in_both_protocols() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("SCRAM fixture connection");
            execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
            let mut copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN (FORMAT text)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start text input");
            assert_eq!(copy.info().format, Format::Text);
            assert_eq!(copy.info().len(), 1);
            assert_eq!(copy.info().formats(), &ResultFormats::All(Format::Text));
            for bytes in [b"1\n2".as_slice(), b"\n\\N".as_slice(), b"\n".as_slice()] {
                bounded(copy.send(bytes))
                    .await
                    .expect("send a partial text record");
            }
            let completion = bounded(copy.finish()).await.expect("finish text input");
            assert_eq!(
                (completion.rows, completion.transaction_status),
                (3, TransactionStatus::Idle)
            );
            let copy = bounded(session.copy_out("COPY (SELECT v FROM cpg_copy_values ORDER BY v NULLS LAST) TO STDOUT (FORMAT text)", &[], protocol, compio_postgres::ExecutionScheduling::Uninterrupted)).await.expect("start text output");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1024,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("collect text output");
            assert_eq!(bytes, b"1\n2\n\\N\n");
            assert_eq!(completion.rows, 3);
            let copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN (FORMAT text)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start empty input");
            assert_eq!(
                bounded(copy.finish())
                    .await
                    .expect("finish empty input")
                    .rows,
                0
            );
            let copy = bounded(session.copy_out(
                "COPY (SELECT v FROM cpg_copy_values WHERE false) TO STDOUT (FORMAT text)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start zero-row output");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 0,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("empty output needs no result bytes");
            assert!(bytes.is_empty());
            assert_eq!(completion.rows, 0);
            assert!(session.is_usable());
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn csv_stream_fragments_can_split_quoted_newlines_and_delimiters() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            execute(
                &mut session,
                "CREATE TEMP TABLE cpg_copy_values (id int4, value text)",
            )
            .await;
            let chunks = [
                b"1,\"li".to_vec(),
                b"ne\n".to_vec(),
                b"one\"\n2,\"a".to_vec(),
                b",b\"\n3,".to_vec(),
                b"\n".to_vec(),
            ];
            let stream_limits = CopyStreamLimits {
                max_chunks: chunks.len(),
                max_payload_bytes: chunks.iter().map(Vec::len).sum(),
            };
            let mut source = stream::iter(chunks.into_iter().map(Ok));
            let copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN (FORMAT csv)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start fragmented CSV input");
            let completion = bounded(copy.send_stream(
                &mut source,
                stream_limits,
                compio_postgres::OnError::DrainToReady,
            ))
            .await
            .expect("stream fragmented CSV input");
            assert_eq!(completion.rows, 3);
            let copy = bounded(session.copy_out(
                "COPY (SELECT id, value FROM cpg_copy_values ORDER BY id) TO STDOUT (FORMAT csv)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start CSV output");
            assert_eq!(copy.info().len(), 2);
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1024,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("collect CSV");
            assert_eq!(bytes, b"1,\"line\none\"\n2,\"a,b\"\n3,\n");
            assert_eq!(completion.rows, 3);
            assert!(session.is_usable());
            session.discard();
        }
    });
}

fn binary_file(rows: &[(i32, Option<i32>)]) -> Vec<u8> {
    // PostgreSQL 的二进制 COPY 头含签名、标志和扩展长度。每行的字段数与字段长度采用大端序，
    // 末尾以字段数 -1 标记数据结束。
    let mut bytes = b"PGCOPY\n\xff\r\n\0".to_vec();
    bytes.extend_from_slice(&0_i32.to_be_bytes());
    bytes.extend_from_slice(&0_i32.to_be_bytes());
    for (id, value) in rows {
        bytes.extend_from_slice(&2_i16.to_be_bytes());
        bytes.extend_from_slice(&4_i32.to_be_bytes());
        bytes.extend_from_slice(&id.to_be_bytes());
        match value {
            Some(value) => {
                bytes.extend_from_slice(&4_i32.to_be_bytes());
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            None => bytes.extend_from_slice(&(-1_i32).to_be_bytes()),
        }
    }
    bytes.extend_from_slice(&(-1_i16).to_be_bytes());
    bytes
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn binary_copy_preserves_int4_boundaries_null_and_empty_file() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            execute(
                &mut session,
                "CREATE TEMP TABLE cpg_copy_values (id int4, value int4)",
            )
            .await;
            let file = binary_file(&[
                (1, Some(i32::MIN)),
                (2, Some(i32::MAX)),
                (3, None),
                (4, Some(0)),
            ]);
            let mut copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN (FORMAT binary)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start binary input");
            assert_eq!(copy.info().format, Format::Binary);
            assert_eq!(copy.info().len(), 2);
            assert_eq!(copy.info().formats(), &ResultFormats::All(Format::Binary));
            for fragment in file.chunks(3) {
                bounded(copy.send(fragment))
                    .await
                    .expect("send binary fragments inside fields");
            }
            assert_eq!(
                bounded(copy.finish())
                    .await
                    .expect("finish binary input")
                    .rows,
                4
            );
            let copy = bounded(session.copy_out("COPY (SELECT id, value FROM cpg_copy_values ORDER BY id) TO STDOUT (FORMAT binary)", &[], protocol, compio_postgres::ExecutionScheduling::Uninterrupted)).await.expect("start binary output");
            let (actual, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1024,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("collect binary file");
            assert_eq!(actual, file);
            assert_eq!(completion.rows, 4);
            let copy = bounded(session.copy_out("COPY (SELECT id, value FROM cpg_copy_values WHERE false) TO STDOUT (FORMAT binary)", &[], protocol, compio_postgres::ExecutionScheduling::Uninterrupted)).await.expect("start empty binary output");
            let (actual, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 64,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("collect empty binary file");
            assert_eq!(actual, binary_file(&[]));
            assert_eq!(completion.rows, 0);
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn copy_fail_and_conversion_error_restore_the_real_autocommit_boundary() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
            let mut copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start input");
            bounded(copy.send(b"1\n")).await.expect("send initial row");
            assert!(
                matches!(bounded(copy.fail("deliberate COPY fixture failure")).await, Ok(compio_postgres::CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014")
            );
            assert!(session.is_usable());
            assert_empty_table(&mut session, protocol).await;
            let mut copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start invalid input");
            let failure = match bounded(copy.send(b"2\nnot-an-int\n")).await {
                Ok(()) => bounded(copy.finish()).await,
                Err(error) => {
                    drop(copy);
                    Err(error)
                }
            };
            assert!(matches!(failure, Err(Error::Database(error)) if error.code() == "22P02"));
            assert_eq!(session.transaction_status(), TransactionStatus::Idle);
            assert!(session.is_usable());
            assert_empty_table(&mut session, protocol).await;
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn explicit_transaction_copy_error_requires_an_explicit_rollback() {
    let config = live_config();
    run(async {
        let mut session = bounded(TcpConnection::connect(config))
            .await
            .expect("connect");
        execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
        let mut transaction = bounded(session.begin_transaction())
            .await
            .expect("begin explicit transaction");
        let mut copy = bounded(transaction.copy_in(
            "COPY cpg_copy_values FROM STDIN",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("COPY in transaction");
        let failure = match bounded(copy.send(b"invalid\n")).await {
            Ok(()) => bounded(copy.finish()).await,
            Err(error) => {
                drop(copy);
                Err(error)
            }
        };
        assert!(matches!(failure, Err(Error::Database(error)) if error.code() == "22P02"));
        assert_eq!(
            transaction.transaction_status(),
            TransactionStatus::FailedTransaction
        );
        assert!(matches!(
            bounded(transaction.one_shot(
                "SELECT 1",
                &[],
                ResultFormats::All(Format::Binary),
                compio_postgres::QueryOptions {
                    limits: query_limits(),
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly
            ))
            .await,
            Err(Error::Unsupported(_))
        ));
        let rolled_back = bounded(transaction.rollback())
            .await
            .expect("explicitly roll back failed transaction");
        assert_eq!(rolled_back.transaction_status, TransactionStatus::Idle);
        session.take_transaction_end();
        assert!(session.is_usable());
        assert_empty_table(&mut session, CopyProtocol::Extended).await;
        session.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn incorrect_copy_directions_permanently_discard_the_connection() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            assert!(matches!(
                bounded(session.copy_in(
                    "COPY (SELECT 1) TO STDOUT",
                    &[],
                    protocol,
                    compio_postgres::ExecutionScheduling::Uninterrupted
                ))
                .await,
                Err(Error::Unsupported(_))
            ));
            assert!(!session.is_usable());
            assert!(matches!(
                bounded(session.prepare(
                    "SELECT $1::int4",
                    &[compio_postgres::types::Oid::INT4],
                    compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
                ))
                .await,
                Err(Error::Broken)
            ));
            session.discard();
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
            assert!(matches!(
                bounded(session.copy_out(
                    "COPY cpg_copy_values FROM STDIN",
                    &[],
                    protocol,
                    compio_postgres::ExecutionScheduling::Uninterrupted
                ))
                .await,
                Err(Error::Unsupported(_))
            ));
            assert!(matches!(
                bounded(session.prepare(
                    "SELECT $1::int4",
                    &[compio_postgres::types::Oid::INT4],
                    compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
                ))
                .await,
                Err(Error::Broken)
            ));
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn json_force_array_is_complete_only_after_copy_completion() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            // 样本仅含整数、null 和无空白的字段名；删除格式化产生的 ASCII 空白不会改动字符串内容。
            let copy = bounded(session.copy_out("COPY (SELECT id, NULL::text AS note FROM (VALUES (1), (2)) AS val(id) ORDER BY id) TO STDOUT (FORMAT JSON, FORCE_ARRAY)", &[], protocol, compio_postgres::ExecutionScheduling::Uninterrupted)).await.expect("PG19 JSON array output");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 4096,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("complete JSON array and protocol boundary");
            let compact: Vec<_> = bytes
                .into_iter()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            assert_eq!(
                compact,
                b"[{\"id\":1,\"note\":null},{\"id\":2,\"note\":null}]"
            );
            assert_eq!(completion.rows, 2);
            let copy = bounded(session.copy_out(
                "COPY (SELECT 1 AS id) TO STDOUT (FORMAT JSON)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("PG19 per-row JSON output");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1024,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("finish per-row JSON");
            let compact: Vec<_> = bytes
                .into_iter()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            assert_eq!(compact, b"{\"id\":1}");
            assert_eq!(completion.rows, 1);
            let copy = bounded(session.copy_out(
                "COPY (SELECT 1 AS id WHERE false) TO STDOUT (FORMAT JSON, FORCE_ARRAY)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("empty JSON array output");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1024,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("finish empty array");
            let compact: Vec<_> = bytes
                .into_iter()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            assert_eq!(compact, b"[]");
            assert_eq!(completion.rows, 0);
            assert!(session.is_usable());
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn output_collection_limit_is_an_error_and_never_a_truncated_success() {
    let config = live_config();
    run(async {
        let mut session = bounded(TcpConnection::connect(config))
            .await
            .expect("connect");
        let copy = bounded(session.copy_out(
            "COPY (SELECT 'larger-than-one-byte') TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start output");
        assert!(matches!(
            bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 1,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit
                },
                compio_postgres::OnError::Discard
            ))
            .await,
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            bounded(session.prepare(
                "SELECT $1::int4",
                &[compio_postgres::types::Oid::INT4],
                compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
            ))
            .await,
            Err(Error::Broken)
        ));
        session.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn dropped_or_forgotten_input_scopes_require_explicit_abandonment() {
    let config = live_config();
    run(async {
        for forget in [false, true] {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
            let copy = bounded(session.copy_in(
                "COPY cpg_copy_values FROM STDIN",
                &[],
                CopyProtocol::Extended,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start abandoned input");
            if forget {
                std::mem::forget(copy);
            } else {
                drop(copy);
            }
            assert!(!session.is_usable());
            assert!(matches!(
                bounded(session.prepare(
                    "SELECT $1::int4",
                    &[compio_postgres::types::Oid::INT4],
                    compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
                ))
                .await,
                Err(Error::Busy)
            ));
            assert!(
                matches!(bounded(session.fail_abandoned_copy("explicitly abandon fixture input")).await, Ok(compio_postgres::CopyAbort::Aborted { diagnostic, .. }) if diagnostic.code() == "57014")
            );
            assert!(session.is_usable());
            assert_empty_table(&mut session, CopyProtocol::Extended).await;
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn forgotten_output_chunk_allows_reading_and_finishing() {
    let config = live_config();
    run(async {
        let mut session = bounded(TcpConnection::connect(config))
            .await
            .expect("connect");
        let mut copy = bounded(session.copy_out(
            "COPY (SELECT id FROM generate_series(1, 3) AS val(id)) TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start output");
        let chunk = bounded(copy.next_chunk())
            .await
            .expect("first chunk")
            .expect("one row");
        let mut bytes = chunk.bytes().to_vec();
        let _forgotten = std::mem::ManuallyDrop::new(chunk);
        while let Some(chunk) = bounded(copy.next_chunk()).await.expect("remaining output") {
            bytes.extend_from_slice(chunk.bytes());
        }
        assert_eq!(bytes, b"1\n2\n3\n");
        assert_eq!(
            bounded(copy.finish())
                .await
                .expect("finish after consuming the remaining output")
                .rows,
            3
        );
        assert!(session.is_usable());
        session.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn dropped_or_forgotten_output_scopes_do_not_clear_active_state() {
    let config = live_config();
    run(async {
        for forget in [false, true] {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            let copy = bounded(session.copy_out(
                "COPY (SELECT 1) TO STDOUT",
                &[],
                CopyProtocol::Extended,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start output scope");
            if forget {
                std::mem::forget(copy);
            } else {
                drop(copy);
            }
            assert!(!session.is_usable());
            assert!(matches!(
                bounded(session.prepare(
                    "SELECT $1::int4",
                    &[compio_postgres::types::Oid::INT4],
                    compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
                ))
                .await,
                Err(Error::Busy)
            ));
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn late_output_error_does_not_confirm_a_tentative_prefix() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            let copy = bounded(session.copy_out("COPY (SELECT 10 / (2 - id) AS value FROM generate_series(1, 3) AS val(id)) TO STDOUT (FORMAT text)", &[], protocol, compio_postgres::ExecutionScheduling::Uninterrupted)).await.expect("start output before executor error");
            assert!(
                matches!(bounded(copy.collect_ready(compio_postgres::OwnedOutput { max_bytes: 4096, allocation: compio_postgres::AllocationPolicy::ReserveLimit }, compio_postgres::OnError::RecoverExplicitly)).await, Err(Error::Database(error)) if error.code() == "22012")
            );
            assert!(session.is_usable());
            let copy = bounded(session.copy_out(
                "COPY (SELECT 42) TO STDOUT",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("new output after the error boundary");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 64,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("finish new output");
            assert_eq!(bytes, b"42\n");
            assert_eq!(completion.rows, 1);
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn source_failure_sends_copy_fail_but_preserves_the_local_error() {
    let config = live_config();
    run(async {
        let mut session = bounded(TcpConnection::connect(config))
            .await
            .expect("connect");
        execute(&mut session, "CREATE TEMP TABLE cpg_copy_values (v int4)").await;
        let mut source = stream::iter([
            Ok(b"1\n".to_vec()),
            Err(Error::InvalidInput("deliberate fixture source failure")),
        ]);
        let copy = bounded(session.copy_in(
            "COPY cpg_copy_values FROM STDIN",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .unwrap();
        assert!(matches!(
            bounded(copy.send_stream(
                &mut source,
                CopyStreamLimits {
                    max_chunks: 1,
                    max_payload_bytes: b"1\n".len(),
                },
                compio_postgres::OnError::DrainToReady,
            ))
            .await,
            Err(Error::InvalidInput("deliberate fixture source failure"))
        ));
        assert!(session.is_usable());
        assert_empty_table(&mut session, CopyProtocol::Extended).await;
        session.discard();
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn direct_output_finish_discards_more_rows_than_the_control_message_budget() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            let copy = bounded(session.copy_out(
                "COPY (SELECT id FROM generate_series(1, 1024) AS val(id)) TO STDOUT (FORMAT text)",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start large discard stream");
            let completion = bounded(copy.finish())
                .await
                .expect("discard all data frames without charging them as control messages");
            assert_eq!(completion.rows, 1024);
            assert_eq!(completion.transaction_status, TransactionStatus::Idle);
            assert!(session.is_usable());
            let copy = bounded(session.copy_out(
                "COPY (SELECT 42) TO STDOUT",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("next COPY after discard");
            let (bytes, completion) = bounded(copy.collect_ready(
                compio_postgres::OwnedOutput {
                    max_bytes: 64,
                    allocation: compio_postgres::AllocationPolicy::ReserveLimit,
                },
                compio_postgres::OnError::RecoverExplicitly,
            ))
            .await
            .expect("finish next COPY");
            assert_eq!(bytes, b"42\n");
            assert_eq!(completion.rows, 1);
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn output_eof_is_stable_until_the_explicit_completion_boundary() {
    let config = live_config();
    run(async {
        for protocol in MODES {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            let mut copy = bounded(session.copy_out(
                "COPY (SELECT 42) TO STDOUT",
                &[],
                protocol,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start output");
            let chunk = bounded(copy.next_chunk())
                .await
                .expect("first chunk")
                .expect("one row");
            assert_eq!(chunk.bytes(), b"42\n");

            for _ in 0..3 {
                assert!(
                    bounded(copy.next_chunk())
                        .await
                        .expect("stable CopyDone")
                        .is_none()
                );
            }
            assert_eq!(
                bounded(copy.finish())
                    .await
                    .expect("explicit final boundary")
                    .rows,
                1
            );
            assert!(session.is_usable());
            session.discard();
        }
    });
}

#[test]
#[ignore = "需要通过 CPG_* 配置独立的 PostgreSQL 19 SCRAM 实例"]
fn parent_drains_abandoned_output_with_a_forgotten_chunk() {
    let config = live_config();
    run(async {
        for forget_chunk in [false, true] {
            let mut session = bounded(TcpConnection::connect(config.clone()))
                .await
                .expect("connect");
            let mut copy = bounded(session.copy_out(
                "COPY (SELECT id FROM generate_series(1, 3) AS val(id)) TO STDOUT",
                &[],
                CopyProtocol::Extended,
                compio_postgres::ExecutionScheduling::Uninterrupted,
            ))
            .await
            .expect("start abandoned output");
            let chunk = bounded(copy.next_chunk())
                .await
                .expect("first chunk")
                .expect("some output");
            if forget_chunk {
                let _forgotten = std::mem::ManuallyDrop::new(chunk);
            }
            drop(copy);
            assert!(!session.is_usable());
            let completion = bounded(session.finish_abandoned_copy_out())
                .await
                .expect("explicit parent-authorized discard and completion");
            assert_eq!(completion.rows, 3);
            assert!(session.is_usable());
            session.discard();
        }
    });
}

fn copy_peer(script: impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static) -> Peer {
    Peer::start_with(
        script,
        peer::prepared::DEADLINE,
        peer::IO_DEADLINE,
        connection_limits().max_request_len,
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn request(socket: &mut TcpStream, tags: &[u8]) -> io::Result<()> {
    for expected in tags {
        let body = read_tag(socket, *expected, connection_limits().max_request_len)?;
        if b"ScH".contains(expected) && !body.is_empty() {
            return Err(invalid("control body must be empty"));
        }
    }
    Ok(())
}
fn copy_response(out: bool, extended: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if extended {
        bytes.extend(frame(b'1', &[]));
        bytes.extend(frame(b'2', &[]));
    }
    bytes.extend(frame(if out { b'H' } else { b'G' }, &[0, 0, 1, 0, 0]));
    bytes
}
fn server_error() -> Vec<u8> {
    frame(b'E', b"SERROR\0C22P02\0MCOPY fixture error\0\0")
}
#[test]
fn simple_copy_out_does_not_append_sync() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"Q")?;
        let mut bytes = copy_response(true, false);
        bytes.extend(frame(b'd', b"1\n"));
        bytes.extend(frame(b'c', &[]));
        bytes.extend(frame(b'C', b"COPY 1\0"));
        bytes.extend(frame(b'Z', b"I"));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let copy = bounded(session.copy_out(
            "COPY (SELECT 1) TO STDOUT",
            &[],
            CopyProtocol::SimpleSingle,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start COPY");
        let (bytes, completion) = bounded(copy.collect_ready(
            compio_postgres::OwnedOutput {
                max_bytes: 64,
                allocation: compio_postgres::AllocationPolicy::ReserveLimit,
            },
            compio_postgres::OnError::RecoverExplicitly,
        ))
        .await
        .expect("finish COPY");
        assert_eq!(bytes, b"1\n");
        assert_eq!(completion.rows, 1);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn extended_copy_out_sends_exactly_one_sync_before_receiving_output() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBES")?;
        let mut bytes = copy_response(true, true);
        bytes.extend(frame(b'd', b"1\n"));
        bytes.extend(frame(b'c', &[]));
        bytes.extend(frame(b'C', b"COPY 1\0"));
        bytes.extend(frame(b'A', b"\0\0\0\x07copy_events\0ready\0"));
        bytes.extend(frame(b'Z', b"I"));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let copy = bounded(session.copy_out(
            "COPY (SELECT 1) TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start COPY");
        let (bytes, completion) = bounded(copy.collect_ready(
            compio_postgres::OwnedOutput {
                max_bytes: 64,
                allocation: compio_postgres::AllocationPolicy::ReserveLimit,
            },
            compio_postgres::OnError::RecoverExplicitly,
        ))
        .await
        .expect("finish COPY");
        assert_eq!(bytes, b"1\n");
        assert_eq!(completion.rows, 1);
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_wrong_copy_direction_discards_the_connection_without_a_second_sync() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBES")?;
        socket.write_all(&copy_response(false, true))?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        assert!(matches!(
            bounded(session.copy_out(
                "COPY fixture FROM STDIN",
                &[],
                CopyProtocol::Extended,
                compio_postgres::ExecutionScheduling::Uninterrupted
            ))
            .await,
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            bounded(session.prepare(
                "SELECT $1::int4",
                &[compio_postgres::types::Oid::INT4],
                compio_postgres::ResultFormats::All(compio_postgres::types::Format::Binary)
            ))
            .await,
            Err(Error::Broken)
        ));
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn command_complete_before_copy_done_is_a_protocol_failure() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBES")?;
        let mut bytes = copy_response(true, true);
        bytes.extend(frame(b'C', b"COPY 1\0"));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let copy = bounded(session.copy_out(
            "COPY (SELECT 1) TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start COPY");
        assert!(matches!(
            bounded(copy.finish()).await,
            Err(Error::Protocol(_))
        ));
        assert!(!session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn a_late_copy_error_never_returns_a_successful_partial_collect() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBES")?;
        let mut bytes = copy_response(true, true);
        bytes.extend(frame(b'd', b"tentative-prefix\n"));
        bytes.extend(server_error());
        bytes.extend(frame(b'Z', b"I"));
        socket.write_all(&bytes)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let copy = bounded(session.copy_out(
            "COPY (SELECT 1) TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start COPY");
        assert!(
            matches!(bounded(copy.collect_ready(compio_postgres::OwnedOutput { max_bytes: 1024, allocation: compio_postgres::AllocationPolicy::ReserveLimit }, compio_postgres::OnError::RecoverExplicitly)).await, Err(Error::Database(error)) if error.code() == "22P02")
        );
        assert!(session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn extended_copy_in_waits_for_copy_done_before_its_sync() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBEH")?;
        socket.write_all(&copy_response(false, true))?;
        request(socket, b"dcS")?;
        let mut response = frame(b'C', b"COPY 1\0");
        response.extend(frame(b'Z', b"I"));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let mut copy = bounded(session.copy_in(
            "COPY fixture FROM STDIN",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .expect("start COPY");
        bounded(copy.send(b"1\n")).await.expect("send COPY data");
        let completion = bounded(copy.finish()).await.expect("finish COPY");
        assert_eq!(completion.rows, 1);
        assert!(session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn extended_copy_in_startup_error_sends_only_the_missing_sync() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBEH")?;
        socket.write_all(&server_error())?;
        request(socket, b"S")?;
        socket.write_all(&frame(b'Z', b"I"))?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let result = bounded(session.copy_in(
            "COPY missing FROM STDIN",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await;
        assert!(matches!(result, Err(Error::Database(error)) if error.code() == "22P02"));
        assert!(session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn extended_copy_out_startup_error_drains_to_the_already_admitted_sync() {
    let peer = copy_peer(|socket| {
        handshake(socket)?;
        request(socket, b"PBES")?;
        let mut response = server_error();
        response.extend(frame(b'Z', b"I"));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let result = bounded(session.copy_out(
            "COPY missing TO STDOUT",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await;
        assert!(matches!(result, Err(Error::Database(error)) if error.code() == "22P02"));
        assert!(session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}

struct OneThenPending {
    first: Option<Vec<u8>>,
    pending: Arc<AtomicBool>,
}
impl Stream for OneThenPending {
    type Item = Result<Vec<u8>, Error>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(bytes) = this.first.take() {
            Poll::Ready(Some(Ok(bytes)))
        } else {
            this.pending.store(true, Ordering::Relaxed);
            Poll::Pending
        }
    }
}

#[test]
fn server_input_error_progresses_while_the_input_source_is_pending() {
    let pending = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&pending);
    let peer = copy_peer(move |socket| {
        handshake(socket)?;
        request(socket, b"PBEH")?;
        socket.write_all(&copy_response(false, true))?;
        request(socket, b"d")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !observed.load(Ordering::Relaxed) {
            if Instant::now() >= deadline {
                return Err(invalid("source did not become Pending"));
            }
            thread::sleep(Duration::from_millis(1));
        }
        socket.write_all(&server_error())?;
        request(socket, b"S")?;
        socket.write_all(&frame(b'Z', b"I"))?;
        eof(socket)
    });
    run(async {
        let mut session = bounded(TcpConnection::connect(
            peer.config_with_limits(connection_limits()),
        ))
        .await
        .expect("mock connection");
        let mut source = OneThenPending {
            first: Some(b"invalid\n".to_vec()),
            pending,
        };
        let copy = bounded(session.copy_in(
            "COPY fixture FROM STDIN",
            &[],
            CopyProtocol::Extended,
            compio_postgres::ExecutionScheduling::Uninterrupted,
        ))
        .await
        .unwrap();
        assert!(matches!(
            bounded(copy.send_stream(
                &mut source,
                CopyStreamLimits {
                    max_chunks: 1,
                    max_payload_bytes: b"invalid\n".len(),
                },
                compio_postgres::OnError::DrainToReady,
            )).await,
            Err(Error::Database(error)) if error.code() == "22P02"
        ));
        assert!(source.pending.load(Ordering::Relaxed));
        assert!(session.is_usable());
        session.close_local().await.unwrap();
    });
    peer.finish();
}
