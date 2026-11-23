//! 单查询和独立 Sync 批次的标量类型与行数校验。

#[path = "support/peer.rs"]
mod peer;

use compio_postgres::{
    BatchOptions, ClientOptions, DatabaseError, Error, ExecutionOptions, ExecutionScheduling,
    OnError, PreparedStatementStorage, QueryLimits, QueryOptions, ResultFormats, ReuseState,
    Statement, StatementLimits, TcpConfig, TcpConnection,
    types::{CodecError, Decode, Format, Oid, Parameter, RawValue},
};
use peer::{Peer, eof, execution, frame, handshake, prepare, ready, result, row, run, sql_error};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::mpsc,
    task::Poll,
    time::Duration,
};

const POLICY: OnError = OnError::RecoverExplicitly;
const BINARY: ResultFormats = ResultFormats::All(Format::Binary);
const SCHEDULING: ExecutionScheduling = ExecutionScheduling::Uninterrupted;
const QUERY: QueryLimits = QueryLimits {
    max_rows: 8,
    max_result_bytes: 4096,
    max_metadata_bytes: 4096,
};
const BATCH: BatchOptions = BatchOptions {
    member_limits: QUERY,
    max_requests: 3,
    max_inflight: 3,
    max_queued_request_bytes: 4096,
    max_diagnostic_bytes: 4096,
    scheduling: SCHEDULING,
};

fn options(config: TcpConfig) -> ClientOptions<TcpConfig> {
    ClientOptions::new(
        config,
        ExecutionOptions {
            query: QueryOptions {
                limits: QUERY,
                scheduling: SCHEDULING,
            },
            batch: Some(BATCH),
        },
        StatementLimits {
            max_statements: 4,
            max_metadata_bytes: 8192,
        },
    )
}

async fn prepared(client: &mut TcpConnection, sql: &str, parameters: &[Oid]) -> Statement {
    client
        .prepare(sql, parameters, PreparedStatementStorage::Named, BINARY)
        .await
        .unwrap()
}

fn prefix<V>(value: V) -> Vec<Result<V, DatabaseError>> {
    let mut output = Vec::with_capacity(BATCH.max_requests + 1);
    output.push(Ok(value));
    output
}

fn scalar_rows(rows: &[Option<i32>]) -> Vec<u8> {
    let mut response = frame(b'2', &[]);
    for &value in rows {
        let bytes = value.map(i32::to_be_bytes);
        response.extend(row(&[bytes.as_ref().map(<[u8; 4]>::as_slice)]));
    }
    let command = format!("SELECT {}\0", rows.len());
    response.extend(frame(b'C', command.as_bytes()));
    response.extend(ready(b'I'));
    response
}

#[test]
fn required_scalar_batch_keeps_null_and_member_sql_error_after_tentative_row() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        for _ in 0..3 {
            execution(socket, &statement)?;
        }
        let mut response = result(23, b'I');
        response.extend(frame(b'2', &[]));
        response.extend(row(&[Some(&17_i32.to_be_bytes())]));
        response.extend(sql_error("22012", b'I'));
        response.extend(scalar_rows(&[None]));
        socket.write_all(&response)?;
        execution(socket, &statement)?;
        socket.write_all(&result(77, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        let statement = prepared(&mut client, "SELECT $1::int4", &[Oid::INT4]).await;
        let mut output = prefix(Some(-1));
        let capacity = output.capacity();
        let progress = client
            .streaming_batch(
                [23, 0, 1]
                    .into_iter()
                    .map(|n| statement.bind_one(Parameter::int4(n))),
            )
            .with_options(BatchOptions {
                max_requests: 8,
                ..BATCH
            })
            .collect_one_into_ready(&mut output, POLICY)
            .await
            .unwrap();
        assert_eq!((progress.confirmed, progress.sql_errors), (3, 1));
        assert_eq!(progress.rows_delivered, 2);
        assert_eq!(output.capacity(), capacity);
        assert_eq!(output.len(), 4);
        assert_eq!(output[0].as_ref().unwrap(), &Some(-1));
        assert_eq!(output[1].as_ref().unwrap(), &Some(23));
        assert_eq!(output[2].as_ref().unwrap_err().code(), "22012");
        assert_eq!(output[3].as_ref().unwrap(), &None);
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(
            client
                .query(&statement, &[Parameter::int4(77)])
                .one::<i32>(POLICY)
                .await
                .unwrap(),
            77
        );
        client.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn optional_scalar_batch_distinguishes_missing_row_sql_null_and_value() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[23], &[23])?;
        for _ in 0..3 {
            execution(socket, &statement)?;
        }
        let mut response = scalar_rows(&[]);
        response.extend(scalar_rows(&[None]));
        response.extend(result(23, b'I'));
        socket.write_all(&response)?;
        eof(socket)
    });
    run(async {
        let mut client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        let statement = prepared(&mut client, "SELECT $1::int4", &[Oid::INT4]).await;
        let mut output = prefix(Some(Some(-1)));
        let progress = client
            .streaming_batch(
                [-1, 0, 23]
                    .into_iter()
                    .map(|n| statement.bind_one(Parameter::int4(n))),
            )
            .collect_zero_or_one_into_ready(&mut output, POLICY)
            .await
            .unwrap();
        assert_eq!((progress.confirmed, progress.rows_delivered), (3, 2));
        assert_eq!(
            output.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            [Some(Some(-1)), None, Some(None), Some(Some(23))]
        );
        client.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn scalar_preflight_rejects_inadequate_output_and_wide_layout_before_sending() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        prepare(socket, &[], &[23, 23])?;
        let good = prepare(socket, &[], &[23])?;
        execution(socket, &good)?;
        socket.write_all(&result(77, b'I'))?;
        eof(socket)
    });
    run(async {
        let mut client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        let wide = prepared(&mut client, "SELECT 1::int4, 2::int4", &[]).await;
        let good = prepared(&mut client, "SELECT 77::int4", &[]).await;
        let mut output = prefix(-1);
        let pulls = Cell::new(0);
        let source = || {
            std::iter::from_fn(|| {
                pulls.set(pulls.get() + 1);
                Some(good.bind(&[]))
            })
        };

        let idle = client
            .streaming_batch(source().take(0))
            .with_options(BatchOptions {
                max_requests: 0,
                max_inflight: 0,
                ..BATCH
            })
            .collect_one_into_ready(&mut output, POLICY)
            .await
            .unwrap();
        assert_eq!((idle.consumed, idle.admitted, pulls.get()), (0, 0, 0));
        let too_many = output.capacity() - output.len() + 1;
        let failure = client
            .streaming_batch(source())
            .with_options(BatchOptions {
                max_requests: too_many,
                ..BATCH
            })
            .collect_one_into_ready(&mut output, POLICY)
            .await
            .unwrap_err();
        assert!(matches!(failure.source, Error::Limit(_)));
        assert_eq!(
            (
                failure.progress.consumed,
                failure.progress.admitted,
                pulls.get()
            ),
            (0, 0, 0)
        );
        let failure = client
            .streaming_batch([wide.bind(&[])])
            .collect_one_into_ready(&mut output, OnError::Discard)
            .await
            .unwrap_err();
        assert!(matches!(failure.source, Error::InvalidInput(_)));
        assert_eq!(
            (failure.progress.consumed, failure.progress.admitted),
            (1, 0)
        );
        assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
        assert_eq!(output.len(), 1);
        assert_eq!(*output[0].as_ref().unwrap(), -1);
        assert_eq!(
            client.query(&good, &[]).one::<i32>(POLICY).await.unwrap(),
            77
        );
        client.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn scalar_cardinality_error_and_malformed_extra_row_keep_distinct_dispositions() {
    for batched in [false, true] {
        for (malformed, policy) in [
            (false, OnError::RecoverExplicitly),
            (false, OnError::DrainToReady),
            (false, OnError::Discard),
            (true, OnError::RecoverExplicitly),
        ] {
            let reusable = !malformed && policy != OnError::Discard;
            let peer = Peer::start(move |socket| {
                handshake(socket)?;
                let statement = prepare(socket, &[], &[23])?;
                execution(socket, &statement)?;
                if malformed {
                    let mut response = frame(b'2', &[]);
                    response.extend(row(&[Some(&41_i32.to_be_bytes())]));
                    // 第二个 DataRow 把非 NULL 字段长度编码为非法负数。
                    response.extend(frame(b'D', &[0, 1, 255, 255, 255, 254]));
                    socket.write_all(&response)?;
                } else {
                    socket.write_all(&scalar_rows(&[Some(41), Some(42)]))?;
                }
                if reusable {
                    execution(socket, &statement)?;
                    socket.write_all(&result(77, b'I'))?;
                }
                eof(socket)
            });
            run(async {
                let mut client = TcpConnection::connect(options(peer.config()))
                    .await
                    .unwrap();
                let statement = prepared(&mut client, "SELECT 1::int4", &[]).await;
                let error = if batched {
                    let mut output = prefix(-1);
                    let failure = client
                        .streaming_batch([statement.bind(&[])])
                        .collect_one_into_ready(&mut output, policy)
                        .await
                        .unwrap_err();
                    assert_eq!(output.len(), 1);
                    assert_eq!(*output[0].as_ref().unwrap(), -1);
                    failure.source
                } else {
                    client
                        .query(&statement, &[])
                        .one::<i32>(policy)
                        .await
                        .unwrap_err()
                };
                if malformed {
                    assert!(
                        matches!(error, Error::Protocol(_) | Error::Codec(_)),
                        "{error:?}"
                    );
                } else {
                    assert!(matches!(error, Error::InvalidInput(_)), "{error:?}");
                }
                let expected = match (reusable, policy) {
                    (false, _) => ReuseState::DiscardOnly,
                    (true, OnError::RecoverExplicitly) => ReuseState::NeedsRecovery,
                    (true, _) => ReuseState::ProtocolIdle,
                };
                assert_eq!(client.reuse_state(), expected);
                if reusable {
                    client.recover_to_ready().await.unwrap();
                    assert_eq!(
                        client
                            .query(&statement, &[])
                            .one::<i32>(POLICY)
                            .await
                            .unwrap(),
                        77
                    );
                    client.close_local().await.unwrap();
                } else {
                    client.discard();
                }
            });
            peer.finish();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Foreign(i32);

impl<'a> Decode<'a> for Foreign {
    fn accepts(oid: Oid, format: Format) -> bool {
        <i32 as Decode>::accepts(oid, format)
    }

    fn decode(raw: RawValue<'a>) -> Result<Self, CodecError> {
        let value = raw.decode::<i32>()?;
        if value == 13 {
            return Err(CodecError::Invalid("application rejects this scalar"));
        }
        Ok(Self(value))
    }
}

#[test]
fn foreign_decode_errors_are_local_on_both_paths() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        for value in [13, 41, 13, 77] {
            execution(socket, &statement)?;
            socket.write_all(&result(value, b'I'))?;
        }
        eof(socket)
    });
    run(async {
        let mut client = TcpConnection::connect(options(peer.config()))
            .await
            .unwrap();
        let statement = prepared(&mut client, "SELECT 1::int4", &[]).await;
        let error = client
            .query(&statement, &[])
            .one::<Foreign>(POLICY)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Codec(error) if matches!(*error, CodecError::Invalid("application rejects this scalar")))
        );
        assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
        client.recover_to_ready().await.unwrap();
        let mut output = prefix(Foreign(-1));
        let pulls = Cell::new(0);
        let requests = [
            statement.bind(&[]),
            statement.bind(&[]),
            statement.bind(&[]),
        ]
        .into_iter()
        .inspect(|_| pulls.set(pulls.get() + 1));
        let failure = client
            .streaming_batch(requests)
            .with_options(BatchOptions {
                max_inflight: 1,
                ..BATCH
            })
            .collect_one_into_ready(&mut output, POLICY)
            .await
            .unwrap_err();
        assert!(
            matches!(failure.source, Error::Codec(error) if matches!(*error, CodecError::Invalid("application rejects this scalar")))
        );
        assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
        assert_eq!(
            (
                pulls.get(),
                failure.progress.admitted,
                failure.progress.confirmed
            ),
            (2, 2, 1)
        );
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].as_ref().unwrap(), &Foreign(-1));
        client.recover_to_ready().await.unwrap();
        assert_eq!(
            client
                .query(&statement, &[])
                .one::<Foreign>(POLICY)
                .await
                .unwrap(),
            Foreign(77)
        );
        client.close_local().await.unwrap();
    });
    peer.finish();
}

#[test]
fn dropping_scalar_batch_rolls_back_a_confirmed_prefix_and_preserves_recovery() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    // 仅本用例构造该类型：放弃批次必须析构暂存值，同时保留调用方已有的值。
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug)]
    struct Tracked(i32);

    impl<'a> Decode<'a> for Tracked {
        fn accepts(oid: Oid, format: Format) -> bool {
            i32::accepts(oid, format)
        }

        fn decode(raw: RawValue<'a>) -> Result<Self, CodecError> {
            raw.decode::<i32>().map(Self)
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    let first_staged = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&first_staged);
    let (resume, receive) = mpsc::channel();
    let peer = Peer::start(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        execution(socket, &statement)?;
        execution(socket, &statement)?;
        let mut response = result(41, b'I');
        // NOTICE 在首个成员的 Ready 之后，此时标量已经进入暂存向量。
        response.extend(frame(
            b'N',
            b"SNOTICE\0VNOTICE\0C00000\0Mfirst scalar staged\0\0",
        ));
        socket.write_all(&response)?;
        receive
            .recv_timeout(Duration::from_secs(3))
            .map_err(io::Error::other)?;
        socket.write_all(&result(42, b'I'))?;
        execution(socket, &statement)?;
        socket.write_all(&result(77, b'I'))?;
        eof(socket)
    });
    run(async {
        let config = peer.config().notice_handler(move |notice| {
            assert_eq!(notice.message, "first scalar staged");
            marker.store(true, Ordering::Release);
        });
        let mut client = TcpConnection::connect(options(config)).await.unwrap();
        let statement = prepared(&mut client, "SELECT 1::int4", &[]).await;
        let mut output = prefix(Tracked(-1));
        let capacity = output.capacity();
        let mut pending = Box::pin(
            client
                .streaming_batch([statement.bind(&[]), statement.bind(&[])])
                .collect_one_into_ready(&mut output, POLICY),
        );
        poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            if first_staged.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!(DROPS.load(Ordering::Relaxed), 0);
        drop(pending);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].as_ref().unwrap().0, -1);
        assert_eq!(output.capacity(), capacity);
        assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
        resume.send(()).unwrap();
        client.recover_to_ready().await.unwrap();
        assert_eq!(
            client
                .query(&statement, &[])
                .one::<Foreign>(POLICY)
                .await
                .unwrap(),
            Foreign(77)
        );
        client.close_local().await.unwrap();
    });
    peer.finish();
}
