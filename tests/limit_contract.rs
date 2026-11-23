//! 验证普通查询与批处理在协议交互和连接建立前执行的限额检查。

#[path = "support/peer.rs"]
mod peer;
#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

use compio_postgres::{
    AbandonPolicy, AllocationPolicy, AuthenticationPolicy, BatchControl, BatchError,
    BatchErrorOrigin as Origin, BatchEvent, BatchOptions, BatchProgress, ClientOptions,
    DatabaseError, Error, ExecutionOptions, ExecutionScheduling, OnError, OwnedOutput,
    PreparedStatementStorage, QueryLimits, QueryOptions, ResultFormats, ReuseState, Statement,
    StatementLimits, TcpConfig, TcpConnection, WireLimits, types::Format,
};
use peer::{Peer, TCP_OPTIONS, eof, execution, frame, handshake, prepare, ready, result, row, run};
use std::{
    cell::Cell,
    future::Future,
    io::Write,
    mem::size_of,
    ops::ControlFlow,
    pin::pin,
    task::{Context, Poll, Waker},
};

const NOTICE: &[u8] = b"SNOTICE\0C00000\0Mfixture notice\0\0";
const DIAGNOSTIC: &str = "fixture diagnostic limit";
const SQLSTATE: &str = "22012";
const FATAL_STATE: &str = "57P01";
const WIRE: WireLimits = WireLimits {
    receive_capacity: 8192,
    max_frame_len: 8191,
    max_request_len: 8192,
    max_messages_per_request: 128,
};
const LIMITS: QueryLimits = QueryLimits {
    max_rows: 8,
    max_result_bytes: 4096,
    max_metadata_bytes: 4096,
};
const BATCH: BatchOptions = BatchOptions {
    member_limits: LIMITS,
    max_requests: 2,
    max_inflight: 2,
    max_queued_request_bytes: 256,
    max_diagnostic_bytes: 4096,
    scheduling: ExecutionScheduling::Uninterrupted,
};
const OUTPUT: OwnedOutput = OwnedOutput {
    max_bytes: 8192,
    allocation: AllocationPolicy::Grow,
};

fn options<C>(config: C, batch: BatchOptions) -> ClientOptions<C> {
    ClientOptions::new(
        config,
        ExecutionOptions {
            query: QueryOptions {
                limits: LIMITS,
                scheduling: ExecutionScheduling::Uninterrupted,
            },
            batch: Some(batch),
        },
        StatementLimits {
            max_statements: 2,
            max_metadata_bytes: 8192,
        },
    )
}

async fn prepared(peer: &Peer) -> (TcpConnection, Statement) {
    let mut client = TcpConnection::connect(options(peer.config_with_limits(WIRE), BATCH))
        .await
        .unwrap();
    let statement = client
        .prepare(
            "SELECT 73::int4",
            &[],
            PreparedStatementStorage::Named,
            ResultFormats::All(Format::Binary),
        )
        .await
        .unwrap();
    (client, statement)
}

async fn recover_and_reuse(mut client: TcpConnection, statement: &Statement) {
    client.recover_to_ready().await.unwrap();
    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
    assert_eq!(
        client
            .query(statement, &[])
            .one::<i32>(OnError::RecoverExplicitly)
            .await
            .unwrap(),
        73
    );
    client.close_local().await.unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchMode {
    Collect,
    VisitReady,
    VisitProvisional,
}

const MODES: [BatchMode; 3] = [
    BatchMode::Collect,
    BatchMode::VisitReady,
    BatchMode::VisitProvisional,
];

#[derive(Debug, Default, PartialEq, Eq)]
struct Seen {
    ready: usize,
    rows: usize,
    commands: usize,
    sql_errors: usize,
}

impl Seen {
    fn ready(&mut self, error: Option<&DatabaseError>) {
        self.ready += 1;
        if let Some(error) = error {
            assert_eq!(error.code(), SQLSTATE);
            assert_eq!(error.severity(), "ERROR");
            assert_eq!(error.message(), DIAGNOSTIC);
            self.sql_errors += 1;
        }
    }
}

#[derive(Debug)]
struct Failure {
    progress: BatchProgress,
    source: Error,
    origin: Origin,
    reuse: ReuseState,
    cleanup: Option<Box<Error>>,
}

impl<T> From<BatchError<T>> for Failure {
    fn from(error: BatchError<T>) -> Self {
        Self {
            progress: error.progress,
            source: error.source,
            origin: error.origin,
            reuse: error.reuse_state,
            cleanup: error.cleanup_error,
        }
    }
}

async fn execute_batch<'q>(
    client: &mut TcpConnection,
    source: impl Iterator<Item = compio_postgres::BatchRequest<'q>>,
    options: BatchOptions,
    mode: BatchMode,
    on_error: OnError,
    seen: &mut Seen,
) -> Result<BatchProgress, Failure> {
    let request = client.streaming_batch(source).with_options(options);
    match mode {
        BatchMode::Collect => {
            let report = request
                .collect_ready(OUTPUT, on_error)
                .await
                .inspect_err(|error| assert!(error.completed.is_empty()))?;
            for result in report.results {
                match result {
                    Ok(result) => {
                        seen.rows += result.rows.len();
                        seen.ready(None);
                    }
                    Err(error) => seen.ready(Some(&error)),
                }
            }
            Ok(report.progress)
        }
        BatchMode::VisitReady => Ok(request
            .visit_ready(OUTPUT, on_error, |event| {
                assert_eq!(event.index, 0);
                match event.outcome {
                    Ok(result) => {
                        seen.rows += result.rows.len();
                        seen.ready(None);
                    }
                    Err(error) => seen.ready(Some(error)),
                }
                Ok(ControlFlow::Continue(()))
            })
            .await?),
        BatchMode::VisitProvisional => Ok(request
            .visit_provisional(AbandonPolicy::RecoverExplicitly, |event| {
                match event {
                    BatchEvent::Row { index, .. } => {
                        assert_eq!(index, 0);
                        seen.rows += 1;
                    }
                    BatchEvent::Command { index, .. } => {
                        assert_eq!(index, 0);
                        seen.commands += 1;
                    }
                    BatchEvent::Ready { index, outcome, .. } => {
                        assert_eq!(index, 0);
                        seen.ready(outcome.err());
                    }
                }
                Ok(BatchControl::Continue)
            })
            .await?),
    }
}

fn control_peer(notices: usize) -> Peer {
    Peer::start(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        execution(socket, &statement)?;
        let notice = frame(b'N', NOTICE);
        let mut response = frame(b'2', &[]);
        for _ in 0..notices / 2 {
            response.extend_from_slice(&notice);
        }
        response.extend(row(&[Some(&73_i32.to_be_bytes())]));
        for _ in notices / 2..notices {
            response.extend_from_slice(&notice);
        }
        response.extend(frame(b'C', b"SELECT 1\0"));
        response.extend(ready(b'I'));
        socket.write_all(&response)?;
        execution(socket, &statement)?;
        socket.write_all(&result(73, b'I'))?;
        eof(socket)
    })
}

#[test]
fn query_and_batch_count_non_rows_across_data_rows_and_recover_the_boundary() {
    // 控制消息包括 BindComplete、各条 Notice、CommandComplete 和 Ready。
    // 后两种情况分别在 Ready 和 CommandComplete 处超过限额。
    for notices in [125, 126, 127] {
        let success = notices == 125;
        let peer = control_peer(notices);
        run(async {
            let (mut client, statement) = prepared(&peer).await;
            let outcome = client
                .query(&statement, &[])
                .one::<i32>(OnError::RecoverExplicitly)
                .await;
            if success {
                assert_eq!(outcome.unwrap(), 73);
                assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
            } else {
                assert!(matches!(outcome, Err(Error::Limit(_))));
                assert_eq!(client.reuse_state(), ReuseState::NeedsRecovery);
            }
            recover_and_reuse(client, &statement).await;
        });
        peer.finish();

        for mode in MODES {
            let peer = control_peer(notices);
            run(async {
                let (mut client, statement) = prepared(&peer).await;
                let mut seen = Seen::default();
                let outcome = execute_batch(
                    &mut client,
                    std::iter::once(statement.bind(&[])),
                    BATCH,
                    mode,
                    OnError::RecoverExplicitly,
                    &mut seen,
                )
                .await;
                if success {
                    let progress = outcome.unwrap();
                    assert_eq!((progress.admitted, progress.confirmed), (1, 1));
                    assert_eq!((seen.rows, seen.ready), (1, 1));
                    assert_eq!(client.reuse_state(), ReuseState::ProtocolIdle);
                } else {
                    let failure = outcome.unwrap_err();
                    assert!(matches!(failure.source, Error::Limit(_)), "{mode:?}");
                    assert_eq!(failure.reuse, ReuseState::NeedsRecovery);
                    assert_eq!(
                        (failure.progress.admitted, failure.progress.confirmed),
                        (1, 0)
                    );
                    assert_eq!(seen.ready, 0);
                    if mode == BatchMode::VisitProvisional {
                        assert_eq!(seen.rows, 1);
                        assert_eq!(seen.commands, usize::from(notices == 126));
                    } else {
                        assert_eq!(seen, Seen::default());
                    }
                }
                recover_and_reuse(client, &statement).await;
            });
            peer.finish();
        }
    }
}

fn diagnostic(severity: &str, sqlstate: &str, message: &str, detail: &str) -> Vec<u8> {
    frame(
        b'E',
        format!("Sfixture severity\0V{severity}\0C{sqlstate}\0M{message}\0D{detail}\0\0")
            .as_bytes(),
    )
}

fn diagnostic_bytes(severity: &str, sqlstate: &str, message: &str) -> usize {
    size_of::<DatabaseError>() + diagnostic(severity, sqlstate, message, "").len() - 5
}

fn diagnostic_peer(terminal: bool, ready_follows: bool, message: &str, detail: &str) -> Peer {
    let mut response = frame(b'2', &[]);
    if terminal {
        for _ in 0..127 {
            response.extend(frame(b'N', NOTICE));
        }
        response.extend(diagnostic("FATAL", FATAL_STATE, message, detail));
    } else {
        response.extend(diagnostic("ERROR", SQLSTATE, message, detail));
    }
    if ready_follows {
        response.extend(ready(b'I'));
    }
    Peer::start(move |socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&response)?;
        match (terminal, ready_follows) {
            (true, _) => eof(socket),
            (false, false) => Ok(()),
            (false, true) => {
                execution(socket, &statement)?;
                socket.write_all(&result(73, b'I'))?;
                eof(socket)
            }
        }
    })
}

#[test]
fn diagnostic_limit_counts_an_ordinary_error_only_at_its_real_ready() {
    let exact = diagnostic_bytes("ERROR", SQLSTATE, DIAGNOSTIC);
    for mode in MODES {
        for (limit, ready_follows) in [(exact, true), (exact - 1, true), (exact - 1, false)] {
            let peer = diagnostic_peer(false, ready_follows, DIAGNOSTIC, "");
            run(async {
                let (mut client, statement) = prepared(&peer).await;
                let mut seen = Seen::default();
                let outcome = execute_batch(
                    &mut client,
                    std::iter::once(statement.bind(&[])),
                    BatchOptions {
                        max_diagnostic_bytes: limit,
                        ..BATCH
                    },
                    mode,
                    OnError::RecoverExplicitly,
                    &mut seen,
                )
                .await;
                if limit == exact {
                    let progress = outcome.unwrap();
                    assert_eq!((progress.confirmed, progress.sql_errors), (1, 1));
                    assert_eq!((seen.ready, seen.sql_errors), (1, 1));
                } else {
                    let failure = outcome.unwrap_err();
                    assert_eq!(seen, Seen::default());
                    assert_eq!(failure.progress.admitted, 1);
                    let confirmed = usize::from(ready_follows);
                    assert_eq!(failure.progress.confirmed, confirmed);
                    assert_eq!(failure.progress.sql_errors, confirmed);
                    assert_eq!(failure.progress.events_delivered, 0);
                    if ready_follows {
                        assert!(matches!(failure.source, Error::Limit(_)));
                        assert_eq!(failure.origin, Origin::Resource);
                    } else {
                        assert_eq!(failure.reuse, ReuseState::DiscardOnly);
                    }
                }
                if ready_follows {
                    recover_and_reuse(client, &statement).await;
                } else {
                    client.discard();
                }
            });
            peer.finish();
        }
    }
}

#[test]
fn fatal_diagnostic_keeps_its_terminal_server_category_at_the_control_and_byte_bounds() {
    let exact = diagnostic_bytes("FATAL", FATAL_STATE, DIAGNOSTIC);
    for mode in MODES {
        for limit in [exact, exact - 1] {
            let peer = diagnostic_peer(true, false, DIAGNOSTIC, "");
            run(async {
                let (mut client, statement) = prepared(&peer).await;
                let mut seen = Seen::default();
                let failure = execute_batch(
                    &mut client,
                    std::iter::once(statement.bind(&[])),
                    BatchOptions {
                        max_diagnostic_bytes: limit,
                        ..BATCH
                    },
                    mode,
                    OnError::RecoverExplicitly,
                    &mut seen,
                )
                .await
                .unwrap_err();
                assert_eq!(
                    (failure.progress.confirmed, failure.progress.sql_errors),
                    (0, 0)
                );
                assert_eq!(seen, Seen::default());
                assert_eq!(failure.origin, Origin::Server);
                assert_eq!(failure.reuse, ReuseState::DiscardOnly);
                assert_eq!(failure.progress.events_delivered, 0);
                if limit == exact {
                    assert!(matches!(
                        failure.source,
                        Error::Database(error)
                            if error.code() == FATAL_STATE && error.severity() == "FATAL" && error.message() == DIAGNOSTIC
                    ));
                } else {
                    assert!(matches!(failure.source, Error::Limit(_)));
                }
                client.discard();
            });
            peer.finish();
        }
    }
}

#[test]
fn automatic_cleanup_keeps_the_primary_and_the_terminal_diagnostic_limits() {
    for mode in [BatchMode::Collect, BatchMode::VisitReady] {
        let peer = Peer::start(|socket| {
            handshake(socket)?;
            let statement = prepare(socket, &[], &[23])?;
            execution(socket, &statement)?;
            execution(socket, &statement)?;
            let mut response = frame(b'2', &[]);
            response.extend(diagnostic("ERROR", SQLSTATE, DIAGNOSTIC, ""));
            response.extend(ready(b'I'));
            response.extend(frame(b'2', &[]));
            response.extend(diagnostic("FATAL", FATAL_STATE, DIAGNOSTIC, ""));
            socket.write_all(&response)?;
            eof(socket)
        });
        run(async {
            let (mut client, statement) = prepared(&peer).await;
            let mut seen = Seen::default();
            let failure = execute_batch(
                &mut client,
                [statement.bind(&[]), statement.bind(&[])].into_iter(),
                BatchOptions {
                    max_diagnostic_bytes: 1,
                    ..BATCH
                },
                mode,
                OnError::DrainToReady,
                &mut seen,
            )
            .await
            .unwrap_err();
            assert_eq!(seen, Seen::default());
            assert_eq!(failure.origin, Origin::Resource);
            assert_eq!(failure.reuse, ReuseState::DiscardOnly);
            assert_eq!(failure.progress.admitted, 2);
            assert_eq!(
                (failure.progress.confirmed, failure.progress.sql_errors),
                (1, 1)
            );
            assert!(matches!(failure.source, Error::Limit(_)));
            assert!(matches!(failure.cleanup.as_deref(), Some(Error::Limit(_))));
            client.discard();
        });
        peer.finish();
    }
}

fn assert_connection_profile<T>(connect: impl Future<Output = Result<T, Error>>, queue: usize) {
    let awaited = pin!(connect).poll(&mut Context::from_waker(Waker::noop()));
    let Poll::Ready(Err(Error::InvalidInput(message))) = awaited else {
        panic!("expected synchronous local validation before a runtime or socket");
    };
    if queue == WIRE.max_request_len {
        assert_eq!(message, "connect must run inside the owning Compio runtime");
    } else {
        assert!(
            message.contains("queue") || message.contains("packet"),
            "{message}"
        );
    }
}

#[test]
fn inherited_batch_queue_rejects_before_runtime_for_every_ordinary_transport() {
    let endpoint = ([127, 0, 0, 1], 5432).into();
    for queue in [0, WIRE.max_request_len, WIRE.max_request_len + 1] {
        let profile = BatchOptions {
            max_queued_request_bytes: queue,
            ..BATCH
        };
        let tcp = TcpConfig::plaintext(
            endpoint,
            "test",
            "test",
            AuthenticationPolicy::AllowAuthenticationOk,
            WIRE,
            TCP_OPTIONS,
        );
        assert_connection_profile(TcpConnection::connect(options(tcp.clone(), profile)), queue);
        #[cfg(target_os = "linux")]
        assert_connection_profile(
            compio_postgres::expert::linux::TcpReadinessConnection::connect(options(tcp, profile)),
            queue,
        );

        #[cfg(unix)]
        {
            let unix = compio_postgres::UnixConfig::plaintext(
                "/cpg-test-no-socket",
                "test",
                "test",
                AuthenticationPolicy::AllowAuthenticationOk,
                WIRE,
                compio_postgres::SendPolicy::BeforeBufferedRead,
            )
            .unwrap();
            assert_connection_profile(
                compio_postgres::UnixConnection::connect(options(unix.clone(), profile)),
                queue,
            );
            #[cfg(target_os = "linux")]
            assert_connection_profile(
                compio_postgres::expert::linux::UnixReadinessConnection::connect(options(
                    unix, profile,
                )),
                queue,
            );
        }

        #[cfg(feature = "tls")]
        {
            use compio_postgres::{TlsConfig, TlsNegotiation, TlsVersions};
            let tls = TlsConfig::from_ca_pem(
                "localhost",
                include_bytes!("fixtures/tls/sha256.pem"),
                tls_options::fixture_tls_options(
                    TlsNegotiation::SslRequest,
                    TlsVersions::Tls12Or13,
                ),
            )
            .unwrap();
            let secure = TcpConfig::tls(
                endpoint,
                "test",
                "test",
                AuthenticationPolicy::AllowAuthenticationOk,
                WIRE,
                tls,
                TCP_OPTIONS,
            );
            assert_connection_profile(
                compio_postgres::TlsConnection::connect(options(secure, profile)),
                queue,
            );
        }
    }
}

#[test]
fn invalid_batch_queue_overrides_are_rejected_before_observing_source() {
    let peer = Peer::start(|socket| {
        handshake(socket)?;
        let statement = prepare(socket, &[], &[23])?;
        execution(socket, &statement)?;
        socket.write_all(&result(73, b'I'))?;
        eof(socket)
    });
    run(async {
        let (mut client, statement) = prepared(&peer).await;
        for mode in MODES {
            for queue in [0, WIRE.max_request_len + 1] {
                let calls = Cell::new(0);
                let source = std::iter::from_fn(|| {
                    calls.set(calls.get() + 1);
                    None::<compio_postgres::BatchRequest<'_>>
                });
                let mut seen = Seen::default();
                let failure = execute_batch(
                    &mut client,
                    source,
                    BatchOptions {
                        max_queued_request_bytes: queue,
                        ..BATCH
                    },
                    mode,
                    OnError::RecoverExplicitly,
                    &mut seen,
                )
                .await
                .unwrap_err();
                assert!(matches!(failure.source, Error::InvalidInput(_)));
                assert_eq!(failure.reuse, ReuseState::ProtocolIdle);
                assert_eq!(seen, Seen::default());
                assert_eq!(calls.get(), 0);
                assert_eq!(
                    (failure.progress.consumed, failure.progress.admitted),
                    (0, 0)
                );
            }
        }
        recover_and_reuse(client, &statement).await;
    });
    peer.finish();
}

#[cfg(feature = "diagnostics")]
#[global_allocator]
static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，避免其他测试影响全局计数"]
fn oversized_diagnostic_is_rejected_without_allocating_its_message() {
    let payload = "x".repeat(7600);
    for mode in MODES {
        for terminal in [false, true] {
            let measure = |message: &str, detail: &str, limit: usize| {
                let peer = diagnostic_peer(terminal, !terminal, message, detail);
                let allocated = run(async {
                    let (mut client, statement) = prepared(&peer).await;
                    let mut seen = Seen::default();
                    let mut bytes = 0;
                    let outcome = {
                        let mut batch = pin!(execute_batch(
                            &mut client,
                            std::iter::once(statement.bind(&[])),
                            BatchOptions {
                                max_diagnostic_bytes: limit,
                                ..BATCH
                            },
                            mode,
                            OnError::RecoverExplicitly,
                            &mut seen,
                        ));
                        // 只统计批次的轮询，排除轮询之间 runtime 为 IOCP 等后端分配的完成数组。
                        std::future::poll_fn(|cx| {
                            let region = stats_alloc::Region::new(ALLOCATOR);
                            let result = batch.as_mut().poll(cx);
                            bytes += region.change().bytes_allocated;
                            result
                        })
                        .await
                    };
                    if limit == 1 {
                        assert!(matches!(outcome.unwrap_err().source, Error::Limit(_)));
                        assert_eq!(seen, Seen::default());
                    } else if terminal {
                        assert!(matches!(outcome.unwrap_err().source,
                            Error::Database(error) if error.detail() == Some(detail)));
                    } else {
                        assert_eq!(outcome.unwrap().sql_errors, 1);
                        assert_eq!(seen.sql_errors, 1);
                    }
                    if terminal {
                        client.discard();
                    } else {
                        recover_and_reuse(client, &statement).await;
                    }
                    bytes
                });
                peer.finish();
                allocated
            };
            // 对端在计量前构造响应。先与短帧比较，再用完全相同的长帧放宽额度，
            // 验证计数器能观察到保留整个诊断时产生的分配。
            let short = measure(DIAGNOSTIC, "", 1);
            let long_message = measure(&payload, "", 1);
            let long_detail = measure(DIAGNOSTIC, &payload, 1);
            let retained = measure(DIAGNOSTIC, &payload, OUTPUT.max_bytes);
            assert!(
                long_message.max(long_detail).saturating_sub(short) < payload.len() / 2,
                "{mode:?}, fatal={terminal}: short={short}, message={long_message}, detail={long_detail}"
            );
            assert!(
                retained.saturating_sub(long_detail) >= payload.len() / 2,
                "{mode:?}, fatal={terminal}: rejected={long_detail}, retained={retained}"
            );
        }
    }
}
