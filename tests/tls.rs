#![cfg(feature = "tls")]

//! 真实 TLS 用例需要 PostgreSQL 19、受信 CA 和服务端名称。本地 TLS 对端用证书及私钥验证握手。

#[path = "support/live.rs"]
mod live;
use live::required;

#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use compio_postgres::{
    AuthenticationPolicy, Error, SecureConfig, TcpConfig, TlsConfig, TlsNegotiation, TlsVersion,
    TlsVersions, WireLimits, expert::TlsSession as TlsConnection,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLIC_UNIT_CA: &[u8] = include_bytes!("fixtures/tls/sha256.pem");

struct Settings {
    endpoint: SocketAddr,
    user: String,
    database: String,
    password: String,
    server_name: String,
    ca_pem: Vec<u8>,
}

impl Settings {
    fn from_env() -> Self {
        Self {
            endpoint: live::endpoint(),
            user: required("CPG_USER"),
            database: required("CPG_DATABASE"),
            password: required("CPG_PASSWORD"),
            server_name: required("CPG_TLS_SERVER_NAME"),
            ca_pem: std::fs::read(required("CPG_TLS_CA_PEM")).expect("read public fixture CA"),
        }
    }

    fn config(&self, negotiation: TlsNegotiation, versions: TlsVersions) -> SecureConfig {
        self.with_server_identity(
            &self.server_name,
            &self.ca_pem,
            negotiation,
            versions,
            self.plus(),
        )
    }

    fn plus(&self) -> AuthenticationPolicy {
        AuthenticationPolicy::ScramSha256Plus {
            password: self.password.clone(),
            max_iterations: live::SCRAM_MAX_ITERATIONS,
        }
    }

    fn with_server_identity(
        &self,
        name: &str,
        ca: &[u8],
        negotiation: TlsNegotiation,
        versions: TlsVersions,
        authentication: AuthenticationPolicy,
    ) -> SecureConfig {
        TcpConfig::tls(
            self.endpoint,
            &self.user,
            &self.database,
            authentication,
            limits(),
            TlsConfig::from_ca_pem(
                name,
                ca,
                tls_options::fixture_tls_options(negotiation, versions),
            )
            .expect("valid fixture TLS configuration"),
            tcp_options::TCP_OPTIONS,
        )
    }
}

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 65_536,
        max_messages_per_request: 128,
    }
}

fn accept_mock(listener: TcpListener) -> std::net::TcpStream {
    listener
        .set_nonblocking(true)
        .expect("finite mock accept mode");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket
                    .set_nonblocking(false)
                    .expect("blocking mock peer socket");
                return socket;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("finite TLS mock could not accept its client: {error}"),
        }
    }
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    let runtime = compio::runtime::Runtime::new().expect("create fixture runtime");
    // 在调用者栈上固定 future，只将引用传给超时器，避免未优化构建反复移动大对象。
    let future = std::pin::pin!(future);
    runtime.block_on(async move {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("TLS fixture deadline")
    })
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    compio::time::timeout(OPERATION_TIMEOUT, future)
        .await
        .expect("TLS operation deadline")
}

fn query_over_tls(negotiation: TlsNegotiation, versions: TlsVersions, expected: TlsVersion) {
    let settings = Settings::from_env();
    run(async {
        let mut connection = bounded(TlsConnection::connect(
            settings.config(negotiation, versions),
        ))
        .await
        .expect("verified TLS and SCRAM-PLUS connection");
        scalar::configure(&mut connection);
        assert_eq!(connection.tls_info().version, expected);
        assert_eq!(connection.tls_info().negotiation, negotiation);
        assert!(connection.tls_info().channel_binding_available);
        assert!(connection.server_info().version.starts_with("19"));
        let statement = bounded(connection.prepare_scalar("SELECT $1::int4"))
            .await
            .expect("prepare over TLS");
        assert_eq!(
            bounded(connection.query_scalar(&statement, Some(42)))
                .await
                .expect("query over TLS"),
            Some(42)
        );
        bounded(connection.close_prepared(&statement))
            .await
            .expect("close over TLS");
        assert!(connection.is_usable());
        bounded(connection.close_local())
            .await
            .expect("confirm native TLS retirement after idle query");
    });
}

#[test]
fn invalid_tls_client_identities_are_rejected_during_configuration() {
    let config = TlsConfig::from_ca_pem(
        "localhost",
        PUBLIC_UNIT_CA,
        tls_options::fixture_tls_options(TlsNegotiation::Direct, TlsVersions::Tls13),
    )
    .unwrap();
    assert!(matches!(
        config.clone().with_client_identity_pem(PUBLIC_UNIT_CA, b""),
        Err(Error::InvalidInput("a TLS client private key is required"))
    ));
    let cert = CertificateDer::from_pem_slice(PUBLIC_UNIT_CA).unwrap();
    assert!(matches!(
        config.with_client_identity_der([cert.as_ref()], b"invalid DER"),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
#[ignore = "需要支持 TLS 和 SCRAM-PLUS 的 PostgreSQL 19、可信客户端 CA 及 CPG_TLS_CLIENT_* 证书配置"]
fn postgres_reports_the_certificate_used_for_mutual_tls() {
    use compio_postgres::{
        ClientOptions, OnError, ResultFormats,
        types::{Format, Parameter},
    };
    let settings = Settings::from_env();
    let chain = std::fs::read(required("CPG_TLS_CLIENT_CERT_PEM")).unwrap();
    let private_key = std::fs::read(required("CPG_TLS_CLIENT_KEY_PEM")).unwrap();
    let leaf = CertificateDer::from_pem_slice(&chain).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
    let serial = certificate.serial.to_string();
    let tls = TlsConfig::from_ca_pem(
        &settings.server_name,
        &settings.ca_pem,
        tls_options::fixture_tls_options(TlsNegotiation::Direct, TlsVersions::Tls13),
    )
    .unwrap();
    assert!(matches!(
        tls.clone().with_client_identity_pem(&[], &private_key),
        Err(Error::InvalidInput(
            "a TLS client certificate chain is required"
        ))
    ));
    let tls = tls.with_client_identity_pem(&chain, &private_key).unwrap();
    let config = TcpConfig::tls(
        settings.endpoint,
        &settings.user,
        &settings.database,
        settings.plus(),
        limits(),
        tls,
        tcp_options::TCP_OPTIONS,
    );
    run(async {
        let mut client =
            compio_postgres::TlsConnection::connect(ClientOptions::short_queries(config))
                .await
                .unwrap();
        let certificate_matches = client
            .one_shot(
                "SELECT ssl AND client_serial::text = $1::text
             FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()",
                &[Parameter::string(&serial)],
                ResultFormats::All(Format::Binary),
            )
            .one::<bool>(OnError::RecoverExplicitly)
            .await
            .unwrap();
        assert!(
            certificate_matches,
            "服务端观测到的客户端证书序列号与夹具不符"
        );
        client.terminate().await.unwrap();
    });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn ssl_request_tls12_authenticates_with_scram_plus() {
    query_over_tls(
        TlsNegotiation::SslRequest,
        TlsVersions::Tls12,
        TlsVersion::Tls12,
    );
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn ssl_request_tls13_authenticates_with_scram_plus() {
    query_over_tls(
        TlsNegotiation::SslRequest,
        TlsVersions::Tls13,
        TlsVersion::Tls13,
    );
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn direct_tls12_authenticates_with_scram_plus() {
    query_over_tls(
        TlsNegotiation::Direct,
        TlsVersions::Tls12,
        TlsVersion::Tls12,
    );
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn direct_tls13_authenticates_with_scram_plus() {
    query_over_tls(
        TlsNegotiation::Direct,
        TlsVersions::Tls13,
        TlsVersion::Tls13,
    );
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn verified_tls_continuous_window_and_prepared_owned_copy_preserve_boundaries() {
    use compio_postgres::{
        CopyDataBuffer, QueryLimits, ReadyBatchEvent, ResultFormats, StatementLimits,
        expert::{PipelineRequest, VisitLimits, WindowLimits, WindowParameters, WindowRequest},
        types::{Format, Oid, Parameter},
    };
    let settings = Settings::from_env();
    run(async {
        for (negotiation, versions) in [
            (TlsNegotiation::SslRequest, TlsVersions::Tls12),
            (TlsNegotiation::Direct, TlsVersions::Tls13),
        ] {
            let mut connection = bounded(TlsConnection::connect(
                settings.config(negotiation, versions),
            ))
            .await
            .unwrap();
            connection
                .configure_statements(StatementLimits {
                    max_statements: 2,
                    max_metadata_bytes: 32768,
                })
                .unwrap();
            let query = QueryLimits {
                max_rows: 1,
                max_result_bytes: 128,
                max_metadata_bytes: 4096,
            };
            let statement = connection
                .prepare(
                    "SELECT $1::int4",
                    &[Oid::INT4],
                    ResultFormats::All(Format::Binary),
                )
                .await
                .unwrap();
            let mut source = (0..64).map(|value| {
                Ok(WindowRequest {
                    statement: &statement,
                    parameters: WindowParameters::One(Parameter::int4(value)),
                    limits: query,
                })
            });
            let completion = connection
                .query_window(
                    &mut source,
                    WindowLimits {
                        storage: compio_postgres::AllocationPolicy::ReserveLimit,
                        max_inflight: 8,
                        max_requests: 64,
                        max_rows: 64,
                        max_result_bytes: 4096,
                        max_queued_request_bytes: 2048,
                        scheduling: compio_postgres::ExecutionScheduling::Cooperative {
                            max_work_per_turn: std::num::NonZeroUsize::new(4).unwrap(),
                        },
                    },
                    compio_postgres::OnError::RecoverExplicitly,
                    &mut |event: ReadyBatchEvent<'_>| {
                        let result = event
                            .outcome
                            .map_err(|_| Error::InvalidInput("TLS window SQL error"))?;
                        assert_eq!(result.rows.len(), 1);
                        for row in result.rows.rows() {
                            assert_eq!(
                                row?.decoder().decode_next::<i32>()?,
                                i32::try_from(event.index).unwrap()
                            );
                        }
                        Ok(std::ops::ControlFlow::Continue(()))
                    },
                )
                .await
                .unwrap();
            assert_eq!(completion.confirmed, 64);
            // 发送大于一个 TLS 记录的有限请求，独立验证访问器的跨记录读取。
            let parameters: Vec<_> = (0..512).map(|value| [Parameter::int4(value)]).collect();
            let requests: Vec<_> = parameters
                .iter()
                .map(|parameters| PipelineRequest {
                    statement: &statement,
                    parameters,
                    limits: query,
                })
                .collect();
            let mut visited = 0;
            let mut first_storage = None;
            let completion = bounded(connection.query_pipeline_visit(
                &requests,
                VisitLimits {
                    storage: compio_postgres::AllocationPolicy::ReserveLimit,
                    max_requests: 512,
                    max_rows: 512,
                    max_result_bytes: 4096,
                    scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                },
                |event: ReadyBatchEvent<'_>| {
                    assert_eq!(event.index, visited);
                    let result = event
                        .outcome
                        .map_err(|_| Error::InvalidInput("TLS finite visit failed"))?;
                    assert!(result.completion.succeeded);
                    assert_eq!(result.rows.len(), 1);
                    let view = result.rows.rows().next().unwrap()?;
                    let storage = view.fields().next().unwrap()?.bytes.unwrap().as_ptr();
                    if let Some(first) = first_storage {
                        assert_eq!(storage, first);
                    } else {
                        first_storage = Some(storage);
                    }
                    assert_eq!(
                        view.decoder().decode_next::<i32>()?,
                        i32::try_from(visited).unwrap()
                    );
                    visited += 1;
                    Ok(())
                },
            ))
            .await
            .unwrap();
            assert_eq!(
                (
                    completion.admitted,
                    completion.confirmed,
                    completion.delivered,
                    completion.sql_errors
                ),
                (512, 512, 512, 0)
            );
            assert_eq!(visited, 512);
            assert!(connection.is_usable());
            {
                let errors = connection
                    .prepare(
                        "SELECT 100 / $1::int4",
                        &[Oid::INT4],
                        ResultFormats::All(Format::Binary),
                    )
                    .await
                    .unwrap();
                let inputs = [
                    [Parameter::int4(2)],
                    [Parameter::int4(0)],
                    [Parameter::int4(4)],
                ];
                let tiny = QueryLimits {
                    max_result_bytes: 12,
                    ..query
                };
                let requests: Vec<_> = inputs
                    .iter()
                    .map(|parameters| PipelineRequest {
                        statement: &errors,
                        parameters,
                        limits: tiny,
                    })
                    .collect();
                let mut observed = Vec::new();
                let completion = bounded(connection.query_pipeline_visit(
                    &requests,
                    VisitLimits {
                        storage: compio_postgres::AllocationPolicy::ReserveLimit,
                        max_requests: 3,
                        max_rows: 3,
                        max_result_bytes: 4096,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    |event: ReadyBatchEvent<'_>| {
                        observed.push(match event.outcome {
                            Ok(result) => Ok(result
                                .rows
                                .rows()
                                .next()
                                .unwrap()?
                                .decoder()
                                .decode_next::<i32>()?),
                            Err(error) => Err(error.code().to_owned()),
                        });
                        Ok(())
                    },
                ))
                .await
                .unwrap();
                assert_eq!(observed, [Ok(50), Err("22012".to_owned()), Ok(25)]);
                assert_eq!(
                    (
                        completion.admitted,
                        completion.confirmed,
                        completion.delivered,
                        completion.sql_errors
                    ),
                    (3, 3, 3, 1)
                );
                assert!(connection.is_usable());
                connection.close_prepared(&errors).await.unwrap();
            }
            // 关闭服务端语句后，待本地句柄和请求借用释放，才能回收槽。
            assert_eq!(connection.reclaim_closed_statements().unwrap(), 1);
            connection.close_prepared(&statement).await.unwrap();
            connection
                .query_simple_single(
                    "CREATE TEMP TABLE cpg_tls_owned(v int4)",
                    compio_postgres::QueryOptions {
                        limits: query,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            let input = connection
                .prepare(
                    "COPY cpg_tls_owned FROM STDIN (FORMAT text)",
                    &[],
                    ResultFormats::All(Format::Text),
                )
                .await
                .unwrap();
            let mut copy = connection
                .copy_in_prepared(
                    &input,
                    &[],
                    compio_postgres::ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            let mut packet = CopyDataBuffer::new(32).unwrap();
            packet.extend_from_slice(b"9\n").unwrap();
            let packet = copy.send_owned(packet).await.unwrap();
            assert_eq!(packet.payload(), b"9\n");
            copy.send_owned(packet).await.unwrap();
            assert_eq!(copy.finish().await.unwrap().rows, 2);
            let mut result = connection
                .query_simple_single(
                    "SELECT count(*)::int8,sum(v)::int8 FROM cpg_tls_owned",
                    compio_postgres::QueryOptions {
                        limits: query,
                        scheduling: compio_postgres::ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            {
                let row = result.next_row().await.unwrap().unwrap();
                let mut decoder = row.view().decoder();
                assert_eq!(decoder.decode_next::<i64>().unwrap(), 2);
                assert_eq!(decoder.decode_next::<i64>().unwrap(), 18);
                decoder.finish().unwrap();
            }
            result.finish().await.unwrap();
            drop(result);
            connection.close_prepared(&input).await.unwrap();
            connection.close_local().await.unwrap();
        }
    });
}

fn assert_certificate_failure(result: Result<TlsConnection, Error>) {
    let Err(Error::Io(error)) = result else {
        panic!("the TLS certificate must be rejected before PostgreSQL authentication")
    };
    assert!(
        error.get_ref().is_some_and(|source| matches!(
            source.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        )),
        "the failure must be a real TLS certificate error"
    );
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn an_untrusted_server_certificate_is_rejected() {
    let settings = Settings::from_env();
    let config = settings.with_server_identity(
        &settings.server_name,
        PUBLIC_UNIT_CA,
        TlsNegotiation::SslRequest,
        TlsVersions::Tls13,
        settings.plus(),
    );
    run(async { assert_certificate_failure(bounded(TlsConnection::connect(config)).await) });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn a_wrong_hostname_is_rejected() {
    let settings = Settings::from_env();
    let config = settings.with_server_identity(
        "wrong-fixture-name.invalid",
        &settings.ca_pem,
        TlsNegotiation::Direct,
        TlsVersions::Tls13,
        settings.plus(),
    );
    run(async { assert_certificate_failure(bounded(TlsConnection::connect(config)).await) });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn authentication_ok_policy_does_not_accept_scram_over_tls() {
    let settings = Settings::from_env();
    let config = settings.with_server_identity(
        &settings.server_name,
        &settings.ca_pem,
        TlsNegotiation::SslRequest,
        TlsVersions::Tls13,
        AuthenticationPolicy::AllowAuthenticationOk,
    );
    run(async {
        assert!(matches!(
            bounded(TlsConnection::connect(config)).await,
            Err(Error::Unsupported(_))
        ))
    });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn a_wrong_password_is_rejected_after_verified_tls() {
    let settings = Settings::from_env();
    let mut password = settings.password.clone();
    password.push_str("-deliberately-incorrect-fixture-password");
    let config = settings.with_server_identity(
        &settings.server_name,
        &settings.ca_pem,
        TlsNegotiation::Direct,
        TlsVersions::Tls13,
        AuthenticationPolicy::ScramSha256Plus {
            password,
            max_iterations: live::SCRAM_MAX_ITERATIONS,
        },
    );
    run(async {
        assert!(
            matches!(bounded(TlsConnection::connect(config)).await, Err(Error::Database(error)) if error.code() == "28P01")
        )
    });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn cancellation_uses_a_fresh_verified_tls_route() {
    let settings = Settings::from_env();
    run(async {
        let config = settings.config(TlsNegotiation::Direct, TlsVersions::Tls13);
        let connection = bounded(TlsConnection::connect(config.clone()))
            .await
            .unwrap();
        let observer = bounded(TlsConnection::connect(config)).await.unwrap();
        scalar::assert_live_cancel(connection, observer).await;
    });
}

#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn ordinary_client_cancels_on_the_worker_stack() {
    use compio_postgres::{
        ClientOptions, ExecutionScheduling, OnError, PreparedStatementStorage, QueryLimits,
        QueryOptions, ResultFormats, StatementLimits, TlsConnection as Client, types::Format,
    };
    let settings = Settings::from_env();
    let options = ClientOptions::direct(
        settings.config(TlsNegotiation::Direct, TlsVersions::Tls13),
        QueryOptions {
            limits: QueryLimits {
                max_rows: 1,
                max_result_bytes: 64,
                max_metadata_bytes: 4096,
            },
            scheduling: ExecutionScheduling::Uninterrupted,
        },
        StatementLimits {
            max_statements: 1,
            max_metadata_bytes: 4096,
        },
    );

    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(bounded(async move {
        let mut client = Client::connect(options).await.unwrap();
        let statement = client
            .prepare(
                "SELECT 42::int4 FROM pg_sleep(0.5)",
                &[],
                PreparedStatementStorage::Named,
                ResultFormats::All(Format::Binary),
            )
            .await
            .unwrap();
        let query = client
            .query(&statement, &[])
            .one::<i32>(OnError::RecoverExplicitly);
        assert!(
            compio::time::timeout(Duration::from_millis(50), query)
                .await
                .is_err()
        );
        client.request_cancel_and_discard().await.unwrap();
    }));
}

#[test]
#[ignore = "需要本地 TLS 对端使用的服务端证书和私钥"]
fn direct_tls_without_postgresql_alpn_is_rejected() {
    let (server_name, ca_pem, server) = local_tls_peer();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind finite TLS mock");
    let endpoint = listener.local_addr().expect("TLS mock address");
    let worker = thread::spawn(move || {
        let socket = accept_mock(listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("mock read timeout");
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("mock write timeout");
        let connection = rustls::ServerConnection::new(Arc::new(server)).expect("server TLS state");
        let mut stream = rustls::StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .expect("finish the finite mock TLS handshake");
        }
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bounded no-startup observation");
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Ok(_) => panic!("the client sent PostgreSQL bytes without negotiated ALPN"),
            Err(error) => panic!("unexpected mock TLS error: {error}"),
        }
        // 关闭本地套接字后，服务端可能暂时读不到 EOF。由客户端断言区分 ALPN 拒绝和普通读超时。
    });
    let config = mock_client_config(endpoint, &server_name, &ca_pem);
    run(async {
        let Err(Error::Io(error)) = bounded(TlsConnection::connect(config)).await else {
            panic!("Direct TLS must reject a missing ALPN selection")
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "Direct TLS did not negotiate PostgreSQL ALPN"
        );
    });
    worker.join().expect("finite TLS mock finished");
}

fn local_tls_peer() -> (String, Vec<u8>, rustls::ServerConfig) {
    let server_name = required("CPG_TLS_SERVER_NAME");
    let ca_pem = std::fs::read(required("CPG_TLS_CA_PEM")).expect("读取夹具 CA");
    let certificates = CertificateDer::pem_file_iter(required("CPG_TLS_SERVER_CERT_PEM"))
        .expect("open public server certificate")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse server certificate");
    let key = PrivateKeyDer::from_pem_file(required("CPG_TLS_SERVER_KEY_PEM"))
        .expect("read only the generated fixture key");
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS13 server")
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .expect("fixture certificate matches key");
    (server_name, ca_pem, server)
}

fn mock_client_config(endpoint: SocketAddr, server_name: &str, ca_pem: &[u8]) -> SecureConfig {
    TcpConfig::tls(
        endpoint,
        "fixture",
        "fixture",
        AuthenticationPolicy::AllowAuthenticationOk,
        limits(),
        TlsConfig::from_ca_pem(
            server_name,
            ca_pem,
            tls_options::fixture_tls_options(TlsNegotiation::Direct, TlsVersions::Tls13),
        )
        .expect("TLS mock client configuration"),
        tcp_options::TCP_OPTIONS,
    )
}

fn read_mock_packet_body(stream: &mut impl Read) -> Vec<u8> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = usize::try_from(i32::from_be_bytes(length)).unwrap();
    assert!((4..=4096).contains(&length));
    let mut body = vec![0; length - 4];
    stream.read_exact(&mut body).unwrap();
    body
}

fn start_mock_session(
    listener: TcpListener,
    server: rustls::ServerConfig,
) -> rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream> {
    let socket = accept_mock(listener);
    socket.set_read_timeout(Some(OPERATION_TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(OPERATION_TIMEOUT)).unwrap();
    let connection = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let startup = read_mock_packet_body(&mut stream);
    assert_eq!(&startup[..4], &[0, 3, 0, 2]);
    assert_eq!(stream.conn.alpn_protocol(), Some(b"postgresql".as_slice()));
    let status: &[(u8, &[u8])] = &[
        (b'R', &[0; 4]),
        (b'S', b"server_version\x0019.0\0"),
        (b'S', b"client_encoding\0UTF8\0"),
        (b'K', &[0, 0, 0, 1, 2, 3, 4, 5]),
        (b'Z', b"I"),
    ];
    let mut startup = Vec::new();
    for (tag, body) in status {
        startup.push(*tag);
        startup.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
        startup.extend_from_slice(body);
    }
    stream.write_all(&startup).unwrap();
    stream.flush().unwrap();
    stream
}

#[test]
#[ignore = "需要本地 TLS 对端使用的服务端证书和私钥"]
fn only_postgresql_frames_crossing_authenticated_records_are_copied() {
    use compio_postgres::{ExecutionScheduling, QueryLimits};

    #[cfg(feature = "diagnostics")]
    const TAG: &[u8] = b"C\0\0\0\rUPDATE 1\0";
    const REPLY: &[u8] = b"C\0\0\0\rUPDATE 1\0Z\0\0\0\x05I";
    const SQL: &str = "UPDATE fixture SET n = 1";

    let (server_name, ca_pem, mut server) = local_tls_peer();
    server.alpn_protocols = vec![b"postgresql".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let mut stream = start_mock_session(listener, server);
        for split in 1..REPLY.len() {
            let mut tag = [0];
            stream.read_exact(&mut tag).unwrap();
            assert_eq!(tag, *b"Q");
            let command = read_mock_packet_body(&mut stream);
            assert_eq!(command.strip_suffix(&[0]), Some(SQL.as_bytes()));
            if split == 1 {
                stream.conn.refresh_traffic_keys().unwrap();
                stream.flush().unwrap();
            }
            stream.write_all(&REPLY[..split]).unwrap();
            stream.flush().unwrap();
            stream.write_all(&REPLY[split..]).unwrap();
            stream.flush().unwrap();
        }
        let mut tag = [0];
        stream.read_exact(&mut tag).unwrap();
        assert_eq!(tag, *b"Q");
        assert_eq!(
            read_mock_packet_body(&mut stream).strip_suffix(&[0]),
            Some(SQL.as_bytes())
        );
        stream.write_all(&REPLY[..3]).unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
    });

    run(async {
        let mut connection = bounded(TlsConnection::connect(mock_client_config(
            endpoint,
            &server_name,
            &ca_pem,
        )))
        .await
        .unwrap();
        let limits = QueryLimits {
            max_rows: 0,
            max_result_bytes: 0,
            max_metadata_bytes: 4096,
        };
        for split in 1..REPLY.len() {
            #[cfg(not(feature = "diagnostics"))]
            let _ = split;
            #[cfg(feature = "diagnostics")]
            let before = compio_postgres::diagnostics::snapshot();
            let mut query = connection
                .query_simple_single(
                    SQL,
                    compio_postgres::QueryOptions {
                        limits,
                        scheduling: ExecutionScheduling::Uninterrupted,
                    },
                    compio_postgres::AbandonPolicy::RecoverExplicitly,
                )
                .await
                .unwrap();
            assert_eq!(
                bounded(query.finish()).await.unwrap().rows_affected,
                Some(1)
            );
            #[cfg(feature = "diagnostics")]
            {
                let observed = compio_postgres::diagnostics::snapshot()
                    .delta(before)
                    .unwrap();
                let split_counts = |frame_bytes, first_chunk_bytes: usize| {
                    let body_bytes = frame_bytes - 5;
                    match first_chunk_bytes.cmp(&5) {
                        std::cmp::Ordering::Less => (5, body_bytes),
                        std::cmp::Ordering::Equal => (0, body_bytes),
                        std::cmp::Ordering::Greater => (body_bytes, 0),
                    }
                };
                let ready_bytes = REPLY.len() - TAG.len();
                let (copied, borrowed) = match split.cmp(&TAG.len()) {
                    std::cmp::Ordering::Less => {
                        let (copied, borrowed) = split_counts(TAG.len(), split);
                        (copied, borrowed + ready_bytes)
                    }
                    std::cmp::Ordering::Equal => (0, REPLY.len()),
                    std::cmp::Ordering::Greater => {
                        let (copied, borrowed) = split_counts(ready_bytes, split - TAG.len());
                        (copied, borrowed + TAG.len())
                    }
                };
                assert_eq!(
                    observed.tls_plaintext_bytes_copied,
                    u64::try_from(copied).unwrap(),
                    "TLS split at {split}"
                );
                assert_eq!(
                    observed.tls_plaintext_bytes_borrowed,
                    u64::try_from(borrowed).unwrap(),
                    "TLS split at {split}"
                );
            }
        }
        assert!(connection.is_usable());
        let mut query = connection
            .query_simple_single(
                SQL,
                compio_postgres::QueryOptions {
                    limits,
                    scheduling: ExecutionScheduling::Uninterrupted,
                },
                compio_postgres::AbandonPolicy::RecoverExplicitly,
            )
            .await
            .unwrap();
        assert!(matches!(
            bounded(query.finish()).await,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        drop(query);
        bounded(connection.close_local()).await.unwrap();
    });
    worker.join().unwrap();
}

#[test]
#[ignore = "需要本地 TLS 对端使用的服务端证书和私钥"]
fn copy_out_terminals_avoid_staging_payloads_across_tls_records() {
    use compio_postgres::{
        AllocationPolicy, ExecutionScheduling, OnError, OwnedOutput, expert::CopyProtocol,
    };

    const SQL: &str = "COPY (SELECT 1) TO STDOUT";
    const PAYLOADS: [&[u8]; 2] = [b"first row\n", b"second row\n"];
    #[derive(Clone, Copy)]
    enum Terminal {
        Borrow,
        Collect,
        Finish,
        Recover,
        Refuse,
    }
    const TERMINALS: [Terminal; 5] = [
        Terminal::Borrow,
        Terminal::Collect,
        Terminal::Finish,
        Terminal::Recover,
        Terminal::Refuse,
    ];

    let (server_name, ca_pem, mut server) = local_tls_peer();
    server.alpn_protocols = vec![b"postgresql".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let mut stream = start_mock_session(listener, server);
        for _ in TERMINALS {
            let mut tag = [0];
            stream.read_exact(&mut tag).unwrap();
            assert_eq!(tag, *b"Q");
            assert_eq!(
                read_mock_packet_body(&mut stream).strip_suffix(&[0]),
                Some(SQL.as_bytes())
            );
            stream.write_all(b"H\0\0\0\x09\0\0\x01\0\0").unwrap();
            stream.flush().unwrap();
            for payload in PAYLOADS {
                stream.write_all(b"d").unwrap();
                stream.flush().unwrap();
                let length = i32::try_from(payload.len() + 4).unwrap();
                stream.write_all(&length.to_be_bytes()).unwrap();
                stream.flush().unwrap();
                for part in payload.chunks(3) {
                    stream.write_all(part).unwrap();
                    stream.flush().unwrap();
                }
            }
            stream
                .write_all(b"c\0\0\0\x04C\0\0\0\x0bCOPY 2\0Z\0\0\0\x05I")
                .unwrap();
            stream.flush().unwrap();
        }
    });

    run(async {
        let mut connection = bounded(TlsConnection::connect(mock_client_config(
            endpoint,
            &server_name,
            &ca_pem,
        )))
        .await
        .unwrap();
        for terminal in TERMINALS {
            let mut copy = connection
                .copy_out(
                    SQL,
                    &[],
                    CopyProtocol::SimpleSingle,
                    ExecutionScheduling::Uninterrupted,
                )
                .await
                .unwrap();
            #[cfg(feature = "diagnostics")]
            let before = compio_postgres::diagnostics::snapshot();
            let completion = match terminal {
                Terminal::Borrow => {
                    for expected in PAYLOADS {
                        assert_eq!(copy.next_chunk().await.unwrap().unwrap().bytes(), expected);
                    }
                    copy.finish().await.unwrap()
                }
                Terminal::Collect => {
                    let (output, completion) = copy
                        .collect_ready(
                            OwnedOutput {
                                max_bytes: 128,
                                allocation: AllocationPolicy::Grow,
                            },
                            OnError::RecoverExplicitly,
                        )
                        .await
                        .unwrap();
                    assert_eq!(output, PAYLOADS.concat());
                    completion
                }
                Terminal::Finish => copy.finish().await.unwrap(),
                Terminal::Recover => {
                    drop(copy);
                    connection.finish_abandoned_copy_out().await.unwrap()
                }
                Terminal::Refuse => {
                    let error = copy
                        .collect_ready(
                            OwnedOutput {
                                max_bytes: 1,
                                allocation: AllocationPolicy::Grow,
                            },
                            OnError::RecoverExplicitly,
                        )
                        .await
                        .unwrap_err();
                    assert!(matches!(error, Error::Limit(_)));
                    connection.finish_abandoned_copy_out().await.unwrap()
                }
            };
            assert_eq!(completion.rows, 2);
            assert!(connection.is_usable());
            #[cfg(feature = "diagnostics")]
            {
                let delta = compio_postgres::diagnostics::snapshot()
                    .delta(before)
                    .unwrap();
                let payload_bytes =
                    u64::try_from(PAYLOADS.iter().map(|p| p.len()).sum::<usize>()).unwrap();
                // 每个 CopyData 帧头分发在两个记录中，共用定长暂存。
                let staged = 10
                    + if matches!(terminal, Terminal::Borrow) {
                        payload_bytes
                    } else {
                        0
                    };
                let collected = if matches!(terminal, Terminal::Collect) {
                    payload_bytes
                } else {
                    0
                };
                assert_eq!(delta.tls_plaintext_bytes_copied, staged);
                assert_eq!(delta.copy_out_payload_bytes_copied, collected);
            }
        }
        connection.close_local().await.unwrap();
    });
    worker.join().unwrap();
}

fn negotiation_failure(response: &'static [u8], expect_tls_hello: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind finite SSLRequest mock");
    let endpoint = listener.local_addr().expect("mock address");
    let worker = thread::spawn(move || {
        let mut socket = accept_mock(listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("mock read timeout");
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .expect("mock write timeout");
        let mut request = [0; 8];
        socket.read_exact(&mut request).expect("read SSLRequest");
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        socket
            .write_all(response)
            .expect("send unauthenticated response");
        let mut received = Vec::new();
        match socket.read_to_end(&mut received) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => panic!("mock client did not close after rejection: {error}"),
        }
        if expect_tls_hello {
            if let Some(first) = received.first() {
                assert_eq!(*first, 22, "only a TLS handshake may follow S");
            }
        } else {
            assert!(
                received.is_empty(),
                "TLS refusal must not cause a plaintext Startup fallback"
            );
        }
    });
    let config = TcpConfig::tls(
        endpoint,
        "fixture",
        "fixture",
        AuthenticationPolicy::AllowAuthenticationOk,
        limits(),
        TlsConfig::from_ca_pem(
            "localhost",
            PUBLIC_UNIT_CA,
            tls_options::fixture_tls_options(TlsNegotiation::SslRequest, TlsVersions::Tls13),
        )
        .expect("mock TLS config"),
        tcp_options::TCP_OPTIONS,
    );
    run(async {
        let Err(error) = bounded(TlsConnection::connect(config)).await else {
            panic!("the unauthenticated SSLRequest response must not establish a session")
        };
        assert!(!error.to_string().contains("untrusted-diagnostic-marker"));
    });
    worker.join().expect("finite SSLRequest mock finished");
}

#[test]
fn ssl_request_refusal_never_falls_back_to_plaintext() {
    negotiation_failure(b"N", false);
}

#[test]
fn ssl_request_error_body_is_not_reported_as_authenticated_diagnostics() {
    negotiation_failure(b"Euntrusted-diagnostic-marker\0", false);
}

#[test]
fn ssl_request_stuffed_suffix_is_not_interpreted_as_postgresql_data() {
    negotiation_failure(b"SEuntrusted-diagnostic-marker\0", true);
}
