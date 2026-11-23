//! Linux 上的原生 TCP、就绪式 TCP 和 TLS 共用显式接收缓冲策略。
#![cfg(target_os = "linux")]

#[path = "support/live.rs"]
mod live;
#[cfg(feature = "tls")]
use live::{endpoint, required};

#[cfg(feature = "tls")]
#[path = "support/tls_options.rs"]
mod tls_options;

#[path = "support/tcp_options.rs"]
mod tcp_options;

#[path = "support/scalar.rs"]
mod scalar;
use scalar::ScalarQueries;

use std::{future::Future, time::Duration};

use compio_postgres::{
    TcpConfig, WireLimits, WireTransport,
    expert::{
        Session, TcpSession as TcpConnection,
        linux::{
            TcpOptionsExt, TcpReadinessSession as TcpReadinessConnection, TcpReceiveBufferPolicy,
            TcpSessionExt,
        },
    },
};

fn run(future: impl Future<Output = ()>) {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        compio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("TCP receive-buffer fixture deadline")
    });
}

fn limits() -> WireLimits {
    WireLimits {
        receive_capacity: 8192,
        max_frame_len: 8191,
        max_request_len: 8192,
        max_messages_per_request: 128,
    }
}

fn config(policy: TcpReceiveBufferPolicy) -> TcpConfig {
    live::tcp_config(
        limits(),
        tcp_options::TCP_OPTIONS.with_receive_buffer(policy),
    )
}

async fn exercise<T: WireTransport>(mut session: Session<T>, policy: TcpReceiveBufferPolicy)
where
    Session<T>: TcpSessionExt,
{
    scalar::configure(&mut session);
    let snapshot = session.tcp_receive_buffer_snapshot();
    match policy {
        TcpReceiveBufferPolicy::SystemManaged => assert_eq!(snapshot, None),
        TcpReceiveBufferPolicy::RequestBytes { bytes } => {
            let applied = snapshot.expect("explicit TCP receive-buffer request");
            assert_eq!(applied.requested_bytes, bytes);
            // 同一内核独立设置一个 TCP socket，核对实际限幅与内核记账后的结果。
            let reference = rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::STREAM,
                None,
            )
            .unwrap();
            rustix::net::sockopt::set_socket_recv_buffer_size(&reference, bytes).unwrap();
            assert_eq!(
                applied.actual_bytes_before_startup,
                rustix::net::sockopt::socket_recv_buffer_size(&reference).unwrap()
            );
        }
    }
    let statement = session
        .prepare_scalar("SELECT $1::int4 AS value")
        .await
        .unwrap();
    for value in [None, Some(i32::MIN), Some(73), Some(i32::MAX)] {
        assert_eq!(
            session.query_scalar(&statement, value).await.unwrap(),
            value
        );
    }
    assert_eq!(
        session.tcp_receive_buffer_snapshot(),
        snapshot,
        "snapshot must not pretend to refresh after I/O"
    );
    session.close_prepared(&statement).await.unwrap();
    session.close_local().await.unwrap();
}

#[test]
#[ignore = "需要 PostgreSQL 19 和 CPG_* 连接配置"]
fn live_tcp_receive_buffer_policies_preserve_native_and_readiness_queries() {
    run(async {
        for policy in [
            TcpReceiveBufferPolicy::SystemManaged,
            TcpReceiveBufferPolicy::RequestBytes { bytes: 256 * 1024 },
        ] {
            exercise(
                TcpConnection::connect(config(policy)).await.unwrap(),
                policy,
            )
            .await;
            exercise(
                TcpReadinessConnection::connect(config(policy))
                    .await
                    .unwrap(),
                policy,
            )
            .await;
        }
    });
}

#[cfg(feature = "tls")]
#[test]
#[ignore = "需要支持 TLS 的 PostgreSQL 19 和相应证书配置"]
fn live_tcp_receive_buffer_policies_preserve_verified_tls_queries() {
    use compio_postgres::{TlsConfig, TlsNegotiation, TlsVersions};
    run(async {
        for policy in [
            TcpReceiveBufferPolicy::SystemManaged,
            TcpReceiveBufferPolicy::RequestBytes { bytes: 256 * 1024 },
        ] {
            let tls = TlsConfig::from_ca_pem(
                &required("CPG_TLS_SERVER_NAME"),
                &std::fs::read(required("CPG_TLS_CA_PEM")).unwrap(),
                tls_options::fixture_tls_options(TlsNegotiation::SslRequest, TlsVersions::Tls13),
            )
            .unwrap();
            let secure = TcpConfig::tls(
                endpoint(),
                required("CPG_USER"),
                required("CPG_DATABASE"),
                live::scram(),
                limits(),
                tls,
                tcp_options::TCP_OPTIONS.with_receive_buffer(policy),
            );
            exercise(
                compio_postgres::expert::TlsSession::connect(secure)
                    .await
                    .unwrap(),
                policy,
            )
            .await;
        }
    });
}
