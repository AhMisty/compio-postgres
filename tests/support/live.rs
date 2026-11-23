//! 真实数据库夹具的显式连接参数。
#![allow(dead_code, reason = "各集成测试按所用传输选择连接参数")]

use std::net::{SocketAddr, ToSocketAddrs};

use compio_postgres::{AuthenticationPolicy, TcpConfig, TcpOptions, WireLimits};

pub(crate) const SCRAM_MAX_ITERATIONS: u32 = 100_000;

pub(crate) fn required(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} 必须设置且为有效的 Unicode"));
    assert!(!value.is_empty(), "{name} 不能为空");
    value
}

pub(crate) fn endpoint() -> SocketAddr {
    let host = required("CPG_HOST");
    let port = required("CPG_PORT")
        .parse::<u16>()
        .expect("CPG_PORT 必须是有效端口");
    assert_ne!(port, 0, "CPG_PORT 不能为零");
    (host.as_str(), port)
        .to_socket_addrs()
        .expect("无法解析数据库地址")
        .next()
        .expect("数据库地址没有解析结果")
}

pub(crate) fn tcp_config(limits: WireLimits, options: TcpOptions) -> TcpConfig {
    tcp_config_with_authentication(limits, options, scram())
}

#[cfg(unix)]
pub(crate) fn unix_config(
    limits: WireLimits,
    send_policy: compio_postgres::SendPolicy,
) -> compio_postgres::UnixConfig {
    compio_postgres::UnixConfig::plaintext(
        required("CPG_UNIX_PATH"),
        required("CPG_USER"),
        required("CPG_DATABASE"),
        scram(),
        limits,
        send_policy,
    )
    .unwrap()
}

pub(crate) fn tcp_config_with_authentication(
    limits: WireLimits,
    options: TcpOptions,
    authentication: AuthenticationPolicy,
) -> TcpConfig {
    TcpConfig::plaintext(
        endpoint(),
        required("CPG_USER"),
        required("CPG_DATABASE"),
        authentication,
        limits,
        options,
    )
}

pub(crate) fn scram() -> AuthenticationPolicy {
    AuthenticationPolicy::ScramSha256 {
        password: required("CPG_PASSWORD"),
        max_iterations: SCRAM_MAX_ITERATIONS,
    }
}

#[cfg(feature = "tls")]
pub(crate) fn tls_config(
    limits: WireLimits,
    tcp: TcpOptions,
    options: compio_postgres::TlsOptions,
) -> compio_postgres::SecureConfig {
    let tls = compio_postgres::TlsConfig::from_ca_pem(
        &required("CPG_TLS_SERVER_NAME"),
        &std::fs::read(required("CPG_TLS_CA_PEM")).unwrap(),
        options,
    )
    .unwrap();
    TcpConfig::tls(
        endpoint(),
        required("CPG_USER"),
        required("CPG_DATABASE"),
        AuthenticationPolicy::ScramSha256Plus {
            password: required("CPG_PASSWORD"),
            max_iterations: SCRAM_MAX_ITERATIONS,
        },
        limits,
        tls,
        tcp,
    )
}
