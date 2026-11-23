//! 示例与基准共用的数据库地址、认证和可信证书配置。
use compio::{net::ToSocketAddrsAsync, runtime::Runtime};
use compio_postgres::{AuthenticationPolicy, TcpConfig, TcpNoDelay, TcpOptions, WireLimits};
use std::{env, error::Error, io};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
pub(crate) enum Transport {
    Tcp,
    #[cfg(feature = "tls")]
    Tls,
    #[cfg(unix)]
    Unix,
}

pub(crate) enum Config {
    Tcp(TcpConfig),
    #[cfg(feature = "tls")]
    Tls(compio_postgres::SecureConfig),
    #[cfg(unix)]
    Unix(compio_postgres::UnixConfig),
}

impl Transport {
    pub(crate) const CHOICES: &'static str = match (cfg!(feature = "tls"), cfg!(unix)) {
        (true, true) => "tcp|tls|unix",
        (true, false) => "tcp|tls",
        (false, true) => "tcp|unix",
        (false, false) => "tcp",
    };

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "tcp" => Ok(Self::Tcp),
            #[cfg(feature = "tls")]
            "tls" => Ok(Self::Tls),
            #[cfg(not(feature = "tls"))]
            "tls" => Err("使用 TLS 需要启用 tls 特性".into()),
            #[cfg(unix)]
            "unix" => Ok(Self::Unix),
            #[cfg(not(unix))]
            "unix" => Err("当前平台的客户端不支持 Unix 套接字".into()),
            _ => Err(format!("传输方式须为 {}", Self::CHOICES).into()),
        }
    }

    pub(crate) fn config(self, runtime: &Runtime) -> Result<Config> {
        let user = setting("CPG_USER")?;
        let database = setting("CPG_DATABASE")?;
        let tcp = TcpOptions::new(TcpNoDelay::Enabled);
        let limits = WireLimits::short_queries();
        let auth = AuthenticationPolicy::ScramSha256 {
            password: setting("CPG_PASSWORD")?,
            max_iterations: 100_000,
        };
        match self {
            Self::Tcp => Ok(Config::Tcp(TcpConfig::plaintext(
                tcp_endpoint(runtime)?,
                user,
                database,
                auth,
                limits,
                tcp,
            ))),
            #[cfg(feature = "tls")]
            Self::Tls => Ok(Config::Tls(TcpConfig::tls(
                tcp_endpoint(runtime)?,
                user,
                database,
                auth,
                limits,
                tls_config()?,
                tcp,
            ))),
            #[cfg(unix)]
            Self::Unix => Ok(Config::Unix(compio_postgres::UnixConfig::plaintext(
                env::var_os("CPG_UNIX_PATH").ok_or("请设置 CPG_UNIX_PATH 为套接字的绝对路径")?,
                user,
                database,
                auth,
                limits,
                compio_postgres::SendPolicy::BeforeBufferedRead,
            )?)),
        }
    }
}

fn tcp_endpoint(runtime: &Runtime) -> Result<std::net::SocketAddr> {
    let host = setting("CPG_HOST")?;
    let port = setting("CPG_PORT")?.parse::<std::num::NonZeroU16>()?.get();
    runtime
        .block_on((host.as_str(), port).to_socket_addrs_async())?
        .next()
        .ok_or_else(|| io::Error::other("CPG_HOST 未解析出地址").into())
}

fn setting(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("环境变量 {name} 需要非空的 Unicode 值"),
        )
        .into()),
    }
}

#[cfg(feature = "tls")]
fn tls_config() -> Result<compio_postgres::TlsConfig> {
    use compio_postgres::{TlsConfig, TlsNegotiation, TlsOptions, TlsResumption, TlsVersions};
    let ca = std::fs::read(setting("CPG_TLS_CA_PEM")?)?;
    let mut tls = TlsConfig::from_ca_pem(
        &setting("CPG_TLS_SERVER_NAME")?,
        &ca,
        TlsOptions {
            negotiation: TlsNegotiation::Direct,
            versions: TlsVersions::Tls13,
            resumption: TlsResumption::Disabled,
            send_buffer_limit: std::num::NonZeroUsize::new(64 * 1024),
        },
    )?;
    match (
        env::var_os("CPG_TLS_CLIENT_CERT_PEM"),
        env::var_os("CPG_TLS_CLIENT_KEY_PEM"),
    ) {
        (None, None) => {}
        (Some(cert), Some(key)) => {
            tls = tls.with_client_identity_pem(&std::fs::read(cert)?, &std::fs::read(key)?)?;
        }
        _ => return Err("请同时设置 CPG_TLS_CLIENT_CERT_PEM 和 CPG_TLS_CLIENT_KEY_PEM".into()),
    }
    Ok(tls)
}
