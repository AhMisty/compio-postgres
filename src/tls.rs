//! PostgreSQL 的 TLS 配置、客户端身份和握手信息。
//!
//! 使用 rustls 证书验证器。调用方指定信任根和预期服务端身份；握手失败即返回错误，禁用 TLS 早期数据。

use std::{
    fmt, io,
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

pub use rustls::CipherSuite;
use rustls::{
    ClientConfig, RootCertStore,
    client::Resumption,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    sign::{CertifiedKey, SingleCertAndKey},
};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x509_parser::{
    asn1_rs::{BitString, Sequence, oid},
    oid_registry::{
        OID_HASH_SHA1, OID_MD5_WITH_RSA, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
        OID_NIST_HASH_SHA512, OID_PKCS1_MD5WITHRSAENC, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA,
        OID_PKCS1_SHA224WITHRSA, OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA,
        OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_DSA_WITH_SHA1,
        OID_SIG_ECDSA_WITH_SHA224, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
        OID_SIG_ECDSA_WITH_SHA512, Oid,
    },
    prelude::{AlgorithmIdentifier, FromDer},
    signature_algorithm::SignatureAlgorithm,
};

use crate::Error;

mod stream;
pub(crate) use stream::{TlsSession, connect};

const POSTGRES_ALPN: &[u8] = b"postgresql";
static TLS_PROVIDER: LazyLock<Arc<CryptoProvider>> =
    LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// PostgreSQL 启动阶段采用的 TLS 协商方式，失败后不会自动切换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsNegotiation {
    SslRequest,
    Direct,
}

/// 客户端配置允许的 TLS 协议版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersions {
    Tls12,
    Tls13,
    Tls12Or13,
}

/// 是否保留同一配置下各连接的 TLS 会话恢复状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsResumption {
    Disabled,
    /// 为此配置指定的服务端启用内存缓存，配置的各个克隆共享缓存。
    InMemory,
}

impl TlsResumption {
    fn new_store(self) -> Resumption {
        match self {
            Self::Disabled => Resumption::disabled(),
            // 一个配置只连接指定的服务端身份，使用 rustls 最小的非空缓存。
            Self::InMemory => Resumption::in_memory_sessions(1),
        }
    }
}

/// TLS 协商方式、协议版本与资源策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsOptions {
    pub negotiation: TlsNegotiation,
    pub versions: TlsVersions,
    pub resumption: TlsResumption,
    /// rustls 应用数据写缓冲区的字节上限，`None` 允许无限缓冲。TLS 记录开销可超过该值；
    /// 握手输出、套接字和 PostgreSQL 缓冲区另行计算。
    pub send_buffer_limit: Option<NonZeroUsize>,
}

/// 握手实际协商并验证的 TLS 版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// 已建立 TLS 连接可公开观察的属性。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    pub version: TlsVersion,
    pub negotiation: TlsNegotiation,
    pub cipher_suite: CipherSuite,
    pub channel_binding_available: bool,
}

/// 可复用的 TLS 配置，由指定的证书信任根验证服务端。
#[derive(Clone)]
pub struct TlsConfig {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    options: TlsOptions,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("server_name", &self.server_name)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    /// 从 PEM 字节中解析一个或多个显式信任的 CA 证书。
    ///
    /// 可在进入请求 runtime 前读入证书文件。任何无效证书段都会返回错误。
    pub fn from_ca_pem(server_name: &str, pem: &[u8], options: TlsOptions) -> Result<Self, Error> {
        let certificates = CertificateDer::pem_slice_iter(pem).map(|certificate| {
            certificate
                .map_err(|error| Error::Io(io::Error::new(io::ErrorKind::InvalidInput, error)))
        });
        Self::with_trust_anchors(server_name, certificates, options)
    }

    /// 信任一个 DER 编码的 CA 证书。
    pub fn from_ca_der(
        server_name: &str,
        ca_der: &[u8],
        options: TlsOptions,
    ) -> Result<Self, Error> {
        Self::from_ca_certificates(server_name, [ca_der], options)
    }

    /// 信任给定的 DER 证书集合；任一根证书无效均返回错误。
    pub fn from_ca_certificates<I, B>(
        server_name: &str,
        certificates: I,
        options: TlsOptions,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        Self::with_trust_anchors(server_name, certificates.into_iter().map(Ok), options)
    }

    fn with_trust_anchors<B: AsRef<[u8]>>(
        server_name: &str,
        certificates: impl Iterator<Item = Result<B, Error>>,
        options: TlsOptions,
    ) -> Result<Self, Error> {
        let server_name = ServerName::try_from(server_name)
            .map_err(|_| Error::InvalidInput("the TLS server name is invalid"))?
            .to_owned();
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            let certificate = certificate?;
            roots
                .add(CertificateDer::from(certificate.as_ref()))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        }
        if roots.is_empty() {
            return Err(Error::InvalidInput(
                "at least one TLS trust anchor is required",
            ));
        }
        let accepted_versions: &[&rustls::SupportedProtocolVersion] = match options.versions {
            TlsVersions::Tls12 => &[&rustls::version::TLS12],
            TlsVersions::Tls13 => &[&rustls::version::TLS13],
            TlsVersions::Tls12Or13 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        };
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&TLS_PROVIDER))
            .with_protocol_versions(accepted_versions)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.resumption = options.resumption.new_store();
        config.enable_early_data = false;
        config.alpn_protocols = vec![POSTGRES_ALPN.to_vec()];
        Ok(Self {
            config: Arc::new(config),
            server_name,
            options,
        })
    }

    /// 服务端要求客户端认证时，提供叶证书在前的 PEM 证书链和唯一私钥。服务端验证和 PostgreSQL 认证策略继续生效。
    pub fn with_client_identity_pem(
        self,
        certificate_chain: &[u8],
        private_key: &[u8],
    ) -> Result<Self, Error> {
        let chain = CertificateDer::pem_slice_iter(certificate_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut keys = PrivateKeyDer::pem_slice_iter(private_key);
        let key = keys
            .next()
            .transpose()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
            .ok_or(Error::InvalidInput("a TLS client private key is required"))?;
        if keys.next().is_some() {
            return Err(Error::InvalidInput(
                "TLS client identity requires exactly one private key",
            ));
        }
        self.install_client_identity(chain, key)
    }

    /// 服务端要求时提供叶证书在前的 DER 证书链及 DER 私钥。支持 PKCS#1、PKCS#8 和 SEC1。
    pub fn with_client_identity_der<I, B>(
        self,
        certificate_chain: I,
        private_key: &[u8],
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let key = PrivateKeyDer::try_from(private_key).map_err(Error::InvalidInput)?;
        let chain = certificate_chain
            .into_iter()
            .map(|certificate| CertificateDer::from(certificate.as_ref()).into_owned())
            .collect();
        self.install_client_identity(chain, key.clone_key())
    }

    fn install_client_identity(
        mut self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Error> {
        if chain.is_empty() {
            return Err(Error::InvalidInput(
                "a TLS client certificate chain is required",
            ));
        }
        let identity = CertifiedKey::from_der(chain, key, self.config.crypto_provider())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = Arc::make_mut(&mut self.config);
        config.client_auth_cert_resolver = Arc::new(SingleCertAndKey::from(identity));
        // 变更客户端身份后使用独立的 TLS 恢复缓存。
        config.resumption = self.options.resumption.new_store();
        Ok(self)
    }

    pub fn options(&self) -> TlsOptions {
        self.options
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateDigest {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl CertificateDigest {
    /// RFC 5929 使用完整叶证书的 DER。只在实际选择 SCRAM-SHA-256-PLUS 后生成绑定数据。
    fn digest(self, der: &[u8]) -> Result<Vec<u8>, Error> {
        fn owned(bytes: &[u8]) -> Result<Vec<u8>, Error> {
            let mut digest = Vec::new();
            digest
                .try_reserve_exact(bytes.len())
                .map_err(|_| Error::Limit("cannot allocate TLS channel binding"))?;
            digest.extend_from_slice(bytes);
            Ok(digest)
        }
        match self {
            Self::Sha224 => owned(&Sha224::digest(der)),
            Self::Sha256 => owned(&Sha256::digest(der)),
            Self::Sha384 => owned(&Sha384::digest(der)),
            Self::Sha512 => owned(&Sha512::digest(der)),
        }
    }
}

fn digest_for_hash(algorithm: &Oid<'_>) -> Option<CertificateDigest> {
    if algorithm == &OID_HASH_SHA1
        || algorithm == &oid!(1.2.840.113549.2.5)
        || algorithm == &OID_NIST_HASH_SHA256
    {
        Some(CertificateDigest::Sha256)
    } else if algorithm == &oid!(2.16.840.1.101.3.4.2.4) {
        Some(CertificateDigest::Sha224)
    } else if algorithm == &OID_NIST_HASH_SHA384 {
        Some(CertificateDigest::Sha384)
    } else if algorithm == &OID_NIST_HASH_SHA512 {
        Some(CertificateDigest::Sha512)
    } else {
        None
    }
}

fn digest_for_signature(algorithm: &Oid<'_>) -> Option<CertificateDigest> {
    if algorithm == &OID_PKCS1_MD5WITHRSAENC
        || algorithm == &OID_MD5_WITH_RSA
        || algorithm == &OID_PKCS1_SHA1WITHRSA
        || algorithm == &OID_SHA1_WITH_RSA
        || algorithm == &OID_SIG_DSA_WITH_SHA1
        || algorithm == &oid!(1.2.840.10045.4.1)
        || algorithm == &OID_PKCS1_SHA256WITHRSA
        || algorithm == &OID_SIG_ECDSA_WITH_SHA256
        || algorithm == &oid!(2.16.840.1.101.3.4.3.2)
    {
        Some(CertificateDigest::Sha256)
    } else if algorithm == &OID_PKCS1_SHA224WITHRSA
        || algorithm == &OID_SIG_ECDSA_WITH_SHA224
        || algorithm == &oid!(2.16.840.1.101.3.4.3.1)
    {
        Some(CertificateDigest::Sha224)
    } else if algorithm == &OID_PKCS1_SHA384WITHRSA
        || algorithm == &OID_SIG_ECDSA_WITH_SHA384
        || algorithm == &oid!(2.16.840.1.101.3.4.3.3)
    {
        Some(CertificateDigest::Sha384)
    } else if algorithm == &OID_PKCS1_SHA512WITHRSA
        || algorithm == &OID_SIG_ECDSA_WITH_SHA512
        || algorithm == &oid!(2.16.840.1.101.3.4.3.4)
    {
        Some(CertificateDigest::Sha512)
    } else {
        None
    }
}

fn certificate_digest(der: &[u8]) -> Result<Option<CertificateDigest>, Error> {
    const INVALID_CERTIFICATE: Error =
        Error::Unsupported("the verified certificate cannot be parsed for channel binding");
    let (trailing, certificate) = Sequence::from_der(der).map_err(|_| INVALID_CERTIFICATE)?;
    // rustls 已验证叶证书。通道绑定只需签名算法，不解析证书主体中的属性、扩展和公钥。
    let (remaining, _) =
        Sequence::from_der(certificate.content.as_ref()).map_err(|_| INVALID_CERTIFICATE)?;
    let (remaining, algorithm) =
        AlgorithmIdentifier::from_der(remaining).map_err(|_| INVALID_CERTIFICATE)?;
    let (remaining, _) = BitString::from_der(remaining).map_err(|_| INVALID_CERTIFICATE)?;
    if !trailing.is_empty() || !remaining.is_empty() {
        return Err(Error::InvalidInput(
            "the channel binding certificate has trailing data",
        ));
    }
    let digest = if algorithm.algorithm == OID_PKCS1_RSASSAPSS {
        let SignatureAlgorithm::RSASSA_PSS(parameters) = SignatureAlgorithm::try_from(&algorithm)
            .map_err(|_| {
            Error::Unsupported("the certificate has unsupported RSA-PSS parameters")
        })?
        else {
            return Err(Error::Unsupported(
                "the certificate has unsupported RSA-PSS parameters",
            ));
        };
        digest_for_hash(parameters.hash_algorithm_oid())
    } else {
        digest_for_signature(&algorithm.algorithm)
    };
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::oid_registry::OID_SIG_ED25519;

    const SHA256_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/sha256.pem");
    const SHA384_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/sha384.pem");
    const PSS_SHA384_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/pss-sha384.pem");

    fn options(negotiation: TlsNegotiation, versions: TlsVersions) -> TlsOptions {
        TlsOptions {
            negotiation,
            versions,
            resumption: TlsResumption::Disabled,
            send_buffer_limit: None,
        }
    }

    #[test]
    fn valid_configuration_fixes_roots_versions_and_alpn_without_early_data() {
        for versions in [
            TlsVersions::Tls12,
            TlsVersions::Tls13,
            TlsVersions::Tls12Or13,
        ] {
            let selected = TlsOptions {
                resumption: TlsResumption::InMemory,
                send_buffer_limit: NonZeroUsize::new(64 * 1024),
                ..options(TlsNegotiation::Direct, versions)
            };
            let config = TlsConfig::from_ca_pem("localhost", SHA256_PEM, selected)
                .expect("build verified TLS configuration");
            assert_eq!(config.options(), selected);
            assert!(Arc::ptr_eq(config.config.crypto_provider(), &TLS_PROVIDER));
            assert_eq!(config.config.alpn_protocols, [POSTGRES_ALPN]);
            assert!(!config.config.enable_early_data);
            let der = CertificateDer::from_pem_slice(SHA256_PEM).expect("parse public CA");
            assert!(
                TlsConfig::from_ca_der(
                    "127.0.0.1",
                    der.as_ref(),
                    options(TlsNegotiation::SslRequest, versions),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn endpoint_binding_hashes_full_der_and_decodes_rsa_pss_hash_parameters() {
        let sha256 = CertificateDer::from_pem_slice(SHA256_PEM).expect("parse SHA256 certificate");
        assert_eq!(
            certificate_digest(sha256.as_ref())
                .unwrap()
                .unwrap()
                .digest(sha256.as_ref())
                .unwrap(),
            Sha256::digest(sha256.as_ref()).as_slice()
        );
        for pem in [SHA384_PEM, PSS_SHA384_PEM] {
            let certificate =
                CertificateDer::from_pem_slice(pem).expect("parse SHA384 certificate");
            let binding = certificate_digest(certificate.as_ref())
                .expect("binding")
                .expect("supported certificate digest")
                .digest(certificate.as_ref())
                .unwrap();
            assert_eq!(binding, Sha384::digest(certificate.as_ref()).to_vec());
            assert_eq!(binding.len(), 48);
            let mut trailing = certificate.as_ref().to_vec();
            trailing.push(0);
            assert!(certificate_digest(&trailing).is_err());
        }
    }

    #[test]
    fn an_invalid_root_is_not_silently_ignored_after_a_valid_root() {
        let valid = CertificateDer::from_pem_slice(SHA256_PEM).expect("parse CA");
        assert!(
            TlsConfig::from_ca_certificates(
                "localhost",
                [valid.as_ref(), b"invalid DER"],
                options(TlsNegotiation::SslRequest, TlsVersions::Tls12Or13),
            )
            .is_err()
        );
        assert!(
            TlsConfig::from_ca_pem(
                "bad server name",
                SHA256_PEM,
                options(TlsNegotiation::Direct, TlsVersions::Tls13),
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_digest_upgrades_weak_hashes_without_guessing_pure_signatures() {
        assert_eq!(
            digest_for_signature(&OID_PKCS1_SHA1WITHRSA),
            Some(CertificateDigest::Sha256)
        );
        assert_eq!(
            digest_for_signature(&OID_PKCS1_MD5WITHRSAENC),
            Some(CertificateDigest::Sha256)
        );
        assert_eq!(
            digest_for_signature(&OID_SIG_ECDSA_WITH_SHA384),
            Some(CertificateDigest::Sha384)
        );
        assert_eq!(
            digest_for_signature(&OID_PKCS1_SHA512WITHRSA),
            Some(CertificateDigest::Sha512)
        );
        assert_eq!(digest_for_signature(&OID_SIG_ED25519), None);
        assert_eq!(
            digest_for_hash(&OID_HASH_SHA1),
            Some(CertificateDigest::Sha256)
        );
        assert!(certificate_digest(b"not a DER certificate").is_err());
    }

    #[test]
    fn configurations_reject_missing_roots_bad_der_and_invalid_names() {
        assert!(
            TlsConfig::from_ca_pem(
                "localhost",
                b"",
                options(TlsNegotiation::SslRequest, TlsVersions::Tls12Or13),
            )
            .is_err()
        );
        assert!(
            TlsConfig::from_ca_der(
                "localhost",
                b"bad",
                options(TlsNegotiation::Direct, TlsVersions::Tls13),
            )
            .is_err()
        );
        assert!(
            TlsConfig::from_ca_certificates(
                "bad server name",
                std::iter::empty::<&[u8]>(),
                options(TlsNegotiation::Direct, TlsVersions::Tls13),
            )
            .is_err()
        );
    }
}
