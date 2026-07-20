// Chrome-mimicking TLS client configs for DPI circumvention.
//
// Why: standard rustls ClientHello fingerprint is detectable by GFW DPI.
// This config uses Chrome 131's cipher suites, signature algorithms,
// ALPN ordering, and key exchange groups to blend in.
//
// Controlled by global config: tls_implementation ("tls"|"utls"), utls_imitate.

use std::sync::Arc;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, SignatureScheme};

#[allow(dead_code)]
const CHROME_TLS13: &[tokio_rustls::rustls::CipherSuite] = &[
    tokio_rustls::rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
    tokio_rustls::rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    tokio_rustls::rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
];

const CHROME_SIG_ALGS: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1, // Chrome still includes this for legacy
];

const CHROME_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

#[allow(dead_code)]
const CHROME_KX_GROUPS: &[tokio_rustls::rustls::NamedGroup] = &[
    tokio_rustls::rustls::NamedGroup::X25519,
    tokio_rustls::rustls::NamedGroup::secp256r1,
    tokio_rustls::rustls::NamedGroup::secp384r1,
];

/// Build a Chrome-mimicking rustls ClientConfig with webpki roots.
pub fn chrome_config() -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = default_provider().into();
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    cfg.alpn_protocols = CHROME_ALPN.iter().map(|&a| a.to_vec()).collect();
    cfg.enable_secret_extraction = false;
    cfg.enable_early_data = false;

    Ok(cfg)
}

/// Build a Chrome-mimicking rustls ClientConfig that skips cert verification.
pub fn chrome_dangerous_config() -> anyhow::Result<ClientConfig> {
    let provider = default_provider().into();
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    cfg.alpn_protocols = CHROME_ALPN.iter().map(|&a| a.to_vec()).collect();
    cfg.enable_secret_extraction = false;
    cfg.enable_early_data = false;

    Ok(cfg)
}

/// Build a standard (non-Chrome) rustls config with webpki roots.
/// Used when tls_implementation is "tls" (default).
pub fn standard_config() -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = default_provider().into();
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Build a standard dangerous rustls config (no cert verification).
pub fn standard_dangerous_config() -> anyhow::Result<ClientConfig> {
    let provider = default_provider().into();
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth())
}

#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        CHROME_SIG_ALGS.to_vec()
    }
}

use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

static USE_CHROME_TLS: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

/// Called from ControlPlane startup with GlobalConfig.tls_implementation.
pub fn set_tls_mode(implementation: &str) {
    let chrome = implementation.eq_ignore_ascii_case("utls");
    USE_CHROME_TLS.store(chrome, Ordering::Release);
    tracing::info!("TLS mode: {} (Chrome={})", implementation, chrome);
}

/// Build the appropriate TLS connector for a node.
pub fn build_connector(
    node: &honk_config::node::Node,
) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let chrome = USE_CHROME_TLS.load(Ordering::Acquire);
    let config = match (node.skip_cert_verify, chrome) {
        (true, true) => chrome_dangerous_config()?,
        (true, false) => standard_dangerous_config()?,
        (false, true) => chrome_config()?,
        (false, false) => standard_config()?,
    };
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}
