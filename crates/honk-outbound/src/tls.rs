//! BoringSSL TLS client — real Chrome fingerprint (uTLS-grade) + ECH.
//!
//! Why: a rustls ClientHello is trivially fingerprinted by DPI. BoringSSL is
//! what Chrome itself ships, so a properly configured BoringSSL ClientHello
//! matches Chrome's: GREASE, permuted extensions, the X25519MLKEM768 hybrid
//! key share, ALPS, brotli certificate compression, and ECH GREASE.
//!
//! ECH: when a node carries an ECHConfigList (`ech_config` / `ech_config_path`)
//! the connector offers real ECH via `SSL_set1_ech_config_list`; without one,
//! Chrome mode sends ECH GREASE like a real browser.
//!
//! Controlled by global config: tls_implementation ("tls"|"utls"), utls_imitate.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use base64::Engine;
use base64::engine::general_purpose;
use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslMethod, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use boring::x509::store::X509StoreBuilder;
use foreign_types::ForeignTypeRef;
use honk_config::node::Node;

/// TLS client stream produced by [`TlsConnector::connect`].
pub type TlsStream<S> = tokio_boring::SslStream<S>;

// Chrome's TLS 1.3 signature-algorithm list (order matters).
pub(crate) const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
     ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
     rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
// Chrome 131+: MLKEM hybrid first. Requires boring's `mlkem` feature.
pub(crate) const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";
const CHROME_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";

// BoringSSL group IDs (ssl.h) for SSL_set1_client_key_shares: Chrome sends
// exactly two shares, MLKEM hybrid then X25519.
const SSL_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const SSL_GROUP_X25519: u16 = 29;

/// Brotli certificate-compression algorithm (RFC 8879), as advertised by Chrome.
pub(crate) struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        // write_all + drop finalizes the brotli stream (same pattern as
        // boring's own cert-compression tests).
        let mut writer = brotli::CompressorWriter::new(output, 4096, 5, 22);
        io::Write::write_all(&mut writer, input)
    }

    fn decompress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut reader = brotli::Decompressor::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }
}

/// BoringSSL connector carrying per-node ECH settings and the global
/// fingerprint mode. Clone-cheap (Arc inside); build once per node.
#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    chrome: bool,
    ech_config_list: Option<Arc<Vec<u8>>>,
}

impl TlsConnector {
    /// Per-connection `Ssl` configuration: applies the parts of the Chrome
    /// profile that only exist per-SSL (permuted extensions, key shares,
    /// ALPS, ECH) — BoringSSL has no ctx-level API for these.
    fn configuration(&self) -> anyhow::Result<ConnectConfiguration> {
        let mut cfg = self.connector.configure()?;
        if self.chrome {
            cfg.set_permute_extensions(true);
            set_chrome_key_shares(&mut cfg)?;
            add_chrome_alps(&mut cfg)?;
        }
        match &self.ech_config_list {
            Some(list) => cfg.set_ech_config_list(list)?,
            // Real Chrome always GREASEs ECH when it holds no ECH keys.
            None if self.chrome => cfg.set_enable_ech_grease(true),
            None => {}
        }
        Ok(cfg)
    }

    /// TLS client handshake over `stream`, verifying the peer against
    /// `domain` (unless the node skips verification).
    pub async fn connect<S>(&self, domain: &str, stream: S) -> anyhow::Result<TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let cfg = self.configuration()?;
        match tokio_boring::connect(cfg, domain, stream).await {
            Ok(stream) => {
                if self.ech_config_list.is_some() {
                    tracing::debug!(
                        ech_accepted = stream.ssl().ech_accepted(),
                        sni = domain,
                        "TLS handshake completed"
                    );
                }
                Ok(stream)
            }
            Err(e) => {
                // ECH rejection: the server may hand us fresh retry configs.
                // NB: SSL_get0_ech_retry_configs asserts unless the failure
                // reason really is ECH_REJECTED — gate on the error text.
                let rejected = e.to_string().contains("ECH_REJECTED");
                if rejected
                    && let Some(ssl) = e.ssl()
                    && ssl.get_ech_retry_configs().is_some()
                {
                    tracing::info!(
                        sni = domain,
                        "ECH rejected; server offered retry ECH configs (not persisted)"
                    );
                }
                Err(anyhow::anyhow!("TLS handshake with {domain} failed: {e}"))
            }
        }
    }

    /// Underlying BoringSSL connector (for QUIC-side reuse of the ctx).
    pub fn boring_connector(&self) -> &SslConnector {
        &self.connector
    }
}

/// Chrome sends two key shares: X25519MLKEM768 and X25519, in that order.
/// boring exposes this only via FFI.
fn set_chrome_key_shares(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    set_chrome_key_shares_ssl_ref(ssl)
}

/// Same as [`set_chrome_key_shares`] for a bare `Ssl` (QUIC path).
pub(crate) fn set_chrome_key_shares_ssl(ssl: &boring::ssl::Ssl) -> anyhow::Result<()> {
    set_chrome_key_shares_ssl_ref(ssl)
}

fn set_chrome_key_shares_ssl_ref(ssl: &boring::ssl::SslRef) -> anyhow::Result<()> {
    let shares = [SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    Ok(())
}

/// Chrome sends ALPS for h2 with an empty settings payload whenever ALPN
/// offers h2. boring exposes this only via FFI.
fn add_chrome_alps(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    let ok = unsafe {
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_add_application_settings");
    }
    Ok(())
}

/// Mozilla root CAs (full DER certs) loaded into a BoringSSL store.
pub(crate) fn root_store() -> Result<boring::x509::store::X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            builder.add_cert(cert)?;
        }
    }
    Ok(builder.build())
}

/// Decode a base64 ECHConfigList (standard or URL-safe, padded or not).
fn decode_ech_config_list(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = encoded.trim();
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::STANDARD_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("invalid base64 ECHConfigList")
}

/// Resolve the node's ECHConfigList, if any. Explicit `ech_config` wins over
/// `ech_config_path`. `ech_enabled` without configs only gates GREASE-free
/// behavior in non-Chrome mode and is a no-op until DNS HTTPS-RR lookup lands.
pub fn load_ech_config_list(node: &Node) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(encoded) = &node.ech_config {
        return decode_ech_config_list(encoded)
            .map(Some)
            .with_context(|| format!("node {}: ech_config", node.name));
    }
    if let Some(path) = &node.ech_config_path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("node {}: read {path}", node.name))?;
        return decode_ech_config_list(&contents)
            .map(Some)
            .with_context(|| format!("node {}: ech_config_path", node.name));
    }
    Ok(None)
}

static USE_CHROME_TLS: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

/// Called from ControlPlane startup with GlobalConfig.tls_implementation.
pub fn set_tls_mode(implementation: &str) {
    let chrome = implementation.eq_ignore_ascii_case("utls");
    USE_CHROME_TLS.store(chrome, Ordering::Release);
    tracing::info!(
        "TLS mode: {} (Chrome fingerprint={})",
        implementation,
        chrome
    );
}

/// Chrome fingerprint active (global `tls_implementation: utls`).
pub fn chrome_mode() -> bool {
    USE_CHROME_TLS.load(Ordering::Acquire)
}

/// Build the TLS connector for a node: BoringSSL with webpki roots,
/// optional real Chrome fingerprint, optional ECH.
fn base_builder(skip_cert_verify: bool) -> anyhow::Result<boring::ssl::SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    if skip_cert_verify {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_verify_cert_store(root_store()?)?;
    }
    Ok(builder)
}

fn apply_chrome_ctx(builder: &mut boring::ssl::SslConnectorBuilder) -> anyhow::Result<()> {
    builder.set_grease_enabled(true);
    builder.set_sigalgs_list(CHROME_SIGALGS)?;
    builder.set_curves_list(CHROME_CURVES)?;
    builder.add_certificate_compression_algorithm(BrotliCertCompression)?;
    Ok(())
}

pub fn build_connector(node: &Node) -> anyhow::Result<TlsConnector> {
    let chrome = chrome_mode();
    let ech_config_list = load_ech_config_list(node)?;

    let mut builder = base_builder(node.skip_cert_verify)?;
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
    }

    Ok(TlsConnector {
        connector: builder.build(),
        chrome,
        ech_config_list: ech_config_list.map(Arc::new),
    })
}

/// BoringSSL connector for DNS upstreams (DoT/DoH): caller-chosen ALPN,
/// webpki verification, the global Chrome fingerprint mode applies.
pub fn build_dns_connector(
    skip_cert_verify: bool,
    alpn_wire: &[u8],
) -> anyhow::Result<TlsConnector> {
    let chrome = chrome_mode();
    let mut builder = base_builder(skip_cert_verify)?;
    if chrome {
        apply_chrome_ctx(&mut builder)?;
    }
    builder.set_alpn_protos(alpn_wire)?;
    Ok(TlsConnector {
        connector: builder.build(),
        chrome,
        ech_config_list: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslStream};
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    /// rcgen self-signed server cert (PEM) for loopback handshakes.
    fn server_cert() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn spawn_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        (port, handle)
    }

    async fn loopback_connect(
        node: &Node,
        chrome: bool,
        port: u16,
    ) -> anyhow::Result<TlsStream<tokio::net::TcpStream>> {
        set_tls_mode(if chrome { "utls" } else { "tls" });
        let connector = build_connector(node)?;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        connector.connect("localhost", tcp).await
    }

    fn test_node() -> Node {
        Node {
            skip_cert_verify: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn handshake_standard_and_chrome() {
        for chrome in [false, true] {
            let (cert, key) = server_cert();
            let (port, server) = spawn_server(&cert, &key);
            let mut stream = loopback_connect(&test_node(), chrome, port)
                .await
                .unwrap_or_else(|e| panic!("chrome={chrome}: {e:?}"));
            use tokio::io::AsyncWriteExt;
            stream.write_all(b"ping").await.unwrap();
            stream.shutdown().await.unwrap();
            let received = server.join().unwrap();
            assert_eq!(received, b"ping", "chrome={chrome}");
        }
    }

    #[tokio::test]
    async fn ech_grease_does_not_break_handshake() {
        // Chrome mode with no ECH config sends ECH GREASE; servers must ignore it.
        let (cert, key) = server_cert();
        let (port, server) = spawn_server(&cert, &key);
        let mut stream = loopback_connect(&test_node(), true, port).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(server.join().unwrap(), b"ok");
    }

    /// Spawn a server holding real ECH keys (boring test fixtures:
    /// public_name ech.com, DHKEM-P256-SHA256).
    fn spawn_ech_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
        use boring::hpke::HpkeKey;
        use boring::ssl::SslEchKeys;

        static ECH_CONFIG: &[u8] = include_bytes!("../tests/fixtures/echconfig");
        static ECH_KEY: &[u8] = include_bytes!("../tests/fixtures/echkey");

        // NB: boring's mozilla_intermediate/_modern set NO_TLSV1_3; ECH needs
        // TLS 1.3, so use the v5 profile (1.2+1.3) and pin 1.3.
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();

        let key = HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap();
        let mut ech_keys = SslEchKeys::builder().unwrap();
        ech_keys.add_key(true, ECH_CONFIG, key).unwrap();
        acceptor.set_ech_keys(&ech_keys.build()).unwrap();

        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        (port, handle)
    }

    /// Full ECH round-trip: client offers real ECH, server decrypts it,
    /// `ech_accepted()` must report true.
    #[tokio::test]
    async fn ech_accepted_end_to_end() {
        static ECH_CONFIG_LIST: &[u8] = include_bytes!("../tests/fixtures/echconfiglist");
        let node = Node {
            skip_cert_verify: true,
            ech_enabled: true,
            ech_config: Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST)),
            ..Default::default()
        };
        let (cert, key) = server_cert();
        let (port, server) = spawn_ech_server(&cert, &key);
        let mut stream = loopback_connect(&node, true, port).await.unwrap();
        assert!(stream.ssl().ech_accepted(), "ECH must be accepted");
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(server.join().unwrap(), b"ok");
    }

    /// Real ECH against a server with NO ECH keys fails closed
    /// (`ECH_REJECTED`): BoringSSL refuses to complete a handshake whose ECH
    /// offer was not confirmed, per RFC anti-downgrade rules. Proves the
    /// config list is actually parsed and offered.
    #[tokio::test]
    async fn ech_rejected_when_server_lacks_keys() {
        static ECH_CONFIG_LIST: &[u8] = include_bytes!("../tests/fixtures/echconfiglist");
        let node = Node {
            skip_cert_verify: true,
            ech_enabled: true,
            ech_config: Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST)),
            ..Default::default()
        };
        let (cert, key) = server_cert();
        let (port, _server) = spawn_server(&cert, &key);
        let err = loopback_connect(&node, true, port)
            .await
            .expect_err("handshake must fail when ECH is not accepted");
        let msg = format!("{err:?}");
        assert!(msg.contains("ECH_REJECTED"), "unexpected error: {msg}");
    }

    #[test]
    fn decode_ech_base64_variants() {
        let raw = b"\xff\x00abc";
        for encoded in [
            general_purpose::STANDARD.encode(raw),
            general_purpose::URL_SAFE.encode(raw),
            general_purpose::URL_SAFE_NO_PAD.encode(raw),
        ] {
            assert_eq!(decode_ech_config_list(&encoded).unwrap(), raw);
        }
        assert!(decode_ech_config_list("!!!not-base64!!!").is_err());
    }
}
