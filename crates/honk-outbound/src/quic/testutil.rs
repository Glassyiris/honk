//! In-process QUIC test servers: self-signed certs plus endpoint builders
//! shared by the TUIC and Juicity handler tests.

use std::sync::Arc;

use anyhow::anyhow;
use quinn::{ServerConfig, TransportConfig};

/// Build a quinn server config with a freshly generated self-signed
/// certificate (valid for `localhost`) and the given ALPN list.
///
/// When `datagrams` is false the server does not advertise QUIC datagram
/// support, which exercises the UDP-over-stream fallback of clients.
pub fn server_config(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
    server_config_with_cert(alpn, datagrams).map(|(config, _)| config)
}

/// [`server_config`] that also returns the leaf certificate DER (for
/// pinSHA256 tests).
pub fn server_config_with_cert(
    alpn: &[&[u8]],
    datagrams: bool,
) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    server_config_impl(alpn, datagrams, false)
}

/// [`server_config`] restricted to TLS 1.3 ChaCha20-Poly1305, forcing the
/// peer onto the ChaCha20 header-protection path.
pub fn server_config_chacha20(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
    server_config_impl(alpn, datagrams, true).map(|(config, _)| config)
}

fn server_config_impl(
    alpn: &[&[u8]],
    datagrams: bool,
    chacha20_only: bool,
) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    if chacha20_only {
        // ChaCha20 first so the handshake negotiates it; AES-128 stays
        // because quinn derives QUIC initial keys from it.
        provider.cipher_suites = vec![
            tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ];
    }
    let mut tls_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("TLS protocol versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                signing_key.serialize_der().into(),
            ),
        )
        .map_err(|e| anyhow!("TLS server config: {e}"))?;
    if chacha20_only {
        // rustls defaults to client order; honk's BoringSSL client offers
        // AES first, so the suite restriction alone is not enough.
        tls_config.ignore_client_order = true;
    }
    tls_config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow!("rustls server config is not QUIC-compatible: {e}"))?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    if !datagrams {
        let mut transport = TransportConfig::default();
        transport.datagram_receive_buffer_size(None);
        config.transport_config(Arc::new(transport));
    }
    Ok((config, cert.der().to_vec()))
}

/// Start a QUIC server endpoint on a loopback ephemeral port.
pub fn server_endpoint(
    alpn: &[&[u8]],
    datagrams: bool,
) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
    let endpoint = quinn::Endpoint::server(
        server_config(alpn, datagrams)?,
        "127.0.0.1:0".parse().expect("hardcoded bind address"),
    )?;
    let addr = endpoint.local_addr()?;
    Ok((endpoint, addr))
}

/// [`server_endpoint`] restricted to ChaCha20-Poly1305.
pub fn server_endpoint_chacha20(
    alpn: &[&[u8]],
    datagrams: bool,
) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
    let endpoint = quinn::Endpoint::server(
        server_config_chacha20(alpn, datagrams)?,
        "127.0.0.1:0".parse().expect("hardcoded bind address"),
    )?;
    let addr = endpoint.local_addr()?;
    Ok((endpoint, addr))
}
