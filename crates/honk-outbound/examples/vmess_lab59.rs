//! VMess AEAD interop probe against the lab server (sing-box 1.13 vmess
//! inbounds): 10.10.10.59:8446 (bare TCP) and 10.10.10.59:8445
//! (ws+tls, self-signed cert, skip verify). Tunnels an HTTP/1.1 GET to
//! www.gstatic.com:80 through the node and expects a real HTTP reply.
//!
//! Run: cargo run -p honk-outbound --features rprx --example vmess_lab59

use std::time::Duration;

use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::proxy::TcpOutbound;
use honk_outbound::proxy::vmess::VmessHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "10.10.10.59";
const UUID_TCP: &str = "82166345-d1bb-48f8-bd3b-cf0c152a863c";
const UUID_WS: &str = "216b9040-3f89-4103-b4d6-5f013ee0b1c4";
const TARGET_HOST: &str = "www.gstatic.com";
const TARGET_PORT: u16 = 80;

fn node(port: u16, uuid: &str, ws_tls: bool) -> Node {
    Node {
        name: format!("lab59-{port}"),
        protocol: NodeProtocol::VMess,
        address: format!("{HOST}:{port}"),
        host: HOST.into(),
        port,
        password: Some(uuid.into()),
        transport: if ws_tls { "ws".into() } else { "tcp".into() },
        tls: ws_tls,
        sni: ws_tls.then(|| "test.local".into()),
        skip_cert_verify: ws_tls,
        ws_path: ws_tls.then(|| "/vmess".into()),
        ..Default::default()
    }
}

async fn probe(node: &Node) -> anyhow::Result<()> {
    let target: std::net::SocketAddr = format!("93.184.216.34:{TARGET_PORT}").parse().unwrap();
    let mut ps = VmessHandler::new()
        .dial(node, target, Some(TARGET_HOST), Duration::from_secs(10))
        .await?;
    println!("[+] dial {} OK (request header sent)", node.name);

    ps.stream
        .write_all(
            format!(
                "GET /generate_204 HTTP/1.1\r\nHost: {TARGET_HOST}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    ps.stream.flush().await?;
    println!("[+] payload written, reading response");

    let mut resp = Vec::new();
    ps.stream
        .take(8192)
        .read_to_end(&mut resp)
        .await
        .map_err(|e| anyhow::anyhow!("payload relay broken: {e}"))?;
    let text = String::from_utf8_lossy(&resp);
    let status = text.lines().next().unwrap_or("");
    anyhow::ensure!(status.starts_with("HTTP/"), "unexpected response: {text:?}");
    println!("[+] {} tunnel OK: {status}", node.name);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Optional: vmess_lab59 [8446|8445|all]
    let which = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let timeout = Duration::from_secs(20);
    if which == "8446" || which == "all" {
        tokio::time::timeout(timeout, probe(&node(8446, UUID_TCP, false))).await??;
    }
    if which == "8445" || which == "all" {
        tokio::time::timeout(timeout, probe(&node(8445, UUID_WS, true))).await??;
    }
    println!("VMess lab59 interop: PASS");
    Ok(())
}
