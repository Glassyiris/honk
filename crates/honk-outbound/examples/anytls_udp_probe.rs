//! Dump the first datagrams received through an anytls (or other) node's
//! UDP relay after sending a probe DNS query — for debugging UoT framing
//! against third-party servers.
//!
//! Usage: anytls_udp_probe <share-link> [dns-server-addr] [payload-bytes]
//! With `payload-bytes` the probe sends a zero-filled datagram of that
//! size instead (point it at a UDP echo server) to exercise datagram
//! fragmentation/reassembly beyond a single QUIC datagram.

use std::net::SocketAddr;
use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::proxy::ProxyRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share-link");
    let dns_server: SocketAddr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "8.8.8.8:53".to_string())
        .parse()?;
    let payload_bytes: Option<usize> = std::env::args().nth(3).and_then(|v| v.parse().ok());

    let node = Node::from_share_link(&link)?;
    let registry = ProxyRegistry::default_resolver()?;

    let transport = registry
        .dial_udp_transport(&node, dns_server, None, Duration::from_secs(10))
        .await?;

    // Minimal DNS query: id 0x1234, RD, google.com A IN.
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["google", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    if let Some(n) = payload_bytes {
        query = vec![0xAB; n];
    }

    transport.send_packet(&query).await?;
    println!("sent {} bytes via {}", query.len(), transport.relay_addr());

    let mut buf = vec![0u8; 65536];
    for i in 0..3 {
        match tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let hex: String = buf[..n.min(64)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("pkt{i}: n={n} src={src} hex={hex}");
            }
            Ok(Err(e)) => {
                println!("pkt{i}: recv error: {e}");
                break;
            }
            Err(_) => {
                println!("pkt{i}: timeout");
                break;
            }
        }
    }
    Ok(())
}
