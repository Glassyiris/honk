use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use super::RelayStats;

/// UDP relay session: forwards datagrams bidirectionally between a client
/// (via shared TPROXY socket) and a proxy server.
///
/// Each UDP "connection" is identified by (client_addr, original_dst).
/// Since UDP is connectionless, we use an idle timeout to clean up sessions.
pub async fn relay_udp(
    client_socket: Arc<UdpSocket>,
    proxy_socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    initial_data: Vec<u8>,
) -> anyhow::Result<RelayStats> {
    let start = tokio::time::Instant::now();
    info!(
        "UDP relay started: {} -> {} via {}",
        client_addr, target_addr, relay_addr
    );

    proxy_socket.send_to(&initial_data, relay_addr).await?;
    let mut client_to_proxy: u64 = initial_data.len() as u64;
    let mut proxy_to_client: u64 = 0;
    let mut datagrams_forwarded: u64 = 1;

    let mut proxy_buf = vec![0u8; 65536];
    let mut client_buf = vec![0u8; 65536];

    let idle_timeout = tokio::time::Duration::from_secs(60);

    loop {
        tokio::select! {
            result = proxy_socket.recv_from(&mut proxy_buf) => {
                match result {
                    Ok((n, src)) if src == relay_addr => {
                        client_socket.send_to(&proxy_buf[..n], client_addr).await?;
                        proxy_to_client += n as u64;
                        datagrams_forwarded += 1;
                        debug!("UDP relay: proxy->client {} bytes", n);
                    }
                    Ok((_n, src)) => {
                        warn!("UDP relay: unexpected datagram from {}", src);
                    }
                    Err(e) => {
                        warn!("UDP relay recv error from proxy: {}", e);
                        break;
                    }
                }
            }
            result = client_socket.recv_from(&mut client_buf) => {
                match result {
                    Ok((n, src)) if src == client_addr => {
                        proxy_socket.send_to(&client_buf[..n], relay_addr).await?;
                        client_to_proxy += n as u64;
                        datagrams_forwarded += 1;
                        debug!("UDP relay: client->proxy {} bytes", n);
                    }
                    Ok((_n, src)) => {
                        warn!("UDP relay: unexpected datagram from {}", src);
                    }
                    Err(e) => {
                        warn!("UDP relay recv error from client: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(idle_timeout) => {
                debug!("UDP relay: idle timeout for {} -> {}", client_addr, target_addr);
                break;
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let stats = RelayStats {
        client_to_proxy,
        proxy_to_client,
        total_bytes: client_to_proxy + proxy_to_client,
        duration_ms,
    };

    info!(
        "UDP relay complete: {} -> {} ({} bytes, {} datagrams in {}ms)",
        client_addr, target_addr, stats.total_bytes, datagrams_forwarded, duration_ms
    );

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdp;

    #[tokio::test]
    async fn test_relay_udp_bidirectional() {
        let proxy_listener = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let client_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let client_addr = client_socket.local_addr().unwrap();

        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();

        let relay_client = client_socket.clone();
        let relay_proxy = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());

        let relay_handle = tokio::spawn(async move {
            relay_udp(
                relay_client,
                relay_proxy,
                proxy_addr,
                client_addr,
                target,
                b"INITIAL_DGRAM".to_vec(),
            )
            .await
        });

        let mut buf = [0u8; 65536];
        let (n, src) = proxy_listener.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"INITIAL_DGRAM");

        proxy_listener
            .send_to(b"RESPONSE_DGRAM", src)
            .await
            .unwrap();

        let (n, _) = client_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"RESPONSE_DGRAM");

        client_socket
            .send_to(b"SECOND_DGRAM", client_addr)
            .await
            .unwrap();

        let (n, _) = proxy_listener.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"SECOND_DGRAM");

        drop(client_socket);
        let stats = relay_handle.await.unwrap().unwrap();
        assert!(stats.client_to_proxy > 0);
        assert!(stats.proxy_to_client > 0);
    }
}
