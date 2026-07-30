use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;

#[tokio::test]
async fn test_udp_query() {
    let response = mock_dns_response(0x1234);
    let response_clone = response.clone();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, source) = server.recv_from(&mut buffer).await.unwrap();
        assert!(length > 0);
        server.send_to(&response_clone, source).await.unwrap();
    });

    let upstream = make_upstream("test-udp", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("test-udp", &mock_dns_query(0x1234))
        .await
        .expect("UDP query should succeed");

    assert_eq!(result, response);
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_tcp_query_pooled() {
    let response = mock_dns_response(0x5678);
    let response_clone = response.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let mut length_buffer = [0_u8; 2];
            stream.read_exact(&mut length_buffer).await.unwrap();
            let query_length = usize::from(u16::from_be_bytes(length_buffer));
            let mut query_buffer = vec![0_u8; query_length];
            stream.read_exact(&mut query_buffer).await.unwrap();
            assert!(!query_buffer.is_empty());

            let response_length = u16::try_from(response_clone.len()).unwrap();
            stream
                .write_all(&response_length.to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response_clone).await.unwrap();
        }
    });

    let upstream = make_upstream("test-tcp", &server_address.to_string(), DnsProtocol::Tcp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let query = mock_dns_query(0x5678);
    let first = pool.query("test-tcp", &query).await.expect("TCP query 1");
    let second = pool.query("test-tcp", &query).await.expect("TCP query 2");
    assert_eq!(first, response);
    assert_eq!(second, response);
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_udp_hedged_retry_on_loss() {
    let response = mock_dns_response(0x1234);
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let response_clone = response.clone();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let _ = server.recv_from(&mut buffer).await.unwrap();
        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        server.send_to(&response_clone, source).await.unwrap();
    });

    let upstream = make_upstream("hedged", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("hedged", &mock_dns_query(0x1234))
        .await
        .expect("hedged retry should succeed");
    assert_eq!(result, response);
}

#[tokio::test]
async fn test_udp_txid_mismatch_discarded() {
    let wrong = mock_dns_response(0x9999);
    let right = mock_dns_response(0x1234);
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let right_clone = right.clone();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        server.send_to(&wrong, source).await.unwrap();
        server.send_to(&right_clone, source).await.unwrap();
    });

    let upstream = make_upstream("txid", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("txid", &mock_dns_query(0x1234))
        .await
        .expect("query should succeed");
    assert_eq!(result, right);
}

#[tokio::test]
async fn test_udp_truncated_answer_upgrades_to_tcp() {
    let mut truncated = mock_dns_response(0x1234);
    truncated[2] |= 0x02;
    let full = mock_dns_response(0x1234);
    let udp_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp_server.local_addr().unwrap();
    let tcp_listener = TcpListener::bind(address).await.unwrap();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, source) = udp_server.recv_from(&mut buffer).await.unwrap();
        udp_server.send_to(&truncated, source).await.unwrap();
    });
    let full_clone = full.clone();
    tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        let mut length_buffer = [0_u8; 2];
        stream.read_exact(&mut length_buffer).await.unwrap();
        let query_length = usize::from(u16::from_be_bytes(length_buffer));
        let mut query_buffer = vec![0_u8; query_length];
        stream.read_exact(&mut query_buffer).await.unwrap();
        let response_length = u16::try_from(full_clone.len()).unwrap();
        stream
            .write_all(&response_length.to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&full_clone).await.unwrap();
    });

    let upstream = make_upstream("tc", &address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("tc", &mock_dns_query(0x1234))
        .await
        .expect("TC upgrade should succeed");
    assert_eq!(result, full);
}

#[test]
fn parses_encrypted_upstream_at_construction() {
    let upstreams = [
        make_upstream("dot", "dns.google", DnsProtocol::Tls),
        make_upstream("doh", "cloudflare-dns.com/dns-query", DnsProtocol::Https),
        make_upstream("doq", "dns.adguard.com", DnsProtocol::Quic),
        make_upstream("h3", "cloudflare-dns.com/dns-query", DnsProtocol::H3),
    ];
    let pool = UpstreamPool::new(&upstreams, make_router()).unwrap();
    assert_eq!(pool.upstream_count(), 4);
}
