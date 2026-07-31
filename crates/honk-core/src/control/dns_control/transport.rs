use super::DnsController;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

impl DnsController {
    /// Handle a UDP DNS query from TPROXY.
    pub async fn handle_udp_dns(
        &self,
        _udp_socket: &UdpSocket,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 || !is_dns_query(data) {
            return Ok(false);
        }

        // Keep the permit through the reply write so the limit bounds the
        // complete request lifecycle rather than only upstream resolution.
        let _permit = match self.concurrency_limit.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                debug!("DNS concurrency limit reached; sending REFUSED");
                let response = build_dns_refused(data);
                let _ = super::super::send_udp_reply_from_orig_dst(
                    &response,
                    client_addr,
                    original_dst,
                )
                .await;
                return Ok(true);
            }
        };

        debug!(%client_addr, "DNS controller (UDP): forwarding query");
        let response = self
            .resolve_with_singleflight(data, Some(original_dst), udp_ingress_profile(data))
            .await;
        let _ =
            super::super::send_udp_reply_from_orig_dst(&response, client_addr, original_dst).await;
        Ok(true)
    }

    /// Handle a TCP DNS-over-TCP connection from TPROXY.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }

        let mut query = Vec::new();
        if !read_tcp_dns_query(stream, &mut query).await {
            return Ok(false);
        }
        debug!(%client_addr, "DNS controller (TCP): forwarding query");
        self.process_tcp_query(stream, &query, original_dst).await?;

        loop {
            if !read_tcp_dns_query(stream, &mut query).await {
                return Ok(true);
            }
            self.process_tcp_query(stream, &query, original_dst).await?;
        }
    }

    async fn process_tcp_query(
        &self,
        stream: &mut TcpStream,
        query: &[u8],
        original_dst: SocketAddr,
    ) -> anyhow::Result<()> {
        // Keep the permit through the framed response write, including every
        // frame on a persistent TCP connection.
        match self.concurrency_limit.try_acquire() {
            Ok(_permit) => {
                let response = self
                    .resolve_with_singleflight(
                        query,
                        Some(original_dst),
                        crate::dns::query::IngressProfile::Tcp,
                    )
                    .await;
                write_tcp_dns_response(stream, &response).await
            }
            Err(_) => write_tcp_dns_response(stream, &build_dns_refused(query)).await,
        }
    }
}

async fn read_tcp_dns_query(stream: &mut TcpStream, query: &mut Vec<u8>) -> bool {
    let mut length = [0u8; 2];
    if stream.read_exact(&mut length).await.is_err() {
        return false;
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length < 12 {
        return false;
    }
    query.resize(length, 0);
    stream.read_exact(query).await.is_ok() && is_dns_query(query)
}

fn is_dns_query(data: &[u8]) -> bool {
    super::super::is_exact_dns_query(data)
}

pub(super) fn udp_ingress_profile(data: &[u8]) -> crate::dns::query::IngressProfile {
    let advertised_size = crate::dns::query::QueryContext::parse(data)
        .ok()
        .and_then(|query| query.edns().map(|edns| edns.advertised_size()))
        .unwrap_or(512);
    crate::dns::query::IngressProfile::Udp { advertised_size }
}

pub(super) fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 2)
}

fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 5)
}

pub(crate) fn build_dns_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return vec![0u8; 12];
    }
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80 | (rcode & 0x0f);
    response
}

async fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> anyhow::Result<()> {
    let response_length = (response.len() as u16).to_be_bytes();
    stream.write_all(&response_length).await?;
    stream.write_all(response).await?;
    Ok(())
}
