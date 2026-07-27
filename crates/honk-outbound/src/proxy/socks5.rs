//! SOCKS5 (RFC 1928) with no-auth and user/pass (RFC 1929) authentication.

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::{ProxyHandler, ProxyStream, UdpProxySocket};

const SOCKS5_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// Full SOCKS5 proxy handler.
pub struct Socks5Handler;

impl Socks5Handler {
    pub fn new() -> Self {
        Self
    }

    /// Perform full SOCKS5 handshake.
    async fn handshake(
        stream: &mut TcpStream,
        target: SocketAddr,
        target_domain: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let methods = if username.is_some() && password.is_some() {
                vec![METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            } else {
                vec![METHOD_NO_AUTH]
            };

            // Send: VER(1) | NMETHODS(1) | METHODS(N)
            let mut greeting = Vec::with_capacity(2 + methods.len());
            greeting.push(SOCKS5_VERSION);
            greeting.push(methods.len() as u8);
            greeting.extend_from_slice(&methods);
            stream.write_all(&greeting).await?;

            // Read: VER(1) | METHOD(1)
            let mut response = [0u8; 2];
            stream.read_exact(&mut response).await?;

            if response[0] != SOCKS5_VERSION {
                anyhow::bail!("SOCKS5: unsupported server version {}", response[0]);
            }

            match response[1] {
                METHOD_NO_AUTH => {}
                METHOD_USERNAME_PASSWORD => {
                    // Perform username/password auth (RFC 1929)
                    let user = username.unwrap_or("");
                    let pass = password.unwrap_or("");

                    // Send: VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
                    let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                    auth_req.push(0x01); // auth version
                    auth_req.push(user.len() as u8);
                    auth_req.extend_from_slice(user.as_bytes());
                    auth_req.push(pass.len() as u8);
                    auth_req.extend_from_slice(pass.as_bytes());
                    stream.write_all(&auth_req).await?;

                    // Read: VER(1) | STATUS(1)
                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;

                    if auth_resp[1] != 0x00 {
                        anyhow::bail!("SOCKS5: authentication failed (status {})", auth_resp[1]);
                    }
                }
                METHOD_NO_ACCEPTABLE => {
                    anyhow::bail!("SOCKS5: no acceptable authentication method");
                }
                m => {
                    anyhow::bail!("SOCKS5: unexpected auth method 0x{:02x}", m);
                }
            }

            // Build request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
            let mut request = Vec::with_capacity(6 + 256);
            request.push(SOCKS5_VERSION);
            request.push(CMD_CONNECT);
            request.push(0x00); // reserved

            match target {
                SocketAddr::V4(v4) => {
                    request.push(ATYP_IPV4);
                    request.extend_from_slice(&v4.ip().octets());
                    request.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    request.push(ATYP_IPV6);
                    request.extend_from_slice(&v6.ip().octets());
                    request.extend_from_slice(&v6.port().to_be_bytes());
                }
            }

            if let Some(domain) = target_domain {
                request[3] = ATYP_DOMAIN;
                request.truncate(4);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                request.extend_from_slice(&target.port().to_be_bytes());
            }

            let atyp_str = if request[3] == ATYP_DOMAIN {
                "domain"
            } else if request[3] == ATYP_IPV4 {
                "ipv4"
            } else if request[3] == ATYP_IPV6 {
                "ipv6"
            } else {
                "unknown"
            };
            debug!(
                "SOCKS5 connect request: ATYP={} target={} addr={}",
                atyp_str,
                target_domain.unwrap_or("<ip>"),
                target
            );

            stream.write_all(&request).await?;

            // Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            let mut reply_header = [0u8; 4];
            stream.read_exact(&mut reply_header).await?;

            if reply_header[0] != SOCKS5_VERSION {
                anyhow::bail!("SOCKS5: bad reply version {}", reply_header[0]);
            }

            let reply_code = reply_header[1];
            if reply_code != REP_SUCCESS {
                let msg = match reply_code {
                    REP_GENERAL_FAILURE => "general failure",
                    REP_CONNECTION_NOT_ALLOWED => "connection not allowed",
                    REP_NETWORK_UNREACHABLE => "network unreachable",
                    REP_HOST_UNREACHABLE => "host unreachable",
                    REP_CONNECTION_REFUSED => "connection refused",
                    REP_TTL_EXPIRED => "TTL expired",
                    REP_COMMAND_NOT_SUPPORTED => "command not supported",
                    REP_ADDRESS_TYPE_NOT_SUPPORTED => "address type not supported",
                    _ => "unknown error",
                };
                anyhow::bail!(
                    "SOCKS5: server replied error: {} (0x{:02x})",
                    msg,
                    reply_code
                );
            }

            // Read the bind address (we don't use it, but need to consume it)
            let atyp = reply_header[3];
            match atyp {
                ATYP_IPV4 => {
                    let mut addr = [0u8; 6];
                    stream.read_exact(&mut addr).await?;
                }
                ATYP_DOMAIN => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await?;
                    let domain_len = len_buf[0] as usize;
                    let mut domain_and_port = vec![0u8; domain_len + 2];
                    stream.read_exact(&mut domain_and_port).await?;
                }
                ATYP_IPV6 => {
                    let mut addr = [0u8; 18];
                    stream.read_exact(&mut addr).await?;
                }
                a => anyhow::bail!("SOCKS5: unknown bind address type 0x{:02x}", a),
            }

            debug!("SOCKS5 handshake complete");
            Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out"))?
    }

    /// Build a SOCKS5 UDP request header (RFC 1928 Section 7).
    /// Format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2) | DATA
    pub fn build_udp_header(target: SocketAddr, target_domain: Option<&str>) -> Vec<u8> {
        let mut header = Vec::with_capacity(6 + 256);
        header.extend_from_slice(&[0x00, 0x00]); // RSV
        header.push(0x00); // FRAG

        match (target_domain, target) {
            (Some(domain), _) => {
                header.push(ATYP_DOMAIN);
                header.push(domain.len() as u8);
                header.extend_from_slice(domain.as_bytes());
                header.extend_from_slice(&target.port().to_be_bytes());
            }
            (None, SocketAddr::V4(v4)) => {
                header.push(ATYP_IPV4);
                header.extend_from_slice(&v4.ip().octets());
                header.extend_from_slice(&v4.port().to_be_bytes());
            }
            (None, SocketAddr::V6(v6)) => {
                header.push(ATYP_IPV6);
                header.extend_from_slice(&v6.ip().octets());
                header.extend_from_slice(&v6.port().to_be_bytes());
            }
        }

        header
    }

    /// Perform SOCKS5 UDP ASSOCIATE handshake (RFC 1928 Section 6).
    /// Returns the relay address where UDP datagrams should be sent.
    /// The TCP control connection must be kept alive for the UDP relay to work.
    async fn udp_associate(
        stream: &mut tokio::net::TcpStream,
        username: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<SocketAddr> {
        let methods = if username.is_some() && password.is_some() {
            vec![METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
        } else {
            vec![METHOD_NO_AUTH]
        };

        let mut greeting = Vec::with_capacity(2 + methods.len());
        greeting.push(SOCKS5_VERSION);
        greeting.push(methods.len() as u8);
        greeting.extend_from_slice(&methods);
        stream.write_all(&greeting).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != SOCKS5_VERSION {
            anyhow::bail!("SOCKS5: unsupported server version {}", response[0]);
        }

        match response[1] {
            METHOD_NO_AUTH => {}
            METHOD_USERNAME_PASSWORD => {
                let user = username.unwrap_or("");
                let pass = password.unwrap_or("");
                let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                auth_req.push(0x01);
                auth_req.push(user.len() as u8);
                auth_req.extend_from_slice(user.as_bytes());
                auth_req.push(pass.len() as u8);
                auth_req.extend_from_slice(pass.as_bytes());
                stream.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    anyhow::bail!("SOCKS5: authentication failed");
                }
            }
            METHOD_NO_ACCEPTABLE => anyhow::bail!("SOCKS5: no acceptable auth method"),
            m => anyhow::bail!("SOCKS5: unexpected auth method 0x{:02x}", m),
        }

        // VER | CMD=0x03 | RSV | ATYP=0x01 | BND.ADDR=0.0.0.0 | BND.PORT=0
        let request = [
            SOCKS5_VERSION,
            CMD_UDP_ASSOCIATE,
            0x00,
            ATYP_IPV4,
            0x00,
            0x00,
            0x00,
            0x00, // 0.0.0.0
            0x00,
            0x00, // port 0
        ];
        stream.write_all(&request).await?;

        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;

        if reply_header[0] != SOCKS5_VERSION {
            anyhow::bail!("SOCKS5 UDP: bad reply version");
        }
        if reply_header[1] != REP_SUCCESS {
            anyhow::bail!(
                "SOCKS5 UDP: server rejected UDP ASSOCIATE (code 0x{:02x})",
                reply_header[1]
            );
        }

        let relay_addr = match reply_header[3] {
            ATYP_IPV4 => {
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
                let ip = std::net::Ipv6Addr::from([
                    ((addr[0] as u16) << 8) | addr[1] as u16,
                    ((addr[2] as u16) << 8) | addr[3] as u16,
                    ((addr[4] as u16) << 8) | addr[5] as u16,
                    ((addr[6] as u16) << 8) | addr[7] as u16,
                    ((addr[8] as u16) << 8) | addr[9] as u16,
                    ((addr[10] as u16) << 8) | addr[11] as u16,
                    ((addr[12] as u16) << 8) | addr[13] as u16,
                    ((addr[14] as u16) << 8) | addr[15] as u16,
                ]);
                let port = u16::from_be_bytes([addr[16], addr[17]]);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_and_port = vec![0u8; domain_len + 2];
                stream.read_exact(&mut domain_and_port).await?;
                let port = u16::from_be_bytes([
                    domain_and_port[domain_len],
                    domain_and_port[domain_len + 1],
                ]);
                // For domain-based relay, we'll use the original server address
                // since the relay address is the SOCKS5 server itself
                let ip = stream.peer_addr()?.ip();
                SocketAddr::new(ip, port)
            }
            a => anyhow::bail!("SOCKS5 UDP: unknown address type 0x{:02x}", a),
        };

        debug!("SOCKS5 UDP ASSOCIATE: relay address {}", relay_addr);
        Ok(relay_addr)
    }
}

impl Default for Socks5Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProxyHandler for Socks5Handler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::Socks5
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("SOCKS5: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        self.dial_with_tcp(node, target, target_domain, stream, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        mut stream: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::handshake(
            &mut stream,
            target,
            target_domain,
            node.username.as_deref(),
            node.password.as_deref(),
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    /// After the greeting (+ optional RFC 1929 auth) and a successful
    /// CONNECT reply, the connection is a pure data channel bound to the
    /// requested target — the server sends nothing of its own before
    /// target data. Safe to pool as a ready stream.
    fn pool_ready_streams(&self, _node: &Node) -> bool {
        true
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("SOCKS5 UDP: connecting control channel to {}", addr);

        let mut control = crate::util::connect_outbound(&addr, connect_timeout).await?;

        let relay_addr = Self::udp_associate(
            &mut control,
            node.username.as_deref(),
            node.password.as_deref(),
        )
        .await?;

        // Bind the UDP relay socket with the same address family as the
        // relay address we will actually send to — NOT the control
        // connection's local family.  A v6 control connection to the server
        // can still return a v4 relay address; a family mismatch here makes
        // every send_to fail with EAFNOSUPPORT (os error 97).
        let bind_addr: SocketAddr = if relay_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
        } else {
            "[::]:0".parse().expect("hardcoded IPv6 bind address")
        };
        let udp_socket = crate::util::udp_marked_bind(bind_addr).await?;
        debug!("SOCKS5 UDP: bound to {}", udp_socket.local_addr()?);

        Ok(UdpProxySocket {
            socket: Arc::new(udp_socket),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
            _control: Some(control),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn run_test_socks5_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        // Simple SOCKS5 server: no auth, always succeed
                        let mut buf = [0u8; 256];

                        // Read greeting
                        let _ = stream.read(&mut buf).await.unwrap();
                        assert!(buf[0] == SOCKS5_VERSION);

                        // Reply: no auth
                        stream
                            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                            .await
                            .unwrap();

                        // Read request
                        let _ = stream.read(&mut buf).await.unwrap();
                        assert!(buf[0] == SOCKS5_VERSION);
                        assert!(buf[1] == CMD_CONNECT);

                        // Reply: success, bind to 0.0.0.0:0
                        let reply = [
                            SOCKS5_VERSION,
                            REP_SUCCESS,
                            0x00, // RSV
                            ATYP_IPV4,
                            0,
                            0,
                            0,
                            0, // 0.0.0.0
                            0,
                            0, // port 0
                        ];
                        stream.write_all(&reply).await.unwrap();

                        // Keep connection alive briefly for test
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    });
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_socks5_handshake_no_auth() {
        let server_addr = run_test_socks5_server().await;

        let node = Node {
            name: "test".into(),
            protocol: NodeProtocol::Socks5,
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };

        let handler = Socks5Handler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let result = handler
            .dial(
                &node,
                target,
                Some("example.com"),
                std::time::Duration::from_secs(3),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_connectivity() {
        let server_addr = run_test_socks5_server().await;

        let node = Node {
            name: "test".into(),
            protocol: NodeProtocol::Socks5,
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };

        let handler = Socks5Handler::new();
        assert!(handler.test_connectivity(&node).await);
    }

    #[test]
    fn test_pool_ready_streams_declared() {
        // SOCKS5 completed-CONNECT streams are pure data channels and may
        // be pooled for direct reuse.
        let handler = Socks5Handler::new();
        assert!(handler.pool_ready_streams(&Node::default()));
    }
}
