//! HTTP CONNECT proxy handler (RFC 7231): real outbound for `http://`
//! nodes — previously every `NodeProtocol::HTTP` node silently fell
//! through to DirectHandler, so http-proxy nodes went direct.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ProxyHandler, ProxyStream};

/// HTTP CONNECT proxy (absolute-form CONNECT + optional Basic auth).
#[derive(Default)]
pub struct HttpConnectHandler;

impl HttpConnectHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProxyHandler for HttpConnectHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::HTTP
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        let mut stream = crate::util::connect_outbound(&addr, connect_timeout).await?;

        // CONNECT authority: the sniffed domain wins over the raw IP.
        let authority = match target_domain {
            Some(d) => format!("{d}:{}", target.port()),
            None => target.to_string(),
        };
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let (Some(u), Some(p)) = (node.username.as_deref(), node.password.as_deref()) {
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            request.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
        }
        request.push_str("\r\n");
        tokio::time::timeout(connect_timeout, stream.write_all(request.as_bytes())).await??;

        // Read the status line (headers up to CRLFCRLF, capped).
        let mut head = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        let read_head = async {
            while head.len() < 4096 {
                stream.read_exact(&mut byte).await?;
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    return Ok::<(), std::io::Error>(());
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http proxy response head too long",
            ))
        };
        tokio::time::timeout(connect_timeout, read_head).await??;
        let head = String::from_utf8_lossy(&head);
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            anyhow::bail!(
                "http proxy CONNECT to {} failed: {}",
                authority,
                head.lines().next().unwrap_or("<no status>")
            );
        }
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A minimal CONNECT server: checks the request line + auth, replies
    /// 200, then echoes everything.
    async fn spawn_connect_server(want_auth: bool) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                conn.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&head);
            assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            if want_auth {
                assert!(head.contains("Proxy-Authorization: Basic dTpw"));
            }
            conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 8];
            conn.read_exact(&mut buf[..4]).await.unwrap();
            assert_eq!(&buf[..4], b"ping");
            conn.write_all(b"pong").await.unwrap();
        });
        (port, task)
    }

    #[tokio::test]
    async fn test_http_connect_dial() {
        let (port, server) = spawn_connect_server(false).await;
        let node = Node {
            name: "http".into(),
            protocol: NodeProtocol::HTTP,
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        let handler = HttpConnectHandler::new();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut stream = handler
            .dial(&node, target, Some("example.com"), Duration::from_secs(5))
            .await
            .unwrap()
            .stream;
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_connect_basic_auth() {
        let (port, server) = spawn_connect_server(true).await;
        let node = Node {
            name: "http".into(),
            protocol: NodeProtocol::HTTP,
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            username: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        };
        let handler = HttpConnectHandler::new();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut stream = handler
            .dial(&node, target, Some("example.com"), Duration::from_secs(5))
            .await
            .unwrap()
            .stream;
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_connect_rejects_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 128];
            let _ = conn.read(&mut head).await.unwrap();
            conn.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        let node = Node {
            name: "http".into(),
            protocol: NodeProtocol::HTTP,
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        let handler = HttpConnectHandler::new();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let err = handler
            .dial(&node, target, Some("example.com"), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"));
    }
}
