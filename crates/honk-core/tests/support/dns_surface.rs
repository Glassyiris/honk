use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use honk_core::dns::forwarder::DnsUpstreamPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub struct StaticUpstream {
    ip: [u8; 4],
    calls: AtomicUsize,
}

impl StaticUpstream {
    pub fn new(ip: [u8; 4]) -> Arc<Self> {
        Arc::new(Self {
            ip,
            calls: AtomicUsize::new(0),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsUpstreamPool for StaticUpstream {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(a_response(raw_query, self.ip))
    }
}

pub struct BlockingUpstream {
    ip: [u8; 4],
    pub entered: Notify,
    pub release: Notify,
}

impl BlockingUpstream {
    pub fn new(ip: [u8; 4]) -> Arc<Self> {
        Arc::new(Self {
            ip,
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
}

#[async_trait]
impl DnsUpstreamPool for BlockingUpstream {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(a_response(raw_query, self.ip))
    }
}

pub struct LoopbackServer {
    pub address: SocketAddr,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl LoopbackServer {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_udp_server(ip: [u8; 4]) -> LoopbackServer {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
    let address = socket.local_addr().expect("UDP address");
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            observed.fetch_add(1, Ordering::SeqCst);
            let response = a_response(&buffer[..length], ip);
            if socket.send_to(&response, peer).await.is_err() {
                return;
            }
        }
    });
    LoopbackServer {
        address,
        calls,
        task,
    }
}

pub async fn spawn_tcp_server(ip: [u8; 4]) -> LoopbackServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
    let address = listener.local_addr().expect("TCP address");
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let observed = Arc::clone(&observed);
            tokio::spawn(async move {
                let length = match stream.read_u16().await {
                    Ok(length) => usize::from(length),
                    Err(_) => return,
                };
                let mut query = vec![0_u8; length];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }
                observed.fetch_add(1, Ordering::SeqCst);
                let response = a_response(&query, ip);
                if let Ok(length) = u16::try_from(response.len()) {
                    let _ = stream.write_u16(length).await;
                    let _ = stream.write_all(&response).await;
                }
            });
        }
    });
    LoopbackServer {
        address,
        calls,
        task,
    }
}

pub fn a_response(raw_query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    a_response_with_ttl(raw_query, ip, 300)
}

pub fn a_response_with_ttl(raw_query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut response = raw_query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&[0, 4, ip[0], ip[1], ip[2], ip[3]]);
    response
}
