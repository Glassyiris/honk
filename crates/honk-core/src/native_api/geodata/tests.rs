use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use honk_config::Config;
use honk_config::group::Group;
use honk_config::node::{Node, OutboundConfig};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::types::NodeProtocol;
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::*;
use crate::download_route::Outbounds;
use crate::routing::Router;

/// Serves `body` at every path but a checksum, which is a 404; counts the
/// requests that reach it.
async fn server(body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let checksum = String::from_utf8_lossy(&head)
                .split(' ')
                .nth(1)
                .is_some_and(|path| path.ends_with(".sha256sum"));
            let (status, body) = if checksum {
                ("404 Not Found", &b""[..])
            } else {
                ("200 OK", body)
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });
    (address, requests)
}

/// A tunnel that connects to the target itself, refusing `refused` ports.
struct Tunnel {
    dials: Arc<AtomicUsize>,
    refused: Vec<u16>,
}

#[async_trait::async_trait]
impl TcpOutbound for Tunnel {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        if self.refused.contains(&target.port()) {
            anyhow::bail!("proxy refused");
        }
        Ok(ProxyStream {
            stream: Box::new(tokio::net::TcpStream::connect(target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

struct World {
    router: RwLock<Router>,
    config: RwLock<Arc<Config>>,
    group_manager: honk_outbound::group::SharedGroupManager,
    proxy_registry: ProxyRegistry,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    dials: Arc<AtomicUsize>,
}

/// Group `proxy` holds one node whose tunnel refuses `refused`; group `empty`
/// holds none. Loopback traffic is routed to `proxy`.
fn world(refused: Vec<u16>) -> World {
    let mut node = Node {
        name: "tunnel".into(),
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "192.0.2.1".into(),
        port: 1080,
        ..Default::default()
    };
    node.id = node.derive_id();
    let config = Config {
        groups: vec![
            Group {
                name: "proxy".into(),
                nodes: vec![node.id],
                ..Default::default()
            },
            Group {
                name: "empty".into(),
                ..Default::default()
            },
        ],
        nodes: vec![node],
        ..Default::default()
    };
    let rules = vec![RoutingRule {
        name: "loopback".into(),
        condition: RoutingCondition {
            ip: vec!["127.0.0.1/32".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let dials = Arc::new(AtomicUsize::new(0));
    let mut proxy_registry = ProxyRegistry::new();
    proxy_registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(Tunnel {
            dials: Arc::clone(&dials),
            refused,
        }),
    ));
    World {
        router: RwLock::new(Router::new(&rules, "direct").unwrap()),
        group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &config.groups,
            &config.nodes,
        )))),
        config: RwLock::new(Arc::new(config)),
        proxy_registry,
        runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
        ))),
        dials,
    }
}

impl World {
    async fn fetch(
        &self,
        route: Route,
        urls: &[String],
    ) -> Result<(Arc<[u8]>, Fetched), &'static str> {
        // Loopback servers are private destinations, so the policy has to allow them.
        let ports: Vec<u16> = urls
            .iter()
            .filter_map(|url| parse_geodata_url(url)?.port())
            .collect();
        let policy = Policy::new(&NativeApiConfig {
            probe_allowed_cidrs: vec!["127.0.0.0/8".into()],
            probe_allowed_ports: ports,
            ..Default::default()
        });
        let egress = Egress {
            bootstrap: "udp://127.0.0.1:9",
            route: &route,
            outbounds: Outbounds {
                router: &self.router,
                config: &self.config,
                group_manager: &self.group_manager,
                proxy_registry: &self.proxy_registry,
                runtime_registry: &self.runtime_registry,
            },
        };
        fetch("geosite", urls, &egress, 1024, &policy, "").await
    }
}

fn url(address: SocketAddr) -> String {
    format!("http://{address}/geosite.dat")
}

#[tokio::test]
async fn a_group_route_downloads_through_the_group() {
    let (address, requests) = server(b"through the group").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world
        .fetch(Route::Group("proxy".into()), &[url(address)])
        .await
        .unwrap();
    assert_eq!(&*bytes, b"through the group");
    assert_eq!(world.dials.load(Ordering::SeqCst), 2, "file and checksum");
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Group("proxy".into()));
    assert_eq!(fetched.group.as_deref(), Some("proxy"));
}

#[tokio::test]
async fn the_routing_route_follows_the_rules() {
    let (address, _) = server(b"routed").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world.fetch(Route::Routing, &[url(address)]).await.unwrap();
    assert_eq!(&*bytes, b"routed");
    assert_eq!(world.dials.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Routing);
    assert_eq!(
        fetched.group.as_deref(),
        Some("proxy"),
        "the group the rules chose"
    );
}

#[tokio::test]
async fn the_direct_route_ignores_the_rules() {
    let (address, requests) = server(b"direct").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world.fetch(Route::Direct, &[url(address)]).await.unwrap();
    assert_eq!(&*bytes, b"direct");
    assert_eq!(world.dials.load(Ordering::SeqCst), 0);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Direct);
    assert_eq!(fetched.group, None);
}

#[tokio::test]
async fn a_url_the_group_cannot_reach_falls_back_to_the_next_through_the_group() {
    let (refused, refused_requests) = server(b"unreachable").await;
    let (address, _) = server(b"second url").await;
    let world = world(vec![refused.port()]);
    let (bytes, fetched) = world
        .fetch(Route::Group("proxy".into()), &[url(refused), url(address)])
        .await
        .unwrap();
    assert_eq!(&*bytes, b"second url");
    assert_eq!(fetched.url, url(address));
    assert_eq!(fetched.group.as_deref(), Some("proxy"));
    assert_eq!(
        refused_requests.load(Ordering::SeqCst),
        0,
        "never retried direct"
    );
    assert_eq!(world.dials.load(Ordering::SeqCst), 3);
}

/// At startup a group may have no member it can use yet. Every URL fails and
/// nothing is fetched direct.
#[test]
fn an_empty_detour_follows_routing_without_a_state_db() {
    let file = |detour: &str| NativeApiConfig {
        geodata_download_detour: detour.into(),
        ..Default::default()
    };
    assert_eq!(route(&file(""), None), Route::Routing);
    assert_eq!(route(&file("routing"), None), Route::Routing);
    assert_eq!(route(&file("direct"), None), Route::Direct);
}

#[tokio::test]
async fn a_group_not_ready_at_startup_fails_every_url_without_going_direct() {
    let (first, first_requests) = server(b"first").await;
    let (second, second_requests) = server(b"second").await;
    let urls = [url(first), url(second)];
    let world = world(vec![first.port(), second.port()]);
    assert_eq!(
        world
            .fetch(Route::Group("proxy".into()), &urls)
            .await
            .unwrap_err(),
        "connection_failed"
    );
    assert_eq!(
        world.fetch(Route::Routing, &urls).await.unwrap_err(),
        "connection_failed",
        "the rules send the URLs to the group"
    );
    assert_eq!(
        world
            .fetch(Route::Group("empty".into()), &urls)
            .await
            .unwrap_err(),
        "group_unavailable"
    );
    assert_eq!(
        world
            .fetch(Route::Group("removed".into()), &urls)
            .await
            .unwrap_err(),
        "group_unavailable"
    );
    assert_eq!(first_requests.load(Ordering::SeqCst), 0);
    assert_eq!(second_requests.load(Ordering::SeqCst), 0);
}
