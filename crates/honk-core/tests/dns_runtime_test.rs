use std::sync::Arc;

use honk_config::Config;
use honk_config::node::Node;
use honk_core::control::ControlPlane;
use honk_core::dns;
use honk_core::dns::DnsResolver;
use honk_core::ebpf::mock::MockEbpfBackend;
use honk_core::proxy::ProxyRegistry;
use honk_core::routing::Router;

fn test_dns_forwarder() -> Arc<dns::forwarder::DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(32)));
    let router = Arc::new(
        dns::routing::DnsRouter::new_from_dns_config(&honk_config::dns::DnsConfig::default())
            .expect("DNS router"),
    );
    let upstream = Arc::new(
        dns::upstream_pool::UpstreamPool::new(
            &[honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: "8.8.8.8:53".into(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            Arc::clone(&router),
        )
        .expect("upstream pool"),
    );
    Arc::new(dns::forwarder::DnsForwarder::new(upstream, cache, router))
}

#[tokio::test]
async fn public_reload_surface_publishes_a_coherent_runtime() {
    let config = Config::default();
    let control = ControlPlane::new(
        config.clone(),
        Box::new(MockEbpfBackend::new()),
        Router::new(&config.routing.rules, &config.routing.default_outbound).expect("router"),
        Arc::new(ProxyRegistry::default_resolver().expect("proxy registry")),
        DnsResolver::new(&config.dns).expect("DNS resolver"),
        test_dns_forwarder(),
    )
    .expect("control plane");
    let subscription_id = uuid::Uuid::new_v4();
    let replacement = Node {
        name: "published-runtime-node".into(),
        subscription_id: Some(subscription_id),
        ..Node::default()
    };

    control
        .merge_subscription_nodes(subscription_id, vec![replacement])
        .await;

    let active = control.config_handle();
    let active = active.read().await;
    assert!(
        active.nodes.iter().any(|node| {
            node.name == "published-runtime-node" && node.subscription_id == Some(subscription_id)
        }),
        "public reload surface did not activate the replacement generation"
    );
    assert!(control.is_datapath_healthy());
}
