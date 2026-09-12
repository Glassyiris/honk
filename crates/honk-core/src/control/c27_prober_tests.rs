use super::*;
use honk_outbound::alive::{HttpProbeResult, HttpProber, UdpProber};

fn invalid_probe_nodes() -> Vec<Node> {
    let node = udp_test_node();
    let mut nil = node.clone();
    nil.id = uuid::Uuid::nil();
    let mut stale = node.clone();
    stale.port += 1;
    let mut intrinsic = node;
    intrinsic.port = 0;
    vec![nil, stale, intrinsic]
}

#[tokio::test]
async fn c27_http_rejects_invalid_nodes_before_dial() {
    for node in invalid_probe_nodes() {
        let original = udp_test_node();
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[original]).unwrap(),
        )));
        let captured = Arc::new(std::sync::Mutex::new(None));
        let mut registry = ProxyRegistry::new();
        registry.register(honk_outbound::proxy::ProtocolEntry::new(
            node.protocol(),
            Arc::new(UdpTestHandler {
                mode: UdpTestMode::TcpCaptureTarget(captured.clone()),
            }),
        ));
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            &[],
        ))));
        let prober = probers::ProxyHttpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            generation,
            "HEAD".into(),
            manager,
        );
        let result = prober
            .probe_http(
                &node.name,
                "127.0.0.1:9".parse().unwrap(),
                "http://127.0.0.1:9/",
                Duration::from_millis(50),
            )
            .await;
        assert!(matches!(result, HttpProbeResult::SetupFailure(_)));
        assert!(
            captured.lock().unwrap().is_none(),
            "invalid node reached TCP dial"
        );
    }
}

#[tokio::test]
async fn c27_udp_rejects_invalid_nodes_without_data_path() {
    for node in invalid_probe_nodes() {
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap(),
        )));
        let captured = Arc::new(std::sync::Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::UdpCaptureTarget(captured.clone()),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
                .with_packet(handler),
        );
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            &[],
        ))));
        let target: SocketAddr = "127.0.0.1:5301".parse().unwrap();
        let prober = probers::ProxyUdpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            generation,
            Arc::new(StatsManager::new()),
            target,
            target.into(),
            None,
            manager,
        );
        let result = prober
            .probe_udp(&node.name, Duration::from_millis(50))
            .await;
        assert!(result.dns.is_err());
        assert!(result.data_path.is_none());
        assert!(
            captured.lock().unwrap().is_none(),
            "invalid node reached UDP dial"
        );
    }
}

#[tokio::test]
async fn c27_legacy_factories_fail_fast_on_invalid_nodes() {
    for node in invalid_probe_nodes() {
        assert!(
            std::panic::catch_unwind(|| { honk_outbound::runtime::NodeRuntime::ephemeral(&node) })
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| {
                honk_outbound::runtime::NodeRuntime::ephemeral_guarded(&node)
            })
            .is_err()
        );
        let generation =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                honk_outbound::urltest::probe_runtime(&generation, &node)
            }))
            .is_err()
        );
    }
}

#[tokio::test]
async fn c27_urltest_propagates_admission_before_dial() {
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap(),
    );
    let captured = Arc::new(std::sync::Mutex::new(None));
    let handler = UdpTestHandler {
        mode: UdpTestMode::TcpCaptureTarget(captured.clone()),
    };
    for node in invalid_probe_nodes() {
        let result = honk_outbound::urltest::urltest_node_in_generation_with_feedback(
            &generation,
            &node,
            &handler,
            None,
            "http://127.0.0.1:9/",
            Duration::from_millis(50),
            &GroupManager::new(&[], &[]),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<honk_outbound::runtime::RuntimeRegistryError>()
                .is_some()
        );
        assert!(captured.lock().unwrap().is_none());
    }
}
