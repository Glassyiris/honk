use super::*;

#[tokio::test]
async fn ready_pool_hit_does_not_wait_for_physical_dial_permit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "ready-socks".into(),
        protocol: NodeProtocol::Socks5,
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let _held = generation.acquire_dial_permit().await;
    let pool = ConnectionPool::new();
    let key = ConnectionPool::ready_key(&format!("{}:{}", node.host(), node.port), target, None);
    pool.deposit_ready(
        &key,
        crate::proxy::ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        },
    )
    .await;
    let registry = ProxyRegistry::default_resolver().unwrap();

    let (stream, fresh) = tokio::time::timeout(
        Duration::from_millis(100),
        ControlPlaneHandle::dial_pooled(
            &registry,
            &pool,
            &generation,
            &node,
            target,
            None,
            Duration::from_secs(1),
        ),
    )
    .await
    .expect("ready stream must bypass an exhausted physical-dial gate")
    .unwrap();
    assert!(
        !fresh,
        "a ready-pool acquire performs no network round trip"
    );

    drop(stream);
    server.abort();
}
