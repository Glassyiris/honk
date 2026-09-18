use super::*;
use crate::control::tests::{
    store_active_tcp_flow,
    support::{canonical_socks5, test_dns_forwarder},
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    plane: ControlPlane,
    handle: ControlPlaneHandle,
    server: crate::native_api::NativeServer,
    http: reqwest::Client,
    api: String,
    listener: tokio::net::TcpListener,
    client: TcpStream,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Fixture {
    async fn new(selected: &str, dial_mode: &str) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let destination = listener.local_addr()?;
        let client = TcpStream::connect(destination).await?;
        let (accepted, source) = listener.accept().await?;
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.nodes.push(canonical_socks5(
            "peer",
            "127.0.0.1",
            destination.port(),
            None,
        ));
        config.global.dial_mode = dial_mode.into();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.global.connect_timeout_ms = 5_000;
        config.routing.default_outbound = "outer".into();
        config.groups = vec![
            Group {
                name: "outer".into(),
                groups: vec!["inner".into()],
                ..Default::default()
            },
            Group {
                name: "inner".into(),
                nodes: config.nodes.iter().map(|node| node.id).collect(),
                default: Some(selected.into()),
                ..Default::default()
            },
        ];
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.allow_anonymous_loopback = true;
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
        let mut plane = ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver()?),
            DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
            test_dns_forwarder(),
        )?;
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = api_listener.local_addr()?;
        let state = crate::native_api::NativeState::new(
            &mut plane,
            address,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
            true,
        )
        .await?;
        let server = crate::native_api::NativeServer::start(api_listener, Arc::new(state));
        let handle = plane.spawn_handle();
        handle.connection_tracker.disable_api();
        store_active_tcp_flow(&handle, destination, source).await?;
        let worker = handle.clone();
        let task = tokio::spawn(async move { worker.serve_connection(accepted, source).await });
        Ok(Self {
            plane,
            handle,
            server,
            http: reqwest::Client::builder().no_proxy().build()?,
            api: format!("http://{address}/api/v1"),
            listener,
            client,
            task,
        })
    }

    async fn flow(&self, state: &str) -> anyhow::Result<Value> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let list: Value = self
                    .http
                    .get(format!("{}/flows", self.api))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if let Some(row) = list["flows"].as_array().and_then(|rows| rows.first())
                    && row["state"] == state
                {
                    let id = row["id"].as_str().unwrap();
                    return self
                        .http
                        .get(format!("{}/flows/{id}", self.api))
                        .send()
                        .await?
                        .error_for_status()?
                        .json::<Value>()
                        .await
                        .map_err(anyhow::Error::from);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
    }
}

fn steps(flow: &Value, stage: &str) -> Vec<Value> {
    flow["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["stage"] == stage)
        .cloned()
        .collect()
}

#[tokio::test]
async fn native_tcp_success_keeps_decision_path_after_selector_change() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("peer", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        upstream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        upstream.write_all(&[5, 0]).await?;
        let mut connect = [0; 10];
        upstream.read_exact(&mut connect).await?;
        assert_eq!(&connect[..4], &[5, 1, 0, 1]);
        upstream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
        let catalog = fixture.handle.native.as_ref().unwrap().catalog.snapshot();
        let leaf_id = fixture
            .handle
            .config
            .read()
            .await
            .nodes
            .iter()
            .find(|node| node.name == "peer")
            .unwrap()
            .id
            .to_string();
        fixture.client.write_all(b"request").await?;
        let mut request = [0; 7];
        upstream.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        upstream.write_all(b"reply").await?;
        let mut reply = [0; 5];
        fixture.client.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"reply");
        let before = fixture.flow("active").await?;
        assert_eq!(before["outbound"], "outer");
        assert_eq!(
            before["chain"],
            serde_json::json!([catalog.groups["outer"], catalog.groups["inner"], leaf_id])
        );
        let attempts = steps(&before, "outbound");
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["data"]["status"], "started");
        assert_eq!(attempts[1]["data"]["status"], "succeeded");
        assert_eq!(
            attempts[0]["data"]["attempt_id"],
            attempts[1]["data"]["attempt_id"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["member_name"],
            "inner"
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["member_name"],
            "peer"
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["group_id"],
            catalog.groups["outer"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][0]["member_id"],
            catalog.groups["inner"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["group_id"],
            catalog.groups["inner"]
        );
        assert_eq!(
            attempts[1]["data"]["selection_path"][1]["member_id"],
            leaf_id
        );
        assert_eq!(
            steps(&before, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            1
        );
        fixture
            .handle
            .group_manager
            .read()
            .set_selector_choice("inner", "block");
        let after = fixture.flow("active").await?;
        assert_eq!(steps(&after, "outbound"), attempts);
        assert_eq!(after["chain"], before["chain"]);
        let connections: Value = fixture
            .http
            .get(format!("{}/connections", fixture.api))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(connections["tcp"][0]["flow_id"], before["id"]);
        fixture.client.shutdown().await?;
        upstream.shutdown().await?;
        (&mut fixture.task).await??;
        let closed = fixture.flow("closed").await?;
        assert_eq!(closed["id"], before["id"]);
        assert_eq!(
            steps(&closed, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "terminal")
                .count(),
            1
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_retains_block_and_failed_dial_without_connection() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        for selected in ["block", "peer"] {
            let mut fixture = Fixture::new(selected, "ip").await?;
            if selected == "peer" {
                let (upstream, _) = fixture.listener.accept().await?;
                drop(upstream);
            }
            let state = if selected == "block" {
                "blocked"
            } else {
                "failed"
            };
            let flow = fixture.flow(state).await?;
            assert!(flow["connection_id"].is_null());
            assert!(flow["ended_at"].is_string());
            let attempts = steps(&flow, "outbound");
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0]["data"]["status"], "started");
            assert_eq!(attempts[1]["data"]["status"], "failed");
            assert_eq!(attempts[1]["data"]["leaf_node_name"], selected);
            assert_eq!(
                attempts[0]["data"]["attempt_id"],
                attempts[1]["data"]["attempt_id"]
            );
            (&mut fixture.task).await??;
            assert_eq!(
                fixture.handle.stats.snapshot()["outer"].errors,
                u32::from(selected == "peer")
            );
            assert_eq!(fixture.handle.stats.snapshot()["outer"].active_conns, 0);
            fixture.server.shutdown().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_cancelled_attempt_keeps_pre_reload_generation_and_name() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("peer", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut greeting = [0; 3];
        upstream.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 5);
        let before = fixture.flow("observed").await?;
        let attempt = steps(&before, "outbound").pop().unwrap();
        assert_eq!(attempt["data"]["status"], "started");
        let mut replacement = fixture.handle.config.read().await.as_ref().clone();
        replacement
            .nodes
            .iter_mut()
            .find(|node| node.name == "peer")
            .unwrap()
            .name = "renamed".into();
        replacement
            .groups
            .iter_mut()
            .find(|group| group.name == "inner")
            .unwrap()
            .default = Some("renamed".into());
        assert!(
            fixture
                .plane
                .reload_runtime_config(replacement, Default::default())
                .await
        );
        fixture.task.abort();
        assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
        assert_eq!(fixture.handle.stats.snapshot()["outer"].active_conns, 0);
        let cancelled = fixture.flow("failed").await?;
        let attempts = steps(&cancelled, "outbound");
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[1]["data"]["status"], "cancelled");
        assert_eq!(attempts[1]["generation_id"], attempt["generation_id"]);
        assert_eq!(attempts[1]["data"]["leaf_node_name"], "peer");
        assert_eq!(
            attempts[1]["data"]["selection_path"],
            attempt["data"]["selection_path"]
        );
        assert_eq!(
            attempts[1]["data"]["attempt_id"],
            attempt["data"]["attempt_id"]
        );
        assert_eq!(
            steps(&cancelled, "connection")
                .iter()
                .filter(|step| step["data"]["milestone"] == "terminal")
                .count(),
            1
        );
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_tcp_http_host_does_not_replace_consumed_ip_routing_input() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::new("direct", "domain+").await?;
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        fixture.client.write_all(request).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        let mut received = vec![0; request.len()];
        upstream.read_exact(&mut received).await?;
        assert_eq!(received, request);
        let flow = fixture.flow("active").await?;
        assert_eq!(flow["input"]["domain"], "example.test");
        assert_eq!(flow["domain_source"], "http_host");
        assert_eq!(flow["chain"], serde_json::json!([]));
        let route = steps(&flow, "route").pop().unwrap();
        assert_eq!(route["data"]["plane"], "userspace");
        assert!(route["data"]["input"]["domain"].is_null());
        let dial_mode = steps(&flow, "dial_mode").pop().unwrap();
        assert_eq!(dial_mode["data"]["configured"], "domain+");
        assert_eq!(dial_mode["data"]["verification"], "not_required");
        assert_eq!(dial_mode["data"]["effective_target"], "ip");
        fixture.client.shutdown().await?;
        upstream.shutdown().await?;
        (&mut fixture.task).await??;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
