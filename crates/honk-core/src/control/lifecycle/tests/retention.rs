use super::*;
use crate::dns::forwarder::{build_dns_query, extract_answer_ips};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_outbound::alive::{IpVersion, ProbeDomain};
use std::net::IpAddr;

async fn dns_query(address: SocketAddr, name: &str) -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(WAIT, async {
        let mut socket = TcpStream::connect(address).await?;
        let query = build_dns_query(name, 1);
        socket.write_u16(query.len() as u16).await?;
        socket.write_all(&query).await?;
        let length = socket.read_u16().await?;
        let mut response = vec![0; usize::from(length)];
        socket.read_exact(&mut response).await?;
        Ok(response)
    })
    .await?
}

async fn assert_geo_route(fixture: &Fixture, domain: &str, expected: &str) {
    let response = fixture
        .http
        .post(format!("{}/routing/trace", fixture.base))
        .json(&serde_json::json!({"input": {
            "network": "tcp", "domain": domain, "dst_ip": "203.0.113.1", "dst_port": 80
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["evaluations"][0]["outbound"], expected);
}

async fn exchange_tcp(
    fixture: &Fixture,
    peer: &tokio::net::TcpListener,
    payload: &[u8],
) -> anyhow::Result<(TcpStream, TcpStream)> {
    tokio::time::timeout(WAIT, async {
        let mut client = fixture.connect_tcp().await?;
        client.write_all(payload).await?;
        let mut upstream = socks_peer(peer).await;
        complete_socks(&mut upstream).await;
        let mut bytes = vec![0; payload.len()];
        upstream.read_exact(&mut bytes).await?;
        assert_eq!(
            bytes, payload,
            "a new transport must carry only its new request"
        );
        upstream.write_all(&bytes).await?;
        client.read_exact(&mut bytes).await?;
        assert_eq!(bytes, payload);
        Ok((client, upstream))
    })
    .await?
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn repeated_cycles_retain_accepted_artifacts_policy_cache_and_history() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let hosts = directory.path().join("hosts.rules");
    let geosite = directory.path().join("geosite.dat");
    let geoip = directory.path().join("geoip.dat");
    std::fs::write(&hosts, "full:retained.invalid 192.0.2.60\n")?;
    // Independent protobuf vectors: exact keep.invalid; 127.0.0.0/8, both in category keep.
    std::fs::write(
        &geosite,
        b"\x0a\x18\x0a\x04keep\x12\x10\x08\x03\x12\x0ckeep.invalid",
    )?;
    std::fs::write(
        &geoip,
        b"\x0a\x10\x0a\x04keep\x12\x08\x0a\x04\x7f\x00\x00\x00\x10\x08",
    )?;
    let second_peer = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream = UdpSocket::bind("127.0.0.1:0").await?;
    let fixture = Fixture::start_with(|config, _| {
        config.global.data_dir = directory.path().to_string_lossy().into_owned();
        config.dns.hosts = vec![hosts.to_string_lossy().into_owned()];
        config.dns.upstream[0].address = upstream.local_addr().unwrap().to_string();
        config
            .dns
            .routing
            .request
            .rules
            .push(honk_config::dns::DnsRequestRule {
                conditions: vec![honk_config::dns::DnsCond::Qname {
                    not: false,
                    matchers: vec![honk_config::dns::DnsDomainMatcher::Geosite("keep".into())],
                }],
                action: honk_config::dns::DnsRequestAction::Reject,
            });
        let second = canonical_socks5(
            "second-peer",
            "127.0.0.1",
            second_peer.local_addr().unwrap().port(),
            None,
        );
        config.groups[0].policy = honk_config::node::GroupPolicy::LoadBalance;
        config.groups[0].nodes.push(second.id);
        config.nodes.push(second);
        config.routing.rules = [
            RoutingCondition {
                geosite: vec!["keep".into()],
                ..Default::default()
            },
            RoutingCondition {
                geo_ip: vec!["keep".into()],
                ..Default::default()
            },
        ]
        .into_iter()
        .enumerate()
        .map(|(index, condition)| RoutingRule {
            name: format!("retained-{index}"),
            condition,
            outbound: RoutingOutbound::Simple("target".into()),
            priority: index as u32,
            must: false,
            mark: 0,
        })
        .collect();
        config.routing.default_outbound = "block".into();
    })
    .await?;
    let manager = fixture.groups.read().clone();
    for name in ["peer", "second-peer"] {
        fixture.alive.report_available_traffic(
            manager.node_by_name(name).unwrap().id,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
    }
    let cache = fixture.dns_service.cache();
    assert_eq!(
        extract_answer_ips(&dns_query(fixture.dns, "retained.invalid").await?),
        ["192.0.2.60".parse::<IpAddr>()?]
    );
    assert!(extract_answer_ips(&dns_query(fixture.dns, "keep.invalid").await?).is_empty());
    assert_geo_route(&fixture, "keep.invalid", "target").await;
    assert_geo_route(&fixture, "gone.invalid", "block").await;

    let (cached, served) = tokio::join!(dns_query(fixture.dns, "cached.invalid"), async {
        let mut packet = [0; 512];
        let (length, source) =
            tokio::time::timeout(WAIT, upstream.recv_from(&mut packet)).await??;
        let mut response = packet[..length].to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 2, 88, 0, 4, 192, 0, 2, 90]);
        upstream.send_to(&response, source).await?;
        anyhow::Ok(())
    });
    served?;
    assert_eq!(
        extract_answer_ips(&cached?),
        ["192.0.2.90".parse::<IpAddr>()?]
    );
    // Keep the peer open but unanswered: every later DNS response must come from the retained cache.
    let runtime = fixture.get("/runtime").await;
    let (mut client, mut peer) = exchange_tcp(&fixture, &fixture.peer, b"before-suspend").await?;
    let history = tokio::time::timeout(WAIT, async {
        loop {
            let history = fixture.get("/runtime/traffic/history").await;
            if let Some(first) = history["samples"].as_array().unwrap().first() {
                break first.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    for cycle in 0..3 {
        fixture.transition(false).await.unwrap();
        assert_eq!(*fixture.phase.borrow(), EnginePhase::Suspended);
        closed(&mut client).await;
        closed(&mut peer).await;
        assert!(fixture.tracker.snapshot().is_empty());
        assert_eq!(
            fixture.get("/runtime").await["instance_id"],
            runtime["instance_id"]
        );
        assert!(
            fixture.get("/runtime/traffic/history").await["samples"]
                .as_array()
                .unwrap()
                .contains(&history)
        );
        assert!(
            TcpStream::connect(fixture.dns).await.is_err(),
            "standalone DNS listener survived suspend"
        );
        std::fs::write(&hosts, "full:retained.invalid 192.0.2.61\n")?;
        std::fs::write(
            &geosite,
            b"\x0a\x18\x0a\x04keep\x12\x10\x08\x03\x12\x0cgone.invalid",
        )?;
        std::fs::write(
            &geoip,
            b"\x0a\x10\x0a\x04keep\x12\x08\x0a\x04\xc0\x00\x02\x00\x10\x18",
        )?;
        fixture.transition(true).await.unwrap();
        fixture.alive.pause_health_checks().await?;
        assert_eq!(*fixture.phase.borrow(), EnginePhase::Running);
        assert!(
            Arc::ptr_eq(&manager, &fixture.groups.read()),
            "resume replaced the accepted policy owner"
        );
        assert!(Arc::ptr_eq(&cache, &fixture.dns_service.cache()));
        assert_eq!(
            fixture.get("/runtime").await["instance_id"],
            runtime["instance_id"]
        );
        assert!(
            fixture.get("/runtime/traffic/history").await["samples"]
                .as_array()
                .unwrap()
                .contains(&history)
        );
        assert_eq!(
            extract_answer_ips(&dns_query(fixture.dns, "retained.invalid").await?),
            ["192.0.2.60".parse::<IpAddr>()?]
        );
        assert_eq!(
            extract_answer_ips(&dns_query(fixture.dns, "cached.invalid").await?),
            ["192.0.2.90".parse::<IpAddr>()?]
        );
        assert!(extract_answer_ips(&dns_query(fixture.dns, "keep.invalid").await?).is_empty());
        assert_geo_route(&fixture, "keep.invalid", "target").await;
        assert_geo_route(&fixture, "gone.invalid", "block").await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                upstream.recv_from(&mut [0; 512])
            )
            .await
            .is_err(),
            "resume or cached/hosts queries contacted DNS upstream"
        );
        let expected_peer = if cycle % 2 == 0 {
            &second_peer
        } else {
            &fixture.peer
        };
        (client, peer) = exchange_tcp(
            &fixture,
            expected_peer,
            format!("fresh-cycle-{cycle}").as_bytes(),
        )
        .await?;
    }
    fixture.transition(false).await.unwrap();
    closed(&mut client).await;
    closed(&mut peer).await;
    fixture.finish(false).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn delay_samples_persist_across_suspend_resume_and_stop_at_shutdown() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state/honk.db");
    let mut node_id = uuid::Uuid::nil();
    let fixture = Fixture::start_with(|config, _| {
        config.experimental.cache_file.enabled = true;
        config.global.data_dir = directory.path().to_string_lossy().into_owned();
        node_id = config
            .nodes
            .iter()
            .find(|node| node.name == "peer")
            .unwrap()
            .id;
    })
    .await?;
    let db = fixture.cache_db.as_ref().unwrap().clone();
    let sqlite = rusqlite::Connection::open(&path)?;
    let alive = fixture.alive.clone();
    let record = |delay| {
        alive.report_available_traffic(node_id, ProbeDomain::Tcp, IpVersion::V4);
        alive.record_probe_latency(
            node_id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(delay),
        );
    };
    let persisted = || -> anyhow::Result<Option<u64>> {
        use rusqlite::OptionalExtension;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let _ = db.load_delay_samples(now, 24 * 3600);
        let value: Option<i64> = sqlite
            .query_row(
                "SELECT delay_ms FROM delay_sample WHERE node = 'peer'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.map(i64::unsigned_abs))
    };
    for delay in [13, 29] {
        fixture.alive.pause_health_checks().await?;
        record(delay);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::timeout(WAIT, async {
            while persisted()? != Some(delay) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        tokio::time::resume();
        if delay == 13 {
            fixture.transition(false).await?;
            assert_eq!(*fixture.phase.borrow(), EnginePhase::Suspended);
            fixture.transition(true).await?;
            assert_eq!(*fixture.phase.borrow(), EnginePhase::Running);
        }
    }
    let _plane = fixture.finish(false).await;
    record(47);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        persisted()?,
        Some(29),
        "terminal shutdown must join the delay writer"
    );
    Ok(())
}
