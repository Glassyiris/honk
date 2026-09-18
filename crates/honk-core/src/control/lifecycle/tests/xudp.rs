use super::*;
use honk_config::node::{Node, OutboundConfig, VlessConfig, VlessUdpEncoding};

const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

async fn accept_carrier(listener: &tokio::net::TcpListener) -> TcpStream {
    tokio::time::timeout(WAIT, async {
        loop {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut header = [0; 19];
            if peer.read_exact(&mut header).await.is_err() {
                continue;
            }
            let mut expected = vec![0];
            expected.extend_from_slice(uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
            expected.extend_from_slice(&[0, 3]);
            assert_eq!(header.as_slice(), expected);
            peer.write_all(&[0, 0]).await.unwrap();
            return peer;
        }
    })
    .await
    .unwrap()
}

// Fixed IPv4/SID-zero vectors, not another protocol decoder. Unexpected frames fail byte-for-byte.
async fn exchange_packet(
    client: &UdpSocket,
    peer: &mut TcpStream,
    target: SocketAddr,
    payload: &[u8],
    first: bool,
) -> [u8; 8] {
    tokio::time::timeout(WAIT, async {
        let SocketAddr::V4(target_v4) = target else {
            panic!("IPv4 fixture");
        };
        let port = target.port().to_be_bytes();
        let mut expected = vec![
            0,
            if first { 20 } else { 12 },
            0,
            0,
            if first { 1 } else { 2 },
            1,
            2,
            port[0],
            port[1],
            1,
        ];
        expected.extend_from_slice(&target_v4.ip().octets());
        let mut metadata = [0; 14];
        peer.read_exact(&mut metadata).await.unwrap();
        assert_eq!(
            metadata.as_slice(),
            expected,
            "both destinations must use the same source carrier and SID"
        );
        let mut source_id = [0; 8];
        if first {
            peer.read_exact(&mut source_id).await.unwrap();
            assert_ne!(source_id, [0; 8]);
        }
        let mut body = vec![0; 2 + payload.len()];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(&body[..2], &(payload.len() as u16).to_be_bytes());
        assert_eq!(&body[2..], payload, "cancelled or old data was replayed");
        metadata[1] = 12;
        metadata[4] = 2;
        peer.write_all(&metadata).await.unwrap();
        peer.write_all(&body).await.unwrap();
        let mut answer = [0; 128];
        let (length, source) = client.recv_from(&mut answer).await.unwrap();
        assert_eq!(
            source, target,
            "source-shared replies must retain each exact destination"
        );
        assert_eq!(&answer[..length], payload);
        source_id
    })
    .await
    .unwrap()
}

async fn closed_carrier(peer: &mut TcpStream) {
    let mut remaining = Vec::new();
    let result = tokio::time::timeout(WAIT, peer.read_to_end(&mut remaining))
        .await
        .unwrap();
    assert!(
        result.is_ok()
            || result.as_ref().is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ))
    );
    assert!(
        remaining.is_empty() || remaining == [0, 4, 0, 0, 3, 0],
        "retirement may send END, never replay data: {remaining:?}"
    );
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn suspend_closes_two_shared_xudp_views_and_resume_uses_fresh_carrier() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(90), async {
        let fixture = Fixture::start_with(|config, address| {
            let mut node = Node {
                name: "peer".into(),
                address: address.to_string(),
                host: address.ip().to_string(),
                port: address.port(),
                outbound: OutboundConfig::Vless(VlessConfig {
                    uuid: Some(UUID.into()),
                    udp_encoding: VlessUdpEncoding::Xudp,
                    ..Default::default()
                }),
                ..Default::default()
            };
            node.id = node.derive_id();
            config.nodes.retain(|node| node.name != "peer");
            config.groups[0].nodes = vec![node.id];
            config.nodes.push(node);
        })
        .await?;
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let first_target = fixture.tproxy;
        let second_target = SocketAddr::from(([127, 0, 0, 2], fixture.tproxy.port()));
        client.send_to(b"old-first", first_target).await?;
        let mut old_carrier = accept_carrier(&fixture.peer).await;
        let old_source_id =
            exchange_packet(&client, &mut old_carrier, first_target, b"old-first", true).await;
        client.send_to(b"old-second", second_target).await?;
        exchange_packet(
            &client,
            &mut old_carrier,
            second_target,
            b"old-second",
            false,
        )
        .await;
        let before = fixture.get("/connections?type=udp&detail=full").await;
        let flows = before["udp"].as_array().unwrap();
        assert_eq!(flows.len(), 2);
        assert_ne!(flows[0]["id"], flows[1]["id"]);
        assert!(
            flows
                .iter()
                .all(|flow| flow["src"] == client.local_addr().unwrap().to_string())
        );
        let old_ids: Vec<_> = flows.iter().map(|flow| flow["id"].clone()).collect();
        fixture.transition(false).await.unwrap();
        assert_eq!(*fixture.phase.borrow(), EnginePhase::Suspended);
        closed_carrier(&mut old_carrier).await;
        assert!(
            fixture.get("/connections?type=udp").await["udp"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut [0; 128]))
                .await
                .is_err()
        );
        fixture.transition(true).await.unwrap();
        fixture.alive.pause_health_checks().await?;
        assert_eq!(*fixture.phase.borrow(), EnginePhase::Running);
        assert!(
            fixture.get("/connections?type=udp").await["udp"]
                .as_array()
                .unwrap()
                .is_empty(),
            "resume restored old flow views"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut [0; 128]))
                .await
                .is_err()
        );
        client.send_to(b"fresh-first", first_target).await?;
        let mut new_carrier = accept_carrier(&fixture.peer).await;
        let new_source_id = exchange_packet(
            &client,
            &mut new_carrier,
            first_target,
            b"fresh-first",
            true,
        )
        .await;
        assert_ne!(
            new_source_id, old_source_id,
            "a retired runtime's source identity must not be restored"
        );
        client.send_to(b"fresh-second", second_target).await?;
        exchange_packet(
            &client,
            &mut new_carrier,
            second_target,
            b"fresh-second",
            false,
        )
        .await;
        let after = fixture.get("/connections?type=udp&detail=full").await;
        let flows = after["udp"].as_array().unwrap();
        assert_eq!(flows.len(), 2);
        assert!(flows.iter().all(|flow| !old_ids.contains(&flow["id"])));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), new_carrier.read_u8())
                .await
                .is_err(),
            "fresh carrier replayed old traffic"
        );
        fixture.transition(false).await.unwrap();
        closed_carrier(&mut new_carrier).await;
        fixture.finish(false).await;
        Ok(())
    })
    .await?
}
