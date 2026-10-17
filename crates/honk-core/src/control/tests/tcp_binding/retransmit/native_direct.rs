use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    handle: &ControlPlaneHandle,
    client_ns: &OwnedFd,
    server_ns: &OwnedFd,
    client_ip: IpAddr,
    wan_ip: IpAddr,
    target: SocketAddr,
    server: std::net::TcpListener,
    dials: &AtomicUsize,
    wan: bool,
) -> anyhow::Result<()> {
    handle
        .ebpf
        .write()
        .await
        .publish_routing_plan(&port_plan(target.port(), "direct", true)?, &[])?;
    let (tap, wire) = in_test_netns(server_ns, || -> anyhow::Result<_> {
        Ok((SynTap(packet_socket()?), Wire::on("honk-s0")?))
    })?;
    let server = TcpListener::from_std(server)?;
    let (mut client, source) = if wan {
        Client::wan(wan_ip, target).await?
    } else {
        Client::lan(client_ns, client_ip, target)?
    };
    let (synack, mut syns) = original_synack(&mut client, &wire, &tap, source, target).await?;
    let key = conn_key(source, target);
    {
        let backend = handle.ebpf.read().await;
        ensure!(
            backend.tcp_conn_state_lookup(&key)?.is_some(),
            "native SYN did not publish conn state"
        );
        ensure!(
            backend.routing_handoff_lookup(&key)?.is_none()
                && backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                    .is_none(),
            "native direct SYN unexpectedly published a proxy handoff/redirect pair"
        );
    }
    let sent_retries = tokio::time::timeout(SYN_RETRY_DEADLINE, async {
        loop {
            let retries = client.retry_count().await?;
            if retries != 0 {
                return Ok::<_, anyhow::Error>(retries);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("native client did not retransmit")??;
    await_retry(&tap, source, target, &mut syns)
        .await
        .with_context(|| format!("client TCP_INFO reports {sent_retries} retransmissions"))?;
    client.release()?;
    wire.replay(&synack)?;
    let client_stream = client.handshake().await?;
    let exchange = async {
        let (mut stream, peer) = server.accept().await?;
        ensure!(
            peer == source,
            "native server saw a proxy source {peer}, not {source}"
        );
        let mut received = vec![0; UP.len()];
        stream.read_exact(&mut received).await?;
        ensure!(received == UP, "native server received the wrong bytes");
        stream.write_all(DOWN).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (server_result, client_result) = tokio::join!(
        tokio::time::timeout(FORWARD_DEADLINE, exchange),
        tokio::time::timeout(FORWARD_DEADLINE, client.exchange(client_stream)),
    );
    server_result.context("native server exchange deadline")??;
    client_result.context("native client exchange deadline")??;
    ensure!(
        dials.load(Ordering::SeqCst) == 0,
        "native direct flow entered the proxy dialer"
    );
    Ok(())
}
