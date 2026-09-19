use super::*;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use std::sync::atomic::AtomicUsize;

struct PanicOnceUpstream {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for PanicOnceUpstream {
    async fn query(&self, _name: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.notify_one();
            panic!("standalone DNS query failed");
        }
        let mut response = query.to_vec();
        response[2] |= 0x80;
        Ok(response)
    }
}

async fn suspend_listener(protocol: &str, panic_query: bool) -> anyhow::Result<()> {
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    let upstream = Arc::new(PanicOnceUpstream {
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
    });
    let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
        &config.dns,
    )?);
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            dns_router,
        )
        .with_cache_enabled(false),
    );
    let mut plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        Router::new(&[], "direct")?,
        Arc::new(ProxyRegistry::default_resolver()?),
        crate::dns::DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        forwarder,
    )?;
    let (phase, observed) = watch::channel(EnginePhase::Running);
    plane.phase = Some(phase);
    let bound = dns_listener::BoundDnsListener::bind(&honk_config::dns::DnsBindEndpoint::parse(
        &format!("{protocol}://127.0.0.1:0"),
    )?)?;
    let address = bound.local_addr();
    let dns = bound.spawn(
        plane.dns_controller.clone(),
        plane.concurrency_limit.clone(),
        plane.stats.clone(),
        plane.drain_tracker.clone(),
    )?;
    // Only the DNS owner is under test; no transparent sockets or privileged setup.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    tcp.set_nonblocking(true)?;
    let (stop, _) = watch::channel(false);
    let mut epoch = Some(RuntimeEpoch {
        listeners: BoundListeners {
            tcp4: tokio::io::unix::AsyncFd::new(tcp)?,
            tcp6: None,
            udp4: Vec::new(),
            udp6: Vec::new(),
            dns: None,
            nfqueue_enabled: false,
        },
        stop,
        ingress: JoinSet::new(),
        tcp: JoinSet::new(),
        maintenance: std::array::from_fn(|_| None),
        dns: Some(dns),
        janitor: None,
        removals: None,
        removal_errors: mpsc::unbounded_channel().1,
        critical_errors: mpsc::unbounded_channel().1,
        health_updates: None,
        #[cfg(feature = "ebpf")]
        queue: None,
    });
    let mut tcp_client = if protocol == "tcp" {
        Some(TcpStream::connect(address).await?)
    } else {
        None
    };
    let udp_client = UdpSocket::bind("127.0.0.1:0").await?;
    if panic_query {
        let query = crate::dns::forwarder::build_dns_query("panic.example", 1);
        if let Some(client) = tcp_client.as_mut() {
            crate::dns::transport::write_length_prefixed(client, &query).await?;
        } else {
            udp_client.send_to(&query, address).await?;
        }
        tokio::time::timeout(WAIT, upstream.entered.notified()).await?;
        tokio::time::timeout(WAIT, async {
            while plane.drain_tracker.active_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // The next request proves the supervisor reaped the failed child before
        // suspension, rather than discovering it only in the final child drain.
        let query = crate::dns::forwarder::build_dns_query("after-panic.example", 1);
        if tcp_client.is_some() {
            let mut client = TcpStream::connect(address).await?;
            crate::dns::transport::write_length_prefixed(&mut client, &query).await?;
            let mut response = Vec::new();
            tokio::time::timeout(
                WAIT,
                crate::dns::transport::read_length_prefixed_into(&mut client, &mut response, None),
            )
            .await??;
            assert_eq!(&response[..2], &query[..2]);
            tcp_client = Some(client);
        } else {
            udp_client.send_to(&query, address).await?;
            let mut response = [0; 512];
            let (size, _) =
                tokio::time::timeout(WAIT, udp_client.recv_from(&mut response)).await??;
            assert_eq!(&response[..2], &query[..2]);
            assert!(size >= 12 && response[2] & 0x80 != 0);
        }
    } else {
        tokio::time::timeout(WAIT, async {
            while plane.drain_tracker.active_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
    }
    let authorizations = crate::subscription::SubscriptionAuthorizations::new(
        &plane.config.read().await.subscriptions,
    )?;
    let mut commands = plane.command_rx.take().unwrap();
    let result = plane
        .suspend_epoch(&mut epoch, &mut commands, &authorizations)
        .await;
    if panic_query {
        let error = result.expect_err("a failed DNS child must prevent successful suspension");
        assert!(
            error
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_panic)
        );
        assert_ne!(*observed.borrow(), EnginePhase::Suspended);
    } else {
        result?;
        assert_eq!(*observed.borrow(), EnginePhase::Suspended);
    }
    assert_eq!(plane.drain_tracker.active_count(), 0);
    drop(tcp_client);
    plane.finalize_shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn reaped_dns_child_panic_prevents_successful_suspend() -> anyhow::Result<()> {
    for protocol in ["udp", "tcp"] {
        suspend_listener(protocol, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn owned_dns_child_cancellation_allows_suspend() -> anyhow::Result<()> {
    suspend_listener("tcp", false).await
}
