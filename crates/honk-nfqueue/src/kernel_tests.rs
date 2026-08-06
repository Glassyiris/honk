//! Real-kernel NFQUEUE test, run in a private network namespace
//! (root-gated, `--ignored`): install the ruleset, send a marked UDP
//! packet, receive it from the queue, verdict it, and assert the packet is
//! released — plus the RAII exactly-once guarantees.
//!
//! Run with:
//!   cargo test -p honk-nfqueue -- --ignored --nocapture

#[cfg(all(test, target_os = "linux"))]
mod kernel {
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::listener::{ListenerError, QueueListener};
    use crate::metrics::NfqueueMetrics;
    use crate::rules::{NftRuleset, RulesetConfig};
    use crate::verdict::VerdictError;
    use crate::{Decision, NfqueueService, NfqueueServiceConfig, VerdictPlan};

    const PENDING_MARK: u32 = 0x2000_0000;
    const ROUTE_MARK: u32 = 0x80;
    const QUEUE_BASE: u16 = 420;
    const SERVER_PORT: u16 = 34099;

    fn ruleset() -> NftRuleset {
        NftRuleset::new(RulesetConfig {
            interfaces: vec!["lo".to_string()],
            queue_base: QUEUE_BASE,
            workers: 1,
            pending_mark: PENDING_MARK,
        })
        .expect("ruleset socket")
    }

    /// Minimal rtnetlink RTM_NEWLINK to bring `lo` up in the test netns
    /// (test-only; the production engine has its own netlink client).
    fn bring_loopback_up() {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
        assert!(
            fd >= 0,
            "NETLINK_ROUTE socket: {}",
            io::Error::last_os_error()
        );
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "bind: {}", io::Error::last_os_error());

        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // len
        buf.extend_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK
        buf.extend_from_slice(&(0x01u16 | 0x04).to_ne_bytes()); // REQUEST|ACK
        buf.extend_from_slice(&1u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        // ifinfomsg: family, pad, type, index, flags, change
        buf.push(0u8); // AF_UNSPEC
        buf.push(0u8);
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&1i32.to_ne_bytes()); // lo
        buf.extend_from_slice(&1u32.to_ne_bytes()); // IFF_UP
        buf.extend_from_slice(&1u32.to_ne_bytes()); // change mask
        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());
        let ret = unsafe { libc::send(fd, buf.as_ptr() as *const _, buf.len(), 0) };
        assert!(ret >= 0, "send: {}", io::Error::last_os_error());
        let mut rbuf = [0u8; 256];
        let n = unsafe { libc::recv(fd, rbuf.as_mut_ptr() as *mut _, rbuf.len(), 0) };
        assert!(n >= 24, "short ack");
        let code = i32::from_ne_bytes(rbuf[16..20].try_into().unwrap());
        assert_eq!(
            code,
            0,
            "RTM_NEWLINK lo up failed: {}",
            io::Error::from_raw_os_error(-code)
        );
        unsafe { libc::close(fd) };
    }

    fn marked_client(mark: u32) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const _,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "SO_MARK: {}", io::Error::last_os_error());
        socket
    }

    fn server() -> UdpSocket {
        let socket = UdpSocket::bind(("127.0.0.1", SERVER_PORT)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        socket
    }

    fn recv_with_deadline(socket: &UdpSocket, deadline: Duration) -> Option<Vec<u8>> {
        socket.set_read_timeout(Some(deadline)).unwrap();
        let mut buf = [0u8; 2048];
        socket.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    }

    /// The full staged-decision loop on a real kernel.
    #[test]
    #[ignore = "requires root; cargo test -p honk-nfqueue -- --ignored"]
    fn nfqueue_kernel_verdict_loop() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: requires root");
            return;
        }
        std::thread::Builder::new()
            .name("nfq-kernel-test".into())
            .spawn(|| {
                // A private netns per test thread: the nftables table and
                // queue bindings die with it, no host state is touched.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
                bring_loopback_up();
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run())
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn recv_packet(
        listener: &mut QueueListener,
    ) -> (crate::packet::QueuedPacket, crate::verdict::VerdictGuard) {
        tokio::time::timeout(Duration::from_secs(3), listener.recv())
            .await
            .expect("packet must reach the queue within 3s")
            .expect("listener recv")
    }

    async fn run() {
        let metrics = NfqueueMetrics::default();
        let mut rules = ruleset();
        rules.install().expect("install rules");
        rules.verify().expect("self-check");

        let mut listener =
            QueueListener::bind(QUEUE_BASE, 128, false, metrics.clone()).expect("bind queue");
        // A second binder on the same queue must fail: queue conflicts are
        // a startup error, never silent sharing.
        match QueueListener::bind(QUEUE_BASE, 128, false, metrics.clone()) {
            Err(ListenerError::QueueBusy(q)) => assert_eq!(q, QUEUE_BASE),
            other => panic!("expected QueueBusy, got {}", other.is_ok()),
        }

        let server = server();

        // 1. Marked packet is queued, verdict ACCEPT releases it to the
        //    server, and the routing mark survives while the pending bit is
        //    cleared by the verdict.
        let client = marked_client(PENDING_MARK | ROUTE_MARK);
        client
            .send_to(b"nfq-payload-1", ("127.0.0.1", SERVER_PORT))
            .unwrap();
        let (packet, mut guard) = recv_packet(&mut listener).await;
        assert_eq!(packet.queue_num, QUEUE_BASE);
        assert_ne!(packet.mark & PENDING_MARK, 0, "pending mark visible");
        assert_ne!(packet.mark & ROUTE_MARK, 0, "routing mark visible");
        let tuple = packet.udp_tuple().expect("udp tuple");
        assert_eq!(tuple.dst_port, SERVER_PORT);
        assert_eq!(&packet.payload[tuple.payload_offset..], b"nfq-payload-1");
        guard.accept(ROUTE_MARK).expect("accept verdict");
        assert_eq!(
            recv_with_deadline(&server, Duration::from_secs(2)),
            Some(b"nfq-payload-1".to_vec()),
            "verdict ACCEPT must release the original packet"
        );
        // Exactly-once: a second verdict on the same packet is an error.
        assert!(matches!(
            guard.accept(ROUTE_MARK),
            Err(VerdictError::AlreadyCommitted)
        ));
        assert!(matches!(
            guard.drop_packet(),
            Err(VerdictError::AlreadyCommitted)
        ));
        drop(guard); // committed: Drop must not fire another verdict
        let snap = metrics.snapshot();
        assert_eq!(snap.verdict_accept_total, 1);
        assert_eq!(snap.verdict_drop_total, 0);
        assert_eq!(snap.guard_default_drop_total, 0);

        // 2. A guard dropped without a commit fails closed (NF_DROP): the
        //    server must not receive the packet.
        client
            .send_to(b"nfq-payload-2", ("127.0.0.1", SERVER_PORT))
            .unwrap();
        let (_packet, guard) = recv_packet(&mut listener).await;
        drop(guard);
        assert_eq!(
            recv_with_deadline(&server, Duration::from_millis(400)),
            None,
            "uncommitted guard must drop the packet"
        );
        let snap = metrics.snapshot();
        assert_eq!(snap.verdict_drop_total, 1);
        assert_eq!(snap.guard_default_drop_total, 1);

        // 3. Explicit NF_DROP.
        client
            .send_to(b"nfq-payload-3", ("127.0.0.1", SERVER_PORT))
            .unwrap();
        let (_packet, mut guard) = recv_packet(&mut listener).await;
        guard.drop_packet().expect("drop verdict");
        drop(guard); // release the socket Arc before listener teardown
        assert_eq!(
            recv_with_deadline(&server, Duration::from_millis(400)),
            None,
            "explicit drop must not deliver"
        );
        drop(listener);
        rules.uninstall().expect("uninstall rules");
        rules.uninstall().expect("uninstall is idempotent");

        // 4. Service-level smoke: start → marked packet flows through the
        //    decide callback → server receives → clean shutdown.
        let decide: Decision = Arc::new(|packet: QueuedPacketAlias| {
            Box::pin(async move {
                VerdictPlan::Accept {
                    mark: packet.mark & !PENDING_MARK,
                }
            })
        });
        let service = NfqueueService::start(
            NfqueueServiceConfig {
                queue_base: QUEUE_BASE,
                workers: 1,
                queue_max_packets: 128,
                fail_open: false,
                interfaces: vec!["lo".to_string()],
                pending_mark: PENDING_MARK,
            },
            decide,
        )
        .await
        .expect("service start");
        client
            .send_to(b"nfq-payload-4", ("127.0.0.1", SERVER_PORT))
            .unwrap();
        // The worker is a task on this single-threaded runtime: wait for
        // its verdict before asserting delivery — a blocking std recv here
        // would otherwise starve it.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service.metrics().snapshot().verdict_accept_total == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("service verdict recorded");
        assert_eq!(
            recv_with_deadline(&server, Duration::from_secs(2)),
            Some(b"nfq-payload-4".to_vec()),
            "service worker must accept the packet through"
        );
        service.shutdown().await;
    }

    // Alias so the closure signature stays readable.
    type QueuedPacketAlias = crate::packet::QueuedPacket;
}
