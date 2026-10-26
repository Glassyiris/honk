use super::*;
use crate::ebpf::interface::{Direction, TcProgram};
use crate::netlink::LinkSnapshot;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

fn link(ifindex: u32, name: &str) -> LinkSnapshot {
    LinkSnapshot {
        ifindex: NonZeroU32::new(ifindex).unwrap(),
        name: name.into(),
        arphrd: 1,
        flags: 0,
        master: None,
        kind: None,
        mac: Some([2, 0, 0, 0, 0, ifindex as u8]),
    }
}

/// Fixed topology: no `lo`, no kernel.
fn topology() -> Topology {
    Topology {
        links: vec![link(2, "eth0"), link(3, "eth1")],
        default_route: None,
    }
}

fn fake_fd() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

type Key = (NonZeroU32, Direction);

fn key(binding: &Binding) -> Key {
    (binding.ifindex, binding.direction)
}

/// A kernel-free `apply` with the same contract: diff by `(ifindex,
/// direction)`, reprogram in place, report what could not be bound.
fn model_apply(
    snapshot: BindingSnapshot,
    plan: &InterfacePlan,
    fail_egress: bool,
    topology_changed: bool,
) -> ApplyReport {
    let mut report = ApplyReport {
        topology_changed,
        ..ApplyReport::default()
    };
    for (held, ..) in &snapshot.owned {
        if !plan.bindings.iter().any(|b| key(b) == key(held)) {
            report.commit.remove.push(key(held));
        }
    }
    for binding in &plan.bindings {
        match snapshot
            .owned
            .iter()
            .find(|(held, ..)| key(held) == key(binding))
        {
            None if fail_egress && binding.direction == Direction::Egress => report
                .failed
                .push((binding.clone(), anyhow::anyhow!("injected attach failure"))),
            None => {
                report
                    .commit
                    .add
                    .push((binding.clone(), binding.ifindex.get() * 10, fake_fd()))
            }
            Some((held, ..)) => {
                if held.interface != binding.interface {
                    report.commit.rename.push((
                        binding.ifindex,
                        binding.direction,
                        binding.interface.clone(),
                    ))
                }
                if held.program != binding.program {
                    report.commit.reprogram.push((
                        binding.ifindex,
                        binding.direction,
                        binding.program,
                    ))
                }
            }
        }
    }
    report
}

#[derive(Clone, Default)]
struct Stub {
    fail_egress: Arc<AtomicBool>,
    /// Report `topology_changed` on every apply.
    moving: Arc<AtomicBool>,
    applies: Arc<AtomicU64>,
    /// Replaces the fixed topology.
    links: Arc<parking_lot::Mutex<Option<Topology>>>,
    /// Names the stub `accept_ra` step was asked to write.
    accept_ra: Arc<parking_lot::Mutex<Vec<String>>>,
}

impl Stub {
    fn reconciler(&self) -> Reconciler {
        let (fail, count, moving) = (
            self.fail_egress.clone(),
            self.applies.clone(),
            self.moving.clone(),
        );
        let (links, accept_ra) = (self.links.clone(), self.accept_ra.clone());
        Reconciler {
            read_topology: Arc::new(move |_| Ok(links.lock().clone().unwrap_or_else(topology))),
            apply: Arc::new(move |snapshot, plan, _, _| {
                count.fetch_add(1, Ordering::SeqCst);
                model_apply(
                    snapshot,
                    plan,
                    fail.load(Ordering::SeqCst),
                    moving.load(Ordering::SeqCst),
                )
            }),
            accept_ra: Arc::new(move |name| accept_ra.lock().push(name.to_string())),
        }
    }
}

struct Fixture {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    commits: Arc<AtomicU64>,
    stub: Stub,
}

fn fixture(lan: &[&str], wan: &[&str]) -> Fixture {
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let commits = backend.binding_commits.clone();
    let mut config = honk_config::Config::default();
    config.global.lan_interface = lan.iter().map(|name| name.to_string()).collect();
    config.global.wan_interface = wan.iter().map(|name| name.to_string()).collect();
    Fixture {
        ebpf: Arc::new(RwLock::new(Box::new(backend))),
        config: Arc::new(RwLock::new(Arc::new(config))),
        commits,
        stub: Stub::default(),
    }
}

impl Fixture {
    fn watch(&self) -> (Watch, mpsc::Receiver<crate::control::ControlCommand>) {
        let (tx, rx) = mpsc::channel(4);
        let watch = Watch::new(
            self.ebpf.clone(),
            self.config.clone(),
            tx,
            self.stub.reconciler(),
        );
        (watch, rx)
    }

    /// Every held binding with its link id.
    async fn bindings(&self) -> Vec<(Binding, u32)> {
        self.ebpf
            .read()
            .await
            .interface_binding_snapshot()
            .unwrap()
            .owned
            .into_iter()
            .map(|(b, id, _)| (b, id))
            .collect()
    }

    async fn owned(&self) -> Vec<(u32, Direction, TcProgram)> {
        let mut owned: Vec<_> = (self.bindings().await)
            .into_iter()
            .map(|(b, _)| (b.ifindex.get(), b.direction, b.program))
            .collect();
        owned.sort();
        owned
    }

    /// `(ifindex, direction, interface name, link id)` of every held binding.
    async fn held(&self) -> Vec<(u32, Direction, String, u32)> {
        let mut held: Vec<_> = (self.bindings().await)
            .into_iter()
            .map(|(b, id)| (b.ifindex.get(), b.direction, b.interface, id))
            .collect();
        held.sort();
        held
    }

    async fn set_interfaces(&self, lan: &[&str], wan: &[&str]) {
        let mut config = self.config.write().await;
        let global = &mut Arc::make_mut(&mut config).global;
        global.lan_interface = lan.iter().map(|name| name.to_string()).collect();
        global.wan_interface = wan.iter().map(|name| name.to_string()).collect();
    }
}

#[test]
fn link_messages_are_recognised_inside_a_datagram() {
    let message = |kind: u16, length: u32| {
        let mut bytes = vec![0u8; (length as usize).max(16)];
        bytes[0..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes
    };
    // RTM_NEWROUTE (24) then RTM_NEWADDR (20): no link message.
    let mut datagram = message(24, 30);
    datagram.resize(32, 0);
    datagram.extend(message(20, 24));
    assert!(!has_link_message(&datagram));
    // A link message behind a padded route message is still found.
    datagram.extend(message(RTM_DELLINK, 16));
    assert!(has_link_message(&datagram));
    assert!(has_link_message(&message(RTM_NEWLINK, 16)));
    // A malformed length ends the scan instead of looping.
    assert!(!has_link_message(&message(24, 0)));
    assert!(!has_link_message(&[]));
}

#[test]
fn only_link_events_and_overruns_force_verification() {
    assert!(!Drained::default().verify());
    assert!(
        Drained {
            link_event: true,
            ..Drained::default()
        }
        .verify()
    );
    assert!(
        Drained {
            overrun: true,
            ..Drained::default()
        }
        .verify()
    );
}

#[tokio::test]
async fn a_watcher_that_cannot_poll_is_reported() {
    let degradations = Arc::new(crate::degradations::Degradations::default());
    // epoll refuses regular files.
    let file = tempfile::tempfile().unwrap();
    let f = fixture(&[], &[]);
    let (commands, _receiver) = mpsc::channel(1);
    let (_stop, rx) = watch::channel(false);
    run(
        file.into(),
        f.ebpf,
        f.config,
        commands,
        rx,
        Arc::clone(&degradations),
        f.stub.reconciler(),
    )
    .await;
    assert_eq!(
        degradations
            .get(crate::degradations::Component::IfaceWatch)
            .map(|issue| issue.reason),
        Some("poll_setup_failed")
    );
}

#[tokio::test]
async fn auto_wan_moving_onto_a_bound_lan_root_writes_accept_ra() {
    let f = fixture(&["eth0"], &["auto"]);
    let (mut watch, _rx) = f.watch();

    // No default route yet: eth0 is plain LAN, no WAN root to write.
    watch.reconcile(false).await.unwrap();
    assert!(f.stub.accept_ra.lock().is_empty());

    // The default route lands on eth0: it becomes LAN+WAN by reprogramming its
    // egress, not by a new binding.
    *f.stub.links.lock() = Some(Topology {
        default_route: Some("eth0".into()),
        ..topology()
    });
    assert!(watch.reconcile(false).await.unwrap());
    assert_eq!(
        f.owned().await,
        [
            (2, Direction::Ingress, TcProgram::LanIngressL2),
            (2, Direction::Egress, TcProgram::WanEgressL2),
        ]
    );
    assert_eq!(*f.stub.accept_ra.lock(), ["eth0"]);

    // Steady state writes nothing more; a newly added WAN root does.
    assert!(!watch.reconcile(false).await.unwrap());
    assert_eq!(f.stub.accept_ra.lock().len(), 1);
    f.set_interfaces(&["eth0"], &["auto", "eth1"]).await;
    assert!(watch.reconcile(false).await.unwrap());
    assert_eq!(*f.stub.accept_ra.lock(), ["eth0", "eth1"]);
}

#[tokio::test]
async fn renamed_port_keeps_its_binding_and_refreshes_the_name() {
    let f = fixture(&["br0"], &[]);
    let topology_with_port = |port: &str| Topology {
        links: vec![
            LinkSnapshot {
                kind: Some("bridge".into()),
                ..link(10, "br0")
            },
            LinkSnapshot {
                master: NonZeroU32::new(10),
                ..link(11, port)
            },
        ],
        default_route: None,
    };
    *f.stub.links.lock() = Some(topology_with_port("p1"));
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    let before = f.held().await;
    assert_eq!(before.len(), 4, "{before:?}");
    let commits = f.commits.load(Ordering::Relaxed);

    // Same ifindex, new name: the keys and links stay, the observed name follows.
    *f.stub.links.lock() = Some(topology_with_port("p1x"));
    assert!(watch.reconcile(false).await.unwrap());
    let after = f.held().await;
    let rename = |held: &[(u32, Direction, String, u32)]| {
        held.iter()
            .map(|(i, d, name, id)| {
                let name = if name == "p1x" { "p1" } else { name };
                (*i, *d, name.to_string(), *id)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(rename(&after), before, "only the port's name changed");
    assert_eq!(
        after.iter().filter(|(_, _, name, _)| name == "p1x").count(),
        2
    );
    assert!(after.iter().all(|(_, _, name, _)| name != "p1"));
    assert_eq!(f.commits.load(Ordering::Relaxed), commits + 1);
    assert!(!watch.reconcile(false).await.unwrap());
}

#[tokio::test]
async fn attach_failure_warning_rearms_after_success() {
    let f = fixture(&["eth0"], &[]);
    f.stub.fail_egress.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();

    for _ in 0..2 {
        assert!(watch.reconcile(false).await.is_err());
        assert!(watch.warned.contains("eth0"));
    }
    // The healthy direction was committed, the failed one is retried.
    assert_eq!(
        f.owned().await,
        [(2, Direction::Ingress, TcProgram::LanIngressL2)]
    );
    f.stub.fail_egress.store(false, Ordering::SeqCst);
    assert!(watch.reconcile(false).await.unwrap());
    assert!(watch.warned.is_empty());
    assert_eq!(f.owned().await.len(), 2);
}

#[tokio::test]
async fn attach_failure_warning_ends_when_interface_is_no_longer_configured() {
    let f = fixture(&["eth0"], &[]);
    f.stub.fail_egress.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();

    assert!(watch.reconcile(false).await.is_err());
    f.set_interfaces(&[], &[]).await;
    watch.reconcile(false).await.unwrap();
    assert!(watch.warned.is_empty());
    assert!(f.owned().await.is_empty(), "removed from config, released");
}

#[tokio::test]
async fn a_moving_topology_is_retried_once_per_batch() {
    let f = fixture(&["eth0"], &[]);
    f.stub.moving.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    assert_eq!(f.stub.applies.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn topology_or_network_event_requests_refresh() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, mut rx) = f.watch();
    watch.pending_notification = false;

    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(crate::control::ControlCommand::NetworkChanged)
    ));

    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    watch.reconcile_and_notify(true, false).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(crate::control::ControlCommand::NetworkChanged)
    ));
}

/// An unchanged topology keeps the original hooks: the ticker must not
/// churn working TC links merely because it reconciles periodically.
#[tokio::test]
async fn reconcile_reuses_unchanged_hooks() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, _rx) = f.watch();

    watch.reconcile(false).await.unwrap();
    let first = f.commits.load(Ordering::Relaxed);
    assert_eq!(first, 1, "first reconcile binds the configured LAN");

    for verify in [false, true] {
        assert!(!watch.reconcile(verify).await.unwrap());
    }
    assert_eq!(
        f.commits.load(Ordering::Relaxed),
        first,
        "unchanged reconcile must not take the write lock"
    );
}

fn watcher_fixture(
    f: &Fixture,
    commands: mpsc::Sender<crate::control::ControlCommand>,
    reconciler: Reconciler,
) -> (IfaceWatcher, std::os::unix::net::UnixDatagram) {
    let (events, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    events.set_nonblocking(true).unwrap();
    let (stop, rx) = watch::channel(false);
    let handle = tokio::spawn(run(
        events.into(),
        f.ebpf.clone(),
        f.config.clone(),
        commands,
        rx,
        Arc::default(),
        reconciler,
    ));
    (IfaceWatcher { handle, stop }, writer)
}

#[tokio::test]
async fn full_control_queue_retains_hint_and_shutdown_joins_the_worker() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let f = fixture(&["eth0"], &[]);
        let retained_backend = Arc::downgrade(&f.ebpf);
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(crate::control::ControlCommand::NetworkChanged)
            .unwrap();
        let (watcher, _events) = watcher_fixture(&f, tx, f.stub.reconciler());
        let Fixture { ebpf, .. } = f;
        drop(ebpf);

        // Freeing capacity must deliver the startup hint the full queue held back.
        assert!(matches!(
            rx.recv().await,
            Some(crate::control::ControlCommand::NetworkChanged)
        ));
        assert!(matches!(
            rx.recv().await,
            Some(crate::control::ControlCommand::NetworkChanged)
        ));
        watcher.shutdown(Duration::from_secs(1)).await;
        assert!(
            retained_backend.upgrade().is_none(),
            "shutdown must join the retained worker"
        );
    })
    .await
    .expect("watcher did not deliver the retained hint or join on shutdown");
}

/// Shutdown never aborts a batch whose blocking thread holds link FDs: it
/// keeps waiting (and warning) until the apply returns.
#[tokio::test]
async fn shutdown_waits_for_an_in_flight_apply() {
    let f = fixture(&["eth0"], &[]);
    let entered = Arc::new(AtomicBool::new(false));
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let gate = Arc::new(parking_lot::Mutex::new(gate));
    let reconciler = Reconciler {
        read_topology: Arc::new(|_| Ok(topology())),
        apply: {
            let entered = entered.clone();
            Arc::new(move |snapshot, plan, _, _| {
                entered.store(true, Ordering::SeqCst);
                gate.lock().recv().unwrap();
                model_apply(snapshot, plan, false, false)
            })
        },
        accept_ra: Arc::new(|_| {}),
    };
    let (tx, _rx) = mpsc::channel(4);
    let (watcher, _events) = watcher_fixture(&f, tx, reconciler);
    while !entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    {
        let mut backend = tokio::time::timeout(Duration::from_millis(100), f.ebpf.write())
            .await
            .expect("blocking apply must not hold the backend lock");
        backend.set_datapath_ready(false).unwrap();
    }

    let shutdown = tokio::spawn(watcher.shutdown(Duration::from_millis(50)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown abandoned a running batch"
    );

    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown must finish once the batch does")
        .unwrap();
    assert_eq!(
        f.owned().await.len(),
        2,
        "the in-flight batch finished its commit before the task ended"
    );
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn route_only_change_wakes_network_subscription() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    std::thread::spawn(|| {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());

        let mut netlink = crate::netlink::NlSock::new().expect("netlink socket");
        netlink
            .add_veth_pair("route-veth", "route-peer")
            .expect("veth pair");
        let (ifindex, _) = netlink.get_link("route-veth").expect("veth ifindex");
        netlink.set_link_up(ifindex, true).expect("bring veth up");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("tokio runtime");

        runtime.block_on(async move {
            let events = subscribe_network_events().expect("network event subscription");
            let events = unsafe { tokio::io::unix::AsyncFd::register(events) }
                .expect("async netlink socket");
            netlink
                .add_route(
                    crate::netlink::FAM_V4,
                    254,
                    crate::netlink::ROUTE_UNICAST,
                    crate::netlink::SCOPE_LINK,
                    crate::netlink::PROTO_STATIC,
                    None,
                    None,
                    Some(ifindex),
                )
                .expect("add default route");

            let _ready = tokio::time::timeout(Duration::from_secs(1), events.readable())
                .await
                .expect("route event timeout")
                .expect("route event readiness");
        });
    })
    .join()
    .expect("network namespace thread");
}

#[tokio::test]
async fn failed_retained_verification_is_retried_on_a_route_only_batch() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    let held = f.owned().await;
    let commits = f.commits.load(Ordering::Relaxed);
    let verifies = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let failing = Arc::new(AtomicBool::new(true));
    watch.reconciler.apply = {
        let verifies = verifies.clone();
        let failing = failing.clone();
        Arc::new(move |snapshot, plan, _, verify| {
            verifies.lock().push(verify);
            let binding = snapshot.owned[0].0.clone();
            let mut report = model_apply(snapshot, plan, false, false);
            if failing.load(Ordering::SeqCst) {
                report
                    .failed
                    .push((binding, anyhow::anyhow!("query failed")));
            }
            report
        })
    };
    assert!(watch.reconcile(true).await.is_err());
    assert!(watch.reconcile(false).await.is_err());
    assert_eq!(f.owned().await, held);
    assert_eq!(f.commits.load(Ordering::Relaxed), commits);
    failing.store(false, Ordering::SeqCst);
    assert!(!watch.reconcile(false).await.unwrap());
    assert!(!watch.reconcile(false).await.unwrap());
    assert_eq!(*verifies.lock(), [true, true, true, false]);
}

#[test]
fn drain_forces_verification_after_enobufs_and_stops_at_the_message_bound() {
    for terminal in [Errno::EAGAIN, Errno::EIO] {
        let mut outcomes = [Err(Errno::ENOBUFS), Err(terminal)].into_iter();
        let drained = drain_with(&mut [0; 64], |_| outcomes.next().unwrap()).unwrap();
        assert!(drained.verify());
        assert_eq!(drained.empty, terminal == Errno::EAGAIN);
    }
    for (kind, verify) in [(24u16, false), (RTM_NEWLINK, true), (RTM_DELLINK, true)] {
        let mut calls = 0;
        let drained = drain_with(&mut [0; 64], |buffer| {
            calls += 1;
            buffer[0..4].copy_from_slice(&16u32.to_ne_bytes());
            buffer[4..6].copy_from_slice(&kind.to_ne_bytes());
            Ok(16)
        })
        .unwrap();
        assert_eq!(calls, 64);
        assert!(!drained.empty);
        assert_eq!(drained.verify(), verify);
    }
}
