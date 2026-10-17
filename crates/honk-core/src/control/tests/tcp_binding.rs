//! Real SYN/request/accepted-FD proof. Packet replay only releases a captured SYNACK;
//! the original SYN and final ACK traverse the production TC and request hooks.

use super::support::TestRetirement;
use super::support::netns::{
    build_lab, lab_config, pinned_hash_snapshot, pinned_map, run_isolated,
};
use super::{
    NETNS_TEST_TIMEOUT, configure_test_edge, in_test_netns, udp_test_forwarder, udp_test_node,
};
use crate::control::{ControlPlane, ControlPlaneHandle};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::{EbpfBackend, TcpSocketOwnership, real::RealEbpfBackend};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::{Array, HashMap};
use honk_config::node::Node;
use honk_ebpf_common::{
    FlowMapValue, RedirectTuple,
    conn::{ConnState, FlowIncarnationSequence},
    redirect_need::{RoutingHandoffEntry, TcpRequestKey, TcpSocketBinding, TuplesKey},
};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket};

mod lifetime;
mod retransmit;

const CHILD: &str = "HONK_TCP_BINDING_CHILD";
const ROOT: &str = "/sys/fs/bpf/tcp-binding";
const FIRST_PUBLISHED_INCARNATION: u64 = 0x005a_1234_5678_9abc;

// Cases whose branch is family-independent (shared fexit/userspace code, no v4/v6
// hook of its own) run once on v4; `accepted` covers the v6 hooks.
macro_rules! kernel_case {
    ($name:ident, $case:literal) => {
        kernel_case!($name, $case, "v4", "v6");
    };
    ($name:ident, $case:literal, $($family:literal),+) => {
        #[test]
        #[ignore = "requires Linux 6.12+, root and the disposable kernel VM gate"]
        fn $name() -> anyhow::Result<()> {
            run_isolated(
                concat!("control::tests::tcp_binding::", stringify!($name)),
                CHILD,
                [$($family),+],
                |family| run_child(family, $case),
            )
        }
    };
}

// Ablate route_request's skb incarnation capture or the fexit storage CREATE.
kernel_case!(netns_tcp_accepted_fd_proves_original_syn, "accepted");
// Ablate adopt_tcp_flow's binding/current incarnation equality.
kernel_case!(
    netns_tcp_queued_closed_child_cannot_adopt_newer_tuple,
    "superseded",
    "v4"
);
// Ablate the fexit current-incarnation check before child storage CREATE.
kernel_case!(
    netns_tcp_superseded_request_cannot_prove_later_child,
    "request-superseded",
    "v4"
);
// Ablate serve_connection's required FD ownership lookup (tuple fallback must fail).
kernel_case!(netns_tcp_missing_request_proof_refuses_adoption, "missing");
// Ablate the fexit request-proof age check.
kernel_case!(netns_tcp_expired_request_proof_refuses_adoption, "expired");
// Ablate the required FD lookup: a cookie-created child has no original SYN proof.
kernel_case!(netns_tcp_forced_syn_cookie_child_is_unproven, "cookie");
// Ablate the required FD lookup, replacing it with tuple authority.
kernel_case!(netns_tcp_full_request_storage_fails_closed, "request-full");
// Ablate the required FD lookup, replacing it with tuple authority.
kernel_case!(
    netns_tcp_child_storage_allocation_failure_fails_closed,
    "child-full",
    "v4"
);
// Ablate destroy_request's exact address/cookie removal.
kernel_case!(
    netns_tcp_request_destruction_removes_exact_proof,
    "destroyed"
);
// Controlled ordering: hold the exact request fence across final ACK and accept,
// not a claim that a reader was paused concurrently inside a kernel hook.
kernel_case!(
    netns_tcp_request_fence_refuses_child_and_preserves_proof,
    "request-fenced"
);

// Ablate the cold native-pin consult in auxiliary/Closing age refusal.
kernel_case!(netns_tcp_live_pin_survives_redirect_age, "lifetime-idle");
kernel_case!(
    netns_tcp_client_half_close_survives_closing_age,
    "lifetime-client-fin"
);
kernel_case!(
    netns_tcp_server_half_close_survives_redirect_age,
    "lifetime-server-fin"
);
kernel_case!(
    netns_tcp_unowned_redirect_age_refuses_without_deletion,
    "lifetime-unowned-redirect"
);
kernel_case!(
    netns_tcp_unowned_closing_age_refuses_without_deletion,
    "lifetime-unowned-closing"
);
kernel_case!(
    netns_tcp_other_incarnation_pin_cannot_rescue_aged_tuple,
    "lifetime-other-incarnation"
);
kernel_case!(
    netns_tcp_duplicate_admission_and_cancel_release_exact_pin,
    "lifetime-cancel"
);
kernel_case!(
    netns_tcp_superseding_syn_cannot_inherit_old_live_pin,
    "lifetime-new-syn"
);
kernel_case!(
    netns_tcp_native_pin_drop_error_reaches_current_worker_epoch,
    "lifetime-pin-drop-error"
);
kernel_case!(
    netns_tcp_native_pin_retirement_error_is_unconfirmed_once,
    "lifetime-pin-retire-error"
);

// Ablate the shared fresh-versus-cached SYN classification: a client retry must
// neither mint a new incarnation nor replace the original request's route.
kernel_case!(
    netns_tcp_retransmitted_syn_keeps_original_request_and_route,
    "retransmit"
);
// Same, with a different real routing policy published before the retry.
kernel_case!(
    netns_tcp_retransmitted_syn_keeps_original_route_after_policy_change,
    "retransmit-policy"
);
// WAN is a genuine second process in the router namespace: this test process is the
// control plane, whose PID the datapath deliberately exempts.
kernel_case!(
    netns_tcp_wan_retransmitted_syn_keeps_original_request_and_route,
    "retransmit-wan"
);
kernel_case!(
    netns_tcp_wan_retransmitted_syn_keeps_original_route_after_policy_change,
    "retransmit-wan-policy"
);
kernel_case!(
    netns_tcp_native_direct_syn_retry_reaches_server,
    "retransmit-native"
);
kernel_case!(
    netns_tcp_wan_native_direct_syn_retry_reaches_server,
    "retransmit-wan-native"
);
kernel_case!(netns_tcp_namespace_disables_request_shortcuts, "namespace");

#[derive(Debug)]
struct CountDial(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl TcpOutbound for CountDial {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _domain: Option<&str>,
        _timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("binding regression reached the outbound consumer")
    }
}

fn run_child(family: &str, case: &str) -> anyhow::Result<()> {
    let ips = match family {
        "v4" => ["10.72.0.1", "10.72.0.2", "198.51.100.1", "198.51.100.2"],
        "v6" => ["fd72::1", "fd72::2", "fd73::1", "fd73::2"],
        _ => anyhow::bail!("unknown family {family}"),
    };
    let [lan, client, wan, destination] = ips.map(|ip| ip.parse::<IpAddr>().unwrap());
    let (client_ns, server_ns) = build_lab(lan, wan)?;
    configure_test_edge(&client_ns, "honk-c0", client, lan, &[]);
    configure_test_edge(&server_ns, "honk-s0", destination, wan, &[]);
    let target = SocketAddr::new(destination, 41002);
    let server = case
        .starts_with("retransmit")
        .then(|| retransmit::listen(&server_ns, target))
        .transpose()?;
    let _dae0 = daens::create_dae0_link()?;
    if case == "namespace" {
        daens::setup_daens_namespace(honk_ebpf_common::TPROXY_MARK, 12345)?;
        return daens::with_daens_netns("verify request shortcut settings", || {
            for name in ["tcp_syncookies", "tcp_migrate_req", "tcp_fastopen"] {
                match std::fs::read_to_string(format!("/proc/sys/net/ipv4/{name}")) {
                    Ok(value) => ensure!(value.trim() == "0", "{name} remains enabled"),
                    Err(error)
                        if name == "tcp_syncookies"
                            && error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });
    }
    let object = std::env::var_os("HONK_TEST_BPF_OBJECT")
        .map(std::fs::read)
        .transpose()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let config = lab_config(&udp_test_node());
            let root = Path::new(ROOT);
            let mut backend = RealEbpfBackend::load(
                object.as_deref().unwrap_or(crate::DEFAULT_BPF_OBJECT),
                root,
                config.global.tproxy_port,
                Some("honk-lan0"),
                "honk-wan0",
                false,
            )
            .await?;
            backend.attach_dae0_programs()?;
            daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
            backend.attach_sk_lookup()?;
            backend.attach_dae0peer_ingress()?;
            let tcp4 = crate::control::sockets::bind_tproxy_tcp(
                SocketAddr::new("0.0.0.0".parse()?, config.global.tproxy_port),
                config.global.tproxy_mark,
            )?;
            // Only an actual missing IPv6 family may omit the proof; a v6 scenario needs its listener.
            let tcp6 = match crate::control::sockets::bind_tproxy_tcp(
                SocketAddr::new("::".parse()?, config.global.tproxy_port),
                config.global.tproxy_mark,
            ) {
                Ok(listener) => Some(listener),
                Err(error)
                    if client.is_ipv4()
                        && error
                            .chain()
                            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                            .any(|cause| cause.raw_os_error() == Some(libc::EAFNOSUPPORT)) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
            backend.publish_listener_sockets(
                tcp4.as_raw_fd(),
                tcp6.as_ref().map(AsRawFd::as_raw_fd),
                &[],
                &[],
            )?;
            let listener = TcpListener::from_std(if client.is_ipv4() {
                tcp4
            } else {
                tcp6.context("IPv6 scenario has no IPv6 transparent listener")?
            })?;
            let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
            let dials = Arc::new(AtomicUsize::new(0));
            let mut registry = ProxyRegistry::new();
            registry.register(if server.is_some() {
                ProtocolEntry::new(
                    honk_config::types::NodeProtocol::Socks5,
                    Arc::new(retransmit::ForwardDial(Arc::clone(&dials))),
                )
            } else {
                ProtocolEntry::new(
                    honk_config::types::NodeProtocol::Socks5,
                    Arc::new(CountDial(Arc::clone(&dials))),
                )
            });
            let mut plane = ControlPlane::new(
                config,
                Box::new(backend),
                router,
                Arc::new(registry),
                DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                udp_test_forwarder(),
            )?;
            plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
                crate::mode::ModeState::new("Rule", "fullcone"),
            )));
            plane.start_datapath_flags_coordinator()?;
            plane.alive_set().shutdown_health_checks().await?;
            let handle = plane.spawn_handle();
            let retirement = (!matches!(
                case,
                "lifetime-pin-drop-error" | "lifetime-pin-retire-error"
            ))
            .then(|| TestRetirement::start(&handle));
            if case == "accepted" {
                let _backend = handle.ebpf.write().await;
                let mut sequence = Array::<_, FlowIncarnationSequence>::try_from(pinned_map(
                    root,
                    "FLOW_INCARNATION_SEQUENCE",
                )?)?;
                sequence.set(
                    0,
                    FlowIncarnationSequence {
                        next: FIRST_PUBLISHED_INCARNATION - 1,
                        ..Default::default()
                    },
                    aya_obj::generated::BPF_F_LOCK as u64,
                )?;
            }
            handle.ebpf.write().await.set_datapath_ready(true)?;
            let exercise = match server {
                Some(server) => {
                    retransmit::exercise(
                        &handle, &listener, &client_ns, &server_ns, client, wan, target, server,
                        &dials, case,
                    )
                    .await
                }
                None => {
                    exercise(&handle, &listener, &client_ns, client, target, case, &dials).await
                }
            };
            handle.ebpf.write().await.set_datapath_ready(false)?;
            let joined = match retirement {
                Some(retirement) => retirement.join(&handle).await,
                None => Ok(()),
            };
            let cleaned = handle.ebpf.write().await.cleanup().await;
            exercise?;
            joined?;
            cleaned?;
            Ok::<_, anyhow::Error>(())
        })
        .with_context(|| format!("TCP binding {case}/{family}"))
}

async fn exercise(
    handle: &ControlPlaneHandle,
    listener: &TcpListener,
    client_ns: &OwnedFd,
    client: IpAddr,
    target: SocketAddr,
    case: &str,
    dials: &AtomicUsize,
) -> anyhow::Result<()> {
    let root = Path::new(ROOT);
    let mut requests = HashMap::<_, TcpRequestKey, TcpSocketBinding>::try_from(pinned_map(
        root,
        "TCP_REQUEST_BINDINGS",
    )?)?;
    if case == "expired"
        || (case.starts_with("lifetime-")
            && !matches!(
                case,
                "lifetime-pin-drop-error" | "lifetime-pin-retire-error"
            ))
    {
        // A real boot clock cannot represent a 120s-old proof before uptime120s.
        let now = monotonic_ns()?;
        let age = honk_ebpf_common::conn::TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;
        if now <= age {
            tokio::time::sleep(Duration::from_nanos(age - now + 1)).await;
        }
    }
    if case == "request-full" {
        for cookie in 1..=65536 {
            requests.insert(
                TcpRequestKey { address: 1, cookie },
                TcpSocketBinding::default(),
                1,
            )?;
        }
    }
    let cookies_before = if case == "cookie" {
        daens::with_daens_netns("force owned-netns SYN cookies", || {
            std::fs::write("/proc/sys/net/ipv4/tcp_syncookies", "2")?;
            ensure!(
                std::fs::read_to_string("/proc/sys/net/ipv4/tcp_syncookies")?.trim() == "2",
                "SYN cookies not forced"
            );
            cookie_count()
        })?
    } else {
        0
    };
    let wire = Wire::on("honk-lan0")?;
    let socket = in_test_netns(client_ns, || -> anyhow::Result<_> {
        let socket = if client.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if case == "lifetime-new-syn" {
            socket.set_reuseaddr(true)?;
        }
        socket.bind(SocketAddr::new(client, 0))?;
        hold_synack(socket.as_raw_fd(), true)?;
        Ok(socket)
    })?;
    let source = socket.local_addr()?;
    let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure!(
        fd >= 0,
        "duplicate client: {}",
        std::io::Error::last_os_error()
    );
    let gate = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut connect = Box::pin(socket.connect(target));
    let synack = tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        tokio::select! {
            result = &mut connect => anyhow::bail!("client crossed SYNACK gate: {result:?}"),
            frame = wire.synack(source, target) => frame,
        }
    })
    .await??;
    let key = crate::control::connection::build_tuples_key(
        target.ip(),
        target.port(),
        source.ip(),
        source.port(),
        6,
    );
    let proof = request_snapshot()?.into_iter().find(|(_, binding)| {
        binding.tuples.src_port == source.port() && binding.tuples.dst_port == target.port()
    });
    let original = handle
        .ebpf
        .read()
        .await
        .conn_state_lookup(&key)?
        .context("real SYN did not publish conn-state")?;
    ensure!(original.incarnation != 0, "real SYN has no incarnation");
    if case == "accepted" {
        ensure!(
            original.incarnation == FIRST_PUBLISHED_INCARNATION,
            "SYN did not retain the configured full-width incarnation"
        );
    }
    if matches!(case, "cookie" | "request-full") {
        ensure!(
            proof.is_none(),
            "failure fixture unexpectedly captured a request proof"
        );
    } else {
        let (request, binding) = proof.context("real SYN did not capture request proof")?;
        ensure!(
            binding.handoff.incarnation == original.incarnation,
            "request captured a different SYN"
        );
        match case {
            "missing" => requests.remove(&request)?,
            "expired" => {
                let mut expired = binding;
                expired.handoff.last_seen_ns = 1;
                requests.insert(request, expired, 2)?;
            }
            "destroyed" => {
                drop(connect);
                drop(gate);
                wire.replay(&synack)?;
                tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                    while request_snapshot()?.iter().any(|(key, _)| *key == request) {
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await
                .context("RST did not destroy exact request proof")??;
                ensure!(
                    dials.load(Ordering::SeqCst) == 0,
                    "destroyed request reached outbound"
                );
                return Ok(());
            }
            _ => {}
        }
    }
    let authority = if case == "request-superseded" {
        supersede(handle, &key).await?
    } else {
        original.incarnation
    };
    let optmem = if case == "child-full" {
        Some(daens::with_daens_netns(
            "deny child storage allocation",
            || -> anyhow::Result<_> {
                let old = std::fs::read_to_string("/proc/sys/net/core/optmem_max")?;
                std::fs::write("/proc/sys/net/core/optmem_max", "0")?;
                Ok(old)
            },
        )?)
    } else {
        None
    };
    let mut request_fence = if case == "request-fenced" {
        let request = proof.context("fenced fixture lost native request")?.0;
        let mut fences =
            HashMap::<_, TcpRequestKey, u64>::try_from(pinned_map(root, "REQUEST_FENCE")?)?;
        let mut active = Array::<_, u32>::try_from(pinned_map(root, "RETIRE_ACTIVE")?)?;
        // No tuple fence: the real final ACK may complete, but its request-map
        // readers and destructor must leave immutable proof to the fence owner.
        active.set(0, 1, 0)?;
        fences.insert(request, 0x7465_7374_u64, 1)?;
        Some((request, fences, active))
    } else {
        None
    };
    hold_synack(gate.as_raw_fd(), false)?;
    wire.replay(&synack)?;
    drop(gate);
    let connected = tokio::time::timeout(NETNS_TEST_TIMEOUT, connect).await;
    let accepted = tokio::time::timeout(NETNS_TEST_TIMEOUT, listener.accept()).await;
    if let Some(old) = optmem {
        daens::with_daens_netns("restore child storage allocation", || {
            std::fs::write("/proc/sys/net/core/optmem_max", old).map_err(anyhow::Error::from)
        })?;
    }
    let client_stream = connected
        .context("client handshake deadline")?
        .context("client handshake")?;
    let (accepted, peer) = accepted.context("accept deadline")??;
    ensure!(
        peer == source && accepted.local_addr()? == target,
        "wrong transparent socket endpoints"
    );
    if let Some((request, fences, active)) = request_fence.as_mut() {
        ensure!(
            request_snapshot()?.iter().any(|(key, _)| key == request),
            "fenced completed accept lost native request proof"
        );
        ensure!(
            handle
                .ebpf
                .read()
                .await
                .tcp_socket_ownership(accepted.as_fd())
                .is_err(),
            "request fence allowed child proof publication"
        );
        fences.remove(request)?;
        active.set(0, 0, 0)?;
    } else if case == "accepted" {
        let request = proof.context("accepted fixture lost native request")?.0;
        ensure!(
            request_snapshot()?.iter().all(|(key, _)| *key != request),
            "unfenced completed accept retained native request proof"
        );
    }
    if case == "cookie" {
        ensure!(
            daens::with_daens_netns("observe forced cookie child", cookie_count)? > cookies_before,
            "fixture did not send a SYN cookie"
        );
    }
    if case.starts_with("lifetime-") {
        return lifetime::exercise(
            handle,
            listener,
            client_ns,
            accepted,
            client_stream,
            peer,
            target,
            key,
            original.incarnation,
            case,
        )
        .await;
    }
    if matches!(case, "accepted" | "superseded") {
        let ownership = handle
            .ebpf
            .read()
            .await
            .tcp_socket_ownership(accepted.as_fd())?;
        let TcpSocketOwnership::Kernel(binding) = ownership else {
            anyhow::bail!("real backend returned model ownership")
        };
        ensure!(
            binding.handoff.incarnation == original.incarnation,
            "accepted FD did not preserve its SYN incarnation"
        );
        ensure!(
            super::support::bytes_of(&binding.tuples) == super::support::bytes_of(&key),
            "accepted FD captured different SYN endpoints"
        );
        let (_, request_binding) =
            proof.context("accepted child lost original request evidence")?;
        ensure!(
            super::support::bytes_of(&binding.handoff)
                == super::support::bytes_of(&request_binding.handoff),
            "accepted FD did not preserve the immutable SYN handoff"
        );
        if case == "superseded" {
            // Only competing tuple authority is injected; the old child's storage
            // remains the real hook-created immutable proof while queued for admission.
            let incarnation = supersede(handle, &key).await?;
            drop(client_stream);
            return refused_without_cleanup(handle, accepted, peer, &key, incarnation, dials).await;
        }
        let result =
            tokio::time::timeout(NETNS_TEST_TIMEOUT, handle.serve_connection(accepted, peer))
                .await?;
        ensure!(
            dials.load(Ordering::SeqCst) == 1,
            "proven child did not reach its one outbound consumer: {result:?}"
        );
        drop(client_stream);
        return Ok(());
    }
    ensure!(
        handle
            .ebpf
            .read()
            .await
            .tcp_socket_ownership(accepted.as_fd())
            .is_err(),
        "unproven child unexpectedly has FD ownership"
    );
    let result = refused_without_cleanup(handle, accepted, peer, &key, authority, dials).await;
    drop(client_stream);
    result
}

async fn refused_without_cleanup(
    handle: &ControlPlaneHandle,
    accepted: tokio::net::TcpStream,
    peer: SocketAddr,
    key: &TuplesKey,
    incarnation: u64,
    dials: &AtomicUsize,
) -> anyhow::Result<()> {
    let result =
        tokio::time::timeout(NETNS_TEST_TIMEOUT, handle.serve_connection(accepted, peer)).await?;
    ensure!(result.is_err(), "unproven/superseded child was admitted");
    ensure!(
        dials.load(Ordering::SeqCst) == 0,
        "unproven/superseded child reached outbound dial"
    );
    let backend = handle.ebpf.read().await;
    ensure!(
        backend
            .conn_state_lookup(key)?
            .map(|value| value.incarnation)
            == Some(incarnation),
        "rejected adoption deleted/rebound conn-state"
    );
    ensure!(
        backend
            .routing_handoff_lookup(key)?
            .map(|value| value.incarnation)
            == Some(incarnation),
        "rejected adoption consumed authoritative handoff"
    );
    ensure!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
            .map(|value| value.incarnation)
            == Some(incarnation),
        "rejected adoption deleted authoritative redirect"
    );
    Ok(())
}

fn monotonic_ns() -> anyhow::Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } == 0,
        "read monotonic clock"
    );
    let time = unsafe { time.assume_init() };
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

fn cookie_count() -> anyhow::Result<u64> {
    let text = std::fs::read_to_string("/proc/thread-self/net/netstat")?;
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        if names.starts_with("TcpExt:") {
            let index = names
                .split_ascii_whitespace()
                .position(|name| name == "SyncookiesSent")
                .context("missing cookie counter")?;
            return Ok(values
                .split_ascii_whitespace()
                .nth(index)
                .context("missing cookie value")?
                .parse()?);
        }
    }
    anyhow::bail!("TcpExt counters missing")
}

fn hold_synack(fd: libc::c_int, hold: bool) -> anyhow::Result<()> {
    let mut instruction = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0,
    };
    let filter = libc::sock_fprog {
        len: 1,
        filter: &mut instruction,
    };
    let unused: libc::c_int = 0;
    let (option, value, length) = if hold {
        (
            libc::SO_ATTACH_FILTER,
            (&filter as *const libc::sock_fprog).cast(),
            std::mem::size_of_val(&filter),
        )
    } else {
        (
            libc::SO_DETACH_FILTER,
            (&unused as *const libc::c_int).cast(),
            std::mem::size_of_val(&unused),
        )
    };
    ensure!(
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, option, value, length as _) } == 0,
        "gate SYNACK: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn packet_socket() -> anyhow::Result<OwnedFd> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    ensure!(
        fd >= 0,
        "open packet capture: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Source IP, destination IP and TCP header+payload of an Ethernet frame carrying
/// TCP over the given IP family; `None` for anything else.
fn tcp_segment(frame: &[u8], ipv6: bool) -> Option<(&[u8], &[u8], &[u8])> {
    let (source, destination, transport) = match frame.get(12..14)? {
        [0x08, 0x00] if !ipv6 && frame.len() >= 34 && frame[23] == 6 => (
            &frame[26..30],
            &frame[30..34],
            14 + (frame[14] as usize & 15) * 4,
        ),
        [0x86, 0xdd] if ipv6 && frame.len() >= 54 && frame[20] == 6 => {
            (&frame[22..38], &frame[38..54], 54)
        }
        _ => return None,
    };
    let tcp = frame.get(transport..)?;
    (tcp.len() >= 20).then_some((source, destination, tcp))
}

struct Wire {
    fd: OwnedFd,
    address: libc::sockaddr_ll,
}

impl Wire {
    fn on(interface: &str) -> anyhow::Result<Self> {
        let fd = packet_socket()?;
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as _;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = crate::netlink::NlSock::new()?.get_link(interface)?.0 as _;
        ensure!(
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } == 0,
            "bind packet capture: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self { fd, address })
    }

    async fn synack(&self, source: SocketAddr, target: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let mut bytes = [0u8; 2048];
        loop {
            let length = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if length < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(error.into());
                }
                tokio::task::yield_now().await;
                continue;
            }
            let frame = &bytes[..length as usize];
            let Some((_, _, tcp)) = tcp_segment(frame, source.is_ipv6()) else {
                continue;
            };
            if u16::from_be_bytes([tcp[0], tcp[1]]) == target.port()
                && u16::from_be_bytes([tcp[2], tcp[3]]) == source.port()
                && tcp[13] & 0x12 == 0x12
            {
                return Ok(frame.to_vec());
            }
        }
    }

    fn replay(&self, frame: &[u8]) -> anyhow::Result<()> {
        // AF_PACKET can observe CHECKSUM_PARTIAL before the veth completes it.
        let mut frame = frame.to_vec();
        let (transport, length, mut sum) = if frame[12..14] == [0x08, 0x00] {
            let header = (frame[14] as usize & 15) * 4;
            let length = u16::from_be_bytes([frame[16], frame[17]]) as usize - header;
            (
                14 + header,
                length,
                checksum_sum(&frame[26..34]) + 6 + length as u32,
            )
        } else {
            let length = u16::from_be_bytes([frame[18], frame[19]]) as usize;
            (54, length, checksum_sum(&frame[22..54]) + 6 + length as u32)
        };
        frame[transport + 16..transport + 18].fill(0);
        sum += checksum_sum(&frame[transport..transport + length]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        frame[transport + 16..transport + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let mut address = self.address;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&frame[..6]);
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as _,
            )
        };
        ensure!(
            sent == frame.len() as isize,
            "replay captured SYNACK: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

fn checksum_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|word| u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32)
        .sum()
}

fn request_snapshot() -> anyhow::Result<Vec<(TcpRequestKey, TcpSocketBinding)>> {
    pinned_hash_snapshot(Path::new(ROOT), "TCP_REQUEST_BINDINGS", 0)
}

async fn supersede(handle: &ControlPlaneHandle, key: &TuplesKey) -> anyhow::Result<u64> {
    let root = Path::new(ROOT);
    let mut conns = HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(pinned_map(
        root,
        "CONN_STATE_MAP",
    )?)?;
    let mut handoffs = HashMap::<_, TuplesKey, FlowMapValue<RoutingHandoffEntry>>::try_from(
        pinned_map(root, "ROUTING_HANDOFF_MAP")?,
    )?;
    let mut backend = handle.ebpf.write().await;
    let mut next = conns.get(key, aya_obj::generated::BPF_F_LOCK as u64)?.value;
    next.incarnation += 1;
    conns.insert(
        *key,
        FlowMapValue::new(next),
        2 | aya_obj::generated::BPF_F_LOCK as u64,
    )?;
    let mut handoff = handoffs
        .get(key, aya_obj::generated::BPF_F_LOCK as u64)?
        .value;
    handoff.incarnation = next.incarnation;
    handoffs.insert(
        *key,
        FlowMapValue::new(handoff),
        2 | aya_obj::generated::BPF_F_LOCK as u64,
    )?;
    let redirect_key = RedirectTuple::from_tuples(key);
    let mut redirect = backend
        .redirect_track_lookup(&redirect_key)?
        .context("missing SYN redirect")?;
    redirect.incarnation = next.incarnation;
    backend.redirect_track_store(&redirect_key, &redirect)?;
    Ok(next.incarnation)
}
