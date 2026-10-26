//! Bond coverage is on the logical device, after bonding's receive admission and
//! before bonding chooses the transmit member. All traffic uses the real control plane.

use super::support::netns::{
    KernelTcpDial, enter_lab_namespaces, lab_config, pinned_map, run_isolated,
};
use super::support::shared_udp::{SharedUdpMode, SharedUdpPeer};
use super::{configure_test_edge, fresh_test_netns, in_test_netns, udp_test_forwarder};
use crate::control::{ControlCommand, ControlPlane};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::EbpfBackend;
use crate::ebpf::interface::{BindingSnapshot, Direction, TcProgram};
use crate::ebpf::real::{IfaceWatcher, RealEbpfBackend, start_interfaces};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::{Array, HashMap};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::{RedirectEntry, RedirectTuple};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, socks5::Socks5Handler};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::sync::RwLock;

mod client;
use client::{Client, client_main};

const CHILD: &str = "HONK_BOND_CHILD";
const CLIENT: &str = "HONK_BOND_CLIENT";
const CLIENT_TEST: &str = "control::tests::bond_binding::netns_bond_wan_only_local_failover";
const ROOT: &str = "/sys/fs/bpf/bond-binding";
const BOND: &str = "hb0"; // modprobe bonding may create bond0 in the VM's initial netns.
const BRIDGE: &str = "hbr0";
const PEER_BRIDGE: &str = "hpbr0";
const LAN: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 1);
const LAN_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 2);
const BRIDGE_SERVER: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 3);
const WAN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const TCP_PORT: u16 = 41011;
const UDP_PORT: u16 = 41012;
const TIMEOUT: Duration = Duration::from_secs(15);
const BLOCK: usize = 1024;

type Backend = Arc<RwLock<Box<dyn EbpfBackend>>>;

macro_rules! bond_case {
    ($name:ident, [$($case:literal),+]) => {
        #[test]
        #[ignore = "requires root, bonding/bridge and the disposable Linux 6.12+ VM gate"]
        fn $name() -> anyhow::Result<()> {
            if let Ok(client) = std::env::var(CLIENT) {
                return client_main(&client);
            }
            run_isolated(
                concat!("control::tests::bond_binding::", stringify!($name)),
                CHILD,
                [$($case),+],
                run_child,
            )
        }
    };
}

bond_case!(
    netns_bond_lan_tcp_udp_master_reply_and_failover,
    ["lan/active-backup"]
);
bond_case!(netns_bond_wan_only_local_failover, ["wan/active-backup"]);
bond_case!(
    netns_bond_inactive_member_respects_receive_admission,
    ["inactive/active-backup"]
);
bond_case!(
    netns_bond_bridge_port_keeps_native_udp_reverse_path,
    ["bridge/active-backup"]
);
bond_case!(
    netns_bond_non_lacp_modes_proxy_tcp_udp,
    ["lan/balance-rr", "lan/balance-xor", "lan/broadcast"]
);

fn ip(netns: Option<&OwnedFd>, args: &[&str]) -> anyhow::Result<()> {
    let run = || std::process::Command::new("ip").args(args).output();
    let output = match netns {
        Some(netns) => in_test_netns(netns, run),
        None => run(),
    }?;
    ensure!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn veth(host: &str, peer: &str, netns: &OwnedFd) -> anyhow::Result<()> {
    let mut nl = crate::netlink::NlSock::new()?;
    nl.add_veth_pair(host, peer)?;
    let (index, _) = nl.get_link(peer)?;
    nl.set_link_netns_fd(index, netns)?;
    Ok(())
}

fn add_member(peer_ns: &OwnedFd, number: u8) -> anyhow::Result<()> {
    let (member, peer) = (format!("hm{number}"), format!("hp{number}"));
    veth(&member, &peer, peer_ns)?;
    ip(None, &["link", "set", &member, "master", BOND])?;
    ip(
        Some(peer_ns),
        &["link", "set", &peer, "master", PEER_BRIDGE],
    )?;
    ip(Some(peer_ns), &["link", "set", &peer, "up"])?;
    ip(None, &["link", "set", &member, "up"])
}

fn bond_edge(peer_ns: &OwnedFd, mode: &str) -> anyhow::Result<()> {
    ip(
        None,
        &[
            "link", "add", BOND, "type", "bond", "mode", mode, "miimon", "100",
        ],
    )?;
    ip(
        Some(peer_ns),
        &[
            "link",
            "add",
            PEER_BRIDGE,
            "type",
            "bridge",
            "forward_delay",
            "0",
        ],
    )?;
    ip(Some(peer_ns), &["link", "set", PEER_BRIDGE, "up"])?;
    for member in 0..2 {
        add_member(peer_ns, member)?;
    }
    ip(None, &["link", "set", BOND, "up"])?;
    let deadline = std::time::Instant::now() + TIMEOUT;
    while std::fs::read_to_string(format!("/sys/class/net/{BOND}/carrier"))?.trim() != "1" {
        ensure!(
            std::time::Instant::now() < deadline,
            "bond did not acquire carrier"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn address(name: &str, ip_addr: Ipv4Addr) -> anyhow::Result<()> {
    ip(
        None,
        &["addr", "add", &format!("{ip_addr}/24"), "dev", name],
    )
}

struct Scenario {
    kind: String,
    mode: String,
    client_ns: Option<OwnedFd>,
    server_ns: OwnedFd,
    bond_peer: OwnedFd,
    source: Ipv4Addr,
    server: Ipv4Addr,
    local: Ipv4Addr,
    lan: Vec<String>,
    wan: Vec<String>,
}

fn run_child(case: &str) -> anyhow::Result<()> {
    let (kind, mode) = case.split_once('/').context("bond case")?;
    enter_lab_namespaces()?;
    ip(None, &["link", "set", "lo", "up"])?;
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    // Neither rp_filter nor an IPv4 Redirect may turn asymmetric bridge traffic into
    // a routing test instead of a port-hook test.
    for setting in ["rp_filter", "send_redirects"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/all/{setting}"), "0")?;
        std::fs::write(format!("/proc/sys/net/ipv4/conf/default/{setting}"), "0")?;
    }
    let peer = fresh_test_netns();
    bond_edge(&peer, mode)?;
    let scenario = if kind == "wan" {
        address(BOND, WAN)?;
        configure_test_edge(&peer, PEER_BRIDGE, SERVER, WAN, &[]);
        Scenario {
            kind: kind.into(),
            mode: mode.into(),
            client_ns: None,
            server_ns: peer.try_clone()?,
            bond_peer: peer,
            source: WAN,
            server: SERVER,
            local: WAN,
            lan: vec![],
            wan: vec![BOND.into()],
        }
    } else if kind == "bridge" {
        ip(
            None,
            &[
                "link",
                "add",
                BRIDGE,
                "type",
                "bridge",
                "forward_delay",
                "0",
            ],
        )?;
        ip(None, &["link", "set", BOND, "master", BRIDGE])?;
        ip(None, &["link", "set", BRIDGE, "up"])?;
        address(BRIDGE, LAN)?;
        let client = fresh_test_netns();
        veth("hl0", "hc0", &client)?;
        ip(None, &["link", "set", "hl0", "master", BRIDGE])?;
        ip(None, &["link", "set", "hl0", "up"])?;
        configure_test_edge(&client, "hc0", LAN_CLIENT, LAN, &[]);
        configure_test_edge(&peer, PEER_BRIDGE, BRIDGE_SERVER, LAN, &[]);
        Scenario {
            kind: kind.into(),
            mode: mode.into(),
            client_ns: Some(client),
            server_ns: peer.try_clone()?,
            bond_peer: peer,
            source: LAN_CLIENT,
            server: BRIDGE_SERVER,
            local: LAN,
            lan: vec![BRIDGE.into()],
            wan: vec![BOND.into()],
        }
    } else {
        address(BOND, LAN)?;
        configure_test_edge(&peer, PEER_BRIDGE, LAN_CLIENT, LAN, &[]);
        let server = fresh_test_netns();
        veth("hw0", "hs0", &server)?;
        ip(None, &["link", "set", "hw0", "up"])?;
        address("hw0", WAN)?;
        configure_test_edge(&server, "hs0", SERVER, WAN, &[]);
        Scenario {
            kind: kind.into(),
            mode: mode.into(),
            client_ns: Some(peer.try_clone()?),
            server_ns: server,
            bond_peer: peer,
            source: LAN_CLIENT,
            server: SERVER,
            local: WAN,
            // The canary proves a member-change event has completed a full reconcile.
            lan: vec![BOND.into(), "hcan0".into()],
            wan: vec!["hw0".into()],
        }
    };
    let (_dae0, setup) = daens::create_dae0_link()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut peer = SharedUdpPeer::start(
                SharedUdpMode::Socks5,
                SocketAddr::new(scenario.local.into(), 0),
            )
            .await?;
            let config = {
                let mut config = lab_config(&peer.node);
                config.global.lan_interface.clone_from(&scenario.lan);
                config.global.wan_interface.clone_from(&scenario.wan);
                if kind == "bridge" {
                    // Only requests match direct. A reply misclassified as a fresh LAN flow
                    // hits the proxy default, so absence of LAN reverse learning breaks data.
                    config.routing.rules.push(RoutingRule {
                        name: "native-request-only".into(),
                        condition: RoutingCondition {
                            ip: vec![format!("{BRIDGE_SERVER}/32")],
                            protocol: vec!["udp".into()],
                            ..Default::default()
                        },
                        outbound: RoutingOutbound::Simple("direct".into()),
                        priority: 0,
                        must: true,
                        mark: 0,
                    });
                }
                config
            };
            let degradations = Arc::new(crate::degradations::Degradations::default());
            let object = std::env::var_os("HONK_TEST_BPF_OBJECT")
                .map(std::fs::read)
                .transpose()?;
            let (mut backend, handoff) = start_interfaces(
                object.as_deref().unwrap_or(crate::DEFAULT_BPF_OBJECT),
                Path::new(ROOT),
                config.global.tproxy_port,
                &setup,
                &scenario.lan,
                &scenario.wan,
                &degradations,
                crate::ebpf::interface::read_topology,
            )
            .await?;
            backend.attach_dae0_programs()?;
            daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
            backend.attach_sk_lookup()?;
            backend.attach_dae0peer_ingress()?;
            let ready =
                Array::<_, u32>::try_from(pinned_map(Path::new(ROOT), "DATAPATH_STATE_MAP")?)?;
            let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
            let mut registry = ProxyRegistry::new();
            let socks = Arc::new(Socks5Handler::new());
            registry.register(
                ProtocolEntry::new(
                    honk_config::types::NodeProtocol::Socks5,
                    Arc::new(KernelTcpDial),
                )
                .with_packet(socks.clone())
                .with_shared(socks),
            );
            let mut control = ControlPlane::new(
                config,
                Box::new(backend),
                router,
                Arc::new(registry),
                DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                udp_test_forwarder(),
            )?;
            control.set_mode_state(Arc::new(parking_lot::RwLock::new(
                crate::mode::ModeState::new("Rule", "fullcone"),
            )));
            control.start_datapath_flags_coordinator()?;
            control.alive_set().shutdown_health_checks().await?;
            let ebpf = control.ebpf_handle();
            control.set_iface_watcher(Some(IfaceWatcher::spawn(
                ebpf.clone(),
                control.config_handle(),
                control.command_sender(),
                degradations,
                handoff,
            )));
            let commands = control.command_sender();
            let shutdown = control.shutdown_requested.clone();
            let task = tokio::spawn(async move {
                let result = control.run().await;
                (control, result)
            });
            let exercised = async {
                tokio::time::timeout(TIMEOUT, async {
                    while ready.get(&0, 0)? == 0 {
                        ensure!(!task.is_finished(), "control stopped before readiness");
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                exercise(&scenario, &ebpf, &mut peer).await
            }
            .await;
            shutdown.store(true, Ordering::Release);
            let sent = if task.is_finished() {
                Ok(())
            } else {
                commands
                    .send(ControlCommand::Shutdown)
                    .await
                    .map_err(anyhow::Error::from)
            };
            let (control, stopped) = task.await.context("control task panicked")?;
            stopped?;
            sent?;
            drop(control);
            let closed = peer.close().await;
            exercised?;
            closed
        })
        .with_context(|| format!("bond {case}"))
}

fn stats(member: &str, field: &str) -> anyhow::Result<u64> {
    Ok(
        std::fs::read_to_string(format!("/sys/class/net/{member}/statistics/{field}"))?
            .trim()
            .parse()?,
    )
}

async fn switch_active(member: &str) -> anyhow::Result<()> {
    std::fs::write(
        format!("/sys/class/net/{BOND}/bonding/active_slave"),
        member,
    )?;
    ensure!(
        std::fs::read_to_string(format!("/sys/class/net/{BOND}/bonding/active_slave"))?.trim()
            == member
    );
    // Wait for the bonding peer notification/bridge learning, not a new honk binding.
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(())
}

async fn assert_hooks(
    ebpf: &Backend,
    device: &str,
    expected: [TcProgram; 2],
) -> anyhow::Result<()> {
    let snapshot = ebpf.read().await.interface_binding_snapshot()?;
    let index = crate::netlink::ifindex_of(device)?;
    for (direction, program) in [Direction::Ingress, Direction::Egress]
        .into_iter()
        .zip(expected)
    {
        let (_, id, _) = snapshot
            .owned
            .iter()
            .find(|(binding, ..)| {
                binding.ifindex.get() == index
                    && binding.direction == direction
                    && binding.program == program
            })
            .with_context(|| format!("missing {device} {direction:?} {program:?}"))?;
        ensure!(
            RealEbpfBackend::test_interface_chain(index, direction)? == [*id],
            "wrong kernel chain on {device} {direction:?}"
        );
    }
    Ok(())
}

fn no_member_hooks() -> anyhow::Result<()> {
    for link in crate::netlink::NlSock::new()?.dump_links()? {
        if link.name.starts_with("hm") {
            for direction in [Direction::Ingress, Direction::Egress] {
                ensure!(
                    RealEbpfBackend::test_interface_chain(link.ifindex.get(), direction)?
                        .is_empty(),
                    "member {} has a honk hook ({direction:?})",
                    link.name
                );
            }
        }
    }
    Ok(())
}

fn tuple(source: SocketAddr, destination: SocketAddr, proto: u8) -> honk_ebpf_common::TuplesKey {
    crate::control::connection::build_tuples_key(
        destination.ip(),
        destination.port(),
        source.ip(),
        source.port(),
        proto,
    )
}

async fn redirected(
    ebpf: &Backend,
    source: SocketAddr,
    destination: SocketAddr,
    proto: u8,
    device: &str,
    from_wan: u8,
) -> anyhow::Result<()> {
    let entry = ebpf
        .read()
        .await
        .redirect_track_lookup(&RedirectTuple::from_tuples(&tuple(
            source,
            destination,
            proto,
        )))?
        .with_context(|| format!("missing {source} -> {destination} redirect"))?;
    let index = crate::netlink::ifindex_of(device)?;
    ensure!(
        entry.ifindex == index && entry.from_wan == from_wan,
        "redirect captured ifindex={} from_wan={}, expected {device} ({index}) from_wan={from_wan}",
        entry.ifindex,
        entry.from_wan
    );
    Ok(())
}

async fn wait_until(
    ebpf: &Backend,
    what: &str,
    done: impl Fn(&BindingSnapshot) -> bool,
) -> anyhow::Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if done(&ebpf.read().await.interface_binding_snapshot()?) {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context(what.to_owned())?
}

async fn member_change(s: &Scenario, ebpf: &Backend) -> anyhow::Result<()> {
    let before = ebpf
        .read()
        .await
        .interface_binding_snapshot()?
        .owned
        .into_iter()
        .filter(|(binding, ..)| binding.interface == BOND)
        .map(|(_, id, _)| id)
        .collect::<Vec<_>>();
    add_member(&s.bond_peer, 2)?;
    // A visible new target fences the watcher's complete pass over the same topology.
    crate::netlink::NlSock::new()?.add_veth_pair("hcan0", "hcan1")?;
    wait_until(
        ebpf,
        "watcher did not process member addition",
        |snapshot| {
            snapshot
                .owned
                .iter()
                .filter(|(binding, ..)| binding.interface == "hcan0")
                .count()
                == 2
        },
    )
    .await?;
    no_member_hooks()?;
    let after = ebpf
        .read()
        .await
        .interface_binding_snapshot()?
        .owned
        .into_iter()
        .filter(|(binding, ..)| binding.interface == BOND)
        .map(|(_, id, _)| id)
        .collect::<Vec<_>>();
    ensure!(before == after, "member addition replaced master hooks");
    ip(None, &["link", "del", "hm2"])?;
    ip(None, &["link", "del", "hcan0"])?;
    wait_until(ebpf, "watcher did not process member removal", |snapshot| {
        snapshot
            .owned
            .iter()
            .all(|(binding, ..)| binding.interface != "hcan0")
    })
    .await?;
    no_member_hooks()
}

async fn exercise(s: &Scenario, ebpf: &Backend, peer: &mut SharedUdpPeer) -> anyhow::Result<()> {
    let tcp_target = SocketAddr::new(s.server.into(), TCP_PORT);
    let udp_target = SocketAddr::new(s.server.into(), UDP_PORT);
    let tcp = in_test_netns(&s.server_ns, || std::net::TcpListener::bind(tcp_target))?;
    tcp.set_nonblocking(true)?;
    let tcp = TcpListener::from_std(tcp)?;
    let tcp_echo: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await?;
            let mut block = [0; BLOCK];
            while stream.read_exact(&mut block).await.is_ok() {
                stream.write_all(&block).await?;
            }
        }
    });
    let udp = in_test_netns(&s.server_ns, || std::net::UdpSocket::bind(udp_target))?;
    udp.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(udp)?;
    let udp_echo: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut block = [0; BLOCK];
        loop {
            let (size, source) = udp.recv_from(&mut block).await?;
            udp.send_to(&block[..size], source).await?;
        }
    });
    let result = async {
        if s.kind == "inactive" {
            return inactive(s, ebpf, tcp_target).await;
        }
        if s.kind == "bridge" {
            return bridge(s, ebpf, udp_target, tcp_target).await;
        }
        let from_wan = u8::from(s.kind == "wan");
        if s.mode == "active-backup" {
            switch_active("hm0").await?;
        }
        let mut tcp = Client::start("tcp", s.source, tcp_target, s.client_ns.as_ref()).await?;
        tcp.rounds(8).await?;
        redirected(ebpf, tcp.local, tcp_target, 6, BOND, from_wan).await?;
        if s.mode == "active-backup" {
            if s.kind == "lan" {
                member_change(s, ebpf).await?;
            }
            switch_active("hm1").await?;
            let (old, active) = (stats("hm0", "tx_packets")?, stats("hm1", "tx_packets")?);
            tcp.rounds(32).await?;
            ensure!(
                stats("hm1", "tx_packets")? > active && stats("hm0", "tx_packets")? == old,
                "TCP replies did not leave exclusively through the current active member"
            );
            redirected(ebpf, tcp.local, tcp_target, 6, BOND, from_wan).await?;
        }
        tcp.finish().await?;
        let mut udp = Client::start("udp", s.source, udp_target, s.client_ns.as_ref()).await?;
        udp.rounds(1).await?;
        let packet = tokio::time::timeout(TIMEOUT, peer.packets.recv())
            .await?
            .context("proxy did not observe UDP")?;
        ensure!(
            packet.target == udp_target && packet.payload.len() == BLOCK,
            "wrong UDP proxy packet"
        );
        redirected(ebpf, udp.local, udp_target, 17, BOND, from_wan).await?;
        if from_wan == 0 {
            let clients = HashMap::<_, RedirectTuple, RedirectEntry>::try_from(pinned_map(
                Path::new(ROOT),
                "CLIENT_REPLY_TRACK",
            )?)?;
            let mut key = RedirectTuple::from_tuples(&tuple(udp.local, udp_target, 17));
            key.dst_ip = In6Addr::zero();
            key.dst_port = 0;
            let framing = clients.get(&key, 0)?;
            ensure!(
                framing.ifindex == crate::netlink::ifindex_of(BOND)?
                    && framing.from_wan == 0
                    && framing.decision_token == 0,
                "CLIENT_REPLY_TRACK did not keep master framing"
            );
            let foreign = in_test_netns(&s.server_ns, || {
                std::net::UdpSocket::bind(SocketAddr::new(s.server.into(), UDP_PORT + 1))
            })?;
            foreign.send_to(b"foreign", packet.mapping)?;
            udp.command("foreign").await?;
        }
        if s.mode == "active-backup" {
            switch_active("hm0").await?;
            let (old, active) = (stats("hm1", "tx_packets")?, stats("hm0", "tx_packets")?);
            udp.rounds(16).await?;
            let mut final_payload = [0x6b; BLOCK];
            final_payload[..4].copy_from_slice(&17u32.to_be_bytes());
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    let continued = peer.packets.recv().await.context("UDP proxy stopped")?;
                    ensure!(
                        continued.association == packet.association
                            && continued.target == udp_target,
                        "UDP changed proxy association/target after failover"
                    );
                    if continued.payload == final_payload {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("post-switch UDP no longer traverses the proxy")??;
            ensure!(
                stats("hm0", "tx_packets")? > active && stats("hm1", "tx_packets")? == old,
                "UDP replies did not follow current member"
            );
            redirected(ebpf, udp.local, udp_target, 17, BOND, from_wan).await?;
        }
        udp.finish().await?;
        let programs = if from_wan == 1 {
            [TcProgram::WanIngressL2, TcProgram::WanEgressL2]
        } else {
            [TcProgram::LanIngressL2, TcProgram::LanEgressL2]
        };
        assert_hooks(ebpf, BOND, programs).await?;
        no_member_hooks()?;
        if from_wan == 1 {
            let snapshot = ebpf.read().await.interface_binding_snapshot()?;
            ensure!(
                snapshot.owned.iter().all(|(binding, ..)| matches!(
                    binding.program,
                    TcProgram::WanIngressL2 | TcProgram::WanEgressL2
                )),
                "WAN-only installed a LAN hook"
            );
        }
        Ok(())
    }
    .await;
    tcp_echo.abort();
    udp_echo.abort();
    let _ = tcp_echo.await;
    let _ = udp_echo.await;
    result
}

async fn inactive(s: &Scenario, ebpf: &Backend, target: SocketAddr) -> anyhow::Result<()> {
    switch_active("hm0").await?;
    let mac = std::fs::read_to_string(format!("/sys/class/net/{BOND}/address"))?;
    let netns = s.client_ns.as_ref().unwrap();
    ip(
        Some(netns),
        &[
            "neigh",
            "replace",
            &LAN.to_string(),
            "lladdr",
            mac.trim(),
            "nud",
            "permanent",
            "dev",
            PEER_BRIDGE,
        ],
    )?;
    for port in ["hp0", "hp1"] {
        let output = in_test_netns(netns, || {
            std::process::Command::new("bridge")
                .args(["link", "set", "dev", port, "learning", "off"])
                .output()
        })?;
        ensure!(output.status.success(), "disable bridge learning");
    }
    let pin = |port: &str| -> anyhow::Result<()> {
        let output = in_test_netns(netns, || {
            std::process::Command::new("bridge")
                .args([
                    "fdb",
                    "replace",
                    mac.trim(),
                    "dev",
                    port,
                    "master",
                    "static",
                ])
                .output()
        })?;
        ensure!(
            output.status.success(),
            "pin FDB: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    };
    pin("hp1")?;
    let before = stats("hm1", "rx_packets")?;
    let socket = in_test_netns(netns, || -> anyhow::Result<_> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(LAN_CLIENT.into(), 0))?;
        Ok(socket)
    })?;
    let local = socket.local_addr()?;
    let outcome = tokio::time::timeout(Duration::from_millis(1500), socket.connect(target)).await;
    ensure!(
        outcome.is_err(),
        "inactive member's SYN was taken over ahead of bonding: {outcome:?}"
    );
    ensure!(
        stats("hm1", "rx_packets")? > before,
        "test SYN did not arrive on inactive member"
    );
    ensure!(
        ebpf.read()
            .await
            .redirect_track_lookup(&RedirectTuple::from_tuples(&tuple(local, target, 6)))?
            .is_none(),
        "inactive frame published a redirect"
    );
    pin("hp0")?;
    let mut control = Client::start("tcp", s.source, target, Some(netns)).await?;
    control.rounds(2).await?;
    redirected(ebpf, control.local, target, 6, BOND, 0).await?;
    control.finish().await?;
    no_member_hooks()?;
    Ok(())
}

async fn bridge(
    s: &Scenario,
    ebpf: &Backend,
    target: SocketAddr,
    tcp_target: SocketAddr,
) -> anyhow::Result<()> {
    let mut udp = Client::start("udp", s.source, target, s.client_ns.as_ref()).await?;
    udp.rounds(4).await?;
    let forward = tuple(udp.local, target, 17);
    let reverse = tuple(target, udp.local, 17);
    let backend = ebpf.read().await;
    let state = backend
        .conn_state_lookup(&reverse)?
        .context("bond port did not learn reverse UDP")?;
    ensure!(
        state.is_wan_ingress_direction == 1,
        "reply was freshly routed, not learned by LAN egress"
    );
    ensure!(
        backend.conn_state_lookup(&forward)?.is_some(),
        "native request not classified"
    );
    ensure!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&forward))?
            .is_none()
            && backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&reverse))?
                .is_none(),
        "bridged native UDP was proxied"
    );
    drop(backend);
    udp.finish().await?;
    assert_hooks(
        ebpf,
        BRIDGE,
        [TcProgram::LanIngressL2, TcProgram::WanEgressL2],
    )
    .await?;
    for port in [BOND, "hl0"] {
        assert_hooks(
            ebpf,
            port,
            [TcProgram::LanIngressL2, TcProgram::LanEgressL2],
        )
        .await?;
    }
    let sibling = fresh_test_netns();
    veth("hsib0", "hsib1", &sibling)?;
    ip(None, &["link", "set", "hsib0", "master", BRIDGE])?;
    ip(None, &["link", "set", "hsib0", "up"])?;
    configure_test_edge(&sibling, "hsib1", Ipv4Addr::new(10, 74, 0, 4), LAN, &[]);
    wait_until(
        ebpf,
        "watcher did not cover hotplugged sibling",
        |snapshot| {
            snapshot
                .owned
                .iter()
                .filter(|(binding, ..)| binding.interface == "hsib0")
                .count()
                == 2
        },
    )
    .await?;
    let mut second =
        Client::start("udp", Ipv4Addr::new(10, 74, 0, 4), target, Some(&sibling)).await?;
    second.rounds(4).await?;
    let state = ebpf
        .read()
        .await
        .conn_state_lookup(&tuple(target, second.local, 17))?
        .context("hotplugged sibling reverse state")?;
    ensure!(state.is_wan_ingress_direction == 1);
    second.finish().await?;
    // Local host TCP crosses the shared bridge root's WAN egress, unlike L2 transit.
    let mut local = Client::start("tcp", LAN, tcp_target, None).await?;
    local.rounds(4).await?;
    redirected(ebpf, local.local, tcp_target, 6, BRIDGE, 1).await?;
    local.finish().await?;
    no_member_hooks()?;
    Ok(())
}
