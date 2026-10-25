//! Real veth traffic for frames honk's parent-device hooks must leave to their own device.
//! `BPF_PROG_TEST_RUN` zeroes the VLAN fields, so only real traffic exercises the tag checks.

use super::support::netns::{
    KernelTcpDial, build_lab, lab_config, pinned_hash_snapshot, pinned_map, run_isolated,
};
use super::{
    NETNS_TEST_TIMEOUT, configure_test_edge, in_test_netns, udp_test_forwarder, udp_test_node,
};
use crate::control::{ControlCommand, ControlPlane};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::{EbpfBackend, real::RealEbpfBackend};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::Array;
use honk_ebpf_common::{
    FlowMapValue, RedirectEntry, RedirectTuple,
    conn::ConnState,
    redirect_need::{RoutingHandoffEntry, TuplesKey},
};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const CHILD: &str = "HONK_VLAN_FRAMES_CHILD";
const HOST_CLIENT: &str = "HONK_VLAN_FRAMES_HOST_CLIENT";
const HOST_CLIENT_TEST: &str =
    "control::tests::vlan_frames::netns_vlan_host_connection_on_parent_wan_is_native";
const ROOT: &str = "/sys/fs/bpf/vlan-frames";
const REQUEST: &[u8] = b"vlan-frame-request";
const REPLY: &[u8] = b"vlan-frame-reply";
const PORT: u16 = 41011;
const LAN: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 1);
const WAN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const HOST_MAC: &str = "02:00:00:00:0a:01";
const CLIENT_MAC: &str = "02:00:00:00:0c:01";

macro_rules! vlan_case {
    ($name:ident, $case:literal) => {
        #[test]
        #[ignore = "requires Linux 6.12+, root, 8021q/macsec and the disposable kernel VM gate"]
        fn $name() -> anyhow::Result<()> {
            if let Some(target) = std::env::var_os(HOST_CLIENT) {
                return host_client(target.to_str().context("host client target")?);
            }
            run_isolated(
                concat!("control::tests::vlan_frames::", stringify!($name)),
                CHILD,
                [$case],
                run_child,
            )
        }
    };
}

// Ablate E1 in lan_ingress: the parent redirects the tagged SYN, daens drops it as OTHERHOST.
vlan_case!(
    netns_vlan_client_on_parent_lan_is_forwarded_natively,
    "lan_parent"
);
// Ablate E1: the parent hook classifies first, so the VLAN device never gets the frame.
vlan_case!(
    netns_vlan_device_lan_is_proxied_beside_its_parent,
    "lan_parent_and_vlan"
);
// An 802.1p priority tag (VID 0) is delivered by the parent: E1 must not skip it.
vlan_case!(
    netns_vlan_priority_tagged_lan_client_is_still_proxied,
    "vid0"
);
// Ablate E2 in wan_egress: the tagged SYN is redirected into daens and dropped.
vlan_case!(
    netns_vlan_host_connection_on_parent_wan_is_native,
    "wan_parent"
);
vlan_case!(netns_vlan_device_wan_intercepts_host_connection, "wan_vlan");
// Ablate E3': the encrypted frame is marked classified, the decrypted upper flow skipped.
vlan_case!(netns_macsec_upper_device_lan_flow_is_classified, "macsec");

/// One request/reply exchange from the host namespace, in its own process.
fn host_client(target: &str) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(target)?;
    stream.set_read_timeout(Some(NETNS_TEST_TIMEOUT))?;
    stream.write_all(REQUEST)?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply)?;
    ensure!(reply == REPLY, "host client received the wrong reply");
    Ok(())
}

fn ip(netns: Option<&OwnedFd>, args: &[&str]) -> anyhow::Result<()> {
    let run = || std::process::Command::new("ip").args(args).output();
    let output = match netns {
        Some(netns) => in_test_netns(netns, run),
        None => run(),
    }?;
    ensure!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Adds `name` (a VLAN or macsec device over `parent`) with `address/24`, up.
fn upper(
    netns: Option<&OwnedFd>,
    parent: &str,
    name: &str,
    kind: &[&str],
    address: Ipv4Addr,
) -> anyhow::Result<()> {
    let mut args = vec!["link", "add", "link", parent, "name", name, "type"];
    args.extend_from_slice(kind);
    ip(netns, &args)?;
    ip(
        netns,
        &["addr", "add", &format!("{address}/24"), "dev", name],
    )?;
    ip(netns, &["link", "set", name, "up"])
}

/// Pinned flow maps, read while the exchange is in flight.
struct Maps {
    redirects: Vec<(RedirectTuple, FlowMapValue<RedirectEntry>)>,
    conns: Vec<(TuplesKey, FlowMapValue<ConnState>)>,
    handoffs: Vec<(TuplesKey, FlowMapValue<RoutingHandoffEntry>)>,
}

impl Maps {
    fn snapshot() -> anyhow::Result<Self> {
        let flags = aya_obj::generated::BPF_F_LOCK as u64;
        let root = Path::new(ROOT);
        Ok(Self {
            redirects: pinned_hash_snapshot(root, "REDIRECT_TRACK", flags)?,
            conns: pinned_hash_snapshot(root, "CONN_STATE_MAP", flags)?,
            handoffs: pinned_hash_snapshot(root, "ROUTING_HANDOFF_MAP", flags)?,
        })
    }
}

/// What honk must have done to the flow.
enum Expect {
    /// Left to the kernel: nothing published for the flow.
    Native,
    /// LAN ingress redirected it into daens; REDIRECT_TRACK carries this device's ifindex.
    LanOn(&'static str),
    /// WAN egress redirected the host's own connection: it published conn state.
    Wan,
}

/// The scenario a case builds: who connects, where, and what honk was told to hook.
struct Scenario {
    /// Network namespace of the connecting socket; `None` is the host itself.
    client_ns: Option<OwnedFd>,
    source: Option<IpAddr>,
    server_ns: OwnedFd,
    target: SocketAddr,
    lan_extra: Vec<&'static str>,
    wan: &'static str,
    expect: Expect,
    /// The address the server sees: the client's own natively, the proxy's when relayed.
    peer: IpAddr,
}

fn run_child(case: &str) -> anyhow::Result<()> {
    let (client_ns, server_ns) = build_lab(LAN.into(), WAN.into())?;
    configure_test_edge(&server_ns, "honk-s0", SERVER, WAN, &[]);
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    ip(None, &["link", "set", "honk-lan0", "address", HOST_MAC])?;
    ip(Some(&client_ns), &["link", "set", "lo", "up"])?;
    ip(
        Some(&client_ns),
        &["link", "set", "honk-c0", "address", CLIENT_MAC],
    )?;
    ip(Some(&client_ns), &["link", "set", "honk-c0", "up"])?;
    let default_via = |gateway: Ipv4Addr, dev: &str| {
        ip(
            Some(&client_ns),
            &[
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                dev,
            ],
        )
    };
    let vlan_lan = || -> anyhow::Result<()> {
        upper(
            None,
            "honk-lan0",
            "honk-lan0.20",
            &["vlan", "id", "20"],
            Ipv4Addr::new(10, 20, 0, 1),
        )?;
        upper(
            Some(&client_ns),
            "honk-c0",
            "honk-c0.20",
            &["vlan", "id", "20"],
            Ipv4Addr::new(10, 20, 0, 2),
        )?;
        default_via(Ipv4Addr::new(10, 20, 0, 1), "honk-c0.20")
    };
    let to_server = SocketAddr::new(SERVER.into(), PORT);
    let scenario = match case {
        "lan_parent" | "lan_parent_and_vlan" => {
            vlan_lan()?;
            let (lan_extra, expect, peer) = match case {
                "lan_parent" => (vec![], Expect::Native, Ipv4Addr::new(10, 20, 0, 2)),
                _ => (vec!["honk-lan0.20"], Expect::LanOn("honk-lan0.20"), WAN),
            };
            Scenario {
                client_ns: Some(client_ns),
                source: Some(Ipv4Addr::new(10, 20, 0, 2).into()),
                server_ns,
                target: to_server,
                lan_extra,
                wan: "honk-wan0",
                expect,
                peer: peer.into(),
            }
        }
        "vid0" => {
            // VID 0 is an 802.1p priority tag (priority 3 here, so vlan_tci is non-zero)
            // the parent delivers itself. The host
            // replies untagged, so pin both neighbours instead of relying on ARP.
            let client = Ipv4Addr::new(10, 74, 0, 2);
            upper(
                Some(&client_ns),
                "honk-c0",
                "honk-c0.0",
                &["vlan", "id", "0", "egress-qos-map", "0:3"],
                client,
            )?;
            default_via(LAN, "honk-c0.0")?;
            ip(
                Some(&client_ns),
                &[
                    "neigh",
                    "replace",
                    &LAN.to_string(),
                    "lladdr",
                    HOST_MAC,
                    "dev",
                    "honk-c0.0",
                    "nud",
                    "permanent",
                ],
            )?;
            ip(
                None,
                &[
                    "neigh",
                    "replace",
                    &client.to_string(),
                    "lladdr",
                    CLIENT_MAC,
                    "dev",
                    "honk-lan0",
                    "nud",
                    "permanent",
                ],
            )?;
            Scenario {
                client_ns: Some(client_ns),
                source: Some(client.into()),
                server_ns,
                target: to_server,
                lan_extra: vec![],
                wan: "honk-wan0",
                expect: Expect::LanOn("honk-lan0"),
                peer: WAN.into(),
            }
        }
        "wan_parent" | "wan_vlan" => {
            let host = Ipv4Addr::new(10, 30, 0, 1);
            upper(
                None,
                "honk-wan0",
                "honk-wan0.20",
                &["vlan", "id", "20"],
                host,
            )?;
            upper(
                Some(&server_ns),
                "honk-s0",
                "honk-s0.20",
                &["vlan", "id", "20"],
                Ipv4Addr::new(10, 30, 0, 2),
            )?;
            let (wan, expect) = match case {
                "wan_parent" => ("honk-wan0", Expect::Native),
                _ => ("honk-wan0.20", Expect::Wan),
            };
            Scenario {
                client_ns: None,
                source: None,
                server_ns,
                target: SocketAddr::new(Ipv4Addr::new(10, 30, 0, 2).into(), PORT),
                lan_extra: vec![],
                wan,
                expect,
                peer: host.into(),
            }
        }
        "macsec" => {
            // Static SAs need no daemon. A missing module or cipher fails here, loudly.
            let (host, client) = (Ipv4Addr::new(10, 76, 0, 1), Ipv4Addr::new(10, 76, 0, 2));
            let keys = [
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
            ];
            let secure = |netns: Option<&OwnedFd>,
                          parent: &str,
                          local: Ipv4Addr,
                          peer_mac: &str,
                          (tx, rx): (&str, &str)|
             -> anyhow::Result<()> {
                upper(
                    netns,
                    parent,
                    "macsec0",
                    &["macsec", "port", "1", "encrypt", "on"],
                    local,
                )
                .context("macsec device (is the macsec module available?)")?;
                ip(
                    netns,
                    &[
                        "macsec", "add", "macsec0", "tx", "sa", "0", "pn", "1", "on", "key", "01",
                        tx,
                    ],
                )
                .context("macsec transmit SA (is gcm(aes) available?)")?;
                ip(
                    netns,
                    &[
                        "macsec", "add", "macsec0", "rx", "port", "1", "address", peer_mac,
                    ],
                )?;
                ip(
                    netns,
                    &[
                        "macsec", "add", "macsec0", "rx", "port", "1", "address", peer_mac, "sa",
                        "0", "pn", "1", "on", "key", "02", rx,
                    ],
                )
            };
            secure(None, "honk-lan0", host, CLIENT_MAC, (keys[0], keys[1]))?;
            secure(
                Some(&client_ns),
                "honk-c0",
                client,
                HOST_MAC,
                (keys[1], keys[0]),
            )?;
            default_via(host, "macsec0")?;
            Scenario {
                client_ns: Some(client_ns),
                source: Some(client.into()),
                server_ns,
                target: to_server,
                lan_extra: vec!["macsec0"],
                wan: "honk-wan0",
                expect: Expect::LanOn("macsec0"),
                peer: WAN.into(),
            }
        }
        _ => anyhow::bail!("unknown VLAN frame case {case}"),
    };
    let _dae0 = daens::create_dae0_link()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(with_datapath(scenario))
        .with_context(|| format!("VLAN frames {case}"))
}

/// Boots the production control plane over the real hooks, drives one TCP exchange and
/// checks whether honk intercepted it.
async fn with_datapath(scenario: Scenario) -> anyhow::Result<()> {
    let object = std::env::var_os("HONK_TEST_BPF_OBJECT")
        .map(std::fs::read)
        .transpose()?;
    let config = lab_config(&udp_test_node());
    let mut backend = RealEbpfBackend::load(
        object.as_deref().unwrap_or(crate::DEFAULT_BPF_OBJECT),
        Path::new(ROOT),
        config.global.tproxy_port,
        Some("honk-lan0"),
        scenario.wan,
        false,
    )
    .await?;
    for lan in &scenario.lan_extra {
        backend.attach_lan(lan, false)?;
    }
    backend.attach_dae0_programs()?;
    daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
    backend.attach_sk_lookup()?;
    backend.attach_dae0peer_ingress()?;
    let ready = Array::<_, u32>::try_from(pinned_map(Path::new(ROOT), "DATAPATH_STATE_MAP")?)?;
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        honk_config::types::NodeProtocol::Socks5,
        Arc::new(KernelTcpDial),
    ));
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
    let commands = control.command_sender();
    let shutdown = control.shutdown_requested.clone();
    let task = tokio::spawn(async move {
        let result = control.run().await;
        (control, result)
    });
    let exercise = async {
        tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
            while ready.get(&0, 0)? == 0 {
                ensure!(
                    !task.is_finished(),
                    "control stopped before listener readiness"
                );
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        exchange(&scenario).await
    }
    .await;
    shutdown.store(true, Ordering::Release);
    let command = if task.is_finished() {
        Ok(())
    } else {
        commands
            .send(ControlCommand::Shutdown)
            .await
            .map_err(anyhow::Error::from)
    };
    let (control, stopped) = task.await.context("control task panicked")?;
    stopped.context("control shutdown failed")?;
    command?;
    drop(control);
    exercise
}

async fn exchange(scenario: &Scenario) -> anyhow::Result<()> {
    let listener = in_test_netns(&scenario.server_ns, || -> anyhow::Result<_> {
        let listener = std::net::TcpListener::bind(scenario.target)?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    })?;
    let listener = TcpListener::from_std(listener)?;
    let server = tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await?;
        let mut received = vec![0; REQUEST.len()];
        stream.read_exact(&mut received).await?;
        ensure!(received == REQUEST, "server received the wrong request");
        // Still mid-flow: the control plane retires conn state once the relay ends.
        let maps = Maps::snapshot()?;
        stream.write_all(REPLY).await?;
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>((peer.ip(), maps))
    });
    let client = async {
        if scenario.client_ns.is_none() {
            // The control plane's own sockets are exempt from interception, so the host
            // client is this test binary run as another process.
            let status = tokio::time::timeout(
                NETNS_TEST_TIMEOUT,
                tokio::process::Command::new(std::env::current_exe()?)
                    .args([HOST_CLIENT_TEST, "--ignored", "--exact", "--nocapture"])
                    .env(HOST_CLIENT, scenario.target.to_string())
                    .kill_on_drop(true)
                    .status(),
            )
            .await
            .context("host client exchange timed out")??;
            ensure!(status.success(), "host client failed: {status}");
            return Ok(());
        }
        let socket = || -> anyhow::Result<_> {
            let socket = TcpSocket::new_v4()?;
            if let Some(source) = scenario.source {
                socket.bind(SocketAddr::new(source, 0))?;
            }
            Ok(socket)
        };
        let socket = match &scenario.client_ns {
            Some(netns) => in_test_netns(netns, socket)?,
            None => socket()?,
        };
        tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
            let mut stream: TcpStream = socket
                .connect(scenario.target)
                .await
                .context("client TCP handshake")?;
            stream.write_all(REQUEST).await?;
            let mut reply = Vec::new();
            stream
                .read_to_end(&mut reply)
                .await
                .context("read client reply through EOF")?;
            ensure!(reply == REPLY, "client received the wrong reply");
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("client exchange timed out")?
    }
    .await;
    if client.is_err() {
        server.abort();
    }
    client?;
    let (
        peer,
        Maps {
            redirects,
            conns,
            handoffs,
        },
    ) = tokio::time::timeout(NETNS_TEST_TIMEOUT, server)
        .await
        .context("server never finished")???;
    match scenario.expect {
        Expect::LanOn(device) => {
            let ifindex = crate::netlink::ifindex_of(device)?;
            ensure!(
                !redirects.is_empty()
                    && redirects
                        .iter()
                        .all(|(_, entry)| entry.value.ifindex == ifindex),
                "flow was not intercepted on {device} (ifindex {ifindex})"
            );
        }
        Expect::Wan => ensure!(
            !conns.is_empty(),
            "wan_egress did not intercept the host connection"
        ),
        Expect::Native => ensure!(
            redirects.is_empty() && conns.is_empty() && handoffs.is_empty(),
            "native flow left flow-map entries"
        ),
    }
    ensure!(
        peer == scenario.peer,
        "server saw {peer}, expected {}",
        scenario.peer
    );
    Ok(())
}
