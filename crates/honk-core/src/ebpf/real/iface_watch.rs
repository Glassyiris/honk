//! RTMGRP_LINK watcher: attaches TC programs to configured interfaces that
//! appear after startup (USB NICs, container veths, late-renamed links),
//! and re-expands bridge/bond slaves of configured LAN masters on every
//! reconcile so containers added later are covered too.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};

use crate::ebpf::{DynamicHooks, EbpfBackend, IfaceRole};

// RTMGRP_LINK as an nl_groups bitmask.
const RTMGRP_LINK_MASK: u32 = 1;
const IFF_UP: u32 = 0x1;
// Events are a wakeup hint only — reconcile re-reads ground truth from
// /sys — but a dropped datagram would stall a pending interface forever,
// so a slow ticker backstops the subscription.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// Attach state per interface name: the ifindex the hooks live on (a
/// delete+recreate gets a new one and needs fresh hooks) and which
/// directions are already attached (retries only fill the gap).
pub type AttachedMap = HashMap<String, (u32, DynamicHooks)>;

pub struct IfaceWatcher {
    handle: tokio::task::JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl IfaceWatcher {
    /// `attached` seeds the names (with ifindex and directions) already
    /// hooked during startup so the first reconcile does not attach twice.
    pub fn spawn(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<honk_config::Config>>,
        attached: AttachedMap,
    ) -> Option<Self> {
        let fd = match subscribe_links() {
            Ok(fd) => fd,
            Err(e) => {
                warn!(
                    "interface watcher disabled: subscribe RTMGRP_LINK failed: {}",
                    e
                );
                return None;
            }
        };
        let (stop, rx) = watch::channel(false);
        let handle = tokio::spawn(run(fd, ebpf, config, attached, rx));
        Some(Self { handle, stop })
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.handle.await;
    }
}

fn subscribe_links() -> std::io::Result<OwnedFd> {
    // SAFETY: plain socket creation; OwnedFd takes ownership on success.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = RTMGRP_LINK_MASK;
    // SAFETY: addr is a valid sockaddr_nl for this socket.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

async fn run(
    fd: OwnedFd,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<honk_config::Config>>,
    mut attached: AttachedMap,
    mut stop: watch::Receiver<bool>,
) {
    let async_fd = match tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("interface watcher disabled: AsyncFd setup failed: {}", e);
            return;
        }
    };
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = [0u8; 8192];

    reconcile(&ebpf, &config, &mut attached).await;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = ticker.tick() => {
                reconcile(&ebpf, &config, &mut attached).await;
            }
            guard = async_fd.readable() => {
                // A transient read failure (ENOBUFS after a burst) must not
                // kill the watcher: the ticker keeps reconciling regardless.
                let mut guard = match guard {
                    Ok(g) => g,
                    Err(e) => {
                        warn!("interface watcher: netlink wait failed: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                // Drain pending link events; their contents are irrelevant
                // because reconcile re-derives state from /sys.
                let drained = guard.try_io(|inner| {
                    loop {
                        // SAFETY: buf is a valid writable region; fd is
                        // non-blocking, so EAGAIN ends the drain.
                        let n = unsafe {
                            libc::recv(
                                inner.as_raw_fd(),
                                buf.as_mut_ptr().cast(),
                                buf.len(),
                                0,
                            )
                        };
                        if n < 0 {
                            let e = std::io::Error::last_os_error();
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                return Ok(());
                            }
                            if e.kind() == std::io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(e);
                        }
                    }
                });
                match drained {
                    Ok(Ok(())) => {
                        guard.clear_ready();
                        reconcile(&ebpf, &config, &mut attached).await;
                    }
                    Ok(Err(e)) => {
                        warn!("interface watcher: netlink recv failed: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    // Spurious readiness; nothing was drained.
                    Err(_) => {}
                }
            }
        }
    }
    debug!("interface watcher stopped");
}

async fn reconcile(
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: &Arc<RwLock<honk_config::Config>>,
    attached: &mut AttachedMap,
) {
    let (desired, single_homed) = {
        let cfg = config.read().await;
        desired_interfaces(&cfg)
    };
    let wanted = |role: IfaceRole| match role {
        IfaceRole::Lan => DynamicHooks {
            ingress: true,
            egress: !single_homed,
        },
        _ => DynamicHooks {
            ingress: true,
            egress: true,
        },
    };
    let mut backend = ebpf.write().await;
    // Forget tracked entries that vanished, were recreated (their hooks
    // died with the old ifindex), or are no longer wanted (un-enslaved,
    // removed from config).
    let tracked: Vec<(String, u32)> = attached
        .iter()
        .map(|(name, (ifindex, _))| (name.clone(), *ifindex))
        .collect();
    for (name, ifindex) in tracked {
        if !desired.contains_key(&name) || iface_ifindex(&name) != Some(ifindex) {
            backend.forget_dynamic_interface(ifindex);
            attached.remove(&name);
        }
    }
    for (name, role) in desired {
        let want = wanted(role);
        let have = attached
            .get(&name)
            .map(|(_, hooks)| *hooks)
            .unwrap_or_default();
        if have == want {
            continue;
        }
        if iface_ifindex(&name).is_none() || !iface_is_up(&name) {
            continue;
        }
        match backend.attach_dynamic_interface(&name, role, single_homed) {
            Ok(hooks) => {
                attached.insert(name.clone(), (iface_ifindex(&name).unwrap_or(0), hooks));
                info!(interface = %name, role = ?role, "attached eBPF programs to new interface");
            }
            Err(e) => {
                warn!(interface = %name, role = ?role, "dynamic attach failed: {}", e);
            }
        }
    }
}

/// The configured interface set with roles, mirroring the startup logic in
/// `run()`: LAN entries win over WAN for the same name (single-homed), and
/// `auto`/empty resolve to the default-route interface.
fn desired_interfaces(config: &honk_config::Config) -> (HashMap<String, IfaceRole>, bool) {
    let lan: Vec<String> = if config.global.lan_interface.is_empty() {
        vec!["lo".to_string()]
    } else {
        config
            .global
            .lan_interface
            .iter()
            .map(|s| crate::resolve_interface(s))
            .collect()
    };
    let wan: Vec<String> = config
        .global
        .wan_interface
        .iter()
        .map(|s| crate::resolve_interface(s))
        .collect();
    let single_homed = !wan.is_empty() && lan.iter().any(|l| wan.contains(l));
    let mut desired = HashMap::new();
    for w in &wan {
        if !lan.contains(w) {
            desired.insert(w.clone(), IfaceRole::Wan);
        }
    }
    for l in &lan {
        desired.insert(l.clone(), IfaceRole::Lan);
    }
    // Bridge/bond slaves of configured LAN masters need their own hooks
    // (forwarded traffic bypasses the master's qdiscs); membership is
    // re-read on every reconcile so late-added containers are covered.
    for master in &lan {
        for slave in super::RealEbpfBackend::bridge_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::LanBridgeSlave);
        }
        for slave in super::RealEbpfBackend::bond_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::LanBondSlave);
        }
    }
    (desired, single_homed)
}

fn iface_ifindex(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn iface_is_up(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & IFF_UP != 0)
}
