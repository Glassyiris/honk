//! RTMGRP_LINK watcher: attaches TC programs to configured interfaces that
//! appear after startup (USB NICs, container veths, late-renamed links),
//! re-expands LAN bridge/bond slaves, and follows WAN bond slaves so newly
//! added physical egress paths receive the matching hooks.

use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, socket,
};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
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

    pub async fn shutdown(self, timeout: Duration) {
        let _ = self.stop.send(true);
        let mut handle = self.handle;
        // A watcher wedged mid-reconcile holds the backend write lock and
        // could re-attach hooks after detach_hooks — abort it rather than
        // drop the handle and leave the task running into teardown.
        if tokio::time::timeout(timeout, &mut handle).await.is_err() {
            handle.abort();
            let _ = (&mut handle).await;
        }
    }
}

fn subscribe_links() -> std::io::Result<OwnedFd> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        Some(SockProtocol::NetlinkRoute),
    )
    .map_err(std::io::Error::from)?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, RTMGRP_LINK_MASK)).map_err(std::io::Error::from)?;
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
                let drained = guard.try_io(|inner| loop {
                    match recv(inner.as_raw_fd(), &mut buf, MsgFlags::empty()) {
                        Ok(_) => {}
                        Err(errno) => {
                            let e = std::io::Error::from(errno);
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
        IfaceRole::WanBondSlave => DynamicHooks {
            ingress: false,
            egress: true,
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
/// `run()`: LAN entries win over WAN for the same name (single-homed), while
/// an empty LAN list installs no LAN hooks.
fn desired_interfaces(config: &honk_config::Config) -> (HashMap<String, IfaceRole>, bool) {
    let crate::ConfiguredInterfaces {
        lan,
        wan,
        single_homed,
    } = crate::configured_interfaces(config);
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
    // A bond may emit host traffic directly on a slave. Re-expand membership
    // so WAN-only mode keeps intercepting slaves added after startup.
    for master in &wan {
        for slave in super::RealEbpfBackend::bond_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::WanBondSlave);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn wan_only_configuration_does_not_synthesize_loopback_lan() {
        let mut config = honk_config::Config::default();
        config.global.wan_interface = vec!["wan0".to_string()];

        let (desired, single_homed) = desired_interfaces(&config);

        assert!(!single_homed);
        assert_eq!(desired.len(), 1);
        assert_eq!(desired.get("wan0"), Some(&IfaceRole::Wan));
        assert!(!desired.contains_key("lo"));
    }

    /// Reconcile attaches an interface's hooks exactly once and never
    /// detaches: hook removal belongs to shutdown alone, a periodic
    /// reconcile must not tear down the datapath.
    #[tokio::test]
    async fn reconcile_attaches_once_and_never_detaches() {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let attach = backend.dynamic_attach_calls.clone();
        let detach = backend.detach_calls.clone();
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec!["lo".to_string()];
        let config = Arc::new(RwLock::new(config));
        let mut attached = AttachedMap::new();

        reconcile(&ebpf, &config, &mut attached).await;
        let first = attach.load(Ordering::Relaxed);
        assert!(first >= 1, "first reconcile attaches the configured LAN");
        assert_eq!(detach.load(Ordering::Relaxed), 0);

        reconcile(&ebpf, &config, &mut attached).await;
        assert_eq!(
            attach.load(Ordering::Relaxed),
            first,
            "second reconcile must not re-attach"
        );
        assert_eq!(
            detach.load(Ordering::Relaxed),
            0,
            "reconcile must never detach"
        );
    }
}
