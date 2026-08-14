use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::group::{SelectionNetwork, SelectionPlanMode};
use honk_config::types::NodeProtocol;
use std::collections::{HashMap, HashSet};

/// Result from the eBPF routing handoff map lookup.
#[derive(Debug, Clone)]
struct HandoffResult {
    outbound: u8,
    mark: u32,
    must: u8,
    decision_token: u32,
    dscp: u8,
    mac: [u8; 6],
    pname: [u8; 16],
    pid: u32,
}

impl From<RoutingHandoffEntry> for HandoffResult {
    fn from(entry: RoutingHandoffEntry) -> Self {
        Self {
            outbound: entry.result.outbound,
            mark: entry.result.mark,
            must: entry.result.must,
            decision_token: entry.result.decision_token,
            dscp: entry.result.dscp,
            mac: entry.result.mac,
            pname: entry.result.pname,
            pid: entry.result.pid,
        }
    }
}

impl HandoffResult {
    /// Convert the eBPF process name byte array to an optional string.
    /// Treats the array as NUL-terminated or fixed-length, trimming trailing
    /// NULs and whitespace.
    fn process_name(&self) -> Option<String> {
        let bytes: Vec<u8> = self.pname.iter().copied().take_while(|&b| b != 0).collect();
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Resolve the process executable path from /proc. The process may have
    /// exited between the cgroup hook and now — any failure just omits the
    /// field. Off the runtime workers: even a /proc readlink is blocking I/O.
    async fn process_path(&self) -> Option<String> {
        if self.pid == 0 {
            return None;
        }
        let pid = self.pid;
        tokio::task::spawn_blocking(move || {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .await
        .ok()
        .flatten()
    }

    /// Convert the eBPF MAC address to canonical lower-case colon form.
    fn mac_address(&self) -> Option<String> {
        if self.mac == [0u8; 6] {
            return None;
        }
        Some(
            self.mac
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct TcpFlowKey {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    l4proto: u8,
}

impl TcpFlowKey {
    pub(super) fn from_tuples(tuples: &TuplesKey) -> Self {
        Self {
            src_ip: *tuples.src_ip.as_bytes(),
            dst_ip: *tuples.dst_ip.as_bytes(),
            src_port: tuples.src_port,
            dst_port: tuples.dst_port,
            l4proto: tuples.l4proto,
        }
    }

    pub(super) fn from_redirect(tuple: &RedirectTuple) -> Self {
        Self {
            src_ip: *tuple.src_ip.as_bytes(),
            dst_ip: *tuple.dst_ip.as_bytes(),
            src_port: tuple.src_port,
            dst_port: tuple.dst_port,
            l4proto: tuple.l4proto,
        }
    }
}

#[derive(Default)]
pub(super) struct TcpFlowPins {
    inner: parking_lot::Mutex<HashMap<TcpFlowKey, usize>>,
}

impl TcpFlowPins {
    fn retain(&self, key: TcpFlowKey) {
        *self.inner.lock().entry(key).or_default() += 1;
    }

    fn release(&self, key: TcpFlowKey) -> Option<bool> {
        let mut pins = self.inner.lock();
        let owners = pins.get_mut(&key)?;
        if *owners > 1 {
            *owners -= 1;
            Some(false)
        } else {
            pins.remove(&key);
            Some(true)
        }
    }

    pub(super) fn snapshot(&self) -> HashSet<TcpFlowKey> {
        self.inner.lock().keys().copied().collect()
    }

    #[cfg(test)]
    pub(super) fn retain_for_test(&self, key: TcpFlowKey) {
        self.retain(key);
    }

    #[cfg(test)]
    pub(super) fn release_for_test(&self, key: TcpFlowKey) -> Option<bool> {
        self.release(key)
    }
}

struct TcpFlowGuard {
    stream: TcpStream,
    tuples: TuplesKey,
    pin_key: Option<TcpFlowKey>,
    pins: Arc<TcpFlowPins>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    tracker_id: Option<String>,
}

impl TcpFlowGuard {
    fn new(
        stream: TcpStream,
        tuples: TuplesKey,
        pins: Arc<TcpFlowPins>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        tracker: Arc<ConnectionTracker>,
    ) -> Self {
        let pin_key = TcpFlowKey::from_tuples(&tuples);
        pins.retain(pin_key);
        Self {
            stream,
            tuples,
            pin_key: Some(pin_key),
            pins,
            ebpf,
            tracker,
            tracker_id: None,
        }
    }

    fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    fn track(&mut self, entry: crate::connection_tracker::ConnectionEntry) {
        assert!(
            self.tracker_id.is_none(),
            "TCP flow tracker attached more than once"
        );
        self.tracker_id = Some(self.tracker.register(entry));
    }

    fn untrack(&mut self) {
        if let Some(id) = self.tracker_id.take() {
            self.tracker.remove(&id);
        }
    }

    fn release_pin(&mut self) -> Option<bool> {
        let key = self.pin_key.take()?;
        match self.pins.release(key) {
            Some(last_owner) => Some(last_owner),
            None => {
                error!(?key, "TCP flow pin release found no owner");
                None
            }
        }
    }

    async fn retire(mut self) {
        self.untrack();
        let now_ns = match super::janitor::monotonic_now_ns() {
            Ok(now_ns) => now_ns,
            Err(error) => {
                error!(%error, "TCP flow retirement could not read monotonic clock");
                return;
            }
        };
        let retire_cutoff_ns = now_ns.saturating_sub(1);
        let ebpf = Arc::clone(&self.ebpf);
        let mut backend = ebpf.write().await;
        if self.release_pin() != Some(true) {
            return;
        }

        let current = match backend.tcp_conn_state_lookup(&self.tuples) {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow retirement lookup failed");
                return;
            }
        };
        match backend.conn_state_remove_if_unchanged(&[(self.tuples, current)], retire_cutoff_ns) {
            Ok(removed) => {
                if removed != 0 {
                    crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
                }
                debug!(removed, ?self.tuples, "TCP flow conn-state retired");
            }
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow conditional retirement failed");
            }
        }
    }
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        self.untrack();
        self.release_pin();
    }
}

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}
fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

mod context;

pub(super) use context::{ConnectionGuard, ControlPlaneHandle};

mod flow;

pub(crate) use flow::build_tuples_key;

#[cfg(test)]
pub(in crate::control) use flow::{RealityOutcome, domain_reality_outcome};
