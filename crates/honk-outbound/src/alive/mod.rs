//! Outbound dialer management — alive detection, sticky cache, recovery state.
//!
//! `AliveDialerSet` tracks 6 independent alive states per node
//! (Tcp4/6, DnsUdp4/6, DataUdp4/6) with exponential probe backoff
//! and pushes changes into the eBPF `outbound_connectivity_map`.
//!
//! Each periodic probe cycle runs the TCP probe (HTTP through the proxy,
//! or raw connect) followed by a UDP probe (`probe_node_udp`, when a
//! [`UdpProber`] is installed): a DNS exchange through the node's own UDP
//! data path whose result drives both UDP domains — catching nodes with
//! healthy TCP but broken UDP (e.g. an AnyTLS server without UoT).
//!
//! Go reference: `component/outbound/dialer/dialer.go`, `connectivity_check.go`

pub mod collection;
pub mod latencies;
mod probe;

#[cfg(test)]
mod tests;

use self::collection::DialerCollection;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeDomain {
    Tcp = 0,
    DnsUdp = 1,
    DataUdp = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4 = 0,
    V6 = 1,
}

impl ProbeDomain {
    pub const fn count() -> usize {
        3
    }
}
impl IpVersion {
    pub const fn count() -> usize {
        2
    }
}

pub const ALIVE_STATES_PER_NODE: usize = ProbeDomain::count() * IpVersion::count();

/// Maximum number of consecutive probe failures before permanent backoff stop.
/// Matches Go's `maxProbeBackoffFailures`.
const MAX_PROBE_BACKOFF_FAILURES: u32 = 10;

/// Number of consecutive successful probes needed to revive a dead node.
/// Prevents transient success (e.g. a TCP SYN accepted but proxy handshake
/// rejected) from immediately marking a dead node as alive.
const RECOVERY_SUCCESSES_NEEDED: u32 = 2;

/// Grace period for newly registered nodes. Probe failures during this
/// window don't count toward the death threshold, preventing new nodes
/// from being immediately marked dead before the first probe completes.
pub(crate) const GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Cooldown between emergency probes to protect the health check pool.
/// Matches Go's 2-second cooldown for NotifyCheckTcp/NotifyCheckDnsUdp.
const EMERGENCY_PROBE_COOLDOWN: Duration = Duration::from_secs(2);

#[inline]
pub fn alive_index(domain: ProbeDomain, ipver: IpVersion) -> usize {
    domain as usize * IpVersion::count() + ipver as usize
}

pub type ProtocolDomain = ProbeDomain;

/// Trait for HTTP-based health check probing through proxy nodes.
///
/// Implemented by `honk-core` to route HTTP requests through the proxy
/// registry, matching Go's `Dialer.HttpCheck`.  Returns the measured
/// round-trip latency on success, or an error string on failure.
pub trait HttpProber: Send + Sync {
    fn probe_http(
        &self,
        node_name: &str,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>>;
}

/// Type-erased HTTP prober stored in `AliveDialerSet`.
pub type HttpProberRef = Arc<dyn HttpProber>;

/// Trait for UDP-based health check probing through proxy nodes.
///
/// Implemented by `honk-core` to route a minimal DNS query through the
/// proxy handler's UDP data path (real UDP, UoT, QUIC datagrams — whatever
/// `dial_udp` provides), matching Go's `Dialer.UdpCheck`. Returns the
/// measured round-trip latency on success, or an error string on failure.
///
/// This catches nodes whose TCP path works but whose UDP path is broken
/// (e.g. an AnyTLS server without UoT support) — a plain TCP probe can
/// never see that failure mode.
pub trait UdpProber: Send + Sync {
    fn probe_udp(
        &self,
        node_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>>;
}

/// Type-erased UDP prober stored in `AliveDialerSet`.
pub type UdpProberRef = Arc<dyn UdpProber>;

/// Returns the failure threshold for probe-based health checks.
/// Matches Go thresholds:
///   TCP probe = 1 (single failure indicates immediate issue)
///   UDP DNS probe = 3 (DNS queries more prone to transient loss)
///   UDP Data probe = 3 (same as DNS)
const fn probe_failure_threshold(domain: ProbeDomain) -> u32 {
    match domain {
        ProbeDomain::Tcp => 1,
        ProbeDomain::DnsUdp => 3,
        ProbeDomain::DataUdp => 3,
    }
}

/// Returns the failure threshold for traffic-based health checks.
/// Matches Go thresholds:
///   TCP traffic = 10 (balance fast discovery with noise resilience)
///   UDP Data traffic = 50 (protect long-lived UDP flows from transient flips)
///   DNS UDP traffic = 3 (DNS failures from real user traffic)
const fn traffic_failure_threshold(domain: ProbeDomain) -> u32 {
    match domain {
        ProbeDomain::Tcp => 10,
        ProbeDomain::DnsUdp => 3,
        ProbeDomain::DataUdp => 50,
    }
}

#[derive(Debug, Clone)]
struct PerProtocolState {
    alive: bool,
    /// Probe-based consecutive failures.
    consecutive_failures: u32,
    /// Probe-based consecutive successes (for recovery hysteresis).
    consecutive_successes: u32,
    /// Traffic-based consecutive failures (separate counter, higher thresholds).
    traffic_failures: u32,
    cooldown_until: Instant,
    /// When true, periodic probes are permanently stopped until resuscitation.
    stopped: bool,
}

impl PerProtocolState {
    fn new() -> Self {
        Self {
            alive: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            traffic_failures: 0,
            cooldown_until: Instant::now(),
            stopped: false,
        }
    }
}

impl Default for PerProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

fn fresh_states() -> [PerProtocolState; ALIVE_STATES_PER_NODE] {
    [
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
    ]
}

type EbpfAliveCallback = Box<dyn Fn(u8, u32, u32, bool) + Send + Sync>;

/// Default URLTest group idle timeout when the group config has none
/// (sing-box default: 30 minutes). Periodic probing of a URLTest group's
/// members pauses while the group is idle and resumes on the next selection.
pub const DEFAULT_URLTEST_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Resolves a node name to its eBPF outbound index for
/// `OUTBOUND_CONNECTIVITY_MAP` writes (direct=0, block=1, group i → 2+i,
/// matching the control plane's routing push). Returns `None` for nodes
/// without an eBPF outbound id (not in any group) — those state changes
/// are not pushed to the kernel map.
pub type OutboundIdResolver = Arc<dyn Fn(&str) -> Option<u8> + Send + Sync>;

/// A single probe record for history/API consumption.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub timestamp: Instant,
    pub success: bool,
    pub latency: Option<Duration>,
}

/// Maximum probe history entries per node per domain/IP version.
const MAX_PROBE_HISTORY: usize = 100;

pub struct AliveDialerSet {
    /// Uses parking_lot RwLock/Mutex for synchronous, uncontended access on the
    /// async runtime (parking_lot blocks OS threads without runtime awareness).
    states: RwLock<HashMap<String, [PerProtocolState; ALIVE_STATES_PER_NODE]>>,
    /// Per-node-per-domain latency collections (Go `collection` struct).
    collections: RwLock<HashMap<String, [Arc<DialerCollection>; ALIVE_STATES_PER_NODE]>>,
    registered: RwLock<HashMap<String, String>>,
    ebpf_callback: RwLock<Option<EbpfAliveCallback>>,
    /// Deprecated: per-protocol thresholds are now used via probe_failure_threshold/traffic_failure_threshold.
    #[allow(dead_code)]
    failure_threshold: u32,
    base_cooldown: Duration,
    max_cooldown: Duration,
    trigger_tx: tokio::sync::mpsc::UnboundedSender<String>,
    trigger_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    /// Optional `SO_MARK` value applied to probe sockets so the eBPF datapath
    /// treats them as control-plane traffic and does not re-route them.
    so_mark: Option<u32>,
    /// Last emergency probe timestamps per node for cooldown (Go: lastNotifyUdp/lastNotifyTcp).
    last_emergency_tcp: Mutex<HashMap<String, Instant>>,
    last_emergency_udp: Mutex<HashMap<String, Instant>>,
    /// HTTP health check URL and method from config (Go: TcpCheckOption).
    /// When set, the probe uses HTTP(S) requests through the proxy instead of
    /// raw TCP connect, matching Go's `HttpCheck` behaviour.
    http_prober: RwLock<Option<HttpProberRef>>,
    check_url: RwLock<String>,
    check_method: RwLock<String>,
    /// Cached resolved IPs from the check URL hostname (Go: TcpCheckOption.Ip46).
    /// Resolved once at startup; refreshed on `refresh_check_ips()`.
    check_url_ips: RwLock<Vec<SocketAddr>>,
    /// UDP health check prober (Go: UdpCheckOption) installed by honk-core.
    /// When set, each periodic probe cycle runs a DNS-over-UDP exchange
    /// through the node's UDP data path after the TCP probe.
    udp_prober: RwLock<Option<UdpProberRef>>,
    /// Timestamp when each node was first registered (for grace period).
    node_registered_at: RwLock<HashMap<String, Instant>>,
    /// Per-node per-domain/IP-version probe history for API/UI.
    probe_history: RwLock<HashMap<(String, usize), Vec<ProbeRecord>>>,
    /// Node name → eBPF outbound index resolver for connectivity pushes.
    outbound_resolver: RwLock<Option<OutboundIdResolver>>,
    /// Last activity timestamp per URLTest group (lazy start: absent = idle).
    group_last_active: RwLock<HashMap<String, Instant>>,
    /// node name → URLTest groups it belongs to (for idle suspension).
    node_urltest_groups: RwLock<HashMap<String, Vec<String>>>,
    /// URLTest group → member node names (for wake-up probes).
    urltest_group_members: RwLock<HashMap<String, Vec<String>>>,
    /// URLTest group → idle timeout (probing pauses past it).
    urltest_group_timeout: RwLock<HashMap<String, Duration>>,
}

impl AliveDialerSet {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            states: RwLock::new(HashMap::new()),
            collections: RwLock::new(HashMap::new()),
            registered: RwLock::new(HashMap::new()),
            ebpf_callback: RwLock::new(None),
            failure_threshold: 3,
            base_cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(300),
            trigger_tx: tx,
            trigger_rx: Mutex::new(Some(rx)),
            so_mark: None,
            last_emergency_tcp: Mutex::new(HashMap::new()),
            last_emergency_udp: Mutex::new(HashMap::new()),
            http_prober: RwLock::new(None),
            check_url: RwLock::new(String::new()),
            check_method: RwLock::new(String::new()),
            check_url_ips: RwLock::new(Vec::new()),
            udp_prober: RwLock::new(None),
            node_registered_at: RwLock::new(HashMap::new()),
            probe_history: RwLock::new(HashMap::new()),
            outbound_resolver: RwLock::new(None),
            group_last_active: RwLock::new(HashMap::new()),
            node_urltest_groups: RwLock::new(HashMap::new()),
            urltest_group_members: RwLock::new(HashMap::new()),
            urltest_group_timeout: RwLock::new(HashMap::new()),
        }
    }

    /// Set the `SO_MARK` value for probe sockets and return `self` for chaining.
    pub fn with_so_mark(mut self, mark: u32) -> Self {
        self.so_mark = Some(mark);
        self
    }

    /// Configure HTTP-based health checks from config (Go: TcpCheckOption).
    ///
    /// Resolves the check URL's hostname once at startup and caches the IPs.
    /// Probes reuse the cached IPs without repeated DNS lookups, matching
    /// Go's `TcpCheckOptionRaw.Option()` pattern.
    pub async fn set_http_probe(
        &self,
        prober: HttpProberRef,
        check_url: String,
        check_method: String,
    ) {
        *self.http_prober.write() = Some(prober);
        *self.check_url.write() = check_url.clone();
        *self.check_method.write() = check_method;

        // Resolve the check URL hostname once at startup; dae-format literal
        // fallback IPs (comma-separated) are merged in so probes still have
        // targets even when DNS resolution fails.
        if let Some(hostname) = Self::parse_url_host(&check_url) {
            match tokio::net::lookup_host(format!("{}:80", hostname)).await {
                Ok(addrs) => {
                    let ips = Self::merge_check_addrs(addrs.collect(), &check_url);
                    tracing::info!(
                        "Health check DNS resolved '{}' → {} IPs",
                        hostname,
                        ips.len()
                    );
                    *self.check_url_ips.write() = ips;
                }
                Err(e) => {
                    tracing::warn!("Failed to resolve health check URL '{}': {}", hostname, e);
                    let ips = Self::merge_check_addrs(Vec::new(), &check_url);
                    if !ips.is_empty() {
                        *self.check_url_ips.write() = ips;
                    }
                }
            }
        } else {
            // No URL hostname at all — literal-only form.
            let ips = Self::merge_check_addrs(Vec::new(), &check_url);
            if !ips.is_empty() {
                *self.check_url_ips.write() = ips;
            }
        }
    }

    /// Install the UDP health check prober (Go: UdpCheckOption).
    ///
    /// Once installed, the periodic health check cycle runs
    /// [`AliveDialerSet::probe_node_udp`] after each node's TCP probe.
    pub fn set_udp_probe(&self, prober: UdpProberRef) {
        *self.udp_prober.write() = Some(prober);
    }

    /// Refresh the cached check URL IPs.  Called at the start of each full
    /// health check cycle so DNS record changes are eventually picked up.
    /// Matches Go's `TcpCheckOptionRaw.Reset()`.
    pub async fn refresh_check_ips(&self) {
        let check_url = self.check_url.read().clone();
        if let Some(hostname) = Self::parse_url_host(&check_url)
            && let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", hostname)).await
        {
            let ips = Self::merge_check_addrs(addrs.collect(), &check_url);
            *self.check_url_ips.write() = ips;
        }
    }

    pub fn set_ebpf_callback(&self, cb: EbpfAliveCallback) {
        *self.ebpf_callback.write() = Some(cb);
    }

    /// Install the node name → eBPF outbound index resolver used by
    /// `push_ebpf`. Re-callable: honk-core re-installs (or refreshes the
    /// captured map) on config reload. Pass `None` to restore the legacy
    /// fallback (outbound 0).
    pub fn set_outbound_resolver(&self, resolver: Option<OutboundIdResolver>) {
        *self.outbound_resolver.write() = resolver;
    }

    fn push_ebpf(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion, alive: bool) {
        let outbound = match *self.outbound_resolver.read() {
            Some(ref resolve) => match resolve(node_id) {
                Some(id) => id,
                // Node has no eBPF outbound id (not in any group) — skip.
                None => return,
            },
            // Legacy fallback when no resolver is installed (tests).
            None => 0,
        };
        if let Some(ref cb) = *self.ebpf_callback.read() {
            cb(outbound, domain as u32, ipver as u32, alive);
        }
    }

    pub fn take_trigger_rx(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
        self.trigger_rx.lock().take()
    }

    fn with_state<F, R>(&self, node_id: &str, idx: usize, f: F) -> R
    where
        F: FnOnce(&mut PerProtocolState) -> R,
    {
        let mut states = self.states.write();
        let entry = states.entry(node_id.into()).or_insert_with(fresh_states);
        f(&mut entry[idx])
    }

    fn read_state(&self, node_id: &str, idx: usize) -> PerProtocolState {
        self.states
            .read()
            .get(node_id)
            .map(|s| s[idx].clone())
            .unwrap_or_default()
    }

    pub fn is_alive_for(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        self.states.read().get(node_id).is_none_or(|s| s[idx].alive)
    }

    pub fn is_alive(&self, node_id: &str) -> bool {
        self.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4)
    }

    pub fn is_alive_udp(&self, node_id: &str) -> bool {
        self.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4)
    }

    /// Whether any UDP-domain state (DataUdp or DnsUdp, either IP version)
    /// has ever been recorded for this node — i.e. it was UDP-probed or had
    /// UDP traffic reported. Group selection uses this to distinguish
    /// "never UDP-probed" (TCP liveness fallback applies) from "UDP-probed
    /// and dead" (excluded from UDP selection even when TCP is alive).
    pub fn has_udp_state(&self, node_id: &str) -> bool {
        let history = self.probe_history.read();
        [ProbeDomain::DataUdp, ProbeDomain::DnsUdp]
            .into_iter()
            .flat_map(|d| {
                [IpVersion::V4, IpVersion::V6]
                    .into_iter()
                    .map(move |v| (d, v))
            })
            .any(|(d, v)| {
                history
                    .get(&(node_id.to_string(), alive_index(d, v)))
                    .is_some_and(|records| !records.is_empty())
            })
    }

    pub fn alive_nodes(&self) -> HashSet<String> {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        self.states
            .read()
            .iter()
            .filter(|(_, s)| s[idx].alive)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn count(&self) -> usize {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        self.states.read().values().filter(|s| s[idx].alive).count()
    }

    #[allow(dead_code)]
    fn mark_alive_for(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_alive_for_latency(node_id, domain, ipver, Duration::ZERO);
    }

    /// Mark a node as alive for a specific domain/IP version, recording the
    /// probe latency so `Latencies10` and `MovingAverage` are updated.
    fn mark_alive_for_latency(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        let idx = alive_index(domain, ipver);
        let was_alive = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.alive = true;
            e.consecutive_failures = 0;
            e.consecutive_successes = 0;
            e.traffic_failures = 0;
            e.stopped = false;
            e.cooldown_until = Instant::now();
            was
        });
        if !was_alive {
            self.push_ebpf(node_id, domain, ipver, true);
        }
        if latency > Duration::ZERO {
            let coll = self.get_or_create_collection(node_id, idx);
            coll.mark_available(latency);
        }
        self.record_probe_history(node_id, idx, true, Some(latency));
    }

    /// Check if a node is within its grace period.
    fn is_in_grace_period(&self, node_id: &str) -> bool {
        self.node_registered_at
            .read()
            .get(node_id)
            .map(|t| t.elapsed() < GRACE_PERIOD)
            .unwrap_or(false)
    }

    /// Append a probe record to history.
    fn record_probe_history(
        &self,
        node_id: &str,
        idx: usize,
        success: bool,
        latency: Option<Duration>,
    ) {
        let key = (node_id.to_string(), idx);
        let mut history = self.probe_history.write();
        let entry = history.entry(key).or_default();
        entry.push(ProbeRecord {
            timestamp: Instant::now(),
            success,
            latency,
        });
        if entry.len() > MAX_PROBE_HISTORY {
            entry.remove(0);
        }
    }

    /// Internal: mark a node as unavailable using either probe or traffic counters.
    ///
    /// Matches Go's `markUnavailableInternal`:
    /// - `force` = true → force-dead immediately
    /// - `is_traffic` = true → use traffic_failure_threshold
    fn mark_unavailable_internal(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        force: bool,
        is_traffic: bool,
    ) {
        let idx = alive_index(domain, ipver);

        // During the grace period (fresh registrations, e.g. right after a
        // restart) neither probe nor traffic failures count toward death:
        // a startup DNS/warm-up hiccup must not mass-mark every node dead
        // and cause a full proxy outage that then needs minutes of revival
        // cycles to recover from. Forced deaths always bypass grace.
        if !force && self.is_in_grace_period(node_id) {
            self.record_probe_history(node_id, idx, false, None);
            return;
        }

        let threshold = if is_traffic {
            traffic_failure_threshold(domain)
        } else {
            probe_failure_threshold(domain)
        };

        let (was_alive, _failures) = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.consecutive_successes = 0;
            if force {
                // Forced death: set counters to threshold to match state.
                e.consecutive_failures = threshold;
                e.traffic_failures = threshold;
                e.alive = false;
            } else if is_traffic {
                e.traffic_failures += 1;
                let f = e.traffic_failures;
                if f >= threshold {
                    e.alive = false;
                }
                // Traffic failures don't advance probe backoff cooldown
            } else {
                e.consecutive_failures += 1;
                let f = e.consecutive_failures;
                let backoff = self
                    .base_cooldown
                    .saturating_mul(2u32.pow(f.min(8)))
                    .min(self.max_cooldown);
                e.cooldown_until = Instant::now() + backoff;
                if f >= MAX_PROBE_BACKOFF_FAILURES {
                    e.stopped = true;
                }
                if f >= threshold {
                    e.alive = false;
                }
            }
            (was, e.consecutive_failures + e.traffic_failures)
        });

        if was_alive && !force {
            let still_alive = self.read_state(node_id, idx).alive;
            if !still_alive {
                self.push_ebpf(node_id, domain, ipver, false);
            }
        }
        let coll = self.get_or_create_collection(node_id, idx);
        if !is_traffic {
            // Only append synthetic TIMEOUT_LATENCY for probe failures,
            // not for traffic-based reporting (which may succeed through
            // other nodes without indicating a true latency change).
            coll.mark_unavailable();
        }

        self.record_probe_history(node_id, idx, false, None);
    }

    fn mark_dead_for(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_unavailable_internal(node_id, domain, ipver, false, false);
    }

    /// Mark a TCP node as dead (public API for proxy dial failure callers).
    pub fn mark_dead(&self, node_id: &str) {
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
    }

    /// Report a node as unavailable due to real traffic failure.
    ///
    /// Uses the per-protocol traffic failure thresholds (TCP=10, UDP Data=50)
    /// so transient glitches don't immediately tear down the node's alive state.
    /// Matches Go's `Dialer.ReportUnavailable`.
    pub fn report_unavailable_traffic(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_unavailable_internal(node_id, domain, ipver, false, true);
    }

    /// Force-mark a node as dead immediately (used on fatal errors).
    /// Matches Go's `Dialer.ReportUnavailableForced`.
    pub fn report_unavailable_forced(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_unavailable_internal(node_id, domain, ipver, true, true);
    }

    /// Report successful traffic through a node, reviving its alive state.
    ///
    /// For DataUDP: a single successful real UDP flow can instantly revive
    /// the data-UDP health domain (Go: `ReportAvailableTraffic`).
    pub fn report_available_traffic(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) {
        let idx = alive_index(domain, ipver);
        let was_alive = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.alive = true;
            e.consecutive_failures = 0;
            e.consecutive_successes = 0;
            e.traffic_failures = 0;
            e.stopped = false;
            was
        });
        if !was_alive {
            self.push_ebpf(node_id, domain, ipver, true);
            tracing::info!(
                "Node '{}' revived via traffic (domain={:?}, ipver={:?})",
                node_id,
                domain,
                ipver
            );
        }
    }

    /// Trigger an emergency TCP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN to protect the worker pool.
    pub fn notify_check_tcp(&self, node_id: &str) {
        let now = Instant::now();
        let mut last = self.last_emergency_tcp.lock();
        if let Some(prev) = last.get(node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id.to_string(), now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Trigger an emergency DNS UDP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN.
    pub fn notify_check_dns_udp(&self, node_id: &str) {
        let now = Instant::now();
        let mut last = self.last_emergency_udp.lock();
        if let Some(prev) = last.get(node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id.to_string(), now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Whether periodic probes are stopped for this node (Go: probeBackoff.stopped).
    /// Emergency probes can still be triggered via `notify_check_*`.
    pub fn is_probe_stopped(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(node_id)
            .map(|s| s[idx].stopped)
            .unwrap_or(false)
    }

    /// Get (or create) the `DialerCollection` for a given node and domain index.
    fn get_or_create_collection(&self, node_id: &str, idx: usize) -> Arc<DialerCollection> {
        let mut cols = self.collections.write();
        let arr = cols.entry(node_id.to_string()).or_insert_with(|| {
            [
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
            ]
        });
        Arc::clone(&arr[idx])
    }

    /// Record a successful probe latency for a node + domain + ip version.
    ///
    /// This is the core method that feeds latency data into the per-node
    /// `Latencies10` ring buffer and `MovingAverage`, which downstream
    /// `GroupManager` can read for selection.
    ///
    /// Applies recovery hysteresis: a dead node needs
    /// `RECOVERY_SUCCESSES_NEEDED` consecutive successes before being
    /// marked alive again. An already-alive node stays alive immediately.
    pub fn record_probe_latency(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        let idx = alive_index(domain, ipver);
        let revived = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            if was {
                // Already alive: straightforward reset.
                e.alive = true;
                e.consecutive_failures = 0;
                e.consecutive_successes = 0;
                e.traffic_failures = 0;
                e.stopped = false;
                e.cooldown_until = Instant::now();
                false
            } else {
                // Was dead: apply recovery hysteresis.
                e.consecutive_successes += 1;
                e.consecutive_failures = 0;
                e.traffic_failures = 0;
                if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                    e.alive = true;
                    e.stopped = false;
                    e.cooldown_until = Instant::now();
                    e.consecutive_successes = 0;
                    true
                } else {
                    tracing::debug!(
                        "Node '{}' recovery progress: {}/{} consecutive successes (domain={:?}, ipver={:?})",
                        node_id,
                        e.consecutive_successes,
                        RECOVERY_SUCCESSES_NEEDED,
                        domain,
                        ipver,
                    );
                    false
                }
            }
        });
        if revived {
            self.push_ebpf(node_id, domain, ipver, true);
        }
        let coll = self.get_or_create_collection(node_id, idx);
        if revived || self.read_state(node_id, idx).alive {
            coll.mark_available(latency);
        }

        self.record_probe_history(node_id, idx, true, Some(latency));
    }

    /// Read the moving average latency for a node-domain pair.
    ///
    /// Used by `GroupManager`'s `MinLatency` / `MinMovingAverage` policies.
    pub fn get_moving_average(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(node_id).map(|arr| &arr[idx])?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Read the last probe latency for a node-domain pair.
    pub fn get_last_latency(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(node_id).map(|arr| &arr[idx])?;
        coll.latencies.last()
    }

    /// Read the most recent REAL (non-synthetic) probe sample and its
    /// measurement time — display semantics for the clash delay history.
    /// Synthetic failure placeholders (10s) are skipped so dashboards never
    /// show them as a measured delay.
    pub fn get_last_real_sample(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<(Duration, std::time::SystemTime)> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(node_id).map(|arr| &arr[idx])?;
        coll.latencies
            .last_real_sample()
            .map(|s| (s.latency, s.at))
    }

    /// Moving average of the recent probe samples for the same
    /// (domain, ipver) state — this is what dae's `min_moving_avg` /
    /// `min_avg10` group policies rank nodes by. Falls back to the latest
    /// sample when there is only one.
    pub fn get_avg_latency(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(node_id).map(|arr| &arr[idx])?;
        coll.latencies.avg().or_else(|| coll.latencies.last())
    }

    /// Delete all latency history for a node (sing-box URLTest "delete
    /// history" semantics on measurement failure). After this call
    /// `get_last_latency` / `get_moving_average` return `None` until the
    /// next successful measurement.
    pub fn clear_latency(&self, node_id: &str) {
        self.collections.write().remove(node_id);
    }

    pub fn register_node(&self, node_id: String, address: String) {
        self.registered.write().insert(node_id.clone(), address);
        self.node_registered_at
            .write()
            .insert(node_id.clone(), Instant::now());
        let mut states = self.states.write();
        states.entry(node_id).or_insert_with(fresh_states);
    }

    /// Snapshot of currently registered nodes (name → address), used by
    /// config reload to diff and re-register only what changed.
    pub fn registered_nodes(&self) -> HashMap<String, String> {
        self.registered.read().clone()
    }

    pub fn remove_node(&self, node_id: &str) {
        self.registered.write().remove(node_id);
        self.states.write().remove(node_id);
        self.node_registered_at.write().remove(node_id);
        self.node_urltest_groups.write().remove(node_id);
        let mut history = self.probe_history.write();
        history.retain(|(id, _), _| id != node_id);
    }

    pub fn trigger_probe(&self, node_id: &str) {
        let _ = self.trigger_tx.send(node_id.to_string());
    }

    pub fn should_probe(&self, node_id: &str, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        let state = self.read_state(node_id, idx);
        // Respect permanent backoff stop (Go: probeBackoff.stopped).
        // Emergency probes bypass this via triggered checks.
        !state.stopped && Instant::now() >= state.cooldown_until
    }

    /// Register a URLTest group for idle-aware probe suspension.
    ///
    /// `members` are node names; callers should exclude members that also
    /// belong to Selector groups (those are probed unconditionally).
    /// `idle_timeout` defaults to [`DEFAULT_URLTEST_IDLE_TIMEOUT`] when
    /// `None`. Re-callable on config reload.
    pub fn register_urltest_group(
        &self,
        group: &str,
        members: &[String],
        idle_timeout: Option<Duration>,
    ) {
        let timeout = idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT);
        self.urltest_group_timeout
            .write()
            .insert(group.to_string(), timeout);
        self.urltest_group_members
            .write()
            .insert(group.to_string(), members.to_vec());
        let mut node_groups = self.node_urltest_groups.write();
        for member in members {
            node_groups
                .entry(member.clone())
                .or_default()
                .push(group.to_string());
        }
    }

    /// Replace the whole URLTest group table (config reload).
    ///
    /// `groups` is `(group name, member node names, idle timeout)` per
    /// URLTest group — the same shape [`register_urltest_group`] takes.
    /// Entries for groups absent from `groups` are dropped, and the
    /// node → groups index is rebuilt from scratch (so stale memberships
    /// and duplicate entries from repeated registration disappear).
    /// `group_last_active` timestamps survive for groups that still exist,
    /// keeping the idle-suspension state across the reload.
    pub fn sync_urltest_groups(&self, groups: &[(String, Vec<String>, Option<Duration>)]) {
        {
            let mut timeouts = self.urltest_group_timeout.write();
            let mut members_map = self.urltest_group_members.write();
            let mut node_groups = self.node_urltest_groups.write();
            timeouts.clear();
            members_map.clear();
            node_groups.clear();
            for (group, members, idle_timeout) in groups {
                timeouts.insert(
                    group.clone(),
                    idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT),
                );
                members_map.insert(group.clone(), members.clone());
                for member in members {
                    node_groups
                        .entry(member.clone())
                        .or_default()
                        .push(group.clone());
                }
            }
        }
        let surviving: HashSet<String> =
            self.urltest_group_timeout.read().keys().cloned().collect();
        self.group_last_active
            .write()
            .retain(|group, _| surviving.contains(group));
    }

    /// Record activity for a group (called from group selection paths).
    ///
    /// When a suspended URLTest group becomes active again, health checks
    /// resume and member probes are kicked off immediately so latency data
    /// is fresh for the next selection.
    pub fn mark_group_active(&self, group: &str) {
        let was_idle = self.is_urltest_group_idle(group);
        self.group_last_active
            .write()
            .insert(group.to_string(), Instant::now());
        if was_idle {
            let members = self
                .urltest_group_members
                .read()
                .get(group)
                .cloned()
                .unwrap_or_default();
            if !members.is_empty() {
                tracing::info!(
                    "URLTest group '{}' active again — resuming member probes",
                    group
                );
                for member in members {
                    self.trigger_probe(&member);
                }
            }
        }
    }

    /// Whether a registered URLTest group has been inactive for longer than
    /// its idle timeout. A never-active group counts as idle (lazy start:
    /// no probes run before the first selection). Unregistered groups are
    /// never idle.
    pub fn is_urltest_group_idle(&self, group: &str) -> bool {
        let timeout = match self.urltest_group_timeout.read().get(group) {
            Some(t) => *t,
            None => return false,
        };
        self.group_last_active
            .read()
            .get(group)
            .map(|t| t.elapsed() >= timeout)
            .unwrap_or(true)
    }

    /// Whether periodic probing of this node is suspended because every
    /// URLTest group it belongs to is idle. Nodes outside URLTest groups
    /// are never suspended.
    pub fn is_probe_suspended(&self, node_id: &str) -> bool {
        let groups = self.node_urltest_groups.read();
        match groups.get(node_id) {
            Some(gs) if !gs.is_empty() => gs.iter().all(|g| self.is_urltest_group_idle(g)),
            _ => false,
        }
    }

    /// Number of consecutive TCP failures for this node.
    /// Used by `GroupManager` to add a backoff penalty to latency-based
    /// selection, deprioritising recently-flapping nodes.
    pub fn consecutive_failures(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> u32 {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(node_id)
            .map(|s| s[idx].consecutive_failures)
            .unwrap_or(0)
    }

    /// Extract hostname from a URL string like "http://cp.cloudflare.com".
    ///
    /// The dae config format allows comma-separated fallback IPs after the
    /// URL (`http://host,ip4,ip6`, Go: `TcpCheckOptionRaw.Raw`); only the
    /// first segment is the URL.
    fn parse_url_host(url: &str) -> Option<String> {
        let s = url.trim();
        // The scheme is optional: dae check URLs are usually written with
        // one, but bare `host/path` forms also appear.
        let s = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
            .unwrap_or(s);
        // dae comma-separated fallback list: first segment is the URL.
        let s = s.split(',').next().unwrap_or(s).trim();
        // Drop any path/query/fragment — only the authority is resolved.
        // (Previously only a single trailing '/' was stripped, so a URL like
        // `http://www.google-analytics.com/generate_204` was looked up as the
        // hostname "www.google-analytics.com/generate_204" and DNS failed.)
        let s = s.split(['/', '?', '#']).next().unwrap_or(s);
        // Strip the port, keeping bracketed IPv6 literals intact.
        let host = if let Some(rest) = s.strip_prefix('[') {
            rest.split(']').next().unwrap_or(s)
        } else {
            s.split(':').next().unwrap_or(s)
        };
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }

    /// Extract the comma-separated literal fallback IPs from a dae-format
    /// check URL (`http://host,ip4,ip6`) as port-80 socket addresses.
    /// Go: the non-URL entries of `TcpCheckOptionRaw.Raw`.
    fn parse_check_literals(check_url: &str) -> Vec<SocketAddr> {
        check_url
            .split(',')
            .skip(1)
            .filter_map(|seg| {
                let ip = seg.trim().parse::<std::net::IpAddr>().ok();
                if ip.is_none() && !seg.trim().is_empty() {
                    tracing::debug!(
                        "ignoring unparseable check URL fallback segment '{}'",
                        seg.trim()
                    );
                }
                ip.map(|ip| SocketAddr::new(ip, 80))
            })
            .collect()
    }

    /// Merge resolved and literal check-target addresses, deduplicated.
    fn merge_check_addrs(resolved: Vec<SocketAddr>, check_url: &str) -> Vec<SocketAddr> {
        let mut ips = resolved;
        ips.extend(Self::parse_check_literals(check_url));
        ips.sort();
        ips.dedup();
        ips
    }
}

impl Default for AliveDialerSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StickyTarget {
    pub addr: String,
    pub protocol: String,
}

pub struct StickyCache {
    cache: Mutex<HashMap<String, (StickyTarget, Instant)>>,
    ttl: Duration,
}

impl StickyCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl,
        }
    }
    pub fn get_sticky(&self, id: &str) -> Option<StickyTarget> {
        self.cache
            .lock()
            .get(id)
            .filter(|(_, exp)| Instant::now() < *exp)
            .map(|(t, _)| t.clone())
    }
    pub fn set_sticky(&self, id: String, target: StickyTarget) {
        self.cache
            .lock()
            .insert(id, (target, Instant::now() + self.ttl));
    }
    pub fn remove_sticky(&self, id: &str) {
        self.cache.lock().remove(id);
    }
    pub fn prune_expired(&self) -> usize {
        let mut c = self.cache.lock();
        let n = c.len();
        c.retain(|_, (_, e)| Instant::now() < *e);
        n - c.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Healthy,
    Degraded,
    Failed,
    Recovering,
}

impl RecoveryEntry {
    fn new() -> Self {
        Self {
            state: NodeState::Healthy,
            consecutive_failures: 0,
            cooldown_until: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct RecoveryEntry {
    state: NodeState,
    consecutive_failures: u32,
    cooldown_until: Instant,
}

pub struct RecoveryState {
    entries: Mutex<HashMap<String, [RecoveryEntry; ProbeDomain::count()]>>,
    failure_threshold: u32,
    base_cooldown: Duration,
    max_cooldown: Duration,
}

impl RecoveryState {
    pub fn new(failure_threshold: u32, base_cooldown: Duration, max_cooldown: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            failure_threshold,
            base_cooldown,
            max_cooldown,
        }
    }

    fn with_entry<F, R>(&self, node: &str, domain: ProbeDomain, f: F) -> R
    where
        F: FnOnce(&mut RecoveryEntry) -> R,
    {
        let mut entries = self.entries.lock();
        let arr = entries.entry(node.into()).or_insert_with(|| {
            [
                RecoveryEntry::new(),
                RecoveryEntry::new(),
                RecoveryEntry::new(),
            ]
        });
        f(&mut arr[domain as usize])
    }

    fn read_entry(&self, node: &str, domain: ProbeDomain) -> RecoveryEntry {
        self.entries
            .lock()
            .get(node)
            .map(|e| e[domain as usize].clone())
            .unwrap_or_else(RecoveryEntry::new)
    }

    pub fn should_probe(&self, node: &str, domain: ProbeDomain) -> bool {
        Instant::now() >= self.read_entry(node, domain).cooldown_until
    }

    pub fn report_success(&self, node: &str, domain: ProbeDomain) {
        self.with_entry(node, domain, |e| {
            e.consecutive_failures = 0;
            e.state = NodeState::Healthy;
            e.cooldown_until = Instant::now();
        });
    }

    pub fn report_failure(&self, node: &str, domain: ProbeDomain) -> NodeState {
        self.with_entry(node, domain, |e| {
            e.consecutive_failures += 1;
            let backoff = self
                .base_cooldown
                .saturating_mul(2u32.pow(e.consecutive_failures.min(8)))
                .min(self.max_cooldown);
            e.cooldown_until = Instant::now() + backoff;
            e.state = if e.consecutive_failures >= self.failure_threshold {
                NodeState::Failed
            } else {
                NodeState::Degraded
            };
            e.state
        })
    }

    pub fn get_state(&self, node: &str, domain: ProbeDomain) -> NodeState {
        self.read_entry(node, domain).state
    }

    pub fn is_usable(&self, node: &str, domain: ProbeDomain) -> bool {
        matches!(
            self.get_state(node, domain),
            NodeState::Healthy | NodeState::Degraded
        )
    }
}
