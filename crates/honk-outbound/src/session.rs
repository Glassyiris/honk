//! Unified session pool for multiplexed outbounds (AnyTLS;
//! QUIC protocols keep their own single-connection holder —
//! see `quic::QuicClient`).
//!
//! What this centralizes (previously re-implemented, slightly
//! differently, per protocol):
//!
//! - one pool per key (per-node constant in the runtime-registry world),
//!   with a hard session cap;
//! - least-loaded scheduling over `Active` sessions (Draining ones take
//!   no new channels);
//! - **pool-owned dial single-flight**: the first caller to find no
//!   in-flight dial registers it and the pool spawns the dial task — a
//!   cancelled caller only ends its own wait, never the shared dial
//!   (outcomes broadcast to every waiter);
//! - caller-owned speculative checkout: atomically reserve an existing stream
//!   permit or a provisional, cap-counted physical-dial slot that cancellation
//!   drops and only an explicit winner commit may publish;
//! - dial circuit breaker: consecutive establishment failures back off
//!   exponentially before the pool dials again (a dead server must not
//!   eat a TCP connect per proxied flow);
//! - RAII stream-slot permits (`SessionPermit`) as the single capacity
//!   truth, and [`SessionPool::open_with`] for atomic reserve+open;
//! - idle reaping, jittered max-age drains and optional prewarm
//!   (`min_idle`) via one janitor per key;
//! - generation retirement that rejects new work while live stream permits
//!   drain, distinct from process shutdown's immediate force-close;
//! - a metrics snapshot (sessions, streams, dial failures) per key.
//!
//! What stays protocol-owned: session establishment, stream open,
//! framing, heartbeats. The pool only knows [`ManagedSession`].

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::Instant;

use anyhow::anyhow;
use futures_util::FutureExt;
use parking_lot::Mutex;

/// Pool sizing and lifecycle policy.
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Hard cap on live sessions per key (including the in-flight dial).
    pub max_sessions: usize,
    /// Soft per-session stream cap: sessions at or above it are skipped
    /// by the scheduler (a new session is dialed instead).
    pub max_streams_per_session: usize,
    /// Janitor tick (prune + prewarm cadence).
    pub janitor_interval: Duration,
    /// First dial-failure backoff; doubles per consecutive failure up to
    /// [`Self::max_dial_backoff`].
    pub dial_backoff: Duration,
    /// Cap for the dial-failure backoff.
    pub max_dial_backoff: Duration,
    /// Max session age before it drains (no new streams; existing ones
    /// finish). Jittered ±10% per session to avoid reconnect storms.
    /// `None` = sessions never age out.
    pub max_session_age: Option<Duration>,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            max_streams_per_session: 8,
            janitor_interval: Duration::from_secs(30),
            dial_backoff: Duration::from_secs(1),
            max_dial_backoff: Duration::from_secs(30),
            max_session_age: None,
        }
    }
}

/// Lifecycle of an established session. `Connecting` is not here — it
/// lives in the pool's inflight dial; writer/demux failures go straight
/// to `Closed`; GOAWAY/max-age go through `Draining` (no new permits,
/// existing channels finish).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Draining,
    Closed,
}

/// RAII stream-slot reservation on one session — the single capacity
/// truth. Released on Drop (stream end, failed open, caller cancel).
pub struct SessionPermit<S> {
    session: Arc<S>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<S> SessionPermit<S> {
    pub fn new(session: Arc<S>, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            session,
            _permit: permit,
        }
    }

    /// The session this permit reserves capacity on.
    // Used by the typed-event/writer work (3B).
    #[allow(dead_code)]
    pub fn session(&self) -> &Arc<S> {
        &self.session
    }
}

impl<S> std::fmt::Debug for SessionPermit<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPermit").finish_non_exhaustive()
    }
}

/// What the pool needs to know about a session; everything else stays
/// with the protocol.
pub trait ManagedSession: Send + Sync {
    /// Currently open streams on this session.
    fn active_streams(&self) -> usize;
    /// Closed/broken sessions are pruned and never offered again.
    fn is_closed(&self) -> bool;
    /// Close the session (idle reap, pool shutdown).
    fn close(&self);
    /// Session state; `Draining` takes no new permits. Default derives
    /// from `is_closed` (legacy sessions without a real machine).
    fn state(&self) -> SessionState {
        if self.is_closed() {
            SessionState::Closed
        } else {
            SessionState::Active
        }
    }
    /// When the session was established (max-age drains; default `now`
    /// means "never ages out" for legacy sessions).
    fn created_at(&self) -> Instant {
        Instant::now()
    }
    /// Stop accepting new logical channels (GOAWAY, max-age); existing
    /// ones run to the end and the session closes at zero.
    fn begin_drain(&self) {}
    /// Atomically reserve one stream slot: check `Active` → acquire →
    /// re-check `Active` (a session that began draining in between
    /// releases the permit immediately and reports `None`). Default `None`
    /// means "no capacity tracking" (legacy protocols not yet on
    /// [`SessionPool::open_with`]).
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>>
    where
        Self: Sized,
    {
        let _ = self;
        None
    }
}

/// Pool lifecycle. Retirement rejects new work while existing sessions drain;
/// shutdown force-closes everything. Both terminal paths wake waiters and stop
/// pool-owned dials and janitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolState {
    Running,
    Draining,
    ShuttingDown,
    Closed,
}

impl From<usize> for PoolState {
    fn from(v: usize) -> Self {
        match v {
            0 => PoolState::Running,
            1 => PoolState::Draining,
            2 => PoolState::ShuttingDown,
            _ => PoolState::Closed,
        }
    }
}

/// Signal broadcast when a pool-owned dial completes.
#[derive(Clone)]
enum DialSignal {
    /// Dial still in flight.
    Pending,
    /// The pool became terminal before the owned dial could publish.
    Closed,
    /// Dial completed — re-check the pool (session inserted or backoff
    /// recorded).
    Done,
    /// Dial failed — waiters surface the error themselves.
    Failed(Arc<anyhow::Error>),
}

/// How a protocol open failed, for the pool's retry decision.
pub enum OpenError {
    /// The session died mid-open: retire it; the pool may retry once on
    /// a fresh session (SYN/first frame was not committed yet — retrying
    /// cannot duplicate a request).
    Session(anyhow::Error),
    /// The target/protocol refused or auth failed: the session is
    /// healthy — surface immediately, never retry.
    Refused(anyhow::Error),
}

impl OpenError {
    // Used by the typed-event mapping (3B).
    #[allow(dead_code)]
    pub fn into_inner(self) -> anyhow::Error {
        match self {
            OpenError::Session(e) | OpenError::Refused(e) => e,
        }
    }
}

/// A speculative checkout atomically either reserves one stream on an
/// existing pooled session or owns one bounded, caller-cancellable dial slot.
pub enum SpeculativeCheckout<S: ManagedSession + 'static> {
    Shared {
        session: Arc<S>,
        permit: SessionPermit<S>,
    },
    Detached(DetachedSessionReservation<S>),
}

impl<S: ManagedSession + 'static> std::fmt::Debug for SpeculativeCheckout<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared { .. } => f.debug_tuple("SpeculativeCheckout::Shared").finish(),
            Self::Detached(_) => f.debug_tuple("SpeculativeCheckout::Detached").finish(),
        }
    }
}

/// Caller-owned capacity reservation for one speculative physical dial.
/// Dropping it removes only its generation-safe slot and closes an attached
/// detached session, so cancellation cannot populate the pool.
pub struct DetachedSessionReservation<S: ManagedSession + 'static> {
    pool: Arc<SessionPool<S>>,
    key: String,
    slot_id: u64,
    active: bool,
}

impl<S: ManagedSession + 'static> std::fmt::Debug for DetachedSessionReservation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSessionReservation")
            .field("key", &self.key)
            .field("slot_id", &self.slot_id)
            .finish_non_exhaustive()
    }
}

/// Per-key pool state.
struct KeyPool<S> {
    sessions: Vec<Arc<S>>,
    /// Caller-owned speculative dial slots. The `Option` is filled after a
    /// detached dial succeeds so shutdown and Drop can synchronously close
    /// that otherwise-unpooled session.
    provisional: HashMap<u64, Option<Arc<S>>>,
    /// Next provisional slot generation.
    next_provisional_id: u64,
    /// While a dial is in flight this is `Some((inflight_id, sender))`;
    /// waiters `wait_for(!Pending)` on a receiver cloned under the lock
    /// (race-free — `watch::Receiver::wait_for` evaluates the predicate
    /// against the current value before parking). The inflight id lets a
    /// [`DialGuard`] clear only its own dial.
    dial_done: Option<(u64, tokio::sync::watch::Sender<DialSignal>)>,
    /// Next inflight-dial id.
    next_inflight_id: u64,
    /// Consecutive dial failures and when the next dial is allowed.
    dial_failures: u32,
    next_dial_at: Option<Instant>,
    /// Whether the janitor task for this key is running.
    janitor_running: bool,
}

impl<S> Default for KeyPool<S> {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            provisional: HashMap::new(),
            next_provisional_id: 0,
            dial_done: None,
            next_inflight_id: 0,
            dial_failures: 0,
            next_dial_at: None,
            janitor_running: false,
        }
    }
}

/// RAII cleanup for the dial leader: if the leader's future is dropped
/// (caller cancellation or unwind) before completion, the inflight entry
/// is cleared — but only when it still matches this guard's id, so a
/// stale guard can never clear a later dial. Clearing drops the watch
/// sender, which closes the channel: waiters' `wait_for` errors and the
/// next caller re-elects a leader. A cancelled caller never touches the
/// failure count or backoff.
struct DialGuard<S> {
    keys: Arc<Mutex<HashMap<String, KeyPool<S>>>>,
    key: String,
    inflight_id: u64,
    armed: bool,
}

impl<S> Drop for DialGuard<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut keys = self.keys.lock();
        if let Some(pool) = keys.get_mut(&self.key)
            && pool.dial_done.as_ref().map(|(id, _)| *id) == Some(self.inflight_id)
        {
            pool.dial_done = None;
        }
    }
}

/// Aggregate pool metrics (clash-API / diagnostics snapshot).
#[derive(Debug, Clone, Default)]
// Used by the clash API once pools are wired into it.
#[allow(dead_code)]
pub struct PoolMetrics {
    pub keys: usize,
    pub sessions: usize,
    pub active_streams: usize,
    pub dial_failures: u64,
}

/// Generic session pool. Cheap to clone (shares the inner state); one
/// instance per protocol replaces its bespoke static manager.
pub struct SessionPool<S: ManagedSession + 'static> {
    config: SessionPoolConfig,
    keys: Arc<Mutex<HashMap<String, KeyPool<S>>>>,
    dial_failures_total: Arc<AtomicUsize>,
    state: Arc<AtomicUsize>,
    shutdown_tx: Arc<tokio::sync::watch::Sender<bool>>,
}

impl<S: ManagedSession + 'static> std::fmt::Debug for SessionPool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPool")
            .field("state", &self.state())
            .field("keys", &self.keys.lock().len())
            .finish_non_exhaustive()
    }
}

impl<S: ManagedSession + 'static> Clone for SessionPool<S> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            keys: Arc::clone(&self.keys),
            dial_failures_total: Arc::clone(&self.dial_failures_total),
            state: Arc::clone(&self.state),
            shutdown_tx: Arc::clone(&self.shutdown_tx),
        }
    }
}

impl<S: ManagedSession + 'static> SessionPool<S> {
    pub fn new(config: SessionPoolConfig) -> Self {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Self {
            config,
            keys: Arc::new(Mutex::new(HashMap::new())),
            dial_failures_total: Arc::new(AtomicUsize::new(0)),
            state: Arc::new(AtomicUsize::new(PoolState::Running as usize)),
            shutdown_tx: Arc::new(shutdown_tx),
        }
    }

    fn state(&self) -> PoolState {
        PoolState::from(self.state.load(Ordering::Acquire))
    }

    #[cfg(test)]
    pub(crate) fn is_retired(&self) -> bool {
        self.state() != PoolState::Running
    }

    fn pool_closed_err() -> anyhow::Error {
        anyhow!("session pool is closed")
    }

    /// Whether this key has a currently usable session. This uses the same
    /// active/capacity predicate as `offer`, without registering a dial.
    pub fn has_usable_session(&self, key: &str) -> bool {
        if self.state() != PoolState::Running {
            return false;
        }
        let mut keys = self.keys.lock();
        if self.state() != PoolState::Running {
            return false;
        }
        let Some(pool) = keys.get_mut(key) else {
            return false;
        };
        pool.sessions.retain(|session| !session.is_closed());
        pool.sessions.iter().any(|session| {
            session.state() == SessionState::Active
                && session.active_streams() < self.config.max_streams_per_session
        })
    }

    /// Live (not closed) session count for `key` — the warm-resource gauge
    /// behind `/stats`.
    pub fn live_session_count(&self, key: &str) -> usize {
        let mut keys = self.keys.lock();
        let Some(pool) = keys.get_mut(key) else {
            return 0;
        };
        pool.sessions.retain(|session| !session.is_closed());
        pool.sessions.len()
    }

    /// Offer the least-loaded live session, dialing one when none is
    /// usable. Concurrent dials for the same key share one establishment:
    /// the FIRST caller to find no inflight registers the dial and the
    /// pool spawns it as an owned task — cancelling any caller only ends
    /// its own wait, never the shared dial. Dial failures broadcast to
    /// every waiter; repeated failures back off per key.
    pub async fn offer<F, Fut>(&self, key: &str, dial: F) -> anyhow::Result<Arc<S>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        let mut dial = Some(dial);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            if self.state() != PoolState::Running {
                return Err(Self::pool_closed_err());
            }
            // Phase 1: pick a live session, register the dial, or park on
            // the in-flight one.
            enum Step<S> {
                Closed,
                Have(Arc<S>),
                Register(u64, tokio::sync::watch::Sender<DialSignal>),
                Wait(tokio::sync::watch::Receiver<DialSignal>),
                Backoff(Duration),
            }
            let step = {
                let mut keys = self.keys.lock();
                if self.state() != PoolState::Running {
                    Step::Closed
                } else {
                    let pool = keys.entry(key.to_string()).or_default();
                    pool.sessions.retain(|s| !s.is_closed());
                    if let Some(s) = pool
                        .sessions
                        .iter()
                        // Draining sessions take no new channels.
                        .filter(|s| {
                            s.state() == SessionState::Active
                                && s.active_streams() < self.config.max_streams_per_session
                        })
                        .min_by_key(|s| s.active_streams())
                    {
                        Step::Have(Arc::clone(s))
                    } else if let Some((_, done)) = &pool.dial_done {
                        Step::Wait(done.subscribe())
                    } else if let Some(wait) = pool
                        .next_dial_at
                        .and_then(|t| t.checked_duration_since(Instant::now()))
                        .filter(|w| *w > Duration::ZERO)
                    {
                        Step::Backoff(wait)
                    } else if pool.sessions.len() + pool.provisional.len()
                        >= self.config.max_sessions
                    {
                        // At the hard cap with every session saturated (including
                        // caller-owned speculative slots): wait
                        // for capacity to free up (a stream closes, a session
                        // is reaped) instead of stampeding past the cap.
                        Step::Backoff(self.config.janitor_interval.min(Duration::from_secs(5)))
                    } else {
                        let id = pool.next_inflight_id;
                        pool.next_inflight_id += 1;
                        let (tx, _) = tokio::sync::watch::channel(DialSignal::Pending);
                        pool.dial_done = Some((id, tx.clone()));
                        Step::Register(id, tx)
                    }
                }
            };

            match step {
                Step::Closed => return Err(Self::pool_closed_err()),
                Step::Have(s) => return Ok(s),
                Step::Backoff(wait) => {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                }
                Step::Wait(mut rx) => {
                    let signal = tokio::select! {
                        // `wait_for` checks the current value first — no
                        // race with a dial that completed before parking.
                        r = rx.wait_for(|s| !matches!(s, DialSignal::Pending)) => {
                            match r {
                                Ok(v) => v.clone(),
                                // Sender dropped (leader cancelled): the
                                // inflight entry is gone — re-elect.
                                Err(_) => DialSignal::Done,
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    };
                    match signal {
                        DialSignal::Closed => return Err(Self::pool_closed_err()),
                        DialSignal::Failed(e) => {
                            return Err(anyhow::anyhow!(e).context("session dial failed"));
                        }
                        DialSignal::Pending | DialSignal::Done => {}
                    }
                }
                Step::Register(id, done) => {
                    // Pool-owned dial task: no caller's cancellation can
                    // poison it; the DialGuard is the panic backstop.
                    let Some(dial_fut) = dial.take().map(|d| d()) else {
                        // A previous Register in this very call consumed
                        // the closure, and the freshly dialed session was
                        // dead on arrival (pruned before it could be
                        // offered) — fail instead of panic/re-dialing.
                        return Err(anyhow!("session established but immediately unusable"));
                    };
                    let task_keys = Arc::clone(&self.keys);
                    let task_key = key.to_string();
                    let failures_total = Arc::clone(&self.dial_failures_total);
                    let task_state = Arc::clone(&self.state);
                    let config = self.config.clone();
                    let mut task_shutdown_rx = self.shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        let mut guard = DialGuard {
                            keys: Arc::clone(&task_keys),
                            key: task_key.clone(),
                            inflight_id: id,
                            armed: true,
                        };
                        let result = tokio::select! {
                            result = std::panic::AssertUnwindSafe(dial_fut).catch_unwind() => Some(result),
                            _ = task_shutdown_rx.changed() => None,
                        };
                        let signal = {
                            let mut keys = task_keys.lock();
                            if PoolState::from(task_state.load(Ordering::Acquire))
                                != PoolState::Running
                            {
                                if let Some(Ok(Ok(session))) = &result {
                                    // A completion that lost the terminal race is never
                                    // published: protocol-owned tasks may retain its Arc.
                                    session.close();
                                }
                                if let Some(pool) = keys.get_mut(&task_key)
                                    && pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id)
                                {
                                    pool.dial_done = None;
                                }
                                guard.armed = false;
                                DialSignal::Closed
                            } else {
                                let pool = keys.entry(task_key.clone()).or_default();
                                if pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id) {
                                    pool.dial_done = None;
                                }
                                guard.armed = false;
                                match result.expect("running pool cannot receive shutdown") {
                                    Ok(Ok(session)) => {
                                        pool.dial_failures = 0;
                                        pool.next_dial_at = None;
                                        pool.sessions.push(session);
                                        DialSignal::Done
                                    }
                                    Ok(Err(e)) => {
                                        failures_total.fetch_add(1, Ordering::Relaxed);
                                        pool.dial_failures += 1;
                                        let shift = pool.dial_failures.min(8) - 1;
                                        let backoff =
                                            (config.dial_backoff.saturating_mul(1u32 << shift))
                                                .min(config.max_dial_backoff);
                                        pool.next_dial_at = Some(Instant::now() + backoff);
                                        DialSignal::Failed(Arc::new(e.context(anyhow!(
                                            "session dial failed ({} consecutive, backoff {:?})",
                                            pool.dial_failures,
                                            backoff
                                        ))))
                                    }
                                    Err(_panic) => {
                                        failures_total.fetch_add(1, Ordering::Relaxed);
                                        pool.dial_failures += 1;
                                        pool.next_dial_at =
                                            Some(Instant::now() + config.dial_backoff);
                                        DialSignal::Failed(Arc::new(anyhow!(
                                            "session dial panicked (backoff {:?})",
                                            config.dial_backoff
                                        )))
                                    }
                                }
                            }
                        };
                        let _ = done.send(signal);
                    });
                    // Fall through: wait on the dial like everyone else.
                }
            }
        }
    }

    /// Atomically reserve an existing stream slot, or reserve capacity for
    /// one caller-owned speculative physical dial. Unlike [`Self::offer`], a
    /// detached dial is never spawned by the pool: aborting its caller drops
    /// the reservation and therefore the dial/session with it.
    pub async fn checkout_speculative(
        self: &Arc<Self>,
        key: &str,
    ) -> anyhow::Result<SpeculativeCheckout<S>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            enum Step<S: ManagedSession + 'static> {
                Closed,
                Shared(Arc<S>, SessionPermit<S>),
                Wait(tokio::sync::watch::Receiver<DialSignal>),
                Backoff(Duration),
                Detached(u64),
            }
            let step = {
                let mut keys = self.keys.lock();
                if self.state() != PoolState::Running {
                    Step::Closed
                } else {
                    let pool = keys.entry(key.to_string()).or_default();
                    pool.sessions.retain(|session| !session.is_closed());
                    if let Some((session, permit)) = pool.sessions.iter().find_map(|session| {
                        if session.state() != SessionState::Active {
                            return None;
                        }
                        let session = Arc::clone(session);
                        session.try_reserve().map(|permit| (session, permit))
                    }) {
                        Step::Shared(session, permit)
                    } else if let Some((_, done)) = &pool.dial_done {
                        // A normal offer already owns capacity for this dial;
                        // wait rather than oversubscribe the hard cap.
                        Step::Wait(done.subscribe())
                    } else if let Some(wait) = pool
                        .next_dial_at
                        .and_then(|at| at.checked_duration_since(Instant::now()))
                        .filter(|wait| *wait > Duration::ZERO)
                    {
                        Step::Backoff(wait)
                    } else if pool.sessions.len()
                        + pool.provisional.len()
                        + usize::from(pool.dial_done.is_some())
                        >= self.config.max_sessions
                    {
                        Step::Backoff(self.config.janitor_interval.min(Duration::from_secs(5)))
                    } else {
                        let slot_id = pool.next_provisional_id;
                        pool.next_provisional_id += 1;
                        pool.provisional.insert(slot_id, None);
                        Step::Detached(slot_id)
                    }
                }
            };

            match step {
                Step::Closed => return Err(Self::pool_closed_err()),
                Step::Shared(session, permit) => {
                    return Ok(SpeculativeCheckout::Shared { session, permit });
                }
                Step::Detached(slot_id) => {
                    return Ok(SpeculativeCheckout::Detached(DetachedSessionReservation {
                        pool: Arc::clone(self),
                        key: key.to_string(),
                        slot_id,
                        active: true,
                    }));
                }
                Step::Backoff(wait) => {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shutdown_rx.changed() => return Err(Self::pool_closed_err()),
                    }
                }
                Step::Wait(mut rx) => {
                    let signal = tokio::select! {
                        result = rx.wait_for(|signal| !matches!(signal, DialSignal::Pending)) => {
                            match result {
                                Ok(signal) => signal.clone(),
                                // A cancelled/panicked normal dial released its
                                // guard; re-check and reserve our own slot.
                                Err(_) => DialSignal::Done,
                            }
                        }
                        _ = shutdown_rx.changed() => return Err(Self::pool_closed_err()),
                    };
                    match signal {
                        DialSignal::Closed => return Err(Self::pool_closed_err()),
                        DialSignal::Failed(error) => {
                            return Err(anyhow::anyhow!(error).context("session dial failed"));
                        }
                        DialSignal::Pending | DialSignal::Done => {}
                    }
                }
            }
        }
    }

    /// Drop a session from the pool and close it.
    pub fn invalidate(&self, key: &str, session: &Arc<S>) {
        session.close();
        let mut keys = self.keys.lock();
        if let Some(pool) = keys.get_mut(key) {
            pool.sessions.retain(|s| !Arc::ptr_eq(s, session));
        }
    }

    /// Open a logical channel on a pooled session: atomically reserve a
    /// stream slot on an Active session, then run the protocol open.
    /// Reserve and open never race the session cap — the permit is taken
    /// before the open starts. A session that dies mid-open is retired
    /// and the open retried once on a fresh session; protocol refusals
    /// and auth errors ([`OpenError::Refused`]) are returned as-is.
    pub async fn open_with<T, D, DFut, O, OFut>(
        &self,
        key: &str,
        dial: D,
        open: O,
    ) -> anyhow::Result<T>
    where
        D: FnOnce() -> DFut + Clone + Send + 'static,
        DFut: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
        O: Fn(Arc<S>, SessionPermit<S>) -> OFut,
        OFut: std::future::Future<Output = Result<T, OpenError>>,
    {
        let mut last_err: Option<anyhow::Error> = None;
        for _attempt in 0..2 {
            let session = self.offer(key, dial.clone()).await?;
            let Some(permit) = session.try_reserve() else {
                if session.state() != SessionState::Active {
                    // Draining/closed between offer and reserve: prune and
                    // retry — the pool dials a fresh session.
                    self.invalidate(key, &session);
                }
                // Saturated between offer and reserve: the session stays —
                // it is healthy and its streams are alive, killing it
                // would nuke up to a full session of live traffic (the
                // "full-capacity false kill"). Retry instead: offer picks
                // another session, dials a new one, or backs off at the cap.
                last_err = Some(anyhow!("session has no stream capacity"));
                continue;
            };
            match open(Arc::clone(&session), permit).await {
                Ok(t) => return Ok(t),
                Err(OpenError::Refused(e)) => return Err(e),
                Err(OpenError::Session(e)) => {
                    self.invalidate(key, &session);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("open_with attempts always record an error"))
    }

    /// Insert an externally-established session (e.g. one built on a
    /// pooled TCP stream). The session is always tracked — even over the
    /// hard cap: an untracked session is orphaned from the janitor while
    /// its demux task holds it (and its TCP connection) open forever.
    /// Over-cap entries are transient; the janitor reaps them when idle.
    /// After shutdown the session is closed instead of inserted.
    #[allow(dead_code)] // test pools insert externally-established sessions
    pub fn insert(&self, key: &str, session: &Arc<S>) {
        if self.state() != PoolState::Running {
            session.close();
            return;
        }
        let mut keys = self.keys.lock();
        // Re-check under the registration lock: shutdown marks terminal
        // before draining this map, so a late dial cannot repopulate it.
        if self.state() != PoolState::Running {
            drop(keys);
            session.close();
            return;
        }
        let pool = keys.entry(key.to_string()).or_default();
        pool.sessions.retain(|s| !s.is_closed());
        pool.sessions.push(Arc::clone(session));
    }

    /// Current metrics snapshot across all keys.
    // Used by the clash API once pools are wired into it.
    #[allow(dead_code)]
    pub fn metrics(&self) -> PoolMetrics {
        let keys = self.keys.lock();
        PoolMetrics {
            keys: keys.len(),
            sessions: keys.values().map(|p| p.sessions.len()).sum(),
            active_streams: keys
                .values()
                .flat_map(|p| p.sessions.iter())
                .map(|s| s.active_streams())
                .sum(),
            dial_failures: self.dial_failures_total.load(Ordering::Relaxed) as u64,
        }
    }

    async fn run_janitor<F, Fut>(
        self: Arc<Self>,
        key: String,
        min_idle: usize,
        idle_timeout: Duration,
        prewarm: F,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        if *shutdown_rx.borrow() || self.state() != PoolState::Running {
            return;
        }
        let mut interval = tokio::time::interval(self.config.janitor_interval);
        interval.tick().await;
        // Per-session zero-stream streak start, keyed by Arc identity
        // (positions in the vec shift as sessions come and go).
        let mut idle_since: HashMap<usize, Instant> = HashMap::new();
        // Per-session max-age deadline (jittered ±10% by pointer so a
        // fleet of same-age sessions never reconnects in lockstep).
        let mut drain_at: HashMap<usize, Instant> = HashMap::new();
        loop {
            tokio::select! {
                biased;
                // Pool shutdown: exit, no further prewarm/reap.
                _ = shutdown_rx.changed() => return,
                _ = interval.tick() => {}
            }
            let now = Instant::now();
            let idle_to_close = {
                let mut keys = self.keys.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                let Some(kp) = keys.get_mut(&key) else {
                    return;
                };
                kp.sessions.retain(|s| !s.is_closed());
                let live: Vec<Arc<S>> = kp.sessions.clone();
                let mut to_close = Vec::new();
                idle_since.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                drain_at.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                for s in &live {
                    let ptr = Arc::as_ptr(s) as usize;
                    // Max-age drain: stop taking new streams past the
                    // jittered deadline; close once fully drained.
                    if let Some(max_age) = self.config.max_session_age {
                        let deadline = drain_at.entry(ptr).or_insert_with(|| {
                            let jitter = 0.9 + ((ptr % 200) as f64) / 1000.0;
                            s.created_at() + max_age.mul_f64(jitter)
                        });
                        if now >= *deadline {
                            s.begin_drain();
                        }
                    }
                    if s.state() == SessionState::Draining && s.active_streams() == 0 {
                        to_close.push(Arc::clone(s));
                        continue;
                    }
                    if s.active_streams() > 0 {
                        idle_since.remove(&ptr);
                        continue;
                    }
                    let since = idle_since.entry(ptr).or_insert(now);
                    if now.duration_since(*since) >= idle_timeout
                        && live.len() - to_close.len() > min_idle
                    {
                        to_close.push(Arc::clone(s));
                    }
                }
                to_close
            };
            for s in &idle_to_close {
                self.invalidate(&key, s);
            }
            // Prewarm to min_idle only while the registered key is live.
            let current = {
                let keys = self.keys.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                let Some(pool) = keys.get(&key) else {
                    return;
                };
                pool.sessions.len()
            };
            if current < min_idle
                && let Ok(s) = self
                    .offer(&key, {
                        let prewarm = prewarm.clone();
                        move || prewarm()
                    })
                    .await
            {
                drop(s);
            }
        }
    }

    /// Start the per-key janitor (prune closed/expired, prewarm to
    /// `min_idle`) once; subsequent calls are no-ops. `prewarm` dials a
    /// fresh session and is only called when below `min_idle`.
    /// `min_idle`/`idle_timeout` are per-key (node-level policies, e.g.
    /// AnyTLS's node fields).
    #[allow(dead_code)]
    pub fn ensure_janitor<F, Fut>(
        self: &Arc<Self>,
        key: &str,
        min_idle: usize,
        idle_timeout: Duration,
        prewarm: F,
    ) where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        if self.state() != PoolState::Running {
            return;
        }
        {
            let mut keys = self.keys.lock();
            if self.state() != PoolState::Running {
                return;
            }
            let pool = keys.entry(key.to_string()).or_default();
            if pool.janitor_running {
                return;
            }
            pool.janitor_running = true;
        }
        let pool = Arc::clone(self);
        let key = key.to_string();
        let shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(pool.run_janitor(key, min_idle, idle_timeout, prewarm, shutdown_rx));
    }

    /// Retire the pool without cutting live streams. New offers, inserts,
    /// prewarms, and speculative checkouts fail immediately; pool-owned dials
    /// and provisional sessions are cancelled. Published sessions enter
    /// Draining and are closed individually once their last stream releases.
    pub fn retire(&self) {
        if self
            .state
            .compare_exchange(
                PoolState::Running as usize,
                PoolState::Draining as usize,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let _ = self.shutdown_tx.send(true);
        // Dials and janitors observe this signal. A late dial verifies the
        // terminal state under the registration lock before publication.
        let (sessions, provisional) = {
            let mut keys = self.keys.lock();
            let mut sessions = Vec::new();
            let mut provisional = Vec::new();
            for pool in keys.values_mut() {
                pool.dial_done = None;
                sessions.extend(pool.sessions.iter().cloned());
                provisional.extend(pool.provisional.drain().filter_map(|(_, session)| session));
            }
            (sessions, provisional)
        };
        for session in provisional {
            session.close();
        }
        for session in &sessions {
            session.begin_drain();
        }

        let keys = Arc::clone(&self.keys);
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            loop {
                let (to_close, empty) = {
                    let mut keys = keys.lock();
                    let mut to_close = Vec::new();
                    for pool in keys.values_mut() {
                        pool.sessions.retain(|session| {
                            if session.is_closed() {
                                return false;
                            }
                            if session.active_streams() == 0 {
                                to_close.push(Arc::clone(session));
                                return false;
                            }
                            true
                        });
                    }
                    keys.retain(|_, pool| {
                        !pool.sessions.is_empty()
                            || !pool.provisional.is_empty()
                            || pool.dial_done.is_some()
                    });
                    (to_close, keys.is_empty())
                };
                for session in to_close {
                    session.close();
                }
                if empty {
                    let _ = state.compare_exchange(
                        PoolState::Draining as usize,
                        PoolState::Closed as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// Shut the pool down: reject offers/inserts/prewarms, abort the
    /// in-flight dial, wake every waiter with PoolClosed, close all
    /// sessions, and stop the janitor. Terminal and idempotent.
    pub fn shutdown(&self) {
        loop {
            let current = self.state();
            match current {
                PoolState::Closed | PoolState::ShuttingDown => return,
                PoolState::Running | PoolState::Draining => {
                    if self
                        .state
                        .compare_exchange(
                            current as usize,
                            PoolState::ShuttingDown as usize,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }
        let _ = self.shutdown_tx.send(true);
        // Dials and janitors observe the terminal signal; terminal
        // registration checks close late dial results safely.
        let sessions: Vec<Arc<S>> = {
            let mut keys = self.keys.lock();
            keys.drain()
                .flat_map(|(_, pool)| {
                    pool.sessions
                        .into_iter()
                        .chain(pool.provisional.into_values().flatten())
                })
                .collect()
        };
        for s in sessions {
            s.close();
        }
        self.state
            .store(PoolState::Closed as usize, Ordering::Release);
    }
}

impl<S: ManagedSession + 'static> DetachedSessionReservation<S> {
    /// Wait until the captured pool generation begins retirement or shutdown.
    /// Callers race this against their detached physical dial so generation
    /// retirement cancels work that the pool deliberately does not own.
    pub async fn cancelled(&self) {
        let mut shutdown_rx = self.pool.shutdown_tx.subscribe();
        if self.pool.state() != PoolState::Running {
            return;
        }
        let _ = shutdown_rx.changed().await;
    }

    /// Attach a completed detached session so pool retirement/shutdown and reservation
    /// cancellation close it before it can escape as a pooled session.
    pub fn attach(&mut self, session: &Arc<S>) -> anyhow::Result<()> {
        let attached = {
            let mut keys = self.pool.keys.lock();
            if !self.active || self.pool.state() != PoolState::Running {
                false
            } else {
                keys.get_mut(&self.key)
                    .and_then(|pool| pool.provisional.get_mut(&self.slot_id))
                    .is_some_and(|slot| {
                        if slot.is_some() {
                            false
                        } else {
                            *slot = Some(Arc::clone(session));
                            true
                        }
                    })
            }
        };
        if attached {
            Ok(())
        } else {
            session.close();
            Err(SessionPool::<S>::pool_closed_err())
        }
    }

    /// Promote the attached session exactly once into the same captured
    /// pool/key. A terminal pool removes the slot and closes the session
    /// instead of allowing a stale generation to repopulate it.
    pub fn commit(mut self) -> anyhow::Result<Arc<S>> {
        let outcome = {
            let mut keys = self.pool.keys.lock();
            if let Some(pool) = keys.get_mut(&self.key) {
                let session = pool.provisional.remove(&self.slot_id).flatten();
                if self.pool.state() == PoolState::Running {
                    if let Some(session) = session {
                        pool.sessions.retain(|existing| !existing.is_closed());
                        pool.sessions.push(Arc::clone(&session));
                        Ok(session)
                    } else {
                        Err(None)
                    }
                } else {
                    Err(session)
                }
            } else {
                Err(None)
            }
        };
        self.active = false;
        match outcome {
            Ok(session) => Ok(session),
            Err(session) => {
                if let Some(session) = session {
                    session.close();
                }
                Err(SessionPool::<S>::pool_closed_err())
            }
        }
    }
}

impl<S: ManagedSession + 'static> Drop for DetachedSessionReservation<S> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let session = self
            .pool
            .keys
            .lock()
            .get_mut(&self.key)
            .and_then(|pool| pool.provisional.remove(&self.slot_id))
            .flatten();
        self.active = false;
        if let Some(session) = session {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[derive(Debug)]
    struct TestSession {
        streams: AtomicUsize,
        closed: AtomicBool,
        state: AtomicUsize,
    }

    impl TestSession {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                streams: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
                state: AtomicUsize::new(0),
            })
        }
    }

    impl ManagedSession for TestSession {
        fn active_streams(&self) -> usize {
            self.streams.load(Ordering::Relaxed)
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
        fn close(&self) {
            self.closed.store(true, Ordering::Relaxed);
        }
        fn state(&self) -> SessionState {
            match self.state.load(Ordering::Relaxed) {
                _ if self.is_closed() => SessionState::Closed,
                0 => SessionState::Active,
                _ => SessionState::Draining,
            }
        }
        fn begin_drain(&self) {
            self.state.store(1, Ordering::Relaxed);
        }
    }

    fn pool(config: SessionPoolConfig) -> SessionPool<TestSession> {
        SessionPool::new(config)
    }

    #[derive(Debug)]
    struct ReservedTestSession {
        closed: AtomicBool,
        stream_permits: Arc<tokio::sync::Semaphore>,
        capacity: usize,
    }

    impl ReservedTestSession {
        fn new(capacity: usize) -> Arc<Self> {
            Arc::new(Self {
                closed: AtomicBool::new(false),
                stream_permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
                capacity,
            })
        }
    }

    impl ManagedSession for ReservedTestSession {
        fn active_streams(&self) -> usize {
            self.capacity - self.stream_permits.available_permits()
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
        fn close(&self) {
            self.closed.store(true, Ordering::Relaxed);
        }
        fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
            if self.is_closed() {
                return None;
            }
            let permit = Arc::clone(&self.stream_permits).try_acquire_owned().ok()?;
            if self.is_closed() {
                drop(permit);
                return None;
            }
            Some(SessionPermit::new(Arc::clone(self), permit))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn offer_dials_once_and_reuses() {
        let pool = pool(SessionPoolConfig::default());
        let dials = Arc::new(AtomicUsize::new(0));
        let dial = {
            let dials = Arc::clone(&dials);
            move || {
                let dials = Arc::clone(&dials);
                async move {
                    dials.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                }
            }
        };
        let s1 = pool.offer("k", dial).await.unwrap();
        let dials2 = Arc::clone(&dials);
        let s2 = pool
            .offer("k", move || async move {
                dials2.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&s1, &s2));
        assert_eq!(dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn least_loaded_is_offered() {
        let pool = pool(SessionPoolConfig {
            max_streams_per_session: 2,
            ..Default::default()
        });
        let dial_count = Arc::new(AtomicUsize::new(0));
        let mk = |pool: &SessionPool<TestSession>, dials: Arc<AtomicUsize>| {
            let d = Arc::clone(&dials);
            let pool = pool.clone();
            async move {
                pool.offer("k", move || async move {
                    d.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                })
                .await
                .unwrap()
            }
        };
        let s1 = mk(&pool, Arc::clone(&dial_count)).await;
        s1.streams.store(2, Ordering::Relaxed); // saturated
        let s2 = mk(&pool, Arc::clone(&dial_count)).await; // dials again
        assert!(!Arc::ptr_eq(&s1, &s2));
        s1.streams.store(1, Ordering::Relaxed);
        s2.streams.store(3, Ordering::Relaxed); // over cap
        let s3 = mk(&pool, Arc::clone(&dial_count)).await;
        assert!(Arc::ptr_eq(&s1, &s3), "least-loaded below cap wins");
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_session_is_not_killed() {
        // "full-capacity false kill": a session that momentarily reports
        // no stream capacity must be RETRIED, never closed — its streams
        // are still live.
        #[derive(Debug)]
        struct CappedSession {
            closed: AtomicBool,
            sem: Arc<tokio::sync::Semaphore>,
        }
        impl ManagedSession for CappedSession {
            fn active_streams(&self) -> usize {
                0
            }
            fn is_closed(&self) -> bool {
                self.closed.load(Ordering::Relaxed)
            }
            fn close(&self) {
                self.closed.store(true, Ordering::Relaxed);
            }
            fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
                if self.is_closed() {
                    return None;
                }
                let p = Arc::clone(&self.sem).try_acquire_owned().ok()?;
                Some(SessionPermit::new(Arc::clone(self), p))
            }
        }

        let pool = SessionPool::<CappedSession>::new(SessionPoolConfig {
            max_sessions: 1,
            ..Default::default()
        });
        let session = Arc::new(CappedSession {
            closed: AtomicBool::new(false),
            sem: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        // Saturate the only stream slot.
        let held = Arc::clone(&session.sem).acquire_owned().await.unwrap();
        pool.insert("k", &session);

        // open_with must fail (only one session, saturated) but must NOT
        // close the session.
        let r = pool
            .open_with(
                "k",
                || async { anyhow::bail!("no fresh dial expected") },
                |_s, _p| async { Ok::<_, OpenError>(()) },
            )
            .await;
        assert!(r.is_err(), "saturated pool must error after retries");
        assert!(
            !session.is_closed(),
            "a saturated-but-healthy session must not be closed"
        );
        drop(held);

        // Capacity frees up: the next open succeeds on the same session.
        pool.open_with(
            "k",
            || async { anyhow::bail!("no dial needed") },
            |_s, _p| async { Ok::<_, OpenError>(()) },
        )
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn insert_over_cap_still_tracked() {
        let pool = pool(SessionPoolConfig {
            max_sessions: 1,
            ..Default::default()
        });
        let s1 = TestSession::new();
        let s2 = TestSession::new();
        pool.insert("k", &s1);
        pool.insert("k", &s2); // over the cap: must still be tracked
        let offered = pool
            .offer("k", || async { unreachable!("no dial needed") })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&offered, &s1) || Arc::ptr_eq(&offered, &s2));
        // An orphaned (untracked) session would be invisible here.
        assert_eq!(pool.metrics().sessions, 2);
    }

    /// v2 (pool-owned dial): cancelling a caller never stops the shared
    /// dial — the waiter still receives the session the pool task
    /// establishes, and no second dial is stamped (single-flight).
    #[tokio::test(start_paused = true)]
    async fn caller_cancel_does_not_stop_shared_dial() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let (tx, rx) = tokio::sync::oneshot::channel::<Arc<TestSession>>();
        let p1 = Arc::clone(&pool);
        let leader = tokio::spawn(async move {
            p1.offer("k", move || async move {
                let s: anyhow::Result<Arc<TestSession>> = Ok(rx.await.expect("trigger"));
                s
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        leader.abort();
        let _ = leader.await;
        let dials = Arc::new(AtomicUsize::new(0));
        let d = Arc::clone(&dials);
        let p2 = Arc::clone(&pool);
        let waiter = tokio::spawn(async move {
            p2.offer("k", move || async move {
                d.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            dials.load(Ordering::Relaxed),
            0,
            "single-flight: the shared dial keeps running, no second dial"
        );
        tx.send(TestSession::new()).unwrap();
        let session = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter stuck behind the shared dial")
            .unwrap()
            .unwrap();
        assert!(!session.is_closed());
        assert!(pool.keys.lock().get("k").unwrap().dial_done.is_none());
        assert_eq!(pool.keys.lock().get("k").unwrap().dial_failures, 0);
    }

    /// v2: a panicking dial surfaces as an internal failure to every
    /// waiter; the inflight entry clears and the next offer re-dials.
    #[tokio::test(start_paused = true)]
    async fn dial_panic_wakes_waiters_and_reelects() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = Arc::clone(&attempts);
        let result = pool
            .offer("k", move || {
                let n = a.fetch_add(1, Ordering::Relaxed);
                async move {
                    if n == 0 {
                        panic!("boom")
                    } else {
                        Ok(TestSession::new())
                    }
                }
            })
            .await;
        assert!(result.is_err(), "panicking dial surfaces as failure");
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(pool.keys.lock().get("k").unwrap().dial_done.is_none());
        // Past the short backoff, a fresh offer re-dials and succeeds.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let a2 = Arc::clone(&attempts);
        let session = pool
            .offer("k", move || {
                a2.fetch_add(1, Ordering::Relaxed);
                async { Ok(TestSession::new()) }
            })
            .await
            .unwrap();
        assert!(!session.is_closed());
    }

    /// Phase 1: shutdown aborts the in-flight dial (leader), wakes every
    /// waiter with PoolClosed, and rejects offers/inserts afterwards.
    #[tokio::test(start_paused = true)]
    async fn shutdown_wakes_leader_and_waiters() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let p1 = Arc::clone(&pool);
        let leader = tokio::spawn(async move {
            p1.offer("k", || async {
                futures_util::future::pending::<anyhow::Result<Arc<TestSession>>>().await
            })
            .await
        });
        let p2 = Arc::clone(&pool);
        let waiter =
            tokio::spawn(async move { p2.offer("k", || async { Ok(TestSession::new()) }).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        pool.shutdown();
        assert!(waiter.await.unwrap().is_err(), "waiter must see PoolClosed");
        assert!(
            leader.await.unwrap().is_err(),
            "leader's dial must abort with PoolClosed"
        );
        pool.shutdown(); // idempotent
        assert!(
            pool.offer("k", || async { Ok(TestSession::new()) })
                .await
                .is_err(),
            "offers stay rejected after shutdown"
        );
        let s = TestSession::new();
        pool.insert("k", &s);
        assert!(
            s.closed.load(Ordering::Relaxed),
            "insert after shutdown closes the session"
        );
        assert!(
            !pool.has_usable_session("k"),
            "a shutdown pool cannot retain a late session insertion"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_before_ensure_does_not_register_janitor_or_prewarm() {
        let pool = Arc::new(pool(SessionPoolConfig {
            janitor_interval: Duration::from_secs(1),
            ..Default::default()
        }));
        let prewarm_calls = Arc::new(AtomicUsize::new(0));
        pool.shutdown();
        pool.ensure_janitor("k", 1, Duration::from_secs(60), {
            let prewarm_calls = Arc::clone(&prewarm_calls);
            move || {
                let prewarm_calls = Arc::clone(&prewarm_calls);
                async move {
                    prewarm_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                }
            }
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(pool.keys.lock().is_empty());
        assert_eq!(prewarm_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_before_first_janitor_poll_exits_without_recreating_key() {
        let pool = Arc::new(pool(SessionPoolConfig {
            janitor_interval: Duration::from_secs(1),
            ..Default::default()
        }));
        {
            let mut keys = pool.keys.lock();
            keys.entry("k".to_string()).or_default().janitor_running = true;
        }
        let _shutdown_listener = pool.shutdown_tx.subscribe();
        pool.shutdown();
        let shutdown_rx = pool.shutdown_tx.subscribe();
        assert!(
            *shutdown_rx.borrow(),
            "first poll observes terminal watch state"
        );
        let prewarm_calls = Arc::new(AtomicUsize::new(0));
        let janitor = tokio::spawn(Arc::clone(&pool).run_janitor(
            "k".to_string(),
            1,
            Duration::from_secs(60),
            {
                let prewarm_calls = Arc::clone(&prewarm_calls);
                move || {
                    let prewarm_calls = Arc::clone(&prewarm_calls);
                    async move {
                        prewarm_calls.fetch_add(1, Ordering::Relaxed);
                        Ok(TestSession::new())
                    }
                }
            },
            shutdown_rx,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            janitor.is_finished(),
            "terminal janitor must exit on first poll"
        );
        assert!(
            pool.keys.lock().is_empty(),
            "terminal janitor must not recreate its key"
        );
        assert_eq!(prewarm_calls.load(Ordering::Relaxed), 0);
    }

    /// v2 max-age: past the jittered deadline the session drains (no new
    /// channels) and the janitor closes it once empty.
    #[tokio::test(start_paused = true)]
    async fn max_age_drains_and_janitor_closes_empty_session() {
        let pool = Arc::new(pool(SessionPoolConfig {
            max_session_age: Some(Duration::from_secs(60)),
            janitor_interval: Duration::from_secs(5),
            ..Default::default()
        }));
        pool.ensure_janitor("k", 0, Duration::from_secs(3600), || async {
            unreachable!("no prewarm")
        });
        let session = pool
            .offer("k", || async { Ok(TestSession::new()) })
            .await
            .unwrap();
        assert_eq!(session.state(), SessionState::Active);
        // Past 60s × 1.1 (the worst jitter), the janitor has drained it
        // (an empty session may already be closed in the same tick).
        tokio::time::sleep(Duration::from_secs(80)).await;
        assert!(
            session.state() == SessionState::Draining || session.is_closed(),
            "past max-age the session drains"
        );
        // Drained and empty: the janitor closes it.
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(session.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn dial_single_flight() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let dials = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            let dials = Arc::clone(&dials);
            handles.push(tokio::spawn(async move {
                pool.offer("k", move || async move {
                    dials.fetch_add(1, Ordering::Relaxed);
                    // Hold the in-flight dial so the others must wait.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(TestSession::new())
                })
                .await
            }));
        }
        let results: Vec<_> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(results.iter().all(|r| r.is_ok()));
        assert_eq!(dials.load(Ordering::Relaxed), 1);
        let first = results[0].as_ref().unwrap();
        assert!(
            results[1..]
                .iter()
                .all(|r| Arc::ptr_eq(r.as_ref().unwrap(), first))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dial_failures_back_off() {
        let pool = pool(SessionPoolConfig {
            dial_backoff: Duration::from_secs(10),
            ..Default::default()
        });
        let fail = || async { anyhow::bail!("boom") };
        let start = Instant::now();
        assert!(pool.offer::<fn() -> _, _>("k", fail).await.is_err());
        assert_eq!(start.elapsed(), Duration::ZERO);
        // Second attempt waits out the backoff before re-dialing.
        assert!(pool.offer::<fn() -> _, _>("k", fail).await.is_err());
        assert!(start.elapsed() >= Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn closed_sessions_are_pruned() {
        let pool = pool(SessionPoolConfig::default());
        let s1 = pool
            .offer("k", || async { Ok(TestSession::new()) })
            .await
            .unwrap();
        pool.invalidate("k", &s1);
        let dials = Arc::new(AtomicUsize::new(0));
        let d = Arc::clone(&dials);
        let s2 = pool
            .offer("k", move || {
                let d = Arc::clone(&d);
                async move {
                    d.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                }
            })
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_closes_everything() {
        let pool = pool(SessionPoolConfig::default());
        let s = pool
            .offer("k", || async { Ok(TestSession::new()) })
            .await
            .unwrap();
        pool.shutdown();
        assert!(s.is_closed());
        assert_eq!(pool.metrics().sessions, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn retirement_rejects_new_work_but_drains_live_sessions() {
        let pool = pool(SessionPoolConfig::default());
        let session = pool
            .offer("k", || async { Ok(TestSession::new()) })
            .await
            .unwrap();
        session.streams.store(1, Ordering::Relaxed);

        pool.retire();

        assert_eq!(session.state(), SessionState::Draining);
        assert!(
            !session.is_closed(),
            "retirement must preserve live streams"
        );
        assert!(
            pool.offer("k", || async { Ok(TestSession::new()) })
                .await
                .is_err(),
            "retired pools must reject new sessions"
        );

        session.streams.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
        assert!(session.is_closed(), "drained sessions must close promptly");
        assert_eq!(pool.metrics().sessions, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_after_retirement_force_closes_live_sessions() {
        let pool = pool(SessionPoolConfig::default());
        let session = pool
            .offer("k", || async { Ok(TestSession::new()) })
            .await
            .unwrap();
        session.streams.store(1, Ordering::Relaxed);
        pool.retire();
        assert!(!session.is_closed());

        pool.shutdown();

        assert!(session.is_closed());
        assert_eq!(pool.metrics().sessions, 0);
    }

    /// A Cold URLTest loser owns its physical dial. Aborting the caller must
    /// drop its detached reservation, releasing its provisional cap slot.
    #[tokio::test]
    async fn speculative_checkout_cancellation_releases_blocked_dial_slot() {
        let pool = Arc::new(pool(SessionPoolConfig {
            max_sessions: 1,
            ..Default::default()
        }));
        let entered = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let pool = Arc::clone(&pool);
            let entered = Arc::clone(&entered);
            async move {
                let _reservation = match pool.checkout_speculative("k").await.unwrap() {
                    SpeculativeCheckout::Detached(reservation) => reservation,
                    SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
                };
                entered.notify_one();
                futures_util::future::pending::<()>().await;
            }
        });
        entered.notified().await;
        assert_eq!(pool.keys.lock().get("k").unwrap().provisional.len(), 1);

        task.abort();
        let _ = task.await;
        assert!(
            pool.keys
                .lock()
                .get("k")
                .is_none_or(|key| key.provisional.is_empty()),
            "aborting a caller-owned dial must release its provisional slot"
        );
    }

    #[tokio::test]
    async fn detached_checkout_shutdown_closes_attached_session_and_rejects_commit() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let mut reservation = match pool.checkout_speculative("k").await.unwrap() {
            SpeculativeCheckout::Detached(reservation) => reservation,
            SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
        };
        let session = TestSession::new();
        reservation.attach(&session).unwrap();

        pool.shutdown();

        assert!(
            session.is_closed(),
            "terminal shutdown must close an attached detached session"
        );
        assert!(
            reservation.commit().is_err(),
            "a detached reservation may not repopulate a terminal pool"
        );
        assert_eq!(pool.metrics().sessions, 0);
    }

    #[tokio::test]
    async fn provisional_slot_blocks_normal_offer_until_released() {
        let pool = Arc::new(pool(SessionPoolConfig {
            max_sessions: 1,
            janitor_interval: Duration::from_millis(1),
            ..Default::default()
        }));
        let reservation = match pool.checkout_speculative("k").await.unwrap() {
            SpeculativeCheckout::Detached(reservation) => reservation,
            SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
        };
        let dials = Arc::new(AtomicUsize::new(0));
        let offer = tokio::spawn({
            let pool = Arc::clone(&pool);
            let dials = Arc::clone(&dials);
            async move {
                pool.offer("k", move || async move {
                    dials.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                })
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            dials.load(Ordering::Relaxed),
            0,
            "a provisional slot counts against normal pool-owned dial admission"
        );

        drop(reservation);
        let session = tokio::time::timeout(Duration::from_secs(1), offer)
            .await
            .expect("normal offer remained blocked after provisional release")
            .unwrap()
            .unwrap();
        assert!(!session.is_closed());
        assert_eq!(dials.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn detached_commit_inserts_once_into_the_captured_pool() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let mut reservation = match pool.checkout_speculative("k").await.unwrap() {
            SpeculativeCheckout::Detached(reservation) => reservation,
            SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
        };
        let session = TestSession::new();
        reservation.attach(&session).unwrap();
        let committed = reservation.commit().unwrap();

        assert!(Arc::ptr_eq(&session, &committed));
        assert_eq!(pool.metrics().sessions, 1);
        assert!(pool.keys.lock().get("k").unwrap().provisional.is_empty());
        let offered = pool
            .offer("k", || async {
                unreachable!("committed session must be reused")
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&committed, &offered));
        assert_eq!(
            pool.metrics().sessions,
            1,
            "commit cannot duplicate insertion"
        );
    }

    #[tokio::test]
    async fn shared_checkout_reserves_its_stream_permit_atomically() {
        let pool = Arc::new(SessionPool::new(SessionPoolConfig {
            max_sessions: 1,
            janitor_interval: Duration::from_millis(1),
            ..Default::default()
        }));
        let session = ReservedTestSession::new(1);
        pool.insert("k", &session);
        let permit = match pool.checkout_speculative("k").await.unwrap() {
            SpeculativeCheckout::Shared {
                session: checked,
                permit,
            } => {
                assert!(Arc::ptr_eq(&session, &checked));
                permit
            }
            SpeculativeCheckout::Detached(_) => panic!("live session must be checked out first"),
        };
        assert_eq!(session.active_streams(), 1);

        let blocked = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.checkout_speculative("k").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !blocked.is_finished(),
            "the occupied shared stream slot must not be offered twice"
        );
        drop(permit);
        let next = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("second checkout did not observe released stream capacity")
            .unwrap()
            .unwrap();
        assert!(matches!(next, SpeculativeCheckout::Shared { .. }));
    }
}
