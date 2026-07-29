//! Unified session pool for multiplexed outbounds (h2mux, AnyTLS,
//! Trojan-Go; QUIC protocols keep their own single-connection holder —
//! see `quic::QuicClient`).
//!
//! What this centralizes (previously re-implemented, slightly
//! differently, per protocol):
//!
//! - one pool per [`PoolKey`] (host:port + auth/TLS fingerprint — the
//!   protocols already build these), with a hard session cap;
//! - least-loaded scheduling: the live session with the fewest active
//!   streams below the soft per-session cap is offered first;
//! - per-key dial single-flight: concurrent dials share one in-flight
//!   session establishment instead of stampeding the server;
//! - dial circuit breaker: consecutive establishment failures back off
//!   exponentially before the pool dials again (a dead server must not
//!   eat a TCP connect per proxied flow);
//! - idle reaping and optional prewarm (`min_idle`) via one janitor per
//!   key;
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
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            max_streams_per_session: 8,
            janitor_interval: Duration::from_secs(30),
            dial_backoff: Duration::from_secs(1),
            max_dial_backoff: Duration::from_secs(30),
        }
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
}

/// Pool lifecycle: shutdown is terminal and idempotent — offers, inserts
/// and prewarms are rejected, waiters wake with PoolClosed, sessions are
/// closed and the janitor exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolState {
    Running,
    ShuttingDown,
    Closed,
}

impl From<usize> for PoolState {
    fn from(v: usize) -> Self {
        match v {
            0 => PoolState::Running,
            1 => PoolState::ShuttingDown,
            _ => PoolState::Closed,
        }
    }
}

/// Per-key pool state.
struct KeyPool<S> {
    sessions: Vec<Arc<S>>,
    /// While a dial is in flight this is `Some((inflight_id, sender))`;
    /// waiters `wait_for(> 0)` on a receiver cloned under the lock
    /// (race-free — `watch::Receiver::wait_for` evaluates the predicate
    /// against the current value before parking). The inflight id lets a
    /// [`DialGuard`] clear only its own dial.
    dial_done: Option<(u64, tokio::sync::watch::Sender<u64>)>,
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

    fn pool_closed_err() -> anyhow::Error {
        anyhow!("session pool is closed")
    }

    /// Offer the least-loaded live session, dialing one when none is
    /// usable. Concurrent dials for the same key share one establishment
    /// (single-flight); repeated failures back off per key.
    pub async fn offer<F, Fut>(&self, key: &str, dial: F) -> anyhow::Result<Arc<S>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Arc<S>>>,
    {
        let mut dial = Some(dial);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            if self.state() != PoolState::Running {
                return Err(Self::pool_closed_err());
            }
            // Phase 1: pick a live session, register as the dialer, or
            // park on the in-flight dial.
            enum Step<S> {
                Have(Arc<S>),
                Dial(u64, tokio::sync::watch::Sender<u64>),
                Wait(tokio::sync::watch::Receiver<u64>),
                Backoff(Duration),
            }
            let step = {
                let mut keys = self.keys.lock();
                let pool = keys.entry(key.to_string()).or_default();
                pool.sessions.retain(|s| !s.is_closed());
                if let Some(s) = pool
                    .sessions
                    .iter()
                    .filter(|s| s.active_streams() < self.config.max_streams_per_session)
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
                } else if pool.sessions.len() >= self.config.max_sessions {
                    // At the hard cap with every session saturated: wait
                    // for capacity to free up (a stream closes, a session
                    // is reaped) instead of stampeding past the cap.
                    Step::Backoff(self.config.janitor_interval.min(Duration::from_secs(5)))
                } else {
                    let id = pool.next_inflight_id;
                    pool.next_inflight_id += 1;
                    let (tx, _) = tokio::sync::watch::channel(0u64);
                    pool.dial_done = Some((id, tx.clone()));
                    Step::Dial(id, tx)
                }
            };

            match step {
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
                    tokio::select! {
                        // `wait_for` checks the current value first — no
                        // race with a dial that completed before parking.
                        r = rx.wait_for(|v| *v > 0) => { let _ = r; }
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                }
                Step::Dial(id, done) => {
                    let mut guard = DialGuard {
                        keys: Arc::clone(&self.keys),
                        key: key.to_string(),
                        inflight_id: id,
                        armed: true,
                    };
                    let dial_fut = dial.take().expect("one dial closure")();
                    let result = tokio::select! {
                        r = std::panic::AssertUnwindSafe(dial_fut).catch_unwind() => r,
                        // Pool shutdown aborts the dial without penalizing
                        // the node; the guard clears the inflight entry.
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    };
                    // Completion: clear the inflight entry under the lock
                    // and wake the waiters.
                    {
                        let mut keys = self.keys.lock();
                        let pool = keys.entry(key.to_string()).or_default();
                        if pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id) {
                            pool.dial_done = None;
                        }
                    }
                    guard.armed = false;
                    let _ = done.send(1);
                    match result {
                        Ok(Ok(session)) => {
                            let mut keys = self.keys.lock();
                            let pool = keys.entry(key.to_string()).or_default();
                            pool.dial_failures = 0;
                            pool.next_dial_at = None;
                            pool.sessions.push(Arc::clone(&session));
                            return Ok(session);
                        }
                        Ok(Err(e)) => {
                            self.dial_failures_total.fetch_add(1, Ordering::Relaxed);
                            let mut keys = self.keys.lock();
                            let pool = keys.entry(key.to_string()).or_default();
                            pool.dial_failures += 1;
                            let shift = pool.dial_failures.min(8) - 1;
                            let backoff = (self.config.dial_backoff.saturating_mul(1u32 << shift))
                                .min(self.config.max_dial_backoff);
                            pool.next_dial_at = Some(Instant::now() + backoff);
                            return Err(e.context(anyhow!(
                                "session dial failed ({} consecutive, backoff {:?})",
                                pool.dial_failures,
                                backoff
                            )));
                        }
                        Err(_panic) => {
                            // A panicking dial is an internal failure:
                            // short backoff, waiters re-elect.
                            self.dial_failures_total.fetch_add(1, Ordering::Relaxed);
                            let mut keys = self.keys.lock();
                            let pool = keys.entry(key.to_string()).or_default();
                            pool.dial_failures += 1;
                            pool.next_dial_at = Some(Instant::now() + self.config.dial_backoff);
                            return Err(anyhow!(
                                "session dial panicked (backoff {:?})",
                                self.config.dial_backoff
                            ));
                        }
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

    /// Insert an externally-established session (e.g. one built on a
    /// pooled TCP stream). The session is always tracked — even over the
    /// hard cap: an untracked session is orphaned from the janitor while
    /// its demux task holds it (and its TCP connection) open forever.
    /// Over-cap entries are transient; the janitor reaps them when idle.
    /// After shutdown the session is closed instead of inserted.
    pub fn insert(&self, key: &str, session: &Arc<S>) {
        if self.state() != PoolState::Running {
            session.close();
            return;
        }
        let mut keys = self.keys.lock();
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

    /// Start the per-key janitor (prune closed/expired, prewarm to
    /// `min_idle`) once; subsequent calls are no-ops. `prewarm` dials a
    /// fresh session and is only called when below `min_idle`.
    /// `min_idle`/`idle_timeout` are per-key (node-level policies, e.g.
    /// AnyTLS's node fields).
    // First consumer: the AnyTLS pool migration (P1.6).
    #[allow(dead_code)]
    pub fn ensure_janitor<F, Fut>(
        self: &Arc<Self>,
        key: &str,
        min_idle: usize,
        idle_timeout: Duration,
        prewarm: F,
    ) where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send,
    {
        if self.state() != PoolState::Running {
            return;
        }
        {
            let mut keys = self.keys.lock();
            let pool = keys.entry(key.to_string()).or_default();
            if pool.janitor_running {
                return;
            }
            pool.janitor_running = true;
        }
        let pool = Arc::clone(self);
        let key = key.to_string();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(pool.config.janitor_interval);
            interval.tick().await;
            // Per-session zero-stream streak start, keyed by Arc identity
            // (positions in the vec shift as sessions come and go).
            let mut idle_since: HashMap<usize, Instant> = HashMap::new();
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    // Pool shutdown: exit, no further prewarm/reap.
                    _ = shutdown_rx.changed() => break,
                }
                let now = Instant::now();
                let idle_to_close = {
                    let mut keys = pool.keys.lock();
                    let kp = keys.entry(key.clone()).or_default();
                    kp.sessions.retain(|s| !s.is_closed());
                    let live: Vec<Arc<S>> = kp.sessions.clone();
                    let mut to_close = Vec::new();
                    idle_since
                        .retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                    for s in &live {
                        let ptr = Arc::as_ptr(s) as usize;
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
                    pool.invalidate(&key, s);
                }
                // Prewarm to min_idle (rejected once the pool is shut).
                let current = pool.keys.lock().get(&key).map_or(0, |p| p.sessions.len());
                if current < min_idle
                    && let Ok(s) = pool.offer(&key, &prewarm).await
                {
                    drop(s);
                }
            }
        });
    }

    /// Shut the pool down: reject offers/inserts/prewarms, abort the
    /// in-flight dial, wake every waiter with PoolClosed, close all
    /// sessions, and stop the janitor. Terminal and idempotent.
    pub fn shutdown(&self) {
        if self
            .state
            .compare_exchange(
                PoolState::Running as usize,
                PoolState::ShuttingDown as usize,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return; // already shutting down or closed
        }
        let _ = self.shutdown_tx.send(true);
        let sessions: Vec<Arc<S>> = {
            let mut keys = self.keys.lock();
            keys.drain().flat_map(|(_, p)| p.sessions).collect()
        };
        for s in sessions {
            s.close();
        }
        self.state
            .store(PoolState::Closed as usize, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct TestSession {
        streams: AtomicUsize,
        closed: AtomicBool,
    }

    impl TestSession {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                streams: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
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
    }

    fn pool(config: SessionPoolConfig) -> SessionPool<TestSession> {
        SessionPool::new(config)
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

    /// Phase 1 (P0): a leader cancelled inside `dial().await` must not
    /// poison the key — the inflight entry clears, a waiter re-elects
    /// and completes, and the failure count stays untouched.
    #[tokio::test(start_paused = true)]
    async fn leader_abort_waiter_reelects_and_clears_inflight() {
        let pool = Arc::new(pool(SessionPoolConfig::default()));
        let p1 = Arc::clone(&pool);
        let leader = tokio::spawn(async move {
            p1.offer("k", || async {
                futures_util::future::pending::<anyhow::Result<Arc<TestSession>>>().await
            })
            .await
        });
        let waiter_dials = Arc::new(AtomicUsize::new(0));
        let dials = Arc::clone(&waiter_dials);
        let p2 = Arc::clone(&pool);
        let waiter = tokio::spawn(async move {
            p2.offer("k", move || async move {
                dials.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        leader.abort();
        let _ = leader.await;
        let session = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter stuck after leader abort")
            .unwrap()
            .unwrap();
        assert_eq!(waiter_dials.load(Ordering::Relaxed), 1);
        assert!(pool.keys.lock().get("k").unwrap().dial_done.is_none());
        assert_eq!(
            pool.keys.lock().get("k").unwrap().dial_failures,
            0,
            "caller cancellation must not penalize the node"
        );
        drop(session);
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
}
