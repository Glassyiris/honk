//! Graceful shutdown and connection draining for the control plane.
//!
//! On SIGTERM, BPF hooks must be detached immediately to restore
//! network connectivity. Existing connections are given a grace
//! period to drain before forced termination.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{info, warn};

const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Tracks the state of connection draining during shutdown.
pub struct DrainTracker {
    active_connections: AtomicUsize,
    reject_new: AtomicBool,
    drain_timeout: Duration,
}

impl DrainTracker {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            reject_new: AtomicBool::new(false),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn increment(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn start_rejecting(&self) {
        self.reject_new.store(true, Ordering::SeqCst);
        info!("DrainTracker: rejecting new connections");
    }

    /// Stop rejecting new connections (e.g., after config reload).
    pub fn stop_rejecting(&self) {
        self.reject_new.store(false, Ordering::SeqCst);
        info!("DrainTracker: accepting new connections again");
    }

    pub fn should_reject(&self) -> bool {
        self.reject_new.load(Ordering::SeqCst)
    }

    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub async fn drain(&self) -> anyhow::Result<usize> {
        self.start_rejecting();

        let remaining = self.active_count();
        if remaining == 0 {
            info!("DrainTracker: no active connections to drain");
            return Ok(0);
        }

        info!(
            "DrainTracker: waiting for {} connections to drain (timeout {:?})",
            remaining, self.drain_timeout
        );

        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        loop {
            let count = self.active_count();
            if count == 0 {
                info!("DrainTracker: all connections drained");
                return Ok(0);
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "DrainTracker: drain timeout after {:?}, {} connections remaining",
                    self.drain_timeout, count
                );
                return Ok(count);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Default for DrainTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Orchestrates a graceful shutdown sequence:
/// 1. Detach BPF hooks (restore network immediately)
/// 2. Stop accepting new connections
/// 3. Drain existing connections with timeout
/// 4. Run deferred cleanup functions
pub struct GracefulShutdown {
    bpf_hooks_detached: AtomicBool,
    shutdown_timeout: Duration,
}

impl GracefulShutdown {
    pub fn new() -> Self {
        Self {
            bpf_hooks_detached: AtomicBool::new(false),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }

    /// Detach BPF hooks immediately. Safe to call multiple times.
    ///
    /// Returns true if this was the first call (hooks were actually detached).
    pub fn detach_bpf_hooks<F>(&self, detach_fn: F) -> anyhow::Result<bool>
    where
        F: FnOnce() -> anyhow::Result<()>,
    {
        if self.bpf_hooks_detached.swap(true, Ordering::SeqCst) {
            return Ok(false);
        }

        info!("[Shutdown] Detaching BPF hooks to restore network");
        detach_fn()?;
        info!("[Shutdown] BPF hooks detached, network restored");
        Ok(true)
    }

    /// Execute the full shutdown sequence.
    pub async fn execute<F, G>(
        &self,
        drain_tracker: &DrainTracker,
        detach_bpf: F,
        run_deferred: G,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<()>,
        G: FnOnce() -> anyhow::Result<()>,
    {
        self.detach_bpf_hooks(detach_bpf)?;
        drain_tracker.drain().await?;

        info!(
            "[Shutdown] Running deferred cleanup (timeout {:?})",
            self.shutdown_timeout
        );
        let result = tokio::time::timeout(self.shutdown_timeout, async { run_deferred() }).await;

        match result {
            Ok(Ok(())) => info!("[Shutdown] Cleanup complete"),
            Ok(Err(e)) => warn!("[Shutdown] Cleanup error: {}", e),
            Err(_) => warn!("[Shutdown] Cleanup timed out"),
        }
        Ok(())
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graceful_shutdown_detach_once() {
        let shutdown = GracefulShutdown::new();
        let mut call_count = 0;
        let result = shutdown.detach_bpf_hooks(|| {
            call_count += 1;
            Ok(())
        });
        assert!(result.unwrap());
        assert_eq!(call_count, 1);

        let result = shutdown.detach_bpf_hooks(|| {
            call_count += 1;
            Ok(())
        });
        assert!(!result.unwrap());
        assert_eq!(call_count, 1);
    }
}
