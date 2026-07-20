//! BPF lifecycle, defer/detach function stacks, and reload flip for zero-downtime config reload.
//! Uses interior mutability (Mutex + AtomicBool) — safe to share via `Arc`.

use crate::ebpf::EbpfBackend;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{info, warn};

type DeferFunc = Box<dyn FnOnce() -> anyhow::Result<()> + Send>;

/// Global flip counter shared across all control plane instances.
///
/// Toggled atomically during reload so the new instance uses the
/// opposite TC filter handle from the old one.
static CURRENT_FLIP: AtomicU8 = AtomicU8::new(0);

/// Mutex guard providing access to the inner [`EbpfBackend`].
/// Created by [`ControlPlaneCore::peek_bpf`]; lock held until dropped.
pub struct BpfGuard<'a> {
    guard: MutexGuard<'a, Option<Box<dyn EbpfBackend>>>,
}

impl BpfGuard<'_> {
    /// # Panics
    ///
    /// Panics if the guard was constructed without a valid backend.
    /// This should never happen when created via `peek_bpf()`.
    pub fn backend(&self) -> &dyn EbpfBackend {
        self.guard
            .as_ref()
            .expect("BpfGuard created without valid bpf backend")
            .as_ref()
    }

    /// # Panics
    ///
    /// Panics if the guard was constructed without a valid backend.
    pub fn backend_mut(&mut self) -> &mut dyn EbpfBackend {
        self.guard
            .as_mut()
            .expect("BpfGuard created without valid bpf backend")
            .as_mut()
    }
}

/// Lifecycle manager for the honk control plane.
///
/// ## Defer Stack vs Hook Detach List
///
/// - **defer_funcs**: General cleanup executed on normal `close()` in reverse (LIFO) order.
/// - **bpf_hook_detach_funcs**: eBPF hook detach functions. Executed immediately by
///   [`detach_bpf_hooks`] (called on SIGTERM) to restore network connectivity.
///
/// During reload, BPF ownership transfers via [`eject_bpf`] / [`inject_bpf`],
/// avoiding BPF resource cleanup and re-initialization.
///
/// [`eject_bpf`]: ControlPlaneCore::eject_bpf
/// [`inject_bpf`]: ControlPlaneCore::inject_bpf
/// [`detach_bpf_hooks`]: ControlPlaneCore::detach_bpf_hooks
pub struct ControlPlaneCore {
    /// Active BPF backend. Protected by Mutex for interior mutability.
    bpf: Mutex<Option<Box<dyn EbpfBackend>>>,

    /// Deferred cleanup functions, executed in reverse order on close.
    defer_funcs: Mutex<Vec<DeferFunc>>,

    /// BPF hook detach functions, executed immediately on SIGTERM.
    bpf_hook_detach_funcs: Mutex<Vec<DeferFunc>>,

    /// Whether this instance was created for a reload.
    is_reload: bool,

    /// Current flip value for TC filter handle (0 or 1).
    flip: u8,

    /// True once BPF has been ejected (ownership transferred).
    bpf_ejected: AtomicBool,

    /// True if this instance owns the BPF backend.
    bpf_owned: AtomicBool,

    /// True once this instance has been retired.
    retired: AtomicBool,

    /// True once BPF hooks have been detached.
    bpf_hooks_detached: AtomicBool,

    /// Shutdown signal sender. Sets to `true` when close() is called.
    closed_tx: tokio::sync::watch::Sender<bool>,

    /// Shutdown signal receiver. Observers can watch for the close signal.
    closed_rx: tokio::sync::watch::Receiver<bool>,
}

impl ControlPlaneCore {
    /// If `is_reload` is `true`, the flip is toggled from the current global flip
    /// so the new instance uses a different TC filter handle. The instance starts
    /// with `bpf_owned = false` — it expects the previous instance to hand off BPF.
    ///
    /// If `is_reload` is `false`, the current global flip is used as-is
    /// and `bpf_owned` is set to `true`.
    pub fn new(is_reload: bool) -> Self {
        let (flip, bpf_owned) = if is_reload {
            let current = CURRENT_FLIP.load(Ordering::SeqCst);
            let new_flip = 1u8.wrapping_sub(current);
            (new_flip, false)
        } else {
            let current = CURRENT_FLIP.load(Ordering::SeqCst);
            (current, true)
        };

        let (tx, rx) = tokio::sync::watch::channel(false);

        Self {
            bpf: Mutex::new(None),
            defer_funcs: Mutex::new(Vec::new()),
            bpf_hook_detach_funcs: Mutex::new(Vec::new()),
            is_reload,
            flip,
            bpf_ejected: AtomicBool::new(false),
            bpf_owned: AtomicBool::new(bpf_owned),
            retired: AtomicBool::new(false),
            bpf_hooks_detached: AtomicBool::new(false),
            closed_tx: tx,
            closed_rx: rx,
        }
    }

    /// Current flip value (0 or 1), used as the TC filter handle/priority
    /// to distinguish old and new BPF programs during reload.
    pub fn flip(&self) -> u8 {
        self.flip
    }

    /// Get the current global flip value without toggling.
    pub fn current_flip() -> u8 {
        CURRENT_FLIP.load(Ordering::SeqCst)
    }

    /// Called during reload so the new control plane uses the opposite handle.
    pub fn toggle_flip() {
        CURRENT_FLIP.fetch_xor(1, Ordering::SeqCst);
    }

    /// Push a cleanup function onto the defer stack.
    /// Executed in **reverse** (LIFO) order on [`close`].
    /// Returns `false` if already closed.
    ///
    /// [`close`]: ControlPlaneCore::close
    pub fn add_defer_func<F>(&self, f: F) -> bool
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        if self.is_closed() {
            return false;
        }
        self.defer_funcs
            .lock()
            .expect("defer_funcs lock poisoned")
            .push(Box::new(f));
        true
    }

    /// Register a BPF hook detach function.
    /// Called in reverse order by [`detach_bpf_hooks`] to restore
    /// network connectivity during shutdown (e.g. SIGTERM).
    ///
    /// [`detach_bpf_hooks`]: ControlPlaneCore::detach_bpf_hooks
    pub fn add_bpf_hook_detach<F>(&self, f: F)
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        self.bpf_hook_detach_funcs
            .lock()
            .expect("bpf_hook_detach_funcs lock poisoned")
            .push(Box::new(f));
    }

    /// Register cleanup for **both** the defer stack and the detach list.
    ///
    /// The function is stored as `Arc<Mutex<Option<F>>>` so it executes at
    /// most once — whichever list is drained first wins. Subsequent invocations
    /// are no-ops. Returns `false` if already closed.
    pub fn add_managed_bpf_hook_cleanup<F>(&self, f: F) -> bool
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        if self.is_closed() {
            return false;
        }

        let cell = Arc::new(std::sync::Mutex::new(Some(f)));

        {
            let cell = Arc::clone(&cell);
            self.bpf_hook_detach_funcs
                .lock()
                .expect("bpf_hook_detach_funcs lock poisoned")
                .push(Box::new(move || {
                    match cell.lock().ok().and_then(|mut g| g.take()) {
                        Some(func) => func(),
                        _ => {
                            Ok(()) // Already executed via the other path
                        }
                    }
                }));
        }

        {
            self.defer_funcs
                .lock()
                .expect("defer_funcs lock poisoned")
                .push(Box::new(move || {
                    match cell.lock().ok().and_then(|mut g| g.take()) {
                        Some(func) => func(),
                        _ => {
                            Ok(()) // Already executed via the other path
                        }
                    }
                }));
        }

        true
    }

    /// Restores network connectivity by detaching eBPF TC/sk_lookup programs.
    /// Idempotent — only the first call executes; subsequent calls are no-ops.
    /// Continues through failures, collecting errors into a combined error.
    pub fn detach_bpf_hooks(&self) -> anyhow::Result<()> {
        if self.bpf_hooks_detached.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Detaching BPF hooks to restore network");

        let mut funcs = self
            .bpf_hook_detach_funcs
            .lock()
            .expect("bpf_hook_detach_funcs lock poisoned");

        let mut errors: Vec<anyhow::Error> = Vec::new();

        while let Some(func) = funcs.pop() {
            if let Err(e) = func() {
                warn!("BPF hook detach failed: {:#}", e);
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(anyhow::anyhow!(
                "{} BPF hook detach errors: {}",
                errors.len(),
                errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }
    }

    /// 1. Sends shutdown signal via the watch channel.
    /// 2. Drains defer functions in reverse (LIFO) order, continuing past failures.
    /// 3. If `bpf_owned`, calls [`EbpfBackend::cleanup`].
    ///
    /// Errors are collected and returned as a combined error.
    ///
    /// [`EbpfBackend::cleanup`]: crate::ebpf::EbpfBackend::cleanup
    pub async fn close(&self) -> anyhow::Result<()> {
        // Ignore the error when no receivers exist.
        let _ = self.closed_tx.send(true);

        let mut errors: Vec<anyhow::Error> = Vec::new();

        {
            let mut funcs = self.defer_funcs.lock().expect("defer_funcs lock poisoned");

            while let Some(func) = funcs.pop() {
                if let Err(e) = func() {
                    warn!("Deferred cleanup function failed: {:#}", e);
                    errors.push(e);
                }
            }
        }

        if self.bpf_owned.load(Ordering::SeqCst) {
            let backend = {
                let mut guard = self.bpf.lock().expect("bpf lock poisoned");
                guard.take()
            };
            if let Some(mut backend) = backend
                && let Err(e) = backend.cleanup().await
            {
                warn!("BPF cleanup failed: {:#}", e);
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(anyhow::anyhow!(
                "{} close errors: {}",
                errors.len(),
                errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }
    }

    /// Reload handoff: transfers BPF ownership to the new instance,
    /// avoiding expensive cleanup and re-initialization.
    /// Sets `bpf_ejected = true`, `bpf_owned = false`.
    /// Returns `None` if already ejected or never injected.
    pub fn eject_bpf(&self) -> Option<Box<dyn EbpfBackend>> {
        if self.bpf_ejected.swap(true, Ordering::SeqCst) {
            return None;
        }

        self.bpf_owned.store(false, Ordering::SeqCst);
        self.bpf.lock().expect("bpf lock poisoned").take()
    }

    /// Reload handoff: accept BPF from the old instance. Sets `bpf_owned = true`.
    pub fn inject_bpf(&self, bpf: Box<dyn EbpfBackend>) {
        self.bpf_owned.store(true, Ordering::SeqCst);
        *self.bpf.lock().expect("bpf lock poisoned") = Some(bpf);
    }

    /// Lock the BPF mutex and return a guard for read/write access.
    /// Returns `None` if no backend is present. Lock released on drop.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(mut guard) = core.peek_bpf() {
    ///     guard.backend_mut().set_param(ParamKey::TproxyPort, 12345)?;
    /// }
    /// ```
    pub fn peek_bpf(&self) -> Option<BpfGuard<'_>> {
        let guard = self.bpf.lock().expect("bpf lock poisoned");
        if guard.is_some() {
            Some(BpfGuard { guard })
        } else {
            None
        }
    }

    /// Has the close signal been sent?
    /// Once closed, `add_defer_func` and `add_managed_bpf_hook_cleanup`
    /// will refuse new registrations.
    pub fn is_closed(&self) -> bool {
        *self.closed_rx.borrow()
    }

    /// Is this a reload instance?
    pub fn is_reload(&self) -> bool {
        self.is_reload
    }

    /// Has BPF been ejected?
    pub fn is_bpf_ejected(&self) -> bool {
        self.bpf_ejected.load(Ordering::SeqCst)
    }

    /// Does this instance own the BPF backend?
    pub fn is_bpf_owned(&self) -> bool {
        self.bpf_owned.load(Ordering::SeqCst)
    }

    /// Mark as retired — should no longer accept new work.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
    }

    /// Has this instance been retired?
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    /// Clone of the shutdown watch receiver. Observers call `changed()`
    /// to be notified when the control plane closes.
    pub fn closed_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.closed_rx.clone()
    }
}

impl Drop for ControlPlaneCore {
    fn drop(&mut self) {
        // If the core is dropped without explicit close(), drain
        // defer funcs as a best-effort cleanup. We cannot log errors
        // from FnOnce closures via the normal anyhow path, so failures
        // here are logged as warnings and swallowed.
        if !*self.closed_rx.borrow()
            && !self.retired.load(Ordering::Relaxed)
            && let Ok(mut funcs) = self.defer_funcs.lock()
        {
            while let Some(func) = funcs.pop() {
                if let Err(e) = func() {
                    warn!("Deferred cleanup in Drop failed: {:#}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::mock::MockEbpfBackend;
    use std::sync::Arc;

    #[test]
    fn test_new_non_reload() {
        let core = ControlPlaneCore::new(false);
        assert!(!core.is_reload());
        assert!(core.is_bpf_owned());
        assert!(!core.is_closed());
        assert!(!core.is_retired());
        assert_eq!(core.peek_bpf().map(|_| ()), None);
    }

    #[test]
    fn test_new_reload() {
        let before = ControlPlaneCore::current_flip();

        let core = ControlPlaneCore::new(true);
        assert!(core.is_reload());
        assert!(!core.is_bpf_owned());
        let expected = 1u8.wrapping_sub(before);
        assert_eq!(core.flip(), expected);
    }

    #[test]
    fn test_new_respects_static_flip() {
        let a = ControlPlaneCore::new(false);
        let b = ControlPlaneCore::new(false);
        assert_eq!(a.flip(), b.flip());
    }

    #[test]
    fn test_current_flip_initial() {
        // CURRENT_FLIP starts at 0 per the static definition, but tests run
        // in parallel, so only the range is checked.
        let val = ControlPlaneCore::current_flip();
        assert!(val == 0 || val == 1, "flip must be 0 or 1, got {}", val);
    }

    #[test]
    fn test_flip_toggle_roundtrip() {
        let initial = ControlPlaneCore::current_flip();
        ControlPlaneCore::toggle_flip();
        assert_eq!(ControlPlaneCore::current_flip(), 1 - initial);
        ControlPlaneCore::toggle_flip();
        assert_eq!(ControlPlaneCore::current_flip(), initial);
    }

    #[test]
    fn test_toggle_flip_xor_semantics() {
        let before = ControlPlaneCore::current_flip();
        ControlPlaneCore::toggle_flip();
        ControlPlaneCore::toggle_flip();
        assert_eq!(ControlPlaneCore::current_flip(), before);
    }

    #[test]
    fn test_defer_stack_reverse_order() {
        let core = ControlPlaneCore::new(false);
        let results = Arc::new(Mutex::new(Vec::new()));

        let r1 = Arc::clone(&results);
        assert!(core.add_defer_func(move || {
            r1.lock().unwrap().push(1);
            Ok(())
        }));

        let r2 = Arc::clone(&results);
        assert!(core.add_defer_func(move || {
            r2.lock().unwrap().push(2);
            Ok(())
        }));

        let r3 = Arc::clone(&results);
        assert!(core.add_defer_func(move || {
            r3.lock().unwrap().push(3);
            Ok(())
        }));

        // Drain via close (LIFO → 3, 2, 1)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(core.close()).unwrap();

        let guard = results.lock().unwrap();
        assert_eq!(
            *guard,
            vec![3, 2, 1],
            "defer funcs must execute in reverse order"
        );
    }

    #[test]
    fn test_close_transitions_state() {
        let core = ControlPlaneCore::new(false);
        assert!(!core.is_closed());

        assert!(core.add_defer_func(|| Ok(())));

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(core.close()).unwrap();

        assert!(core.is_closed());
        assert!(!core.add_defer_func(|| Ok(())));
    }

    #[test]
    fn test_close_is_idempotent() {
        let core = ControlPlaneCore::new(false);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let c = Arc::clone(&counter);
        core.add_defer_func(move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(core.close()).unwrap();
        rt.block_on(core.close()).unwrap(); // Second close is safe

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_close_with_error_in_defer() {
        let core = ControlPlaneCore::new(false);

        core.add_defer_func(|| Ok(()));
        core.add_defer_func(|| anyhow::bail!("intentional test error"));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(core.close());
        assert!(result.is_err(), "close should propagate defer errors");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("intentional test error")
        );
    }

    #[test]
    fn test_close_bpf_cleanup_when_owned() {
        let core = ControlPlaneCore::new(false);
        core.inject_bpf(Box::new(MockEbpfBackend::new()));

        let rt = tokio::runtime::Runtime::new().unwrap();
        // Should succeed — MockEbpfBackend::cleanup is infallible
        rt.block_on(core.close()).unwrap();
    }

    #[test]
    fn test_inject_then_eject() {
        let core = ControlPlaneCore::new(false);

        assert!(core.peek_bpf().is_none());

        core.inject_bpf(Box::new(MockEbpfBackend::new()));
        assert!(core.is_bpf_owned());
        {
            let guard = core.peek_bpf();
            assert!(guard.is_some());
        }

        let ejected = core.eject_bpf();
        assert!(ejected.is_some());
        assert!(core.is_bpf_ejected());
        assert!(!core.is_bpf_owned());
        assert!(core.peek_bpf().is_none());
    }

    #[test]
    fn test_eject_only_once() {
        let core = ControlPlaneCore::new(false);
        core.inject_bpf(Box::new(MockEbpfBackend::new()));

        let first = core.eject_bpf();
        assert!(first.is_some());

        let second = core.eject_bpf();
        assert!(second.is_none(), "second eject must return None");
    }

    #[test]
    fn test_eject_without_inject_returns_none() {
        let core = ControlPlaneCore::new(false);
        assert!(core.eject_bpf().is_none());
    }

    #[test]
    fn test_detach_bpf_hooks_reverse_order() {
        let core = ControlPlaneCore::new(false);
        let results = Arc::new(Mutex::new(Vec::new()));

        let r1 = Arc::clone(&results);
        core.add_bpf_hook_detach(move || {
            r1.lock().unwrap().push("first".to_string());
            Ok(())
        });

        let r2 = Arc::clone(&results);
        core.add_bpf_hook_detach(move || {
            r2.lock().unwrap().push("second".to_string());
            Ok(())
        });

        core.detach_bpf_hooks().unwrap();

        let guard = results.lock().unwrap();
        assert_eq!(
            *guard,
            vec!["second", "first"],
            "detach must be reverse order"
        );
    }

    #[test]
    fn test_detach_bpf_hooks_idempotent() {
        let core = ControlPlaneCore::new(false);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let c = Arc::clone(&counter);
        core.add_bpf_hook_detach(move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        core.detach_bpf_hooks().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second call is a no-op
        core.detach_bpf_hooks().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_detach_bpf_hooks_continues_on_error() {
        let core = ControlPlaneCore::new(false);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let c = Arc::clone(&counter);
        core.add_bpf_hook_detach(move || {
            c.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("first failed")
        });

        let c2 = Arc::clone(&counter);
        core.add_bpf_hook_detach(move || {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let result = core.detach_bpf_hooks();
        assert!(result.is_err());
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "both hooks should execute despite error"
        );
    }

    #[test]
    fn test_managed_cleanup_executes_once() {
        let core = ControlPlaneCore::new(false);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let c = Arc::clone(&counter);
        core.add_managed_bpf_hook_cleanup(move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        // Detach first (SIGTERM path)
        core.detach_bpf_hooks().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Then close (defer path) — should be a no-op for managed hooks
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(core.close()).unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "managed cleanup must execute at most once"
        );
    }

    #[test]
    fn test_retire_and_check() {
        let core = ControlPlaneCore::new(false);
        assert!(!core.is_retired());
        core.retire();
        assert!(core.is_retired());
    }

    #[tokio::test]
    async fn test_closed_receiver_signals_on_close() {
        let core = ControlPlaneCore::new(false);
        let rx = core.closed_receiver();

        assert!(!*rx.borrow());

        core.close().await.unwrap();

        assert!(*rx.borrow());
    }

    #[test]
    fn test_drop_drains_defer_funcs() {
        let results = Arc::new(Mutex::new(Vec::new()));

        {
            let core = ControlPlaneCore::new(false);
            let r = Arc::clone(&results);
            core.add_defer_func(move || {
                r.lock().unwrap().push("dropped".to_string());
                Ok(())
            });
            // core is dropped here without explicit close()
        }

        let guard = results.lock().unwrap();
        assert!(
            guard.contains(&"dropped".to_string()),
            "Drop should drain defer funcs"
        );
    }
}
