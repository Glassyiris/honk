use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct ProjectionLifecycle {
    terminated: AtomicBool,
    termination: tokio::sync::Notify,
}

impl ProjectionLifecycle {
    pub(super) fn running() -> Arc<Self> {
        Arc::new(Self {
            terminated: AtomicBool::new(false),
            termination: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn finish(&self) {
        self.terminated.store(true, Ordering::Release);
        self.termination.notify_waiters();
    }

    pub(super) async fn wait(&self) {
        loop {
            let terminated = self.termination.notified();
            if self.terminated.load(Ordering::Acquire) {
                return;
            }
            terminated.await;
        }
    }
}

pub(super) struct TerminationGuard(Arc<ProjectionLifecycle>);

impl TerminationGuard {
    pub(super) fn new(lifecycle: Arc<ProjectionLifecycle>) -> Self {
        Self(lifecycle)
    }
}

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[cfg(test)]
pub(super) struct ProjectionTerminationProbe(Arc<ProjectionLifecycle>);

#[cfg(test)]
impl ProjectionTerminationProbe {
    pub(super) fn new(lifecycle: Arc<ProjectionLifecycle>) -> Self {
        Self(lifecycle)
    }

    pub(super) fn is_terminated(&self) -> bool {
        self.0.terminated.load(Ordering::Acquire)
    }

    pub(super) async fn wait(&self) {
        self.0.wait().await;
    }
}
