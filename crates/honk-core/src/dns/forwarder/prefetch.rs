use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinSet;

const MAX_PREFETCH_TASKS: usize = 32;

struct Registry {
    closed: bool,
    tasks: JoinSet<()>,
}

pub(super) struct PrefetchTasks {
    registry: Mutex<Registry>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

struct ActiveTask {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl Drop for ActiveTask {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

impl PrefetchTasks {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self::with_closed(false))
    }

    pub(super) fn closed() -> Arc<Self> {
        Arc::new(Self::with_closed(true))
    }

    fn with_closed(closed: bool) -> Self {
        Self {
            registry: Mutex::new(Registry {
                closed,
                tasks: JoinSet::new(),
            }),
            active: Arc::new(AtomicUsize::new(0)),
            idle: Arc::new(Notify::new()),
        }
    }

    pub(super) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        let mut registry = self.registry.lock();
        while registry.tasks.try_join_next().is_some() {}
        if registry.closed || self.active.load(Ordering::Acquire) >= MAX_PREFETCH_TASKS {
            return false;
        }

        self.active.fetch_add(1, Ordering::AcqRel);
        let active = ActiveTask {
            active: Arc::clone(&self.active),
            idle: Arc::clone(&self.idle),
        };
        registry.tasks.spawn(async move {
            let _active = active;
            task.await;
        });
        true
    }

    pub(super) async fn shutdown(&self) {
        let mut tasks = {
            let mut registry = self.registry.lock();
            registry.closed = true;
            std::mem::take(&mut registry.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    #[cfg(test)]
    pub(super) async fn wait_empty(&self) {
        loop {
            let idle = self.idle.notified();
            if self.active() == 0 {
                return;
            }
            idle.await;
        }
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::PrefetchTasks;

    #[tokio::test]
    async fn bounded_and_closed_registry_rejects_without_detaching() {
        let tasks = PrefetchTasks::new();
        for _ in 0..32 {
            assert!(tasks.spawn(pending()));
        }
        assert!(!tasks.spawn(pending()), "task 33 must be rejected");
        assert_eq!(tasks.active(), 32, "rejection must not detach task 33");

        tasks.shutdown().await;

        assert!(!tasks.spawn(async {}), "closed registry must reject");
        assert_eq!(tasks.active(), 0);
    }
}
