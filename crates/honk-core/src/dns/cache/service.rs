use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{CacheCounters, DnsCacheService, PublicationEpoch, lock};

pub(crate) struct PublicationFlushGuard {
    service: Arc<DnsCacheService>,
    persistence: Option<crate::dns::persist::DnsCachePersister>,
}

impl PublicationFlushGuard {
    pub(crate) const fn persistence(&self) -> Option<&crate::dns::persist::DnsCachePersister> {
        self.persistence.as_ref()
    }
}

impl Drop for PublicationFlushGuard {
    fn drop(&mut self) {
        self.service.finish_flush();
    }
}

impl DnsCacheService {
    pub(crate) fn publication_epoch(&self) -> PublicationEpoch {
        PublicationEpoch(lock(&self.refresh_tasks).publication_epoch)
    }

    pub(crate) fn begin_flush(self: &Arc<Self>) -> PublicationFlushGuard {
        let mut registry = lock(&self.refresh_tasks);
        registry.publication_epoch = registry.publication_epoch.saturating_add(1);
        registry.accepting_publications = false;
        self.clear();
        PublicationFlushGuard {
            service: Arc::clone(self),
            persistence: lock(&self.persister).clone(),
        }
    }

    fn finish_flush(&self) {
        let mut registry = lock(&self.refresh_tasks);
        registry.publication_epoch = registry.publication_epoch.saturating_add(1);
        registry.accepting_publications = true;
    }

    pub(crate) fn singleflight(&self) -> super::Singleflight {
        self.flights.clone()
    }

    pub fn counters(&self) -> CacheCounters {
        CacheCounters {
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            stale: self.counters.stale.load(Ordering::Relaxed),
        }
    }

    pub fn flight_counters(&self) -> crate::dns::singleflight::FlightCounters {
        self.flights.counters()
    }

    pub fn active_flights(&self) -> usize {
        self.flights.active_len()
    }

    pub(crate) fn spawn_refresh<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut registry = lock(&self.refresh_tasks);
        while registry.tasks.try_join_next().is_some() {}
        if registry.closed {
            return false;
        }
        self.active_refresh_tasks.fetch_add(1, Ordering::Relaxed);
        let active = Arc::clone(&self.active_refresh_tasks);
        registry.tasks.spawn(async move {
            let _guard = ActiveGuard(active);
            future.await;
        });
        true
    }

    pub fn refresh_task_count(&self) -> usize {
        self.active_refresh_tasks.load(Ordering::Relaxed)
    }

    pub async fn close_refresh_tasks(&self) {
        let mut tasks = {
            let mut registry = lock(&self.refresh_tasks);
            registry.closed = true;
            std::mem::replace(&mut registry.tasks, tokio::task::JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    pub(crate) fn persistence(&self) -> Option<crate::dns::persist::DnsCachePersister> {
        lock(&self.persister).clone()
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
