use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::broadcast;

use super::cache::CacheKey;
use super::cache::OperationKind;
use super::response::ResponseTemplate;

pub(crate) const MAX_ACTIVE_FLIGHTS: usize = 2048;
pub(crate) const MAX_WAITERS_PER_FLIGHT: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlightCounters {
    pub leaders: u64,
    pub waiters: u64,
    pub key_saturation_bypass: u64,
    pub waiter_saturation_bypass: u64,
    pub aborts: u64,
    pub retries: u64,
    pub refreshes: u64,
}

#[derive(Default)]
struct CounterSet {
    leaders: AtomicU64,
    waiters: AtomicU64,
    key_saturation_bypass: AtomicU64,
    waiter_saturation_bypass: AtomicU64,
    aborts: AtomicU64,
    retries: AtomicU64,
    refreshes: AtomicU64,
}

struct FlightEntry {
    sender: broadcast::Sender<Arc<ResponseTemplate>>,
    state: FlightState,
}

enum FlightState {
    Running,
    Published(Arc<ResponseTemplate>),
}

#[derive(Clone, Default)]
pub(crate) struct Singleflight {
    entries: Arc<Mutex<HashMap<CacheKey, FlightEntry>>>,
    counters: Arc<CounterSet>,
}

pub(crate) enum FlightRole {
    Leader(FlightLeader),
    Waiter(FlightWaiter),
    Ready(Arc<ResponseTemplate>),
    Bypass,
}

pub(crate) struct FlightWaiter {
    receiver: broadcast::Receiver<Arc<ResponseTemplate>>,
    counters: Arc<CounterSet>,
}

pub(crate) struct FlightLeader {
    key: Option<CacheKey>,
    entries: Arc<Mutex<HashMap<CacheKey, FlightEntry>>>,
    counters: Arc<CounterSet>,
}

impl Singleflight {
    pub(crate) fn acquire(&self, key: CacheKey) -> FlightRole {
        let mut entries = lock(&self.entries);
        if let Some(entry) = entries.get(&key) {
            if let FlightState::Published(template) = &entry.state {
                self.counters.waiters.fetch_add(1, Ordering::Relaxed);
                return FlightRole::Ready(Arc::clone(template));
            }
            if entry.sender.receiver_count() >= MAX_WAITERS_PER_FLIGHT {
                self.counters
                    .waiter_saturation_bypass
                    .fetch_add(1, Ordering::Relaxed);
                return FlightRole::Bypass;
            }
            self.counters.waiters.fetch_add(1, Ordering::Relaxed);
            return FlightRole::Waiter(FlightWaiter {
                receiver: entry.sender.subscribe(),
                counters: Arc::clone(&self.counters),
            });
        }
        if entries.len() >= MAX_ACTIVE_FLIGHTS {
            self.counters
                .key_saturation_bypass
                .fetch_add(1, Ordering::Relaxed);
            return FlightRole::Bypass;
        }
        let (sender, _) = broadcast::channel(1);
        entries.insert(
            key.clone(),
            FlightEntry {
                sender,
                state: FlightState::Running,
            },
        );
        self.counters.leaders.fetch_add(1, Ordering::Relaxed);
        if matches!(key.operation(), OperationKind::Refresh) {
            self.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        }
        FlightRole::Leader(FlightLeader {
            key: Some(key),
            entries: Arc::clone(&self.entries),
            counters: Arc::clone(&self.counters),
        })
    }

    pub(crate) fn counters(&self) -> FlightCounters {
        FlightCounters {
            leaders: self.counters.leaders.load(Ordering::Relaxed),
            waiters: self.counters.waiters.load(Ordering::Relaxed),
            key_saturation_bypass: self.counters.key_saturation_bypass.load(Ordering::Relaxed),
            waiter_saturation_bypass: self
                .counters
                .waiter_saturation_bypass
                .load(Ordering::Relaxed),
            aborts: self.counters.aborts.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
            refreshes: self.counters.refreshes.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        lock(&self.entries).len()
    }
}

impl FlightWaiter {
    pub(crate) async fn receive(mut self) -> Option<Arc<ResponseTemplate>> {
        match self.receiver.recv().await {
            Ok(template) => Some(template),
            Err(_) => {
                self.counters.retries.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

impl FlightLeader {
    pub(crate) fn publish(&mut self, template: Arc<ResponseTemplate>) {
        let Some(key) = self.key.as_ref() else {
            return;
        };
        if let Some(entry) = lock(&self.entries).get_mut(key) {
            entry.state = FlightState::Published(Arc::clone(&template));
            let _ = entry.sender.send(template);
        }
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let aborted = lock(&self.entries)
            .remove(&key)
            .is_some_and(|entry| matches!(entry.state, FlightState::Running));
        if aborted {
            self.counters.aborts.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
