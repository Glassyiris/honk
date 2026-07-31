use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{BuildFailure, LifecycleSlot, SlotState};

pub(super) struct CloseGuard<'a, T> {
    slot: &'a LifecycleSlot<T>,
    armed: bool,
}

impl<'a, T> CloseGuard<'a, T> {
    pub(super) fn new(slot: &'a LifecycleSlot<T>) -> Self {
        Self { slot, armed: true }
    }

    pub(super) fn complete(mut self) {
        {
            let mut inner = self.slot.inner.lock();
            inner.state = SlotState::Closed;
        }
        self.slot.close_count.fetch_add(1, Ordering::SeqCst);
        self.armed = false;
        self.slot.changed.notify_waiters();
    }
}

impl<T> Drop for CloseGuard<'_, T> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut inner = self.slot.inner.lock();
            if let SlotState::Closing { owner, .. } = &mut inner.state {
                *owner = false;
            }
        }
        self.slot.changed.notify_waiters();
    }
}

pub(super) struct BuildGuard<'a, T> {
    slot: &'a LifecycleSlot<T>,
    generation: u64,
    armed: bool,
}

impl<'a, T> BuildGuard<'a, T> {
    pub(super) fn new(slot: &'a LifecycleSlot<T>, generation: u64) -> Self {
        Self {
            slot,
            generation,
            armed: true,
        }
    }

    pub(super) fn publish(mut self, value: T) -> Arc<T> {
        let value = Arc::new(value);
        {
            let mut inner = self.slot.inner.lock();
            inner.state = SlotState::Ready(Arc::clone(&value));
        }
        self.armed = false;
        self.slot.changed.notify_waiters();
        value
    }

    pub(super) fn fail(mut self, message: Arc<str>) {
        self.record_failure(message);
        self.armed = false;
    }

    fn record_failure(&self, message: Arc<str>) {
        {
            let mut inner = self.slot.inner.lock();
            if matches!(
                inner.state,
                SlotState::Building { generation } if generation == self.generation
            ) {
                inner.state = SlotState::Closed;
                inner.last_failure = Some(BuildFailure {
                    generation: self.generation,
                    message,
                });
            }
        }
        self.slot.changed.notify_waiters();
    }
}

impl<T> Drop for BuildGuard<'_, T> {
    fn drop(&mut self) {
        if self.armed {
            self.record_failure(Arc::from("transport initialization cancelled"));
        }
    }
}
