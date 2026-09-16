use super::*;
use std::sync::atomic::AtomicBool;
mod admission;
mod lifecycle;
mod scheduling;
mod speculative;

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
    draining: AtomicBool,
    stream_permits: Arc<tokio::sync::Semaphore>,
    capacity: usize,
    // Release after taking a stale capacity snapshot, before the caller can park.
    release_on_check: Mutex<Option<SessionPermit<Self>>>,
    // Occupy the last slot after offer's snapshot but before its reservation.
    compete_on_reserve: AtomicBool,
}

impl ReservedTestSession {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            closed: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            capacity,
            release_on_check: Mutex::new(None),
            compete_on_reserve: AtomicBool::new(false),
        })
    }
}

impl ManagedSession for ReservedTestSession {
    fn active_streams(&self) -> usize {
        let active = self.capacity - self.stream_permits.available_permits();
        drop(self.release_on_check.lock().take());
        active
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn state(&self) -> SessionState {
        if self.is_closed() {
            SessionState::Closed
        } else if self.draining.load(Ordering::Relaxed) {
            SessionState::Draining
        } else {
            SessionState::Active
        }
    }
    fn begin_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.state() != SessionState::Active {
            return None;
        }
        let competing = self.compete_on_reserve.load(Ordering::Relaxed).then(|| {
            Arc::clone(&self.stream_permits)
                .try_acquire_owned()
                .unwrap()
        });
        let permit = Arc::clone(&self.stream_permits).try_acquire_owned();
        drop(competing);
        drop(self.release_on_check.lock().take());
        let permit = permit.ok()?;
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        Some(SessionPermit::new(Arc::clone(self), permit))
    }
}
