//! The sink: the loopback server at the far end of every flow and of the warmup.

use super::load::{Server, Side, WARMUP, Workload, lock};
use crate::sys;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct SinkState {
    workload: Mutex<Option<Arc<Workload>>>,
    /// CLOCK_BOOTTIME at which the last connection ended.
    last_end_ns: AtomicU64,
    /// Connections that carried exactly `WARMUP`.
    warmups: AtomicU64,
}

/// The far end of every flow. Without a workload it reads each connection to EOF and counts
/// the warmups among them; with one, each new connection is a flow of it.
pub struct Sink {
    pub server: Server,
    state: Arc<SinkState>,
}

impl Sink {
    pub fn start(cpus: &[usize]) -> Result<Sink, String> {
        let state = Arc::new(SinkState::default());
        let st = state.clone();
        let server = Server::start("tb-sink", cpus, move |mut s, _| {
            let workload = lock(&st.workload).clone();
            match workload {
                Some(w) => w.run(s, Side::Sink),
                None => {
                    if io::copy(&mut s, &mut io::sink()).is_ok_and(|n| n == WARMUP.len() as u64) {
                        st.warmups.fetch_add(1, Relaxed);
                    }
                }
            }
            st.last_end_ns.store(sys::boottime_ns(), Relaxed);
        })?;
        Ok(Sink { server, state })
    }

    pub fn set_workload(&self, w: Option<Arc<Workload>>) {
        *lock(&self.state.workload) = w;
    }

    pub fn last_end_ns(&self) -> u64 {
        self.state.last_end_ns.load(Relaxed)
    }

    /// Warmup connections read to their end so far.
    pub fn warmups(&self) -> u64 {
        self.state.warmups.load(Relaxed)
    }
}
