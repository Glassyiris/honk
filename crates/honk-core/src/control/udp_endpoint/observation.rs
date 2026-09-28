//! Flow evidence one UDP endpoint reports, and the terminal outcome it shares
//! with its initializer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use honk_outbound::runtime::flow_observation::FlowObserver;
use parking_lot::Mutex;

use super::UdpEndpointPool;
use crate::observe::flows::FlowGuard;

pub(in crate::control) struct NativeUdpTerminal {
    flow: Arc<FlowGuard>,
    state: Mutex<NativeUdpState>,
}

struct NativeUdpState {
    outcome: Option<(&'static str, &'static str)>,
    cleaned: Option<bool>,
    initializer_done: bool,
}

/// The terminal outcome an endpoint shares with its initializer.
pub(in crate::control) type SharedTerminal = Arc<NativeUdpTerminal>;

pub(in crate::control) struct NativeInitializerGuard {
    terminal: SharedTerminal,
    completed: bool,
}

impl NativeInitializerGuard {
    pub(in crate::control) fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for NativeInitializerGuard {
    fn drop(&mut self) {
        let mut state = self.terminal.state.lock();
        if !self.completed {
            state
                .outcome
                .get_or_insert(("failed", "initializer_cancelled"));
        }
        state.initializer_done = true;
        self.terminal.publish(&state);
    }
}

impl NativeUdpTerminal {
    pub(super) fn new(flow: Arc<FlowGuard>, initializer_done: bool) -> SharedTerminal {
        Arc::new(Self {
            flow,
            state: Mutex::new(NativeUdpState {
                outcome: None,
                cleaned: None,
                initializer_done,
            }),
        })
    }

    pub(in crate::control) fn initializer(self: &Arc<Self>) -> NativeInitializerGuard {
        self.state.lock().initializer_done = false;
        NativeInitializerGuard {
            terminal: Arc::clone(self),
            completed: false,
        }
    }

    pub(super) fn packet_drop(&self, reason: &'static str) {
        self.flow.datapath("userspace", "drop", reason, None);
    }

    pub(in crate::control) fn outcome(&self, state: &'static str, reason: &'static str) {
        let mut terminal = self.state.lock();
        if reason == "cleanup_failed" {
            terminal.outcome = Some((state, reason));
        } else {
            terminal.outcome.get_or_insert((state, reason));
        }
        self.publish(&terminal);
    }

    pub(super) fn cleaned(&self, success: bool) {
        let mut terminal = self.state.lock();
        terminal.cleaned = Some(terminal.cleaned.unwrap_or(true) && success);
        self.publish(&terminal);
    }

    fn publish(&self, terminal: &NativeUdpState) {
        if !terminal.initializer_done {
            return;
        }
        match (terminal.outcome, terminal.cleaned) {
            (_, Some(false)) => self.flow.finish("failed", "cleanup_failed"),
            (Some((state, reason)), Some(true)) => self.flow.finish(state, reason),
            _ => {}
        }
    }
}

#[derive(Default)]
pub(in crate::control) struct EndpointObservation {
    flow: Option<Arc<FlowGuard>>,
    pool: Weak<UdpEndpointPool>,
    observer: Option<FlowObserver>,
    terminal: Option<SharedTerminal>,
    received_reply: AtomicBool,
}

impl EndpointObservation {
    pub(in crate::control) fn set_flow(
        &mut self,
        flow: Option<Arc<FlowGuard>>,
        pool: &Arc<UdpEndpointPool>,
        terminal: Option<SharedTerminal>,
    ) {
        self.terminal =
            terminal.or_else(|| flow.clone().map(|flow| NativeUdpTerminal::new(flow, true)));
        self.flow = flow;
        self.pool = Arc::downgrade(pool);
    }

    pub(in crate::control) fn set_observer(&mut self, observer: Option<FlowObserver>) {
        self.observer = observer;
    }

    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.flow.as_ref()
    }

    pub(super) fn observer(&self) -> Option<&FlowObserver> {
        self.observer.as_ref()
    }

    pub(super) fn terminal(&self) -> Option<&SharedTerminal> {
        self.terminal.as_ref()
    }

    pub(super) fn received_reply(&self) -> bool {
        self.received_reply.load(Ordering::Relaxed)
    }

    pub(super) fn dropped(&self, reason: &'static str, error: Option<&'static str>) {
        if let Some(flow) = &self.flow {
            flow.datapath("userspace", "drop", reason, error);
        }
    }

    pub(super) fn reply_received(&self) {
        if let Some(flow) = &self.flow {
            self.received_reply.store(true, Ordering::Relaxed);
            if flow.first_reply() {
                flow.transition("active", "reply_received", "first_reply", Some(true));
            }
        }
    }

    pub(super) fn finish(&self, state: &'static str, reason: &'static str) {
        if let Some(terminal) = &self.terminal {
            let shutdown = self
                .pool
                .upgrade()
                .is_some_and(|pool| pool.terminal.load(Ordering::Acquire));
            if shutdown {
                terminal.outcome("closed", "shutdown");
            } else {
                terminal.outcome(state, reason);
            }
        }
    }
}
