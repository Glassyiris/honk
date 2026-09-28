//! Source-owned, optional evidence for one observed business operation.

#[cfg(feature = "flow-observation")]
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "flow-observation")]
use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowContext {
    pub flow_id: Uuid,
    pub generation: u64,
    pub attempt_id: Option<Uuid>,
    pub lookup_id: Option<Uuid>,
    pub dns_purpose: &'static str,
}

#[cfg(feature = "flow-observation")]
#[derive(Clone)]
pub struct FlowObserver {
    context: FlowContext,
    callback: Arc<dyn Fn(FlowContext, FlowEvent) + Send + Sync>,
    milestones: Arc<std::sync::atomic::AtomicU8>,
}

#[cfg(feature = "flow-observation")]
impl std::fmt::Debug for FlowObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FlowObserver")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "flow-observation")]
impl FlowObserver {
    pub fn new(
        context: FlowContext,
        callback: Arc<dyn Fn(FlowContext, FlowEvent) + Send + Sync>,
    ) -> Self {
        Self {
            context,
            callback,
            milestones: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        }
    }

    pub fn context(&self) -> FlowContext {
        self.context
    }

    pub fn with_context(&self, context: FlowContext) -> Self {
        if context == self.context {
            return self.clone();
        }
        Self::new(context, Arc::clone(&self.callback))
    }

    /// Callbacks must remain bounded, synchronous and non-reentrant, with no I/O.
    pub fn publish(&self, event: FlowEvent) {
        (self.callback)(self.context, event);
    }

    /// Shared streams may carry many business flows; deduplicate only this context.
    pub fn milestone_once(&self, milestone: &'static str) {
        let bit = match milestone {
            "transport_ready" => 1,
            "target_request_sent" => 2,
            "target_confirmed" => 4,
            _ => return,
        };
        if self
            .milestones
            .fetch_or(bit, std::sync::atomic::Ordering::Relaxed)
            & bit
            == 0
        {
            self.publish(FlowEvent::Milestone { milestone });
        }
    }

    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        scope(Some(self.clone()), future)
    }

    pub fn sync_scope<T>(&self, build: impl FnOnce() -> T) -> T {
        FLOW_OBSERVER.sync_scope(Some(self.clone()), build)
    }
}

#[cfg(feature = "flow-observation")]
tokio::task_local! {
    static FLOW_OBSERVER: Option<FlowObserver>;
    static SUPPRESSED: bool;
    static REQUEST_WRITE: RequestWrite;
}

#[cfg(feature = "flow-observation")]
pub fn current() -> Option<FlowObserver> {
    if is_suppressed() {
        return None;
    }
    FLOW_OBSERVER.try_with(Clone::clone).ok().flatten()
}

#[cfg(feature = "flow-observation")]
pub(crate) fn is_suppressed() -> bool {
    SUPPRESSED
        .try_with(|suppressed| *suppressed)
        .unwrap_or(false)
}

#[cfg(feature = "flow-observation")]
pub(crate) fn scope<F: Future>(
    observer: Option<FlowObserver>,
    future: F,
) -> impl Future<Output = F::Output> {
    FLOW_OBSERVER.scope(observer, future)
}

#[cfg(feature = "flow-observation")]
pub fn without<F: Future>(future: F) -> impl Future<Output = F::Output> {
    SUPPRESSED.scope(true, scope(None, future))
}

#[cfg(feature = "flow-observation")]
pub fn milestone(milestone: &'static str) {
    if let Some(observer) = current() {
        observer.milestone_once(milestone);
    }
}

#[cfg(feature = "flow-observation")]
#[derive(Clone, Debug)]
pub(crate) struct RequestWrite {
    observer: FlowObserver,
    state: Arc<parking_lot::Mutex<RequestWriteState>>,
}

#[cfg(feature = "flow-observation")]
#[derive(Debug, Default)]
struct RequestWriteState {
    required: u64,
    delivered: u64,
    finished: bool,
}

#[cfg(feature = "flow-observation")]
impl RequestWrite {
    pub(crate) fn current() -> Option<Self> {
        if is_suppressed() {
            return None;
        }
        REQUEST_WRITE.try_with(Clone::clone).ok()
    }

    pub(crate) fn defer(&self, position: u64) {
        self.state.lock().required = position;
    }

    pub(crate) fn delivered(&self, position: u64) {
        let publish = {
            let mut state = self.state.lock();
            state.delivered = state.delivered.max(position);
            state.finished && state.delivered >= state.required
        };
        if publish {
            self.observer.milestone_once("target_request_sent");
        }
    }

    fn finish(&self) {
        let publish = {
            let mut state = self.state.lock();
            state.finished = true;
            state.delivered >= state.required
        };
        if publish {
            self.observer.milestone_once("target_request_sent");
        }
    }
}

#[cfg(feature = "flow-observation")]
/// A buffered transport may defer the event until the actual frame writer flushes.
pub(crate) async fn request_write<T, E>(
    future: std::pin::Pin<&mut impl Future<Output = Result<T, E>>>,
) -> Result<T, E> {
    let Some(observer) = current() else {
        return future.await;
    };
    let request = RequestWrite {
        observer,
        state: Arc::new(parking_lot::Mutex::new(RequestWriteState::default())),
    };
    let result = REQUEST_WRITE.scope(request.clone(), future).await;
    if result.is_ok() {
        request.finish();
    }
    result
}
#[expect(
    clippy::large_enum_variant,
    reason = "Synchronous callbacks avoid a separate allocation for every DNS event"
)]
#[derive(Debug)]
pub enum FlowEvent {
    Transport {
        attempt_id: Uuid,
        server_addr: Option<SocketAddr>,
        status: &'static str,
        resolution_location: &'static str,
        error: Option<&'static str>,
    },
    TransportAttached {
        server_addr: Option<SocketAddr>,
        resolution_location: &'static str,
    },
    Milestone {
        milestone: &'static str,
    },
    Session {
        reason: &'static str,
        error: Option<&'static str>,
    },
    Dns(DnsLookup),
    Gap(&'static str),
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsLookup {
    pub lookup_id: Uuid,
    pub parent_lookup_id: Option<Uuid>,
    pub attempt_id: Option<Uuid>,
    pub purpose: &'static str,
    pub name: String,
    pub qtype: String,
    pub source: &'static str,
    pub upstream_transport: Option<&'static str>,
    pub carrier_transport: Option<&'static str>,
    pub cache: &'static str,
    pub cache_entry_id: Option<String>,
    pub upstream: Option<String>,
    pub route_evaluation_ids: Vec<String>,
    pub status: &'static str,
    pub addresses: Vec<IpAddr>,
    pub selected_ip: Option<IpAddr>,
    pub error: Option<&'static str>,
}

#[cfg(feature = "flow-observation")]
/// Lookup facts captured by this resolution operation, never recovered by name.
pub struct LookupSelection {
    observer: FlowObserver,
    lookups: Arc<parking_lot::Mutex<Vec<(FlowContext, DnsLookup)>>>,
}

#[cfg(feature = "flow-observation")]
impl LookupSelection {
    pub fn selected_ip(&self, ip: IpAddr) {
        let (selected, ambiguous) = {
            let lookups = self.lookups.lock();
            let mut matches = lookups
                .iter()
                .filter(|(_, lookup)| lookup.addresses.contains(&ip));
            let selected = matches.next();
            let ambiguous = selected.is_some_and(|(_, selected)| {
                matches.any(|(_, other)| other.lookup_id != selected.lookup_id)
            });
            (selected.cloned(), ambiguous)
        };
        if ambiguous {
            self.observer.publish(FlowEvent::Gap("not_instrumented"));
            return;
        }
        if let Some((context, mut lookup)) = selected {
            lookup.selected_ip = Some(ip);
            (self.observer.callback)(context, FlowEvent::Dns(lookup));
        }
    }
}

#[cfg(feature = "flow-observation")]
/// Preserve source identity until a consumer chooses an address from the result.
pub async fn observe_resolution<F: Future>(future: F) -> (F::Output, Option<LookupSelection>) {
    let future = std::pin::pin!(future);
    let Some(observer) = current() else {
        return (future.await, None);
    };
    let context = observer.context();
    let lookups = Arc::new(parking_lot::Mutex::new(
        Vec::<(FlowContext, DnsLookup)>::new(),
    ));
    let captured = Arc::clone(&lookups);
    let output = observer.clone();
    let nested = FlowObserver::new(
        context,
        Arc::new(move |source, event| {
            if let FlowEvent::Dns(lookup) = &event
                && lookup.parent_lookup_id == context.lookup_id
                && lookup.purpose == context.dns_purpose
                && lookup.selected_ip.is_none()
                && !lookup.addresses.is_empty()
            {
                let overflow = {
                    let mut captured = captured.lock();
                    if captured.len() == 4 || lookup.addresses.len() > 32 {
                        true
                    } else {
                        captured.push((source, lookup.clone()));
                        false
                    }
                };
                if overflow {
                    output.publish(FlowEvent::Gap("buffer_overflow"));
                }
            }
            (output.callback)(source, event);
        }),
    );
    let result = nested.scope(future).await;
    (result, Some(LookupSelection { observer, lookups }))
}

#[cfg(feature = "flow-observation")]
/// One real physical attempt. Capture before starting I/O, not before admission.
pub struct TransportAttempt {
    observer: FlowObserver,
    attempt_id: Uuid,
    server_addr: Option<SocketAddr>,
    resolution_location: &'static str,
    finished: bool,
}

#[cfg(feature = "flow-observation")]
impl TransportAttempt {
    pub fn start(
        server_addr: Option<SocketAddr>,
        resolution_location: &'static str,
    ) -> Option<Self> {
        let observer = current()?;
        let attempt = Self {
            observer,
            attempt_id: Uuid::new_v4(),
            server_addr,
            resolution_location,
            finished: false,
        };
        attempt.publish("started", None);
        Some(attempt)
    }

    pub fn finish(&mut self, status: &'static str, error: Option<&'static str>) {
        if !self.finished {
            self.finished = true;
            self.publish(status, error);
        }
    }

    fn publish(&self, status: &'static str, error: Option<&'static str>) {
        self.observer.publish(FlowEvent::Transport {
            attempt_id: self.attempt_id,
            server_addr: self.server_addr,
            status,
            resolution_location: self.resolution_location,
            error,
        });
    }
}

#[cfg(feature = "flow-observation")]
impl Drop for TransportAttempt {
    fn drop(&mut self) {
        self.finish("cancelled", Some("cancelled"));
    }
}

/// Inert twin: uninhabited types keep `Option<_>` fields zero-sized and every
/// hook folds away, so call sites need no feature gates.
#[cfg(not(feature = "flow-observation"))]
mod inert {
    use std::future::Future;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;

    use futures_util::FutureExt;

    use super::{FlowContext, FlowEvent};

    #[derive(Clone, Debug)]
    pub enum FlowObserver {}

    impl FlowObserver {
        #[inline]
        pub fn context(&self) -> FlowContext {
            match *self {}
        }

        #[inline]
        pub fn with_context(&self, _context: FlowContext) -> Self {
            match *self {}
        }

        #[inline]
        pub fn publish(&self, _event: FlowEvent) {
            match *self {}
        }

        #[inline]
        pub fn milestone_once(&self, _milestone: &'static str) {
            match *self {}
        }

        #[inline]
        pub fn scope<F: Future>(&self, _future: F) -> F {
            match *self {}
        }

        #[inline]
        pub fn sync_scope<T>(&self, _build: impl FnOnce() -> T) -> T {
            match *self {}
        }
    }

    #[inline]
    pub fn current() -> Option<FlowObserver> {
        None
    }

    #[inline]
    pub(crate) fn is_suppressed() -> bool {
        false
    }

    // Only the rprx VMess relay re-scopes a captured observer in inert builds.
    #[cfg(feature = "rprx")]
    #[inline]
    pub(crate) fn scope<F: Future>(_observer: Option<FlowObserver>, future: F) -> F {
        future
    }

    #[inline]
    pub fn without<F: Future>(future: F) -> F {
        future
    }

    #[inline]
    pub fn milestone(_milestone: &'static str) {}

    #[derive(Clone, Debug)]
    pub(crate) enum RequestWrite {}

    impl RequestWrite {
        #[inline]
        pub(crate) fn current() -> Option<Self> {
            None
        }

        #[inline]
        pub(crate) fn defer(&self, _position: u64) {
            match *self {}
        }

        #[inline]
        pub(crate) fn delivered(&self, _position: u64) {
            match *self {}
        }
    }

    #[inline]
    pub(crate) fn request_write<F: Future>(future: Pin<&mut F>) -> Pin<&mut F> {
        future
    }

    pub enum LookupSelection {}

    impl LookupSelection {
        #[inline]
        pub fn selected_ip(&self, _ip: IpAddr) {
            match *self {}
        }
    }

    #[inline]
    pub fn observe_resolution<F: Future>(
        future: F,
    ) -> impl Future<Output = (F::Output, Option<LookupSelection>)> {
        future.map(|output| (output, None))
    }

    pub enum TransportAttempt {}

    impl TransportAttempt {
        #[inline]
        pub fn start(
            _server_addr: Option<SocketAddr>,
            _resolution_location: &'static str,
        ) -> Option<Self> {
            None
        }

        #[inline]
        pub fn finish(&mut self, _status: &'static str, _error: Option<&'static str>) {
            match *self {}
        }
    }

    const _: () = assert!(size_of::<Option<FlowObserver>>() == 0);
    const _: () = assert!(size_of::<Option<TransportAttempt>>() == 0);
}

#[cfg(all(not(feature = "flow-observation"), feature = "rprx"))]
pub(crate) use inert::scope;
#[cfg(not(feature = "flow-observation"))]
pub use inert::{
    FlowObserver, LookupSelection, TransportAttempt, current, milestone, observe_resolution,
    without,
};
#[cfg(not(feature = "flow-observation"))]
pub(crate) use inert::{RequestWrite, is_suppressed, request_write};

#[cfg(all(test, feature = "flow-observation"))]
mod tests;
