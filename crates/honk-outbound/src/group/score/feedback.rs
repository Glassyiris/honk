use super::evidence::Observation;
use super::{
    FlowSample, MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_DURATION,
    ScoreAttribution, ScoreAuthority, ScoreOutcome, ScorePolicyState, ScoreSelectionContext,
    ScoreSource, StartedCells,
};
use parking_lot::Mutex;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct ScoreFeedback {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    source: ScoreSource,
    probe_scope: u64,
}

impl std::fmt::Debug for ScoreFeedback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScoreFeedback")
            .finish_non_exhaustive()
    }
}
impl ScoreFeedback {
    pub(in crate::group) fn new(
        state: Arc<ScorePolicyState>,
        authority: Arc<ScoreAuthority>,
        context: ScoreSelectionContext,
        attributions: Vec<ScoreAttribution>,
    ) -> Self {
        Self {
            state,
            authority,
            context,
            attributions: attributions.into(),
            source: ScoreSource::Traffic,
            probe_scope: 0,
        }
    }

    /// Classify an attempt before admission; only traffic settles business reliability.
    pub fn with_source(mut self, source: ScoreSource) -> Self {
        self.source = source;
        if source == ScoreSource::HealthProbe {
            let mut scope = std::collections::hash_map::DefaultHasher::new();
            self.context.hash(&mut scope);
            self.probe_scope = scope.finish();
        }
        self
    }

    /// Bind an HTTP health sample to the complete canonical request cohort.
    pub(crate) fn with_probe_identity(mut self, uri: &str, method: &str) -> Self {
        if self.source == ScoreSource::HealthProbe {
            let mut scope = std::collections::hash_map::DefaultHasher::new();
            (&self.context, uri, method).hash(&mut scope);
            self.probe_scope = scope.finish();
        }
        self
    }

    pub fn attributions(&self) -> &[ScoreAttribution] {
        &self.attributions
    }
    pub fn context(&self) -> &ScoreSelectionContext {
        &self.context
    }

    /// Add an outer Score group when a terminal `final` outbound supplies the
    /// leaf. Existing nested attribution order remains outer-to-inner.
    pub fn prepend_attribution(mut self, group: String, node_id: Uuid) -> Self {
        if !self
            .attributions
            .iter()
            .any(|attribution| attribution.group == group)
        {
            let mut attributions = Vec::with_capacity(self.attributions.len() + 1);
            attributions.push(ScoreAttribution { group, node_id });
            attributions.extend(self.attributions.iter().cloned());
            self.attributions = attributions.into();
        }
        self
    }
    /// Reuse the selected group chain for a related attempt with different
    /// transport dimensions, such as a UDP DNS reply retried over TCP.
    pub fn with_context(mut self, context: ScoreSelectionContext) -> Self {
        self.context = context;
        let source = self.source;
        self.with_source(source)
    }

    /// Call only when the physical dial or logical stream actually starts.
    pub fn start(&self) -> ScoreReporter {
        self.start_at(Instant::now())
    }

    pub(super) fn start_at(&self, started: Instant) -> ScoreReporter {
        let cells = self.state.start_at_with_authority(
            &self.authority,
            &self.context,
            &self.attributions,
            started,
            self.source,
        );
        ScoreReporter {
            shared: Arc::new(ReporterShared {
                feedback: self.clone(),
                cells: cells.into(),
                started,
                handles: AtomicUsize::new(1),
                progress: Mutex::new(ReporterProgress {
                    window_start: started,
                    setup: None,
                    first_response: false,
                    probe: false,
                    finished: false,
                    tx: 0,
                    rx: 0,
                    last_rx_at: None,
                    window_tx: 0,
                    window_rx: 0,
                }),
            }),
        }
    }
}

struct ReporterProgress {
    setup: Option<Duration>,
    first_response: bool,
    probe: bool,
    finished: bool,
    tx: u64,
    rx: u64,
    last_rx_at: Option<Instant>,
    window_start: Instant,
    window_tx: u64,
    window_rx: u64,
}

struct ReporterShared {
    feedback: ScoreFeedback,
    cells: Arc<[StartedCells]>,
    started: Instant,
    handles: AtomicUsize,
    progress: Mutex<ReporterProgress>,
}

/// Cloneable exact-once flow reporter. The first terminal call wins; dropping
/// the final unfinished handle reports cancellation.
pub struct ScoreReporter {
    shared: Arc<ReporterShared>,
}

impl Clone for ScoreReporter {
    fn clone(&self) -> Self {
        self.shared.handles.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl ScoreReporter {
    pub fn setup_succeeded(&self) {
        self.setup_succeeded_at(Instant::now());
    }

    pub(super) fn setup_succeeded_at(&self, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished || progress.setup.is_some() {
            return;
        }
        let elapsed = now.saturating_duration_since(self.shared.started);
        progress.setup = Some(elapsed);
        progress.window_start = now;
        self.observe(Observation::Setup(elapsed), now);
    }

    pub fn setup_failed(&self, outcome: ScoreOutcome) {
        self.finish(outcome);
    }

    pub fn first_response(&self) {
        self.first_response_at(Instant::now());
    }

    pub(super) fn first_response_at(&self, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished || progress.first_response {
            return;
        }
        progress.first_response = true;
        self.observe(
            Observation::Response(now.saturating_duration_since(self.shared.started)),
            now,
        );
    }

    /// Publish a genuinely measured configured-probe RTT, never a cached average.
    pub fn probe_latency(&self, latency: Duration) {
        self.probe_latency_at(latency, Instant::now());
    }

    pub(super) fn probe_latency_at(&self, latency: Duration, now: Instant) {
        let mut progress = self.shared.progress.lock();
        let feedback = &self.shared.feedback;
        if progress.finished || progress.probe || feedback.source != ScoreSource::HealthProbe {
            return;
        }
        progress.probe = true;
        self.observe(
            Observation::Probe {
                latency,
                scope: feedback.probe_scope,
                slot: super::evidence::probe_slot(&feedback.context),
            },
            now,
        );
    }

    pub fn tx(&self, bytes: u64) {
        self.transfer_at(bytes, 0, Instant::now());
    }

    pub fn rx(&self, bytes: u64) {
        self.transfer_at(0, bytes, Instant::now());
    }

    pub(super) fn transfer_at(&self, tx: u64, rx: u64, now: Instant) {
        if tx == 0 && rx == 0 {
            return;
        }
        let mut progress = self.shared.progress.lock();
        if progress.finished {
            return;
        }
        progress.tx = progress.tx.saturating_add(tx);
        progress.rx = progress.rx.saturating_add(rx);
        if self.shared.feedback.source != ScoreSource::Traffic {
            return;
        }
        if rx > 0 {
            progress.last_rx_at = Some(progress.last_rx_at.map_or(now, |at| at.max(now)));
        }
        if now.saturating_duration_since(progress.window_start) > MAX_THROUGHPUT_DURATION {
            progress.window_start = now;
            progress.window_tx = 0;
            progress.window_rx = 0;
        }
        progress.window_tx = progress.window_tx.saturating_add(tx);
        progress.window_rx = progress.window_rx.saturating_add(rx);
        self.publish_window(&mut progress, now);
    }

    fn publish_window(&self, progress: &mut ReporterProgress, now: Instant) {
        let elapsed = now.saturating_duration_since(progress.window_start);
        if progress.setup.is_none()
            || !progress.first_response
            || progress.tx == 0
            || progress.rx == 0
            || elapsed < MIN_THROUGHPUT_DURATION
            || progress.window_tx.max(progress.window_rx) < MIN_THROUGHPUT_BYTES
        {
            return;
        }
        self.observe(
            Observation::Transfer {
                tx: progress.window_tx,
                rx: progress.window_rx,
                elapsed,
            },
            now,
        );
        progress.window_tx = 0;
        progress.window_rx = 0;
        progress.window_start = now;
    }

    fn observe(&self, observation: Observation, now: Instant) {
        let feedback = &self.shared.feedback;
        let mut inner = feedback.state.inner.lock();
        if feedback.source == ScoreSource::HealthProbe
            && !inner
                .active_authority
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &feedback.authority))
        {
            return;
        }
        ScorePolicyState::observe(
            &mut inner,
            &feedback.context,
            &feedback.attributions,
            &self.shared.cells,
            feedback.source,
            observation,
            now,
        );
    }

    /// Recover the immutable attribution plan for a related physical attempt.
    pub fn feedback(&self) -> ScoreFeedback {
        self.shared.feedback.clone()
    }

    /// Complete a successful preparation that carried no application payload.
    pub fn finish_setup_only(&self) {
        self.finish_at(ScoreOutcome::Success, false, Instant::now());
    }

    pub fn finish(&self, outcome: ScoreOutcome) {
        self.finish_at(outcome, true, Instant::now());
    }

    pub(super) fn finish_at(&self, outcome: ScoreOutcome, count_usefulness: bool, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished {
            return;
        }
        progress.finished = true;
        self.publish_window(&mut progress, now);
        let feedback = &self.shared.feedback;
        let sample = FlowSample {
            outcome,
            setup: progress.setup,
            source: feedback.source,
            tx: progress.tx,
            rx: progress.rx,
            last_rx_at: progress.last_rx_at,
            elapsed: now.saturating_duration_since(self.shared.started),
            count_usefulness,
        };
        feedback.state.finish_at(
            &feedback.context,
            &feedback.attributions,
            &self.shared.cells,
            &sample,
            now,
        );
    }
}

impl Drop for ScoreReporter {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_at(ScoreOutcome::Cancelled, false, Instant::now());
        }
    }
}
