use super::{
    FlowSample, ScoreAttribution, ScoreAuthority, ScoreOutcome, ScorePolicyState,
    ScoreSelectionContext, StartedCells,
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct ScoreFeedback {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    streak_neutral: bool,
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
            streak_neutral: false,
        }
    }

    /// Probe, urltest, and warm-up outcomes must not touch the failure
    /// streak: a probe succeeding through a half-dead leaf must not wash out
    /// consecutive real-flow failures (and vice versa).
    pub fn streak_neutral(mut self) -> Self {
        self.streak_neutral = true;
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
        self
    }

    /// Call only when the physical dial or logical stream actually starts.
    pub fn start(&self) -> ScoreReporter {
        let started = Instant::now();
        let cells = self.state.start_at_with_authority(
            &self.authority,
            &self.context,
            &self.attributions,
            started,
        );
        ScoreReporter {
            shared: Arc::new(ReporterShared {
                state: Arc::clone(&self.state),
                authority: Arc::clone(&self.authority),
                context: self.context.clone(),
                attributions: Arc::clone(&self.attributions),
                cells: cells.into(),
                started,
                finished: AtomicBool::new(false),
                handles: AtomicUsize::new(1),
                tx: AtomicU64::new(0),
                rx: AtomicU64::new(0),
                progress: Mutex::new(ReporterProgress::default()),
                streak_neutral: self.streak_neutral,
            }),
        }
    }
}

#[derive(Default)]
struct ReporterProgress {
    setup: Option<Duration>,
    first_response: Option<Duration>,
}

struct ReporterShared {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    cells: Arc<[StartedCells]>,
    started: Instant,
    finished: AtomicBool,
    handles: AtomicUsize,
    tx: AtomicU64,
    rx: AtomicU64,
    progress: Mutex<ReporterProgress>,
    streak_neutral: bool,
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
        let mut progress = self.shared.progress.lock();
        progress
            .setup
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn setup_failed(&self, outcome: ScoreOutcome) {
        self.finish(outcome);
    }

    pub fn first_response(&self) {
        let mut progress = self.shared.progress.lock();
        progress
            .first_response
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn tx(&self, bytes: u64) {
        saturating_add(&self.shared.tx, bytes);
    }

    pub fn rx(&self, bytes: u64) {
        saturating_add(&self.shared.rx, bytes);
    }

    /// Recover the immutable attribution plan for a related physical attempt.
    pub fn feedback(&self) -> ScoreFeedback {
        ScoreFeedback {
            state: Arc::clone(&self.shared.state),
            authority: Arc::clone(&self.shared.authority),
            context: self.shared.context.clone(),
            attributions: Arc::clone(&self.shared.attributions),
            streak_neutral: self.shared.streak_neutral,
        }
    }

    /// Complete a successful preparation that carried no application payload.
    pub fn finish_setup_only(&self) {
        self.finish_inner(ScoreOutcome::Success, false);
    }

    pub fn finish(&self, outcome: ScoreOutcome) {
        self.finish_inner(outcome, true);
    }

    fn finish_inner(&self, outcome: ScoreOutcome, count_usefulness: bool) {
        if self
            .shared
            .finished
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let progress = self.shared.progress.lock();
        let sample = FlowSample {
            outcome,
            setup: progress.setup,
            first_response: progress.first_response,
            tx: self.shared.tx.load(Ordering::Relaxed),
            rx: self.shared.rx.load(Ordering::Relaxed),
            elapsed: self.shared.started.elapsed(),
            count_usefulness,
            streak_neutral: self.shared.streak_neutral,
        };
        self.shared.state.finish(
            &self.shared.context,
            &self.shared.attributions,
            &self.shared.cells,
            &sample,
        );
    }
}

impl Drop for ScoreReporter {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_inner(ScoreOutcome::Cancelled, false);
        }
    }
}

fn saturating_add(value: &AtomicU64, amount: u64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(amount))
    });
}
