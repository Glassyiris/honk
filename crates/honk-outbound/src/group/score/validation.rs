//! Target-bound validation demand and run ownership, separate from currency and scoring.
use super::ranking::Decision;
use super::verification::{CandidateQuestion, Evaluation};
use super::*;
use honk_config::node::Node;

const RUN_LIFETIME: Duration = Duration::from_secs(45);

pub(super) struct ValidationRun {
    reference: Uuid,
    challenger: Uuid,
    target: ScoreTarget,
    deadline: Instant,
    offers: u8,
    trials: u8,
    phase: Phase,
}

enum Phase {
    Staged {
        pending: Arc<budget::Life>,
    },
    Bound {
        fence: u64,
        pending: Option<Arc<budget::Life>>,
        control_due: bool,
    },
}

impl ValidationRun {
    fn owns_target(&self, context: &ScoreSelectionContext) -> bool {
        context.target.as_ref() == Some(&self.target)
    }

    pub(super) fn focused(&self, context: &ScoreSelectionContext, now: Instant) -> Option<Uuid> {
        (now < self.deadline && self.owns_target(context)).then_some(self.challenger)
    }

    fn admits(
        &self,
        inner: &StateInner,
        group: &str,
        context: &ScoreSelectionContext,
        life: &Arc<budget::Life>,
        now: Instant,
    ) -> bool {
        match &self.phase {
            Phase::Staged { pending } => Arc::ptr_eq(pending, life),
            Phase::Bound { fence, pending, .. } => {
                pending
                    .as_ref()
                    .is_some_and(|pending| Arc::ptr_eq(pending, life))
                    && comparison::response_progress(
                        inner,
                        group,
                        context,
                        self.reference,
                        self.challenger,
                        now,
                    )
                    .is_some_and(|(_, current)| current == *fence)
            }
        }
    }

    /// Binds a turn's work to the run deadline as its pending offer.
    fn bind(&mut self, inner: &mut StateInner, work: &Arc<budget::Work>) {
        let Phase::Bound { pending, .. } = &mut self.phase else {
            unreachable!("turns belong to bound runs")
        };
        *pending = Some(budget::bind_deadline(inner, work, self.deadline));
    }
}

enum ResponseDemand {
    Ordinary,
    Unavailable,
    Focused {
        counts: [u8; 2],
        fence: u64,
        needed: u64,
    },
}

fn response_demand(
    inner: &StateInner,
    (key, context): (&SelectionCadenceKey, &ScoreSelectionContext),
    (reference, challenger): (Uuid, Uuid),
    candidate: CandidateQuestion,
    active: bool,
    now: Instant,
) -> ResponseDemand {
    // A fixed pair cannot align several rivals; recovery needs only one attempt.
    if candidate.question == ScoreEvidenceQuestion::Recovery || candidate.needs_alignment() {
        return ResponseDemand::Ordinary;
    }
    let Some((counts, fence)) =
        comparison::response_progress(inner, &key.group, context, reference, challenger, now)
    else {
        return ResponseDemand::Unavailable;
    };
    if !active
        && candidate.question == ScoreEvidenceQuestion::Response
        && candidate.required == 1
        && counts[1] == 4
    {
        return ResponseDemand::Ordinary;
    }
    ResponseDemand::Focused {
        counts,
        fence,
        needed: u64::from(if counts[1] < 4 { 4 - counts[1] } else { 4 }),
    }
}

/// What the cadence's run asks of one offer. A turn is the run's uncharged control or, when
/// `funded` holds the response samples still needed, its funded challenger.
enum RunAction {
    Ordinary,
    Wait,
    Turn { index: usize, funded: Option<usize> },
}

/// Advances the cadence's run for one offer; the caller acquires the turn's work and stores the
/// returned run.
fn response_validation(
    inner: &StateInner,
    (key, context): (&SelectionCadenceKey, &ScoreSelectionContext),
    decision: &Decision,
    evaluation: &Evaluation,
    nodes: &[&Node],
    mut run: Option<ValidationRun>,
    now: Instant,
) -> (RunAction, Option<ValidationRun>) {
    let reference = decision.ordinary.index;
    if let Some(active) = &mut run {
        if now >= active.deadline || active.offers >= 16 || active.trials >= 8 {
            if active.owns_target(context) {
                return (RunAction::Wait, None);
            }
            run = None;
        } else if !active.owns_target(context) {
            let keep = match &active.phase {
                Phase::Staged { pending } => !pending.finished(),
                Phase::Bound { fence, .. } => comparison::response_progress(
                    inner,
                    &key.group,
                    &ScoreSelectionContext {
                        target: Some(active.target.clone()),
                        ..*context
                    },
                    active.reference,
                    active.challenger,
                    now,
                )
                .is_some_and(|(counts, current)| current == *fence && counts != [4, 4]),
            };
            if keep {
                return (RunAction::Wait, run);
            }
            run = None;
        } else {
            if active.reference != nodes[reference].id {
                return (RunAction::Wait, None);
            }
            active.offers += 1;
        }
    }
    let idle = |run: &Option<ValidationRun>| {
        if run.is_some() {
            RunAction::Wait
        } else {
            RunAction::Ordinary
        }
    };
    let candidate = run
        .as_ref()
        .and_then(|run| nodes.iter().position(|node| node.id == run.challenger))
        .or_else(|| {
            run.is_none()
                .then_some(evaluation.validation_index)
                .flatten()
        });
    let Some(candidate) = candidate else {
        return (idle(&run), None);
    };
    let question = evaluation.candidates[candidate];
    if !question.actionable() || question.question == ScoreEvidenceQuestion::Recovery {
        return (idle(&run), None);
    }
    // Misalignment must release a staged run too, before waiting for business evidence.
    if question.needs_alignment() {
        return (RunAction::Ordinary, None);
    }
    if let Some(ValidationRun {
        phase: Phase::Staged { pending },
        ..
    }) = &run
        && decision.evidence[candidate].business.is_none()
    {
        return if pending.finished() {
            (RunAction::Ordinary, None)
        } else {
            (RunAction::Wait, run)
        };
    }
    let (counts, fence, needed) = match response_demand(
        inner,
        (key, context),
        (nodes[reference].id, nodes[candidate].id),
        question,
        run.is_some(),
        now,
    ) {
        ResponseDemand::Ordinary => return (RunAction::Ordinary, None),
        ResponseDemand::Unavailable => {
            let action = idle(&run);
            return (
                action,
                run.filter(|run| matches!(run.phase, Phase::Staged { .. })),
            );
        }
        ResponseDemand::Focused {
            counts,
            fence,
            needed,
        } => (counts, fence, needed),
    };
    let mut run = if let Some(mut active) = run {
        active.phase = match active.phase {
            Phase::Staged { pending } => Phase::Bound {
                fence,
                pending: Some(pending),
                control_due: false,
            },
            Phase::Bound {
                fence: old,
                pending,
                control_due,
            } => {
                if old != fence {
                    return (RunAction::Wait, None);
                }
                Phase::Bound {
                    fence,
                    pending,
                    control_due,
                }
            }
        };
        active
    } else {
        if budget::available_credit(inner, &key.group, context, now) < needed {
            return (
                if budget::cold_available(inner, &key.group, context, now) {
                    RunAction::Ordinary
                } else {
                    RunAction::Wait
                },
                None,
            );
        }
        let Some(target) = context.target.as_ref() else {
            return (RunAction::Wait, None);
        };
        ValidationRun {
            reference: nodes[reference].id,
            challenger: nodes[candidate].id,
            target: target.clone(),
            deadline: now + RUN_LIFETIME,
            offers: 1,
            trials: 0,
            phase: Phase::Bound {
                fence,
                pending: None,
                control_due: counts[0] <= counts[1],
            },
        }
    };
    let Phase::Bound {
        pending,
        control_due,
        ..
    } = &mut run.phase
    else {
        unreachable!("response progress binds the run above")
    };
    if let Some(previous) = pending.take() {
        if previous.original_started() {
            *control_due = !*control_due;
        } else if previous.pending() {
            *pending = Some(previous);
            return (RunAction::Wait, Some(run));
        }
    }
    let control = *control_due;
    let funded = (!control).then(|| {
        run.trials += 1;
        question
            .required
            .max(usize::from(4_u8.saturating_sub(counts[1])))
    });
    let index = if control { reference } else { candidate };
    (RunAction::Turn { index, funded }, Some(run))
}

pub(super) fn cancel_run(
    inner: &mut StateInner,
    key: &SelectionCadenceKey,
    context: &ScoreSelectionContext,
) {
    if let Some(cadence) = inner.selection_counts.get_mut(key)
        && cadence
            .run
            .as_ref()
            .is_some_and(|run| run.owns_target(context))
    {
        cadence.run = None;
    }
}

/// A run whose challenger left the evaluation set loses its witness, so its unbegun work is refused.
pub(super) fn drop_runs_outside(
    inner: &mut StateInner,
    group: &str,
    network: SelectionNetwork,
    set: &super::evaluation::EvaluationSet,
) {
    for (key, cadence) in &mut inner.selection_counts {
        if key.group == group
            && key.network == network
            && cadence
                .run
                .as_ref()
                .is_some_and(|run| !set.evaluates(run.challenger))
        {
            cadence.run = None;
        }
    }
}

pub(super) fn plan(
    state: &Arc<ScorePolicyState>,
    inner: &mut StateInner,
    (key, context): (&SelectionCadenceKey, &ScoreSelectionContext),
    decision: &Decision,
    evaluation: &Evaluation,
    nodes: &[&Node],
    now: Instant,
) -> (RankedSelection, Option<Arc<budget::Work>>) {
    let ordinary = decision.ordinary;
    let cold = budget::cold_available(inner, &key.group, context, now);
    let run = inner
        .selection_counts
        .get_mut(key)
        .and_then(|cadence| cadence.run.take());
    let (action, mut run) =
        response_validation(inner, (key, context), decision, evaluation, nodes, run, now);
    // A refused funded turn waits for its run instead of falling back to sampling.
    let planned = match action {
        RunAction::Wait => None,
        RunAction::Turn { index, funded } => {
            let work = match funded {
                None => Some(budget::Work::new(
                    state,
                    &key.group,
                    context,
                    nodes[index].id,
                    ScoreTrialSource::None,
                )),
                Some(required) => budget::reserve(
                    state,
                    inner,
                    &key.group,
                    context,
                    nodes[index].id,
                    (ScoreEvidenceQuestion::Response, required),
                    now,
                ),
            };
            work.map(|work| {
                run.as_mut()
                    .expect("a turn belongs to its run")
                    .bind(inner, &work);
                (index, index != ordinary.index, work)
            })
        }
        RunAction::Ordinary => sample(
            state,
            inner,
            (key, context),
            (decision, evaluation, nodes),
            (cold, &mut run),
            now,
        )
        .map(|(index, work)| (index, true, work)),
    };
    inner
        .selection_counts
        .get_mut(key)
        .expect("cadence exists")
        .run = run;
    let Some((index, trial, work)) = planned else {
        return (ordinary, None);
    };
    let selection = if trial {
        RankedSelection {
            index,
            reason: if cold {
                SelectionReason::ColdExplore
            } else {
                SelectionReason::PeriodicExplore
            },
        }
    } else {
        ordinary
    };
    (selection, Some(work))
}

/// Funded sampling of the next actionable member when no run turn applies; an availability
/// sample of a challenger stages a run that binds its response pair later.
fn sample(
    state: &Arc<ScorePolicyState>,
    inner: &mut StateInner,
    (key, context): (&SelectionCadenceKey, &ScoreSelectionContext),
    (decision, evaluation, nodes): (&Decision, &Evaluation, &[&Node]),
    (cold, run): (bool, &mut Option<ValidationRun>),
    now: Instant,
) -> Option<(usize, Arc<budget::Work>)> {
    let ordinary = decision.ordinary;
    let proposed = if cold {
        verification::startup_index(decision).or(evaluation.validation_index)
    } else {
        evaluation.validation_index
    }?;
    let mut candidates: Vec<_> = evaluation
        .candidates
        .iter()
        .enumerate()
        .filter(|(index, candidate)| {
            (*index == proposed || *index != ordinary.index) && candidate.actionable()
        })
        .map(|(index, _)| index)
        .collect();
    candidates.sort_by_key(|&index| (index != proposed, decision.scores[index].selected_at, index));
    for index in candidates {
        let candidate = evaluation.candidates[index];
        if let Some(work) = budget::reserve(
            state,
            inner,
            &key.group,
            context,
            nodes[index].id,
            (candidate.question, candidate.required),
            now,
        ) {
            if index != ordinary.index
                && candidate.question == ScoreEvidenceQuestion::Availability
                && context.target_family.is_some()
                && let Some(target) = context.target.as_ref()
                && key
                    .group
                    .len()
                    .saturating_add(comparison::target_bytes(target))
                    <= comparison::MAX_KEY_BYTES
            {
                let deadline = now + RUN_LIFETIME;
                *run = Some(ValidationRun {
                    reference: nodes[ordinary.index].id,
                    challenger: nodes[index].id,
                    target: target.clone(),
                    deadline,
                    offers: 1,
                    trials: 1,
                    phase: Phase::Staged {
                        pending: budget::bind_deadline(inner, &work, deadline),
                    },
                });
            }
            return Some((index, work));
        }
        if budget::wait_reason(
            inner,
            &key.group,
            context,
            nodes[index].id,
            candidate.question,
            candidate.required,
            now,
        ) == ScoreWaitReason::Budget
        {
            break;
        }
    }
    None
}

pub(super) fn apply_budget_wait(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    reference: usize,
    now: Instant,
    evaluation: &mut Evaluation,
) {
    let Some(index) = evaluation.validation_index else {
        return;
    };
    let candidate = evaluation.candidates[index];
    let mut wait = budget::wait_reason(
        inner,
        group,
        context,
        nodes[index].id,
        candidate.question,
        candidate.required,
        now,
    );
    if wait == ScoreWaitReason::None
        && context.target.is_some()
        && !budget::cold_available(inner, group, context, now)
    {
        let key = SelectionCadenceKey::new(group, context);
        let active = inner
            .selection_counts
            .get(&key)
            .is_some_and(|cadence| cadence.run.is_some());
        if !active
            && let ResponseDemand::Focused { needed, .. } = response_demand(
                inner,
                (&key, context),
                (nodes[reference].id, nodes[index].id),
                candidate,
                active,
                now,
            )
            && budget::available_credit(inner, group, context, now) < needed
        {
            wait = ScoreWaitReason::Budget;
        }
    }
    if wait != ScoreWaitReason::None {
        evaluation.snapshot.wait_reason = wait;
    }
}

pub(super) fn failed(
    inner: &mut StateInner,
    attribution: &ScoreAttribution,
    context: &ScoreSelectionContext,
    node_wide: bool,
) {
    for (key, cadence) in &mut inner.selection_counts {
        if key.group == attribution.group
            && key.network == context.network
            && cadence.run.as_ref().is_some_and(|run| {
                [run.reference, run.challenger].contains(&attribution.node_id)
                    && (node_wide
                        || (key.family == context.target_family && run.owns_target(context)))
            })
        {
            cadence.run = None;
        }
    }
}

pub(super) fn admissible(
    inner: &StateInner,
    context: &ScoreSelectionContext,
    work: &[Arc<budget::Work>],
    now: Instant,
) -> bool {
    work.iter().all(|item| {
        item.life.deadline().is_none_or(|until| {
            now < until
                && inner
                    .selection_counts
                    .get(&item.key)
                    .and_then(|cadence| cadence.run.as_ref())
                    .is_some_and(|run| run.admits(inner, &item.key.group, context, &item.life, now))
        })
    })
}
