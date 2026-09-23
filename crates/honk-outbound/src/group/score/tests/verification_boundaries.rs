use super::super::verification as verification_engine;
use super::*;

mod lifecycle;
mod scope_expiry;

fn answer_run_attempt(attempt: ScoreAttempt, at: Instant) {
    let reporter = attempt.begin_at(at).unwrap().start_at(at);
    reporter.setup_succeeded_at(at);
    let received = at + Duration::from_millis(100);
    reporter.first_response_at(received);
    reporter.transfer_at(1, 1, received);
    reporter.finish_at(ScoreOutcome::Success, true, received);
}
