//! Cold URLTest UDP transport preparation with absolute stagger offsets.
//!
//! This module deliberately prepares only `PacketTransport`-equivalent values.
//! Lease binding, reply-socket creation, endpoint publication, and the first
//! application send remain in the caller after a winner has been finalized.

use crate::group::SelectionPlanMode;
use honk_config::node::Node;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// One candidate transport-preparation future. The candidate index preserves
/// path-specific feedback when the same leaf appears through multiple groups.
pub(super) type UdpPrepare<T> = Arc<
    dyn Fn(usize, Node) -> Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send>> + Send + Sync,
>;

/// Fixed callbacks let the scheduler keep policy, health, and metric effects
/// at the integration boundary. In particular, only an actual future `Err`
/// triggers `on_dial_error`; aborted or never-started candidates are neutral.
pub(super) struct UdpStaggerCallbacks {
    pub(super) is_eligible: Arc<dyn Fn(&Node) -> bool + Send + Sync>,
    pub(super) on_dial_error: Arc<dyn Fn(&Node) + Send + Sync>,
    pub(super) on_attempt: Arc<dyn Fn() + Send + Sync>,
    pub(super) on_winner: Arc<dyn Fn() + Send + Sync>,
    pub(super) on_cancellation: Arc<dyn Fn() + Send + Sync>,
}

fn stagger_offset(index: usize) -> Duration {
    match index {
        0 => Duration::ZERO,
        1 => Duration::from_millis(30),
        index => Duration::from_millis(80 + 80 * (index as u64 - 2)),
    }
}

/// Start cold URLTest preparations at their absolute offsets, up to three at
/// once, and return the first successful still-eligible result.
///
/// Authoritative plans defensively use only their first node, even if a buggy
/// caller supplied more. A winner aborts and drains every started loser before
/// this function returns, so speculative transports cannot leak into the
/// endpoint/lease lifecycle.
pub(super) async fn prepare_udp_plan<T>(
    mode: SelectionPlanMode,
    candidates: Vec<Node>,
    prepare: UdpPrepare<T>,
    callbacks: UdpStaggerCallbacks,
) -> Option<(Node, T)>
where
    T: Send + 'static,
{
    let records_stagger_metrics = mode == SelectionPlanMode::ColdUrlTest;
    let candidates: Vec<Node> = match mode {
        SelectionPlanMode::Authoritative => candidates.into_iter().take(1).collect(),
        SelectionPlanMode::ColdUrlTest => candidates,
    };
    let started_at = tokio::time::Instant::now();
    let mut next = 0;
    let mut tasks = JoinSet::new();

    loop {
        // Fill available slots whose absolute deadline has passed. If a
        // completed attempt opened a slot after a deadline, this starts the
        // delayed candidate immediately instead of drifting the schedule.
        while next < candidates.len() && tasks.len() < 3 {
            let node = candidates[next].clone();
            if !(callbacks.is_eligible)(&node) {
                next += 1;
                continue;
            }
            let due = started_at + stagger_offset(next);
            if tokio::time::Instant::now() < due {
                break;
            }
            next += 1;
            if records_stagger_metrics {
                (callbacks.on_attempt)();
            }
            let prepare = Arc::clone(&prepare);
            tasks.spawn(async move {
                let result = prepare(next - 1, node.clone()).await;
                (node, result)
            });
        }

        if tasks.is_empty() {
            if next == candidates.len() {
                return None;
            }
            tokio::time::sleep_until(started_at + stagger_offset(next)).await;
            continue;
        }

        // While a slot remains, observe both the next absolute start and an
        // in-flight completion. At capacity (or after every candidate has
        // started), only a completion can move the state forward.
        let joined = if next < candidates.len() && tasks.len() < 3 {
            let due = started_at + stagger_offset(next);
            tokio::select! {
                joined = tasks.join_next() => joined,
                _ = tokio::time::sleep_until(due) => continue,
            }
        } else {
            tasks.join_next().await
        };

        let Some(joined) = joined else {
            continue;
        };
        let Ok((node, result)) = joined else {
            // A task panic/abort has no observed transport result and must not
            // affect health. Continue scheduling the remaining candidates.
            continue;
        };
        match result {
            Ok(value) if (callbacks.is_eligible)(&node) => {
                if records_stagger_metrics {
                    (callbacks.on_winner)();
                }
                tasks.abort_all();
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok((node, Err(_))) => (callbacks.on_dial_error)(&node),
                        Ok((_, Ok(_))) => {}
                        Err(error) if error.is_cancelled() && records_stagger_metrics => {
                            (callbacks.on_cancellation)()
                        }
                        Err(_) => {}
                    }
                }
                return Some((node, value));
            }
            Ok(_) => {
                // The node died between launch and completion. Dropping the
                // speculative transport is neutral; it never owned a lease.
            }
            Err(_) => {
                // This is the sole scheduler path that is a real dial error.
                (callbacks.on_dial_error)(&node);
            }
        }
    }
}
