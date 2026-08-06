//! NFQUEUE UDP staged-decision transport: netlink listeners, packet
//! parsing, exactly-once verdicts, and atomic nftables rule management.
//!
//! This crate is pure mechanism.  The decision policy (direct/proxy/block
//! commit, QUIC sniff staging) lives in honk-core; here a [`Decision`]
//! callback maps each queued packet to a [`VerdictPlan`] and the
//! [`VerdictGuard`] guarantees every packet receives exactly one verdict
//! (uncommitted guards fail closed to NF_DROP).
//!
//! Activation order (`NfqueueService::start`): bind all queue listeners →
//! atomically install the `honk_nfqueue` ruleset → structural self-check →
//! spawn workers.  Callers must only set the eBPF NFQ_READY flag after
//! `start` returns, so the datapath never produces a mark nobody drains.

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests;
pub mod listener;
pub mod metrics;
mod netlink;
pub mod packet;
pub mod rules;
pub mod verdict;

use std::sync::Arc;

use listener::{ListenerError, QueueListener};
use metrics::NfqueueMetrics;
use packet::QueuedPacket;
use rules::{NftRuleset, RulesError, RulesetConfig};
use tracing::{error, warn};
use verdict::VerdictGuard;

#[derive(Debug, thiserror::Error)]
pub enum NfqueueError {
    #[error(transparent)]
    Listener(#[from] ListenerError),
    #[error(transparent)]
    Rules(#[from] RulesError),
    #[error("nfqueue self-check failed: {0}")]
    SelfCheck(String),
}

pub struct NfqueueServiceConfig {
    /// First queue number; workers occupy queue_base..queue_base+workers-1.
    pub queue_base: u16,
    pub workers: u16,
    pub queue_max_packets: u32,
    /// failure_policy "availability": kernel accepts packets when a queue is
    /// full.  Default "closed" drops them instead.
    pub fail_open: bool,
    /// Managed LAN interface names the prerouting chain matches on.
    pub interfaces: Vec<String>,
    /// skb->mark bit the TC datapath tags staged flows with.
    pub pending_mark: u32,
}

/// The verdict a [`Decision`] asks the worker to commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictPlan {
    /// NF_ACCEPT the original skb; `mark` replaces the whole skb->mark
    /// (NFQA_MARK semantics), so it must carry the routing bits and have
    /// the pending bit cleared.
    Accept {
        mark: u32,
    },
    Drop,
}

pub type Decision = Arc<dyn Fn(QueuedPacket) -> DecisionFuture + Send + Sync + 'static>;
pub type DecisionFuture = std::pin::Pin<Box<dyn std::future::Future<Output = VerdictPlan> + Send>>;

pub struct NfqueueService {
    rules: Option<NftRuleset>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    metrics: NfqueueMetrics,
}

impl NfqueueService {
    /// Bring the pipeline up in the only safe order.  Any failure unwinds
    /// everything already created (listeners unbind on drop, rules are
    /// uninstalled), so a half-up NFQUEUE never lingers.
    pub async fn start(
        config: NfqueueServiceConfig,
        decide: Decision,
    ) -> Result<Self, NfqueueError> {
        let metrics = NfqueueMetrics::default();
        let mut listeners = Vec::new();
        for i in 0..config.workers {
            let queue_num = config.queue_base + i;
            match QueueListener::bind(
                queue_num,
                config.queue_max_packets,
                config.fail_open,
                metrics.clone(),
            ) {
                Ok(listener) => listeners.push(listener),
                Err(error) => return Err(error.into()),
            }
        }
        let mut rules = NftRuleset::new(RulesetConfig {
            interfaces: config.interfaces.clone(),
            queue_base: config.queue_base,
            workers: config.workers,
            pending_mark: config.pending_mark,
        })?;
        if let Err(error) = rules.install() {
            let _ = rules.uninstall();
            return Err(error.into());
        }
        if let Err(error) = rules.verify() {
            let _ = rules.uninstall();
            return Err(error.into());
        }
        let workers = listeners
            .into_iter()
            .map(|listener| tokio::spawn(worker_loop(listener, decide.clone())))
            .collect();
        Ok(Self {
            rules: Some(rules),
            workers,
            metrics,
        })
    }

    pub fn metrics(&self) -> NfqueueMetrics {
        self.metrics.clone()
    }

    /// Reverse order of `start`: stop the workers first (in-flight guards
    /// fail closed to NF_DROP), then atomically remove only our own rules.
    /// The caller clears the eBPF NFQ_READY flag before calling this, so no
    /// new PENDING packets are produced while the rules come down.
    pub async fn shutdown(mut self) {
        for worker in self.workers.drain(..) {
            worker.abort();
        }
        if let Some(mut rules) = self.rules.take()
            && let Err(error) = rules.uninstall()
        {
            warn!(%error, "failed to uninstall nfqueue rules");
        }
    }
}

async fn worker_loop(mut listener: QueueListener, decide: Decision) {
    loop {
        let (packet, mut guard) = match listener.recv().await {
            Ok(pair) => pair,
            Err(error) => {
                error!(%error, "nfqueue listener receive failed; worker exits");
                return;
            }
        };
        apply_plan(decide(packet).await, &mut guard);
    }
}

fn apply_plan(plan: VerdictPlan, guard: &mut VerdictGuard) {
    let result = match plan {
        VerdictPlan::Accept { mark } => guard.accept(mark),
        VerdictPlan::Drop => guard.drop_packet(),
    };
    if let Err(error) = result {
        warn!(%error, "nfqueue verdict commit failed");
    }
}
