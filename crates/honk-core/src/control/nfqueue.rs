//! NFQUEUE staged-decision runtime (`experimental.udp_nfqueue`), phase-1
//! skeleton.
//!
//! Activation is all-or-nothing and strictly ordered: queue listeners
//! bound → nftables rules installed → structural self-check → only then is
//! `DATAPATH_FLAG_NFQ_READY` published into the datapath flags word, so the
//! TC programs never produce a PENDING_MARK nobody drains.  With the
//! feature disabled (the default) none of this runs and the datapath is
//! the pre-NFQUEUE one.
//!
//! Phase-1 decision policy: the TC side only stages Rule-mode, non-`must`,
//! non-offloadable *direct* UDP flows, so a staged packet's decision is
//! already direct.  The worker stamps the conn_state `DirectActive` (the
//! retained offload write) and NF_ACCEPTs the original skb with the
//! pending bit cleared — the flow's first datagram keeps the client's own
//! 5-tuple and later packets pass through the kernel.  Real decisions
//! (proxy/block commit, QUIC sniff staging) land in phase 2.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::Context;
use honk_nfqueue::{Decision, NfqueueService, NfqueueServiceConfig, VerdictPlan};
use tracing::info;

use crate::ebpf::EbpfBackend;

pub(crate) struct NfqueueRuntime {
    service: NfqueueService,
}

impl NfqueueRuntime {
    /// Bring the pipeline up from the startup config.  Returns `Ok(None)`
    /// when the feature is disabled; any enabled-but-broken setup is a hard
    /// startup error (fail closed — a half-up staging path would either
    /// leak policy or black-hole flows).
    /// `flag` is the shared NFQ_READY cell (0 while the pipeline is down);
    /// on success it carries DATAPATH_FLAG_NFQ_READY and every datapath
    /// flags write picks it up (startup sync, reload re-assert, clash mode
    /// switch).
    pub(crate) async fn start(
        config: &honk_config::experimental::UdpNfqueueConfig,
        lan_interfaces: &[String],
        ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>,
        flag: Arc<AtomicU32>,
    ) -> anyhow::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        if config.failure_policy == "legacy" {
            anyhow::bail!(
                "experimental.udp_nfqueue.failure_policy \"legacy\" is not implemented yet"
            );
        }
        if config.gso {
            anyhow::bail!("experimental.udp_nfqueue.gso is not implemented yet");
        }
        if lan_interfaces.is_empty() {
            anyhow::bail!(
                "experimental.udp_nfqueue requires at least one global.lan_interface to match on"
            );
        }
        let service = NfqueueService::start(
            NfqueueServiceConfig {
                queue_base: config.queue_base,
                workers: config.workers,
                queue_max_packets: config.queue_max_packets,
                fail_open: config.failure_policy == "availability",
                interfaces: lan_interfaces.to_vec(),
                pending_mark: honk_ebpf_common::NFQUEUE_PENDING_MARK,
            },
            skeleton_decision(ebpf),
        )
        .await
        .context("start NFQUEUE staged-decision pipeline")?;
        flag.store(honk_ebpf_common::DATAPATH_FLAG_NFQ_READY, Ordering::Relaxed);
        info!(
            queues = format!("{}..{}", config.queue_base, config.queue_base + config.workers - 1),
            interfaces = ?lan_interfaces,
            "NFQUEUE UDP staged-decision pipeline active (phase-1 direct skeleton)"
        );
        Ok(Some(Self { service }))
    }

    /// Reverse the activation order.  The caller clears the flag cell (and
    /// re-syncs the datapath flags) before calling this, so no new PENDING
    /// packets are produced while the rules come down; in-flight guards
    /// fail closed to NF_DROP as the workers stop.
    pub(crate) async fn shutdown(self) {
        self.service.shutdown().await;
    }
}

/// Phase-1 skeleton decision: everything staged is a direct flow by
/// construction (the TC gate only queues Rule-mode non-must direct UDP), so
/// commit `DirectActive` and release the original skb.  The conn_state
/// write is best-effort: on failure the flow simply stays Pending and its
/// next packet is queued again (degraded, never incorrect).
fn skeleton_decision(ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>) -> Decision {
    Arc::new(move |packet| {
        let ebpf = ebpf.clone();
        Box::pin(async move {
            if let Some(tuple) = packet.udp_tuple() {
                let key = crate::control::connection::build_tuples_key(
                    tuple.dst_ip,
                    tuple.dst_port,
                    tuple.src_ip,
                    tuple.src_port,
                    17,
                );
                if let Err(error) = ebpf.write().await.offload_udp_flow(&key) {
                    tracing::warn!(%error, "nfqueue skeleton: conn_state DirectActive write failed");
                }
            }
            VerdictPlan::Accept {
                mark: packet.mark & !honk_ebpf_common::NFQUEUE_PENDING_MARK,
            }
        })
    })
}
