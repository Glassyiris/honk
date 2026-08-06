//! NFQUEUE verdicts and the exactly-once RAII guard.
//!
//! Every queued packet must receive exactly one verdict.  [`VerdictGuard`]
//! owns that obligation: `accept`/`drop_packet` commit a verdict exactly
//! once (a second commit is an error), and a guard dropped without a
//! commit — worker panic, task cancellation, early return — sends NF_DROP
//! from its `Drop`.  Fail-closed is the default on purpose: an unverdicted
//! packet must never silently become an accept.

use std::sync::Arc;

use crate::listener::QueueSocket;
use crate::metrics::NfqueueMetrics;
use crate::netlink;

// Verdict values (netfilter.h).
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

// Verdict message attributes (enum nfqnl_attr_type).
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;

#[derive(Debug, thiserror::Error)]
pub enum VerdictError {
    #[error("packet already has a verdict")]
    AlreadyCommitted,
    #[error("verdict send failed: {0}")]
    Io(#[from] std::io::Error),
}

/// RAII owner of one queued packet's verdict.  Constructed by the listener
/// alongside each [`crate::packet::QueuedPacket`].
pub struct VerdictGuard {
    socket: Arc<QueueSocket>,
    queue_num: u16,
    packet_id: u32,
    committed: bool,
    metrics: NfqueueMetrics,
}

impl VerdictGuard {
    pub(crate) fn new(
        socket: Arc<QueueSocket>,
        queue_num: u16,
        packet_id: u32,
        metrics: NfqueueMetrics,
    ) -> Self {
        Self {
            socket,
            queue_num,
            packet_id,
            committed: false,
            metrics,
        }
    }

    /// NF_ACCEPT the original skb.  `mark` replaces the whole skb->mark
    /// (NFQA_MARK semantics), so the caller must pass the received mark
    /// with NFQUEUE_PENDING_MARK cleared and the routing bits preserved —
    /// there is no "keep mark" verdict.
    pub fn accept(&mut self, mark: u32) -> Result<(), VerdictError> {
        self.commit(NF_ACCEPT, Some(mark))
    }

    /// NF_DROP the packet.
    pub fn drop_packet(&mut self) -> Result<(), VerdictError> {
        self.commit(NF_DROP, None)
    }

    fn commit(&mut self, verdict: u32, mark: Option<u32>) -> Result<(), VerdictError> {
        if self.committed {
            return Err(VerdictError::AlreadyCommitted);
        }
        self.socket
            .send_verdict(self.queue_num, self.packet_id, verdict, mark)?;
        self.committed = true;
        match verdict {
            NF_ACCEPT => self.metrics.verdict_accept_total().inc(),
            _ => self.metrics.verdict_drop_total().inc(),
        }
        Ok(())
    }
}

impl Drop for VerdictGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Uncommitted guard: fail closed.  A send error here only means the
        // kernel keeps/drops the packet on its own when the queue dies —
        // either way the packet is never silently accepted.
        let _ = self
            .socket
            .send_verdict(self.queue_num, self.packet_id, NF_DROP, None);
        self.metrics.verdict_drop_total().inc();
        self.metrics.guard_default_drop_total().inc();
    }
}

/// Build one NFQA_MSG_VERDICT message.
pub fn build_verdict_msg(
    buf: &mut Vec<u8>,
    queue_num: u16,
    packet_id: u32,
    verdict: u32,
    mark: Option<u32>,
    seq: u32,
) {
    let start = netlink::put_msg_header(
        buf,
        (netlink::NFNL_SUBSYS_QUEUE << 8) | 1, // NFQA_MSG_VERDICT
        netlink::NLM_F_REQUEST,
        seq,
        0, // family unused for verdicts
        queue_num,
    );
    let mut hdr = [0u8; 8];
    hdr[..4].copy_from_slice(&verdict.to_be_bytes());
    hdr[4..].copy_from_slice(&packet_id.to_be_bytes());
    netlink::put_attr(buf, NFQA_VERDICT_HDR, &hdr);
    if let Some(mark) = mark {
        netlink::put_attr_be32(buf, NFQA_MARK, mark);
    }
    netlink::seal_msg(buf, start);
}
