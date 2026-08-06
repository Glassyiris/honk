//! NFQUEUE listener: one NETLINK_NETFILTER socket per queue, bound and
//! configured (copy mode, maxlen, fail-open policy) at startup, tokio-ized
//! for the receive loop.
//!
//! The socket is created blocking for the synchronous config exchange and
//! switched to nonblocking before it enters the async loop.  Verdicts are
//! plain atomic `send(2)` calls on the same fd — netlink is full-duplex and
//! a single sendmsg cannot interleave — so the [`VerdictGuard`] needs no
//! lock.

use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::metrics::NfqueueMetrics;
use crate::netlink;
use crate::packet::{self, QueuedPacket};
use crate::verdict::{self, VerdictGuard};

// nfnetlink_queue message types (NFNL_SUBSYS_QUEUE << 8 | type).
const NFQA_MSG_PACKET: u16 = 0;
const NFQA_MSG_CONFIG: u16 = 2;

// NFQA_CFG_* attribute ids.
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

// nfqnl_config_mode / commands.
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;
const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;
const NFQNL_COPY_PACKET: u8 = 2;

const NFQA_CFG_F_FAIL_OPEN: u32 = 1 << 0;
const NFQA_CFG_F_GSO: u32 = 1 << 2;

const SO_RCVBUF_SIZE: libc::c_int = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("netlink socket: {0}")]
    Io(#[from] io::Error),
    #[error("queue {0} is already bound by another process")]
    QueueBusy(u16),
}

/// The raw queue socket shared with verdict guards.
pub struct QueueSocket {
    fd: RawFd,
    queue_num: u16,
    seq: AtomicU32,
}

impl QueueSocket {
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Fire-and-forget verdict: verdicts carry no ACK request (the receive
    /// loop must not have to reassemble ACKs among packets), a failed send
    /// surfaces as an error to the caller and the kernel-side packet is
    /// eventually dropped when the queue dies.
    pub fn send_verdict(
        &self,
        queue_num: u16,
        packet_id: u32,
        verdict: u32,
        mark: Option<u32>,
    ) -> io::Result<()> {
        let mut buf = Vec::with_capacity(64);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        verdict::build_verdict_msg(&mut buf, queue_num, packet_id, verdict, mark, seq);
        netlink::send(self.fd, &buf)
    }

    fn send_config(&self, attr_type: u16, payload: &[u8], res_id: u16) -> io::Result<()> {
        let mut buf = Vec::with_capacity(64);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let start = netlink::put_msg_header(
            &mut buf,
            (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_CONFIG,
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
            seq,
            0,
            res_id,
        );
        netlink::put_attr(&mut buf, attr_type, payload);
        netlink::seal_msg(&mut buf, start);
        netlink::send_and_ack(self.fd, &buf, seq)
    }

    fn send_config_cmd(&self, command: u8, pf: u16, queue: u16) -> io::Result<()> {
        // struct nfqnl_msg_config_cmd { __u8 command; __u8 _pad; __be16 pf; }
        let mut payload = [0u8; 4];
        payload[0] = command;
        payload[2..4].copy_from_slice(&pf.to_be_bytes());
        self.send_config(NFQA_CFG_CMD, &payload, queue)
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        let _ = self.send_config_cmd(NFQNL_CFG_CMD_UNBIND, 0, self.queue_num);
        let _ = self.send_config_cmd(NFQNL_CFG_CMD_PF_UNBIND, libc::AF_INET as u16, 0);
        let _ = self.send_config_cmd(NFQNL_CFG_CMD_PF_UNBIND, libc::AF_INET6 as u16, 0);
        unsafe { libc::close(self.fd) };
    }
}

/// One bound NFQUEUE queue with its tokio receive half.
pub struct QueueListener {
    socket: Arc<QueueSocket>,
    async_fd: tokio::io::unix::AsyncFd<RawFd>,
    metrics: NfqueueMetrics,
    /// Packets drained from the socket but not yet handed out: one recvmsg
    /// datagram can carry several NFQA messages.
    pending: std::collections::VecDeque<(QueuedPacket, VerdictGuard)>,
}

impl QueueListener {
    /// Bind and configure queue `queue_num`.  `fail_open` maps to
    /// NFQA_CFG_F_FAIL_OPEN (queue-full accepts instead of drops) — the
    /// "availability" failure policy; the default "closed" policy leaves
    /// the flag clear.  GSO stays disabled: the kernel segments first and
    /// userspace always parses plain UDP datagrams.
    pub fn bind(
        queue_num: u16,
        queue_max_packets: u32,
        fail_open: bool,
        metrics: NfqueueMetrics,
    ) -> Result<Self, ListenerError> {
        let fd = netlink::netlink_socket(false)?;
        let socket = Arc::new(QueueSocket {
            fd,
            queue_num,
            seq: AtomicU32::new(1),
        });
        let result: Result<(), ListenerError> = (|| {
            // A larger receive buffer absorbs decision-latency bursts; it is
            // not a substitute for draining (ENOBUFS stays loud).
            let rcvbuf = SO_RCVBUF_SIZE;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &rcvbuf as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error().into());
            }
            socket.send_config_cmd(NFQNL_CFG_CMD_PF_BIND, libc::AF_INET as u16, 0)?;
            socket.send_config_cmd(NFQNL_CFG_CMD_PF_BIND, libc::AF_INET6 as u16, 0)?;
            socket
                .send_config_cmd(NFQNL_CFG_CMD_BIND, 0, queue_num)
                .map_err(|e| {
                    // EBUSY on older kernels, EPERM on newer ones (the
                    // queue is owned by another netlink portid).
                    if matches!(e.raw_os_error(), Some(libc::EBUSY) | Some(libc::EPERM)) {
                        ListenerError::QueueBusy(queue_num)
                    } else {
                        ListenerError::Io(e)
                    }
                })?;
            // struct nfqnl_msg_config_params { __be32 copy_range; __u8 copy_mode; }
            let mut params = [0u8; 5];
            params[..4].copy_from_slice(&0xFFFFu32.to_be_bytes());
            params[4] = NFQNL_COPY_PACKET;
            socket.send_config(NFQA_CFG_PARAMS, &params, queue_num)?;
            socket.send_config(
                NFQA_CFG_QUEUE_MAXLEN,
                &queue_max_packets.to_be_bytes(),
                queue_num,
            )?;
            // MASK and FLAGS must ride in the same message; a FLAGS-only
            // message is EINVAL.
            let mask = NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN;
            let flags = if fail_open { NFQA_CFG_F_FAIL_OPEN } else { 0 };
            let mut buf = Vec::with_capacity(64);
            let seq = socket.next_seq();
            let start = netlink::put_msg_header(
                &mut buf,
                (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_CONFIG,
                netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
                seq,
                0,
                queue_num,
            );
            netlink::put_attr_be32(&mut buf, NFQA_CFG_MASK, mask);
            netlink::put_attr_be32(&mut buf, NFQA_CFG_FLAGS, flags);
            netlink::seal_msg(&mut buf, start);
            netlink::send_and_ack(fd, &buf, seq)?;
            // Switch to nonblocking for the async loop only after the
            // synchronous config exchange is done.
            let flags_now = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags_now < 0
                || unsafe { libc::fcntl(fd, libc::F_SETFL, flags_now | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        })();
        match result {
            Ok(()) => {}
            Err(err) => {
                drop(socket); // Drop unbinds the queue and closes the fd.
                return Err(err);
            }
        }
        let async_fd = tokio::io::unix::AsyncFd::new(fd)?;
        Ok(Self {
            socket,
            async_fd,
            metrics,
            pending: std::collections::VecDeque::new(),
        })
    }

    /// Receive the next queued packet together with its verdict guard.
    pub async fn recv(&mut self) -> io::Result<(QueuedPacket, VerdictGuard)> {
        loop {
            if let Some(item) = self.pending.pop_front() {
                return Ok(item);
            }
            let mut ready = self.async_fd.readable().await?;
            let mut buf = vec![0u8; 256 * 1024];
            match ready.try_io(|fd| netlink::recv(*fd.get_ref(), &mut buf)) {
                Ok(Ok(n)) => self.drain_datagrams(&buf[..n]),
                Ok(Err(error)) => {
                    // The kernel dropped queued packets because we read too
                    // slowly.  Loud by design (no NETLINK_NO_ENOBUFS): the
                    // phase-3 recovery hooks in here.
                    if error.raw_os_error() == Some(libc::ENOBUFS) {
                        self.metrics.netlink_enobufs_total().inc();
                        tracing::error!(
                            queue = self.socket.fd(),
                            "NFQUEUE socket hit ENOBUFS; kernel dropped queued packets"
                        );
                        continue;
                    }
                    return Err(error);
                }
                Err(_would_block) => continue,
            }
        }
    }

    fn drain_datagrams(&mut self, buf: &[u8]) {
        for msg in netlink::split_messages(buf) {
            if msg.body.len() < netlink::NFGENMSG_LEN {
                continue;
            }
            if msg.msg_type != (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_PACKET {
                continue;
            }
            // The queue number rides in the nfgenmsg res_id.
            let queue_num = u16::from_be_bytes([msg.body[2], msg.body[3]]);
            let Some(packet) = packet::parse_packet_msg(msg.body, queue_num) else {
                continue;
            };
            self.metrics.packets_total().inc();
            self.metrics
                .bytes_total()
                .inc_by(packet.payload.len() as u64);
            let guard = VerdictGuard::new(
                self.socket.clone(),
                packet.queue_num,
                packet.packet_id,
                self.metrics.clone(),
            );
            self.pending.push_back((packet, guard));
        }
    }
}
