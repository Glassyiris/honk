mod netlink;
mod packet;
mod queue;
mod rules;
mod verdict;

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use packet::{PacketError, QueuedPacket, UdpTuple};
pub use rules::{CHAIN_NAME, CHAIN_PRIORITY, TABLE_NAME};
pub use verdict::{NF_ACCEPT, NF_DROP, VerdictError, VerdictGuard};

pub const QUEUE_NUM: u16 = 320;
pub const QUEUE_MAXLEN: u32 = 4096;
pub const COPY_RANGE: u32 = 65_535;
pub const SO_RCVBUF_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_DATAGRAM_SIZE: usize = 128 * 1024;
pub const NFQUEUE_PENDING_MARK: u32 = 0x8000_0000;
pub const NFQUEUE_SIGNATURE_MARK: u32 = 0xc000_0000;
pub const NFQUEUE_TOKEN_MASK: u32 = 0x3fff_ffff;

pub type PacketCallback = Arc<dyn Fn(QueuedPacket, VerdictGuard) + Send + Sync + 'static>;
pub type FatalReceiver = tokio::sync::oneshot::Receiver<FatalError>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueStats {
    pub kernel_queue_depth: u64,
    pub kernel_dropped: u64,
    pub kernel_user_dropped: u64,
    pub held_packets: usize,
    pub held_peak: usize,
    pub socket_receive_buffer_bytes: usize,
}

fn parse_kernel_queue_stats(contents: &str) -> Option<(u64, u64, u64)> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let queue = fields.next()?.parse::<u16>().ok()?;
        let _peer_port = fields.next()?;
        let depth = fields.next()?.parse().ok()?;
        let _copy_mode = fields.next()?;
        let _copy_range = fields.next()?;
        let dropped = fields.next()?.parse().ok()?;
        let user_dropped = fields.next()?.parse().ok()?;
        (queue == QUEUE_NUM).then_some((depth, dropped, user_dropped))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum FatalError {
    #[error("NFQUEUE receive lost packets with ENOBUFS")]
    Enobufs,
    #[error("NFQUEUE listener {operation} failed: {error}")]
    ListenerIo {
        operation: &'static str,
        error: String,
    },
    #[error("NFQUEUE datagram length {length} exceeds limit {limit}")]
    DatagramTooLarge { length: usize, limit: usize },
    #[error("NFQUEUE datagram length changed from {expected} to {actual}")]
    DatagramLengthChanged { expected: usize, actual: usize },
    #[error("NFQUEUE datagram was truncated")]
    DatagramTruncated,
    #[error("malformed NFQUEUE message: {error}")]
    MalformedMessage { error: String },
    #[error("unexpected netfilter netlink message type {message_type}")]
    UnexpectedMessage { message_type: u16 },
    #[error("packet arrived on unexpected NFQUEUE {queue}")]
    UnexpectedQueue { queue: u16 },
    #[error("NFQUEUE packet callback panicked")]
    CallbackPanicked,
    #[error("NFQUEUE listener exited unexpectedly")]
    ListenerExited,
    #[error("NFQUEUE listener thread panicked")]
    ListenerPanicked,
    #[error("NFQUEUE verdict socket failed: {error}")]
    VerdictSocket { error: String },
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to bind and configure NFQUEUE: {0}")]
    Queue(String),
    #[error("failed to install NFQUEUE nftables ownership: {0}")]
    Rules(String),
    #[error("failed to spawn NFQUEUE listener: {0}")]
    ListenerThread(#[source] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    #[error("failed to remove NFQUEUE nftables ownership: {0}")]
    Rules(String),
}

pub struct NfqueueService {
    stop: Arc<AtomicBool>,
    listener: Option<std::thread::JoinHandle<()>>,
    socket: Option<Arc<queue::QueueSocket>>,
    rules: Option<rules::NftRuleset>,
    guards: Arc<verdict::GuardTracker>,
    shutdown_complete: bool,
}

impl NfqueueService {
    /// Binds the fixed queue before publishing the atomic nftables transaction.
    pub fn start(callback: PacketCallback) -> Result<(Self, FatalReceiver), StartError> {
        let (fatal, fatal_receiver) = fatal_channel();
        let socket = queue::QueueSocket::bind(Arc::clone(&fatal))
            .map_err(|error| StartError::Queue(error.to_string()))?;
        let mut rules =
            rules::NftRuleset::install().map_err(|error| StartError::Rules(error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let guards = verdict::GuardTracker::new();

        let listener_socket = Arc::clone(&socket);
        let listener_stop = Arc::clone(&stop);
        let listener_guards = Arc::clone(&guards);
        let listener_fatal = Arc::clone(&fatal);
        let listener = match std::thread::Builder::new()
            .name("honk-nfqueue".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    queue::listen(
                        listener_socket,
                        Arc::clone(&listener_stop),
                        callback,
                        listener_guards,
                    )
                }));
                match result {
                    Ok(Ok(())) if listener_stop.load(Ordering::Acquire) => {}
                    Ok(Ok(())) => listener_fatal.notify(FatalError::ListenerExited),
                    Ok(Err(error)) => listener_fatal.notify(error),
                    Err(_) => listener_fatal.notify(FatalError::ListenerPanicked),
                }
            }) {
            Ok(listener) => listener,
            Err(error) => {
                socket.mark_closed();
                let _ = rules.uninstall();
                return Err(StartError::ListenerThread(error));
            }
        };

        Ok((
            Self {
                stop,
                listener: Some(listener),
                socket: Some(socket),
                rules: Some(rules),
                guards,
                shutdown_complete: false,
            },
            fatal_receiver,
        ))
    }

    pub async fn stats(&self) -> QueueStats {
        let (kernel_queue_depth, kernel_dropped, kernel_user_dropped) =
            tokio::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue")
                .await
                .ok()
                .and_then(|contents| parse_kernel_queue_stats(&contents))
                .unwrap_or_default();
        QueueStats {
            kernel_queue_depth,
            kernel_dropped,
            kernel_user_dropped,
            held_packets: self.guards.count(),
            held_peak: self.guards.peak(),
            socket_receive_buffer_bytes: self
                .socket
                .as_ref()
                .map_or(0, |socket| socket.receive_buffer_bytes()),
        }
    }

    /// The caller must fence packet producers first; this waits for every
    /// dispatched guard, closes the queue, then deletes the wholly owned table.
    pub fn shutdown(mut self) -> Result<(), ShutdownError> {
        self.stop_listener();
        self.guards.wait_until_drained();
        self.close_queue();
        let result = self.remove_rules();
        self.shutdown_complete = true;
        result
    }

    fn stop_listener(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
    }

    fn close_queue(&mut self) {
        if let Some(socket) = self.socket.take() {
            socket.mark_closed();
            drop(socket);
        }
    }

    fn remove_rules(&mut self) -> Result<(), ShutdownError> {
        let Some(mut rules) = self.rules.take() else {
            return Ok(());
        };
        rules
            .uninstall()
            .map_err(|error| ShutdownError::Rules(error.to_string()))
    }
}

impl Drop for NfqueueService {
    fn drop(&mut self) {
        if self.shutdown_complete {
            return;
        }
        self.stop_listener();
        self.close_queue();
        // Only explicit shutdown proves producers are fenced; the unbound no-bypass rule
        // must remain fail-closed during unwinding.
    }
}

pub(crate) struct FatalNotifier {
    sender: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<FatalError>>>,
}

impl FatalNotifier {
    pub(crate) fn notify(&self, error: FatalError) {
        let sender = self.sender.lock().take();
        if let Some(sender) = sender {
            let _ = sender.send(error);
        }
    }
}

pub(crate) fn fatal_channel() -> (Arc<FatalNotifier>, FatalReceiver) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    (
        Arc::new(FatalNotifier {
            sender: parking_lot::Mutex::new(Some(sender)),
        }),
        receiver,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_owned_kernel_queue_stats() {
        let input = "319 10 1 2 65535 3 4 8\n320 20 17 2 65535 5 6 9\n";
        assert_eq!(super::parse_kernel_queue_stats(input), Some((17, 5, 6)));
    }
}
