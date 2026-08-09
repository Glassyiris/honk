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
