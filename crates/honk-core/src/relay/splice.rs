//! Zero-copy bidirectional TCP relay via the `splice(2)` syscall.
//!
//! Moves data directly between two plain TCP sockets through kernel pipes,
//! avoiding userspace copies entirely:
//!
//! ```text
//! client ──splice──→ pipe[1]  pipe[0] ──splice──→ upstream
//! client ◄──splice── pipe[0]  pipe[1] ◄──splice── upstream
//! ```
//!
//! Each direction runs as an independent pump driven by tokio readiness
//! (`TcpStream::async_io`, which re-arms readiness on `WouldBlock`, so the
//! raw syscalls never busy-loop). When one direction sees EOF it shuts down
//! the opposite socket's write side (half-close propagation) and the other
//! direction drains until its own EOF — bounded by [`DRAIN_DEADLINE`] so a
//! silent peer cannot pin the relay forever.
//!
//! The first splice of each direction doubles as a capability probe: a
//! failed `splice(2)` moves no bytes, so if it returns EINVAL/ENOSYS/EXDEV
//! the whole connection falls back to the userspace copy relay without
//! losing data, and a global flag skips probing for future connections.
//!
//! Go ref: `tcp_copy_linux.go` (340L), `tcp_copy_engine.go` (118L)

use super::{RelayStats, is_ignorable_connection_error, relay_tcp};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::Interest;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Upper bound requested for one active splice direction. A live pipe owns
/// two FDs and at most this many kernel-buffer bytes; a full-duplex relay is
/// therefore bounded to four FDs and 128 KiB of requested pipe pages. Linux
/// may refuse the resize, in which case `capacity` records the smaller
/// kernel-selected value.
const PIPE_SIZE: usize = 64 * 1024;

/// Conservative capacity used only when `F_GETPIPE_SZ` itself fails.
const DEFAULT_PIPE_SIZE: usize = 64 * 1024;

/// Set when the kernel rejects `splice(2)` for TCP sockets (e.g. seccomp).
/// Once latched, every connection uses the userspace copy relay directly.
static SPLICE_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// Whether `splice(2)` has worked so far on this host.
pub fn splice_available() -> bool {
    !SPLICE_UNSUPPORTED.load(Ordering::Relaxed)
}

/// Whether an errno from the very first `splice(2)` attempt means "splice
/// is not supported for these file descriptors" (as opposed to a regular
/// connection error). Only checked before any byte has been moved, so
/// falling back to the copy relay loses nothing.
fn is_unsupported_errno(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EXDEV)
    )
}

/// Outcome of a failed splice operation.
#[derive(Debug)]
enum SpliceError {
    /// `splice(2)` is unsupported for these fds (EINVAL/ENOSYS/EXDEV on the
    /// capability probe, before any byte was moved).
    Unsupported,
    /// A regular I/O error.
    Io(io::Error),
}

impl SpliceError {
    fn classify(err: io::Error) -> Self {
        if is_unsupported_errno(&err) {
            SpliceError::Unsupported
        } else {
            SpliceError::Io(err)
        }
    }
}

/// Thin wrapper over `splice(2)` (non-blocking, retries on EINTR).
fn raw_splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<usize> {
    loop {
        let n = unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut(),
                fd_out,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

/// A kernel pipe used as the intermediate buffer for one splice direction.
struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    capacity: usize,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Best-effort: grow the pipe to reduce syscall frequency.
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_SIZE as libc::c_int);
        }
        let capacity = unsafe { libc::fcntl(fds[1], libc::F_GETPIPE_SZ) };
        let capacity = if capacity > 0 {
            capacity as usize
        } else {
            DEFAULT_PIPE_SIZE
        };
        // Safety: both fds were just created by pipe2 and are uniquely owned.
        Ok(Pipe {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            capacity,
        })
    }
}

/// Half-close the write side of a socket (best-effort).
fn shutdown_write(stream: &TcpStream) {
    let _ = unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_WR) };
}

/// Perform the very first splice of a direction without waiting for
/// readiness. This doubles as the capability probe: a failed `splice(2)`
/// moves no bytes, so an [`SpliceError::Unsupported`] result here still
/// allows a lossless fallback to the copy relay.
///
/// Returns the number of bytes staged in the pipe (0 when the source had no
/// data ready or is already at EOF; the pump re-reads either way).
fn probe(src: &TcpStream, pipe: &Pipe) -> Result<usize, SpliceError> {
    #[cfg(test)]
    if let Some(errno) = test_hook::forced_probe_errno() {
        return Err(SpliceError::classify(io::Error::from_raw_os_error(errno)));
    }
    match raw_splice(src.as_raw_fd(), pipe.write.as_raw_fd(), pipe.capacity) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(SpliceError::classify(e)),
    }
}

/// Splice one direction until the source reaches EOF.
///
/// `staged` is the number of bytes the probe already moved into the pipe.
/// The pump alternates between two states: with an empty pipe it pulls from
/// the source (waiting for readability), with a non-empty pipe it drains to
/// the destination (waiting for writability). EOF is only observed with an
/// empty pipe, so `shutdown(Write)` on the destination propagates a clean
/// half-close after all staged bytes; the reverse direction keeps running.
async fn pump(
    src: &TcpStream,
    dst: &TcpStream,
    pipe: &Pipe,
    mut staged: usize,
    progress: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
) -> io::Result<u64> {
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let pipe_r = pipe.read.as_raw_fd();
    let pipe_w = pipe.write.as_raw_fd();
    let mut total = 0u64;

    loop {
        if staged == 0 {
            staged = src
                .async_io(Interest::READABLE, || {
                    raw_splice(src_fd, pipe_w, pipe.capacity)
                })
                .await?;
            if staged == 0 {
                // Source reached EOF: propagate the half-close.
                shutdown_write(dst);
                return Ok(total);
            }
        } else {
            let n = dst
                .async_io(Interest::WRITABLE, || raw_splice(pipe_r, dst_fd, staged))
                .await?;
            if n == 0 {
                // A non-empty pipe must always make progress; bail out
                // instead of spinning.
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice pipe→socket made no progress",
                ));
            }
            staged -= n;
            total += n as u64;
            if let Some(counter) = &progress {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

/// Grace window for the surviving direction after the first EOF. A peer
/// that received our half-close should finish draining within seconds;
/// without a bound, a silent peer (dead node, blackholed tunnel) pins the
/// relay task and both sockets forever — observed in production as a
/// growing pile of CLOSE-WAIT accepted sockets.
/// Idle budget for the surviving direction after the first EOF: it is cut
/// only when this much time passes without any byte of progress, so a
/// silent peer cannot pin the relay task and both sockets forever —
/// observed in production as a growing pile of CLOSE-WAIT accepted
/// sockets. Active transfers may outlive it freely.
pub(crate) const DRAIN_DEADLINE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(500)
} else {
    std::time::Duration::from_secs(30)
};

/// Shared engine behind [`splice_bidirectional`] and [`relay_splice`].
async fn run(
    client: &TcpStream,
    upstream: &TcpStream,
    progress: super::RelayProgress,
) -> Result<(u64, u64), SpliceError> {
    let pipe_c2p = Pipe::new().map_err(SpliceError::Io)?;
    let pipe_p2c = Pipe::new().map_err(SpliceError::Io)?;

    // The probes run before any byte reaches a destination socket, so an
    // `Unsupported` verdict here still allows a lossless copy fallback.
    let staged_c2p = probe(client, &pipe_c2p)?;
    let staged_p2c = match probe(upstream, &pipe_p2c) {
        Ok(n) => n,
        Err(SpliceError::Unsupported) if staged_c2p == 0 => return Err(SpliceError::Unsupported),
        Err(SpliceError::Unsupported) => {
            // Unreachable in practice (the first probe already succeeded on
            // the same kind of fds), but bytes have left the client socket,
            // so a copy fallback would lose them. Fail instead of silently
            // corrupting the stream.
            return Err(SpliceError::Io(io::Error::other(
                "splice probe failed after staging bytes",
            )));
        }
        Err(e) => return Err(e),
    };

    // Byte counters double as final stats when the drain deadline cancels
    // the surviving pump before it can return its own total.
    let (cnt_c2p, cnt_p2c) = match &progress {
        Some((up, down)) => (up.clone(), down.clone()),
        None => (
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    };
    let c2p = pump(
        client,
        upstream,
        &pipe_c2p,
        staged_c2p,
        Some(cnt_c2p.clone()),
    );
    let p2c = pump(
        upstream,
        client,
        &pipe_p2c,
        staged_p2c,
        Some(cnt_p2c.clone()),
    );
    tokio::pin!(c2p);
    tokio::pin!(p2c);

    // The first direction to finish half-closes the other (inside pump);
    // the survivor then drains until its own EOF or a full DRAIN_DEADLINE
    // without progress (a slow active download is never cut). An error in
    // either direction still cancels the whole relay, mirroring
    // `copy_bidirectional`.
    let c2p_first = match tokio::select! {
        r = &mut c2p => r.map(|_| true),
        r = &mut p2c => r.map(|_| false),
    } {
        Ok(b) => b,
        Err(e) => return Err(SpliceError::Io(e)),
    };
    let (survivor, survivor_cnt) = if c2p_first {
        (&mut p2c, &cnt_p2c)
    } else {
        (&mut c2p, &cnt_c2p)
    };
    match super::drain_wait(survivor, survivor_cnt).await {
        Ok(_) => {}
        Err(e) => return Err(SpliceError::Io(e)),
    }
    Ok((
        cnt_c2p.load(Ordering::Relaxed),
        cnt_p2c.load(Ordering::Relaxed),
    ))
}

/// Relay two plain TCP sockets with zero-copy `splice(2)`.
///
/// Returns the bytes moved in each direction `(client→upstream,
/// upstream→client)`, matching `tokio::io::copy_bidirectional` accounting.
///
/// Half-close propagation: when one direction reaches EOF, the opposite
/// socket's write side is shut down and the reverse direction drains until
/// its own EOF (bounded by [`DRAIN_DEADLINE`]) before returning. Both
/// sockets are shut down on exit.
///
/// Returns `ErrorKind::Unsupported` when the kernel rejects `splice(2)` on
/// the capability probe (before any byte is moved). Callers that still own
/// equivalent streams may then retry with the copy relay; [`relay_splice`]
/// handles that fallback itself.
pub async fn splice_bidirectional(
    client: TcpStream,
    upstream: TcpStream,
) -> io::Result<(u64, u64)> {
    let result = run(&client, &upstream, None).await;
    // Shut down both sides regardless of outcome (mirrors `relay_tcp`).
    shutdown_write(&client);
    shutdown_write(&upstream);
    match result {
        Ok(counts) => Ok(counts),
        Err(SpliceError::Unsupported) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "splice(2) not supported for these sockets",
        )),
        Err(SpliceError::Io(e)) => Err(e),
    }
}

/// Relay two plain TCP sockets, using zero-copy `splice(2)` when the kernel
/// supports it and falling back to the userspace copy relay otherwise.
///
/// Produces the exact same [`RelayStats`] accounting as [`relay_tcp`]; the
/// fallback is lossless because the capability probe runs before any byte
/// is moved, and it is latched process-wide so later connections go
/// straight to the copy path.
pub async fn relay_splice(
    client: TcpStream,
    upstream: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: super::RelayProgress,
) -> anyhow::Result<RelayStats> {
    if !splice_available() {
        return relay_tcp_counted(client, upstream, client_addr, target_addr, progress).await;
    }

    let start = tokio::time::Instant::now();

    debug!(
        "TCP splice relay started: {} → {}",
        client_addr, target_addr
    );

    match run(&client, &upstream, progress.clone()).await {
        Ok((c2p_bytes, p2c_bytes)) => {
            shutdown_write(&client);
            shutdown_write(&upstream);
            let duration_ms = start.elapsed().as_millis() as u64;
            let stats = RelayStats {
                client_to_proxy: c2p_bytes,
                proxy_to_client: p2c_bytes,
                total_bytes: c2p_bytes + p2c_bytes,
                duration_ms,
            };
            debug!(
                "TCP splice relay complete: {} → {} ({} bytes in {}ms)",
                client_addr, target_addr, stats.total_bytes, duration_ms
            );
            Ok(stats)
        }
        Err(SpliceError::Unsupported) => {
            SPLICE_UNSUPPORTED.store(true, Ordering::Relaxed);
            debug!(
                "splice(2) unsupported on this host; falling back to copy relay for {} → {}",
                client_addr, target_addr
            );
            relay_tcp_counted(client, upstream, client_addr, target_addr, progress).await
        }
        Err(SpliceError::Io(e)) => {
            shutdown_write(&client);
            shutdown_write(&upstream);
            if !is_ignorable_connection_error(&e) {
                warn!(
                    "TCP splice relay error for {} → {}: {}",
                    client_addr, target_addr, e
                );
            }
            Err(e.into())
        }
    }
}

/// `relay_tcp` with optional live progress counters: when provided, each
/// side is wrapped in a [`super::ReadCounter`] so byte totals update as data
/// flows, not only at close.
async fn relay_tcp_counted(
    client: TcpStream,
    upstream: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: super::RelayProgress,
) -> anyhow::Result<RelayStats> {
    match progress {
        Some((up, down)) => {
            relay_tcp(
                super::ReadCounter::wrap(client, up),
                super::ReadCounter::wrap(upstream, down),
                client_addr,
                target_addr,
            )
            .await
        }
        None => relay_tcp(client, upstream, client_addr, target_addr).await,
    }
}

/// Relay entry for proxy streams that are not plain TCP sockets (TLS- or
/// protocol-wrapped). Always uses the userspace copy relay; plain-TCP
/// direct connections go through [`relay_splice`] instead.
///
/// Both sides are generic over async I/O so the proxy side may be a plain TCP
/// socket or a TLS-wrapped stream. When `progress` is provided, byte totals
/// are updated live through the shared counters.
pub async fn relay_auto<S1, S2>(
    client: S1,
    proxy: S2,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: super::RelayProgress,
) -> anyhow::Result<RelayStats>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    match progress {
        Some((up, down)) => {
            super::relay_tcp(
                super::ReadCounter::wrap(client, up),
                super::ReadCounter::wrap(proxy, down),
                client_addr,
                target_addr,
            )
            .await
        }
        None => super::relay_tcp(client, proxy, client_addr, target_addr).await,
    }
}

/// Test-only hooks to exercise the capability-probe fallback without a
/// kernel that actually rejects `splice(2)`.
#[cfg(test)]
mod test_hook {
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    /// When non-zero, `probe()` fails with this errno instead of splicing.
    static FORCED_PROBE_ERRNO: AtomicI32 = AtomicI32::new(0);
    /// Number of `probe()` calls, to assert the probe is skipped once the
    /// global "unsupported" flag is latched.
    static PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub fn forced_probe_errno() -> Option<i32> {
        PROBE_CALLS.fetch_add(1, Ordering::Relaxed);
        match FORCED_PROBE_ERRNO.load(Ordering::Relaxed) {
            0 => None,
            e => Some(e),
        }
    }

    pub fn probe_calls() -> usize {
        PROBE_CALLS.load(Ordering::Relaxed)
    }

    pub fn set_forced_errno(errno: i32) {
        FORCED_PROBE_ERRNO.store(errno, Ordering::Relaxed);
    }

    pub fn reset() {
        FORCED_PROBE_ERRNO.store(0, Ordering::Relaxed);
        PROBE_CALLS.store(0, Ordering::Relaxed);
        super::SPLICE_UNSUPPORTED.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The probe fallback mutates process-global state, so all tests that
    /// go through `run()` serialize on this lock.
    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Reset global splice state even when a test panics.
    struct StateGuard;
    impl StateGuard {
        fn new() -> Self {
            test_hook::reset();
            StateGuard
        }
    }
    impl Drop for StateGuard {
        fn drop(&mut self) {
            test_hook::reset();
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Start a TCP echo server (writes back everything it reads, closes on
    /// EOF) and return its address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    /// Start a server that reads until EOF, then sends `trailer` and
    /// closes. Used to verify half-close propagation.
    async fn spawn_read_then_trailer(trailer: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sink = Vec::new();
                    let _ = stream.read_to_end(&mut sink).await;
                    let _ = stream.write_all(trailer).await;
                    // Dropping the stream closes the socket (FIN).
                });
            }
        });
        addr
    }

    /// Accept one connection on a fresh listener, dial `backend`, and relay
    /// between them with [`splice_bidirectional`].
    async fn spawn_splice_front(
        backend: SocketAddr,
    ) -> (SocketAddr, tokio::task::JoinHandle<io::Result<(u64, u64)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(backend).await.unwrap();
            splice_bidirectional(client, upstream).await
        });
        (front, relay)
    }

    #[test]
    fn test_is_unsupported_errno() {
        assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
            libc::EINVAL
        )));
        assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
            libc::ENOSYS
        )));
        assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
            libc::EXDEV
        )));
        assert!(!is_unsupported_errno(&io::Error::from_raw_os_error(
            libc::ECONNRESET
        )));
        assert!(!is_unsupported_errno(&io::Error::from_raw_os_error(
            libc::EAGAIN
        )));
        assert!(!is_unsupported_errno(&io::Error::other("synthetic")));
    }

    /// Two active directions are bounded to four private FDs and 128 KiB of
    /// requested pipe pages per full-duplex connection, down from the prior
    /// 512 KiB request. Pipes are never shared, so closing a connection
    /// cannot expose staged bytes to another one.
    #[test]
    fn test_full_duplex_pipe_resource_bound() {
        let client_to_upstream = Pipe::new().expect("create client pipe");
        let upstream_to_client = Pipe::new().expect("create upstream pipe");
        assert_ne!(
            client_to_upstream.read.as_raw_fd(),
            client_to_upstream.write.as_raw_fd()
        );
        assert_ne!(
            upstream_to_client.read.as_raw_fd(),
            upstream_to_client.write.as_raw_fd()
        );
        assert!(
            client_to_upstream.capacity <= PIPE_SIZE && upstream_to_client.capacity <= PIPE_SIZE,
            "kernel pipe capacity must remain within the requested per-direction bound"
        );
        assert!(
            client_to_upstream.capacity + upstream_to_client.capacity <= 2 * PIPE_SIZE,
            "full-duplex splice relay exceeds its 128 KiB pipe-page bound"
        );
    }

    /// Bidirectional transfer larger than any pipe capacity, with data
    /// integrity and per-direction byte counts verified.
    #[tokio::test]
    async fn test_splice_bidirectional_large_transfer() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();

        let echo = spawn_echo().await;
        let (front, relay) = spawn_splice_front(echo).await;

        let client = TcpStream::connect(front).await.unwrap();
        let data = pattern(4 * 1024 * 1024);
        let expected = data.clone();
        let (mut rd, mut wr) = client.into_split();

        let writer = tokio::spawn(async move {
            wr.write_all(&data).await.unwrap();
            // Half-close: the echo server sees EOF, closes, and the relay
            // must complete on its own.
            wr.shutdown().await.unwrap();
        });

        let mut received = Vec::with_capacity(expected.len());
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            rd.read_to_end(&mut received),
        )
        .await
        .expect("client read hung")
        .unwrap();
        writer.await.unwrap();

        assert_eq!(received.len(), expected.len());
        assert!(received == expected, "echoed data corrupted");

        let (c2p, p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap()
            .unwrap();
        assert_eq!(c2p, expected.len() as u64);
        assert_eq!(p2c, expected.len() as u64);
    }

    /// The client FINs its upload first; data already in flight from the
    /// server (sent after it sees EOF) must still be delivered — the
    /// reverse direction must survive the forward direction's EOF.
    #[tokio::test]
    async fn test_splice_half_close_propagation() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();

        let trailer: &'static [u8] = b"server trailer after client EOF";
        let backend = spawn_read_then_trailer(trailer).await;
        let (front, relay) = spawn_splice_front(backend).await;

        let mut client = TcpStream::connect(front).await.unwrap();
        let upload = pattern(1024 * 1024);
        client.write_all(&upload).await.unwrap();
        // Client half-closes; the trailer must still arrive.
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_to_end(&mut received),
        )
        .await
        .expect("client read hung — half-close not propagated")
        .unwrap();
        assert_eq!(received, trailer);

        let (c2p, p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap()
            .unwrap();
        assert_eq!(c2p, upload.len() as u64);
        assert_eq!(p2c, trailer.len() as u64);
    }

    /// A silent peer must not pin the relay forever: after the client
    /// EOFs, the surviving direction is cut at the drain deadline.
    #[tokio::test]
    async fn test_splice_drain_deadline_reaps_silent_peer() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();

        // Blackhole: accept and hold the socket, never read or write.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                std::mem::forget(stream);
            }
        });
        let (front, relay) = spawn_splice_front(backend).await;

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = pattern(64 * 1024);
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();

        let (c2p, _p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay pinned by silent peer")
            .unwrap()
            .unwrap();
        assert_eq!(c2p, payload.len() as u64);
    }

    /// `relay_splice` produces the same `RelayStats` shape as the copy path.
    #[tokio::test]
    async fn test_relay_splice_stats_match_copy_semantics() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();
        assert!(splice_available());

        let echo = spawn_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, client_addr) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay_splice(client, upstream, client_addr, echo, None)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = b"stats accounting roundtrip";
        client.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap();
        assert_eq!(stats.client_to_proxy, payload.len() as u64);
        assert_eq!(stats.proxy_to_client, payload.len() as u64);
        assert_eq!(stats.total_bytes, 2 * payload.len() as u64);
        assert!(splice_available());
    }

    /// Live progress counters are incremented as data flows and end up equal
    /// to the final RelayStats (splice path).
    #[tokio::test]
    async fn test_relay_splice_live_progress_matches_stats() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();
        assert!(splice_available());

        let echo = spawn_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let up = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let down = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (up2, down2) = (up.clone(), down.clone());
        let relay = tokio::spawn(async move {
            let (client, client_addr) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay_splice(client, upstream, client_addr, echo, Some((up2, down2))).await
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = pattern(512 * 1024);
        client.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        client.read_exact(&mut received).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap()
            .unwrap();
        assert_eq!(
            up.load(Ordering::Relaxed),
            stats.client_to_proxy,
            "live upload counter must match final stats"
        );
        assert_eq!(
            down.load(Ordering::Relaxed),
            stats.proxy_to_client,
            "live download counter must match final stats"
        );
        assert!(stats.client_to_proxy > 0);
    }

    /// Live progress counters work the same through the copy relay
    /// (`relay_auto` with wrapped streams).
    #[tokio::test]
    async fn test_relay_auto_live_progress_matches_stats() {
        let echo = spawn_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let up = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let down = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (up2, down2) = (up.clone(), down.clone());
        let relay = tokio::spawn(async move {
            let (client, client_addr) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay_auto(client, upstream, client_addr, echo, Some((up2, down2))).await
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = pattern(256 * 1024);
        client.write_all(&payload).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        client.read_exact(&mut received).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap()
            .unwrap();
        assert_eq!(up.load(Ordering::Relaxed), stats.client_to_proxy);
        assert_eq!(down.load(Ordering::Relaxed), stats.proxy_to_client);
        assert!(stats.client_to_proxy > 0);
    }

    /// A probe that fails with an unsupported errno must fall back to the
    /// copy relay without losing a single byte, latch the global flag, and
    /// skip probing for the next connection.
    #[tokio::test]
    async fn test_probe_failure_falls_back_to_copy() {
        let _lock = TEST_LOCK.lock().await;
        let _state = StateGuard::new();

        let echo = spawn_echo().await;

        // Arm the probe hook: the first connection's probes fail with EINVAL.
        test_hook::set_forced_errno(libc::EINVAL);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, client_addr) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay_splice(client, upstream, client_addr, echo, None)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = b"fallback keeps every byte";
        client.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_exact(&mut buf),
        )
        .await
        .expect("fallback copy hung")
        .unwrap();
        assert_eq!(&buf, payload);
        // The failed probe latched the process-wide flag.
        assert!(!splice_available());
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay task hung")
            .unwrap();
        assert_eq!(stats.client_to_proxy, payload.len() as u64);
        assert_eq!(stats.proxy_to_client, payload.len() as u64);

        // Second connection: the latched flag skips the probe entirely and
        // goes straight to the copy relay (hook still armed).
        let probes_before = test_hook::probe_calls();
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front2 = listener2.local_addr().unwrap();
        let relay2 = tokio::spawn(async move {
            let (client, client_addr) = listener2.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay_splice(client, upstream, client_addr, echo, None)
                .await
                .unwrap()
        });
        let mut client2 = TcpStream::connect(front2).await.unwrap();
        client2.write_all(payload).await.unwrap();
        let mut buf2 = vec![0u8; payload.len()];
        client2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, payload);
        client2.shutdown().await.unwrap();
        let stats2 = tokio::time::timeout(std::time::Duration::from_secs(5), relay2)
            .await
            .expect("relay task hung")
            .unwrap();
        assert_eq!(stats2.total_bytes, 2 * payload.len() as u64);
        assert_eq!(
            test_hook::probe_calls(),
            probes_before,
            "probe must be skipped once splice is known unsupported"
        );
    }
}
