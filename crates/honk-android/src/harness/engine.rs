//! The engine under test: starting it on a tun fd with every flow sent towards the sink (directly
//! for honk, through the relay for hev), listing its threads, reading its tun counters, stopping
//! it, and the warmup connection that proves the path first.
//!
//! The runner thread calls these, one engine at a time: honk-android's counters are
//! process-wide. `start` blocks until the engine is up, `warmup` until its deadline at most; the
//! host's `stop_hev` waits for hev's thread.

use super::account::Tun;
use super::load::{CANCELLED, Stop, WARMUP};
use super::plan::{Cpus, Engine};
use super::relay::Relay;
use super::run::Host;
use super::sink::Sink;
use crate::engine as honk;
use crate::sys;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::RawFd;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::time::{Duration, Instant};

/// The name of the thread that starts hev. hev names none of its threads, so each inherits this
/// one, those it creates later included.
pub const HEV_THREAD: &str = "tb-hev";

pub enum Running {
    Honk(honk::Handle),
    Hev,
}

/// Starts `engine` on `tun`, its flows going to `upstream` (the sink for honk, the relay for
/// hev). The start runs on a thread pinned to `cpus` and named after the engine, so every thread
/// the engine creates inherits both.
pub fn start(
    engine: Engine,
    tun: RawFd,
    mtu: u16,
    upstream: SocketAddr,
    cpus: &Cpus,
    host: &dyn Host,
) -> Result<Running, String> {
    let name = match engine {
        Engine::Honk => "honk-start",
        Engine::Hev => HEV_THREAD,
    };
    thread::scope(|s| {
        let starter = thread::Builder::new()
            .name(name.into())
            .spawn_scoped(s, || {
                sys::set_affinity(cpus.as_slice())
                    .map_err(|e| format!("pin the engine to {cpus}: {e}"))?;
                start_here(engine, tun, mtu, upstream, cpus, host)
            })
            .map_err(|e| format!("spawn {name}: {e}"))?;
        starter.join().map_err(|_| format!("{name} panicked"))?
    })
}

fn start_here(
    engine: Engine,
    tun: RawFd,
    mtu: u16,
    upstream: SocketAddr,
    cpus: &Cpus,
    host: &dyn Host,
) -> Result<Running, String> {
    match engine {
        Engine::Honk => honk::Params::parse(
            tun,
            i32::from(mtu),
            &upstream.ip().to_string(),
            i32::from(upstream.port()),
            &cpus.to_string(),
        )
        .and_then(honk::start)
        .map(Running::Honk)
        .map_err(|e| format!("honk: {e}")),
        Engine::Hev => host
            .start_hev(&hev_config(mtu, upstream), tun)
            .map(|()| Running::Hev),
    }
}

/// The app's manual-mode config, with the relay as the SOCKS5 server.
fn hev_config(mtu: u16, socks: SocketAddr) -> String {
    format!(
        "tunnel:\n  mtu: {mtu}\n  ipv4: 198.18.0.2\nsocks5:\n  port: {}\n  address: '{}'\n  \
         udp: 'tcp'\nmisc:\n  log-level: warn\n",
        socks.port(),
        socks.ip()
    )
}

impl Running {
    /// The engine's threads now: honk's worker, or every thread named `HEV_THREAD`.
    pub fn threads(&self) -> Result<Vec<i32>, String> {
        match self {
            Running::Honk(_) => Ok(vec![honk::SHARED.tid.load(Relaxed)]),
            Running::Hev => {
                sys::threads_named(HEV_THREAD).map_err(|e| format!("list threads: {e}"))
            }
        }
    }

    pub fn tun(&self, host: &dyn Host) -> Result<Tun, String> {
        match self {
            Running::Honk(_) => {
                let s = &honk::SHARED;
                Ok(Tun {
                    reads: s.tx_packets.load(Relaxed),
                    read_bytes: s.tx_bytes.load(Relaxed),
                    writes: s.rx_packets.load(Relaxed),
                    write_bytes: s.rx_bytes.load(Relaxed),
                })
            }
            Running::Hev => host.hev_tun(),
        }
    }

    /// Stops the engine and waits for its threads; the tun fd stays open. Err if it may still
    /// run.
    pub fn stop(self, host: &dyn Host) -> Result<(), String> {
        match self {
            Running::Honk(h) => {
                h.stop();
                Ok(())
            }
            Running::Hev => host.stop_hev(),
        }
    }
}

/// Opens one connection to `target` through the engine and waits until the sink has read it and
/// it has ended at the sink and the relay, so the whole path is known to work and no connection
/// thread is left over. Every wait ends by the deadline, or with `CANCELLED` once `stop` is set.
pub fn warmup(
    target: SocketAddr,
    sink: &Sink,
    relay: Option<&Relay>,
    stop: &Stop,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let left = || deadline.saturating_duration_since(Instant::now());
    let warmups = sink.warmups();
    let mut s = loop {
        if stop.is_set() {
            return Err(CANCELLED.into());
        }
        // A SYN sent before the engine reads the tun is retransmitted only after a second.
        match TcpStream::connect_timeout(&target, left().min(Duration::from_secs(1))) {
            Ok(s) => break s,
            Err(e) if left().is_zero() => {
                return Err(format!("warmup: no connection to {target}: {e}"));
            }
            Err(_) => {
                stop.wait(Duration::from_millis(100));
            }
        }
    };
    s.write_all(WARMUP)
        .and_then(|()| s.shutdown(Shutdown::Write))
        .map_err(|e| format!("warmup through {target}: {e}"))?;
    // The sink reads to EOF and closes, so the read sees EOF once the path has carried both.
    let mut ended = Ok(());
    stop.wait_for(
        deadline,
        |until| {
            let slice = until.saturating_duration_since(Instant::now());
            let read = s
                .set_read_timeout(Some(slice.max(Duration::from_millis(1))))
                .and_then(|()| s.read(&mut [0u8; 1]));
            match read {
                Ok(0) => true,
                Ok(_) => {
                    ended = Err("warmup: the sink sent data".into());
                    true
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
                Err(e) => {
                    ended = Err(format!("warmup through {target}: {e}"));
                    true
                }
            }
        },
        || format!("warmup: no answer through {target} within {timeout:?}"),
    )?;
    ended?;
    let idle =
        |until| sink.server.wait_idle(until) && relay.is_none_or(|r| r.server.wait_idle(until));
    stop.wait_for(deadline, idle, || {
        "warmup: the connection did not end at the sink".into()
    })?;
    if sink.warmups() == warmups {
        return Err("warmup: the sink did not receive it".into());
    }
    Ok(())
}
