//! Thin libc wrappers: fds, epoll, timers, sockets, affinity, logcat and /proc telemetry.

use std::ffi::CString;
use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

// c_int on glibc, usize on bionic.
#[allow(clippy::unnecessary_cast)]
const CPU_SETSIZE: usize = libc::CPU_SETSIZE as usize;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_size(r: libc::ssize_t) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

// ---- logcat ----

#[cfg(target_os = "android")]
mod alog {
    #[link(name = "log")]
    unsafe extern "C" {
        pub fn __android_log_write(
            prio: libc::c_int,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> libc::c_int;
    }
}

fn log(prio: i32, msg: &str) {
    #[cfg(target_os = "android")]
    {
        let text = CString::new(msg.replace('\0', " ")).unwrap_or_default();
        // SAFETY: both strings are NUL-terminated and live for the call.
        unsafe { alog::__android_log_write(prio, c"HonkEngine".as_ptr(), text.as_ptr()) };
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("HonkEngine[{prio}]: {msg}");
}

pub fn log_info(msg: &str) {
    log(4, msg);
}

pub fn log_warn(msg: &str) {
    log(5, msg);
}

pub fn log_error(msg: &str) {
    log(6, msg);
}

// ---- fds ----

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a caller-provided fd; failures are reported.
    let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(())
}

pub fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf is valid for writes of buf.len() bytes.
    cvt_size(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) })
}

pub fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: buf is valid for reads of buf.len() bytes.
    cvt_size(unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) })
}

/// `send` without SIGPIPE.
pub fn send(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: buf is valid for reads of buf.len() bytes.
    cvt_size(unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) })
}

pub fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned from here on.
    let fd = cvt(unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn eventfd_signal(fd: RawFd) {
    let _ = write(fd, &1u64.to_ne_bytes());
}

/// Reads an eventfd or timerfd counter so level-triggered epoll stops reporting it.
pub fn drain_counter(fd: RawFd) {
    let mut b = [0u8; 8];
    let _ = read(fd, &mut b);
}

// ---- epoll ----

pub const EPOLLIN: u32 = libc::EPOLLIN as u32;
pub const EPOLLOUT: u32 = libc::EPOLLOUT as u32;
pub const EPOLLERR: u32 = libc::EPOLLERR as u32;
pub const EPOLLHUP: u32 = libc::EPOLLHUP as u32;
pub const EPOLLRDHUP: u32 = libc::EPOLLRDHUP as u32;
pub const EPOLLET: u32 = libc::EPOLLET as u32;

pub struct Epoll(OwnedFd);

impl Epoll {
    pub fn new() -> io::Result<Epoll> {
        // SAFETY: plain syscall; the fd is owned from here on.
        let fd = cvt(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        Ok(Epoll(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn ctl(&self, op: libc::c_int, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        let mut ev = libc::epoll_event { events, u64: token };
        // SAFETY: ev is a valid epoll_event for the call.
        cvt(unsafe { libc::epoll_ctl(self.0.as_raw_fd(), op, fd, &mut ev) })?;
        Ok(())
    }

    pub fn add(&self, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_ADD, fd, events, token)
    }

    pub fn modify(&self, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_MOD, fd, events, token)
    }

    /// Waits up to `timeout_ms` (-1: forever); EINTR returns zero events.
    pub fn wait(&self, events: &mut [libc::epoll_event], timeout_ms: i32) -> io::Result<usize> {
        // SAFETY: events is valid for events.len() entries.
        let n = unsafe {
            libc::epoll_wait(
                self.0.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout_ms,
            )
        };
        match cvt(n) {
            Ok(n) => Ok(n as usize),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
            Err(e) => Err(e),
        }
    }
}

// ---- timerfd ----

pub fn timerfd() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned from here on.
    let fd = cvt(unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Arms a one-shot relative timer (at least 1 ns, since zero would disarm it).
pub fn timerfd_arm(fd: RawFd, after: Duration) -> io::Result<()> {
    let after = after.max(Duration::from_nanos(1));
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: after.as_secs() as libc::time_t,
            tv_nsec: after.subsec_nanos() as libc::c_long,
        },
    };
    // SAFETY: spec is a valid itimerspec; the old value is not requested.
    cvt(unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) })?;
    Ok(())
}

// ---- sockets ----

/// A nonblocking TCP socket with TCP_NODELAY, connecting to `to`.
pub fn tcp_connect(to: SocketAddr) -> io::Result<OwnedFd> {
    let family = match to {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain syscall; the fd is owned from here on.
    let fd = cvt(unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    setsockopt_int(fd.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;

    // SAFETY: an all-zero sockaddr_storage is valid; the address is written into it below.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match to {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than sockaddr_in and suitably aligned.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: an all-zero sockaddr_in6 is valid.
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_scope_id = a.scope_id();
            // SAFETY: sockaddr_storage is larger than sockaddr_in6 and suitably aligned.
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin6) };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    // SAFETY: ss holds a valid address of `len` bytes.
    let r = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&ss as *const libc::sockaddr_storage).cast(),
            len as libc::socklen_t,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(fd)
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    v: libc::c_int,
) -> io::Result<()> {
    // SAFETY: v outlives the call and its size is passed.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&v as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// The pending socket error (SO_ERROR), zero if none.
pub fn so_error(fd: RawFd) -> io::Result<i32> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: v and len are valid for writes.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    })?;
    Ok(v)
}

pub fn shutdown_write(fd: RawFd) {
    // SAFETY: plain syscall.
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
}

/// Makes the coming close() send RST instead of FIN.
pub fn linger_zero(fd: RawFd) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: l outlives the call and its size is passed.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&l as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
}

// ---- threads, affinity ----

pub fn gettid() -> i32 {
    // SAFETY: plain syscall.
    unsafe { libc::gettid() }
}

/// Parses "0-2,7" into CPU numbers; empty input gives an empty list.
pub fn parse_cpu_list(s: &str) -> io::Result<Vec<usize>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("bad CPU list {s:?}"));
    let mut cpus = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (
                a.trim().parse().map_err(|_| bad())?,
                b.trim().parse().map_err(|_| bad())?,
            ),
            None => {
                let c: usize = part.parse().map_err(|_| bad())?;
                (c, c)
            }
        };
        if lo > hi || hi >= CPU_SETSIZE {
            return Err(bad());
        }
        cpus.extend(lo..=hi);
    }
    Ok(cpus)
}

/// Pins the calling thread; threads it creates afterwards inherit the mask.
pub fn set_affinity(cpus: &[usize]) -> io::Result<()> {
    // SAFETY: an all-zero cpu_set_t is the empty set; CPU_SET stays in bounds (checked by
    // parse_cpu_list); pid 0 is the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for &c in cpus {
            libc::CPU_SET(c, &mut set);
        }
        cvt(libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        ))?;
    }
    Ok(())
}

/// The calling thread's affinity as a CPU list ("0-1,7").
pub fn affinity_list() -> io::Result<String> {
    // SAFETY: set is valid for writes; CPU_ISSET reads within CPU_SETSIZE.
    let set = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        cvt(libc::sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut set,
        ))?;
        set
    };
    let cpus: Vec<usize> = (0..CPU_SETSIZE)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cpus.len() {
        let mut j = i;
        while j + 1 < cpus.len() && cpus[j + 1] == cpus[j] + 1 {
            j += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if i == j {
            let _ = write!(out, "{}", cpus[i]);
        } else {
            let _ = write!(out, "{}-{}", cpus[i], cpus[j]);
        }
        i = j + 1;
    }
    Ok(out)
}

/// Names the calling thread (comm, at most 15 bytes); threads it creates inherit the name.
pub fn set_thread_name(name: &str) {
    let mut n: String = name.chars().filter(|&c| c != '\0').collect();
    n.truncate(15);
    if let Ok(c) = CString::new(n) {
        // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most 16 bytes.
        unsafe { libc::prctl(libc::PR_SET_NAME, c.as_ptr() as libc::c_ulong, 0, 0, 0) };
    }
}

/// Lowest TID of this process whose comm is `name`, other than `exclude`.
pub fn find_thread(name: &str, exclude: i32) -> Option<i32> {
    std::fs::read_dir("/proc/self/task")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&tid| tid != exclude)
        .filter(|&tid| {
            std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
                .is_ok_and(|c| c.trim_end_matches('\n') == name)
        })
        .min()
}

// ---- telemetry ----

/// One line of `key=value` pairs for thread `tid` of this process: stat utime, stime (clock
/// ticks) and processor, se.nr_migrations when /proc/.../sched is readable, context switches and
/// Cpus_allowed_list from status, plus the process cpuset and the tick rate.
pub fn telemetry(tid: i32) -> String {
    // SAFETY: plain libc query.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let mut out = format!("tid={tid} clk_tck={hz}");
    let base = format!("/proc/self/task/{tid}");
    match std::fs::read_to_string(format!("{base}/stat")) {
        Ok(stat) if tid > 0 => {
            if let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) {
                let comm: String = stat[open + 1..close]
                    .chars()
                    .map(|c| if c.is_whitespace() { '_' } else { c })
                    .collect();
                // Field 3 (state) is the first after the closing parenthesis.
                let f: Vec<&str> = stat[close + 1..].split_whitespace().collect();
                let field = |n: usize| f.get(n - 3).copied().unwrap_or("?");
                let _ = write!(
                    out,
                    " comm={comm} state={} utime={} stime={} processor={}",
                    field(3),
                    field(14),
                    field(15),
                    field(39)
                );
            }
        }
        _ => out.push_str(" error=no_such_thread"),
    }
    if let Ok(sched) = std::fs::read_to_string(format!("{base}/sched"))
        && let Some(v) = sched
            .lines()
            .find(|l| l.trim_start().starts_with("se.nr_migrations"))
            .and_then(|l| l.split(':').nth(1))
    {
        let _ = write!(out, " nr_migrations={}", v.trim());
    }
    if let Ok(status) = std::fs::read_to_string(format!("{base}/status")) {
        for (key, name) in [
            ("voluntary_ctxt_switches", "voluntary_ctxt_switches"),
            ("nonvoluntary_ctxt_switches", "nonvoluntary_ctxt_switches"),
            ("Cpus_allowed_list", "cpus_allowed_list"),
        ] {
            if let Some(v) = status
                .lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            {
                let _ = write!(out, " {name}={}", v.trim());
            }
        }
    }
    let cpuset = std::fs::read_to_string("/proc/self/cpuset")
        .map(|s| s.trim().replace(char::is_whitespace, "_"))
        .unwrap_or_else(|_| "?".into());
    let _ = write!(out, " cpuset={cpuset}");
    out
}
