//! Per-thread readings from /proc/self/task, parsed by procfs: the bench accounting's samples and
//! the telemetry line. Reads only this process's threads and never writes; any thread may call.
//! procfs is used here and nowhere else in the crate.

use super::{clock_ticks, cvt, format_cpu_list};
use procfs::FromRead;
use procfs::process::{Schedstat, Stat, Status};
use std::ffi::CStr;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

fn proc_error(e: procfs::ProcError) -> io::Error {
    io::Error::other(e.to_string())
}

/// This process's cpuset ("/top-app").
pub fn cpuset() -> io::Result<String> {
    std::fs::read_to_string("/proc/self/cpuset").map(|s| s.trim().to_owned())
}

/// A thread of this process, held open (an O_PATH descriptor of its directory): once it exits,
/// readings fail instead of reading a newer thread that reuses its TID. Not procfs's `Process`
/// and `Task`: opening a `Process` reads /proc/sys/kernel/osrelease, which an app may not read,
/// and every denial is an audit record that the kernel and logd write inside the window.
pub struct Thread(File);

/// One reading of a thread's counters.
pub struct ThreadSample {
    pub comm: String,
    /// stat utime and stime, in clock ticks.
    pub utime: u64,
    pub stime: u64,
    /// The CPU it last ran on.
    pub processor: Option<i32>,
    /// schedstat sum_exec_runtime in ns, or why it could not be read.
    pub runtime_ns: Result<u64, String>,
    /// status voluntary and nonvoluntary context switches, or why they could not be read.
    pub ctxt_switches: Result<(u64, u64), String>,
}

impl Thread {
    pub fn open(tid: i32) -> io::Result<Thread> {
        (OpenOptions::new().read(true))
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(format!("/proc/self/task/{tid}"))
            .map(Thread)
    }

    /// Parses the file `name` in the thread's directory.
    fn read<T: FromRead>(&self, name: &CStr) -> io::Result<T> {
        let flags = libc::O_RDONLY | libc::O_CLOEXEC;
        // SAFETY: the directory fd is open and `name` NUL-terminated for the call; the fd it
        // returns is new, and the File takes it over.
        let file = unsafe {
            let fd = cvt(libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags))?;
            File::from_raw_fd(fd)
        };
        T::from_read(file).map_err(proc_error)
    }

    /// The CPUs it may run on (status Cpus_allowed_list), ascending; read through the handle, so
    /// it fails once the thread is gone.
    pub fn affinity(&self) -> io::Result<Vec<usize>> {
        let status: Status = self.read(c"status")?;
        (status.cpus_allowed_list.as_deref())
            .map(cpus)
            .ok_or_else(|| io::Error::other("status: no Cpus_allowed_list"))
    }

    /// Fails only if the thread is gone.
    pub fn sample(&self) -> io::Result<ThreadSample> {
        let stat: Stat = self.read(c"stat")?;
        let ctxt_switches = match self.read::<Status>(c"status") {
            Ok(s) => s
                .voluntary_ctxt_switches
                .zip(s.nonvoluntary_ctxt_switches)
                .ok_or_else(|| "status: no ctxt_switches lines".to_owned()),
            Err(e) => Err(format!("status: {e}")),
        };
        Ok(ThreadSample {
            comm: stat.comm,
            utime: stat.utime,
            stime: stat.stime,
            processor: stat.processor,
            runtime_ns: (self.read::<Schedstat>(c"schedstat"))
                .map(|s| s.sum_exec_runtime)
                .map_err(|e| format!("schedstat: {e}")),
            ctxt_switches,
        })
    }
}

fn cpus(ranges: &[(u32, u32)]) -> Vec<usize> {
    (ranges.iter())
        .flat_map(|&(lo, hi)| lo as usize..=hi as usize)
        .collect()
}

// ---- telemetry ----

/// One line of `key=value` pairs for thread `tid` of this process: stat utime, stime (clock
/// ticks) and processor, se.nr_migrations when /proc/.../sched is readable, context switches and
/// Cpus_allowed_list from status, plus the process cpuset and the tick rate.
pub fn telemetry(tid: i32) -> String {
    let mut out = format!("tid={tid} clk_tck={}", clock_ticks());
    let task = Thread::open(tid).ok();
    match task.as_ref().map(|t| t.read::<Stat>(c"stat")) {
        Some(Ok(stat)) if tid > 0 => {
            let comm: String = stat
                .comm
                .chars()
                .map(|c| if c.is_whitespace() { '_' } else { c })
                .collect();
            let processor = stat.processor.map_or_else(|| "?".into(), |p| p.to_string());
            let _ = write!(
                out,
                " comm={comm} state={} utime={} stime={} processor={processor}",
                stat.state, stat.utime, stat.stime
            );
        }
        _ => out.push_str(" error=no_such_thread"),
    }
    // procfs has no parser for `sched`.
    if let Ok(sched) = std::fs::read_to_string(format!("/proc/self/task/{tid}/sched"))
        && let Some(v) = sched
            .lines()
            .find(|l| l.trim_start().starts_with("se.nr_migrations"))
            .and_then(|l| l.split(':').nth(1))
    {
        let _ = write!(out, " nr_migrations={}", v.trim());
    }
    if let Some(Ok(status)) = task.as_ref().map(|t| t.read::<Status>(c"status")) {
        for (name, v) in [
            ("voluntary_ctxt_switches", status.voluntary_ctxt_switches),
            (
                "nonvoluntary_ctxt_switches",
                status.nonvoluntary_ctxt_switches,
            ),
        ] {
            if let Some(v) = v {
                let _ = write!(out, " {name}={v}");
            }
        }
        if let Some(ranges) = &status.cpus_allowed_list {
            let _ = write!(out, " cpus_allowed_list={}", format_cpu_list(&cpus(ranges)));
        }
    }
    let cpuset = cpuset()
        .map(|s| s.replace(char::is_whitespace, "_"))
        .unwrap_or_else(|_| "?".into());
    let _ = write!(out, " cpuset={cpuset}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{affinity, affinity_list, gettid, parse_cpu_list};
    use std::time::{Duration, Instant};

    #[test]
    fn telemetry_keeps_its_keys() {
        let line = telemetry(gettid());
        let keys: Vec<&str> = line
            .split(' ')
            .map(|kv| kv.split_once('=').unwrap().0)
            .collect();
        let mut want = vec![
            "tid",
            "clk_tck",
            "comm",
            "state",
            "utime",
            "stime",
            "processor",
        ];
        if line.contains(" nr_migrations=") {
            want.push("nr_migrations");
        }
        want.extend([
            "voluntary_ctxt_switches",
            "nonvoluntary_ctxt_switches",
            "cpus_allowed_list",
            "cpuset",
        ]);
        assert_eq!(keys, want, "{line}");
        let allowed = line.split(" cpus_allowed_list=").nth(1).unwrap();
        let allowed = allowed.split(' ').next().unwrap();
        assert_eq!(allowed, affinity_list().unwrap());
        assert!(telemetry(0).contains(" error=no_such_thread"));
    }

    #[test]
    fn cpu_lists_round_trip() {
        for s in ["7", "0-1", "0-2,7", "0,2,4-5"] {
            assert_eq!(format_cpu_list(&parse_cpu_list(s).unwrap()), s);
        }
    }

    #[test]
    fn a_thread_reads_fail_once_it_exits() {
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            tx.send(gettid()).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let thread = Thread::open(rx.recv().unwrap()).unwrap();
        let s = thread.sample().unwrap();
        assert!(s.runtime_ns.is_ok() && s.ctxt_switches.is_ok());
        assert_eq!(thread.affinity().unwrap(), affinity(0).unwrap());
        t.join().unwrap();
        // join returns slightly before the kernel releases the task.
        let deadline = Instant::now() + Duration::from_secs(5);
        while thread.sample().is_ok() {
            assert!(Instant::now() < deadline, "still readable");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(thread.affinity().is_err());
    }
}
