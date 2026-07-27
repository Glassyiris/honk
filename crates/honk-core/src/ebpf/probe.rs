//! Runtime capability probing for batched `bpf()` map commands.
//!
//! aya 0.14 does not expose the batch map commands
//! (`BPF_MAP_LOOKUP_BATCH` / `BPF_MAP_DELETE_BATCH` / `BPF_MAP_UPDATE_BATCH`,
//! all Linux 5.6+) or `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (Linux 4.20+), so
//! `ebpf::real` issues them as raw syscalls.  Availability is detected at
//! runtime instead of relying on kernel version parsing: the first call
//! attempts the batch command and latches the outcome in a
//! [`BatchCapability`].  `Unsupported` is permanent — subsequent calls go
//! straight to the per-element fallback without touching the kernel.
//!
//! The latch is per command, not per (command, map): every map the batch
//! paths touch belongs to the htab family (`REDIRECT_TRACK`,
//! `ROUTING_HANDOFF_MAP`, `CONN_STATE_MAP` and `COOKIE_PID_MAP` are plain
//! hash), and `BPF_MAP_UPDATE_BATCH` is only used on the `ROUTING_MAP`
//! array, so a single verdict per command is valid for all of them.

use std::ffi::c_long;
use std::sync::atomic::{AtomicU8, Ordering};

/// Errno values that mean "this bpf() command (for this map type) is not
/// available on the running kernel":
/// - `EINVAL`: the command number is unknown (pre-5.6 kernels have no
///   batch commands; pre-4.20 kernels have no LOOKUP_AND_DELETE_ELEM);
/// - `EOPNOTSUPP` (== `ENOTSUP` on Linux): the map type provides no
///   implementation for the command;
/// - `EPERM`: bpf() is restricted (e.g. `kernel.unprivileged_bpf_disabled`
///   without the required capabilities);
/// - `ENOSYS`: the bpf() syscall is missing entirely.
pub fn is_capability_errno(errno: c_long) -> bool {
    errno == libc::EINVAL as c_long
        || errno == libc::EOPNOTSUPP as c_long
        || errno == libc::EPERM as c_long
        || errno == libc::ENOSYS as c_long
}

/// Tri-state latch recording whether one bpf() batch command works on the
/// running kernel: Unknown → (first attempt) → Supported | Unsupported.
///
/// Cheap to query (`Relaxed` atomic load) and safe to share behind `&self`
/// references, which is what the backend's read-locked map paths hold.
#[derive(Debug)]
pub struct BatchCapability(AtomicU8);

impl Default for BatchCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchCapability {
    const UNKNOWN: u8 = 0;
    const SUPPORTED: u8 = 1;
    const UNSUPPORTED: u8 = 2;

    pub const fn new() -> Self {
        Self(AtomicU8::new(Self::UNKNOWN))
    }

    /// True once a probe has conclusively failed.  Callers check this
    /// before attempting the batch syscall; while latched they go straight
    /// to the per-element fallback.
    pub fn is_unsupported(&self) -> bool {
        self.0.load(Ordering::Relaxed) == Self::UNSUPPORTED
    }

    /// Record the outcome of one batch attempt.
    ///
    /// Returns `true` when the caller should consume the batch result:
    /// the command succeeded, missed (`ENOENT` — the map command ran but
    /// found no entry / no more entries), or failed with a real error that
    /// the caller must propagate.  Returns `false` when the kernel lacks
    /// the command; `Unsupported` is then latched permanently and the
    /// caller must fall back to the per-element path.
    pub fn observe(&self, result: Result<(), c_long>) -> bool {
        match result {
            Ok(()) => {
                self.0.store(Self::SUPPORTED, Ordering::Relaxed);
                true
            }
            Err(e) if e == libc::ENOENT as c_long => {
                // Key miss / exhausted scan: the command itself executed.
                self.0.store(Self::SUPPORTED, Ordering::Relaxed);
                true
            }
            Err(e) if is_capability_errno(e) => {
                self.0.store(Self::UNSUPPORTED, Ordering::Relaxed);
                false
            }
            Err(_) => {
                // A real error (bad pointer, size mismatch, ...): the
                // command exists, so keep the current state and let the
                // caller propagate the error.
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_errno_classification() {
        assert!(is_capability_errno(libc::EINVAL as c_long));
        assert!(is_capability_errno(libc::EOPNOTSUPP as c_long));
        // ENOTSUP == EOPNOTSUPP on Linux; assert it explicitly for clarity.
        assert!(is_capability_errno(libc::ENOTSUP as c_long));
        assert!(is_capability_errno(libc::EPERM as c_long));
        assert!(is_capability_errno(libc::ENOSYS as c_long));
        assert!(!is_capability_errno(libc::ENOENT as c_long));
        assert!(!is_capability_errno(libc::EFAULT as c_long));
        assert!(!is_capability_errno(libc::E2BIG as c_long));
    }

    #[test]
    fn probe_latches_supported_on_success() {
        let cap = BatchCapability::new();
        assert!(!cap.is_unsupported());
        assert!(cap.observe(Ok(())));
        assert!(!cap.is_unsupported());
        // Subsequent successes keep the command usable.
        assert!(cap.observe(Ok(())));
        assert!(!cap.is_unsupported());
    }

    #[test]
    fn probe_treats_enoent_as_supported_miss() {
        let cap = BatchCapability::new();
        assert!(cap.observe(Err(libc::ENOENT as c_long)));
        assert!(!cap.is_unsupported());
    }

    #[test]
    fn probe_latches_unsupported_permanently() {
        let cap = BatchCapability::new();
        assert!(!cap.observe(Err(libc::EINVAL as c_long)));
        assert!(cap.is_unsupported());
        // The latch is terminal: callers check is_unsupported() before
        // attempting, so no further syscall is ever made.
        assert!(cap.is_unsupported());
    }

    #[test]
    fn probe_latches_unsupported_for_each_capability_errno() {
        for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::EPERM, libc::ENOSYS] {
            let cap = BatchCapability::new();
            assert!(!cap.observe(Err(errno as c_long)), "errno={}", errno);
            assert!(cap.is_unsupported(), "errno={}", errno);
        }
    }

    #[test]
    fn probe_propagates_real_errors_without_latching() {
        let cap = BatchCapability::new();
        // A genuine runtime error must be visible to the caller (true) and
        // must not poison the capability state.
        assert!(cap.observe(Err(libc::EFAULT as c_long)));
        assert!(!cap.is_unsupported());
    }

    #[test]
    fn probe_supported_then_capability_failure_still_latches() {
        // State machine ordering: a capability failure after earlier
        // successes still flips to Unsupported.
        let cap = BatchCapability::new();
        assert!(cap.observe(Ok(())));
        assert!(!cap.observe(Err(libc::EOPNOTSUPP as c_long)));
        assert!(cap.is_unsupported());
    }
}
