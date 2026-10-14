//! Whether a source's uplink is wedged: it still takes datagrams from the
//! driver but admits none of them.

use super::*;

/// An unadmitted send deadline is packet-local, but a source whose uplink
/// admits nothing would otherwise live on as long as replies arrive. A run of
/// unadmitted deadlines, none further apart than this and none interrupted by
/// an admitted datagram, that lasts this long is a transport failure, as an
/// admitted deadline already is.
const LIMIT: Duration = Duration::from_secs(30);

/// Monotonic nanos of the first and the latest unadmitted deadline of a stall
/// run; the start is zero while the uplink admits datagrams.
///
/// Two atomics rather than a lock under the source: a concurrent admission can
/// race a deadline that an old run already made due, which at this scale only
/// shifts a decision the limit has long since settled.
#[derive(Debug, Default)]
pub(in crate::control) struct UplinkStall {
    started: AtomicI64,
    latest: AtomicI64,
}

impl UplinkStall {
    /// A datagram reached the wire path, so nothing is stalled any more.
    pub(in crate::control) fn admitted(&self) {
        if self.started.load(Ordering::Relaxed) != 0 {
            self.started.store(0, Ordering::Relaxed);
        }
    }

    /// Records a send deadline the transport never admitted; true once the
    /// current stall run has lasted [`LIMIT`].
    pub(in crate::control) fn unadmitted_deadline(&self) -> bool {
        let now = monotonic_nanos().max(1);
        let limit = nanos_from_dur(LIMIT);
        let latest = self.latest.swap(now, Ordering::Relaxed);
        let started = self.started.load(Ordering::Relaxed);
        if started == 0 || now.saturating_sub(latest) > limit {
            self.started.store(now, Ordering::Relaxed);
            return false;
        }
        now.saturating_sub(started) >= limit
    }

    /// Pretends the current stall run began [`LIMIT`] ago, its latest deadline
    /// either just now or before a quiet gap past the limit.
    #[cfg(test)]
    pub(in crate::control) fn backdate_for_test(&self, quiet_gap: bool) {
        let now = monotonic_nanos();
        let limit = nanos_from_dur(LIMIT);
        self.started.store(now - limit, Ordering::Relaxed);
        self.latest.store(
            if quiet_gap {
                now - limit - nanos_from_dur(Duration::from_secs(1))
            } else {
                now
            },
            Ordering::Relaxed,
        );
    }
}
