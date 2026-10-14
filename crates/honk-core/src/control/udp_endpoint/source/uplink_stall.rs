//! Whether a source's uplink is wedged: it still takes datagrams from the
//! driver but admits none of them.

use super::*;

/// An unadmitted send deadline is packet-local, but a source whose uplink
/// admits nothing would otherwise live on as long as replies arrive. A run of
/// unadmitted deadlines, none interrupted by an admitted datagram, that lasts
/// this long is a transport failure, as an admitted deadline already is: how
/// far apart the deadlines fall says nothing about whether the uplink works.
const LIMIT: Duration = Duration::from_secs(30);

/// Monotonic nanos of the first unadmitted deadline of a stall run; the start
/// is zero while the uplink admits datagrams.
///
/// One atomic rather than a lock under the source: a concurrent admission can
/// race a deadline that an old run already made due, which at this scale only
/// shifts a decision the limit has long since settled.
#[derive(Debug, Default)]
pub(in crate::control) struct UplinkStall {
    started: AtomicI64,
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
        let started = self.started.load(Ordering::Relaxed);
        if started == 0 {
            self.started.store(now, Ordering::Relaxed);
            return false;
        }
        now.saturating_sub(started) >= nanos_from_dur(LIMIT)
    }

    /// Pretends the current stall run began [`LIMIT`] ago, so its next
    /// deadline is due.
    #[cfg(test)]
    pub(in crate::control) fn backdate_for_test(&self) {
        self.backdate(LIMIT);
    }

    #[cfg(test)]
    fn backdate(&self, age: Duration) {
        self.started
            .store(monotonic_nanos() - nanos_from_dur(age), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_inside_the_limit_stays_packet_local() {
        let stall = UplinkStall::default();
        assert!(!stall.unadmitted_deadline());
        stall.backdate(Duration::from_secs(5));
        assert!(!stall.unadmitted_deadline());
    }

    /// An uplink that admits nothing stays wedged however its datagrams are
    /// spaced, so a deadline after a quiet gap must not restart the run.
    #[test]
    fn a_deadline_after_a_quiet_gap_still_counts_the_whole_run() {
        let stall = UplinkStall::default();
        stall.backdate(Duration::from_secs(40));
        assert!(stall.unadmitted_deadline());
    }

    #[test]
    fn an_admitted_datagram_ends_the_run() {
        let stall = UplinkStall::default();
        stall.backdate(Duration::from_secs(40));
        stall.admitted();
        assert!(!stall.unadmitted_deadline());
    }
}
