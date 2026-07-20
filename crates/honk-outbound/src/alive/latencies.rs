//! Ring buffer of last N latency samples with O(1) statistics.

use parking_lot::Mutex;
use std::time::Duration;

pub(crate) struct Latencies10 {
    buf: Vec<Duration>,
    head: usize,
    len: usize,
    sum: Duration,
    cap: usize,
}

impl Latencies10 {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            buf: vec![Duration::ZERO; n],
            head: 0,
            len: 0,
            sum: Duration::ZERO,
            cap: n,
        }
    }

    pub(crate) fn append(&mut self, latency: Duration) {
        if self.len < self.cap {
            self.buf[self.len] = latency;
            self.sum += latency;
            self.len += 1;
        } else {
            let old = self.buf[self.head];
            self.buf[self.head] = latency;
            self.head = (self.head + 1) % self.cap;
            self.sum = self.sum - old + latency;
        }
    }

    pub(crate) fn last(&self) -> Option<Duration> {
        if self.len == 0 {
            return None;
        }
        let idx = if self.len < self.cap {
            self.len - 1
        } else {
            (self.head + self.cap - 1) % self.cap
        };
        Some(self.buf[idx])
    }

    pub(crate) fn avg(&self) -> Option<Duration> {
        if self.len == 0 {
            return None;
        }
        Some(self.sum / self.len as u32)
    }

    #[allow(dead_code)]
    pub(crate) fn count(&self) -> usize {
        self.len
    }
}

pub(crate) struct SyncLatencies10 {
    inner: Mutex<Latencies10>,
}

impl SyncLatencies10 {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            inner: Mutex::new(Latencies10::new(n)),
        }
    }

    pub(crate) fn append(&self, latency: Duration) {
        self.inner.lock().append(latency);
    }

    pub(crate) fn last(&self) -> Option<Duration> {
        self.inner.lock().last()
    }

    pub(crate) fn avg(&self) -> Option<Duration> {
        self.inner.lock().avg()
    }

    #[allow(dead_code)]
    pub(crate) fn count(&self) -> usize {
        self.inner.lock().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_last() {
        let mut l = Latencies10::new(10);
        l.append(Duration::from_millis(5));
        l.append(Duration::from_millis(15));
        assert_eq!(l.last(), Some(Duration::from_millis(15)));
        assert_eq!(l.count(), 2);
        assert_eq!(l.avg(), Some(Duration::from_millis(10)));
    }

    #[test]
    fn test_ring_overflow() {
        let mut l = Latencies10::new(3);
        l.append(Duration::from_secs(1));
        l.append(Duration::from_secs(2));
        l.append(Duration::from_secs(3));
        l.append(Duration::from_secs(4));
        assert_eq!(l.last(), Some(Duration::from_secs(4)));
        assert_eq!(l.count(), 3);
        assert_eq!(l.avg(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn test_empty() {
        let l = Latencies10::new(5);
        assert_eq!(l.last(), None);
        assert_eq!(l.avg(), None);
        assert_eq!(l.count(), 0);
    }
}
