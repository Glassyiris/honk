//! The [`CompletionRing`] is a consumer ring that userspace can dequeue packets
//! that have been sent on the NIC queue the ring is bound to

use crate::{FrameError, Umem, libc::rings};

/// The ring used to dequeue buffers that the kernel has finished sending
pub struct CompletionRing {
    ring: super::XskConsumer<u64>,
    quarantine: Vec<usize>,
    next_quarantine: Vec<usize>,
    _mmap: crate::mmap::Mmap,
}

impl CompletionRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.completion_count,
            rings::RingPageOffsets::Completion,
            &offsets.completion,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Completion,
        })?;

        ring.cached_consumed = 0;
        ring.cached_produced = 0;

        Ok(Self {
            ring: super::XskConsumer(ring),
            quarantine: Vec::with_capacity(cfg.completion_count as usize),
            next_quarantine: Vec::with_capacity(cfg.completion_count as usize),
            _mmap,
        })
    }

    /// Dequeues every completion currently visible, up to `capacity`.
    ///
    /// The operation fails without consuming descriptors when `capacity` is too
    /// small. Completed frames remain quarantined until the next full drain
    /// observes no stale duplicate before making those frames allocatable again.
    pub fn dequeue(&mut self, umem: &Umem, capacity: usize) -> Result<usize, FrameError> {
        let available = self.checked_available(capacity)?;
        let (actual, idx) = self.ring.peek(available as u32);
        debug_assert_eq!(actual, available);
        debug_assert!(self.next_quarantine.is_empty());
        let mut first_error = None;
        for i in idx..idx + actual {
            let address = self.ring.get(i);
            match umem.complete_addr(address) {
                Ok(frame) => self.next_quarantine.push(frame),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if actual > 0 {
            self.ring.release(actual as _);
        }
        self.finish_batch(umem, first_error)?;
        Ok(actual)
    }

    fn checked_available(&mut self, capacity: usize) -> Result<usize, FrameError> {
        let available = self.ring.available(u32::MAX) as usize;
        validate_completion_capacity(available, capacity)?;
        Ok(available)
    }

    fn finish_batch(
        &mut self,
        umem: &Umem,
        batch_error: Option<FrameError>,
    ) -> Result<(), FrameError> {
        preserve_failed_batch(&mut self.quarantine, &mut self.next_quarantine, batch_error)?;

        let mut release_error = None;
        self.quarantine.retain(|frame| {
            if let Err(error) = umem.release_completion(*frame) {
                release_error.get_or_insert(error);
                true
            } else {
                false
            }
        });
        if let Some(error) = release_error {
            self.quarantine.append(&mut self.next_quarantine);
            return Err(error);
        }
        std::mem::swap(&mut self.quarantine, &mut self.next_quarantine);
        Ok(())
    }

    /// The same as [`Self::dequeue`], except the timestamp for each packet is
    /// written to the provided slice.
    ///
    /// Note this requires that [`crate::Packet::set_tx_metadata`] was called.
    pub fn dequeue_with_timestamps(
        &mut self,
        umem: &Umem,
        timestamps: &mut [u64],
    ) -> Result<usize, FrameError> {
        let available = self.checked_available(timestamps.len())?;
        let (actual, idx) = self.ring.peek(available as u32);
        debug_assert_eq!(actual, available);
        debug_assert!(self.next_quarantine.is_empty());
        let mut first_error = None;
        for (timestamp, i) in timestamps.iter_mut().zip(idx..idx + actual) {
            let address = self.ring.get(i);
            match umem.get_completion_timestamp(address) {
                Ok((frame, value)) => {
                    self.next_quarantine.push(frame);
                    *timestamp = value;
                }
                Err(error) => {
                    *timestamp = 0;
                    first_error.get_or_insert(error);
                }
            }
        }
        if actual > 0 {
            self.ring.release(actual as _);
        }
        self.finish_batch(umem, first_error)?;
        Ok(actual)
    }
}

fn preserve_failed_batch(
    quarantine: &mut Vec<usize>,
    next_quarantine: &mut Vec<usize>,
    error: Option<FrameError>,
) -> Result<(), FrameError> {
    if let Some(error) = error {
        quarantine.append(next_quarantine);
        return Err(error);
    }
    Ok(())
}

fn validate_completion_capacity(available: usize, capacity: usize) -> Result<(), FrameError> {
    if available > capacity {
        return Err(FrameError::CompletionBatchTooSmall {
            available,
            capacity,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_completion_batches_are_rejected() {
        assert!(validate_completion_capacity(0, 0).is_ok());
        assert!(validate_completion_capacity(4, 4).is_ok());
        assert!(matches!(
            validate_completion_capacity(2, 1),
            Err(FrameError::CompletionBatchTooSmall {
                available: 2,
                capacity: 1
            })
        ));
    }

    #[test]
    fn failed_batch_keeps_successful_completions_quarantined() {
        let mut quarantine = vec![1];
        let mut next = vec![2, 3];
        let error = preserve_failed_batch(
            &mut quarantine,
            &mut next,
            Some(FrameError::InvalidLength {
                length: 65,
                capacity: 64,
            }),
        )
        .unwrap_err();

        assert!(matches!(error, FrameError::InvalidLength { .. }));
        assert_eq!(quarantine, vec![1, 2, 3]);
        assert!(next.is_empty());
    }
}
