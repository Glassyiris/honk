//! The [`CompletionRing`] is a consumer ring that userspace can dequeue packets
//! that have been sent on the NIC queue the ring is bound to

use crate::{FrameError, Umem, libc::rings};

/// The ring used to dequeue buffers that the kernel has finished sending
pub struct CompletionRing {
    ring: super::XskConsumer<u64>,
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
            _mmap,
        })
    }

    /// Dequeues up to `num_packets` and makes them available for use again
    ///
    /// # Returns
    ///
    /// The number of packets that were actually dequeued.
    pub fn dequeue(&mut self, umem: &Umem, num_packets: usize) -> Result<usize, FrameError> {
        if num_packets == 0 {
            return Ok(0);
        }

        let (actual, idx) = self.ring.peek(num_packets as _);
        let mut first_error = None;
        for i in idx..idx + actual {
            let address = self.ring.get(i);
            if let Err(error) = umem.complete_addr(address) {
                first_error.get_or_insert(error);
            }
        }
        if actual > 0 {
            self.ring.release(actual as _);
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(actual)
        }
    }

    /// The same as [`Self::dequeue`], except the timestamp each packet was
    /// transmitted is written to the provided slice.
    ///
    /// Note this requires that [`crate::Packet::set_tx_metadata`] was called
    pub fn dequeue_with_timestamps(
        &mut self,
        umem: &Umem,
        timestamps: &mut [u64],
    ) -> Result<usize, FrameError> {
        if timestamps.is_empty() {
            return Ok(0);
        }

        let (actual, idx) = self.ring.peek(timestamps.len() as _);
        let mut first_error = None;
        for (timestamp, i) in timestamps.iter_mut().zip(idx..idx + actual) {
            let address = self.ring.get(i);
            match umem.free_get_timestamp(address) {
                Ok(value) => *timestamp = value,
                Err(error) => {
                    *timestamp = 0;
                    first_error.get_or_insert(error);
                }
            }
        }
        if actual > 0 {
            self.ring.release(actual as _);
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(actual)
        }
    }
}
