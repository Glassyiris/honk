//! The [`RxRing`] is a consumer ring that userspace can dequeue packets that have
//! been received on the NIC queue the ring is bound to

use crate::{FrameError, Umem, libc, slab::Slab};

/// Ring from which we can dequeue packets that have been filled by the kernel
pub struct RxRing {
    ring: super::XskConsumer<libc::xdp::xdp_desc>,
    _mmap: crate::mmap::Mmap,
}

impl RxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &libc::rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.rx_count,
            libc::rings::RingPageOffsets::Rx,
            &offsets.rx,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Rx,
        })?;

        ring.cached_consumed = ring.consumer.load(std::sync::atomic::Ordering::Relaxed);
        ring.cached_produced = ring.producer.load(std::sync::atomic::Ordering::Relaxed);

        Ok(Self {
            ring: super::XskConsumer(ring),
            _mmap,
        })
    }

    /// Pops packets that have finished receiving
    ///
    /// The number of packets returned will be the minimum of the number of packets
    /// actually available in the ring, and the remaining capacity in the slab
    ///
    /// # Returns
    ///
    /// The number of actual packets that were pushed to the slab
    ///
    /// # Safety
    ///
    /// The packets returned in the slab must not outlive the [`Umem`]
    #[inline]
    pub unsafe fn recv<S: Slab>(
        &mut self,
        umem: &Umem,
        packets: &mut S,
    ) -> Result<usize, FrameError> {
        let nb = packets.available();
        if nb == 0 {
            return Ok(0);
        }

        let (actual, idx) = self.ring.peek(nb as _);
        let mut delivered = 0;
        let mut first_error = None;
        for i in idx..idx + actual {
            let desc = self.ring.get(i);
            // SAFETY: the caller guarantees the UMEM lifetime.
            match unsafe { umem.packet(desc) } {
                Ok(packet) if first_error.is_none() => {
                    if packets.push_front(packet).is_some() {
                        unreachable!("RX reservation exceeded slab capacity");
                    }
                    delivered += 1;
                }
                Ok(packet) => drop(packet),
                Err(error) => {
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
            Ok(delivered)
        }
    }
}
