//! The [`FillRing`] is a producer ring that userspace can enqueue packets to be
//! filled with data received on the NIC queue the ring is bound to

use crate::{
    FrameError, Umem,
    libc::{self, rings},
};

/// The ring used to enqueue buffers for the kernel to fill in with packets
/// received from a NIC
pub struct FillRing {
    ring: super::XskProducer<u64>,
    _mmap: crate::mmap::Mmap,
}

impl FillRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.fill_count,
            rings::RingPageOffsets::Fill,
            &offsets.fill,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Fill,
        })?;

        ring.cached_consumed = cfg.fill_count;
        ring.cached_produced = 0;

        Ok(Self {
            ring: super::XskProducer(ring),
            _mmap,
        })
    }

    /// Enqueues up to `num_packets` to be received and filled by the kernel
    ///
    /// # Safety
    ///
    /// The [`Umem`] must outlive the `AF_XDP` socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the [`Umem`] didn't have enough
    /// open slots, or the rx ring had insufficient capacity
    pub unsafe fn enqueue(&mut self, umem: &Umem, num_packets: usize) -> Result<usize, FrameError> {
        let requested = std::cmp::min(umem.allocatable(), num_packets);
        if requested == 0 {
            return Ok(0);
        }

        let (actual, idx) = self.ring.reserve(requested as _);
        let mut queued = 0;
        for i in idx..idx + actual {
            match umem.take_fill_addr() {
                Ok(Some(address)) => {
                    self.ring.set(i, address);
                    queued += 1;
                }
                Ok(None) => unreachable!("UMEM availability changed during fill reservation"),
                Err(error) => {
                    self.ring.cancel((actual - queued) as u32);
                    if queued > 0 {
                        self.ring.submit(queued as u32);
                    }
                    return Err(error);
                }
            }
        }
        if queued > 0 {
            self.ring.submit(queued as u32);
        }
        Ok(queued)
    }
}

/// The wakable version of [`FillRing`], which requires that we notify the kernel
/// when there are new buffers available to receive packets
pub struct WakableFillRing {
    inner: FillRing,
    socket: std::os::fd::RawFd,
}

impl WakableFillRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let inner = FillRing::new(socket, cfg, offsets)?;

        Ok(Self { inner, socket })
    }

    /// Enqueues buffers and wakes the driver only when the fill ring requests it.
    ///
    /// # Safety
    ///
    /// The [`Umem`] must outlive the `AF_XDP` socket.
    #[inline]
    pub unsafe fn enqueue(
        &mut self,
        umem: &Umem,
        num_packets: usize,
    ) -> Result<usize, super::RingError> {
        // SAFETY: FillRing::enqueue has the same UMEM lifetime requirement.
        let queued =
            unsafe { self.inner.enqueue(umem, num_packets) }.map_err(super::RingError::Frame)?;
        if queued > 0 && self.inner.ring.needs_wakeup() {
            loop {
                // SAFETY: poll only reads the provided descriptor.
                let ret = unsafe {
                    libc::socket::poll(
                        &mut libc::socket::pollfd {
                            fd: self.socket,
                            events: libc::socket::PollEvents::POLLIN,
                            revents: 0,
                        },
                        1,
                        0,
                    )
                };
                if ret >= 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(super::RingError::Io {
                        error,
                        submitted: queued,
                    });
                }
                break;
            }
        }
        Ok(queued)
    }
}
