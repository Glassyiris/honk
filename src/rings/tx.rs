//! The [`TxRing`] is a producer ring that userspace can enqueue packets to be
//! sent by the NIC the ring is bound to

use crate::{
    Umem,
    frame::FrameRegistry,
    libc::{self, rings},
    slab::Slab,
};
use std::ptr::NonNull;

/// The ring used to enqueue packets for the kernel to send
pub struct TxRing {
    ring: super::XskProducer<libc::xdp::xdp_desc>,
    registry: NonNull<FrameRegistry>,
    _mmap: crate::mmap::Mmap,
}

// SAFETY: the TX path accesses only immutable registry metadata and atomic
// frame states; the existing ring API requires its UMEM to outlive the ring.
unsafe impl Send for TxRing {}

impl TxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        umem: &Umem,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let (_mmap, mut ring) = super::map_ring(
            socket,
            cfg.tx_count,
            rings::RingPageOffsets::Tx,
            &offsets.tx,
        )
        .map_err(|inner| crate::socket::SocketError::RingMap {
            inner,
            ring: super::Ring::Tx,
        })?;

        ring.cached_produced = ring.producer.load(std::sync::atomic::Ordering::Relaxed);
        ring.cached_consumed =
            ring.consumer.load(std::sync::atomic::Ordering::Relaxed) + cfg.tx_count;

        Ok(Self {
            ring: super::XskProducer(ring),
            registry: NonNull::from(umem.frame_registry()),
            _mmap,
        })
    }

    /// Enqueues packets to be sent by the kernel
    ///
    /// # Safety
    ///
    /// The [`crate::Umem`] that owns the packets being sent must outlive the `AF_XDP`
    /// socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the ring doesn't have sufficient
    /// capacity
    pub unsafe fn send<S: Slab>(&mut self, packets: &mut S) -> Result<usize, super::RingError> {
        let requested = packets.len();
        if requested == 0 {
            return Ok(0);
        }

        let (actual, idx) = self.ring.reserve(requested as _);
        let mut queued = 0;
        // SAFETY: the UMEM must outlive the socket and all of its rings.
        let registry = unsafe { self.registry.as_ref() };
        for i in idx..idx + actual {
            let Some(packet) = packets.pop_back() else {
                unreachable!()
            };
            match packet.into_descriptor(registry) {
                Ok(descriptor) => {
                    self.ring.set(i, descriptor);
                    queued += 1;
                }
                Err(error) => {
                    self.ring.cancel((actual - queued) as u32);
                    if queued > 0 {
                        self.ring.submit(queued as u32);
                    }
                    return Err(super::RingError::Frame {
                        error,
                        submitted: queued,
                    });
                }
            }
        }
        if queued > 0 {
            self.ring.submit(queued as u32);
        }
        Ok(queued)
    }
}

/// Wakable version of [`TxRing`]
pub struct WakableTxRing {
    inner: TxRing,
    socket: std::os::fd::RawFd,
}

impl WakableTxRing {
    pub(crate) fn new(
        socket: std::os::fd::RawFd,
        umem: &Umem,
        cfg: &super::RingConfig,
        offsets: &rings::xdp_mmap_offsets,
    ) -> Result<Self, crate::socket::SocketError> {
        let inner = TxRing::new(socket, umem, cfg, offsets)?;
        Ok(Self { inner, socket })
    }

    /// Enqueues packets to be sent by the kernel
    ///
    /// # Safety
    ///
    /// The [`crate::Umem`] that owns the packets being sent must outlive the `AF_XDP`
    /// socket
    ///
    /// # Returns
    ///
    /// The number of packets that were actually enqueued. This number can be
    /// lower than the requested `num_packets` if the ring doesn't have sufficient
    /// capacity
    pub unsafe fn send<S: Slab>(&mut self, packets: &mut S) -> Result<usize, super::RingError> {
        // SAFETY: TxRing::send has the same UMEM lifetime requirement.
        let queued = unsafe { self.inner.send(packets) }?;
        if queued > 0 && self.inner.ring.needs_wakeup() {
            loop {
                // SAFETY: a zero-length sendto only wakes the bound AF_XDP socket.
                let ret = unsafe {
                    libc::socket::sendto(
                        self.socket,
                        std::ptr::null_mut(),
                        0,
                        libc::socket::MsgFlags::DONTWAIT,
                        std::ptr::null_mut(),
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
