//! [`Umem`] creation and operation

use crate::{
    FrameError, FrameState, FrameStateCounts, Packet,
    error::{ConfigError, Error},
    frame::FrameRegistry,
    libc::{self, InternalXdpFlags, xdp::xdp_desc},
};
use std::ptr::NonNull;

/// The packet size (`libc::xdp_umem_reg::chunk_size`) can only be [>=2048 or <=4096](https://github.com/torvalds/linux/blob/c2ee9f594da826bea183ed14f2cc029c719bf4da/Documentation/networking/af_xdp.rst#xdp_umem_reg-setsockopt)
///
/// Note: [Kernel source](https://github.com/torvalds/linux/blob/ae90f6a6170d7a7a1aa4fddf664fbd093e3023bc/net/xdp/xdp_umem.c#L166-L174)
#[derive(Copy, Clone)]
pub enum FrameSize {
    /// The minimum size
    TwoK,
    /// The maximum size, same as `PAGE_SIZE`
    FourK,
    // Non power of sizes are allowed, but forces the [`Umem`] to use huge tables
    //Unaligned(usize),
}

impl TryFrom<FrameSize> for u32 {
    type Error = ConfigError;

    fn try_from(value: FrameSize) -> Result<Self, Self::Error> {
        let ret = match value {
            FrameSize::TwoK => 2048,
            FrameSize::FourK => 4096,
            //FrameSize::Unaligned(size) => {
            // TODO: Support unaligned frames, I don't particularly care about
            // it since 2k is plenty enough for my use case, and would mean
            // changing the easy masking of addresses currently done, as well
            // as require huge pages for the memory mapping

            //}
        };

        Ok(ret)
    }
}

/// A memory region that is shared between kernel and userspace where packet
/// data can be written to (recv) and read from (send)
///
/// ```txt
/// ┌──────┌──────┌──────┌──────┌──────┌──────┌──────┐
/// │chunk0│chunk1│chunk2│chunk3│chunk4│chunk5│...   │
/// └──────└──────└──────└──────└──────└──────└──────┘
/// ```
///
/// A [`Umem`] can best be thought of as a specialized memory allocator that
/// is only capable of returning buffers of the same size, and cannot grow after
/// initialization.
///
/// This is the single source of `unsafe` that is exposed in the public API, along
/// with the [`crate::TxRing::send`], [`crate::RxRing::recv`], and
/// [`crate::FillRing::enqueue`] methods as it vastly simplifies the API to
/// require the user to guarantee that [`Packet`]s cannot outlive the [`Umem`]
/// they are allocated from
pub struct Umem {
    /// The actual memory mapping
    pub(crate) mmap: crate::mmap::Mmap,
    /// Runtime ownership of every frame in the mapping.
    pub(crate) registry: Box<FrameRegistry>,
    /// The size of each individual packet within the mapping
    pub(crate) frame_size: usize,
    /// The headroom configured for the Umem, a number of bytes (after the kernel
    /// reserved [`XDP_PACKET_HEADROOM`]) where the kernel will not place packet
    /// data when receiving, which allows the packet to grow downward when eg.
    /// changing from IPv4 -> IPv6 without needing to copying data upwards
    pub(crate) head_room: usize,
    /// Flags that control how the umem is registered and thus what capabilities
    /// each packet has
    pub(crate) options: InternalXdpFlags::Enum,
}

impl Umem {
    /// Attempts to build a [`Self`] by mapping a memory region
    ///
    /// # Examples
    ///
    /// ```
    /// let mut _umem = xdp::Umem::map(xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg")).expect("failed to map memory");
    /// ```
    pub fn map(cfg: UmemCfg) -> std::io::Result<Self> {
        let mmap = crate::mmap::Mmap::map_umem(cfg.frame_count as usize * cfg.frame_size as usize)?;
        let registry = Box::new(FrameRegistry::new(
            cfg.frame_count,
            cfg.frame_size,
            cfg.frame_mask,
        ));

        Ok(Self {
            mmap,
            registry,
            frame_size: cfg.frame_size as usize - libc::xdp::XDP_PACKET_HEADROOM as usize,
            head_room: cfg.head_room as _,
            options: cfg.options,
        })
    }

    /// The total capacity of this [`Umem`] in number of frames
    #[inline]
    pub fn capacity(&self) -> usize {
        self.registry.capacity()
    }

    /// The number of frames that are currently allocated from this [`Umem`]
    #[inline]
    pub fn outstanding(&self) -> usize {
        self.registry.outstanding()
    }

    /// The number of frames that can be allocated from this [`Umem`] before it is exhausted
    #[inline]
    pub fn allocatable(&self) -> usize {
        self.registry.allocatable()
    }

    /// Given an [`xdp_desc`] filled by the kernel, retrieves the memory block
    /// it points to as a [`Packet`]
    ///
    /// # Safety
    ///
    /// The [`Packet`] returned by this function is pointing to memory owned by
    /// this [`Umem`], it must not outlive this [`Umem`]
    #[inline]
    pub(crate) unsafe fn packet(&self, desc: xdp_desc) -> Result<Packet, FrameError> {
        let frame =
            self.registry
                .transition_address(desc.addr, FrameState::Fill, FrameState::Rx)?;
        let raw_frame_size = self.frame_size + libc::xdp::XDP_PACKET_HEADROOM as usize;
        let frame_base = frame * raw_frame_size;
        let data_offset = frame_base + libc::xdp::XDP_PACKET_HEADROOM as usize;
        let data_end = data_offset + self.frame_size;
        let descriptor_offset = desc.addr as usize;
        if descriptor_offset < data_offset || descriptor_offset > data_end {
            self.registry.release(frame, FrameState::Rx)?;
            return Err(self.registry.record(FrameError::InvalidAddress {
                address: desc.addr,
                umem_len: self.mmap.len(),
            }));
        }

        let head = descriptor_offset - data_offset;
        let available = data_end - descriptor_offset;
        if desc.len as usize > available {
            self.registry.release(frame, FrameState::Rx)?;
            return Err(self.registry.record(FrameError::InvalidLength {
                length: desc.len as usize,
                capacity: available,
            }));
        }

        // SAFETY: the descriptor range was validated inside its owning frame.
        let data = unsafe { self.mmap.ptr.byte_offset(data_offset as _) };
        Ok(Packet {
            data,
            capacity: self.frame_size,
            head,
            tail: head + desc.len as usize,
            base: self.mmap.ptr,
            options: desc.options | self.options,
            registry: Some(NonNull::from(self.registry.as_ref())),
            frame_index: frame,
        })
    }

    /// Attempts to allocate a packet from the [`Umem`]. Returns `Ok(None)` when
    /// there are no available frames and [`FrameError`] on an ownership fault.
    ///
    /// # Safety
    ///
    /// The [`Packet`] returned by this function is pointing to memory owned by
    /// this [`Umem`], it must not outlive this [`Umem`]
    ///
    /// # Examples
    ///
    /// ```
    /// let mut umem = xdp::Umem::map(xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg")).expect("failed to map memory");
    ///
    /// unsafe {
    ///     let mut packet = umem.alloc()
    ///         .expect("UMEM invariant violated")
    ///         .expect("UMEM exhausted");
    ///     assert!(packet.is_empty());
    /// }
    /// ```
    #[inline]
    pub unsafe fn alloc(&mut self) -> Result<Option<Packet>, FrameError> {
        let Some((address, frame)) = self.registry.take(FrameState::Rx)? else {
            return Ok(None);
        };

        // SAFETY: the registry only returns addresses inside the live mmap.
        let data = unsafe {
            self.mmap
                .ptr
                .byte_offset((address + libc::xdp::XDP_PACKET_HEADROOM) as _)
        };
        Ok(Some(Packet {
            data,
            capacity: self.frame_size,
            head: self.head_room,
            tail: self.head_room,
            base: self.mmap.ptr,
            options: self.options,
            registry: Some(NonNull::from(self.registry.as_ref())),
            frame_index: frame,
        }))
    }

    pub(crate) fn take_fill_addr(&self) -> Result<Option<u64>, FrameError> {
        Ok(self
            .registry
            .take(FrameState::Fill)?
            .map(|(address, _)| address + libc::xdp::XDP_PACKET_HEADROOM + self.head_room as u64))
    }

    pub(crate) fn complete_addr(&self, address: u64) -> Result<usize, FrameError> {
        self.registry.complete(address)
    }

    /// Returns the completed frame and its transmit timestamp.
    #[inline]
    pub(crate) fn get_completion_timestamp(
        &self,
        address: u64,
    ) -> Result<(usize, u64), FrameError> {
        use libc::xdp::xsk_tx_metadata;

        let frame =
            self.registry
                .transition_address(address, FrameState::Tx, FrameState::Completion)?;
        let raw_frame_size = self.frame_size + libc::xdp::XDP_PACKET_HEADROOM as usize;
        let align_offset = address % raw_frame_size as u64;
        let timestamp = if align_offset >= std::mem::size_of::<xsk_tx_metadata>() as u64 {
            // SAFETY: the descriptor address was validated by transition_address.
            unsafe {
                let tx_meta = std::ptr::read_unaligned(
                    self.mmap
                        .ptr
                        .byte_offset((address - std::mem::size_of::<xsk_tx_metadata>() as u64) as _)
                        .cast::<xsk_tx_metadata>(),
                );
                tx_meta.offload.completion
            }
        } else {
            0
        };

        Ok((frame, timestamp))
    }

    pub(crate) fn release_completion(&self, frame: usize) -> Result<(), FrameError> {
        self.registry.release_completion(frame)
    }

    #[inline]
    pub(crate) fn frame_registry(&self) -> &FrameRegistry {
        &self.registry
    }

    /// Returns the number of frame ownership violations observed by this UMEM.
    #[inline]
    pub fn integrity_faults(&self) -> u64 {
        self.registry.integrity_faults()
    }

    /// Returns a consistent snapshot of frame ownership counters.
    pub fn frame_state_counts(&self) -> FrameStateCounts {
        self.registry.state_counts()
    }

    /// Reclaims frames left in the kernel fill state after socket teardown.
    ///
    /// # Safety
    ///
    /// Every socket and ring registered against this UMEM must already be
    /// closed. No kernel or userspace thread may access its descriptors.
    pub unsafe fn reclaim_fill_after_socket_close(&self) -> Result<usize, FrameError> {
        self.registry.reclaim_fill_after_socket_close()
    }
}

/// Builder for a [`Umem`].
///
/// Using [`UmemCfgBuilder::default`] will result in a [`Umem`] with 8k frames of
/// size 4KiB for a total of 32MiB.
pub struct UmemCfgBuilder {
    /// The size of each packet/chunk. Defaults to 4096.
    pub frame_size: FrameSize,
    /// The size of the headroom, an offset from the beginning of the packet
    /// which the kernel will not write data to. Defaults to 0.
    pub head_room: u32,
    /// The number of total frames. Defaults to 8192.
    pub frame_count: u32,
    /// If true, the [`Umem`] will be registered with the socket with an
    /// additional section before the packet that may be filled with TX metadata
    /// that either request a checksum be calculated by the NIC
    pub tx_checksum: bool,
    /// If true, the [`Umem`] will be , and/or that the
    /// transmission timestamp is set before being added to the completion queue
    pub tx_timestamp: bool,
    /// For testing purposes only, enables the
    /// [`libc::xdp::UmemFlags::XDP_UMEM_TX_SW_CSUM`] flag so the checksum is
    /// calculated by the driver in software
    #[cfg(debug_assertions)]
    pub software_checksum: bool,
}

impl Default for UmemCfgBuilder {
    fn default() -> Self {
        Self {
            frame_size: FrameSize::FourK, // XSK_UMEM_DEFAULT_FRAME_SIZE
            head_room: 0,
            frame_count: 8 * 1024,
            tx_checksum: false,
            tx_timestamp: false,
            #[cfg(debug_assertions)]
            software_checksum: false,
        }
    }
}

impl UmemCfgBuilder {
    /// Creates a builder with TX checksum offload and/or timestamping if supported
    /// by the NIC
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let nic = xdp::nic::NicIndex(0);
    /// let caps = nic.query_capabilities().expect("failed to query NIC capabilities");
    /// let _umem_cfg = xdp::umem::UmemCfgBuilder::new(caps.tx_metadata).build().expect("failed to build umem cfg");
    /// ```
    pub fn new(tx_flags: crate::nic::XdpTxMetadata) -> Self {
        Self {
            tx_checksum: tx_flags.checksum(),
            tx_timestamp: tx_flags.timestamp(),
            ..Default::default()
        }
    }

    /// Attempts build a [`UmemCfg`] that can be used with [`Umem::map`]
    ///
    /// # Examples
    ///
    /// ```
    /// let umem_cfg = xdp::umem::UmemCfgBuilder::default().build().expect("failed to build umem cfg");
    /// let umem = xdp::Umem::map(umem_cfg).expect("failed to map umem");
    /// ```
    pub fn build(self) -> Result<UmemCfg, Error> {
        let frame_size = self.frame_size.try_into()?;
        // For now we only allow 2k and 4k sizes, but if we supported unaligned
        // frames in the future we'd need to change this
        let frame_mask = !(frame_size as u64 - 1);

        let head_room = within_range!(
            self,
            head_room,
            0..(frame_size - libc::xdp::XDP_PACKET_HEADROOM as u32) as _
        );
        let frame_count = within_range!(self, frame_count, 1..u32::MAX as _);

        let total_size = frame_count as usize * frame_size as usize;
        if total_size > isize::MAX as usize {
            return Err(Error::Cfg(crate::error::ConfigError {
                name: "frame_count * frame_size",
                kind: crate::error::ConfigErrorKind::OutOfRange {
                    size: total_size,
                    range: frame_size as usize..isize::MAX as usize,
                },
            }));
        }

        let mut options = 0;
        if self.tx_checksum {
            options |= InternalXdpFlags::SUPPORTS_CHECKSUM_OFFLOAD;
        }
        if self.tx_timestamp {
            options |= InternalXdpFlags::SUPPORTS_TIMESTAMP;
        }
        #[cfg(debug_assertions)]
        if self.software_checksum {
            options |= InternalXdpFlags::USE_SOFTWARE_OFFLOAD;
        }

        Ok(UmemCfg {
            frame_size,
            frame_mask,
            frame_count,
            head_room,
            options,
        })
    }
}

/// The configuration used to create a [`Umem`]
#[derive(Copy, Clone)]
pub struct UmemCfg {
    frame_size: u32,
    frame_mask: u64,
    frame_count: u32,
    head_room: u32,
    options: InternalXdpFlags::Enum,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(frame_count: u32, head_room: u32) -> UmemCfg {
        UmemCfgBuilder {
            frame_count,
            head_room,
            ..UmemCfgBuilder::default()
        }
        .build()
        .unwrap()
    }

    #[test]
    fn adjusted_rx_descriptor_uses_stable_frame_base() {
        let umem = Umem::map(test_config(1, 256)).unwrap();
        let fill_address = umem.take_fill_addr().unwrap().unwrap();
        let descriptor = xdp_desc {
            addr: fill_address + 14,
            len: 128,
            options: 0,
        };

        // SAFETY: the packet is dropped before its UMEM.
        let packet = unsafe { umem.packet(descriptor) }.unwrap();
        assert_eq!(packet.head, 270);
        assert_eq!(packet.len(), 128);
        // SAFETY: the descriptor range was validated by Umem::packet.
        assert_eq!(packet.as_ptr(), unsafe {
            umem.mmap.ptr.add(descriptor.addr as usize)
        });
        drop(packet);
        assert_eq!(umem.outstanding(), 0);
    }

    #[test]
    fn rx_descriptor_cannot_cross_its_frame_boundary() {
        let umem = Umem::map(test_config(2, 256)).unwrap();
        let _first = umem.take_fill_addr().unwrap().unwrap();
        let second = umem.take_fill_addr().unwrap().unwrap();
        let frame_base = second & !(4096 - 1);
        let descriptor = xdp_desc {
            addr: frame_base + 4090,
            len: 14,
            options: 0,
        };

        // SAFETY: the malformed descriptor is rejected before a packet is exposed.
        let error = match unsafe { umem.packet(descriptor) } {
            Err(error) => error,
            Ok(_) => panic!("cross-frame descriptor was accepted"),
        };
        assert!(matches!(
            error,
            FrameError::InvalidLength {
                length: 14,
                capacity: 6
            }
        ));
        assert_eq!(umem.frame_state_counts().rx, 0);
        assert_eq!(umem.integrity_faults(), 1);
    }
}
