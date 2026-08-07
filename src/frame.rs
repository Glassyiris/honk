use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt,
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
};

static NEXT_UMEM_ID: AtomicU64 = AtomicU64::new(1);

/// The exclusive owner of an `AF_XDP` frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameState {
    /// Available for userspace allocation or submission to a fill ring.
    Free = 0,
    /// Submitted to a fill ring for kernel RX.
    Fill = 1,
    /// Owned by userspace after RX or explicit allocation.
    Rx = 2,
    /// Submitted to a TX ring.
    Tx = 3,
    /// Returned by the kernel through a completion ring.
    Completion = 4,
}

impl FrameState {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Free),
            1 => Some(Self::Fill),
            2 => Some(Self::Rx),
            3 => Some(Self::Tx),
            4 => Some(Self::Completion),
            _ => None,
        }
    }
}

/// A frame ownership or descriptor integrity violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// A packet from another UMEM was submitted to this socket.
    ForeignUmem {
        /// The UMEM expected by the socket.
        expected: u64,
        /// The UMEM that owns the packet.
        actual: u64,
    },
    /// A descriptor did not point inside the registered UMEM.
    InvalidAddress {
        /// The descriptor address.
        address: u64,
        /// The registered UMEM length.
        umem_len: usize,
    },
    /// A descriptor length exceeded its frame capacity.
    InvalidLength {
        /// The descriptor length.
        length: usize,
        /// The maximum packet length for the frame.
        capacity: usize,
    },
    /// A frame did not have the owner required by an operation.
    InvalidTransition {
        /// The zero-based frame index.
        frame: usize,
        /// The required current owner.
        expected: FrameState,
        /// The observed owner, or `None` for a corrupt state byte.
        actual: Option<FrameState>,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignUmem { expected, actual } => {
                write!(f, "foreign UMEM packet: expected {expected}, got {actual}")
            }
            Self::InvalidAddress { address, umem_len } => {
                write!(
                    f,
                    "frame address {address} is outside UMEM length {umem_len}"
                )
            }
            Self::InvalidLength { length, capacity } => {
                write!(
                    f,
                    "descriptor length {length} exceeds frame capacity {capacity}"
                )
            }
            Self::InvalidTransition {
                frame,
                expected,
                actual,
            } => write!(
                f,
                "frame {frame} ownership mismatch: expected {expected:?}, got {actual:?}"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

pub(crate) struct FrameRegistry {
    id: u64,
    frame_size: u64,
    frame_mask: u64,
    umem_len: usize,
    available: RefCell<VecDeque<u64>>,
    states: Box<[AtomicU8]>,
    integrity_faults: AtomicU64,
}

impl FrameRegistry {
    pub(crate) fn new(frame_count: u32, frame_size: u32, frame_mask: u64) -> Self {
        let mut available = VecDeque::with_capacity(frame_count as usize);
        available.extend((0..frame_count as u64).map(|index| index * frame_size as u64));

        let id = NEXT_UMEM_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, 0, "UMEM identity exhausted");

        Self {
            id,
            frame_size: frame_size as u64,
            frame_mask,
            umem_len: frame_count as usize * frame_size as usize,
            available: RefCell::new(available),
            states: (0..frame_count)
                .map(|_| AtomicU8::new(FrameState::Free as u8))
                .collect(),
            integrity_faults: AtomicU64::new(0),
        }
    }

    #[inline]
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.states.len()
    }

    #[inline]
    pub(crate) fn allocatable(&self) -> usize {
        self.available.borrow().len()
    }

    #[inline]
    pub(crate) fn outstanding(&self) -> usize {
        self.capacity() - self.allocatable()
    }

    pub(crate) fn take(&self, next: FrameState) -> Result<Option<(u64, usize)>, FrameError> {
        let Some(address) = self.available.borrow_mut().pop_front() else {
            return Ok(None);
        };
        let frame = self.frame_index(address)?;
        self.transition(frame, FrameState::Free, next)?;
        Ok(Some((address, frame)))
    }

    pub(crate) fn transition_address(
        &self,
        address: u64,
        expected: FrameState,
        next: FrameState,
    ) -> Result<usize, FrameError> {
        let frame = self.frame_index(address)?;
        self.transition(frame, expected, next)?;
        Ok(frame)
    }

    pub(crate) fn transition(
        &self,
        frame: usize,
        expected: FrameState,
        next: FrameState,
    ) -> Result<(), FrameError> {
        let Some(state) = self.states.get(frame) else {
            return self.fail(FrameError::InvalidAddress {
                address: frame as u64 * self.frame_size,
                umem_len: self.umem_len,
            });
        };

        match state.compare_exchange(
            expected as u8,
            next as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(actual) => self.fail(FrameError::InvalidTransition {
                frame,
                expected,
                actual: FrameState::from_raw(actual),
            }),
        }
    }

    pub(crate) fn release(&self, frame: usize, expected: FrameState) -> Result<(), FrameError> {
        self.transition(frame, expected, FrameState::Free)?;
        self.available
            .borrow_mut()
            .push_front(frame as u64 * self.frame_size);
        Ok(())
    }

    pub(crate) fn complete(&self, address: u64) -> Result<usize, FrameError> {
        let frame = self.transition_address(address, FrameState::Tx, FrameState::Completion)?;
        self.release(frame, FrameState::Completion)?;
        Ok(frame)
    }

    #[inline]
    pub(crate) fn integrity_faults(&self) -> u64 {
        self.integrity_faults.load(Ordering::Acquire)
    }
    pub(crate) fn record(&self, error: FrameError) -> FrameError {
        self.integrity_faults.fetch_add(1, Ordering::Relaxed);
        error
    }

    fn frame_index(&self, address: u64) -> Result<usize, FrameError> {
        let frame_address = address & self.frame_mask;
        if frame_address >= self.umem_len as u64 || frame_address % self.frame_size != 0 {
            return self.fail(FrameError::InvalidAddress {
                address,
                umem_len: self.umem_len,
            });
        }
        Ok((frame_address / self.frame_size) as usize)
    }

    fn fail<T>(&self, error: FrameError) -> Result<T, FrameError> {
        Err(self.record(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_lifecycle_and_double_return_are_checked_in_release() {
        let registry = FrameRegistry::new(2, 4096, !(4096 - 1));
        let (address, frame) = registry.take(FrameState::Fill).unwrap().unwrap();
        registry
            .transition_address(address + 256, FrameState::Fill, FrameState::Rx)
            .unwrap();
        registry
            .transition(frame, FrameState::Rx, FrameState::Tx)
            .unwrap();
        registry.complete(address + 256).unwrap();

        assert_eq!(registry.allocatable(), 2);
        assert!(matches!(
            registry.release(frame, FrameState::Rx),
            Err(FrameError::InvalidTransition {
                expected: FrameState::Rx,
                actual: Some(FrameState::Free),
                ..
            })
        ));
        assert_eq!(registry.allocatable(), 2);
        assert_eq!(registry.integrity_faults(), 1);
    }

    #[test]
    fn out_of_range_descriptor_is_rejected() {
        let registry = FrameRegistry::new(1, 4096, !(4096 - 1));
        assert!(matches!(
            registry.transition_address(8192, FrameState::Fill, FrameState::Rx),
            Err(FrameError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn packet_from_foreign_umem_is_rejected_and_reclaimed() {
        let config = crate::umem::UmemCfgBuilder::default().build().unwrap();
        let mut source = crate::Umem::map(config).unwrap();
        let destination = crate::Umem::map(config).unwrap();
        // SAFETY: the packet is dropped before its source UMEM.
        let packet = unsafe { source.alloc() }.unwrap().unwrap();
        let error = match packet.into_descriptor(destination.frame_registry()) {
            Err(error) => error,
            Ok(_) => panic!("foreign packet was accepted"),
        };
        assert!(matches!(error, FrameError::ForeignUmem { .. }));
        assert_eq!(source.outstanding(), 0);
        assert_eq!(source.integrity_faults(), 0);
        assert_eq!(destination.integrity_faults(), 1);
    }
}
