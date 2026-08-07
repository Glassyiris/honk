#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

macro_rules! within_range {
    ($ctx:expr, $name:ident, $range:expr) => {{
        let val = $ctx.$name;
        let uval = val as usize;

        if !$range.contains(&uval) {
            return Err($crate::error::ConfigError {
                name: stringify!($name),
                kind: $crate::error::ConfigErrorKind::OutOfRange {
                    size: uval,
                    range: $range,
                },
            }
            .into());
        }

        val
    }};
}

pub mod affinity;
pub mod error;
mod frame;
pub mod packet;
pub use frame::{FrameError, FrameState, FrameStateCounts};
pub use packet::Packet;
pub mod libc;
mod mmap;
pub mod nic;
mod rings;
pub mod slab;
pub use socket::ActualMode;
pub mod socket;
pub mod umem;
pub use umem::Umem;

pub use rings::{
    CompletionRing, FillRing, RingConfig, RingConfigBuilder, RingError, Rings, RxRing, TxRing,
    WakableFillRing, WakableRings, WakableTxRing,
};
