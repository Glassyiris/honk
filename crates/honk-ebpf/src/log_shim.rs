//! Logging shim: uses aya-log-ebpf when the "log" feature is enabled,
//! otherwise compiles to no-ops.

#[cfg(feature = "log")]
pub use aya_log_ebpf::{debug, error, info, log, trace, warn};

#[cfg(not(feature = "log"))]
#[macro_export]
macro_rules! noop_log {
    ($ctx:expr, target: $target:expr, $($arg:tt)*) => {};
    (target: $target:expr, $($arg:tt)*) => {};
    ($ctx:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "log"))]
pub use noop_log as debug;
#[cfg(not(feature = "log"))]
pub use noop_log as error;
#[cfg(not(feature = "log"))]
pub use noop_log as info;
#[cfg(not(feature = "log"))]
pub use noop_log as log;
#[cfg(not(feature = "log"))]
pub use noop_log as trace;
#[cfg(not(feature = "log"))]
pub use noop_log as warn;
