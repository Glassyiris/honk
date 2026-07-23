//! TC verdict constants and the program-body `Result` convention.
//!
//! TC program bodies return [`Verdict`]: `Ok(action)` for the normal
//! verdict, `Err(action)` for an early exit — both flatten to the `i32`
//! the kernel ABI expects at the entry-point wrapper ([`flatten`]).

use core::ffi::c_long;

/// Verdict carrier for TC program bodies.
pub type Verdict = Result<c_long, c_long>;

pub const TC_ACT_OK: c_long = 0;
pub const TC_ACT_SHOT: c_long = 2;
pub const TC_ACT_PIPE: c_long = 3;
pub const TC_ACT_REDIRECT: c_long = 7;
pub const TC_ACT_UNSPEC: c_long = -1;

/// Flatten a program body's verdict to the `i32` the kernel expects.
#[inline(always)]
pub fn flatten(v: Verdict) -> i32 {
    match v {
        Ok(a) | Err(a) => a as i32,
    }
}
