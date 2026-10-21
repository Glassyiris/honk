//! The one place that still calls tokio's deprecated `AsyncFd` constructor.
//!
//! tokio deprecated `AsyncFd::with_interest` because `AsRawFd` alone cannot prove the descriptor
//! stays open and unchanged. Every caller here passes an owned descriptor (`OwnedFd`, a std
//! socket, an aya map), for which the old behaviour is sound. The replacement `register` is
//! `unsafe`, which CONTRIBUTING.md reserves for human-authored changes.

use std::{io, os::fd::AsRawFd};

use tokio::io::{Interest, unix::AsyncFd};

#[allow(deprecated)]
pub(crate) fn with_interest<T: AsRawFd>(inner: T, interest: Interest) -> io::Result<AsyncFd<T>> {
    AsyncFd::with_interest(inner, interest)
}
