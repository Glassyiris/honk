use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cloneable failure for shared initialization waiters, preserving typed causes.
/// An `Arc<anyhow::Error>` alone becomes an opaque message when re-wrapped.
#[derive(Clone)]
pub struct SharedError {
    error: Arc<anyhow::Error>,
    episode: Option<u64>,
}

impl SharedError {
    pub fn new(error: anyhow::Error) -> Self {
        Self {
            error: Arc::new(error),
            episode: None,
        }
    }

    /// One failure delivered to several flows, such as a carrier's terminal cause or a dial all
    /// waiters share; its recipients report a single Score episode.
    pub fn fanout(error: anyhow::Error) -> Self {
        Self {
            error: Arc::new(error),
            episode: Some(next_episode()),
        }
    }

    pub(crate) fn episode(&self) -> Option<u64> {
        self.episode
    }
}

/// Score orders every shared failure episode by this one sequence.
pub(crate) fn next_episode() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl std::fmt::Debug for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.error.as_ref(), formatter)
    }
}

impl std::fmt::Display for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.error.as_ref(), formatter)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref().as_ref())
    }
}
