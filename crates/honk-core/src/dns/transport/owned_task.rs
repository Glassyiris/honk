use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub(crate) struct OwnedTask {
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl OwnedTask {
    pub(crate) fn spawn<F>(future: F, active: Arc<AtomicUsize>) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        active.fetch_add(1, Ordering::SeqCst);
        let handle = tokio::spawn(async move {
            let _guard = ActiveTaskGuard(active);
            future.await;
        });
        Self {
            handle: Mutex::new(Some(handle)),
        }
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) {
        let Some(mut handle) = self.handle.lock().await.take() else {
            return;
        };
        if tokio::time::timeout(timeout, &mut handle).await.is_err() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.get_mut().take() {
            handle.abort();
        }
    }
}

struct ActiveTaskGuard(Arc<AtomicUsize>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_awaits_task_termination() {
        // Given
        let active = Arc::new(AtomicUsize::new(0));
        let task = OwnedTask::spawn(std::future::pending(), Arc::clone(&active));
        assert_eq!(active.load(Ordering::SeqCst), 1);

        // When
        task.shutdown(Duration::ZERO).await;

        // Then
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
