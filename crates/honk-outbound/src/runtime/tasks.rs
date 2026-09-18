/// Spawn a protocol/pool task in its captured runtime, when ownership is enabled.
pub(crate) fn spawn_owned<F>(future: F) -> Option<tokio::task::AbortHandle>
where
    F: Future<Output = ()> + Send + 'static,
{
    #[cfg(feature = "native-api")]
    if let Ok(Some(owner)) = OWNER.try_with(Clone::clone) {
        return owner.upgrade().and_then(|owner| owner.spawn(future));
    }
    Some(tokio::spawn(future).abort_handle())
}

tokio::task_local! {
    static OWNER: Option<std::sync::Weak<TaskOwner>>;
}

#[derive(Clone, Debug, Default)]
/// Weak runtime scope for work retained by another supervisor's task set.
pub struct TaskScope {
    #[cfg(feature = "native-api")]
    owner: Option<std::sync::Weak<TaskOwner>>,
}

impl TaskScope {
    /// Capture task ownership without keeping the runtime alive.
    pub fn capture() -> Self {
        Self {
            #[cfg(feature = "native-api")]
            owner: capture_owner(),
        }
    }

    pub(crate) fn spawn<F>(&self, future: F) -> Option<tokio::task::AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.sync_scope(|| spawn_owned(future))
    }

    pub(crate) fn sync_scope<T>(&self, build: impl FnOnce() -> T) -> T {
        #[cfg(feature = "native-api")]
        if self.owner.is_some() {
            return OWNER.sync_scope(self.owner.clone(), build);
        }
        build()
    }

    /// Restore ownership for a future already retained by its own supervisor.
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        #[cfg(feature = "native-api")]
        if self.owner.is_some() {
            return OWNER.scope(self.owner.clone(), future).await;
        }
        future.await
    }

    /// Move this weak scope into a supervised child future.
    pub async fn scope_owned<F: Future>(self, future: F) -> F::Output {
        self.scope(future).await
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeEndpoint {
    endpoint: quinn::Endpoint,
    #[cfg(feature = "native-api")]
    _lease: Option<std::sync::Arc<()>>,
}

impl std::ops::Deref for RuntimeEndpoint {
    type Target = quinn::Endpoint;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

pub(crate) fn new_owned_quic_endpoint(
    build: impl FnOnce() -> std::io::Result<quinn::Endpoint>,
) -> std::io::Result<RuntimeEndpoint> {
    #[cfg(feature = "native-api")]
    if let Some(owner) = capture_owner() {
        let owner = owner
            .upgrade()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Interrupted))?;
        owner.reap_endpoints();
        let mut state = owner.state.lock();
        if state.closed {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if owner
            .limit
            .is_some_and(|limit| state.endpoints.len() >= limit)
        {
            state.capacity_rejected = true;
            drop(state);
            owner.abort();
            return Err(crate::proxy::PacketRejection::Capacity.into());
        }
        let endpoint = build()?;
        let lease = std::sync::Arc::new(());
        state
            .endpoints
            .push((std::sync::Arc::downgrade(&lease), endpoint.clone()));
        return Ok(RuntimeEndpoint {
            endpoint,
            _lease: Some(lease),
        });
    }
    Ok(RuntimeEndpoint {
        endpoint: build()?,
        #[cfg(feature = "native-api")]
        _lease: None,
    })
}

#[cfg(feature = "native-api")]
pub(super) fn capture_owner() -> Option<std::sync::Weak<TaskOwner>> {
    OWNER.try_with(Clone::clone).ok().flatten()
}

#[cfg(feature = "native-api")]
pub(super) async fn scope_owner<F: Future>(
    owner: Option<std::sync::Weak<TaskOwner>>,
    future: F,
) -> F::Output {
    OWNER.scope(owner, future).await
}

#[cfg(feature = "native-api")]
pub(super) fn sync_scope_owner<T>(
    owner: Option<std::sync::Weak<TaskOwner>>,
    build: impl FnOnce() -> T,
) -> T {
    OWNER.sync_scope(owner, build)
}

#[derive(Debug, Default)]
struct OwnedTasks {
    closed: bool,
    capacity_rejected: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    endpoints: Vec<(std::sync::Weak<()>, quinn::Endpoint)>,
}

#[derive(Debug)]
/// Joined task lifetime for a runtime or pre-runtime health/DNS work.
/// Closing rejects new work; already-started blocking resolvers must finish.
pub struct TaskOwner {
    // Probe fanout has a separate logical cap; production follows the existing
    // carrier/flow limits and reaps completed jobs instead of capping streams.
    limit: Option<usize>,
    state: parking_lot::Mutex<OwnedTasks>,
    joining: tokio::sync::Mutex<()>,
    closed: tokio::sync::Notify,
    failed: std::sync::atomic::AtomicBool,
}

impl Default for TaskOwner {
    fn default() -> Self {
        Self::new(Some(256))
    }
}

impl TaskOwner {
    /// Use the caller's existing job/flow admission rather than the probe cap.
    pub fn production() -> Self {
        Self::new(None)
    }

    fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            state: Default::default(),
            joining: Default::default(),
            closed: Default::default(),
            failed: Default::default(),
        }
    }

    /// Capture this owner for a child retained by an existing supervisor.
    pub fn task_scope(self: &std::sync::Arc<Self>) -> TaskScope {
        TaskScope {
            #[cfg(feature = "native-api")]
            owner: Some(std::sync::Arc::downgrade(self)),
        }
    }

    #[cfg(feature = "native-api")]
    pub(super) fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    /// Sticky panic status, including tasks already reaped before close.
    pub fn has_failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn reap(&self) {
        self.state.lock().tasks.retain_mut(|task| {
            if !task.is_finished() {
                return true;
            }
            report_join(
                &self.failed,
                futures_util::FutureExt::now_or_never(task)
                    .expect("finished task has a ready join result"),
            );
            false
        });
        self.reap_endpoints();
    }

    fn reap_endpoints(&self) {
        let candidates: Vec<_> = self
            .state
            .lock()
            .endpoints
            .iter()
            .filter(|(lease, _)| lease.strong_count() == 0)
            .cloned()
            .collect();
        for (lease, endpoint) in candidates {
            if futures_util::FutureExt::now_or_never(endpoint.wait_idle()).is_some() {
                self.state
                    .lock()
                    .endpoints
                    .retain(|(current, _)| !current.ptr_eq(&lease));
            }
        }
    }

    pub(super) fn sync_scope<T>(self: &std::sync::Arc<Self>, build: impl FnOnce() -> T) -> T {
        OWNER.sync_scope(Some(std::sync::Arc::downgrade(self)), build)
    }

    /// Run inline work in this owner; callers still drain the inline future.
    pub async fn scope<T, F>(self: &std::sync::Arc<Self>, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        let closed = self.closed.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        let error = || {
            if self.state.lock().capacity_rejected {
                anyhow::Error::new(crate::proxy::PacketRejection::Capacity)
            } else {
                std::io::Error::new(std::io::ErrorKind::Interrupted, "outbound runtime closed")
                    .into()
            }
        };
        if self.state.lock().closed {
            self.sync_scope(|| drop(future));
            return Err(error());
        }
        tokio::select! {
            biased;
            _ = &mut closed => Err(error()),
            result = OWNER.scope(Some(std::sync::Arc::downgrade(self)), future) => {
                if self.state.lock().closed {
                    self.sync_scope(|| drop(result));
                    Err(error())
                } else {
                    result
                }
            }
        }
    }

    pub(super) fn spawn<F>(
        self: &std::sync::Arc<Self>,
        future: F,
    ) -> Option<tokio::task::AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.register(|owner| tokio::spawn(OWNER.scope(Some(owner), future)))
    }

    /// Retain blocking platform work before publication. The caller's admission
    /// bounds concurrency; abort cannot stop started work, but close joins it.
    pub fn spawn_blocking<F>(
        self: &std::sync::Arc<Self>,
        work: F,
    ) -> Option<tokio::task::AbortHandle>
    where
        F: FnOnce() + Send + 'static,
    {
        self.register(|owner| {
            // TaskLocalFuture also restores the weak owner during Drop if a
            // queued blocking job is cancelled before its closure ever runs.
            let work = OWNER.scope(Some(owner), async move {
                work();
            });
            tokio::task::spawn_blocking(move || {
                futures_util::FutureExt::now_or_never(work).expect("blocking work cannot suspend");
            })
        })
    }

    fn register<S>(self: &std::sync::Arc<Self>, start: S) -> Option<tokio::task::AbortHandle>
    where
        S: FnOnce(std::sync::Weak<Self>) -> tokio::task::JoinHandle<()>,
    {
        let mut state = self.state.lock();
        if state.closed {
            drop(state);
            self.sync_scope(|| drop(start));
            return None;
        }
        state.tasks.retain_mut(|task| {
            if !task.is_finished() {
                return true;
            }
            let result = futures_util::FutureExt::now_or_never(task)
                .expect("finished task has a ready join result");
            report_join(&self.failed, result);
            false
        });
        if self.limit.is_some_and(|limit| state.tasks.len() >= limit) {
            state.capacity_rejected = true;
            drop(state);
            self.abort();
            self.sync_scope(|| drop(start));
            return None;
        }
        // Registration and admission closure share this lock, including tasks
        // aborted before their first poll. Children inherit only a weak owner.
        let task = start(std::sync::Arc::downgrade(self));
        let abort = task.abort_handle();
        state.tasks.push(task);
        Some(abort)
    }

    /// Close admission and request task cancellation; this is not a join.
    pub fn abort(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        for task in &state.tasks {
            task.abort();
        }
        for (_, endpoint) in &state.endpoints {
            endpoint.close(quinn::VarInt::from_u32(0), b"outbound runtime closed");
        }
        self.closed.notify_waiters();
    }

    /// Await every retained task and QUIC endpoint. Cancellation preserves ownership.
    /// Started libc resolver calls cannot be aborted and can delay completion.
    pub async fn close(&self) {
        self.abort();
        let _joining = self.joining.lock().await;
        loop {
            // Keep the join in the owner while awaiting, so cancellation of a
            // close waiter cannot detach a still-releasing carrier.
            let task = self.state.lock().tasks.pop();
            let Some(task) = task else { break };
            let mut task = PendingJoin {
                owner: self,
                task: Some(task),
            };
            report_join(&self.failed, task.task.as_mut().unwrap().await);
            task.task.take();
        }
        loop {
            let endpoint = self.state.lock().endpoints.pop();
            let Some(endpoint) = endpoint else { return };
            let mut endpoint = PendingEndpoint {
                owner: self,
                endpoint: Some(endpoint),
            };
            endpoint.endpoint.as_ref().unwrap().1.wait_idle().await;
            endpoint.endpoint.take();
        }
    }
}

#[cfg(feature = "native-api")]
pub(crate) async fn lookup_host_owned(
    host: &str,
    port: u16,
) -> Option<std::io::Result<Vec<std::net::SocketAddr>>> {
    use std::net::ToSocketAddrs as _;

    let owner = capture_owner()?;
    let Some(owner) = owner.upgrade() else {
        return Some(Err(std::io::ErrorKind::Interrupted.into()));
    };
    let host = host.to_owned();
    let (result, receiver) = tokio::sync::oneshot::channel();
    if owner
        .spawn_blocking(move || {
            let addresses = (host.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect);
            let _ = result.send(addresses);
        })
        .is_none()
    {
        return Some(Err(if owner.state.lock().capacity_rejected {
            crate::proxy::PacketRejection::Capacity.into()
        } else {
            std::io::ErrorKind::Interrupted.into()
        }));
    }
    Some(
        receiver
            .await
            .unwrap_or_else(|_| Err(std::io::Error::other("owned resolver task stopped"))),
    )
}

impl Drop for TaskOwner {
    fn drop(&mut self) {
        self.abort();
    }
}

fn report_join(failed: &std::sync::atomic::AtomicBool, result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result
        && error.is_panic()
    {
        failed.store(true, std::sync::atomic::Ordering::Release);
        tracing::error!(%error, "outbound runtime task panicked");
    }
}

struct PendingJoin<'a> {
    owner: &'a TaskOwner,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for PendingJoin<'_> {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.owner.state.lock().tasks.push(task);
        }
    }
}

struct PendingEndpoint<'a> {
    owner: &'a TaskOwner,
    endpoint: Option<(std::sync::Weak<()>, quinn::Endpoint)>,
}

impl Drop for PendingEndpoint<'_> {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            self.owner.state.lock().endpoints.push(endpoint);
        }
    }
}

#[cfg(all(test, feature = "native-api"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct LateChild {
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
        rejected: Arc<AtomicBool>,
    }

    impl Drop for LateChild {
        fn drop(&mut self) {
            let permit = self.permit.take();
            let child = spawn_owned(async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            });
            self.rejected.store(child.is_none(), Ordering::Release);
        }
    }

    #[tokio::test]
    async fn close_joins_unpolled_parent_and_rejects_its_late_child() {
        let owner = Arc::new(TaskOwner::default());
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let rejected = Arc::new(AtomicBool::new(false));
        let late = LateChild {
            permit: Some(Arc::clone(&capacity).acquire_owned().await.unwrap()),
            rejected: Arc::clone(&rejected),
        };
        owner.sync_scope(|| {
            spawn_owned(async move {
                let _late = late;
                std::future::pending::<()>().await;
            })
            .unwrap();
        });
        assert_eq!(capacity.available_permits(), 0);
        owner.close().await;
        assert!(rejected.load(Ordering::Acquire));
        assert_eq!(capacity.available_permits(), 1);
        assert!(owner.state.lock().tasks.is_empty());
    }

    #[tokio::test]
    async fn expired_captured_scope_rejects_children_spawned_while_dropping_a_factory() {
        let owner = Arc::new(TaskOwner::production());
        let scope = owner.task_scope();
        owner.close().await;
        drop(owner);
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let rejected = Arc::new(AtomicBool::new(false));
        let late = LateChild {
            permit: Some(Arc::clone(&capacity).acquire_owned().await.unwrap()),
            rejected: Arc::clone(&rejected),
        };
        assert!(
            scope
                .spawn(async move {
                    let _late = late;
                    std::future::pending::<()>().await;
                })
                .is_none()
        );
        assert!(rejected.load(Ordering::Acquire));
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn captured_admission_keeps_factory_owned_outside_initial_scope() {
        let owner = Arc::new(TaskOwner::default());
        let admission = owner.sync_scope(crate::runtime::capture_dial_admission);
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
        admission
            .scope(async {
                spawn_owned(async move {
                    let _permit = permit;
                    std::future::pending::<()>().await;
                })
                .unwrap();
            })
            .await;
        owner.close().await;
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn production_jobs_exceed_probe_limit_and_join_before_capacity_returns() {
        let owner = Arc::new(TaskOwner::production());
        let capacity = Arc::new(tokio::sync::Semaphore::new(300));
        for _ in 0..300 {
            let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
            owner
                .spawn(async move {
                    let _permit = permit;
                    std::future::pending::<()>().await;
                })
                .expect(
                    "production carrier/flow ownership, not the probe task cap, admits this job",
                );
        }
        assert_eq!(capacity.available_permits(), 0);
        owner.close().await;
        assert_eq!(capacity.available_permits(), 300);
    }

    #[tokio::test]
    async fn started_blocking_resolution_survives_cancelled_close_until_real_completion() {
        use futures_util::FutureExt as _;

        let owner = Arc::new(TaskOwner::production());
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&capacity).acquire_owned().await.unwrap();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let rejected = Arc::new(AtomicBool::new(false));
        let child_rejected = Arc::clone(&rejected);
        owner
            .spawn_blocking(move || {
                let _permit = permit;
                started.send(()).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let child = spawn_owned(std::future::pending::<()>());
                child_rejected.store(child.is_none(), Ordering::Release);
                if let Some(child) = child {
                    child.abort();
                }
            })
            .unwrap();
        entered.await.unwrap();
        owner.abort();
        let mut close = Box::pin(owner.close());
        assert!(close.as_mut().now_or_never().is_none());
        drop(close);
        assert_eq!(capacity.available_permits(), 0);
        assert_eq!(
            owner
                .task_scope()
                .scope(crate::bootstrap::lookup_host("localhost", 0))
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Interrupted
        );
        release.send(()).unwrap();
        owner.close().await;
        assert_eq!(capacity.available_permits(), 1);
        assert!(rejected.load(Ordering::Acquire));
    }

    #[test]
    fn queued_blocking_factory_drop_keeps_closed_scope() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let owner = Arc::new(TaskOwner::production());
            let (started, entered) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            owner
                .spawn_blocking(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                })
                .unwrap();
            entered.await.unwrap();
            let capacity = Arc::new(tokio::sync::Semaphore::new(1));
            let rejected = Arc::new(AtomicBool::new(false));
            let late = LateChild {
                permit: Some(Arc::clone(&capacity).acquire_owned().await.unwrap()),
                rejected: Arc::clone(&rejected),
            };
            let ran = Arc::new(AtomicBool::new(false));
            let work_ran = Arc::clone(&ran);
            owner
                .spawn_blocking(move || {
                    work_ran.store(true, Ordering::Release);
                    drop(late);
                })
                .unwrap();
            owner.abort();
            release.send(()).unwrap();
            owner.close().await;
            assert!(!ran.load(Ordering::Acquire));
            assert!(rejected.load(Ordering::Acquire));
            assert_eq!(capacity.available_permits(), 1);
            assert!(!owner.has_failed());
        });
    }

    #[tokio::test]
    async fn reaped_panic_remains_visible_after_close() {
        let owner = Arc::new(TaskOwner::production());
        let (started, entered) = tokio::sync::oneshot::channel();
        owner
            .spawn(async move {
                started.send(()).unwrap();
                panic!("owned driver failure");
            })
            .unwrap();
        entered.await.unwrap();
        owner.reap();
        assert!(owner.has_failed());
        owner.close().await;
        assert!(owner.has_failed());
    }

    #[tokio::test]
    async fn task_capacity_rejection_is_typed_and_joins_every_admitted_task() {
        let owner = Arc::new(TaskOwner::default());
        let result: anyhow::Result<()> = owner
            .scope(async {
                for _ in 0..257 {
                    let _ = spawn_owned(std::future::pending::<()>());
                }
                Ok(())
            })
            .await;
        assert!(matches!(
            result
                .unwrap_err()
                .downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        ));
        owner.close().await;
        assert!(owner.state.lock().tasks.is_empty());
    }
}
