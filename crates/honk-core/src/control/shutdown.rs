use super::*;

/// Bound for shutdown stages that have no natural deadline (watcher join,
/// runtime-generation retirement, DNS controller/persistence close). The
/// datapath hooks are already detached by then, so a hung stage must time
/// out and log rather than leave the process half-torn-down forever.
const SHUTDOWN_STAGE_TIMEOUT: Duration = Duration::from_secs(10);

impl ControlPlane {
    #[cfg(feature = "ebpf")]
    pub(super) async fn cleanup_nfqueue_startup_failure(
        &mut self,
        runtime: &mut Option<NfqueueRuntime>,
    ) {
        let Some(runtime) = runtime.as_mut() else {
            return;
        };
        runtime.begin_pending_drain().await;
        if let Err(error) = runtime.shutdown_service().await {
            error!(%error, "failed to stop NFQUEUE after startup failure");
        }
        if let Err(error) = runtime.finish_pending_drain().await {
            error!(%error, "failed to drain NFQUEUE after startup failure");
        }
        self.pending_udp_verdicts = None;
    }

    async fn cleanup_flags_startup_failure(&mut self) {
        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.disable().await
        {
            error!(%error, "datapath flags startup cleanup failed");
        }
    }
    pub(super) async fn cleanup_pre_admission_failure(&mut self) {
        self.drain_tracker.start_rejecting();
        self.cleanup_flags_startup_failure().await;
        {
            let mut tasks = self.background_tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        }
        if let Err(error) = self.ebpf.write().await.detach_hooks() {
            error!(%error, "failed to detach eBPF hooks after startup failure");
        }
        if let Err(error) = self.finalize_shutdown().await {
            error!(%error, "failed to finalize startup rollback");
        }
    }
    pub(super) async fn cleanup_started_control_tasks(
        &mut self,
        udp_removal_task: &mut tokio::task::JoinHandle<()>,
        dns_listener: Option<&mut dns_listener::DnsListener>,
    ) {
        if let Some(listener) = dns_listener {
            listener.stop_accepting();
            listener.abort_and_join().await;
        }
        if !self.udp_pool.shutdown().await {
            error!("UDP endpoint shutdown required forced cleanup during startup rollback");
        }
        if let Err(error) = udp_removal_task.await {
            error!(%error, "UDP removal worker failed during startup rollback");
        }
        self.cleanup_pre_admission_failure().await;
    }

    /// Datapath half of shutdown: close admission, stop background work,
    /// detach the eBPF hooks (network restored before the connection drain,
    /// Go dae behaviour), then drain flows and retire the outbound runtime
    /// generation.  Every await without a natural deadline is bounded —
    /// with the hooks already detached, a hung stage would otherwise leave
    /// the engine half-torn-down forever: links gone, process alive.
    pub(super) async fn shutdown_datapath(
        &mut self,
        drain: &Arc<DrainTracker>,
        udp_removal_task: &mut tokio::task::JoinHandle<()>,
        dns_listener: Option<&mut dns_listener::DnsListener>,
    ) -> anyhow::Result<()> {
        info!(
            "Control plane shutting down, draining {} active connections",
            drain.active_count()
        );
        if let Some(listener) = dns_listener.as_ref() {
            listener.stop_accepting();
        }
        self.stop_udp_warm_coordinator().await;
        self.stop_selector_warm_coordinator().await;
        if !self.udp_pool.shutdown().await {
            error!("UDP endpoint shutdown required forced cleanup");
        }
        // Keep the removal consumer alive until terminal endpoint cleanup has
        // emitted and drained every conn-state/tracker retirement.
        if let Err(error) = (&mut *udp_removal_task).await {
            warn!("UDP removal consumer failed during shutdown: {}", error);
        }
        // Abort remaining background tasks (health check, janitors, preconnect)
        // only after UDP drivers and their removal sink have drained.
        {
            let mut tasks = self.background_tasks.lock().await;
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        // Stop the interface watcher first: it shares the backend and could
        // re-attach hooks mid-drain. The timeout aborts the worker instead
        // of detaching it (a detached watcher could re-attach hooks after
        // detach_hooks).
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        }
        // Detach BPF hooks immediately to restore network connectivity
        // before draining connections (matches Go dae behaviour).
        info!("shutdown: detaching eBPF hooks");
        {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.detach_hooks() {
                warn!("Failed to detach BPF hooks: {}", e);
            }
        }
        info!("shutdown: draining connections");
        drain.drain().await?;
        if let Some(listener) = dns_listener {
            listener.abort_and_join().await;
        }
        // Active flows own the current runtime until the drain completes; only
        // then terminally close its session pools and reject any late warm work.
        // Dropping this future on timeout detaches nothing: the force-closes
        // are synchronous once entered and none of the runtimes touch the
        // eBPF backend.
        let generation = self.runtime_registry.read().clone();
        info!("shutdown: retiring outbound runtime generation");
        if tokio::time::timeout(SHUTDOWN_STAGE_TIMEOUT, generation.shutdown())
            .await
            .is_err()
        {
            warn!(
                "outbound runtime generation shutdown exceeded {:?}; continuing",
                SHUTDOWN_STAGE_TIMEOUT
            );
        }
        Ok(())
    }

    /// Userspace half of shutdown: DNS controller, DNS persistence, and the
    /// eBPF backend cleanup.  Bounded like `shutdown_datapath` so a stuck
    /// DNS transport cannot pin the process after the datapath is down.
    pub(super) async fn finalize_shutdown(&mut self) -> anyhow::Result<()> {
        info!("shutdown: stopping DNS controller");
        self.dns_controller.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        let dns_cache = self.dns_controller.cache().await;
        let persistence = dns_cache.lock().await.persistence();
        if let Some(persistence) = persistence {
            // The worker is a std thread that cannot be aborted, but the
            // Shutdown command is queued before the join starts, and the
            // spawn_blocking join keeps owning the thread handle even if
            // this future is dropped on timeout — no detached writer.
            match tokio::time::timeout(SHUTDOWN_STAGE_TIMEOUT, persistence.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "DNS persistence shutdown failed"),
                Err(_) => warn!(
                    "DNS persistence shutdown exceeded {:?}; continuing",
                    SHUTDOWN_STAGE_TIMEOUT
                ),
            }
        }
        info!("shutdown: cleaning up eBPF backend");
        self.ebpf.write().await.cleanup().await?;
        info!("Control plane stopped");
        Ok(())
    }
}
