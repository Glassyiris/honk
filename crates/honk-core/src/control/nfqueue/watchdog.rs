use super::*;

impl PendingUdpVerdicts {
    pub(in crate::control) async fn run_watchdog(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => self.watchdog_tick().await,
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                }
            }
        }
    }

    pub(super) async fn watchdog_tick(&self) {
        self.drain_scheduled_cleanups().await;
        let now = Instant::now();
        let mut overdue = Vec::new();
        let mut expired = Vec::new();
        for entry in &self.cells {
            let cell = Arc::clone(entry.value());
            let state = cell.state.lock();
            match &*state {
                CellState::Pending {
                    started_at,
                    armed: false,
                    ..
                } if now.saturating_duration_since(*started_at) >= HARD_HOLD_TIMEOUT => {
                    overdue.push(cell.identity);
                }
                CellState::Pending { .. } => {}
                terminal
                    if terminal
                        .terminal_expiry()
                        .is_some_and(|expiry| expiry <= now) =>
                {
                    expired.push((*entry.key(), Arc::clone(&cell)));
                }
                _ => {}
            }
        }
        for identity in overdue {
            let _ = self.cancel(identity).await;
        }
        for (key, cell) in expired {
            self.remove_if_expired(key, &cell, now);
        }
        self.notify_empty_if_needed();
    }

    pub(super) async fn drain_scheduled_cleanups(&self) {
        let _drainer = self.cleanup_drainer.lock().await;
        loop {
            let request = self.scheduled_cleanups.lock().iter().next().copied();
            let Some(request) = request else {
                self.notify_empty_if_needed();
                return;
            };
            let retry = match request {
                CleanupRequest::Flow(identity) => match self.cancel(identity).await {
                    Ok(()) | Err(PendingUdpDecisionError::StaleIdentity) => false,
                    Err(PendingUdpDecisionError::ArmedInProgress) => true,
                    Err(PendingUdpDecisionError::ReservedDirectMark) => unreachable!(),
                    Err(PendingUdpDecisionError::Fatal(_)) => false,
                },
                CleanupRequest::Token {
                    key,
                    decision_token,
                } => {
                    let result = {
                        let Ok(mut backend) = self.ebpf.try_write() else {
                            return;
                        };
                        backend.abort_pending_udp_flow(&key.tuples(), decision_token)
                    };
                    match result {
                        Ok(UdpDecisionCommitResult::Applied)
                        | Ok(UdpDecisionCommitResult::Missing) => {}
                        Ok(result) => self.record_commit_mismatch(result),
                        Err(error) => self.signal_fatal(PendingUdpFatal::new(
                            "scheduled abort",
                            error.to_string(),
                        )),
                    }
                    false
                }
            };
            if retry {
                return;
            }
            self.scheduled_cleanups.lock().remove(&request);
            self.notify_empty_if_needed();
        }
    }

    pub(super) async fn armed_backend_before_deadline<'a>(
        &'a self,
        cell: &Arc<FlowCell>,
        identity: PendingUdpIdentity,
    ) -> Result<tokio::sync::RwLockWriteGuard<'a, Box<dyn EbpfBackend>>, PendingUdpDecisionError>
    {
        let deadline = {
            let state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: true,
                ..
            } = &*state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            *started_at + HARD_HOLD_TIMEOUT
        };
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.ebpf.write())
            .await
        {
            Ok(backend) => Ok(backend),
            Err(_) => {
                self.fail_armed(cell, identity);
                Err(PendingUdpDecisionError::ArmedInProgress)
            }
        }
    }

    pub(super) async fn backend_before_deadline<'a>(
        &'a self,
        cell: &Arc<FlowCell>,
        identity: PendingUdpIdentity,
    ) -> Result<tokio::sync::RwLockWriteGuard<'a, Box<dyn EbpfBackend>>, PendingUdpDecisionError>
    {
        let deadline = {
            let state = cell.state.lock();
            let CellState::Pending { started_at, .. } = &*state else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            *started_at + HARD_HOLD_TIMEOUT
        };
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.ebpf.write())
            .await
        {
            Ok(backend) => Ok(backend),
            Err(_) => Err(self.expire_unarmed_pending(cell, identity)),
        }
    }

    pub(super) fn expire_unarmed_pending(
        &self,
        cell: &Arc<FlowCell>,
        identity: PendingUdpIdentity,
    ) -> PendingUdpDecisionError {
        let verdicts = {
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed, verdicts, ..
            } = &mut *state
            else {
                return PendingUdpDecisionError::StaleIdentity;
            };
            if *armed {
                return PendingUdpDecisionError::ArmedInProgress;
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.client(),
            identity.destination(),
            identity.decision_token,
            identity.endpoint_generation,
        );
        self.schedule_cleanup(CleanupRequest::Token {
            key: identity.key,
            decision_token: identity.decision_token,
        });
        PendingUdpDecisionError::StaleIdentity
    }

    pub(super) fn matching_cell(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<Arc<FlowCell>, PendingUdpDecisionError> {
        let cell = self
            .cells
            .get(&identity.key)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(PendingUdpDecisionError::StaleIdentity)?;
        if cell.identity != identity {
            self.stats.record_udp_nfqueue_token_mismatch();
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        Ok(cell)
    }

    pub(super) fn insert_dead_vacant(
        &self,
        vacant: dashmap::mapref::entry::VacantEntry<'_, FlowKey, Arc<FlowCell>>,
        key: FlowKey,
        decision_token: u32,
        flow_slot: OwnedSemaphorePermit,
    ) {
        let identity = PendingUdpIdentity::new(key, decision_token, 0);
        vacant.insert(Arc::new(FlowCell::terminal(
            identity,
            CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            },
            flow_slot,
        )));
        self.stats.increment_udp_nfqueue_active_flows();
    }

    pub(super) fn remove_if_expired(
        &self,
        key: FlowKey,
        cell: &Arc<FlowCell>,
        now: Instant,
    ) -> bool {
        let dashmap::mapref::entry::Entry::Occupied(occupied) = self.cells.entry(key) else {
            return false;
        };
        if !Arc::ptr_eq(occupied.get(), cell) {
            return false;
        }
        let state = cell.state.lock();
        if !state.terminal_expiry().is_some_and(|expiry| expiry <= now) {
            return false;
        }
        drop(state);
        occupied.remove();
        self.stats.decrement_udp_nfqueue_active_flows();
        self.notify_empty_if_needed();
        true
    }

    pub(super) fn remove_cell_now(&self, key: FlowKey, cell: &Arc<FlowCell>) -> bool {
        let dashmap::mapref::entry::Entry::Occupied(occupied) = self.cells.entry(key) else {
            return false;
        };
        if !Arc::ptr_eq(occupied.get(), cell) {
            return false;
        }
        occupied.remove();
        self.stats.decrement_udp_nfqueue_active_flows();
        self.notify_empty_if_needed();
        true
    }

    pub(super) fn schedule_cleanup_for_key(&self, key: FlowKey, decision_token: u32) {
        let Some(entry) = self.cells.try_entry(key) else {
            self.schedule_cleanup(CleanupRequest::Token {
                key,
                decision_token,
            });
            return;
        };
        match entry {
            dashmap::mapref::entry::Entry::Occupied(occupied)
                if occupied.get().identity.decision_token == decision_token =>
            {
                let cell = Arc::clone(occupied.get());
                drop(occupied);
                let Some(mut state) = cell.state.try_lock() else {
                    self.schedule_cleanup(CleanupRequest::Token {
                        key,
                        decision_token,
                    });
                    return;
                };
                let should_schedule = match &mut *state {
                    CellState::Pending { armed: true, .. } => false,
                    CellState::Pending { cancelling, .. } => {
                        *cancelling = true;
                        true
                    }
                    _ => true,
                };
                drop(state);
                if should_schedule {
                    self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                }
            }
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                drop(occupied);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                drop(vacant);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
            }
        }
    }

    pub(super) fn schedule_cleanup(&self, request: CleanupRequest) {
        let mut requests = self.scheduled_cleanups.lock();
        if requests.contains(&request) {
            return;
        }
        if requests.len() >= MAX_SCHEDULED_CLEANUPS {
            drop(requests);
            self.signal_fatal(PendingUdpFatal::new(
                "cleanup scheduling",
                "scheduled cleanup set reached NFQUEUE maxlen",
            ));
            return;
        }
        requests.insert(request);
    }

    pub(super) fn accept_one(&self, verdict: HeldVerdict, mark: u32) {
        let _ = self.accept_one_fatal(verdict, mark);
    }

    pub(super) fn accept_one_fatal(
        &self,
        mut verdict: HeldVerdict,
        mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        match verdict.guard.accept(mark) {
            Ok(()) => {
                self.stats
                    .record_udp_nfqueue_direct_accepted(verdict.received_at.elapsed());
                Ok(())
            }
            Err(error) => {
                self.stats.record_udp_nfqueue_verdict_error();
                let fatal = PendingUdpFatal::new("NF_ACCEPT verdict", error);
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
        }
    }

    pub(super) fn drop_one(&self, verdict: HeldVerdict, outcome: DropOutcome) {
        let _ = self.drop_one_fatal(verdict, outcome);
    }

    pub(super) fn drop_one_fatal(
        &self,
        mut verdict: HeldVerdict,
        outcome: DropOutcome,
    ) -> Result<(), PendingUdpDecisionError> {
        match verdict.guard.drop_packet() {
            Ok(()) => {
                let elapsed = verdict.received_at.elapsed();
                match outcome {
                    DropOutcome::Proxy => {
                        self.stats.record_udp_nfqueue_proxy_copied();
                        self.stats.record_udp_nfqueue_proxy_dropped(elapsed);
                    }
                    DropOutcome::Block => self.stats.record_udp_nfqueue_block(elapsed),
                    DropOutcome::Cancel => self.stats.record_udp_nfqueue_cancel(elapsed),
                    DropOutcome::Other => self.stats.record_udp_nfqueue_drop(elapsed),
                }
                Ok(())
            }
            Err(error) => {
                self.stats.record_udp_nfqueue_verdict_error();
                let fatal = PendingUdpFatal::new("NF_DROP verdict", error);
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
        }
    }

    pub(super) fn drop_many(&self, mut verdicts: VecDeque<HeldVerdict>, outcome: DropOutcome) {
        while let Some(verdict) = verdicts.pop_front() {
            if self.drop_one_fatal(verdict, outcome).is_err() {
                return;
            }
        }
    }

    pub(super) fn record_commit_mismatch(&self, result: UdpDecisionCommitResult) {
        if matches!(result, UdpDecisionCommitResult::TokenMismatch) {
            self.stats.record_udp_nfqueue_token_mismatch();
        }
    }

    pub(super) fn fatal_error(
        &self,
        operation: &'static str,
        detail: String,
    ) -> PendingUdpDecisionError {
        let fatal = PendingUdpFatal::new(operation, detail);
        self.signal_fatal(fatal.clone());
        fatal.into()
    }

    pub(super) fn signal_fatal(&self, fatal: PendingUdpFatal) {
        let _ = self.fatal.try_send(fatal);
    }

    pub(super) fn notify_empty_if_needed(&self) {
        if self.is_empty() {
            self.empty.notify_waiters();
        }
    }
}
