use super::*;

impl PendingUdpVerdicts {
    pub(in crate::control) async fn activate_direct(
        &self,
        identity: PendingUdpIdentity,
        lease: &mut UdpInitLease,
        direct_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if skb_mark_has_reserved_bits(direct_rule_mark) {
            return Err(PendingUdpDecisionError::ReservedDirectMark);
        }
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let final_mark = direct_rule_mark | CLASSIFIED_MARK;
        let cell = self.matching_cell(identity)?;

        {
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed,
                cancelling,
                ..
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
            if *armed {
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            if *cancelling {
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ArmDirect(direct_rule_mark),
                )
                .map_err(|error| self.fatal_error("arm direct", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            *armed = true;
        }
        cell.changed.notify_waiters();

        loop {
            let batch = {
                let mut state = cell.state.lock();
                match &mut *state {
                    CellState::Pending {
                        armed: true,
                        verdicts,
                        ..
                    } => std::mem::take(verdicts),
                    _ => {
                        let fatal = PendingUdpFatal::new(
                            "direct verdict",
                            "armed correlator changed phase before activation",
                        );
                        self.signal_fatal(fatal.clone());
                        return Err(fatal.into());
                    }
                }
            };
            for verdict in batch {
                self.accept_one_fatal(verdict, final_mark)?;
            }

            let mut backend = self.armed_backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                started_at,
                verdicts,
                ..
            } = &mut *state
            else {
                let fatal = PendingUdpFatal::new(
                    "activate direct",
                    "armed correlator changed phase before backend activation",
                );
                self.signal_fatal(fatal.clone());
                return Err(fatal.into());
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                self.fail_armed(&cell, identity);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            if !verdicts.is_empty() {
                drop(state);
                drop(backend);
                continue;
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ActivateDirect(direct_rule_mark),
                )
                .map_err(|error| self.fatal_error("activate direct", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                let fatal = PendingUdpFatal::new(
                    "activate direct",
                    format!("backend rejected armed transition: {result:?}"),
                );
                self.signal_fatal(fatal.clone());
                return Err(fatal.into());
            }
            *state = CellState::ActiveDirect {
                expires_at: Instant::now() + TERMINAL_GRACE,
                final_mark,
            };
            break;
        }
        cell.changed.notify_waiters();

        if !lease.commit_kernel_handoff() {
            let fatal = PendingUdpFatal::new(
                "direct endpoint handoff",
                "backend activated after endpoint identity was retired",
            );
            self.signal_fatal(fatal.clone());
            return Err(fatal.into());
        }
        Ok(())
    }

    pub(in crate::control) async fn activate_proxy(
        &self,
        identity: PendingUdpIdentity,
        lease: &UdpInitLease,
        final_outbound: u8,
        final_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        let verdicts = {
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ActivateProxy(final_outbound, final_rule_mark),
                )
                .map_err(|error| self.fatal_error("activate proxy", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Proxy {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        for verdict in verdicts {
            self.drop_one_fatal(verdict, DropOutcome::Proxy)?;
        }
        Ok(())
    }

    pub(in crate::control) async fn block(
        &self,
        identity: PendingUdpIdentity,
        lease: &mut UdpInitLease,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        let verdicts = {
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::Block,
                )
                .map_err(|error| self.fatal_error("block", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Block {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        for verdict in verdicts {
            self.drop_one_fatal(verdict, DropOutcome::Block)?;
        }
        if !lease.commit_kernel_handoff() {
            let fatal = PendingUdpFatal::new(
                "block endpoint handoff",
                "backend blocked after endpoint identity was retired",
            );
            self.signal_fatal(fatal.clone());
            return Err(fatal.into());
        }
        Ok(())
    }

    pub(in crate::control) async fn cancel(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<(), PendingUdpDecisionError> {
        let cell = self.matching_cell(identity)?;
        {
            let state = cell.state.lock();
            match &*state {
                CellState::Pending { armed: true, .. } => {
                    drop(state);
                    self.fail_armed(&cell, identity);
                    return Err(PendingUdpDecisionError::ArmedInProgress);
                }
                CellState::Pending { .. } => {}
                _ => return Ok(()),
            }
        }

        let (verdicts, mismatch) = {
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                verdicts,
                ..
            } = &mut *state
            else {
                let armed = matches!(&*state, CellState::Pending { armed: true, .. });
                drop(state);
                drop(backend);
                if armed {
                    self.fail_armed(&cell, identity);
                    return Err(PendingUdpDecisionError::ArmedInProgress);
                }
                return Ok(());
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
            let result = backend
                .abort_pending_udp_flow(&identity.tuples(), identity.decision_token)
                .map_err(|error| self.fatal_error("abort pending flow", error.to_string()))?;
            let mismatch = match result {
                UdpDecisionCommitResult::Applied
                | UdpDecisionCommitResult::Missing
                | UdpDecisionCommitResult::Superseded => None,
                UdpDecisionCommitResult::TokenMismatch => {
                    self.stats.record_udp_nfqueue_token_mismatch();
                    Some(UdpDecisionCommitResult::TokenMismatch)
                }
                UdpDecisionCommitResult::StateMismatch => {
                    Some(UdpDecisionCommitResult::StateMismatch)
                }
            };
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            (verdicts, mismatch)
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.client(),
            identity.destination(),
            identity.decision_token,
            identity.endpoint_generation,
        );
        match mismatch {
            Some(UdpDecisionCommitResult::TokenMismatch) => {
                Err(PendingUdpDecisionError::StaleIdentity)
            }
            Some(UdpDecisionCommitResult::StateMismatch) => {
                let fatal = PendingUdpFatal::new(
                    "abort pending flow",
                    "backend left Pending while retaining a non-pending token state",
                );
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
            None => Ok(()),
            Some(
                UdpDecisionCommitResult::Applied
                | UdpDecisionCommitResult::Missing
                | UdpDecisionCommitResult::Superseded,
            ) => unreachable!("successful abort results are not mismatches"),
        }
    }

    pub(super) fn fail_armed(&self, cell: &Arc<FlowCell>, identity: PendingUdpIdentity) {
        let verdicts = {
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                verdicts,
                ..
            } = &mut *state
            else {
                return;
            };
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
        self.signal_fatal(PendingUdpFatal::new(
            "armed flow cancellation",
            "DirectArmed flow lost its initializer before activation",
        ));
    }
}
