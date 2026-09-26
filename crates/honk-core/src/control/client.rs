//! Shared command client for state changes that must serialize with reload.

#[cfg(feature = "native-api")]
use honk_outbound::group::SelectorMember;
#[cfg(any(feature = "native-api", feature = "clash-api"))]
use honk_outbound::group::SelectorNetworks;
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(feature = "clash-api")]
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct ControlClient {
    sender: mpsc::Sender<super::ControlCommand>,
}

#[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
#[derive(Debug)]
pub(crate) enum ModeRequest {
    #[cfg(test)]
    Runtime {
        mode: &'static str,
        target: Option<String>,
    },
    #[cfg(feature = "clash-api")]
    ClashMode(String),
    #[cfg(feature = "clash-api")]
    ClashSelection(String),
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Debug)]
pub(crate) enum SelectionRequest {
    #[cfg(feature = "clash-api")]
    Name { group: String, member: String },
    #[cfg(feature = "native-api")]
    Native {
        group_id: String,
        member_id: String,
        networks: SelectorNetworks,
    },
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Debug)]
pub(crate) struct SelectionResult {
    #[cfg(feature = "native-api")]
    pub(crate) revision: u64,
    #[cfg(feature = "native-api")]
    pub(crate) interrupted: bool,
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum ControlError {
    #[error("resource not found")]
    NotFound,
    #[error("selection is unsupported")]
    Unsupported,
    #[error("control owner is unavailable")]
    Unavailable,
    #[error("transport interruption could not be confirmed")]
    InterruptionFailed,
}

impl ControlClient {
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.sender
            .send(super::ControlCommand::Shutdown)
            .await
            .map_err(|_| anyhow::anyhow!("control command owner is unavailable"))
    }
    pub(crate) fn new(sender: mpsc::Sender<super::ControlCommand>) -> Self {
        Self { sender }
    }

    #[cfg(feature = "clash-api")]
    pub(crate) async fn select(
        &self,
        request: SelectionRequest,
    ) -> Result<SelectionResult, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(super::ControlCommand::SetSelector { request, reply })
            .map_err(|_| ControlError::Unavailable)?;
        response.await.map_err(|_| ControlError::Unavailable)?
    }

    #[cfg(all(feature = "native-api", feature = "clash-api"))]
    pub(crate) async fn mode(
        &self,
        request: ModeRequest,
    ) -> Result<crate::mode::ModeState, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(super::ControlCommand::SetRuntimeMode { request, reply })
            .map_err(|_| ControlError::Unavailable)?;
        response.await.map_err(|_| ControlError::Unavailable)?
    }
}

impl super::ControlPlane {
    /// Drive mutations for an embedded engine whose caller owns ingress and shutdown.
    pub async fn serve_control_commands(&mut self) -> anyhow::Result<()> {
        let mut receiver = self
            .command_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("control command receiver is already owned"))?;
        let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(
            &self.config.read().await.subscriptions,
        )?;
        let drain = Arc::clone(&self.drain_tracker);
        while let Some(command) = receiver.recv().await {
            if !self
                .dispatch_control_command(command, &drain, &mut authorizations)
                .await
            {
                break;
            }
        }
        Ok(())
    }
    #[cfg(any(feature = "native-api", feature = "clash-api"))]
    pub(super) async fn apply_selector_request(
        &self,
        request: SelectionRequest,
    ) -> Result<SelectionResult, ControlError> {
        let _reload = self.reload_lock.lock().await;
        #[cfg(feature = "native-api")]
        if self.native.is_some() {
            match self.phase.as_ref().map(|phase| *phase.borrow()) {
                Some(super::EnginePhase::Running) if self.is_datapath_healthy() => {}
                _ => return Err(ControlError::Unavailable),
            }
        }
        let config = self.config.read().await;
        let manager = self.group_manager.read().clone();
        let (name, member, networks) = match request {
            #[cfg(feature = "clash-api")]
            SelectionRequest::Name { group, member } => {
                let selected = manager
                    .selector_member_by_name(&group, &member)
                    .map_err(selection_error)?;
                (group, selected, SelectorNetworks::Both)
            }
            #[cfg(feature = "native-api")]
            SelectionRequest::Native {
                group_id,
                member_id,
                networks,
            } => {
                let native = self.native.as_ref().ok_or(ControlError::Unavailable)?;
                let catalog = native.catalog.snapshot();
                let name = catalog
                    .groups
                    .iter()
                    .find(|(_, id)| **id == group_id)
                    .map(|(name, _)| name.clone())
                    .ok_or(ControlError::NotFound)?;
                let selected = manager
                    .native_members(&name)
                    .find_map(|member| match member {
                        honk_outbound::group::NativeGroupMember::Node(node)
                            if node.id.to_string() == member_id =>
                        {
                            Some(SelectorMember::Node(node.id))
                        }
                        honk_outbound::group::NativeGroupMember::Group(group)
                            if catalog.groups.get(&group.name) == Some(&member_id) =>
                        {
                            Some(SelectorMember::Group(group.name.clone()))
                        }
                        _ => None,
                    })
                    .ok_or(ControlError::Unsupported)?;
                (name, selected, networks)
            }
        };
        let group = config
            .groups
            .iter()
            .rev()
            .find(|group| group.name == name)
            .ok_or(ControlError::NotFound)?;
        let group_id = group.id.to_string();
        #[cfg(feature = "native-api")]
        let group_id = if let Some(native) = &self.native {
            native
                .catalog
                .snapshot()
                .groups
                .get(&name)
                .cloned()
                .ok_or(ControlError::NotFound)?
        } else {
            group_id
        };
        let mut selected = Vec::new();
        if group.interrupt_connections {
            for (network, label) in [
                (honk_outbound::group::SelectionNetwork::Tcp, "tcp"),
                (honk_outbound::group::SelectionNetwork::Udp, "udp"),
            ] {
                if matches!(
                    (networks, network),
                    (SelectorNetworks::Both, _)
                        | (
                            SelectorNetworks::Tcp,
                            honk_outbound::group::SelectionNetwork::Tcp
                        )
                        | (
                            SelectorNetworks::Udp,
                            honk_outbound::group::SelectionNetwork::Udp
                        )
                ) {
                    selected.push((
                        network,
                        self.connection_tracker
                            .snapshot_group(&group_id, Some(label)),
                    ));
                }
            }
        }
        let update = manager
            .publish_selector_choice(&name, &member, networks)
            .map_err(selection_error)?;
        #[cfg(feature = "native-api")]
        let revision = update.revision;
        let changed = update.changed_networks.clone();
        drop(config);
        update.run_callbacks_without_interrupt();
        use futures::StreamExt;
        let mut pending: futures::stream::FuturesUnordered<_> = selected
            .into_iter()
            .filter(|(network, _)| changed.contains(network))
            .flat_map(|(_, connections)| connections)
            .map(|connection| self.connection_tracker.start_close(connection).wait())
            .collect();
        #[cfg(feature = "native-api")]
        let mut interrupted = false;
        let mut uncertain = false;
        while let Some(outcome) = pending.next().await {
            match outcome {
                crate::connection_tracker::CloseOutcome::Closed => {
                    #[cfg(feature = "native-api")]
                    {
                        interrupted = true;
                    }
                }
                crate::connection_tracker::CloseOutcome::Gone => {}
                _ => uncertain = true,
            }
        }
        if uncertain {
            return Err(ControlError::InterruptionFailed);
        }
        Ok(SelectionResult {
            #[cfg(feature = "native-api")]
            revision,
            #[cfg(feature = "native-api")]
            interrupted,
        })
    }
}

#[cfg(any(feature = "native-api", feature = "clash-api"))]
fn selection_error(error: honk_outbound::group::SelectorError) -> ControlError {
    match error {
        honk_outbound::group::SelectorError::GroupNotFound => ControlError::NotFound,
        honk_outbound::group::SelectorError::RevisionExhausted => ControlError::Unavailable,
        _ => ControlError::Unsupported,
    }
}
