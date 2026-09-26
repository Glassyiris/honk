mod completion;
mod geodata;
mod revisions;
#[cfg(test)]
mod tests;
mod validation;

use super::super::management::{self, Completion, Mutation};
use super::super::{
    config_write::WriteError,
    offline,
    store::{Committed, SourceStore, StoreKind},
};
use super::*;
use crate::configuration::{Activation, ActivationRequest};
use crate::control::{ControlCommand, LogFiles};
use crate::subscription::SubscriptionSupervisorHandle;
use honk_config::parser::LoadedConfig;
use tokio::sync::watch;
use validation::{config_error, diagnostics_error, not_included, restart_diagnostics};

pub(crate) struct ConfigCoordinator {
    service: Arc<ConfigService>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct Worker {
    service: Arc<ConfigService>,
    store: Option<Arc<dyn SourceStore>>,
    data_dir: PathBuf,
    source_managed: bool,
    active: Arc<tokio::sync::RwLock<Arc<Config>>>,
    log_files: LogFiles,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    subscriptions: SubscriptionSupervisorHandle,
    activation: Activation,
}

impl ConfigService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        self: &Arc<Self>,
        store: Option<Arc<dyn SourceStore>>,
        initial: Option<SourceUpdate>,
        data_dir: PathBuf,
        active: Arc<tokio::sync::RwLock<Arc<Config>>>,
        log_files: LogFiles,
        diagnostics: crate::config_diagnostics::SharedDiagnostics,
        commands: mpsc::Sender<ControlCommand>,
        subscriptions: SubscriptionSupervisorHandle,
    ) -> ConfigCoordinator {
        if let Some(initial) = &initial {
            let config = active.read().await;
            let generation = diagnostics.read().generation;
            self.sources
                .accept(self.sources.prepare_accept(initial), generation);
            self.sources
                .generation_committed(&super::super::catalog::revision_for(&config), generation);
        }
        *self.store.write() = store.clone();
        let (sender, mut receiver) = mpsc::channel(16);
        *self.sender.lock() = Some(sender);
        let (stop, mut stopping) = watch::channel(false);
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut worker = Worker {
                service,
                store,
                data_dir,
                source_managed: initial.is_some(),
                active,
                log_files,
                diagnostics,
                activation: Activation::new(commands, subscriptions.clone()),
                subscriptions,
            };
            loop {
                let work = tokio::select! { biased; _=stopping.changed()=>break, work=receiver.recv()=>match work{Some(work)=>work,None=>break} };
                worker.perform(work).await;
            }
            receiver.close();
            while let Some(work) = receiver.recv().await {
                match work {
                    Work::Validate { response, .. } => {
                        let _ = response.send(Err(unavailable()));
                    }
                    Work::Manage { response, .. } => {
                        let _ = response.send(Err(unavailable().for_management(true)));
                    }
                    _ => {}
                }
            }
        });
        ConfigCoordinator {
            service: Arc::clone(self),
            stop,
            task,
        }
    }
}

impl ConfigCoordinator {
    pub(crate) async fn shutdown(self) {
        self.service.sender.lock().take();
        let _ = self.stop.send(true);
        if self.task.await.is_err() {
            tracing::error!("native configuration coordinator stopped unexpectedly");
        }
    }
}

impl Worker {
    async fn perform(&mut self, work: Work) {
        if let Err(error) = self.service.check_phase(&work) {
            match work {
                Work::Manage {
                    mutation, response, ..
                } => {
                    let _ = response.send(Err(error.for_management(mutation.deleting())));
                }
                Work::Replace { reservation, .. }
                | Work::Create { reservation, .. }
                | Work::GeoUpdate { reservation, .. }
                | Work::GroupPatch { reservation, .. }
                | Work::Reload { reservation }
                | Work::Import { reservation }
                | Work::ActivateRevision { reservation, .. } => {
                    self.service.operations.reject(&reservation.id, error);
                }
                Work::Sighup => tracing::warn!("SIGHUP refused while engine is not running"),
                _ => unreachable!("excluded non-activation work"),
            }
            return;
        }
        match work {
            Work::GeoUpdate { plan, reservation } => {
                self.perform_geodata(*plan, reservation).await;
            }
            Work::Manage {
                mutation,
                catalog,
                group_manager,
                alive_set,
                response,
            } => {
                let deleting = mutation.deleting();
                let result = self
                    .manage(mutation, &catalog, &group_manager, &alive_set)
                    .await
                    .map_err(|error| error.for_management(deleting));
                let _ = response.send(result);
            }
            Work::GroupPatch { patch, reservation } => {
                let id = reservation.id.clone();
                let group_id = patch.id.clone();
                let revision = patch.revision.clone();
                match self
                    .prepare_group_patch(*patch, &reservation.principal)
                    .await
                {
                    Ok(Some((candidate, sources, diagnostics, committed))) => {
                        self.replace_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources: Some(sources),
                                diagnostics,
                                expected_revision: Some(revision),
                                deferred_provider: None,
                            },
                            Some(&group_id),
                            committed,
                        )
                        .await;
                    }
                    Ok(None) => {
                        self.service.operations.accept(&id);
                        self.service.operations.running(&id);
                        self.service.operations.succeed(
                            &id,
                            crate::native_api::operations::OperationResult::GroupUpdate {
                                group_id,
                                config_revision: revision,
                            },
                        );
                    }
                    Err(error) => {
                        self.service.operations.reject(&id, error);
                    }
                }
                drop(reservation);
            }
            Work::Validate { request, response } => {
                let result = self.validate(request).await;
                let _ = response.send(result);
            }
            Work::Replace {
                source_id,
                content,
                if_match,
                reservation,
            } => {
                let id = reservation.id.clone();
                match self
                    .prepare_replace(
                        &source_id,
                        content,
                        if_match,
                        None,
                        None,
                        &reservation.principal,
                    )
                    .await
                {
                    Ok((candidate, sources, diagnostics, committed)) => {
                        self.replace_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources: Some(sources),
                                diagnostics,
                                expected_revision: None,
                                deferred_provider: None,
                            },
                            None,
                            committed,
                        )
                        .await;
                    }
                    Err(error) => {
                        self.service.operations.reject(&id, error);
                    }
                }
                drop(reservation);
            }
            Work::Create {
                path,
                content,
                reservation,
            } => {
                let id = reservation.id.clone();
                let prepared = self
                    .prepare_create(path, content, &reservation.principal)
                    .await;
                self.tree_operation(&id, prepared).await;
                drop(reservation);
            }
            Work::Import { reservation } => {
                let id = reservation.id.clone();
                let prepared = self.prepare_import(&reservation.principal).await;
                self.tree_operation(&id, prepared).await;
                drop(reservation);
            }
            Work::ActivateRevision {
                number,
                reservation,
            } => {
                let id = reservation.id.clone();
                let (head, blocked) = self
                    .store
                    .as_ref()
                    .and_then(|store| store.database())
                    .map_or((None, false), |database| {
                        (
                            database.cached_head().map(|(head, _)| head),
                            database.blocked(),
                        )
                    });
                let current = head == Some(number);
                if current && !blocked {
                    self.service.operations.accept(&id);
                    self.service.operations.running(&id);
                    let generation = self.diagnostics.read().generation;
                    self.service.operations.succeed(
                        &id,
                        super::super::operations::OperationResult::Reload {
                            active_generation_id: Some(format!(
                                "{}:{generation}",
                                self.service.instance_id
                            )),
                            datapath_generation_id: None,
                        },
                    );
                } else {
                    let prepared = self
                        .prepare_revision(number, &reservation.principal, current)
                        .await;
                    self.tree_operation(&id, prepared).await;
                }
                drop(reservation);
            }
            Work::Reload { reservation } => {
                let id = reservation.id.clone();
                self.service.operations.accept(&id);
                self.service.operations.running(&id);
                match self.load().await {
                    Ok((candidate, sources, diagnostics)) => {
                        self.reload_operation(
                            &id,
                            ActivationRequest {
                                candidate,
                                sources,
                                diagnostics,
                                expected_revision: None,
                                deferred_provider: None,
                            },
                        )
                        .await;
                    }
                    Err(_) => self.failed(
                        &id,
                        "reload_rejected",
                        "Configuration reload was rejected",
                        None,
                    ),
                }
                drop(reservation);
            }
            Work::Sighup => match self.load().await {
                Ok((candidate, sources, diagnostics)) => {
                    let completion = self
                        .activation
                        .activate(ActivationRequest {
                            candidate,
                            sources,
                            diagnostics,
                            expected_revision: None,
                            deferred_provider: None,
                        })
                        .await;
                    completion::log_sighup(completion);
                }
                Err(_) => tracing::warn!("SIGHUP configuration admission rejected"),
            },
        }
    }

    async fn manage(
        &mut self,
        mutation: Mutation,
        catalog: &super::super::catalog::Catalog,
        group_manager: &honk_outbound::group::SharedGroupManager,
        alive_set: &honk_outbound::alive::AliveDialerSet,
    ) -> Result<Completion, ApiError> {
        if !self.service.can_manage() {
            return Err(management::unsupported());
        }
        let active = self.active.read().await.clone();
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(management::unsupported)?;
        if !self.service.source_writable(&accepted, 0) {
            return Err(management::unsupported());
        }
        let main = &accepted.update.sources[0];
        use honk_config::parser::source_edit::{
            append_node_source, append_subscription_source, remove_node_source,
            remove_subscription_source,
        };
        let content = match &mutation {
            Mutation::CreateNode(input) => {
                if active.nodes.iter().any(|node| node.name == input.name) {
                    return Err(management::conflict());
                }
                append_node_source(main, &input.name, &input.link)
                    .map_err(|_| management::unsupported_value())?
            }
            Mutation::CreateProvider(input) => {
                if active
                    .subscriptions
                    .iter()
                    .any(|subscription| subscription.name == input.name)
                {
                    return Err(management::conflict());
                }
                append_subscription_source(main, &input.name, &input.url, &input.options())
                    .map_err(|_| management::unsupported_value())?
            }
            Mutation::DeleteNode(id) => {
                let node = uuid::Uuid::parse_str(id)
                    .ok()
                    .and_then(|id| active.nodes.iter().find(|node| node.id == id));
                let Some(node) = node else {
                    return Ok(Completion::Deleted(0));
                };
                if node.subscription_id.is_some()
                    || matches!(
                        node.protocol(),
                        honk_config::types::NodeProtocol::Direct
                            | honk_config::types::NodeProtocol::Block
                    )
                {
                    return Err(management::unsupported());
                }
                remove_node_source(main, node.id)
                    .map_err(|_| management::unsupported())?
                    .ok_or_else(management::unsupported)?
            }
            Mutation::DeleteProvider(id) => {
                if id == "inline" {
                    return Err(management::unsupported());
                }
                let subscription = uuid::Uuid::parse_str(id).ok().and_then(|id| {
                    active
                        .subscriptions
                        .iter()
                        .find(|subscription| subscription.id == id)
                });
                let Some(subscription) = subscription else {
                    return Ok(Completion::Deleted(0));
                };
                if active.subscriptions.iter().any(|other| {
                    other.id != subscription.id
                        && crate::subscription::same_subscription_fetch_identity(
                            other,
                            subscription,
                        )
                }) {
                    return Err(management::unsupported());
                }
                if !(subscription.url.starts_with("http://")
                    || subscription.url.starts_with("https://"))
                {
                    return Err(management::unsupported());
                }
                remove_subscription_source(main, subscription)
                    .map_err(|_| management::unsupported())?
                    .ok_or_else(management::unsupported)?
            }
        };
        drop(active);
        let (candidate, sources, diagnostics, committed) = self
            .prepare_replace(
                &accepted.ids[&main.path],
                content,
                accepted.hashes[0].clone(),
                Some(accepted.revision.clone()),
                match &mutation {
                    Mutation::CreateProvider(input) => Some(input.name.clone()),
                    _ => None,
                },
                self.service.principal(),
            )
            .await?;
        let created = match &mutation {
            Mutation::CreateNode(input) => candidate
                .nodes
                .iter()
                .find(|node| node.name == input.name && node.subscription_id.is_none())
                .map(|node| ("nodes", node.id)),
            Mutation::CreateProvider(input) => candidate
                .subscriptions
                .iter()
                .find(|subscription| subscription.name == input.name)
                .map(|subscription| ("providers", subscription.id)),
            _ => None,
        };
        let deferred = created
            .filter(|(collection, _)| *collection == "providers")
            .map(|(_, id)| id);
        self.begin_record(&committed);
        let completion = self
            .activation
            .activate(ActivationRequest {
                candidate,
                sources: Some(sources),
                diagnostics,
                expected_revision: Some(accepted.revision),
                deferred_provider: deferred,
            })
            .await;
        let stored = self
            .record(committed, &completion)
            .await
            .map_err(|details| unavailable().with_details(details))?;
        completion.map_err(|failure| failure.management_error(stored))?;
        if mutation.deleting() {
            return Ok(Completion::Deleted(1));
        }
        let (collection, id) = created.ok_or_else(|| {
            management::activation_error("resource_unavailable", Some(true), Some(true), Some(true))
        })?;
        // Capture under the publication barrier before the queue can delete this resource.
        let active = self.active.read().await;
        let value = if collection == "nodes" {
            let secrets = {
                let accepted = self.service.sources.accepted.read();
                self.service
                    .secrets(accepted.as_ref())
                    .as_ref()
                    .clone()
                    .with_clash(&active.experimental.clash_api.secret)
            };
            super::super::catalog::node_value(
                &active,
                &catalog.snapshot(),
                &group_manager.read(),
                alive_set,
                id,
                &secrets,
            )
        } else {
            super::super::providers::provider_value(
                &active,
                Some(&self.subscriptions),
                id,
                Some(&self.service),
                |name| super::super::geodata::group_id(catalog, name),
            )
        }
        .ok_or_else(|| {
            management::activation_error("resource_unavailable", Some(true), Some(true), Some(true))
        })?;
        Ok(Completion::Created {
            collection,
            id,
            value,
        })
    }

    async fn tree_operation(&mut self, id: &str, prepared: Result<Prepared, ApiError>) {
        match prepared {
            Ok((candidate, sources, diagnostics, committed)) => {
                self.replace_operation(
                    id,
                    ActivationRequest {
                        candidate,
                        sources: Some(sources),
                        diagnostics,
                        expected_revision: None,
                        deferred_provider: None,
                    },
                    None,
                    committed,
                )
                .await;
            }
            Err(error) => {
                self.service.operations.reject(id, error);
            }
        }
    }

    async fn load(
        &self,
    ) -> Result<(Config, Option<SourceUpdate>, Vec<DetailedDiagnostic>), ApiError> {
        let store = self.store.clone().ok_or_else(unsupported)?;
        let source_managed = self.source_managed;
        tokio::task::spawn_blocking(move || {
            let mut diagnostics = Vec::new();
            if !source_managed {
                let mut config = crate::load_operator_config(
                    store.entry().to_str().ok_or_else(invalid)?,
                    &mut diagnostics,
                )
                .map_err(|error| config_error(error, &diagnostics, &[], None, None))?;
                config.ensure_builtin_nodes();
                return Ok((config, None, diagnostics));
            }
            let loaded = store
                .load(&HashMap::new(), &mut diagnostics)
                .map_err(|error| config_error(error, &diagnostics, &[], None, None))?;
            let mut config = crate::admit_operator_config(
                loaded.config,
                loaded.sources[0].source.clone(),
                &mut diagnostics,
            )
            .map_err(|error| config_error(error, &diagnostics, &loaded.sources, None, None))?;
            config.ensure_builtin_nodes();
            Ok((
                config,
                Some(SourceUpdate {
                    sources: loaded.sources,
                    dependencies: Vec::new(),
                    geo_sources: None,
                }),
                diagnostics,
            ))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn prepare_group_patch(
        &self,
        patch: super::super::groups::GroupPatch,
        principal: &str,
    ) -> Result<Option<Prepared>, ApiError> {
        let expected = patch.expected.as_ref().map_err(Clone::clone)?;
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(unavailable)?;
        if accepted.revision != *expected || accepted.revision != patch.revision {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                ErrorCode::StaleRevision,
                "Group configuration revision changed",
                None,
            ));
        }
        let index = *accepted
            .group_sources
            .get(&patch.name)
            .ok_or_else(not_found)?;
        if !self.service.source_writable(&accepted, index) {
            return Err(super::super::groups::read_only());
        }
        let changes = patch.changes()?;
        let content = honk_config::parser::source_edit::edit_group_source(
            &accepted.update.sources[index],
            &patch.name,
            &changes,
        )
        .map_err(|_| invalid())?;
        if content == accepted.update.sources[index].content.as_ref() {
            let store = self.store.clone().ok_or_else(unsupported)?;
            let service = Arc::clone(&self.service);
            tokio::task::spawn_blocking(move || {
                let mut diagnostics = Vec::new();
                let baseline = store
                    .load(&HashMap::new(), &mut diagnostics)
                    .map_err(|_| stale())?;
                if service.sources.revision().as_ref() != Some(&patch.revision)
                    || !same_source_documents(&accepted.update.sources, &baseline.sources)
                {
                    return Err(stale());
                }
                Ok(())
            })
            .await
            .map_err(|_| unavailable())??;
            return Ok(None);
        }
        self.prepare_replace(
            &accepted.ids[&accepted.update.sources[index].path],
            content,
            accepted.hashes[index].clone(),
            Some(patch.revision),
            None,
            principal,
        )
        .await
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_replace(
        &self,
        source_id: &str,
        content: String,
        expected: String,
        group_revision: Option<String>,
        new_provider: Option<String>,
        principal: &str,
    ) -> Result<Prepared, ApiError> {
        if content.len() > MAX_SOURCE_BYTES {
            return Err(too_large());
        }
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(not_found)?;
        let index = accepted
            .update
            .sources
            .iter()
            .position(|source| accepted.ids[&source.path] == source_id)
            .ok_or_else(not_found)?;
        if !self.service.source_writable(&accepted, index) {
            return Err(denied());
        }
        let target = accepted.update.sources[index].path.clone();
        let mut check = self.candidate_check(accepted).await?;
        let source_id = source_id.to_owned();
        let principal = principal.to_owned();
        #[cfg(test)]
        let before_replace = self.service.before_replace.lock().take();
        let service = Arc::clone(&self.service);
        tokio::task::spawn_blocking(move || {
            let store = Arc::clone(&check.store);
            let accepted = &check.accepted;
            let kind = store.kind();
            let pin = store
                .pin(&target)
                .map_err(|error| store_write_error(kind, error))?;
            if pin.sha256() != expected {
                return Err(stale());
            }
            if let Some(revision) = &group_revision {
                if service.sources.revision().as_ref() != Some(revision) {
                    return Err(stale());
                }
                let mut diagnostics = Vec::new();
                let baseline = store
                    .load(&HashMap::new(), &mut diagnostics)
                    .map_err(|_| stale())?;
                if !same_source_documents(&accepted.update.sources, &baseline.sources) {
                    return Err(stale());
                }
            }
            let mut overlay = HashMap::new();
            overlay.insert(target.clone(), Arc::<str>::from(content.as_str()));
            let mut diagnostics = Vec::new();
            let loaded = store.load(&overlay, &mut diagnostics).map_err(|error| {
                config_error(
                    error,
                    &diagnostics,
                    &accepted.update.sources,
                    Some(&source_id),
                    Some(&accepted.ids),
                )
            })?;
            if let Some(name) = &new_provider {
                let provider = loaded
                    .config
                    .subscriptions
                    .iter()
                    .find(|provider| provider.name == *name)
                    .ok_or_else(management::unsupported_value)?;
                if check.active.subscriptions.iter().any(|other| {
                    crate::subscription::same_subscription_fetch_identity(other, provider)
                }) {
                    return Err(management::unsupported_value());
                }
                check.deferred.push(provider.clone());
            }
            let validated = check.validate(
                loaded,
                &mut diagnostics,
                &target,
                &content,
                Some(&source_id),
                &check.accepted.ids,
            )?;
            let recheck = Box::new(|| {
                #[cfg(test)]
                if let Some(hook) = before_replace {
                    hook();
                }
                if group_revision
                    .as_ref()
                    .is_some_and(|revision| service.sources.revision().as_ref() != Some(revision))
                {
                    return Err(WriteError::Conflict);
                }
                check.recheck(&overlay, &validated)
            });
            let committed = store
                .commit(pin, &content, &validated.sources, &principal, recheck)
                .map_err(|error| store_write_error(kind, error))?;
            Ok(prepared(validated, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn prepare_create(
        &self,
        label: String,
        content: String,
        principal: &str,
    ) -> Result<Prepared, ApiError> {
        if content.len() > MAX_SOURCE_BYTES {
            return Err(too_large());
        }
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(unsupported)?;
        let check = self.candidate_check(accepted).await?;
        let principal = principal.to_owned();
        #[cfg(test)]
        let before_replace = self.service.before_replace.lock().take();
        tokio::task::spawn_blocking(move || {
            let store = &check.store;
            let accepted = &check.accepted;
            let target = store.resolve(&label)?;
            if accepted.ids.contains_key(&target)
                || (store.kind() == StoreKind::File && target.symlink_metadata().is_ok())
            {
                return Err(exists());
            }
            let main = accepted.ids[&accepted.update.sources[0].path].as_str();
            // The new source has no accepted ID until it loads; this one names it in diagnostics.
            let mut ids = accepted.ids.clone();
            ids.insert(target.clone(), uuid::Uuid::new_v4().to_string());
            let overlay = HashMap::from([(target.clone(), Arc::<str>::from(content.as_str()))]);
            let mut diagnostics = Vec::new();
            let loaded = store.load(&overlay, &mut diagnostics).map_err(|error| {
                config_error(
                    error,
                    &diagnostics,
                    &accepted.update.sources,
                    Some(main),
                    Some(&ids),
                )
            })?;
            let validated = check.validate(
                loaded,
                &mut diagnostics,
                &target,
                &content,
                Some(main),
                &ids,
            )?;
            if !validated.sources.iter().any(|source| source.path == target) {
                return Err(not_included(main));
            }
            let recheck = Box::new(|| {
                #[cfg(test)]
                if let Some(hook) = before_replace {
                    hook();
                }
                check.recheck(&overlay, &validated)
            });
            let committed = store
                .create(&target, &content, &validated.sources, &principal, recheck)
                .map_err(|error| match error {
                    WriteError::Conflict => changed(),
                    // The parent became a symlink after resolution: still a path outside the root.
                    WriteError::UnsafePath => invalid(),
                    error => store_write_error(store.kind(), error),
                })?;
            Ok(prepared(validated, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn candidate_check(&self, accepted: Accepted) -> Result<CandidateCheck, ApiError> {
        Ok(CandidateCheck {
            store: self.store.clone().ok_or_else(unsupported)?,
            active: self.active.read().await.clone(),
            log_files: self.log_files.clone(),
            data_dir: self.data_dir.clone(),
            deferred: self
                .subscriptions
                .deferred_subscriptions()
                .await
                .map_err(|_| unavailable())?,
            accepted,
        })
    }
}

/// What a source write validates its candidate against, captured before blocking work.
struct CandidateCheck {
    store: Arc<dyn SourceStore>,
    active: Arc<Config>,
    log_files: LogFiles,
    data_dir: PathBuf,
    deferred: Vec<honk_config::subscription::Subscription>,
    accepted: Accepted,
}

impl CandidateCheck {
    /// Full validation of a candidate that puts `content` at `target`, refusing anything
    /// the write or the following reload must not admit.
    fn validate(
        &self,
        loaded: LoadedConfig,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        target: &Path,
        content: &str,
        fallback: Option<&str>,
        ids: &HashMap<PathBuf, String>,
    ) -> Result<offline::ValidatedConfig, ApiError> {
        let active = &self.active;
        let parsed_sources = loaded.sources.clone();
        let validated = offline::validate_for_coordinator(
            loaded,
            self.store.dependency_root(),
            active,
            &self.data_dir,
            limits(),
            diagnostics,
            &self.deferred,
            None,
            &[],
        )
        .map_err(|error| config_error(error, diagnostics, &parsed_sources, fallback, Some(ids)))?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                Some(ids),
            ));
        }
        if validated.config.experimental.native_api != active.experimental.native_api
            || validated.config.experimental.clash_api.secret
                != active.experimental.clash_api.secret
            || (self.store.kind() == StoreKind::Database
                && validated.config.global.data_dir != active.global.data_dir)
        {
            return Err(denied());
        }
        let old_credentials: Vec<_> = self
            .accepted
            .update
            .sources
            .iter()
            .filter(|source| source.contains_api_secret)
            .map(|source| (&source.path, &source.content))
            .collect();
        let new_credentials: Vec<_> = validated
            .sources
            .iter()
            .filter(|source| source.contains_api_secret)
            .map(|source| (&source.path, &source.content))
            .collect();
        if old_credentials != new_credentials
            || validated
                .sources
                .iter()
                .any(|source| source.path == target && source.contains_api_secret)
            || [
                &active.experimental.native_api.secret,
                &active.experimental.clash_api.secret,
            ]
            .iter()
            .any(|secret| !secret.is_empty() && content.contains(secret.as_str()))
        {
            return Err(denied());
        }
        // The reload would reject these, and a rejected reload leaves the written file
        // ahead of the accepted hash; refuse before writing.
        let written = validated
            .sources
            .iter()
            .find(|source| source.path == target)
            .unwrap_or(&validated.sources[0]);
        let restart = restart_diagnostics(
            active,
            &validated.config,
            &self.log_files,
            &written.source,
            Severity::Error,
        );
        if !restart.is_empty() {
            diagnostics.extend(restart);
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                Some(ids),
            ));
        }
        Ok(validated)
    }

    /// Fails with `Conflict` unless the store still yields the validated candidate.
    fn recheck(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        validated: &offline::ValidatedConfig,
    ) -> Result<(), WriteError> {
        let mut diagnostics = Vec::new();
        let reloaded = self
            .store
            .load(overlay, &mut diagnostics)
            .map_err(|_| WriteError::Conflict)?;
        if !same_source_documents(&validated.sources, &reloaded.sources) {
            return Err(WriteError::Conflict);
        }
        let dependencies = validated
            .recapture_dependencies(&self.active, &self.data_dir, limits(), &self.deferred)
            .map_err(|_| WriteError::Conflict)?;
        if !same_dependencies(&validated.dependencies, &dependencies) {
            return Err(WriteError::Conflict);
        }
        Ok(())
    }
}

fn prepared(
    validated: offline::ValidatedConfig,
    diagnostics: Vec<DetailedDiagnostic>,
    committed: Committed,
) -> Prepared {
    let update = SourceUpdate {
        sources: validated.sources,
        dependencies: validated.dependencies,
        geo_sources: None,
    };
    (validated.config, update, diagnostics, committed)
}

type Prepared = (Config, SourceUpdate, Vec<DetailedDiagnostic>, Committed);

fn store_write_error(kind: StoreKind, error: WriteError) -> ApiError {
    match (kind, error) {
        (StoreKind::Database, WriteError::Unavailable) => {
            unavailable().with_details(json!({"stage":"store"}))
        }
        (_, error) => write_error(error),
    }
}

fn write_error(error: WriteError) -> ApiError {
    match error {
        WriteError::Conflict => stale(),
        WriteError::Exists => exists(),
        WriteError::TooLarge => too_large(),
        WriteError::UnsafePath => denied().with_details(json!({"stage":"write"})),
        WriteError::InvalidUtf8 => invalid(),
        WriteError::Unavailable => unavailable().with_details(json!({"stage":"write"})),
        WriteError::ChangedButNotDurable => {
            unavailable().with_details(json!({"stage":"durability","written":true,"durability_confirmed":false,"committed":false})).without_retry_after()
        }
    }
}
