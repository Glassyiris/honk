use super::super::{
    config_write::{SourceFile, WriteError},
    offline,
};
use super::*;
use crate::control::{ControlCommand, ReloadOutcome, ReloadReply};
use crate::subscription::SubscriptionSupervisorHandle;
use honk_config::parser::{LoadedConfig, parse_dae_sources};
use tokio::sync::watch;

pub(crate) struct ConfigCoordinator {
    service: Arc<ConfigService>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct Worker {
    service: Arc<ConfigService>,
    entry: PathBuf,
    active: Arc<tokio::sync::RwLock<Arc<Config>>>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    commands: mpsc::Sender<ControlCommand>,
    subscriptions: SubscriptionSupervisorHandle,
    request_id: u64,
}

impl ConfigService {
    pub(crate) async fn start(
        self: &Arc<Self>,
        entry: PathBuf,
        initial: SourceUpdate,
        active: Arc<tokio::sync::RwLock<Arc<Config>>>,
        diagnostics: crate::config_diagnostics::SharedDiagnostics,
        commands: mpsc::Sender<ControlCommand>,
        subscriptions: SubscriptionSupervisorHandle,
    ) -> ConfigCoordinator {
        {
            let config = active.read().await;
            let generation = diagnostics.read().generation;
            self.accept(&initial, generation);
            self.generation_committed(&super::super::catalog::revision_for(&config), generation);
        }
        let (sender, mut receiver) = mpsc::channel(16);
        *self.sender.lock() = Some(sender);
        let (stop, mut stopping) = watch::channel(false);
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut worker = Worker {
                service,
                entry,
                active,
                diagnostics,
                commands,
                subscriptions,
                request_id: 0,
            };
            loop {
                let work = tokio::select! { biased; _=stopping.changed()=>break, work=receiver.recv()=>match work{Some(work)=>work,None=>break} };
                worker.perform(work).await;
            }
            receiver.close();
            while let Some(work) = receiver.recv().await {
                if let Work::Validate { response, .. } = work {
                    let _ = response.send(Err(unavailable()));
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
        match work {
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
                match self.prepare_replace(&source_id, content, if_match).await {
                    Ok((candidate, sources, diagnostics)) => {
                        self.apply(candidate, sources, diagnostics, Some(&id), false)
                            .await
                    }
                    Err(error) => {
                        self.service.operations.reject(&id, error);
                    }
                }
                drop(reservation);
            }
            Work::Reload { reservation } => {
                let id = reservation.id.clone();
                self.service.operations.accept(&id);
                self.service.operations.running(&id);
                match self.load().await {
                    Ok((candidate, sources, diagnostics)) => {
                        self.apply(candidate, sources, diagnostics, Some(&id), true)
                            .await
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
                    self.apply(candidate, sources, diagnostics, None, true)
                        .await
                }
                Err(_) => tracing::warn!("SIGHUP configuration admission rejected"),
            },
        }
    }

    async fn load(&self) -> Result<(Config, SourceUpdate, Vec<DetailedDiagnostic>), ApiError> {
        let entry = self.entry.clone();
        tokio::task::spawn_blocking(move || {
            let mut diagnostics = Vec::new();
            let loaded = Config::from_dae_file_with_sources(
                &entry,
                &HashMap::new(),
                limits(),
                &mut diagnostics,
            )
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
                SourceUpdate {
                    sources: loaded.sources,
                    dependencies: Vec::new(),
                },
                diagnostics,
            ))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn prepare_replace(
        &self,
        source_id: &str,
        content: String,
        expected: Result<String, ApiError>,
    ) -> Result<(Config, SourceUpdate, Vec<DetailedDiagnostic>), ApiError> {
        let expected = expected?;
        if content.len() > MAX_SOURCE_BYTES {
            return Err(too_large());
        }
        let accepted = self.service.accepted.read().clone().ok_or_else(not_found)?;
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
        let entry = self.entry.clone();
        let active = self.active.read().await.clone();
        let source_id = source_id.to_owned();
        #[cfg(test)]
        let before_replace = self.service.before_replace.lock().take();
        tokio::task::spawn_blocking(move || {
            let file = SourceFile::open(&target, MAX_SOURCE_BYTES).map_err(write_error)?;
            if file.sha256() != expected {
                return Err(stale());
            }
            let mut overlay = HashMap::new();
            overlay.insert(target.clone(), Arc::<str>::from(content.as_str()));
            let mut diagnostics = Vec::new();
            let loaded =
                Config::from_dae_file_with_sources(&entry, &overlay, limits(), &mut diagnostics)
                    .map_err(|error| {
                        config_error(
                            error,
                            &diagnostics,
                            &accepted.update.sources,
                            Some(&source_id),
                            Some(&accepted.ids),
                        )
                    })?;
            let parsed_sources = loaded.sources.clone();
            let validated = offline::validate(loaded, &active, limits(), &mut diagnostics)
                .map_err(|error| {
                    config_error(
                        error,
                        &diagnostics,
                        &parsed_sources,
                        Some(&source_id),
                        Some(&accepted.ids),
                    )
                })?;
            if diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error)
            {
                return Err(diagnostics_error(
                    &diagnostics,
                    &validated.sources,
                    Some(&source_id),
                    Some(&accepted.ids),
                ));
            }
            if validated.config.experimental.native_api != active.experimental.native_api
                || validated.config.experimental.clash_api.secret
                    != active.experimental.clash_api.secret
            {
                return Err(denied());
            }
            let old_credentials: Vec<_> = accepted
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
            let update = SourceUpdate {
                sources: validated.sources,
                dependencies: validated.dependencies,
            };
            file.replace(&expected, &content, || {
                #[cfg(test)]
                if let Some(hook) = before_replace {
                    hook();
                }
                let mut recheck_diagnostics = Vec::new();
                let reloaded = Config::from_dae_file_with_sources(
                    &entry,
                    &overlay,
                    limits(),
                    &mut recheck_diagnostics,
                )
                .map_err(|_| WriteError::Conflict)?;
                let checked =
                    offline::validate(reloaded, &active, limits(), &mut recheck_diagnostics)
                        .map_err(|_| WriteError::Conflict)?;
                let checked = SourceUpdate {
                    sources: checked.sources,
                    dependencies: checked.dependencies,
                };
                if !same_sources(&update, &checked) {
                    return Err(WriteError::Conflict);
                }
                Ok(())
            })
            .map_err(write_error)?;
            Ok((validated.config, update, diagnostics))
        })
        .await
        .map_err(|_| unavailable())?
    }

    async fn apply(
        &mut self,
        candidate: Config,
        sources: SourceUpdate,
        diagnostics: Vec<DetailedDiagnostic>,
        operation: Option<&str>,
        already_accepted: bool,
    ) {
        let Some(next) = self.request_id.checked_add(1) else {
            if let Some(id) = operation {
                if already_accepted {
                    self.failed(
                        id,
                        "request_exhausted",
                        "Reload request sequence exhausted",
                        None,
                    );
                } else {
                    self.service.operations.reject(id, unavailable());
                }
            }
            return;
        };
        self.request_id = next;
        let (result, reply) = oneshot::channel::<ReloadReply>();
        if self
            .commands
            .send(ControlCommand::ReloadConfig {
                request_id: next,
                config: Box::new(candidate),
                diagnostics,
                result,
                sources: Some(Arc::new(sources)),
            })
            .await
            .is_err()
        {
            if let Some(id) = operation {
                if already_accepted {
                    self.failed(
                        id,
                        "engine_unavailable",
                        "Reload engine is unavailable",
                        None,
                    );
                } else {
                    self.service
                        .operations
                        .reject(id, unavailable().with_details(json!({"written":true})));
                }
            }
            return;
        }
        if let Some(id) = operation
            && !already_accepted
        {
            self.service.operations.accept(id);
            self.service.operations.running(id);
        }
        let reply = match reply.await {
            Ok(reply) => reply,
            Err(_) => {
                if let Some(id) = operation {
                    self.failed(
                        id,
                        "engine_unavailable",
                        "Reload engine stopped before completion",
                        None,
                    );
                }
                return;
            }
        };
        if reply.outcome.accepted()
            && self
                .subscriptions
                .reconcile(reply.authorized)
                .await
                .is_err()
        {
            let generation = reply
                .outcome
                .generation()
                .map(|generation| format!("{}:{generation}", self.service.instance_id));
            if let Some(id) = operation {
                self.failed(
                    id,
                    "supervisor_reconciliation_failed",
                    "Configuration committed but worker reconciliation failed",
                    Some(json!({"active_generation_id":generation,"committed":true})),
                );
            }
            let _ = self.commands.send(ControlCommand::Shutdown).await;
            return;
        }
        match reply.outcome {
            ReloadOutcome::Rejected => {
                if let Some(id) = operation {
                    self.failed(
                        id,
                        "reload_rejected",
                        "Configuration reload was rejected",
                        None,
                    );
                } else {
                    tracing::warn!("SIGHUP reload rejected");
                }
            }
            ReloadOutcome::CommittedDegraded { generation } => {
                if let Some(id) = operation {
                    self.failed(id,"reload_degraded","Configuration committed with degraded datapath",Some(json!({"active_generation_id":format!("{}:{generation}",self.service.instance_id),"committed":true})));
                } else {
                    tracing::warn!(generation, "SIGHUP reload committed with degraded datapath");
                }
            }
            ReloadOutcome::Noop { generation } | ReloadOutcome::Committed { generation } => {
                if let Some(id) = operation {
                    self.service.operations.succeed(
                        id,
                        Some(format!("{}:{generation}", self.service.instance_id)),
                        None,
                    );
                    *self.service.last_reload.write() = Some(
                        json!({"operation_id":id,"status":"succeeded","finished_at":timestamp(SystemTime::now()),"error":null}),
                    );
                } else {
                    tracing::info!(generation, "SIGHUP reload applied");
                }
            }
        }
    }

    fn failed(&self, id: &str, code: &'static str, message: &'static str, details: Option<Value>) {
        self.service
            .operations
            .fail(id, code, message, details.clone());
        *self.service.last_reload.write() = Some(
            json!({"operation_id":id,"status":"failed","finished_at":timestamp(SystemTime::now()),"error":{"code":code,"message":message,"details":details}}),
        );
    }

    async fn validate(&self, request: ValidationRequest) -> Result<Value, ApiError> {
        let active = self.active.read().await.clone();
        let generation = self.diagnostics.read().generation;
        let instance = self.service.instance_id.clone();
        let entry = self.entry.clone();
        let accepted = self.service.accepted.read().clone();
        tokio::task::spawn_blocking(move||{
            let root=entry.parent().ok_or_else(invalid)?;
            let mut documents=Vec::new();let mut ids=HashMap::new();
            for (index,source) in request.sources.iter().enumerate(){
                let resolved=if request.mode=="syntax" {PathBuf::from(source.path.clone().unwrap_or_else(||format!("source-{}.dae",index+1)))}
                    else if index==0 {
                        if let Some(path)=&source.path {let supplied=resolve_source_path(root,path)?;if supplied!=entry{return Err(denied());}}
                        entry.clone()
                    }else if let Some(path)=&source.path { resolve_source_path(root,path)? }
                    else if let Some(path)=source.id.as_ref().and_then(|id|accepted.as_ref()?.ids.iter().find(|(_,value)|*value==id).map(|(path,_)|path.clone())) { path }
                    else { root.join(format!("source-{}.dae",index+1)) };
                if ids.insert(resolved.clone(),source.id.clone().unwrap_or_else(||format!("source-{}",index+1))).is_some(){return Err(invalid());}
                documents.push((resolved,Arc::<str>::from(source.content.as_str())));
            }
            let mut diagnostics=Vec::new();
            let syntax=parse_dae_sources(&documents,limits(),&mut diagnostics);
            let initial_sources=syntax.as_ref().map(|loaded|loaded.sources.clone()).unwrap_or_default();
            let result=if request.mode=="syntax" {syntax}
                else {syntax.and_then(|_|{
                    let overlay=documents.iter().cloned().collect();
                    let loaded=Config::from_dae_file_with_sources(&entry,&overlay,limits(),&mut diagnostics)?;
                    let validated=offline::validate(loaded,&active,limits(),&mut diagnostics)?;
                    let loaded_paths:HashSet<_>=validated.sources.iter().map(|source|&source.path).collect();
                    let unused:Vec<_>=documents.iter().filter(|(path,_)|!loaded_paths.contains(path)).collect();
                    let bytes=validated.sources.iter().map(|source|source.content.len()).chain(validated.dependencies.iter().map(|source|source.bytes)).chain(unused.iter().map(|(_,text)|text.len())).sum::<usize>();
                    if bytes>MAX_SOURCE_BYTES||validated.sources.len()+validated.dependencies.len()+unused.len()>MAX_SOURCES{
                        return Err(honk_config::error::DetailedConfigError::new(honk_config::error::ErrorCategory::Validation,"config-byte-limit",honk_config::diagnostic::DiagnosticSources::new(None).root(),honk_config::diagnostic::SettingPath::new("config"),"configuration dependency budget exceeded"));
                    }
                    Ok(LoadedConfig {config:validated.config,sources:validated.sources})
                })};
            if let Err(error)=&result {
                if is_limit(error){return Err(too_large());}
                if !diagnostics.iter().any(|diagnostic|diagnostic==error.diagnostic.as_ref()){diagnostics.push(error.diagnostic.as_ref().clone());}
            }
            let sources=result.as_ref().map(|loaded|loaded.sources.as_slice()).unwrap_or(&initial_sources);
            let main_id=ids.get(&documents[0].0).map(String::as_str);
            let projected=diagnostics.iter().map(|diagnostic|project_diagnostic(diagnostic,sources,&ids,main_id)).collect::<Vec<_>>();
            Ok(json!({"valid":result.is_ok()&&!diagnostics.iter().any(|row|row.severity==Severity::Error),"diagnostics":projected,
                "generation_id":format!("{instance}:{generation}"),"validated_at":timestamp(SystemTime::now())}))
        }).await.map_err(|_|unavailable())?
    }
}

fn is_limit(error: &honk_config::error::DetailedConfigError) -> bool {
    matches!(
        error.diagnostic.code,
        "config-source-limit"
            | "config-byte-limit"
            | "dependency-byte-limit"
            | "dependency-source-limit"
    )
}
fn diagnostics_error(
    diagnostics: &[DetailedDiagnostic],
    sources: &[SourceSnapshot],
    fallback: Option<&str>,
    accepted_ids: Option<&HashMap<PathBuf, String>>,
) -> ApiError {
    let generated = sources
        .iter()
        .enumerate()
        .map(|(index, source)| (source.path.clone(), format!("source-{}", index + 1)))
        .collect();
    let ids = accepted_ids.unwrap_or(&generated);
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY,ErrorCode::UnsupportedValue,"Configuration validation failed",None)
        .with_details(json!({"diagnostics":diagnostics.iter().map(|diagnostic|project_diagnostic(diagnostic,sources,ids,fallback)).collect::<Vec<_>>()}))
}
fn config_error(
    error: honk_config::error::DetailedConfigError,
    diagnostics: &[DetailedDiagnostic],
    sources: &[SourceSnapshot],
    fallback: Option<&str>,
    ids: Option<&HashMap<PathBuf, String>>,
) -> ApiError {
    if is_limit(&error) {
        return too_large();
    }
    let mut all = diagnostics.to_vec();
    if !all.iter().any(|row| row == error.diagnostic.as_ref()) {
        all.push(*error.diagnostic);
    }
    diagnostics_error(&all, sources, fallback, ids)
}
fn write_error(error: WriteError) -> ApiError {
    match error {
        WriteError::Conflict => stale(),
        WriteError::TooLarge => too_large(),
        WriteError::UnsafePath => denied(),
        WriteError::InvalidUtf8 => invalid(),
        WriteError::Unavailable => unavailable(),
        WriteError::ChangedButNotDurable => {
            unavailable().with_details(json!({"written":true,"durability_confirmed":false}))
        }
    }
}
