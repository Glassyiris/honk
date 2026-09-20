use super::*;
use honk_config::parser::parse_dae_sources;

impl Worker {
    pub(super) async fn validate(&self, request: ValidationRequest) -> Result<Value, ApiError> {
        let active = self.active.read().await.clone();
        let generation = self.diagnostics.read().generation;
        let instance = self.service.instance_id.clone();
        let entry = self.entry.clone().ok_or_else(unsupported)?;
        let accepted = self.service.sources.accepted.read().clone();
        let data_dir = self.data_dir.clone();
        let deferred = if request.mode == "syntax" {
            Vec::new()
        } else {
            self.subscriptions
                .deferred_subscriptions()
                .await
                .map_err(|_| unavailable())?
        };
        tokio::task::spawn_blocking(move||{
            let root=entry.parent().ok_or_else(invalid)?;
            let mut documents=Vec::new();let mut ids=HashMap::new();
            for (index,source) in request.sources.iter().enumerate(){
                let path=source.path.as_deref();
                let resolved=if request.mode=="syntax" {PathBuf::from(path.map(str::to_owned).unwrap_or_else(||format!("source-{}.dae",index+1)))}
                    else if index==0 {
                        if let Some(path)=path {let supplied=resolve_source_path(root,path)?;if supplied!=entry{return Err(denied());}}
                        entry.clone()
                    }else if let Some(path)=path { resolve_source_path(root,path)? }
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
                    let validated=offline::validate_for_coordinator(loaded,&active,&data_dir,limits(),&mut diagnostics,&deferred,None)?;
                    let loaded_paths:HashSet<_>=validated.sources.iter().map(|source|&source.path).collect();
                    let unused:Vec<_>=documents.iter().filter(|(path,_)|!loaded_paths.contains(path)).collect();
                    let budgeted=validated.dependencies.iter().filter(|dependency|!dependency.asset);
                    let bytes=validated.sources.iter().map(|source|source.content.len()).chain(budgeted.clone().map(|source|source.bytes)).chain(unused.iter().map(|(_,text)|text.len())).sum::<usize>();
                    if bytes>MAX_SOURCE_BYTES||validated.sources.len()+budgeted.count()+unused.len()>MAX_SOURCES{
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
pub(super) fn diagnostics_error(
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
pub(super) fn config_error(
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
