use super::*;
use crate::configuration::{DependencyReader, DependencySnapshot, digest};
use crate::native_api::config_write::{SourceFile, StagedFile};
use crate::native_api::geodata::{self, GeoUpdatePlan};
use crate::native_api::operations::OperationResult;
use crate::routing::{GeoAssetSnapshot, GeoRequirements, GeoSourceSet};

#[derive(Clone, Copy, serde::Serialize)]
struct AssetWrite {
    kind: &'static str,
    written: Option<bool>,
    durability_confirmed: Option<bool>,
}

struct DownloadedAsset {
    original: GeoAssetSnapshot,
    bytes: Arc<[u8]>,
}

struct StagedAsset {
    snapshot: GeoAssetSnapshot,
    bytes: Arc<[u8]>,
    staged: StagedFile,
}

struct InstalledAsset {
    snapshot: GeoAssetSnapshot,
    installed: SourceFile,
    receipt: AssetWrite,
}

struct PreparedGeodata {
    activation: ActivationRequest,
    assets: Vec<InstalledAsset>,
}

fn failure(stage: &'static str, writes: impl IntoIterator<Item = impl serde::Serialize>) -> Value {
    json!({"stage":stage,"assets":writes.into_iter().collect::<Vec<_>>(),"committed":false})
}

fn unwritten(assets: &[GeoAssetSnapshot]) -> Vec<AssetWrite> {
    assets
        .iter()
        .map(|asset| AssetWrite {
            kind: asset.kind,
            written: Some(false),
            durability_confirmed: Some(false),
        })
        .collect()
}

impl Worker {
    pub(super) async fn perform_geodata(&mut self, plan: GeoUpdatePlan, reservation: Reservation) {
        let id = &reservation.id;
        self.service.operations.accept(id);
        self.service.operations.running(id);
        match self.update_geodata(&plan).await {
            Ok(data) => self
                .service
                .operations
                .succeed(id, OperationResult::Geodata(data)),
            Err(details) => self.service.operations.fail(
                id,
                "geodata_update_failed",
                "Geodata update did not complete successfully",
                Some(details),
            ),
        };
    }

    async fn update_geodata(&mut self, plan: &GeoUpdatePlan) -> Result<geodata::GeoData, Value> {
        let writes = unwritten(&plan.assets);
        let active = self.active.read().await.clone();
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(|| failure("source_authority_lost", &writes))?;
        if accepted.revision != plan.revision
            || !self.service.writable()
            || geodata::capture_assets(&plan.traffic_router, &self.active, &plan.dns)
                .await
                .map_err(|_| failure("loaded_assets_unavailable", &writes))?
                != plan.assets
        {
            return Err(failure("revision_conflict", &writes));
        }
        let deadline = tokio::time::Instant::now() + geodata::NETWORK_TIMEOUT;
        let mut downloads = Vec::with_capacity(plan.assets.len());
        for asset in &plan.assets {
            let bytes = geodata::download(
                geodata::configured_url(&active.experimental.native_api, asset.kind),
                &active.global.bootstrap_resolver,
                deadline,
                offline::MAX_ASSET_BYTES,
            )
            .await
            .map_err(|stage| failure(stage, &writes))?;
            downloads.push(DownloadedAsset {
                original: asset.clone(),
                bytes,
            });
        }
        let service = Arc::clone(&self.service);
        let store = self
            .store
            .clone()
            .ok_or_else(|| failure("source_authority_lost", &writes))?;
        let revision = plan.revision.clone();
        let data_dir = self.data_dir.clone();
        let deferred = self
            .subscriptions
            .deferred_subscriptions()
            .await
            .map_err(|_| failure("subscription_owner_unavailable", &writes))?;
        let prepared = tokio::task::spawn_blocking(move || {
            prepare_and_replace(
                &service, &*store, &active, &accepted, downloads, &revision, &data_dir, &deferred,
            )
        })
        .await
        .map_err(|_| {
            failure(
                "write_completion_unconfirmed",
                writes.into_iter().map(|write| AssetWrite {
                    kind: write.kind,
                    written: None,
                    durability_confirmed: None,
                }),
            )
        })??;
        let PreparedGeodata {
            activation,
            assets: prepared,
        } = prepared;
        self.activation
            .activate(activation)
            .await
            .map_err(|failure| {
                let mut details = failure
                    .management_error()
                    .into_details()
                    .unwrap_or_else(|| json!({"committed":null}));
                details["assets"] = json!(
                    prepared
                        .iter()
                        .map(|asset| &asset.receipt)
                        .collect::<Vec<_>>()
                );
                details
            })?;
        let assets = geodata::capture_assets(&plan.traffic_router, &self.active, &plan.dns)
            .await
            .map_err(|_| {
                let mut details = failure(
                    "published_assets_unavailable",
                    prepared.iter().map(|asset| &asset.receipt),
                );
                details["committed"] = json!(true);
                details
            })?;
        if assets.len() != prepared.len()
            || assets.iter().zip(&prepared).any(|(actual, prepared)| {
                let expected = &prepared.snapshot;
                actual.kind != expected.kind
                    || actual.path != expected.path
                    || actual.sha256 != expected.sha256
                    || actual.size_bytes != expected.size_bytes
            })
        {
            let mut details = failure(
                "published_assets_mismatch",
                prepared.iter().map(|asset| &asset.receipt),
            );
            details["committed"] = json!(true);
            return Err(details);
        }
        let active = self.active.read().await;
        Ok(geodata::project(
            assets,
            &self.service.settings,
            &active,
            &self.service,
        ))
    }
}

/// Whether the dependencies the accepted configuration was admitted with still
/// describe the disk, apart from subscription caches: the subscription owner
/// rewrites those on every refresh without a new source acceptance, so a
/// refreshed body is not a conflict with the sources the update is based on.
/// The caches still fence the write itself, through the recapture that runs
/// under the staged replacement.
fn same_settled_dependencies(
    accepted: &[DependencySnapshot],
    captured: &[DependencySnapshot],
) -> bool {
    let settled = |dependencies: &[DependencySnapshot]| {
        dependencies
            .iter()
            .filter(|dependency| {
                !dependency
                    .readers
                    .iter()
                    .any(|reader| matches!(reader, DependencyReader::Subscription(_)))
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    same_dependencies(&settled(accepted), &settled(captured))
}

#[allow(clippy::too_many_arguments)]
fn prepare_and_replace(
    service: &ConfigService,
    store: &dyn SourceStore,
    active: &Config,
    accepted: &Accepted,
    downloads: Vec<DownloadedAsset>,
    revision: &str,
    data_dir: &Path,
    deferred: &[honk_config::subscription::Subscription],
) -> Result<PreparedGeodata, Value> {
    let writes: Vec<_> = downloads
        .iter()
        .map(|asset| AssetWrite {
            kind: asset.original.kind,
            written: Some(false),
            durability_confirmed: Some(false),
        })
        .collect();
    let mut diagnostics = Vec::new();
    let loaded = store
        .load(&HashMap::new(), &mut diagnostics)
        .map_err(|_| failure("source_conflict", &writes))?;
    if !same_source_documents(&accepted.update.sources, &loaded.sources)
        || service.sources.revision().as_deref() != Some(revision)
    {
        return Err(failure("source_conflict", &writes));
    }
    let requirements = GeoRequirements::for_traffic(&loaded.config.routing.rules).union(
        &crate::dns::routing::DnsRouter::geo_requirements(&loaded.config.dns),
    );
    let captured = offline::capture_for_coordinator(
        loaded,
        store.dependency_root(),
        active,
        data_dir,
        limits(),
        &mut diagnostics,
        deferred,
        None,
    )
    .map_err(|_| failure("dependency_validation_failed", &writes))?;
    if !accepted.update.dependencies.is_empty()
        && !same_settled_dependencies(&accepted.update.dependencies, &captured.dependencies)
    {
        return Err(failure("dependency_conflict", &writes));
    }
    let mut guards = Vec::new();
    for source in &captured.sources {
        let file = SourceFile::open(&source.path, MAX_SOURCE_BYTES)
            .map_err(|_| failure("source_conflict", &writes))?;
        if file.sha256() != digest(source.content.as_bytes()) {
            return Err(failure("source_conflict", &writes));
        }
        guards.push(file);
    }
    for dependency in captured
        .dependencies
        .iter()
        .filter(|dependency| !dependency.asset)
    {
        let file = SourceFile::open_binary(&dependency.path, MAX_SOURCE_BYTES)
            .map_err(|_| failure("dependency_conflict", &writes))?;
        if file.sha256() != dependency.sha256 {
            return Err(failure("dependency_conflict", &writes));
        }
        guards.push(file);
    }
    let mut assets: std::collections::VecDeque<StagedAsset> =
        std::collections::VecDeque::with_capacity(downloads.len());
    for download in downloads {
        let original = download.original;
        let path = original
            .path
            .as_ref()
            .ok_or_else(|| failure("asset_path_unavailable", &writes))?;
        let file = SourceFile::open_binary(path, offline::MAX_ASSET_BYTES)
            .map_err(|_| failure("asset_path_unavailable", &writes))?;
        let dependency_path =
            std::fs::canonicalize(path).map_err(|_| failure("asset_path_unavailable", &writes))?;
        if file.sha256() != original.sha256
            || !captured.dependencies.iter().any(|dependency| {
                dependency.asset
                    && dependency.path == dependency_path
                    && dependency.sha256 == original.sha256
                    && dependency
                        .readers
                        .contains(&crate::configuration::DependencyReader::Geo(original.kind))
            })
        {
            return Err(failure("asset_conflict", &writes));
        }
        if guards.iter().any(|other| file.same_target(other))
            || assets.iter().any(|asset| asset.staged.same_target(&file))
        {
            return Err(failure("asset_alias", &writes));
        }
        let staged = file
            .stage(&original.sha256, &download.bytes)
            .map_err(|_| failure("staging_failed", &writes))?;
        let snapshot = GeoAssetSnapshot {
            kind: original.kind,
            path: original.path,
            sha256: staged.sha256().to_owned(),
            size_bytes: download.bytes.len() as u64,
            modified_at: staged.modified_at(),
        };
        assets.push_back(StagedAsset {
            snapshot,
            bytes: download.bytes,
            staged,
        });
    }
    let geo = GeoSourceSet::from_assets(
        &requirements,
        assets
            .iter()
            .map(|asset| (asset.snapshot.clone(), Arc::clone(&asset.bytes)))
            .collect(),
    )
    .map_err(|_| failure("asset_validation_failed", &writes))?;
    let validated = captured
        .with_geo(geo)
        .and_then(offline::CapturedConfig::validate)
        .map_err(|_| failure("candidate_validation_failed", &writes))?;
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        return Err(failure("candidate_validation_failed", &writes));
    }
    let mut installed: Vec<InstalledAsset> = Vec::with_capacity(assets.len());
    while let Some(StagedAsset {
        snapshot, staged, ..
    }) = assets.pop_front()
    {
        let mut receipt = AssetWrite {
            kind: snapshot.kind,
            written: Some(false),
            durability_confirmed: Some(false),
        };
        let report = |stage, receipt| {
            failure(
                stage,
                installed
                    .iter()
                    .map(|asset| asset.receipt)
                    .chain(std::iter::once(receipt))
                    .chain(assets.iter().map(|asset| AssetWrite {
                        kind: asset.snapshot.kind,
                        written: Some(false),
                        durability_confirmed: Some(false),
                    })),
            )
        };
        let result = staged.replace(|| {
            #[cfg(test)]
            {
                let hook = service.before_replace.lock().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            if service.sources.revision().as_deref() != Some(revision) {
                return Err(WriteError::Conflict);
            }
            for guard in &guards {
                guard.recheck()?;
            }
            for completed in &installed {
                completed.installed.recheck()?;
            }
            for pending in &assets {
                pending.staged.recheck()?;
            }
            let mut notices = Vec::new();
            let loaded = store
                .load(&HashMap::new(), &mut notices)
                .map_err(|_| WriteError::Conflict)?;
            if notices
                .iter()
                .any(|notice| notice.severity == Severity::Error)
                || !same_source_documents(&validated.sources, &loaded.sources)
            {
                return Err(WriteError::Conflict);
            }
            let dependencies = validated
                .recapture_dependencies(active, data_dir, limits(), deferred)
                .map_err(|_| WriteError::Conflict)?;
            if !same_dependencies(&validated.dependencies, &dependencies) {
                return Err(WriteError::Conflict);
            }
            Ok(())
        });
        let completed = match result {
            Ok(completed) => completed,
            Err(WriteError::ChangedButNotDurable) => {
                receipt.written = Some(true);
                return Err(report("directory_sync_failed", receipt));
            }
            Err(_) => return Err(report("replacement_failed", receipt)),
        };
        receipt.written = Some(true);
        receipt.durability_confirmed = Some(completed.durability_confirmed);
        if !completed.durability_confirmed {
            return Err(report("directory_sync_failed", receipt));
        }
        completed
            .file
            .recheck()
            .map_err(|_| report("written_asset_conflict", receipt))?;
        installed.push(InstalledAsset {
            snapshot,
            installed: completed.file,
            receipt,
        });
    }
    for guard in guards
        .iter()
        .chain(installed.iter().map(|asset| &asset.installed))
    {
        guard.recheck().map_err(|_| {
            failure(
                "postwrite_conflict",
                installed.iter().map(|asset| &asset.receipt),
            )
        })?;
    }
    Ok(PreparedGeodata {
        activation: ActivationRequest {
            candidate: validated.config,
            sources: Some(SourceUpdate {
                sources: validated.sources,
                dependencies: validated.dependencies,
                geo_sources: validated.geo_sources,
            }),
            diagnostics,
            expected_revision: Some(revision.to_owned()),
            deferred_provider: None,
        },
        assets: installed,
    })
}

#[cfg(test)]
mod settled_tests {
    use super::*;
    use std::path::PathBuf;

    fn dependency(path: &str, sha256: &str, readers: Vec<DependencyReader>) -> DependencySnapshot {
        DependencySnapshot {
            path: PathBuf::from(path),
            sha256: sha256.to_owned(),
            bytes: 1,
            asset: readers
                .iter()
                .any(|reader| matches!(reader, DependencyReader::Geo(_))),
            readers,
        }
    }

    #[test]
    fn a_refreshed_subscription_cache_is_not_a_conflict_but_a_changed_asset_is() {
        let accepted = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "11",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        let refreshed = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "22",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        assert!(same_settled_dependencies(&accepted, &refreshed));
        let edited = vec![
            dependency(
                "/state/geosite.dat",
                "bb",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "11",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        assert!(!same_settled_dependencies(&accepted, &edited));
        let hosts_changed = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/etc/hosts",
                "cc",
                vec![DependencyReader::Hosts(0, "/etc/hosts".into())],
            ),
        ];
        assert!(!same_settled_dependencies(&accepted, &hosts_changed));
    }
}
