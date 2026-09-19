use super::*;

#[derive(Default)]
pub(super) struct DelayWriter {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl DelayWriter {
    pub(super) async fn stop_and_join(&mut self) -> anyhow::Result<()> {
        super::lifecycle::abort_and_join(&mut self.task).await
    }
}

impl Drop for DelayWriter {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl ControlPlane {
    /// Open the persistent cache database (sing-box `cache_file`), wire
    /// selector-choice persistence into the group manager, and restore
    /// persisted choices. An existing cache relative to the original config
    /// directory is retained during the data-directory cutover. No-op when
    /// `experimental.cache_file` is disabled or the database cannot be opened.
    /// Called once from `run()`.
    pub async fn init_cache_db(&mut self, legacy_config_dir: Option<&Path>) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(db) = crate::cachedb::CacheDb::open_with_config_dir(&cache_cfg, legacy_config_dir)
        else {
            return;
        };
        let db = Arc::new(db);

        // Restore persisted selector choices before wiring the persist
        // callback so restoration does not rewrite the same values.
        {
            let groups = self.config.read().await.groups.clone();
            let group_manager = self.group_manager.read().clone();
            for group in groups
                .iter()
                .filter(|group| group.policy == GroupPolicy::Selector)
            {
                for network in [
                    honk_outbound::group::SelectionNetwork::Tcp,
                    honk_outbound::group::SelectionNetwork::Udp,
                ] {
                    let member = match db.load_network_selector(&group.name, network) {
                        Some(Ok(member)) => Some(member),
                        Some(Err(_)) => None,
                        None => db.load_selector_choice(&group.name).and_then(|name| {
                            group_manager
                                .selector_member_by_name(&group.name, &name)
                                .ok()
                        }),
                    };
                    if let Some(member) = member
                        && let Ok(update) = group_manager.publish_selector_choice(
                            &group.name,
                            &member,
                            network.into(),
                        )
                    {
                        update.run_callbacks_without_interrupt();
                    }
                }
            }
        }

        let db_cb = db.clone();
        self.group_manager
            .read()
            .set_persist_callback(Some(Arc::new(move |group, network, member| {
                db_cb.save_network_selector(group, network, member);
            })));

        // Delay-history persistence (sing-box URLTest history storage
        // parity): restore the last real delay sample per node so URLTest
        // groups don't start cold after a restart, then mirror fresh
        // samples back every minute. Liveness is NOT restored — probes
        // re-decide that; stale entries (>24h) are dropped on load.
        {
            const DELAY_SAMPLE_MAX_AGE_SECS: u64 = 24 * 3600;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let samples = db.load_delay_samples(now_unix, DELAY_SAMPLE_MAX_AGE_SECS);
            // cache.db keys delay samples by node name (format unchanged);
            // resolve them onto this generation's NodeIds — samples for
            // nodes no longer configured are dropped.
            let id_by_name: std::collections::HashMap<String, uuid::Uuid> = {
                let config = self.config.read().await;
                config
                    .nodes
                    .iter()
                    .map(|n| (n.name.clone(), n.id))
                    .collect()
            };
            let mut restored = 0usize;
            for (node, delay_ms, measured_at) in samples {
                let Some(node_id) = id_by_name.get(node.as_str()).copied() else {
                    continue;
                };
                self.alive_set.restore_latency(
                    node_id,
                    std::time::Duration::from_millis(delay_ms),
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(measured_at),
                );
                restored += 1;
            }
            if restored > 0 {
                info!("cache.db: restored {} persisted delay sample(s)", restored);
            }
            let db_delay = db.clone();
            let alive_for_delay = self.alive_set.clone();
            let config_for_delay = self.config.clone();
            let delay_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // first snapshot after one period
                loop {
                    let names: std::collections::HashMap<uuid::Uuid, String> = config_for_delay
                        .read()
                        .await
                        .nodes
                        .iter()
                        .map(|n| (n.id, n.name.clone()))
                        .collect();
                    for (node_id, latency, at) in alive_for_delay.latency_snapshot() {
                        let Some(name) = names.get(&node_id) else {
                            continue;
                        };
                        let measured_at = at
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        db_delay.save_delay_sample(name, latency.as_millis() as u64, measured_at);
                    }
                    interval.tick().await;
                }
            });
            self.delay_writer.task = Some(delay_task);
        }

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into cache.db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.store_dns {
            let dns_cache = self.dns_controller.cache().await;
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            let policy = self.dns_controller.forwarder().policy_id();
            match persister.restore_cache(&dns_cache, policy).await {
                Ok(restored) if restored > 0 => {
                    info!("cache.db: restored {} persisted DNS answer(s)", restored);
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "cache.db DNS restore failed"),
            }
            dns_cache.lock().await.set_persister(Some(persister));
        }

        self.cache_db = Some(db);
    }

    /// Shared handle to the persistent cache database (clash API, etc.).
    pub fn cache_db(&self) -> Option<Arc<crate::cachedb::CacheDb>> {
        self.cache_db.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::support::{canonical_socks5, control_plane};
    use honk_outbound::alive::{IpVersion, ProbeDomain};

    #[tokio::test(start_paused = true)]
    async fn startup_failure_and_drop_stop_delay_persistence() -> anyhow::Result<()> {
        for fail_startup in [false, true] {
            let directory = tempfile::tempdir()?;
            let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
            let node = canonical_socks5("cache-peer", "127.0.0.1", 9, None);
            let node_id = node.id;
            let mut config = Config::default();
            config.ensure_builtin_nodes();
            config.nodes.push(node);
            config.dns.bind = format!("tcp://{}", occupied.local_addr()?);
            config.experimental.cache_file.enabled = true;
            config.experimental.cache_file.path = directory
                .path()
                .join("cache.db")
                .to_string_lossy()
                .into_owned();
            let mut plane = control_plane(config);
            plane.init_cache_db(None).await;
            let db = plane.cache_db().unwrap();
            let alive = plane.alive_set();
            let record = |delay| {
                alive.record_probe_latency(
                    node_id,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                    Duration::from_millis(delay),
                );
            };
            let persisted = || {
                db.load_delay_samples(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    24 * 3600,
                )
                .into_iter()
                .find(|(name, _, _)| name == "cache-peer")
                .map(|(_, delay, _)| delay)
            };
            record(13);
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while persisted() != Some(13) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            if fail_startup {
                plane.run().await.expect_err("occupied DNS listener");
            } else {
                drop(plane);
            }
            record(29);
            tokio::time::advance(Duration::from_secs(120)).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert_eq!(
                persisted(),
                Some(13),
                "stopped cache writer must not snapshot again"
            );
        }
        Ok(())
    }
}
