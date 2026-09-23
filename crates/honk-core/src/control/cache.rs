use std::collections::HashSet;

use super::*;
use crate::state::StateDb;
use crate::state::cache::{CacheDb, Maintenance};

const DELAY_SAMPLE_MAX_AGE_SECS: u64 = 24 * 3600;

/// The state db maintenance tick, every 60 s while the cache is open.
#[derive(Default)]
pub(super) struct StateTick {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl StateTick {
    pub(super) async fn stop_and_join(&mut self) -> anyhow::Result<()> {
        super::lifecycle::abort_and_join(&mut self.task).await
    }
}

impl Drop for StateTick {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl ControlPlane {
    /// Open the cache tables of the state database (sing-box `cache_file`),
    /// import a legacy `cache.db`, wire selector-choice persistence into the
    /// group manager, restore persisted choices, and start the maintenance
    /// tick. Without `experimental.cache_file` only the tick starts, for
    /// subscription bodies. No-op when there is no state database.
    /// Called once from `run()`, with the instance lock held.
    pub async fn init_cache_db(
        &mut self,
        state: Option<Arc<StateDb>>,
        legacy: Option<crate::state::import::LegacyCache>,
    ) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(state) = state else {
            return;
        };
        self.state_db = Some(Arc::clone(&state));
        if !cache_cfg.enabled {
            self.start_state_tick(state, None);
            return;
        }
        if let Some(legacy) = legacy {
            let scope = {
                let config = self.config.read().await;
                crate::state::import::ImportScope {
                    selector_groups: config
                        .groups
                        .iter()
                        .filter(|group| group.policy == GroupPolicy::Selector)
                        .map(|group| group.name.clone())
                        .collect(),
                    nodes: config.nodes.iter().map(|node| node.name.clone()).collect(),
                }
            };
            crate::state::import::import_cache_db(&state, &legacy, &scope);
        }
        let db = match CacheDb::open(Arc::clone(&state)) {
            Ok(db) => Arc::new(db),
            Err(error) => {
                warn!(%error, "state cache unavailable; continuing without persistence");
                self.start_state_tick(state, None);
                return;
            }
        };

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
                    if let Some(Ok(member)) = db.load_network_selector(&group.name, network)
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
        // samples back every minute from the maintenance tick. Liveness is
        // NOT restored — probes re-decide that; stale entries (>24h) are
        // dropped on load.
        {
            let samples = db.load_delay_samples(unix_now(), DELAY_SAMPLE_MAX_AGE_SECS);
            // Delay samples are keyed by node name; resolve them onto this
            // generation's NodeIds — samples for nodes no longer configured
            // are dropped.
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
                info!("state db: restored {} persisted delay sample(s)", restored);
            }
        }

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into the state db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.store_dns {
            let dns_cache = self.dns_controller.cache().await;
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            let policy = self.dns_controller.forwarder().policy_id();
            match persister.restore_cache(&dns_cache, policy).await {
                Ok(restored) if restored > 0 => {
                    info!("state db: restored {} persisted DNS answer(s)", restored);
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "state db DNS restore failed"),
            }
            dns_cache.lock().await.set_persister(Some(persister));
        }
        // Startup prune, after restore: only the age and expiry rules.
        if let Err(error) = db.maintain(Maintenance {
            delay_cutoff: unix_now().saturating_sub(DELAY_SAMPLE_MAX_AGE_SECS),
            dns_expired_at: cache_cfg.store_dns.then(unix_now),
            ..Maintenance::default()
        }) {
            warn!(%error, "state db startup prune failed");
        }
        self.start_state_tick(state, Some(Arc::clone(&db)));

        self.cache_db = Some(db);
    }

    fn start_state_tick(&mut self, state: Arc<StateDb>, db: Option<Arc<CacheDb>>) {
        let alive = self.alive_set.clone();
        let config = self.config.clone();
        let task = tokio::spawn(async move {
            let mut missing = Missing::default();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // first tick after one period
            loop {
                let (live, owners, names) = {
                    let config = config.read().await;
                    (
                        Live::of(&config),
                        TickOwners {
                            store_dns: config.experimental.cache_file.store_dns,
                            store_subscribe: config.global.store_subscribe,
                        },
                        config
                            .nodes
                            .iter()
                            .map(|n| (n.id, n.name.clone()))
                            .collect::<std::collections::HashMap<uuid::Uuid, String>>(),
                    )
                };
                let samples = if db.is_some() {
                    alive
                        .latency_snapshot()
                        .into_iter()
                        .filter_map(|(node_id, latency, at)| {
                            let measured_at = at
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            Some((
                                names.get(&node_id)?.clone(),
                                latency.as_millis() as u64,
                                measured_at,
                            ))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let (state, db) = (Arc::clone(&state), db.clone());
                missing = tokio::task::spawn_blocking(move || {
                    maintenance_tick(
                        &state,
                        db.as_deref(),
                        &live,
                        samples,
                        &mut missing,
                        owners,
                        unix_now(),
                    );
                    missing
                })
                .await
                .unwrap_or_default();
                interval.tick().await;
            }
        });
        self.state_tick.task = Some(task);
    }

    /// The state database, when `init_cache_db` had one.
    #[cfg(feature = "native-api")]
    pub(crate) fn state_db(&self) -> Option<Arc<StateDb>> {
        self.state_db.clone()
    }

    /// Shared handle to the persistent cache database (clash API, etc.).
    pub fn cache_db(&self) -> Option<Arc<crate::state::cache::CacheDb>> {
        self.cache_db.clone()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Names the config holds when a tick starts.
pub(super) struct Live {
    selector_groups: HashSet<String>,
    nodes: HashSet<String>,
}

impl Live {
    fn of(config: &Config) -> Self {
        Self {
            selector_groups: config
                .groups
                .iter()
                .filter(|group| group.policy == GroupPolicy::Selector)
                .map(|group| group.name.clone())
                .collect(),
            nodes: config.nodes.iter().map(|node| node.name.clone()).collect(),
        }
    }
}

/// Keys that were missing from the config at the previous tick, one per row.
#[derive(Default)]
pub(super) struct Missing {
    groups: HashSet<String>,
    nodes: HashSet<String>,
    bodies: HashSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TickOwners {
    store_dns: bool,
    store_subscribe: bool,
}

/// One maintenance tick. With `store_subscribe`, deletes subscription bodies
/// whose subscription was not enabled at this tick and the previous one. With
/// the cache open, writes `samples`, deletes Selector and delay rows whose
/// group or node was missing at this tick and the previous one, delay rows
/// older than 24 h and, with `store_dns`, expired DNS rows, then runs
/// `incremental_vacuum`. The two-tick rule keeps rows across a config that
/// briefly drops and restores a group, node or subscription.
pub(super) fn maintenance_tick(
    state: &StateDb,
    db: Option<&CacheDb>,
    live: &Live,
    samples: Vec<(String, u64, u64)>,
    missing: &mut Missing,
    owners: TickOwners,
    now: u64,
) {
    if owners.store_subscribe
        && let Err(error) = crate::subscription::prune_bodies(state, &mut missing.bodies)
    {
        warn!(%error, "state db subscription body maintenance failed");
    }
    let Some(db) = db else {
        return;
    };
    db.save_delay_samples(samples);
    let stale = |rows: Result<Vec<String>, _>,
                 present: &HashSet<String>,
                 previous: &mut HashSet<String>| {
        let current: HashSet<String> = match rows {
            Ok(rows) => rows
                .into_iter()
                .filter(|key| !present.contains(key))
                .collect(),
            Err(error) => {
                warn!(%error, "state db maintenance read failed");
                HashSet::new()
            }
        };
        let expired = current.intersection(previous).cloned().collect();
        *previous = current;
        expired
    };
    let work = Maintenance {
        groups: stale(
            db.selector_groups(),
            &live.selector_groups,
            &mut missing.groups,
        ),
        nodes: stale(db.delay_nodes(), &live.nodes, &mut missing.nodes),
        delay_cutoff: now.saturating_sub(DELAY_SAMPLE_MAX_AGE_SECS),
        dns_expired_at: owners.store_dns.then_some(now),
    };
    if let Err(error) = db.maintain(work) {
        warn!(%error, "state db maintenance failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::support::{canonical_socks5, control_plane};
    use honk_outbound::alive::{IpVersion, ProbeDomain};

    #[test]
    fn a_dropped_group_and_node_keep_their_rows_for_one_tick() {
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        let db = CacheDb::open(Arc::clone(&state)).unwrap();
        let now = 1_700_000_000;
        let member = honk_outbound::group::SelectorMember::Group("m".into());
        for group in ["kept", "dropped"] {
            db.save_network_selector(group, honk_outbound::group::SelectionNetwork::Tcp, &member);
        }
        db.save_delay_samples(vec![
            ("kept-node".into(), 5, now),
            ("dropped-node".into(), 5, now),
        ]);
        db.write_dns(vec![
            ("expired".into(), now - 1, vec![0]),
            ("fresh".into(), now + 60, vec![0]),
        ])
        .unwrap();
        db.maintain(Maintenance::default()).unwrap();
        let live = Live {
            selector_groups: HashSet::from(["kept".to_owned()]),
            nodes: HashSet::from(["kept-node".to_owned()]),
        };
        let rows = |db: &CacheDb| {
            let mut groups = db.selector_groups().unwrap();
            let mut nodes = db.delay_nodes().unwrap();
            groups.sort();
            nodes.sort();
            let dns: Vec<String> = db
                .load_dns()
                .unwrap()
                .into_iter()
                .map(|row| row.0)
                .collect();
            (groups, nodes, dns)
        };
        let mut missing = Missing::default();
        let owners = TickOwners {
            store_dns: true,
            store_subscribe: false,
        };

        maintenance_tick(
            &state,
            Some(&db),
            &live,
            Vec::new(),
            &mut missing,
            owners,
            now,
        );
        assert_eq!(
            rows(&db),
            (
                vec!["dropped".to_owned(), "kept".to_owned()],
                vec!["dropped-node".to_owned(), "kept-node".to_owned()],
                vec!["fresh".to_owned()],
            )
        );
        maintenance_tick(
            &state,
            Some(&db),
            &live,
            Vec::new(),
            &mut missing,
            owners,
            now,
        );
        assert_eq!(
            rows(&db),
            (
                vec!["kept".to_owned()],
                vec!["kept-node".to_owned()],
                vec!["fresh".to_owned()],
            )
        );
    }

    #[tokio::test]
    async fn a_disabled_subscription_keeps_its_body_for_one_tick() {
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        let store = crate::subscription::SubscriptionStore::new(Arc::clone(&state));
        let subscription = |name: &str| honk_config::subscription::Subscription {
            url: format!("https://example.invalid/{name}"),
            ..Default::default()
        };
        let (kept, dropped) = (subscription("kept"), subscription("dropped"));
        for sub in [&kept, &dropped] {
            store.store_content(sub, "body".into()).await.unwrap();
        }
        store.set_enabled([&kept]);
        let live = Live {
            selector_groups: HashSet::new(),
            nodes: HashSet::new(),
        };
        let owners = TickOwners {
            store_dns: false,
            store_subscribe: true,
        };
        let mut missing = Missing::default();
        let bodies = || -> i64 {
            state
                .strict()
                .query_row("SELECT count(*) FROM subscription_body", [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        maintenance_tick(&state, None, &live, Vec::new(), &mut missing, owners, 0);
        assert_eq!(bodies(), 2);
        maintenance_tick(&state, None, &live, Vec::new(), &mut missing, owners, 0);
        let remaining: String = state
            .strict()
            .query_row("SELECT key FROM subscription_body", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            remaining,
            crate::subscription::SubscriptionStore::key(&kept)
        );
    }

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
            let state = Arc::new(crate::state::StateDb::open(directory.path())?);
            let mut plane = control_plane(config);
            plane.init_cache_db(Some(state), None).await;
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
