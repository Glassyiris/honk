use super::record::{FlowError, OutboundAttempt, Selection};
use super::*;
use crate::native_api::events::EventHub;
use honk_config::types::DialMode;

mod evidence;
mod retention;

fn store() -> Arc<FlowStore> {
    store_with_hub().0
}

fn store_with_hub() -> (Arc<FlowStore>, Arc<EventHub>) {
    let instance = Uuid::new_v4().to_string();
    let hub = Arc::new(EventHub::new(instance.clone()));
    let store = Arc::new(FlowStore::new(
        instance,
        Arc::clone(&hub) as Arc<dyn Events>,
    ));
    (store, hub)
}

fn begin(store: &Arc<FlowStore>, network: Network) -> FlowGuard {
    try_begin(store, network).expect("recording flow")
}

fn try_begin(store: &Arc<FlowStore>, network: Network) -> Option<FlowGuard> {
    store.begin(
        network,
        "127.0.0.1:31000".parse().unwrap(),
        "127.0.0.2:443".parse().unwrap(),
    )
}

fn filters(network: &str, state: &str, full: bool, limit: usize) -> Filters {
    Filters::new(network.to_owned(), state.to_owned(), None, full, limit)
}

fn dial_mode() -> StepData {
    StepData::DialMode {
        configured: DialMode::Ip,
        effective_target: "ip",
        domain: None,
        domain_source: None,
        verification: "not_required",
        reason: "original_destination",
    }
}

fn count(hub: &EventHub, kind: &str) -> usize {
    hub.buffered_kinds()
        .into_iter()
        .filter(|buffered| *buffered == kind)
        .count()
}

#[test]
fn pinned_pages_survive_mutation_and_bind_all_filters() {
    let store = store();
    let old = begin(&store, crate::observe::vocab::Network::Tcp);
    old.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let ignored = begin(&store, crate::observe::vocab::Network::Udp);
    ignored.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let recent = begin(&store, crate::observe::vocab::Network::Tcp);
    recent.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let query = filters("tcp", "active", true, 1);
    let first = store.page(query.clone(), None).unwrap();
    assert_eq!(first["flows"][0]["id"], recent.id());
    let cursor = first["next_cursor"].as_str().unwrap();
    old.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let newcomer = begin(&store, crate::observe::vocab::Network::Tcp);
    newcomer.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let second = store.page(query.clone(), Some(cursor)).unwrap();
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["flows"][0]["id"], old.id());
    assert_eq!(second["flows"][0]["state"], "active");
    assert!(second["next_cursor"].is_null());
    for changed in [
        filters("udp", "active", true, 1),
        filters("tcp", "closed", true, 1),
        filters("tcp", "active", false, 1),
        filters("tcp", "active", true, 2),
    ] {
        assert_eq!(
            store.page(changed, Some(cursor)).unwrap_err(),
            PageRefusal::Mismatch
        );
    }
    let other_instance = super::tests::store();
    assert_eq!(
        other_instance
            .page(query.clone(), Some(cursor))
            .unwrap_err(),
        PageRefusal::Expired
    );
    store.inner.lock().snapshots[0].created = Instant::now() - SNAPSHOT_TTL;
    assert_eq!(
        store.page(query, Some(cursor)).unwrap_err(),
        PageRefusal::Expired
    );
}
