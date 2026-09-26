use super::resolves_direct;

#[cfg(feature = "native-api")]
mod routed;

#[test]
fn the_default_is_direct_only_without_a_routed_transport() {
    assert!(
        resolves_direct("", false),
        "builds without native-api keep direct"
    );
    assert!(!resolves_direct("", true));
    for routed_transport in [false, true] {
        assert!(resolves_direct("direct", routed_transport));
        assert!(
            !resolves_direct("routing", routed_transport),
            "explicit, never direct"
        );
        assert!(!resolves_direct("proxy", routed_transport));
    }
}
