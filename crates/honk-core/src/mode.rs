//! Shared clash mode state (sing-box `mode` / `StoreMode` equivalent).
//!
//! Holds the current clash mode (`Rule` / `Global` / `Direct`) and the
//! GLOBAL group's current selection. One instance is shared between the
//! control plane (which applies the mode override on the outbound decision
//! path) and the clash API (which reads/writes it via `/configs` and
//! `/proxies/GLOBAL`). Values are restored from and persisted to cache.db.

use std::sync::Arc;

/// Clash mode + GLOBAL selection, shared via [`SharedModeState`].
#[derive(Debug, Clone)]
pub struct ModeState {
    /// Canonical clash mode: `"Rule"` | `"Global"` | `"Direct"`.
    pub mode: String,
    /// Current GLOBAL selection: a group name, a node name, or the virtual
    /// `"Proxy"` entry dashboards send for the default selection.
    pub global_selection: String,
}

/// Shared handle to the clash mode state.
pub type SharedModeState = Arc<parking_lot::RwLock<ModeState>>;

impl ModeState {
    /// Create a new state; an unrecognized `mode` falls back to `Rule`.
    pub fn new(mode: &str, global_selection: impl Into<String>) -> Self {
        Self {
            mode: Self::normalize(mode).unwrap_or_else(|| "Rule".to_string()),
            global_selection: global_selection.into(),
        }
    }

    /// Normalize a mode string to canonical case (`"global"` → `"Global"`).
    /// Returns `None` for values outside Rule/Global/Direct.
    pub fn normalize(mode: &str) -> Option<String> {
        if mode.eq_ignore_ascii_case("rule") {
            Some("Rule".to_string())
        } else if mode.eq_ignore_ascii_case("global") {
            Some("Global".to_string())
        } else if mode.eq_ignore_ascii_case("direct") {
            Some("Direct".to_string())
        } else {
            None
        }
    }

    /// Whether the current mode is `Direct`.
    pub fn is_direct(&self) -> bool {
        self.mode.eq_ignore_ascii_case("direct")
    }

    /// Whether the current mode is `Rule` — the only mode in which the eBPF
    /// datapath may offload non-`must` `direct` flows, because the mode
    /// override is the identity there.
    pub fn is_rule(&self) -> bool {
        self.mode.eq_ignore_ascii_case("rule")
    }

    /// Whether the current mode is `Global`.
    pub fn is_global(&self) -> bool {
        self.mode.eq_ignore_ascii_case("global")
    }

    /// Decide the effective outbound after clash-mode override.
    ///
    /// - `block` results and `must` results (dae `(must)` rules / eBPF
    ///   handoff must flag) are final routing decisions and are never
    ///   overridden — a block rule is an explicit safety decision and a
    ///   must rule is an explicit force, neither of which a mode switch
    ///   may bypass;
    /// - mode `Direct` forces `direct`;
    /// - mode `Global` forces the current GLOBAL selection when it
    ///   resolves (`selection_resolvable` — the caller owns the config);
    ///   an unresolvable selection keeps the routed outbound;
    /// - mode `Rule` (or anything else) keeps the routed outbound.
    pub fn override_outbound(
        &self,
        outbound_name: &str,
        must: bool,
        selection_resolvable: bool,
    ) -> String {
        if must || outbound_name == "block" {
            return outbound_name.to_string();
        }
        if self.is_direct() {
            return "direct".to_string();
        }
        if self.is_global() && !self.global_selection.is_empty() && selection_resolvable {
            return self.global_selection.clone();
        }
        outbound_name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(ModeState::normalize("rule").as_deref(), Some("Rule"));
        assert_eq!(ModeState::normalize("GLOBAL").as_deref(), Some("Global"));
        assert_eq!(ModeState::normalize("Direct").as_deref(), Some("Direct"));
        assert_eq!(ModeState::normalize("bogus"), None);
    }

    #[test]
    fn test_new_fallback() {
        let s = ModeState::new("bogus", "proxy");
        assert_eq!(s.mode, "Rule");
        assert_eq!(s.global_selection, "proxy");
        assert!(!s.is_direct());
        assert!(!s.is_global());
    }

    #[test]
    fn test_override_outbound_rule_mode_keeps_routing() {
        let s = ModeState::new("rule", "proxy");
        assert_eq!(s.override_outbound("proxy", false, true), "proxy");
        assert_eq!(s.override_outbound("direct", false, true), "direct");
    }

    #[test]
    fn test_override_outbound_direct_and_global() {
        let direct = ModeState::new("direct", "proxy");
        assert_eq!(direct.override_outbound("proxy", false, true), "direct");

        let global = ModeState::new("global", "proxy");
        assert_eq!(global.override_outbound("other", false, true), "proxy");
        // Unresolvable GLOBAL selection keeps the routed outbound.
        assert_eq!(global.override_outbound("other", false, false), "other");
        // Empty selection behaves the same way.
        let empty = ModeState::new("global", "");
        assert_eq!(empty.override_outbound("other", false, true), "other");
    }

    #[test]
    fn test_override_outbound_block_never_overridden() {
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        assert_eq!(direct.override_outbound("block", false, true), "block");
        assert_eq!(global.override_outbound("block", false, true), "block");
    }

    /// dae must-rule semantics: a `(must)` routing result is final and
    /// must survive Direct/Global mode switches, exactly like `block`.
    #[test]
    fn test_override_outbound_must_never_overridden() {
        let rule = ModeState::new("rule", "proxy");
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        for state in [&rule, &direct, &global] {
            assert_eq!(state.override_outbound("proxy", true, true), "proxy");
            assert_eq!(state.override_outbound("direct", true, true), "direct");
            assert_eq!(state.override_outbound("block", true, true), "block");
        }
    }
}
