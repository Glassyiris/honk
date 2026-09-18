use honk_config::{Config, node::Node};

use crate::subscription::AuthorizedSubscription;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadOutcome {
    Rejected,
    Noop { generation: u64 },
    Committed { generation: u64 },
    CommittedDegraded { generation: u64 },
}

impl ReloadOutcome {
    pub(crate) fn accepted(self) -> bool {
        self.generation().is_some()
    }

    pub(crate) fn generation(self) -> Option<u64> {
        match self {
            Self::Rejected => None,
            Self::Noop { generation }
            | Self::Committed { generation }
            | Self::CommittedDegraded { generation } => Some(generation),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReloadReply {
    pub outcome: ReloadOutcome,
    pub authorized: Vec<AuthorizedSubscription>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ControlCommand {
    ReloadConfig {
        request_id: u64,
        config: Box<Config>,
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
        #[cfg(feature = "native-api")]
        sources: Option<std::sync::Arc<crate::native_api::config::SourceUpdate>>,
        result: tokio::sync::oneshot::Sender<ReloadReply>,
    },
    /// Merge freshly fetched subscription nodes into the running config,
    /// replacing the previous node set of that subscription. Used by
    /// late startup fetches and periodic refreshes; subscription nodes
    /// live in memory only and are never written back to the config file.
    MergeSubscription {
        subscription_id: uuid::Uuid,
        revision: u64,
        nodes: Vec<Node>,
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
    },
    /// Refresh interface-dependent runtime state and bypass stale health
    /// backoff after a link, address, route, or interface-role change.
    NetworkChanged,
    Shutdown,
}
