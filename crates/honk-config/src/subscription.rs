use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::SubscriptionType;

/// A proxy subscription (e.g., subscription link).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subscription {
    /// Unique subscription ID
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    /// Display name
    pub name: String,
    /// Subscription URL
    pub url: String,
    /// Subscription type
    #[serde(default)]
    pub sub_type: SubscriptionType,
    /// Update interval in seconds (0 = manual)
    #[serde(default = "default_update_interval")]
    pub update_interval: u64,
    /// User-Agent for fetching
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Custom headers
    #[serde(default)]
    pub headers: Vec<SubscriptionHeader>,
    /// Enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Last update time
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of nodes from this subscription
    #[serde(default)]
    pub node_count: u32,
    /// Created at
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

fn default_update_interval() -> u64 {
    86400 // 24 hours
}

/// Custom HTTP header for subscription fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionHeader {
    pub key: String,
    pub value: String,
}
