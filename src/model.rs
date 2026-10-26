use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const LEASE_SECONDS: u64 = 15;
pub const SYNC_SECONDS: u64 = 3;
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub zone_id: String,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub expires_at: Option<i64>,
    pub zones: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// All configured zones, including disabled zones; None means an older controller.
    #[serde(default)]
    pub private_zones: Option<Vec<String>>,
    pub revision: i64,
    pub token_qps: u32,
    pub zones: Vec<Zone>,
    pub records: Vec<DnsRecord>,
    pub credentials: HashMap<String, Credential>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub bucket: i64,
    pub total: i64,
    pub success: i64,
    pub denied: i64,
    pub errors: i64,
    pub latency_us: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub id: String,
    pub metrics: Vec<Metric>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub node_id: String,
    pub applied_revision: i64,
    pub version: String,
    pub report: Option<Report>,
}
#[derive(Serialize, Deserialize)]
pub struct SyncResponse {
    pub snapshot: Snapshot,
    pub lease_seconds: u64,
}
