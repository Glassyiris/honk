//! Optional DNS cache persistence (sing-box `cache_file.store_dns`).
//!
//! When enabled, every positive answer inserted into the shared
//! [`DnsCache`](super::cache::DnsCache) is mirrored to cache.db: the cache
//! forwards a [`DnsPersistEntry`] over an unbounded channel, and a
//! background task batches the entries and writes them through
//! [`CacheDb::save_dns_answer`](crate::cachedb::CacheDb::save_dns_answer)
//! (sing-box `SaveDNSCacheAsync` semantics). On startup,
//! [`restore_dns_cache`] loads the still-fresh answers back into the cache.
//!
//! When `store_dns` is false no persister is installed, the cache keeps a
//! `None` sink, and the overhead is a single branch per insert.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::sync::{Mutex, mpsc};

use super::cache::DnsCache;
use crate::cachedb::CacheDb;

/// How often the background writer flushes pending entries to cache.db.
const PERSIST_FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// One DNS answer queued for persistence.
#[derive(Debug)]
pub struct DnsPersistEntry {
    pub name: String,
    pub qtype: u16,
    /// Raw wire-format DNS response bytes.
    pub response: Vec<u8>,
    /// Absolute expiry (seconds since UNIX epoch).
    pub expire_at_unix: u64,
}

/// Cheap-cloneable handle to the background DNS cache writer.
///
/// Installed into the shared [`DnsCache`] via
/// [`DnsCache::set_persister`](super::cache::DnsCache::set_persister).
/// Sending is non-blocking; a full or closed channel drops the entry
/// (persistence is best-effort and never stalls the DNS path).
#[derive(Debug, Clone)]
pub struct DnsCachePersister {
    tx: mpsc::UnboundedSender<DnsPersistEntry>,
}

impl DnsCachePersister {
    /// Spawn the background batch writer draining into `db`.
    pub fn spawn(db: Arc<CacheDb>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<DnsPersistEntry>();
        tokio::spawn(async move {
            // Newest entry per (name, qtype) wins; flushed periodically.
            let mut pending: HashMap<(String, u16), DnsPersistEntry> = HashMap::new();
            let mut tick = tokio::time::interval(PERSIST_FLUSH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    maybe = rx.recv() => {
                        match maybe {
                            Some(entry) => {
                                pending.insert((entry.name.clone(), entry.qtype), entry);
                            }
                            // All senders dropped — final flush, then exit.
                            None => {
                                flush_pending(&db, &mut pending);
                                break;
                            }
                        }
                    }
                    _ = tick.tick() => {
                        flush_pending(&db, &mut pending);
                    }
                }
            }
        });
        Self { tx }
    }

    /// Queue one answer for persistence (non-blocking, best-effort).
    pub fn save(&self, entry: DnsPersistEntry) {
        let _ = self.tx.send(entry);
    }
}

/// Write all pending entries and clear the batch. Failures only warn.
fn flush_pending(db: &CacheDb, pending: &mut HashMap<(String, u16), DnsPersistEntry>) {
    if pending.is_empty() {
        return;
    }
    for entry in pending.drain().map(|(_, e)| e) {
        db.save_dns_answer(
            &entry.name,
            entry.qtype,
            &encode_answer(&entry.response),
            entry.expire_at_unix,
        );
    }
}

/// Encode raw wire-format response bytes as the JSON payload stored by
/// [`CacheDb::save_dns_answer`]. Kept deliberately small: `{"r": base64}`.
pub fn encode_answer(response: &[u8]) -> String {
    serde_json::json!({
        "r": base64::engine::general_purpose::STANDARD.encode(response),
    })
    .to_string()
}

/// Inverse of [`encode_answer`]; `None` on malformed payloads.
pub fn decode_answer(answer_json: &str) -> Option<Vec<u8>> {
    let value = serde_json::from_str::<serde_json::Value>(answer_json).ok()?;
    let b64 = value.get("r")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Current UNIX time in seconds (0 on clock skew before the epoch).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load every still-fresh persisted answer from cache.db into `cache`.
/// Returns the number of restored entries. Call once at startup, before
/// installing the persister, so restored entries are not re-persisted.
pub async fn restore_dns_cache(db: &CacheDb, cache: &Arc<Mutex<DnsCache>>) -> usize {
    let now = unix_now();
    let answers = db.load_dns_answers(now);
    if answers.is_empty() {
        return 0;
    }
    let mut cache = cache.lock().await;
    let mut restored = 0;
    for answer in answers {
        let ttl = answer.expire_at_unix.saturating_sub(now);
        let Ok(ttl) = u32::try_from(ttl) else {
            continue;
        };
        if ttl == 0 {
            continue;
        }
        let Some(response) = decode_answer(&answer.answer_json) else {
            continue;
        };
        cache.put(format!("{}:{}", answer.name, answer.qtype), response, ttl);
        restored += 1;
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::experimental::CacheFileConfig;

    fn test_db(dir: &tempfile::TempDir) -> Arc<CacheDb> {
        let cfg = CacheFileConfig {
            enabled: true,
            path: dir.path().join("cache.db").to_str().unwrap().to_string(),
            cache_id: String::new(),
            store_fakeip: false,
            store_dns: true,
        };
        Arc::new(CacheDb::open(&cfg, None).expect("cache.db opens"))
    }

    #[test]
    fn answer_payload_roundtrip() {
        let bytes = b"\x00\x01raw-dns-bytes\xff".to_vec();
        let json = encode_answer(&bytes);
        assert_eq!(decode_answer(&json).as_deref(), Some(bytes.as_slice()));
        assert!(decode_answer("not json").is_none());
        assert!(decode_answer(r#"{"x":1}"#).is_none());
    }

    #[tokio::test]
    async fn persister_batches_writes_to_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = test_db(&dir);
        let persister = DnsCachePersister::spawn(db.clone());
        let expire = unix_now() + 300;

        persister.save(DnsPersistEntry {
            name: "example.com".into(),
            qtype: 1,
            response: b"wire-bytes".to_vec(),
            expire_at_unix: expire,
        });
        // A second entry for the same key overwrites the first in the batch.
        persister.save(DnsPersistEntry {
            name: "example.com".into(),
            qtype: 1,
            response: b"wire-bytes-v2".to_vec(),
            expire_at_unix: expire,
        });

        // Wait for at least one flush interval.
        tokio::time::sleep(PERSIST_FLUSH_INTERVAL * 4).await;

        let answers = db.load_dns_answers(unix_now());
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(
            decode_answer(&answers[0].answer_json).as_deref(),
            Some(b"wire-bytes-v2".as_slice())
        );
    }

    #[tokio::test]
    async fn restore_loads_fresh_answers_with_remaining_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let db = test_db(&dir);
        let now = unix_now();
        db.save_dns_answer("example.com", 1, &encode_answer(b"wire-bytes"), now + 300);
        db.save_dns_answer("stale.com", 1, &encode_answer(b"old"), now - 1);

        let cache = Arc::new(Mutex::new(DnsCache::new(16)));
        let restored = restore_dns_cache(&db, &cache).await;
        assert_eq!(restored, 1);

        let mut cache = cache.lock().await;
        let entry = cache.get("example.com:1").expect("restored entry");
        assert_eq!(entry.response, b"wire-bytes");
        let remaining = entry.remaining_ttl_secs();
        assert!(
            (295..=300).contains(&remaining),
            "remaining ttl ~300s, got {remaining}"
        );
        assert!(cache.get("stale.com:1").is_none());
    }
}
