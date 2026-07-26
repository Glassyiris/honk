//! Persistent cache database (sing-box `cache_file` equivalent).
//!
//! Stores selector choices, clash mode, and (optionally, via
//! `cache_file.store_dns`) DNS answers across honk-core restarts.
//! Backed by SQLite in WAL mode. On open, if the file fails to open or
//! does not pass `PRAGMA quick_check`, the corrupt file is renamed to
//! `<name>.corrupt-<unix_ts>` and a fresh database is created (sing-box
//! `resetDB` semantics). Write failures are logged and never fatal.
//!
//! `cache_id` namespaces all keys: when non-empty, every key is stored as
//! `"{cache_id}:{key}"` so multiple router instances can share one file.
//! The prefix is an internal detail; the public API takes plain keys.

use honk_config::experimental::CacheFileConfig;
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct CacheDb {
    conn: Mutex<Connection>,
    /// Key namespace prefix derived from `cache_id` ("" when empty).
    prefix: String,
}

impl CacheDb {
    /// Open (or create) the cache database at the configured path.
    /// Returns `None` when `config.enabled` is false, or when the database
    /// cannot be opened even after a corruption reset.
    pub fn open(config: &CacheFileConfig, config_dir: Option<&str>) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let path = resolve_path(&config.path, config_dir);
        let prefix = if config.cache_id.is_empty() {
            String::new()
        } else {
            format!("{}:", config.cache_id)
        };

        let conn = match open_and_check(&path) {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(
                    "cache.db at {} failed open/integrity check ({}); resetting",
                    path.display(),
                    e
                );
                reset_corrupt(&path);
                match open_and_check(&path) {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("cache.db reset at {} failed: {}", path.display(), e);
                        return None;
                    }
                }
            }
        };

        if let Err(e) = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');",
        ) {
            tracing::warn!("cache.db schema init failed: {}", e);
            return None;
        }

        tracing::info!("cache.db opened at {}", path.display());
        Some(Self {
            conn: Mutex::new(conn),
            prefix,
        })
    }

    /// Wrap a plain key with the `cache_id` namespace prefix.
    fn wrap(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}{}", self.prefix, key)
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let key = self.wrap(key);
        let conn = self.conn.lock().ok()?;
        conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .ok()
    }

    pub fn set(&self, key: &str, value: &str) {
        let key = self.wrap(key);
        if let Ok(conn) = self.conn.lock()
            && let Err(e) = conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
        {
            tracing::warn!("cache.db set '{}' failed: {}", key, e);
        }
    }

    pub fn remove(&self, key: &str) {
        let key = self.wrap(key);
        if let Ok(conn) = self.conn.lock()
            && let Err(e) = conn.execute("DELETE FROM kv WHERE key = ?1", params![key])
        {
            tracing::warn!("cache.db remove '{}' failed: {}", key, e);
        }
    }

    /// Delete all keys starting with `prefix` (after namespacing).
    /// Reserved for future use (e.g. flushing persisted FakeIP mappings).
    pub fn flush_prefix(&self, prefix: &str) {
        let prefix = self.wrap(prefix);
        // Escape LIKE metacharacters so the prefix matches literally.
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        if let Ok(conn) = self.conn.lock()
            && let Err(e) = conn.execute(
                "DELETE FROM kv WHERE key LIKE ?1 ESCAPE '\\'",
                params![format!("{}%", escaped)],
            )
        {
            tracing::warn!("cache.db flush_prefix '{}' failed: {}", prefix, e);
        }
    }

    pub fn load_selector_choice(&self, group: &str) -> Option<String> {
        self.get(&format!("selector:{}", group))
    }

    pub fn save_selector_choice(&self, group: &str, node: &str) {
        self.set(&format!("selector:{}", group), node);
    }

    pub fn load_clash_mode(&self) -> Option<String> {
        self.get("clash_mode")
    }

    pub fn save_clash_mode(&self, mode: &str) {
        self.set("clash_mode", mode);
    }

    /// Persist a node's last real delay sample under `delay:{node}`
    /// (sing-box URLTest history storage parity: selections formed right
    /// after a restart must not start cold).
    pub fn save_delay_sample(&self, node: &str, delay_ms: u64, measured_at_unix: u64) {
        let value = serde_json::json!({
            "delay_ms": delay_ms,
            "measured_at": measured_at_unix,
        });
        self.set(&format!("delay:{}", node), &value.to_string());
    }

    /// Load every persisted delay sample no older than `max_age_secs`
    /// relative to `now_unix`. Stale or malformed entries are skipped and
    /// lazily deleted. Returns `(node, delay_ms, measured_at_unix)`.
    pub fn load_delay_samples(&self, now_unix: u64, max_age_secs: u64) -> Vec<(String, u64, u64)> {
        let prefix = self.wrap("delay:");
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows: Vec<(String, String)> = {
            let Ok(conn) = self.conn.lock() else {
                return Vec::new();
            };
            let mut stmt =
                match conn.prepare("SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\'") {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        tracing::warn!("cache.db load_delay_samples prepare failed: {}", e);
                        return Vec::new();
                    }
                };
            match stmt
                .query_map(params![format!("{}%", escaped)], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("cache.db load_delay_samples query failed: {}", e);
                    return Vec::new();
                }
            }
        };
        let mut out = Vec::new();
        for (key, value) in rows {
            let node = key[prefix.len()..].to_string();
            let parsed = serde_json::from_str::<serde_json::Value>(&value).ok();
            let (delay_ms, measured_at) = parsed
                .as_ref()
                .and_then(|v| {
                    Some((
                        v.get("delay_ms")?.as_u64()?,
                        v.get("measured_at")?.as_u64()?,
                    ))
                })
                .unwrap_or((0, 0));
            if measured_at == 0
                || delay_ms == 0
                || now_unix.saturating_sub(measured_at) > max_age_secs
            {
                self.remove(&format!("delay:{}", node));
                continue;
            }
            out.push((node, delay_ms, measured_at));
        }
        out
    }

    /// Persist one DNS answer under `dns:{name}:{qtype}`. `answer_json` is
    /// the opaque payload produced by the DNS layer (a JSON document);
    /// `expire_at_unix` is the absolute expiry as seconds since UNIX epoch.
    pub fn save_dns_answer(&self, name: &str, qtype: u16, answer_json: &str, expire_at_unix: u64) {
        // Embed the answer payload as nested JSON when it parses; otherwise
        // keep it as a plain string so no data is ever dropped.
        let answer = serde_json::from_str::<serde_json::Value>(answer_json)
            .unwrap_or_else(|_| serde_json::Value::String(answer_json.to_string()));
        let value = serde_json::json!({
            "expire_at": expire_at_unix,
            "answer": answer,
        });
        self.set(&format!("dns:{}:{}", name, qtype), &value.to_string());
    }

    /// Load every persisted DNS answer that is still fresh at `now_unix`.
    /// Expired (or malformed) entries are skipped and lazily deleted.
    pub fn load_dns_answers(&self, now_unix: u64) -> Vec<PersistedDnsAnswer> {
        let prefix = self.wrap("dns:");
        let escaped = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows: Vec<(String, String)> = {
            let Ok(conn) = self.conn.lock() else {
                return Vec::new();
            };
            let mut stmt =
                match conn.prepare("SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\'") {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        tracing::warn!("cache.db load_dns_answers prepare failed: {}", e);
                        return Vec::new();
                    }
                };
            match stmt
                .query_map(params![format!("{}%", escaped)], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("cache.db load_dns_answers query failed: {}", e);
                    return Vec::new();
                }
            }
        };

        let mut out = Vec::new();
        for (wrapped_key, value) in rows {
            let key = wrapped_key
                .strip_prefix(&self.prefix)
                .unwrap_or(&wrapped_key);
            let Some(rest) = key.strip_prefix("dns:") else {
                continue;
            };
            // The key is `dns:{name}:{qtype}`; DNS names never contain ':'.
            let Some((name, qtype)) = rest.rsplit_once(':') else {
                continue;
            };
            let Ok(qtype) = qtype.parse::<u16>() else {
                continue;
            };
            let parsed = serde_json::from_str::<serde_json::Value>(&value).ok();
            let expire_at = parsed
                .as_ref()
                .and_then(|v| v.get("expire_at"))
                .and_then(|v| v.as_u64());
            let answer_json = parsed.as_ref().and_then(|v| v.get("answer")).and_then(|v| {
                if v.is_string() {
                    v.as_str().map(str::to_string)
                } else {
                    serde_json::to_string(v).ok()
                }
            });
            let (Some(expire_at), Some(answer_json)) = (expire_at, answer_json) else {
                // Malformed row — drop it so it does not linger forever.
                self.remove(key);
                continue;
            };
            if expire_at <= now_unix {
                // Expired — lazily delete (sing-box cache_file semantics).
                self.remove(key);
                continue;
            }
            out.push(PersistedDnsAnswer {
                name: name.to_string(),
                qtype,
                answer_json,
                expire_at_unix: expire_at,
            });
        }
        out
    }

    /// Delete all persisted DNS answers (`dns:` prefix).
    pub fn flush_dns(&self) {
        self.flush_prefix("dns:");
    }
}

/// A DNS answer restored from the persistent cache (`store_dns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedDnsAnswer {
    pub name: String,
    pub qtype: u16,
    /// Opaque payload as produced by `save_dns_answer` (JSON document).
    pub answer_json: String,
    pub expire_at_unix: u64,
}

/// Open the database, apply pragmas, and verify integrity via quick_check.
fn open_and_check(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA busy_timeout=1000;
         PRAGMA synchronous=NORMAL;",
    )
    .map_err(|e| e.to_string())?;
    let ok: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if ok != "ok" {
        return Err(format!("quick_check returned '{}'", ok));
    }
    Ok(conn)
}

/// Rename a corrupt database file aside (`<name>.corrupt-<unix_ts>`) and
/// remove stale WAL/SHM sidecars so a fresh database can be created.
fn reset_corrupt(path: &Path) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cache.db");
    let backup = path.with_file_name(format!("{}.corrupt-{}", name, ts));
    if let Err(e) = std::fs::rename(path, &backup) {
        tracing::warn!(
            "failed to rename corrupt cache.db {} -> {}: {}",
            path.display(),
            backup.display(),
            e
        );
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            let _ = std::fs::remove_file(sidecar);
        }
    }
}

/// Resolve the cache file path. Relative paths are relative to the config dir.
fn resolve_path(path: &str, config_dir: Option<&str>) -> PathBuf {
    let p = PathBuf::from(if path.is_empty() { "cache.db" } else { path });
    if p.is_absolute() {
        p
    } else if let Some(dir) = config_dir {
        PathBuf::from(dir).join(p)
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(path: &Path, cache_id: &str) -> CacheFileConfig {
        CacheFileConfig {
            enabled: true,
            path: path.to_str().unwrap().to_string(),
            cache_id: cache_id.to_string(),
            store_fakeip: false,
            store_dns: false,
        }
    }

    #[test]
    fn basic_get_set_overwrite_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();

        assert!(db.get("missing").is_none());
        db.set("k", "v1");
        assert_eq!(db.get("k").as_deref(), Some("v1"));
        db.set("k", "v2");
        assert_eq!(db.get("k").as_deref(), Some("v2"));
        db.remove("k");
        assert!(db.get("k").is_none());
    }

    #[test]
    fn selector_choice_and_clash_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();

        assert!(db.load_selector_choice("proxy").is_none());
        db.save_selector_choice("proxy", "node-a");
        assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-a"));

        assert!(db.load_clash_mode().is_none());
        db.save_clash_mode("Global");
        assert_eq!(db.load_clash_mode().as_deref(), Some("Global"));
    }

    #[test]
    fn cache_id_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let a = CacheDb::open(&cfg(&path, "a"), None).unwrap();
        let b = CacheDb::open(&cfg(&path, "b"), None).unwrap();

        a.save_selector_choice("proxy", "node-a");
        a.save_clash_mode("Global");

        // Different cache_id on the same file sees nothing.
        assert!(b.load_selector_choice("proxy").is_none());
        assert!(b.load_clash_mode().is_none());

        b.save_selector_choice("proxy", "node-b");
        assert_eq!(a.load_selector_choice("proxy").as_deref(), Some("node-a"));
        assert_eq!(b.load_selector_choice("proxy").as_deref(), Some("node-b"));

        // Empty cache_id is yet another (legacy) namespace.
        let plain = CacheDb::open(&cfg(&path, ""), None).unwrap();
        assert!(plain.load_selector_choice("proxy").is_none());
    }

    #[test]
    fn delay_sample_save_load_and_age_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();
        let now = 1_700_000_000u64;

        db.save_delay_sample("node-a", 123, now - 60);
        db.save_delay_sample("node-old", 456, now - 25 * 3600);

        let samples = db.load_delay_samples(now, 24 * 3600);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0], ("node-a".to_string(), 123, now - 60));
        // Stale entry was lazily deleted.
        assert!(
            db.load_delay_samples(now, 24 * 3600).is_empty()
                || db
                    .load_delay_samples(now, 24 * 3600)
                    .iter()
                    .all(|(n, _, _)| n != "node-old")
        );
        assert!(db.get("delay:node-old").is_none());
    }

    #[test]
    fn corrupt_file_is_backed_up_and_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        // Garbage large enough that SQLite cannot treat it as an empty db.
        std::fs::write(&path, vec![0xABu8; 256]).unwrap();

        let db = CacheDb::open(&cfg(&path, ""), None).expect("open should recover");

        let backup_exists = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("cache.db.corrupt-"))
                    .unwrap_or(false)
            });
        assert!(backup_exists, "corrupt file should be renamed aside");

        db.set("k", "v");
        assert_eq!(db.get("k").as_deref(), Some("v"));
    }

    #[test]
    fn legacy_kv_schema_is_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        // Build a legacy-format db by hand: only the kv table.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE kv (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
                 INSERT INTO kv (key, value) VALUES ('selector:iris', 'iris');",
            )
            .unwrap();
        }

        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();
        assert_eq!(db.load_selector_choice("iris").as_deref(), Some("iris"));

        // The meta table is added on top without touching existing rows.
        let conn = db.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn dns_answer_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        db.save_dns_answer("example.com", 28, r#"{"r":"REVG"}"#, now + 600);

        let answers = db.load_dns_answers(now);
        assert_eq!(answers.len(), 2);
        let a = answers
            .iter()
            .find(|a| a.qtype == 1)
            .expect("A answer present");
        assert_eq!(a.name, "example.com");
        assert_eq!(a.answer_json, r#"{"r":"QUJD"}"#);
        assert_eq!(a.expire_at_unix, now + 300);
        let aaaa = answers
            .iter()
            .find(|a| a.qtype == 28)
            .expect("AAAA answer present");
        assert_eq!(aaaa.answer_json, r#"{"r":"REVG"}"#);
    }

    #[test]
    fn dns_answer_expired_is_skipped_and_lazily_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("stale.com", 1, r#"{"r":"QUJD"}"#, now - 1);
        db.save_dns_answer("fresh.com", 1, r#"{"r":"REVG"}"#, now + 60);

        let answers = db.load_dns_answers(now);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "fresh.com");

        // The expired row was removed during the load.
        assert!(db.get("dns:stale.com:1").is_none());
        assert!(db.get("dns:fresh.com:1").is_some());
    }

    #[test]
    fn dns_flush_only_clears_dns_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let db = CacheDb::open(&cfg(&path, ""), None).unwrap();
        let now = 1_000_000u64;

        db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        db.save_selector_choice("proxy", "node-a");

        db.flush_dns();
        assert!(db.load_dns_answers(now).is_empty());
        assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-a"));
    }

    #[test]
    fn dns_answers_respect_cache_id_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let now = 1_000_000u64;
        let a = CacheDb::open(&cfg(&path, "a"), None).unwrap();
        let b = CacheDb::open(&cfg(&path, "b"), None).unwrap();

        a.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
        assert_eq!(a.load_dns_answers(now).len(), 1);
        assert!(b.load_dns_answers(now).is_empty());

        b.flush_dns();
        assert_eq!(
            a.load_dns_answers(now).len(),
            1,
            "flushing namespace b must not touch namespace a"
        );
    }
}
