//! Runtime state in the cache tables of the state database: Selector choices,
//! delay samples, Clash mode and GLOBAL, and DNS answers.
//!
//! One writer thread owns the cache-class connection, so readers never wait
//! behind a write batch. Point writes (selectors, Clash state) are coalesced
//! in `pending` and read from there until the writer has committed them.
//! Write failures are logged and never fatal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};

use honk_outbound::group::{SelectionNetwork, SelectorMember};
use rusqlite::{Connection, params};

use super::{Class, StateDb, StateError};

const CHANNEL_CAPACITY: usize = 256;
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
pub enum CacheDbError {
    #[error("state cache writer is closed")]
    Closed,
    /// Only the result code: SQLite messages can quote stored values.
    #[error("state cache operation failed with SQLite result code {0}")]
    Sqlite(i32),
}

impl From<rusqlite::Error> for CacheDbError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.sqlite_error().map_or(-1, |error| error.extended_code))
    }
}

/// A coalesced point write.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Selector(String, &'static str),
    Clash(&'static str),
}

struct PendingWrite {
    sequence: u64,
    value: String,
}

enum Write {
    Set(Key, String),
    Barrier(mpsc::Sender<Result<(), CacheDbError>>),
    Delays(Vec<(String, u64, u64)>),
    DeleteDelaysBefore(u64),
    Dns(
        Vec<(String, u64, Vec<u8>)>,
        mpsc::Sender<Result<(), CacheDbError>>,
    ),
    FlushDns(mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(any(feature = "native-api", test))]
    DeleteDns(Vec<String>, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    SetQueryOnly(bool, mpsc::Sender<Result<(), CacheDbError>>),
    #[cfg(test)]
    Block(mpsc::Sender<()>, mpsc::Receiver<()>),
}

fn network_name(network: SelectionNetwork) -> &'static str {
    match network {
        SelectionNetwork::Tcp => "tcp",
        SelectionNetwork::Udp => "udp",
    }
}

fn unix(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn flush_pending_writes(
    pending: &Mutex<HashMap<Key, PendingWrite>>,
    writer: &mpsc::SyncSender<Write>,
) -> Result<(), CacheDbError> {
    let snapshot = pending
        .lock()
        .map_err(|_| CacheDbError::Closed)?
        .iter()
        .map(|(key, value)| (key.clone(), value.sequence))
        .collect::<HashMap<_, _>>();
    if snapshot.is_empty() {
        return Ok(());
    }
    let (ack, result) = mpsc::channel();
    writer
        .send(Write::Barrier(ack))
        .map_err(|_| CacheDbError::Closed)?;
    result.recv().map_err(|_| CacheDbError::Closed)??;
    pending
        .lock()
        .map_err(|_| CacheDbError::Closed)?
        .retain(|key, value| snapshot.get(key) != Some(&value.sequence));
    Ok(())
}

fn write_points(
    connection: &mut Connection,
    latest: &mut HashMap<Key, String>,
) -> rusqlite::Result<()> {
    if latest.is_empty() {
        return Ok(());
    }
    let transaction = connection.transaction()?;
    {
        let mut selector = transaction.prepare(
            "INSERT OR REPLACE INTO selector (grp, network, member) VALUES (?1, ?2, ?3)",
        )?;
        let mut clash = transaction
            .prepare("INSERT OR REPLACE INTO clash_state (key, value) VALUES (?1, ?2)")?;
        for (key, value) in latest.iter() {
            match key {
                Key::Selector(group, network) => {
                    selector.execute(params![group, network, value])?;
                }
                Key::Clash(key) => {
                    clash.execute(params![key, value])?;
                }
            }
        }
    }
    transaction.commit()?;
    latest.clear();
    Ok(())
}

fn run_writer(mut connection: Connection, receiver: mpsc::Receiver<Write>) {
    let mut latest = HashMap::<Key, String>::new();
    while let Ok(write) = receiver.recv() {
        match write {
            Write::Set(key, value) => {
                latest.insert(key, value);
                if latest.len() >= 64
                    && let Err(error) = write_points(&mut connection, &mut latest)
                {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache point-write batch failed");
                }
            }
            Write::Barrier(ack) => {
                let result = write_points(&mut connection, &mut latest).map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            Write::Delays(samples) => {
                let result = (|| -> rusqlite::Result<()> {
                    let transaction = connection.transaction()?;
                    {
                        let mut statement = transaction.prepare(
                            "INSERT OR REPLACE INTO delay_sample (node, delay_ms, measured_at)
                             VALUES (?1, ?2, ?3)",
                        )?;
                        for (node, delay_ms, measured_at) in &samples {
                            statement.execute(params![node, unix(*delay_ms), unix(*measured_at)])?;
                        }
                    }
                    transaction.commit()
                })();
                if let Err(error) = result {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache delay batch failed");
                }
            }
            Write::DeleteDelaysBefore(cutoff) => {
                if let Err(error) = connection.execute(
                    "DELETE FROM delay_sample WHERE measured_at < ?1 OR delay_ms <= 0 OR measured_at <= 0",
                    [unix(cutoff)],
                ) {
                    tracing::warn!(error = %CacheDbError::from(error), "state cache delay prune failed");
                }
            }
            Write::Dns(entries, ack) => {
                let result = (|| -> rusqlite::Result<()> {
                    let transaction = connection.transaction()?;
                    {
                        let mut statement = transaction.prepare(
                            "INSERT OR REPLACE INTO dns_answer (key, expire_at, entry) VALUES (?1, ?2, ?3)",
                        )?;
                        for (key, expire_at, entry) in &entries {
                            statement.execute(params![key, unix(*expire_at), entry])?;
                        }
                    }
                    transaction.commit()
                })()
                .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            Write::FlushDns(ack) => {
                let result = connection
                    .execute("DELETE FROM dns_answer", [])
                    .map(|_| ())
                    .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(any(feature = "native-api", test))]
            Write::DeleteDns(keys, ack) => {
                let result = (|| -> rusqlite::Result<()> {
                    let transaction = connection.transaction()?;
                    {
                        let mut statement =
                            transaction.prepare("DELETE FROM dns_answer WHERE key = ?1")?;
                        for key in &keys {
                            statement.execute([key])?;
                        }
                    }
                    transaction.commit()
                })()
                .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(test)]
            Write::SetQueryOnly(enabled, ack) => {
                let result = connection
                    .pragma_update(None, "query_only", enabled)
                    .map_err(CacheDbError::from);
                let _ = ack.send(result);
            }
            #[cfg(test)]
            Write::Block(entered, release) => {
                let _ = entered.send(());
                let _ = release.recv();
            }
        }
    }
    if let Err(error) = write_points(&mut connection, &mut latest) {
        tracing::warn!(error = %CacheDbError::from(error), "state cache final point-write flush failed");
    }
}

#[cfg(test)]
pub(crate) struct CacheDbWriterGuard {
    release: mpsc::Sender<()>,
}

#[cfg(test)]
impl Drop for CacheDbWriterGuard {
    fn drop(&mut self) {
        let _ = self.release.send(());
    }
}

/// Wakes the flusher only while a point write is pending, so an idle cache
/// costs no timer wakeups.
#[derive(Default)]
struct FlushSignal {
    /// `(pending, closed)`.
    state: Mutex<(bool, bool)>,
    ready: std::sync::Condvar,
    #[cfg(test)]
    wakeups: std::sync::atomic::AtomicU64,
}

impl FlushSignal {
    fn notify(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = true;
            self.ready.notify_one();
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = true;
            self.ready.notify_one();
        }
    }

    /// Blocks until a write is pending; `false` once the cache is closed.
    fn wait(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        while !state.0 && !state.1 {
            state = match self.ready.wait(state) {
                Ok(state) => state,
                Err(_) => return false,
            };
        }
        if state.1 {
            return false;
        }
        state.0 = false;
        #[cfg(test)]
        self.wakeups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }
}

pub struct CacheDb {
    _state: Arc<StateDb>,
    /// Reader connection; writes go through `writer`.
    conn: Mutex<Connection>,
    pending: Arc<Mutex<HashMap<Key, PendingWrite>>>,
    writer: mpsc::SyncSender<Write>,
    next_sequence: std::sync::atomic::AtomicU64,
    flush: Arc<FlushSignal>,
    #[cfg(test)]
    write_attempted: std::sync::atomic::AtomicBool,
}

impl Drop for CacheDb {
    fn drop(&mut self) {
        if let Err(error) = self.flush_pending() {
            tracing::warn!(%error, "state cache final point-write flush failed");
        }
        self.flush.close();
    }
}

impl CacheDb {
    /// Opens the reader and writer connections and starts the writer thread.
    pub fn open(state: Arc<StateDb>) -> Result<Self, StateError> {
        let reader = state.connect(Class::Cache)?;
        let connection = state.connect(Class::Cache)?;
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (writer, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        std::thread::Builder::new()
            .name("honk-cache-db-writer".into())
            .spawn(move || run_writer(connection, receiver))
            .map_err(|_| StateError::Unavailable)?;
        let flush_pending = Arc::downgrade(&pending);
        let flush_writer = writer.clone();
        let flush = Arc::new(FlushSignal::default());
        let signal = Arc::clone(&flush);
        std::thread::Builder::new()
            .name("honk-cache-db-flusher".into())
            .spawn(move || {
                // A pending write reaches SQLite within `FLUSH_INTERVAL`.
                while signal.wait() {
                    std::thread::sleep(FLUSH_INTERVAL);
                    let Some(pending) = flush_pending.upgrade() else {
                        break;
                    };
                    if let Err(error) = flush_pending_writes(&pending, &flush_writer) {
                        tracing::warn!(%error, "state cache periodic point-write flush failed");
                    }
                    // Writes that arrived during the flush wait for the next round.
                    if pending.lock().is_ok_and(|pending| !pending.is_empty()) {
                        signal.notify();
                    }
                }
            })
            .map_err(|_| StateError::Unavailable)?;
        Ok(Self {
            _state: state,
            conn: Mutex::new(reader),
            pending,
            writer,
            next_sequence: std::sync::atomic::AtomicU64::new(1),
            flush,
            #[cfg(test)]
            write_attempted: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn get(&self, key: &Key) -> Option<String> {
        if let Some(value) = self.pending.lock().ok()?.get(key) {
            return Some(value.value.clone());
        }
        let conn = self.conn.lock().ok()?;
        match key {
            Key::Selector(group, network) => conn.query_row(
                "SELECT member FROM selector WHERE grp = ?1 AND network = ?2",
                params![group, network],
                |row| row.get(0),
            ),
            Key::Clash(key) => conn.query_row(
                "SELECT value FROM clash_state WHERE key = ?1",
                [key],
                |row| row.get(0),
            ),
        }
        .ok()
    }

    fn set(&self, key: Key, value: String) {
        let sequence = self
            .next_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut pending) = self.pending.lock() else {
            tracing::warn!("state cache pending-write lock poisoned");
            return;
        };
        let previous = pending.insert(
            key.clone(),
            PendingWrite {
                sequence,
                value: value.clone(),
            },
        );
        if let Err(error) = self.writer.send(Write::Set(key.clone(), value)) {
            match previous {
                Some(value) => {
                    pending.insert(key, value);
                }
                None => {
                    pending.remove(&key);
                }
            }
            tracing::warn!(%error, "state cache writer closed; point write rejected");
            return;
        }
        drop(pending);
        self.flush.notify();
    }

    fn flush_pending(&self) -> Result<(), CacheDbError> {
        flush_pending_writes(&self.pending, &self.writer)
    }

    fn request(
        &self,
        write: impl FnOnce(mpsc::Sender<Result<(), CacheDbError>>) -> Write,
    ) -> Result<(), CacheDbError> {
        let (ack, result) = mpsc::channel();
        self.writer
            .send(write(ack))
            .map_err(|_| CacheDbError::Closed)?;
        result.recv().map_err(|_| CacheDbError::Closed)?
    }

    pub fn load_network_selector(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> Option<Result<SelectorMember, serde_json::Error>> {
        self.get(&Key::Selector(group.to_owned(), network_name(network)))
            .map(|value| serde_json::from_str(&value))
    }

    pub(crate) fn save_network_selector(
        &self,
        group: &str,
        network: SelectionNetwork,
        member: &SelectorMember,
    ) {
        self.set(
            Key::Selector(group.to_owned(), network_name(network)),
            serde_json::to_string(member).expect("selector identity serializes"),
        );
    }

    pub fn load_clash_mode(&self) -> Option<String> {
        self.get(&Key::Clash("mode"))
    }

    pub fn save_clash_mode(&self, mode: &str) {
        self.set(Key::Clash("mode"), mode.to_owned());
    }

    /// The Clash GLOBAL selection.
    pub fn load_clash_global(&self) -> Option<String> {
        self.get(&Key::Clash("global"))
    }

    pub fn save_clash_global(&self, selection: &str) {
        self.set(Key::Clash("global"), selection.to_owned());
    }

    /// Records `(node, delay_ms, measured_at_unix)` samples in one transaction
    /// (sing-box URLTest history storage parity: selections formed right after
    /// a restart must not start cold).
    pub fn save_delay_samples(&self, samples: Vec<(String, u64, u64)>) {
        if samples.is_empty() {
            return;
        }
        if let Err(error) = self.writer.send(Write::Delays(samples)) {
            tracing::warn!(%error, "state cache writer closed; delay batch rejected");
        }
    }

    /// Every delay sample no older than `max_age_secs` relative to `now_unix`,
    /// as `(node, delay_ms, measured_at_unix)`. Older or zero samples are
    /// deleted.
    pub fn load_delay_samples(&self, now_unix: u64, max_age_secs: u64) -> Vec<(String, u64, u64)> {
        let cutoff = now_unix.saturating_sub(max_age_secs);
        let rows = (|| -> rusqlite::Result<Vec<(String, u64, u64)>> {
            let conn = self
                .conn
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let mut statement = conn.prepare(
                "SELECT node, delay_ms, measured_at FROM delay_sample
                 WHERE measured_at >= ?1 AND measured_at > 0 AND delay_ms > 0",
            )?;
            statement
                .query_map([unix(cutoff)], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.unsigned_abs(),
                        row.get::<_, i64>(2)?.unsigned_abs(),
                    ))
                })?
                .collect()
        })();
        if let Err(error) = self.writer.send(Write::DeleteDelaysBefore(cutoff)) {
            tracing::warn!(%error, "state cache writer closed; delay prune rejected");
        }
        rows.unwrap_or_else(|error| {
            tracing::warn!(error = %CacheDbError::from(error), "state cache delay load failed");
            Vec::new()
        })
    }

    /// Writes `(key, expire_at_unix, entry)` DNS rows in one transaction.
    pub(crate) fn write_dns(
        &self,
        entries: Vec<(String, u64, Vec<u8>)>,
    ) -> Result<(), CacheDbError> {
        if entries.is_empty() {
            return Ok(());
        }
        #[cfg(test)]
        self.write_attempted
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.request(|ack| Write::Dns(entries, ack))
    }

    /// Every DNS row as `(key, entry)`.
    pub(crate) fn load_dns(&self) -> Result<Vec<(String, Vec<u8>)>, CacheDbError> {
        let conn = self.conn.lock().map_err(|_| CacheDbError::Closed)?;
        let mut statement = conn.prepare("SELECT key, entry FROM dns_answer")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub(crate) fn flush_dns(&self) -> Result<(), CacheDbError> {
        self.request(Write::FlushDns)
    }

    #[cfg(any(feature = "native-api", test))]
    pub(crate) fn delete_dns_entries(&self, keys: &[String]) -> Result<(), CacheDbError> {
        self.request(|ack| Write::DeleteDns(keys.to_vec(), ack))
    }

    /// A cache over a new state db in `directory`.
    #[cfg(test)]
    pub(crate) fn in_dir(directory: &std::path::Path) -> Self {
        Self::open(Arc::new(StateDb::open(directory).expect("state db"))).expect("state cache")
    }

    #[cfg(test)]
    pub(crate) fn set_query_only_for_test(&self, enabled: bool) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.pragma_update(None, "query_only", enabled);
        }
        let _ = self.request(|ack| Write::SetQueryOnly(enabled, ack));
    }

    #[cfg(test)]
    pub(crate) fn lock_for_test(&self) -> CacheDbWriterGuard {
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.writer
            .send(Write::Block(entered, released))
            .expect("state cache writer available");
        ready.recv().expect("state cache writer blocked");
        CacheDbWriterGuard { release }
    }

    #[cfg(test)]
    pub(crate) fn write_attempted_for_test(&self) -> bool {
        self.write_attempted
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
