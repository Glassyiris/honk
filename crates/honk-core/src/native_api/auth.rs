//! Administrator credentials and sessions for password mode.
//!
//! One record in the state db's `admin` row names the administrator and holds a
//! PBKDF2-HMAC-SHA256 hash of the password. Sessions are opaque random tokens kept in memory as
//! SHA-256 digests; a restart forgets them all.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use hmac::Mac as _;
use hmac::digest::KeyInit as _;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use parking_lot::Mutex;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use rusqlite::{OptionalExtension as _, TransactionBehavior};

use crate::state::{DIR_FLAGS, StateDb, effective_uid};

#[cfg(test)]
mod tests;

/// Where releases before the state db kept the record, below the data directory.
pub(crate) const LEGACY_DIR: &str = "native-api";
pub(crate) const LEGACY_RECORD: &str = "admin.json";
const RECORD_LIMIT: usize = 4096;
/// A login costs this many HMAC rounds: about a tenth of a second on a router-class CPU, which
/// only the administrator pays, and enough that a stolen record is not cheap to guess against.
pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;
const ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = 100_000..=1_000_000;
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
pub(crate) const SESSION_LIMIT: usize = 32;
const TOKEN_PREFIX: &str = "hnk1_";

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// RFC 8018 §5.2 with HMAC-SHA256 and a single 32-byte block.
pub(crate) fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let keyed =
        <hmac::Hmac<Sha256>>::new_from_slice(password).expect("HMAC accepts any key length");
    let mut mac = keyed.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
    let mut output = block;
    for _ in 1..iterations {
        let mut mac = keyed.clone();
        mac.update(&block);
        block = mac.finalize().into_bytes().into();
        for (out, byte) in output.iter_mut().zip(block) {
            *out ^= byte;
        }
    }
    output
}

pub(crate) fn valid_username(username: &str) -> bool {
    (1..=64).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub(crate) fn valid_password(password: &str) -> bool {
    let scalars = password.chars().count();
    (8..=128).contains(&scalars) && password.len() <= 512
}

/// The stored administrator: everything needed to verify a login, nothing that reveals the password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) username: String,
    pub(crate) iterations: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: u32,
    username: String,
    algorithm: String,
    iterations: u32,
    salt: String,
    hash: String,
}

impl Record {
    pub(crate) fn create(username: &str, password: &str) -> Option<Self> {
        if !valid_username(username) || !valid_password(password) {
            return None;
        }
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        Some(Self {
            username: username.to_owned(),
            iterations: PBKDF2_ITERATIONS,
            salt,
            hash: pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS),
        })
    }

    /// Always runs the full derivation, so a wrong username costs the same as a wrong password.
    pub(crate) fn verify(&self, username: &str, password: &str) -> bool {
        let expected: [u8; 32] = Sha256::digest(self.username.as_bytes()).into();
        let given: [u8; 32] = Sha256::digest(username.as_bytes()).into();
        let name_ok = expected.ct_eq(&given);
        let derived = pbkdf2_sha256(password.as_bytes(), &self.salt, self.iterations);
        bool::from(name_ok & derived.ct_eq(&self.hash))
    }

    fn to_json(&self) -> Vec<u8> {
        let file = RecordFile {
            version: 1,
            username: self.username.clone(),
            algorithm: "pbkdf2-hmac-sha256".to_owned(),
            iterations: self.iterations,
            salt: BASE64.encode(self.salt),
            hash: BASE64.encode(self.hash),
        };
        let mut json = serde_json::to_vec(&file).expect("record serialises");
        json.push(b'\n');
        json
    }

    fn from_json(bytes: &[u8]) -> Result<Self, StoreError> {
        let file: RecordFile = serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
        if file.version != 1
            || file.algorithm != "pbkdf2-hmac-sha256"
            || !ITERATIONS_RANGE.contains(&file.iterations)
            || !valid_username(&file.username)
        {
            return Err(StoreError::Corrupt);
        }
        let salt = BASE64.decode(&file.salt).map_err(|_| StoreError::Corrupt)?;
        let hash = BASE64.decode(&file.hash).map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            username: file.username,
            iterations: file.iterations,
            salt: salt.try_into().map_err(|_| StoreError::Corrupt)?,
            hash: hash.try_into().map_err(|_| StoreError::Corrupt)?,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StoreError {
    #[error("credential store is unusable: {0}")]
    Unavailable(&'static str),
    #[error("legacy credential directory or record is not private to this user")]
    Unsafe,
    #[error("credential record is corrupt or unsupported")]
    Corrupt,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SetupError {
    #[error("an administrator already exists")]
    AlreadyCompleted,
    #[error("the record could not be written")]
    Unavailable,
    /// The row may or may not be durable; nothing may rely on it until a restart.
    #[error("the record was written but not confirmed durable")]
    NotDurable,
}

/// The administrator record in the state db's `admin` row.
pub(crate) struct CredentialStore {
    db: Arc<StateDb>,
    state: Mutex<StoreState>,
}

#[derive(Default)]
struct StoreState {
    record: Option<Record>,
    /// Set after a write whose durability was not confirmed: no login, no second setup.
    blocked: bool,
}

impl CredentialStore {
    /// Imports a legacy `<data_dir>/native-api/admin.json`, then reads the record if present.
    /// A record that fails its checks fails closed. Call with the instance lock held.
    pub(crate) fn open(db: Arc<StateDb>, data_dir: &Path) -> Result<Self, StoreError> {
        import_admin_json(&db, data_dir)?;
        let record: Option<String> = db
            .strict()
            .query_row("SELECT record FROM admin WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| StoreError::Unavailable("state db"))?;
        let record = record
            .map(|record| Record::from_json(record.as_bytes()))
            .transpose()?;
        Ok(Self {
            db,
            state: Mutex::new(StoreState {
                record,
                blocked: false,
            }),
        })
    }

    pub(crate) fn setup_required(&self) -> bool {
        self.state.lock().record.is_none()
    }

    /// Verifies a login against the stored record; false while there is no record or the store is blocked.
    pub(crate) fn verify(&self, username: &str, password: &str) -> bool {
        let record = {
            let state = self.state.lock();
            if state.blocked {
                return false;
            }
            state.record.clone()
        };
        record.is_some_and(|record| record.verify(username, password))
    }

    /// Publishes the first administrator without replacing anything: a second creator, racing or
    /// not, in this process or another, sees `AlreadyCompleted`.
    pub(crate) fn setup(&self, username: &str, password: &str) -> Result<(), SetupError> {
        let record = Record::create(username, password).ok_or(SetupError::Unavailable)?;
        let mut state = self.state.lock();
        if state.record.is_some() || state.blocked {
            return Err(SetupError::AlreadyCompleted);
        }
        let json = String::from_utf8(record.to_json()).map_err(|_| SetupError::Unavailable)?;
        let mut connection = self.db.strict();
        // Nothing is written yet if the transaction cannot start, for example while busy.
        let Ok(transaction) = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        else {
            return Err(SetupError::Unavailable);
        };
        let result = (move || {
            transaction.execute("INSERT INTO admin (id, record) VALUES (1, ?1)", [&json])?;
            transaction.commit()
        })();
        match result {
            Ok(()) => {
                state.record = Some(record);
                Ok(())
            }
            Err(error)
                if error.sqlite_error().is_some_and(|error| {
                    error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                }) =>
            {
                Err(SetupError::AlreadyCompleted)
            }
            Err(_) => {
                // Failing at the statement or at COMMIT leaves the row's durability unknown.
                state.blocked = true;
                Err(SetupError::NotDurable)
            }
        }
    }
}

/// Copies a legacy `admin.json` into the `admin` row once, unless a row exists,
/// then unlinks it and removes `native-api/` if that left it empty.
fn import_admin_json(db: &StateDb, data_dir: &Path) -> Result<(), StoreError> {
    let parent = File::from(
        open(data_dir, DIR_FLAGS, Mode::empty())
            .map_err(|_| StoreError::Unavailable("data directory"))?,
    );
    let directory = match openat(&parent, LEGACY_DIR, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::ENOENT) => return Ok(()),
        Err(Errno::ELOOP | Errno::ENOTDIR) => return Err(StoreError::Unsafe),
        Err(_) => return Err(StoreError::Unavailable("legacy credential directory")),
    };
    let metadata = directory
        .metadata()
        .map_err(|_| StoreError::Unavailable("legacy credential directory"))?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(StoreError::Unsafe);
    }
    let Some(record) = read_record(&directory)? else {
        return Ok(());
    };
    let source = format!("admin.json:{}", data_dir.join(LEGACY_DIR).display());
    // Whether this call inserted the row; `None` when an earlier start had
    // already imported this file's location.
    let copied = (|| -> rusqlite::Result<Option<bool>> {
        let mut connection = db.strict();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let done: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM legacy_import WHERE source = ?1",
                [&source],
                |row| row.get(0),
            )
            .optional()?;
        let mut inserted = None;
        if done.is_none() {
            let json = String::from_utf8_lossy(&record.to_json()).into_owned();
            inserted = Some(
                transaction.execute(
                    "INSERT OR IGNORE INTO admin (id, record) VALUES (1, ?1)",
                    [&json],
                )? == 1,
            );
            transaction.execute(
                "INSERT INTO legacy_import (source, done_at) VALUES (?1, ?2)",
                rusqlite::params![source, unix_now_secs()],
            )?;
        }
        transaction.commit()?;
        Ok(inserted)
    })();
    let inserted = copied.map_err(|_| StoreError::Unavailable("state db"))?;
    unlinkat(&directory, LEGACY_RECORD, UnlinkatFlags::NoRemoveDir)
        .map_err(|_| StoreError::Unavailable("legacy credential record"))?;
    directory
        .sync_all()
        .map_err(|_| StoreError::Unavailable("legacy credential directory"))?;
    // Fails while anything else is left in it.
    let _ = unlinkat(&parent, LEGACY_DIR, UnlinkatFlags::RemoveDir);
    match inserted {
        Some(true) => {
            tracing::info!("imported the administrator record from native-api/admin.json")
        }
        Some(false) => tracing::warn!(
            "native-api/admin.json removed without import: the state db already has an administrator"
        ),
        None => tracing::warn!(
            "native-api/admin.json removed without import: an earlier start imported this location, so the file is from an older binary"
        ),
    }
    Ok(())
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

fn read_record(directory: &File) -> Result<Option<Record>, StoreError> {
    let file = match openat(
        directory,
        LEGACY_RECORD,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::ENOENT) => return Ok(None),
        Err(Errno::ELOOP) => return Err(StoreError::Unsafe),
        Err(_) => return Err(StoreError::Unavailable("credential record")),
    };
    let metadata = file
        .metadata()
        .map_err(|_| StoreError::Unavailable("credential record"))?;
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(StoreError::Unsafe);
    }
    if metadata.len() > RECORD_LIMIT as u64 {
        return Err(StoreError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&file)
        .take(RECORD_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Unavailable("credential record"))?;
    if bytes.len() > RECORD_LIMIT {
        return Err(StoreError::Corrupt);
    }
    Record::from_json(&bytes).map(Some)
}

/// Sessions issued by login: at most `SESSION_LIMIT`, each `SESSION_LIFETIME` long, known only by digest.
#[derive(Default)]
pub(crate) struct Sessions {
    inner: Mutex<Vec<Session>>,
}

struct Session {
    digest: [u8; 32],
    issued: Instant,
    expires: Instant,
}

pub(crate) struct Issued {
    pub(crate) token: String,
    pub(crate) expires_at: SystemTime,
}

impl Sessions {
    pub(crate) fn issue(&self) -> Issued {
        self.issue_at(Instant::now(), SystemTime::now())
    }

    fn issue_at(&self, now: Instant, wall: SystemTime) -> Issued {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let token = format!("{TOKEN_PREFIX}{}", BASE64.encode(bytes));
        let mut sessions = self.inner.lock();
        sessions.retain(|session| session.expires > now);
        while sessions.len() >= SESSION_LIMIT {
            let oldest = sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, session)| session.issued)
                .map(|(index, _)| index)
                .expect("non-empty");
            sessions.swap_remove(oldest);
        }
        sessions.push(Session {
            digest: Sha256::digest(token.as_bytes()).into(),
            issued: now,
            expires: now + SESSION_LIFETIME,
        });
        Issued {
            token,
            expires_at: wall + SESSION_LIFETIME,
        }
    }

    /// Whether `token` names a live session; every stored digest is compared so timing does not say which matched.
    pub(crate) fn authenticate(&self, token: &str) -> bool {
        self.authenticate_at(token, Instant::now())
    }

    fn authenticate_at(&self, token: &str, now: Instant) -> bool {
        if !token.starts_with(TOKEN_PREFIX) {
            return false;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let sessions = self.inner.lock();
        let mut found = subtle::Choice::from(0);
        for session in sessions.iter().filter(|session| session.expires > now) {
            found |= session.digest.ct_eq(&digest);
        }
        bool::from(found)
    }

    /// Ends the session; returns whether one was ended.
    pub(crate) fn revoke(&self, token: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut sessions = self.inner.lock();
        let before = sessions.len();
        sessions.retain(|session| !bool::from(session.digest.ct_eq(&digest)));
        sessions.len() != before
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

/// Login admission: per-peer and global attempt windows, one credential worker, and a global lock
/// after repeated credential failures. Counters are process-local and reset with the process.
pub(crate) struct AuthRate {
    inner: Mutex<RateState>,
}

struct RateState {
    peers: std::collections::HashMap<std::net::IpAddr, Vec<Instant>>,
    global: Vec<Instant>,
    failures: u32,
    locked_until: Option<Instant>,
}

/// Attempts allowed per peer and overall in one minute, and the lock after consecutive failures.
pub(crate) const PEER_ATTEMPTS: usize = 5;
pub(crate) const GLOBAL_ATTEMPTS: usize = 10;
pub(crate) const FAILURES_BEFORE_LOCK: u32 = 5;
pub(crate) const LOCK: Duration = Duration::from_secs(60);
const WINDOW: Duration = Duration::from_secs(60);
const PEER_LIMIT: usize = 1024;

impl Default for AuthRate {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RateState {
                peers: std::collections::HashMap::new(),
                global: Vec::new(),
                failures: 0,
                locked_until: None,
            }),
        }
    }
}

impl AuthRate {
    /// Seconds the caller must wait, or `None` when the attempt may proceed.
    pub(crate) fn admit(&self, peer: std::net::IpAddr) -> Option<u32> {
        self.admit_at(peer, Instant::now())
    }

    fn admit_at(&self, peer: std::net::IpAddr, now: Instant) -> Option<u32> {
        let mut state = self.inner.lock();
        if let Some(until) = state.locked_until {
            if until > now {
                return Some(seconds_until(until, now));
            }
            state.locked_until = None;
            state.failures = 0;
        }
        state.global.retain(|at| now.duration_since(*at) < WINDOW);
        state
            .peers
            .retain(|_, attempts| attempts.iter().any(|at| now.duration_since(*at) < WINDOW));
        if state.global.len() >= GLOBAL_ATTEMPTS {
            let oldest = state.global[0];
            return Some(seconds_until(oldest + WINDOW, now));
        }
        let known = state.peers.contains_key(&peer);
        if !known && state.peers.len() >= PEER_LIMIT {
            return Some(WINDOW.as_secs() as u32);
        }
        let attempts = state.peers.entry(peer).or_default();
        attempts.retain(|at| now.duration_since(*at) < WINDOW);
        if attempts.len() >= PEER_ATTEMPTS {
            let oldest = attempts[0];
            return Some(seconds_until(oldest + WINDOW, now));
        }
        attempts.push(now);
        state.global.push(now);
        None
    }

    /// A wrong credential; the global lock closes after `FAILURES_BEFORE_LOCK` in a row.
    pub(crate) fn failed(&self) {
        self.failed_at(Instant::now());
    }

    fn failed_at(&self, now: Instant) {
        let mut state = self.inner.lock();
        state.failures += 1;
        if state.failures >= FAILURES_BEFORE_LOCK {
            state.locked_until = Some(now + LOCK);
        }
    }

    pub(crate) fn succeeded(&self) {
        let mut state = self.inner.lock();
        state.failures = 0;
        state.locked_until = None;
    }
}

fn seconds_until(deadline: Instant, now: Instant) -> u32 {
    deadline.saturating_duration_since(now).as_secs().max(1) as u32
}

/// Everything password mode owns: the record, the live sessions and the login admission.
pub(crate) struct Auth {
    pub(crate) store: CredentialStore,
    pub(crate) sessions: Sessions,
    pub(crate) rate: AuthRate,
}

impl Auth {
    pub(crate) fn open(db: Arc<StateDb>, data_dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            store: CredentialStore::open(db, data_dir)?,
            sessions: Sessions::default(),
            rate: AuthRate::default(),
        })
    }
}

// ---- HTTP endpoints -------------------------------------------------------

use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::types::RequestId;

use super::{ApiError, ErrorCode, NativeState, Peer, error};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}

/// The listener runs in password mode, or these endpoints do not exist.
fn required<'a>(state: &'a NativeState, id: &RequestId) -> Result<&'a Auth, ApiError> {
    state.auth.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Password login is not enabled on this listener",
            Some(id.0.clone()),
        )
    })
}

async fn credentials(request: Request, id: &RequestId) -> Result<Credentials, ApiError> {
    let json_body = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim() == "application/json")
        });
    if !json_body {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Credentials require application/json",
            Some(id.0.clone()),
        ));
    }
    if request.uri().query().is_some() {
        return Err(invalid(id));
    }
    // The boundary has already read the body into memory and bounded its size.
    let bytes = axum::body::to_bytes(request.into_body(), RECORD_LIMIT)
        .await
        .map_err(|_| invalid(id))?;
    let credentials: Credentials = serde_json::from_slice(&bytes).map_err(|_| invalid(id))?;
    if !valid_username(&credentials.username) || !valid_password(&credentials.password) {
        return Err(invalid(id));
    }
    Ok(credentials)
}

fn invalid(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Credentials require a username and a password of 8 to 128 characters",
        Some(id.0.clone()),
    )
}

/// One shape for a wrong username and a wrong password, so neither can be probed.
fn rejected(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        ErrorCode::InvalidCredentials,
        "Username or password is not correct",
        Some(id.0.clone()),
    )
}

fn issued(session: Issued) -> Response {
    let expires_at = super::timestamp(session.expires_at);
    Json(json!({"token": session.token, "expires_at": expires_at})).into_response()
}

fn admit(auth: &Auth, peer: Peer, id: &RequestId) -> Result<(), ApiError> {
    match auth.rate.admit(peer.0) {
        None => Ok(()),
        Some(after) => Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "Too many login attempts",
            Some(id.0.clone()),
        )
        .with_retry_after(after)),
    }
}

/// Claims the one administrator account. Only a loopback or private peer may do this, and only while
/// no account exists; deriving the peer from a header would let anyone claim it through a proxy.
pub(super) async fn setup(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let result = async {
        let auth = required(&state, &id)?;
        let peer = *request
            .extensions()
            .get::<Peer>()
            .ok_or_else(|| forbidden_setup(&id))?;
        if !peer.may_set_up() {
            return Err(forbidden_setup(&id));
        }
        admit(auth, peer, &id)?;
        if !auth.store.setup_required() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::SetupAlreadyCompleted,
                "An administrator already exists",
                Some(id.0.clone()),
            ));
        }
        let credentials = credentials(request, &id).await?;
        match auth
            .store
            .setup(&credentials.username, &credentials.password)
        {
            Ok(()) => {
                auth.rate.succeeded();
                Ok((StatusCode::CREATED, issued(auth.sessions.issue())).into_response())
            }
            Err(SetupError::AlreadyCompleted) => Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::SetupAlreadyCompleted,
                "An administrator already exists",
                Some(id.0.clone()),
            )),
            Err(SetupError::NotDurable) => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "The administrator was written but its directory did not sync",
                Some(id.0.clone()),
            )
            .with_details(json!({"written": true, "durability_confirmed": false}))),
            Err(SetupError::Unavailable) => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "The administrator record could not be written",
                Some(id.0.clone()),
            )),
        }
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

fn forbidden_setup(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "Administrator setup is allowed from loopback and private addresses only",
        Some(id.0.clone()),
    )
}

pub(super) async fn login(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let result = async {
        let auth = required(&state, &id)?;
        let peer = *request
            .extensions()
            .get::<Peer>()
            .ok_or_else(|| rejected(&id))?;
        admit(auth, peer, &id)?;
        if auth.store.setup_required() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::SetupRequired,
                "No administrator exists yet",
                Some(id.0.clone()),
            ));
        }
        let credentials = credentials(request, &id).await?;
        if !auth
            .store
            .verify(&credentials.username, &credentials.password)
        {
            auth.rate.failed();
            return Err(rejected(&id));
        }
        auth.rate.succeeded();
        Ok(issued(auth.sessions.issue()))
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn logout(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Password login is not enabled on this listener",
            &id,
        )
        .into_response();
    };
    // The boundary admitted this request, so the bearer is a live session.
    if let Some(token) = state.security_bearer(&request) {
        auth.sessions.revoke(token);
    }
    StatusCode::NO_CONTENT.into_response()
}
