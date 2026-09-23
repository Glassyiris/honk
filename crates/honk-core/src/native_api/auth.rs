//! Administrator credentials and sessions for password mode.
//!
//! One record in `<data_dir>/native-api/admin.json` names the administrator and holds a
//! PBKDF2-HMAC-SHA256 hash of the password. Sessions are opaque random tokens kept in memory as
//! SHA-256 digests; a restart forgets them all.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use hmac::Mac as _;
use hmac::digest::KeyInit as _;
use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::fcntl::{Flock, FlockArg, OFlag, open, openat};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, linkat, unlinkat};
use parking_lot::Mutex;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::state::{DIR_FLAGS, effective_uid};

#[cfg(test)]
mod tests;

/// Directory under the data directory that holds the record; mode 0700.
pub(crate) const CREDENTIAL_DIR: &str = "native-api";
pub(crate) const RECORD_FILE: &str = "admin.json";
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
    (12..=128).contains(&scalars) && password.len() <= 512
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
    #[error("credential directory is unusable: {0}")]
    Unavailable(&'static str),
    #[error("credential directory or record is not private to this user")]
    Unsafe,
    #[error("credential record is corrupt or unsupported")]
    Corrupt,
    #[error("another honk process holds the credential directory")]
    Locked,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SetupError {
    #[error("an administrator already exists")]
    AlreadyCompleted,
    #[error("the record could not be written")]
    Unavailable,
    /// The record is visible but the directory did not sync; nothing may rely on it until a restart.
    #[error("the record was written but not confirmed durable")]
    NotDurable,
}

/// The credential directory, held open and locked for the life of the process.
pub(crate) struct CredentialStore {
    directory: Flock<File>,
    state: Mutex<StoreState>,
}

#[derive(Default)]
struct StoreState {
    record: Option<Record>,
    /// Set after a write whose durability was not confirmed: no login, no second setup.
    blocked: bool,
}

impl CredentialStore {
    /// Opens `<data_dir>/native-api`, creating it 0700 if absent, and reads the record if present.
    /// Anything that is not a private directory holding a valid record, or no record, fails closed.
    pub(crate) fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let parent = File::from(
            open(data_dir, DIR_FLAGS, Mode::empty())
                .map_err(|_| StoreError::Unavailable("data directory"))?,
        );
        match mkdirat(&parent, CREDENTIAL_DIR, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(_) => return Err(StoreError::Unavailable("credential directory")),
        }
        let directory = File::from(
            openat(&parent, CREDENTIAL_DIR, DIR_FLAGS, Mode::empty())
                .map_err(|_| StoreError::Unavailable("credential directory"))?,
        );
        let metadata = directory
            .metadata()
            .map_err(|_| StoreError::Unavailable("credential directory"))?;
        if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
            return Err(StoreError::Unsafe);
        }
        let directory = Flock::lock(directory, FlockArg::LockExclusiveNonblock)
            .map_err(|_| StoreError::Locked)?;
        let record = read_record(&directory)?;
        Ok(Self {
            directory,
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
    /// not, sees `AlreadyCompleted`. The record is fsynced, linked into place, then the directory synced.
    pub(crate) fn setup(&self, username: &str, password: &str) -> Result<(), SetupError> {
        let record = Record::create(username, password).ok_or(SetupError::Unavailable)?;
        let mut state = self.state.lock();
        if state.record.is_some() || state.blocked {
            return Err(SetupError::AlreadyCompleted);
        }
        let name = format!(".admin-{}.tmp", uuid::Uuid::new_v4());
        let mut file = File::from(
            openat(
                &*self.directory,
                name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(|_| SetupError::Unavailable)?,
        );
        let written = file
            .write_all(&record.to_json())
            .and_then(|()| file.sync_all())
            .map_err(|_| SetupError::Unavailable);
        let linked = written.and_then(|()| {
            linkat(
                &*self.directory,
                name.as_str(),
                &*self.directory,
                RECORD_FILE,
                AtFlags::empty(),
            )
            .map_err(|error| {
                if error == Errno::EEXIST {
                    SetupError::AlreadyCompleted
                } else {
                    SetupError::Unavailable
                }
            })
        });
        let _ = unlinkat(&*self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir);
        linked?;
        if self.directory.sync_all().is_err() {
            state.blocked = true;
            return Err(SetupError::NotDurable);
        }
        state.record = Some(record);
        Ok(())
    }
}

fn read_record(directory: &File) -> Result<Option<Record>, StoreError> {
    let file = match openat(
        directory,
        RECORD_FILE,
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
    pub(crate) fn open(data_dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            store: CredentialStore::open(data_dir)?,
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
use std::sync::Arc;

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
        "Credentials require a username and a password of 12 to 128 characters",
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
