//! Mercury audit writer.
//!
//! Records are appended to a JSON-L file, one JSON object per line. With
//! integrity enabled (the default) every record carries a chained HMAC and a
//! sequence number that continue across daemon restarts, size rotation and
//! SIGHUP reopen, so edits, removed records and removed files are detectable
//! with [`verify_chain`]. Records are optionally mirrored to journald.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use core_types::{AUDIT_SCHEMA_VERSION, ActionType, AuditEvent, Decision, SystemResource};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod chain;
#[cfg(unix)]
mod journal;

pub use chain::{
    ChainIssue, ChainReport, EVENT_CHAIN_LINK, EVENT_CHAIN_START, EVENT_FILE_EXPIRED, FileReport,
    IssueKind, Severity, VerifyOptions, load_key, order_rotation_files, parse_key_hex,
    rotation_set, verify_chain,
};
#[cfg(unix)]
pub use journal::encode_journal_fields;

use chain::{ChainState, TailState, ZERO_MAC};

pub const DEFAULT_AUDIT_PATH: &str = "/var/log/mercury/audit.jsonl";
/// Auto-generated (0600) when integrity is on and no key is configured.
pub const DEFAULT_INTEGRITY_KEY_PATH: &str = "/var/lib/mercury/audit-integrity.key";
pub const DEFAULT_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_FILES: usize = 10;
/// `context.source` of the records the audit writer emits about itself.
pub const AUDIT_SOURCE: &str = "audit";
/// Unsigned system event written when the default key cannot be loaded or
/// created and the log continues without integrity.
pub const EVENT_INTEGRITY_UNAVAILABLE: &str = "audit_integrity_unavailable";

/// Longest a dirty log waits for fdatasync in `interval` mode.
const SYNC_INTERVAL: Duration = Duration::from_secs(1);
/// Minimum spacing of the early syncs triggered by denies and system events.
const URGENT_SYNC_GAP: Duration = Duration::from_millis(100);
const NO_POLICY_VERSION: &str = "-";

/// When the audit log is flushed to stable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsyncMode {
    /// Never fdatasync; the kernel writes back on its own schedule.
    None,
    /// fdatasync at most once per second while dirty, and within ~100 ms of a
    /// DENY or SYSTEM_EVENT record. Also on rotation, reopen and close.
    #[default]
    Interval,
    /// fdatasync after every record.
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournaldMirrorMode {
    /// journald native protocol on `/run/systemd/journal/socket`.
    #[default]
    Native,
    /// Pre-v2 behavior: an RFC 3164 line on journald's syslog forwarding
    /// socket, which only a local syslog daemon reads.
    Syslog,
}

/// Where the integrity key comes from.
#[derive(Clone, PartialEq, Eq)]
pub enum IntegrityKeySource {
    Disabled,
    /// Existing 64-hex-character key file; missing or invalid is an error.
    File(PathBuf),
    /// Key file created (0600) on first use. When it cannot be read or
    /// created the log continues unsigned: the failure is logged, recorded
    /// in [`AuditStats::last_error`] and written to the log as an
    /// `audit_integrity_unavailable` system event.
    AutoGenerate(PathBuf),
    /// Key material resolved from a secret reference; never written to disk.
    Hex(String),
}

impl fmt::Debug for IntegrityKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::AutoGenerate(path) => f.debug_tuple("AutoGenerate").field(path).finish(),
            Self::Hex(_) => f.write_str("Hex(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub jsonl_path: PathBuf,
    /// Rotate when the active file reaches this size.
    pub max_bytes: u64,
    /// Rotated files kept (`<path>.1` .. `<path>.<max_files>`) besides the
    /// active file. The oldest is deleted after an `audit_file_expired`
    /// record describing it is written.
    pub max_files: usize,
    /// Mirror audit events to journald (Linux only; ignored on other platforms).
    pub mirror_to_journald: bool,
    pub journald_mirror_mode: JournaldMirrorMode,
    /// Socket override for the mirror (tests, containers); defaults to the
    /// standard socket of `journald_mirror_mode`.
    pub journald_socket_path: Option<PathBuf>,
    pub integrity: IntegrityKeySource,
    pub fsync: FsyncMode,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            jsonl_path: PathBuf::from(DEFAULT_AUDIT_PATH),
            max_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            mirror_to_journald: true,
            journald_mirror_mode: JournaldMirrorMode::default(),
            journald_socket_path: None,
            integrity: IntegrityKeySource::AutoGenerate(PathBuf::from(DEFAULT_INTEGRITY_KEY_PATH)),
            fsync: FsyncMode::default(),
        }
    }
}

/// Counters for monitoring the audit writer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStats {
    /// Lines written to the audit file, including chain bookkeeping records.
    pub records_written: u64,
    /// Failed writes, rotations, reopens and fdatasyncs.
    pub write_failures: u64,
    /// Records that could not be mirrored to journald at all.
    pub mirror_failures: u64,
    /// Records mirrored without (part of) their JSON because of size.
    pub mirror_truncated: u64,
    pub rotations: u64,
    pub files_expired: u64,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub integrity_enabled: bool,
    /// Sequence number of the last signed record.
    pub chain_seq: Option<u64>,
}

#[derive(Default)]
struct Counters {
    records_written: AtomicU64,
    write_failures: AtomicU64,
    mirror_failures: AtomicU64,
    mirror_truncated: AtomicU64,
    rotations: AtomicU64,
    files_expired: AtomicU64,
    last_error: Mutex<Option<(String, DateTime<Utc>)>>,
}

struct Writer {
    file: File,
    /// (dev, inode) of `file`, to notice the path being replaced or removed.
    identity: Option<(u64, u64)>,
    /// None when integrity is off.
    chain: Option<ChainState>,
    dirty: bool,
    last_sync: Instant,
    /// The file ends inside a cut-off record; start the next one on a new line.
    needs_newline: bool,
}

#[derive(Default)]
struct FlushSignal {
    urgent: bool,
    shutdown: bool,
}

struct Stamped {
    json: String,
    event_id: String,
}

/// A record written under the file lock, mirrored after the lock is released.
struct PendingMirror {
    event: AuditEvent,
    stamped: Stamped,
    seq: Option<u64>,
}

struct Inner {
    config: AuditConfig,
    key: Option<[u8; 32]>,
    host: Option<String>,
    writer: Mutex<Writer>,
    #[cfg(unix)]
    mirror: Option<journal::JournalMirror>,
    stats: Counters,
    signal: Mutex<FlushSignal>,
    signal_cv: Condvar,
}

pub struct AuditLogger {
    inner: Arc<Inner>,
    flusher: Option<JoinHandle<()>>,
}

impl fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLogger")
            .field("jsonl_path", &self.inner.config.jsonl_path)
            .field("integrity", &self.inner.key.is_some())
            .field("fsync", &self.inner.config.fsync)
            .finish_non_exhaustive()
    }
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Result<Self, AuditError> {
        if let Some(parent) = parent_dir(&config.jsonl_path) {
            fs::create_dir_all(parent).map_err(AuditError::Io)?;
        }
        let (key, key_problem) = load_integrity_key(&config.integrity)?;

        let tail = match chain::read_tail(&config.jsonl_path, 2) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(chain::Tail::default()),
            other => other,
        };
        let needs_newline = tail.as_ref().is_ok_and(|tail| tail.torn);
        if needs_newline {
            warn!(
                path = %config.jsonl_path.display(),
                "audit log ends inside a cut-off record; continuing on a new line"
            );
        }
        let tail_state = key.as_ref().map(|key| match &tail {
            Ok(tail) => chain::analyze_tail(tail, key),
            Err(err) => {
                warn!(error = %err, "cannot read the audit log tail; starting a new chain");
                TailState::Restart {
                    reason: "unreadable_tail",
                    last_seq: None,
                }
            }
        });

        let file = open_append(&config.jsonl_path)?;
        let stats = Counters::default();
        #[cfg(unix)]
        let mirror = if config.mirror_to_journald {
            match journal::JournalMirror::new(
                config.journald_mirror_mode,
                config.journald_socket_path.clone(),
            ) {
                Ok(mirror) => {
                    if !mirror.target().exists() {
                        warn!(
                            socket = %mirror.target().display(),
                            "journald socket not found; audit mirroring will fail until it exists"
                        );
                    }
                    Some(mirror)
                }
                Err(err) => {
                    error!(error = %err, "failed to create journald socket; continuing without mirror");
                    set_last_error(&stats, format!("journald mirror unavailable: {err}"));
                    None
                }
            }
        } else {
            None
        };

        let inner = Arc::new(Inner {
            host: hostname(),
            writer: Mutex::new(Writer {
                identity: file_identity(&file),
                file,
                chain: None,
                dirty: false,
                last_sync: Instant::now(),
                needs_newline,
            }),
            #[cfg(unix)]
            mirror,
            stats,
            signal: Mutex::new(FlushSignal::default()),
            signal_cv: Condvar::new(),
            key,
            config,
        });
        inner.initialize(tail_state, key_problem)?;

        let flusher = if inner.config.fsync == FsyncMode::Interval {
            let worker = Arc::clone(&inner);
            Some(
                thread::Builder::new()
                    .name("audit-fsync".to_string())
                    .spawn(move || flusher_loop(worker))
                    .map_err(AuditError::Io)?,
            )
        } else {
            None
        };
        Ok(Self { inner, flusher })
    }

    /// Writes one record. Missing `event_id`, `schema_version` and `host`
    /// are filled in. The record is mirrored to journald even when the file
    /// write fails; every failure is counted in [`AuditLogger::stats`].
    pub fn log(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let inner = &self.inner;
        let stamped = inner
            .stamp(event)
            .inspect_err(|err| inner.record_write_failure(err))?;
        let mut pending = Vec::new();
        let written = inner.write_record(&stamped.json, &mut pending);

        debug!(
            agent_id = %event.agent_id,
            action = ?event.action_type,
            decision = ?event.decision,
            reason = %event.reason,
            rule_id = ?event.rule_id,
            profile = %event.profile,
            policy_version = %event.policy_version,
            "ai guard decision"
        );

        inner.mirror_pending(pending);
        inner.mirror(event, &stamped, written.as_ref().ok().copied().flatten());
        if inner.config.fsync == FsyncMode::Interval && written.is_ok() && is_urgent(event) {
            inner.request_sync();
        }
        written.map(|_| ())
    }

    /// Reopens the audit log at the configured path, e.g. after an external
    /// `logrotate` rename. When the path now names a different file, the new
    /// file starts with an `audit_chain_link` record pointing back at the
    /// previous one; when it is the same file this is a no-op.
    pub fn reopen(&self) -> Result<(), AuditError> {
        let mut pending = Vec::new();
        let result = self.inner.reopen(&mut pending);
        self.inner.mirror_pending(pending);
        result.inspect_err(|err| self.inner.record_write_failure(err))
    }

    /// fdatasyncs the active file now.
    pub fn sync(&self) -> Result<(), AuditError> {
        let mut writer = self.inner.lock_writer()?;
        writer.file.sync_data().map_err(|err| {
            self.inner.record_write_failure(&err);
            AuditError::Io(err)
        })?;
        writer.dirty = false;
        writer.last_sync = Instant::now();
        Ok(())
    }

    pub fn stats(&self) -> AuditStats {
        let stats = &self.inner.stats;
        let last_error = stats
            .last_error
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let (last_error, last_error_at) = match last_error {
            Some((message, at)) => (Some(message), Some(at)),
            None => (None, None),
        };
        AuditStats {
            records_written: stats.records_written.load(Ordering::Relaxed),
            write_failures: stats.write_failures.load(Ordering::Relaxed),
            mirror_failures: stats.mirror_failures.load(Ordering::Relaxed),
            mirror_truncated: stats.mirror_truncated.load(Ordering::Relaxed),
            rotations: stats.rotations.load(Ordering::Relaxed),
            files_expired: stats.files_expired.load(Ordering::Relaxed),
            last_error,
            last_error_at,
            integrity_enabled: self.inner.key.is_some(),
            chain_seq: self
                .inner
                .writer
                .lock()
                .ok()
                .and_then(|writer| writer.chain.map(|chain| chain.seq)),
        }
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        if let Some(handle) = self.flusher.take() {
            lock_ignore_poison(&self.inner.signal).shutdown = true;
            self.inner.signal_cv.notify_all();
            let _ = handle.join();
        }
        if self.inner.config.fsync != FsyncMode::None
            && let Ok(mut writer) = self.inner.writer.lock()
            && writer.dirty
        {
            match writer.file.sync_data() {
                Ok(()) => writer.dirty = false,
                Err(err) => warn!(error = %err, "failed to fdatasync the audit log on close"),
            }
        }
    }
}

impl Inner {
    fn lock_writer(&self) -> Result<MutexGuard<'_, Writer>, AuditError> {
        self.writer.lock().map_err(|_| {
            let err = AuditError::Poison("audit file mutex poisoned".to_string());
            self.record_write_failure(&err);
            err
        })
    }

    fn record_write_failure(&self, err: &dyn fmt::Display) {
        self.stats.write_failures.fetch_add(1, Ordering::Relaxed);
        set_last_error(&self.stats, format!("audit write: {err}"));
    }

    /// Writes the key-problem record and positions the chain: resume from
    /// the file tail, link to the most recent rotated file, or start anew.
    fn initialize(
        &self,
        tail_state: Option<TailState>,
        key_problem: Option<String>,
    ) -> Result<(), AuditError> {
        let mut pending = Vec::new();
        let result = self.initialize_locked(tail_state, key_problem, &mut pending);
        self.mirror_pending(pending);
        result
    }

    fn initialize_locked(
        &self,
        tail_state: Option<TailState>,
        key_problem: Option<String>,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        let mut writer = self.lock_writer()?;
        if let Some(problem) = key_problem {
            set_last_error(&self.stats, format!("audit integrity disabled: {problem}"));
            let event = AuditEvent::system(
                AUDIT_SOURCE,
                SystemResource::new(EVENT_INTEGRITY_UNAVAILABLE).detail(problem),
                NO_POLICY_VERSION,
                "audit integrity chain disabled: the integrity key could not be loaded or created",
            );
            self.write_internal_locked(&mut writer, event, pending)?;
        }
        let Some(state) = tail_state else {
            return Ok(());
        };
        match state {
            TailState::Resume(chain) => {
                info!(seq = chain.seq, path = %self.config.jsonl_path.display(), "resuming audit integrity chain");
                writer.chain = Some(chain);
                Ok(())
            }
            TailState::Empty => match self.previous_file_chain() {
                Some((prev_file, chain)) => {
                    writer.chain = Some(chain);
                    self.write_link_locked(&mut writer, "open", Some(prev_file), pending)
                }
                None => self.start_chain_locked(&mut writer, "new_log", None, pending),
            },
            TailState::Restart { reason, last_seq } => {
                warn!(reason, ?last_seq, path = %self.config.jsonl_path.display(), "starting a new audit integrity chain");
                self.start_chain_locked(&mut writer, reason, last_seq, pending)
            }
        }
    }

    /// Chain position at the end of `<path>.1`, for an empty active file.
    fn previous_file_chain(&self) -> Option<(String, ChainState)> {
        let key = self.key.as_ref()?;
        let previous = backup_path(&self.config.jsonl_path, 1);
        let tail = chain::read_tail(&previous, 2).ok()?;
        match chain::analyze_tail(&tail, key) {
            TailState::Resume(chain) => Some((file_name_string(&previous), chain)),
            _ => None,
        }
    }

    fn stamp(&self, event: &AuditEvent) -> Result<Stamped, AuditError> {
        let mut json = serde_json::to_string(event).map_err(AuditError::Serialize)?;
        let context = &event.context;
        let event_id = context
            .event_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        // Unset context fields are skipped when serializing, so appending
        // them cannot create duplicate keys.
        let mut extra = String::new();
        if context.event_id.is_none() {
            extra.push_str(",\"event_id\":\"");
            extra.push_str(&event_id);
            extra.push('"');
        }
        if context.schema_version.is_none() {
            extra.push_str(",\"schema_version\":");
            extra.push_str(&AUDIT_SCHEMA_VERSION.to_string());
        }
        if context.host.is_none()
            && let Some(host) = &self.host
        {
            extra.push_str(",\"host\":");
            extra.push_str(&serde_json::to_string(host).map_err(AuditError::Serialize)?);
        }
        if !extra.is_empty() && json.ends_with('}') {
            json.pop();
            json.push_str(&extra);
            json.push('}');
        }
        Ok(Stamped { json, event_id })
    }

    fn write_record(
        &self,
        json: &str,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<Option<u64>, AuditError> {
        let mut writer = self.lock_writer()?;
        if let Err(err) = self.maintain_locked(&mut writer, pending) {
            // Keep writing to the current file; the record matters more.
            error!(error = %err, "audit log rotation/reopen failed");
            self.record_write_failure(&err);
        }
        self.append_locked(&mut writer, json)
    }

    fn write_internal_locked(
        &self,
        writer: &mut Writer,
        event: AuditEvent,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        let stamped = self.stamp(&event)?;
        let seq = self.append_locked(writer, &stamped.json)?;
        pending.push(PendingMirror {
            event,
            stamped,
            seq,
        });
        Ok(())
    }

    /// Appends one line, signing it when integrity is on. Returns its seq.
    fn append_locked(&self, writer: &mut Writer, json: &str) -> Result<Option<u64>, AuditError> {
        let (line, next) = match (&self.key, writer.chain) {
            (Some(key), Some(chain)) => {
                let seq = chain.seq + 1;
                let mac = chain::mac_v2(key, &chain.mac, seq, &[json.as_bytes()]);
                (
                    chain::format_v2_line(json, seq, &mac),
                    Some(ChainState { seq, mac }),
                )
            }
            _ => {
                let mut line = String::with_capacity(json.len() + 1);
                line.push_str(json);
                line.push('\n');
                (line, None)
            }
        };
        if writer.needs_newline {
            if let Err((_, err)) = write_fully(&mut writer.file, b"\n") {
                self.record_write_failure(&err);
                return Err(AuditError::Io(err));
            }
            writer.needs_newline = false;
        }
        if let Err((written, err)) = write_fully(&mut writer.file, line.as_bytes()) {
            writer.needs_newline = written > 0;
            writer.dirty |= written > 0;
            self.record_write_failure(&err);
            return Err(AuditError::Io(err));
        }
        if next.is_some() {
            writer.chain = next;
        }
        writer.dirty = true;
        self.stats.records_written.fetch_add(1, Ordering::Relaxed);
        if self.config.fsync == FsyncMode::Always {
            match writer.file.sync_data() {
                Ok(()) => {
                    writer.dirty = false;
                    writer.last_sync = Instant::now();
                }
                Err(err) => self.record_write_failure(&err),
            }
        }
        Ok(next.map(|chain| chain.seq))
    }

    /// Follows the path to a replaced or removed file, then rotates by size.
    fn maintain_locked(
        &self,
        writer: &mut Writer,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match fs::metadata(&self.config.jsonl_path) {
                Ok(meta) => {
                    if writer
                        .identity
                        .is_some_and(|identity| identity != (meta.dev(), meta.ino()))
                    {
                        self.reopen_locked(writer, "file_replaced", pending)?;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.reopen_locked(writer, "file_missing", pending)?;
                }
                Err(err) => return Err(AuditError::Io(err)),
            }
        }
        let len = writer.file.metadata().map_err(AuditError::Io)?.len();
        if len >= self.config.max_bytes {
            self.rotate_locked(writer, pending)?;
        }
        Ok(())
    }

    fn reopen(&self, pending: &mut Vec<PendingMirror>) -> Result<(), AuditError> {
        let mut writer = self.lock_writer()?;
        self.reopen_locked(&mut writer, "reopen", pending)
            .map(|_| ())
    }

    /// Switches to the file now at the configured path. Returns false when
    /// it is the file already open.
    fn reopen_locked(
        &self,
        writer: &mut Writer,
        reason: &'static str,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<bool, AuditError> {
        let path = &self.config.jsonl_path;
        if let Some(parent) = parent_dir(path) {
            fs::create_dir_all(parent).map_err(AuditError::Io)?;
        }
        let file = open_append(path)?;
        let identity = file_identity(&file);
        if identity.is_some() && identity == writer.identity {
            return Ok(false);
        }
        let prev_file = fd_path(&writer.file);
        self.sync_before_switch(writer);
        writer.needs_newline = ends_without_newline(path);
        writer.file = file;
        writer.identity = identity;
        writer.dirty = false;
        info!(reason, path = %path.display(), prev_file = ?prev_file, "audit log reopened");
        self.write_link_locked(writer, reason, prev_file, pending)?;
        Ok(true)
    }

    fn sync_before_switch(&self, writer: &mut Writer) {
        if self.config.fsync == FsyncMode::None || !writer.dirty {
            return;
        }
        if let Err(err) = writer.file.sync_data() {
            warn!(error = %err, "failed to fdatasync the audit log before switching files");
            self.record_write_failure(&err);
        }
    }

    fn rotate_locked(
        &self,
        writer: &mut Writer,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        let base = &self.config.jsonl_path;
        let max = self.config.max_files.max(1) as u64;
        // Also expires files left over from a larger `max_files`.
        for (index, path) in chain::rotation_backups(base).map_err(AuditError::Io)? {
            if index >= max {
                self.expire_locked(writer, &path, pending)?;
            }
        }
        for index in (1..max).rev() {
            let src = backup_path(base, index);
            if src.exists() {
                fs::rename(&src, backup_path(base, index + 1)).map_err(AuditError::Io)?;
            }
        }
        self.sync_before_switch(writer);
        let first = backup_path(base, 1);
        fs::rename(base, &first).map_err(AuditError::Io)?;
        let file = open_append(base)?;
        writer.identity = file_identity(&file);
        writer.file = file;
        writer.dirty = false;
        writer.needs_newline = false;
        if self.config.fsync != FsyncMode::None {
            sync_parent_dir(base);
        }
        self.stats.rotations.fetch_add(1, Ordering::Relaxed);
        debug!(path = %base.display(), "rotated audit log");
        self.write_link_locked(writer, "rotation", Some(file_name_string(&first)), pending)
    }

    /// Records the final state of a rotated file in the active log, then
    /// deletes it.
    fn expire_locked(
        &self,
        writer: &mut Writer,
        path: &Path,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        let name = file_name_string(path);
        let size = fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        let mut resource = SystemResource::new(EVENT_FILE_EXPIRED)
            .attr("file", name.clone())
            .attr("size_bytes", size);
        if let Ok(Some(first_seq)) = chain::first_signed_seq(path) {
            resource = resource.attr("first_seq", first_seq);
        }
        if let Ok(Some(last)) = chain::last_signed(path) {
            resource = resource
                .attr("last_seq", last.seq)
                .attr("final_mac", hex::encode(last.mac));
        }
        let event = AuditEvent::system(
            AUDIT_SOURCE,
            resource,
            NO_POLICY_VERSION,
            format!("audit file {name} expired by rotation ({size} bytes)"),
        );
        self.write_internal_locked(writer, event, pending)?;
        fs::remove_file(path).map_err(AuditError::Io)?;
        self.stats.files_expired.fetch_add(1, Ordering::Relaxed);
        info!(file = %path.display(), size, "expired oldest audit file");
        Ok(())
    }

    fn write_link_locked(
        &self,
        writer: &mut Writer,
        reason: &str,
        prev_file: Option<String>,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        let Some(chain) = writer.chain else {
            return Ok(());
        };
        let from = prev_file
            .as_deref()
            .unwrap_or("the previous file")
            .to_string();
        let mut resource = SystemResource::new(EVENT_CHAIN_LINK)
            .attr("reason", reason)
            .attr("prev_seq", chain.seq)
            .attr("prev_mac", hex::encode(chain.mac));
        if let Some(prev_file) = prev_file {
            resource = resource.attr("prev_file", prev_file);
        }
        let event = AuditEvent::system(
            AUDIT_SOURCE,
            resource,
            NO_POLICY_VERSION,
            format!(
                "audit chain continues from {from} at seq {} ({reason})",
                chain.seq
            ),
        );
        self.write_internal_locked(writer, event, pending)
    }

    fn start_chain_locked(
        &self,
        writer: &mut Writer,
        reason: &str,
        last_seq: Option<u64>,
        pending: &mut Vec<PendingMirror>,
    ) -> Result<(), AuditError> {
        if self.key.is_none() {
            return Ok(());
        }
        // The start record is signed with an all-zero predecessor MAC; seq
        // keeps counting from the previous chain when it is known.
        writer.chain = Some(ChainState {
            seq: last_seq.unwrap_or(0),
            mac: ZERO_MAC,
        });
        let mut resource = SystemResource::new(EVENT_CHAIN_START).attr("reason", reason);
        if let Some(seq) = last_seq {
            resource = resource.attr("prev_seq", seq);
        }
        let event = AuditEvent::system(
            AUDIT_SOURCE,
            resource,
            NO_POLICY_VERSION,
            format!("audit integrity chain started ({reason})"),
        );
        self.write_internal_locked(writer, event, pending)
    }

    fn mirror_pending(&self, pending: Vec<PendingMirror>) {
        for record in pending {
            self.mirror(&record.event, &record.stamped, record.seq);
        }
    }

    #[cfg(unix)]
    fn mirror(&self, event: &AuditEvent, stamped: &Stamped, seq: Option<u64>) {
        let Some(mirror) = &self.mirror else {
            return;
        };
        let outcome = mirror.send(&journal::MirrorRecord {
            event,
            json: &stamped.json,
            event_id: &stamped.event_id,
            seq,
        });
        match outcome {
            journal::MirrorOutcome::Sent => {}
            journal::MirrorOutcome::Truncated(reason) => {
                let count = self.stats.mirror_truncated.fetch_add(1, Ordering::Relaxed) + 1;
                set_last_error(
                    &self.stats,
                    format!(
                        "journald mirror truncated record {}: {reason}",
                        stamped.event_id
                    ),
                );
                if worth_logging(count) {
                    warn!(event_id = %stamped.event_id, error = %reason, count, "audit record mirrored to journald without its full JSON");
                }
            }
            journal::MirrorOutcome::Failed(reason) => {
                let count = self.stats.mirror_failures.fetch_add(1, Ordering::Relaxed) + 1;
                set_last_error(
                    &self.stats,
                    format!(
                        "journald mirror failed for record {}: {reason}",
                        stamped.event_id
                    ),
                );
                if worth_logging(count) {
                    error!(event_id = %stamped.event_id, error = %reason, count, "failed to mirror audit event to journald");
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn mirror(&self, _event: &AuditEvent, _stamped: &Stamped, _seq: Option<u64>) {}

    fn request_sync(&self) {
        lock_ignore_poison(&self.signal).urgent = true;
        self.signal_cv.notify_one();
    }

    /// Time until the dirty log is due for fdatasync; None when clean.
    fn next_sync_delay(&self, urgent: bool) -> Option<Duration> {
        let writer = self.writer.lock().ok()?;
        if !writer.dirty {
            return None;
        }
        let gap = if urgent {
            URGENT_SYNC_GAP
        } else {
            SYNC_INTERVAL
        };
        Some(gap.saturating_sub(writer.last_sync.elapsed()))
    }

    /// fdatasyncs a duplicate descriptor so writers are not blocked.
    fn sync_if_dirty(&self) {
        let handle = {
            let Ok(mut writer) = self.writer.lock() else {
                return;
            };
            if !writer.dirty {
                return;
            }
            writer.last_sync = Instant::now();
            match writer.file.try_clone() {
                Ok(handle) => {
                    writer.dirty = false;
                    handle
                }
                Err(err) => {
                    self.record_write_failure(&err);
                    return;
                }
            }
        };
        if let Err(err) = handle.sync_data() {
            warn!(error = %err, "audit log fdatasync failed");
            self.record_write_failure(&err);
            if let Ok(mut writer) = self.writer.lock() {
                writer.dirty = true;
            }
        }
    }
}

fn flusher_loop(inner: Arc<Inner>) {
    let mut signal = lock_ignore_poison(&inner.signal);
    loop {
        if signal.shutdown {
            return;
        }
        match inner.next_sync_delay(signal.urgent) {
            Some(delay) if delay.is_zero() => {
                signal.urgent = false;
                drop(signal);
                inner.sync_if_dirty();
                signal = lock_ignore_poison(&inner.signal);
            }
            Some(delay) => signal = wait_signal(&inner.signal_cv, signal, delay),
            None => {
                signal.urgent = false;
                signal = wait_signal(&inner.signal_cv, signal, SYNC_INTERVAL);
            }
        }
    }
}

fn wait_signal<'a>(
    cv: &Condvar,
    guard: MutexGuard<'a, FlushSignal>,
    timeout: Duration,
) -> MutexGuard<'a, FlushSignal> {
    match cv.wait_timeout(guard, timeout) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn set_last_error(stats: &Counters, message: String) {
    *lock_ignore_poison(&stats.last_error) = Some((message, Utc::now()));
}

/// Log the first occurrence and then every thousandth.
fn worth_logging(count: u64) -> bool {
    count == 1 || count.is_multiple_of(1000)
}

/// Records whose loss matters most get an early fdatasync.
fn is_urgent(event: &AuditEvent) -> bool {
    event.decision == Decision::Deny || event.action_type == ActionType::SystemEvent
}

/// Writes all of `buf`, reporting how many bytes made it on failure.
fn write_fully(file: &mut File, buf: &[u8]) -> Result<(), (usize, io::Error)> {
    let mut written = 0;
    while written < buf.len() {
        match file.write(&buf[written..]) {
            Ok(0) => return Err((written, io::Error::from(io::ErrorKind::WriteZero))),
            Ok(n) => written += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err((written, err)),
        }
    }
    Ok(())
}

fn load_integrity_key(
    source: &IntegrityKeySource,
) -> Result<(Option<[u8; 32]>, Option<String>), AuditError> {
    match source {
        IntegrityKeySource::Disabled => Ok((None, None)),
        IntegrityKeySource::File(path) => chain::load_key(path).map(|key| (Some(key), None)),
        IntegrityKeySource::Hex(hex) => chain::parse_key_hex(hex).map(|key| (Some(key), None)),
        IntegrityKeySource::AutoGenerate(path) => match load_or_generate_key(path) {
            Ok(key) => Ok((Some(key), None)),
            Err(err) => {
                error!(path = %path.display(), error = %err, "audit integrity key unavailable; audit records will be unsigned");
                Ok((None, Some(err.to_string())))
            }
        },
    }
}

fn load_or_generate_key(path: &Path) -> Result<[u8; 32], AuditError> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            warn_if_key_exposed(path);
            chain::parse_key_hex(&raw)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => generate_key(path),
        Err(err) => Err(AuditError::IntegrityKey(format!(
            "failed to read integrity key from {}: {err}",
            path.display()
        ))),
    }
}

fn generate_key(path: &Path) -> Result<[u8; 32], AuditError> {
    let fail = |what: &str, err: io::Error| {
        AuditError::IntegrityKey(format!("failed to {what} {}: {err}", path.display()))
    };
    if let Some(parent) = parent_dir(path)
        && !parent.exists()
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .map_err(|err| fail("create the directory of", err))?;
    }
    let mut key = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut key))
        .map_err(|err| fail("gather randomness for", err))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        // Another writer created it first.
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return chain::load_key(path),
        Err(err) => return Err(fail("create", err)),
    };
    if let Err(err) = file
        .write_all(format!("{}\n", hex::encode(key)).as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(path);
        return Err(fail("write", err));
    }
    info!(path = %path.display(), "generated audit integrity key");
    Ok(key)
}

fn warn_if_key_exposed(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            warn!(path = %path.display(), "audit integrity key is accessible to group/other; chmod 600 it");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditError::Io)
}

fn file_identity(file: &File) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        file.metadata().ok().map(|meta| (meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        None
    }
}

/// Current name of an open file (its name after an external rename).
fn fd_path(file: &File) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .ok()
            .map(|path| path.display().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        None
    }
}

fn ends_without_newline(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut last = [0u8; 1];
    file.seek(SeekFrom::End(-1))
        .and_then(|_| file.read_exact(&mut last))
        .is_ok_and(|()| last[0] != b'\n')
}

fn sync_parent_dir(path: &Path) {
    let dir = parent_dir(path).unwrap_or(Path::new("."));
    if let Err(err) = File::open(dir).and_then(|dir| dir.sync_all()) {
        debug!(error = %err, dir = %dir.display(), "failed to fsync audit log directory");
    }
}

fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn backup_path(base: &Path, index: u64) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its full length.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
        (!name.is_empty()).then_some(name)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("serialize: {0}")]
    Serialize(serde_json::Error),
    #[error("state poison: {0}")]
    Poison(String),
    #[error("integrity key: {0}")]
    IntegrityKey(String),
}

#[cfg(test)]
mod tests;
