use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use chrono::{TimeZone, Utc};
use core_types::{
    Action, ActionContext, ActionType, AuditEvent, Decision, DecisionReason, DecisionResult,
    DefaultDecision, EnforcementMode, EventContext, ExecResource, FailMode, FileResource,
    NetworkProtocol, NetworkResource, Resource, SystemResource,
};
use kernel_runtime::FilesystemBackend;
use parking_lot::{Mutex, RwLock};
use policy_engine::{CompiledPolicy, EngineOptions, PolicyEngine};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use uuid::Uuid;

// Re-export from platform_traits so `linux_adapter::AppArmorConfig` still works.
pub use platform_traits::{AppArmorAuditSource, AppArmorConfig};

#[cfg(test)]
use crate::apparmor_records::action_from_operation;
use crate::apparmor_records::{
    AppArmorAction, DedupeWindow, LAUNCHER_COMM, LossNotice, PROFILE_PREFIX, ParsedAuditRecord,
    ParsedLine, RawAuditLine, RecordOrigin, Verdict, action_from_record, base_label, parse_line,
};
use crate::apparmor_sources::{
    AuditLogReader, CursorReset, JournalSelection, JournaldReader, Position, SourceBatch,
};

const BOOTSTRAP_SUPPRESSION_WINDOW: Duration = Duration::from_secs(3);
const TOMBSTONE_TTL: Duration = Duration::from_secs(120);
/// Keys of recently emitted records, for cross-source deduplication.
const DEDUPE_WINDOW: usize = 16_384;
const PROC_CACHE_TTL: Duration = Duration::from_secs(2);
const PROC_CACHE_MAX: usize = 4_096;
/// A repeated identical source error is re-announced at most this often.
const SOURCE_ERROR_REPEAT: Duration = Duration::from_secs(60);
/// `context.source` of every record this module emits.
const EVENT_SOURCE: &str = "apparmor";
/// `profile` of records whose Mercury profile cannot be recovered.
const UNKNOWN_PROFILE: &str = "unknown";
/// `rule_id` of accesses the kernel allowed through the profile's fixed
/// baseline (abstractions/base, library paths, runtime prefixes) that the
/// Mercury policy itself does not grant.
const BASELINE_RULE_ID: &str = "apparmor-baseline";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppArmorCapabilities {
    pub enabled: bool,
    pub parser_present: bool,
    pub supports_fine_grained_network: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectRegistrationMode {
    PreExecLaunch,
    ExistingProcess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedProfile {
    pub label: String,
}

/// Counters describing AppArmor audit ingestion, for export by the daemon.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppArmorTelemetryStats {
    /// AppArmor records for Mercury profiles that were parsed.
    pub records_parsed: u64,
    /// Audit events produced from records (including unmapped ones).
    pub records_emitted: u64,
    /// Records emitted as `apparmor_unmapped_operation`.
    pub records_unmapped: u64,
    /// Records whose agent could not be recovered from memory or the label.
    pub records_unattributed: u64,
    /// Records already emitted from another transport.
    pub records_deduplicated: u64,
    /// Launcher records hidden during the pre-exec bootstrap window.
    pub records_suppressed_bootstrap: u64,
    /// Kernel verdicts that disagreed with the Mercury policy.
    pub verdict_mismatches: u64,
    /// Entries that looked like records but could not be decoded.
    pub parse_errors: u64,
    /// journalctl / audit log read failures.
    pub source_errors: u64,
    /// Cursor files that could not be written.
    pub cursor_persist_errors: u64,
    /// Sources that lost their position (telemetry gap).
    pub cursor_resets: u64,
    /// Sum of `kauditd_printk_skb: N callbacks suppressed`.
    pub kernel_suppressed_callbacks: u64,
    /// Records the kernel audit subsystem reported as lost.
    pub kernel_audit_lost: u64,
    /// Events held back by the adapter because a drain exceeded its limit.
    pub overflow_carried: u64,
    /// Profiles whose enrollment root exited but that still confine tasks.
    pub profiles_pending_removal: u64,
    /// Profiles unloaded after their last confined task exited.
    pub profiles_removed: u64,
}

#[derive(Debug, Default)]
struct TelemetryCounters {
    records_parsed: AtomicU64,
    records_emitted: AtomicU64,
    records_unmapped: AtomicU64,
    records_unattributed: AtomicU64,
    records_deduplicated: AtomicU64,
    records_suppressed_bootstrap: AtomicU64,
    verdict_mismatches: AtomicU64,
    parse_errors: AtomicU64,
    source_errors: AtomicU64,
    cursor_persist_errors: AtomicU64,
    cursor_resets: AtomicU64,
    kernel_suppressed_callbacks: AtomicU64,
    kernel_audit_lost: AtomicU64,
    profiles_removed: AtomicU64,
}

fn bump(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

/// Host locations, overridable so tests never touch the real journal or
/// `/proc`.
#[derive(Debug, Clone)]
pub(crate) struct HostPaths {
    pub journalctl: PathBuf,
    pub proc_root: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            journalctl: PathBuf::from("journalctl"),
            proc_root: PathBuf::from("/proc"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AppArmorManager {
    config: AppArmorConfig,
    filesystem_backend: FilesystemBackend,
    capabilities: AppArmorCapabilities,
    host: HostPaths,
    state: RwLock<AppArmorState>,
    sources: Mutex<AuditSources>,
    dedupe: Mutex<DedupeWindow>,
    proc_cache: Mutex<HashMap<u32, CachedProc>>,
    audit_transport_seen: AtomicBool,
    counters: TelemetryCounters,
}

#[derive(Debug, Default)]
struct AuditSources {
    journald: Option<JournaldReader>,
    audit_log: Option<AuditLogReader>,
    audit_log_optional: bool,
}

#[derive(Debug, Default)]
struct AppArmorState {
    active_policy: Option<CompiledPolicy>,
    subjects: HashMap<u32, AppArmorSubject>,
    tombstones: HashMap<u32, TombstoneSubject>,
    /// Every Mercury label seen this run, so records are attributable after
    /// the in-memory subject is gone.
    labels: HashMap<String, LabelInfo>,
    /// Labels whose enrollment root exited; unloaded once nothing is
    /// confined by them any more.
    retiring: HashMap<String, RetiringProfile>,
    /// System events waiting for the next drain.
    pending_events: Vec<AuditEvent>,
    last_audit_lost: Option<u64>,
    source_error_marks: HashMap<&'static str, (String, Instant)>,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct AppArmorSubject {
    pid: u32,
    ppid: u32,
    uid: u32,
    _proc_start_time: u64,
    agent_id: Uuid,
    profile: String,
    label: String,
    bootstrap_until: Option<Instant>,
}

#[derive(Debug, Clone)]
struct TombstoneSubject {
    subject: AppArmorSubject,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct LabelInfo {
    agent_id: Uuid,
    profile: Option<String>,
    root_pid: Option<u32>,
    root_ppid: Option<u32>,
    removed_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct RetiringProfile {
    agent_id: Uuid,
    profile: Option<String>,
    root_pid: Option<u32>,
    since: Instant,
    checks: u64,
    max_confined: usize,
}

#[derive(Debug, Clone, Copy)]
struct CachedProc {
    facts: Option<ProcFacts>,
    at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFacts {
    ppid: u32,
}

/// Who a record belongs to, from the best source available: the registered
/// subject, the label cache, or the profile file on disk.
#[derive(Debug, Clone)]
struct Attribution {
    agent_id: String,
    profile: Option<String>,
    root_pid: Option<u32>,
    root_ppid: Option<u32>,
    uid: Option<u32>,
    bootstrap_until: Option<Instant>,
}

impl Attribution {
    fn unattributed(label: &str) -> Self {
        Self {
            agent_id: label.to_string(),
            profile: None,
            root_pid: None,
            root_ppid: None,
            uid: None,
            bootstrap_until: None,
        }
    }

    fn profile_name(&self) -> String {
        self.profile
            .clone()
            .unwrap_or_else(|| UNKNOWN_PROFILE.to_string())
    }
}

impl AppArmorManager {
    pub(crate) fn new(config: AppArmorConfig, filesystem_backend: FilesystemBackend) -> Self {
        Self::new_with_host(config, filesystem_backend, HostPaths::default())
    }

    pub(crate) fn new_with_host(
        config: AppArmorConfig,
        filesystem_backend: FilesystemBackend,
        host: HostPaths,
    ) -> Self {
        let sources = build_sources(&config, &host);
        Self {
            capabilities: detect_capabilities(config.parser_path.as_str()),
            config,
            filesystem_backend,
            host,
            state: RwLock::new(AppArmorState::default()),
            sources: Mutex::new(sources),
            dedupe: Mutex::new(DedupeWindow::new(DEDUPE_WINDOW)),
            proc_cache: Mutex::new(HashMap::new()),
            audit_transport_seen: AtomicBool::new(false),
            counters: TelemetryCounters::default(),
        }
    }

    pub(crate) fn capabilities(&self) -> AppArmorCapabilities {
        self.capabilities.clone()
    }

    pub(crate) fn start(&self) -> anyhow::Result<()> {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return Ok(());
        }
        if !self.capabilities.enabled {
            return Err(anyhow!("AppArmor is not enabled on this host"));
        }
        if !self.capabilities.parser_present {
            return Err(anyhow!(
                "AppArmor parser not found at {}",
                self.config.parser_path
            ));
        }

        fs::create_dir_all(self.generated_policy_dir()).with_context(|| {
            format!(
                "create AppArmor policy dir {}",
                self.generated_policy_dir().display()
            )
        })?;

        self.start_sources()?;
        self.adopt_orphan_profiles();
        Ok(())
    }

    /// Positions every configured source (persisted cursor or tail). Cursor
    /// resets are queued as `apparmor_cursor_reset` for the next drain.
    fn start_sources(&self) -> anyhow::Result<()> {
        let mut resets = Vec::new();
        {
            let mut sources = self.sources.lock();
            if let Some(journald) = sources.journald.as_mut() {
                resets.extend(journald.start()?);
            }
            let optional = sources.audit_log_optional;
            if let Some(audit_log) = sources.audit_log.as_mut() {
                match audit_log.start() {
                    Ok(found) => resets.extend(found),
                    Err(err) if optional => {
                        warn!(error = %err, "AppArmor audit log source unavailable");
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        let policy_version = self.policy_version();
        let events: Vec<AuditEvent> = resets
            .iter()
            .map(|reset| self.cursor_reset_event(reset, policy_version.as_str()))
            .collect();
        self.state.write().pending_events.extend(events);
        Ok(())
    }

    /// Profiles left behind by a previous daemon run may still confine
    /// processes. Track them so their records stay attributable, and retire
    /// them so they are unloaded once nothing runs under them.
    fn adopt_orphan_profiles(&self) {
        let Ok(entries) = fs::read_dir(self.generated_policy_dir()) else {
            return;
        };
        let mut state = self.state.write();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(label) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".apparmor"))
                .filter(|label| label.starts_with(PROFILE_PREFIX))
            else {
                continue;
            };
            if state
                .subjects
                .values()
                .any(|subject| subject.label == label)
            {
                continue;
            }
            let (header_agent, profile) = read_profile_header(&entry.path());
            let Some(agent_id) = header_agent.or_else(|| agent_id_from_label(label)) else {
                continue;
            };
            state.labels.insert(
                label.to_string(),
                LabelInfo {
                    agent_id,
                    profile: profile.clone(),
                    root_pid: None,
                    root_ppid: None,
                    removed_at: None,
                },
            );
            state
                .retiring
                .entry(label.to_string())
                .or_insert(RetiringProfile {
                    agent_id,
                    profile,
                    root_pid: None,
                    since: Instant::now(),
                    checks: 0,
                    max_confined: 0,
                });
        }
    }

    pub(crate) fn load_policy(&self, policy: &CompiledPolicy) -> anyhow::Result<()> {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return Ok(());
        }

        let active_subjects = {
            let mut state = self.state.write();
            state.active_policy = Some(policy.clone());
            let mut seen = BTreeSet::new();
            state
                .subjects
                .values()
                .filter(|subject| seen.insert(subject.label.clone()))
                .map(|subject| (subject.agent_id, subject.profile.clone()))
                .collect::<Vec<_>>()
        };

        for (agent_id, profile) in active_subjects {
            self.ensure_profile_loaded(agent_id, profile.as_str())?;
        }
        self.clear_error();

        // Tasks that outlived their enrollment root must follow policy
        // updates too, or they would keep running under the old rules.
        self.prune_retired_profiles();
        let retiring = self
            .state
            .read()
            .retiring
            .values()
            .filter_map(|retiring| Some((retiring.agent_id, retiring.profile.clone()?)))
            .collect::<Vec<_>>();
        for (agent_id, profile) in retiring {
            if let Err(err) = self.ensure_profile_loaded(agent_id, profile.as_str()) {
                warn!(error = %err, %agent_id, profile, "failed to refresh retiring AppArmor profile");
                self.set_error(format!(
                    "refresh AppArmor profile for exited agent {agent_id}: {err:#}"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_profile(
        &self,
        agent_id: Uuid,
        profile: &str,
    ) -> anyhow::Result<Option<PreparedProfile>> {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return Ok(None);
        }

        let label = profile_label(agent_id);
        {
            let mut state = self.state.write();
            state.retiring.remove(&label);
            state.labels.insert(
                label.clone(),
                LabelInfo {
                    agent_id,
                    profile: Some(profile.to_string()),
                    root_pid: None,
                    root_ppid: None,
                    removed_at: None,
                },
            );
        }
        self.ensure_profile_loaded(agent_id, profile)?;
        Ok(Some(PreparedProfile { label }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_subject(
        &self,
        pid: u32,
        ppid: u32,
        uid: u32,
        proc_start_time: u64,
        agent_id: Uuid,
        profile: &str,
        prepared: &PreparedProfile,
        mode: SubjectRegistrationMode,
    ) -> anyhow::Result<()> {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return Ok(());
        }

        if mode == SubjectRegistrationMode::ExistingProcess
            && !self.current_profile_matches(pid, prepared.label.as_str())?
        {
            let message = format!(
                "pid {pid} is not confined by expected AppArmor profile {}",
                prepared.label
            );
            self.set_error(message.clone());
            return Err(anyhow!(message));
        }

        let replaced = {
            let mut state = self.state.write();
            prune_tombstones(&mut state);
            state.tombstones.remove(&pid);
            state.retiring.remove(&prepared.label);
            state.labels.insert(
                prepared.label.clone(),
                LabelInfo {
                    agent_id,
                    profile: Some(profile.to_string()),
                    root_pid: Some(pid),
                    root_ppid: Some(ppid).filter(|ppid| *ppid != 0),
                    removed_at: None,
                },
            );
            state
                .subjects
                .insert(
                    pid,
                    AppArmorSubject {
                        pid,
                        ppid,
                        uid,
                        _proc_start_time: proc_start_time,
                        agent_id,
                        profile: profile.to_string(),
                        label: prepared.label.clone(),
                        bootstrap_until: (mode == SubjectRegistrationMode::PreExecLaunch)
                            .then_some(Instant::now() + BOOTSTRAP_SUPPRESSION_WINDOW),
                    },
                )
                .filter(|subject| subject.label != prepared.label)
        };

        if let Some(subject) = replaced {
            self.retire_label_if_unused(&subject);
        }

        self.clear_error();
        Ok(())
    }

    /// Forgets the enrollment root `pid`. Its profile is not unloaded while
    /// any task is still confined by it (daemonized children would otherwise
    /// become unconfined); removal is re-checked by
    /// [`Self::prune_retired_profiles`].
    pub(crate) fn unregister_subject(&self, pid: u32) -> anyhow::Result<bool> {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return Ok(false);
        }

        let removed = {
            let mut state = self.state.write();
            prune_tombstones(&mut state);
            let Some(subject) = state.subjects.remove(&pid) else {
                return Ok(false);
            };
            state.tombstones.insert(
                pid,
                TombstoneSubject {
                    subject: subject.clone(),
                    expires_at: Instant::now() + TOMBSTONE_TTL,
                },
            );
            subject
        };

        self.retire_label_if_unused(&removed);
        Ok(true)
    }

    fn retire_label_if_unused(&self, subject: &AppArmorSubject) {
        {
            let mut state = self.state.write();
            if state
                .subjects
                .values()
                .any(|other| other.label == subject.label)
            {
                return;
            }
            state
                .retiring
                .entry(subject.label.clone())
                .or_insert(RetiringProfile {
                    agent_id: subject.agent_id,
                    profile: Some(subject.profile.clone()),
                    root_pid: Some(subject.pid),
                    since: Instant::now(),
                    checks: 0,
                    max_confined: 0,
                });
        }
        self.prune_retired_profiles();
    }

    /// Unloads retiring profiles that no longer confine any task and queues
    /// an `agent_exited` event for each. Profiles that still confine tasks
    /// stay loaded and are re-checked on the next call. Returns the number
    /// of profiles removed.
    pub(crate) fn prune_retired_profiles(&self) -> usize {
        if self.filesystem_backend != FilesystemBackend::AppArmor {
            return 0;
        }

        let labels = {
            let mut state = self.state.write();
            let now = Instant::now();
            state.labels.retain(|_, info| {
                info.removed_at
                    .is_none_or(|removed| now.duration_since(removed) < TOMBSTONE_TTL)
            });
            state.retiring.keys().cloned().collect::<Vec<_>>()
        };
        if labels.is_empty() {
            return 0;
        }

        // `None` (unreadable /proc) counts as still confined.
        let confined_counts = self.confined_task_counts();
        let mut removed = 0;
        for label in labels {
            let confined = confined_counts
                .as_ref()
                .map(|counts| counts.get(&label).copied().unwrap_or(0));
            let retiring = {
                let mut state = self.state.write();
                if state
                    .subjects
                    .values()
                    .any(|subject| subject.label == label)
                {
                    state.retiring.remove(&label);
                    continue;
                }
                if confined != Some(0) {
                    if let Some(retiring) = state.retiring.get_mut(&label) {
                        retiring.checks += 1;
                        retiring.max_confined = retiring.max_confined.max(confined.unwrap_or(0));
                    }
                    continue;
                }
                let Some(retiring) = state.retiring.remove(&label) else {
                    continue;
                };
                if let Some(info) = state.labels.get_mut(&label) {
                    info.removed_at = Some(Instant::now());
                }
                retiring
            };

            let unload_error = self.unload_profile_by_label(label.as_str()).err();
            bump(&self.counters.profiles_removed, 1);
            removed += 1;
            let event = self.agent_exited_event(label.as_str(), &retiring, unload_error);
            self.state.write().pending_events.push(event);
        }
        removed
    }

    /// Live (non-zombie) tasks per Mercury label, from one pass over
    /// `/proc`. `None` when `/proc` cannot be listed.
    fn confined_task_counts(&self) -> Option<HashMap<String, usize>> {
        let entries = fs::read_dir(&self.host.proc_root).ok()?;
        let mut counts = HashMap::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Some(current) = read_proc_label(&self.host.proc_root, pid) else {
                continue;
            };
            let label = base_label(current.as_str());
            if !label.starts_with(PROFILE_PREFIX) {
                continue;
            }
            let zombie = fs::read_to_string(self.host.proc_root.join(format!("{pid}/stat")))
                .ok()
                .and_then(|stat| parse_proc_stat(stat.as_str()))
                .is_some_and(|(state, _)| matches!(state, 'Z' | 'X' | 'x'));
            if !zombie {
                *counts.entry(label.to_string()).or_insert(0) += 1;
            }
        }
        Some(counts)
    }

    /// Returns what the configured sources hold, up to `max_events`. Never
    /// fails: read and cursor errors become `apparmor_source_error` events
    /// and counters, and whatever was already processed is still returned.
    pub(crate) fn drain_audit_events_limited(&self, max_events: usize) -> Vec<AuditEvent> {
        if self.filesystem_backend != FilesystemBackend::AppArmor || max_events == 0 {
            return Vec::new();
        }

        let (policy, mut events) = {
            let mut state = self.state.write();
            prune_tombstones(&mut state);
            let take = state.pending_events.len().min(max_events);
            let events = state.pending_events.drain(..take).collect::<Vec<_>>();
            (state.active_policy.clone(), events)
        };
        let Some(policy) = policy else {
            return events;
        };

        let engine = PolicyEngine::with_policy(
            policy.clone(),
            EngineOptions {
                policy_unavailable_mode: FailMode::FailClosed,
                ..EngineOptions::default()
            },
        );

        let mut sources = self.sources.lock();
        let AuditSources {
            journald,
            audit_log,
            ..
        } = &mut *sources;

        if let Some(reader) = journald.as_mut()
            && events.len() < max_events
        {
            match reader.read(read_limit(max_events - events.len())) {
                Ok(batch) => {
                    if let Some(Position::Journal(cursor)) =
                        self.consume_batch(batch, max_events, &engine, &policy, &mut events)
                        && let Err(err) = reader.commit(cursor)
                    {
                        self.source_error("journald", "cursor_persist", &err, &mut events);
                    }
                }
                Err(err) => self.source_error("journald", "read", &err, &mut events),
            }
        }

        if let Some(reader) = audit_log.as_mut()
            && events.len() < max_events
        {
            match reader.read(read_limit(max_events - events.len())) {
                Ok(batch) => {
                    if let Some(Position::AuditLog(cursor)) =
                        self.consume_batch(batch, max_events, &engine, &policy, &mut events)
                        && let Err(err) = reader.commit(cursor)
                    {
                        self.source_error("audit_log", "cursor_persist", &err, &mut events);
                    }
                }
                Err(err) => self.source_error("audit_log", "read", &err, &mut events),
            }
        }

        events
    }

    /// Processes lines until `events` holds `max_events`, returning the
    /// position to commit: the batch end when every line was processed,
    /// otherwise the last processed line.
    fn consume_batch(
        &self,
        batch: SourceBatch,
        max_events: usize,
        engine: &PolicyEngine,
        policy: &CompiledPolicy,
        events: &mut Vec<AuditEvent>,
    ) -> Option<Position> {
        for reset in &batch.resets {
            events.push(self.cursor_reset_event(reset, policy.version.as_str()));
        }
        bump(&self.counters.parse_errors, batch.malformed);

        let total = batch.lines.len();
        let mut processed = 0usize;
        let mut last = None;
        for (line, position) in batch.lines {
            if events.len() >= max_events {
                break;
            }
            if let Some(event) = self.process_line(&line, engine, policy) {
                events.push(event);
            }
            processed += 1;
            last = Some(position);
        }
        if processed == total {
            batch.end.or(last)
        } else {
            last
        }
    }

    fn process_line(
        &self,
        line: &RawAuditLine,
        engine: &PolicyEngine,
        policy: &CompiledPolicy,
    ) -> Option<AuditEvent> {
        match parse_line(line) {
            ParsedLine::Ignored => None,
            ParsedLine::Malformed(reason) => {
                bump(&self.counters.parse_errors, 1);
                debug!(reason, text = %line.text, "skipping malformed AppArmor record");
                None
            }
            ParsedLine::Loss(notice) => self.loss_event(line, notice, policy.version.as_str()),
            ParsedLine::Record(record) => {
                bump(&self.counters.records_parsed, 1);
                if line.origin == RecordOrigin::JournaldAudit {
                    self.audit_transport_seen.store(true, Ordering::Relaxed);
                }
                if let Some(key) = record.dedupe_key
                    && !self.dedupe.lock().insert(key)
                {
                    bump(&self.counters.records_deduplicated, 1);
                    return None;
                }
                let event = self.record_event(&record, engine, policy)?;
                bump(&self.counters.records_emitted, 1);
                Some(event)
            }
        }
    }

    fn record_event(
        &self,
        record: &ParsedAuditRecord,
        engine: &PolicyEngine,
        policy: &CompiledPolicy,
    ) -> Option<AuditEvent> {
        let attribution = self.attribute(record).unwrap_or_else(|| {
            bump(&self.counters.records_unattributed, 1);
            Attribution::unattributed(record.label.as_str())
        });

        if record.verdict == Verdict::Status {
            return Some(self.status_event(record, &attribution, policy.version.as_str()));
        }
        if is_launcher_bootstrap(record, &attribution) {
            bump(&self.counters.records_suppressed_bootstrap, 1);
            return None;
        }

        let pid = record.pid.or(attribution.root_pid);
        let ppid = self.resolve_ppid(pid, record.label.as_str(), &attribution);
        let uid = record.uid.or(attribution.uid);
        let action = match record.verdict {
            Verdict::Unknown => None,
            _ => action_from_record(record),
        };
        let Some(action) = action else {
            bump(&self.counters.records_unmapped, 1);
            return Some(self.unmapped_event(
                record,
                &attribution,
                pid,
                ppid,
                policy.version.as_str(),
            ));
        };

        let (action_type, resource) = self.resource_for(record, action, pid);
        let evaluation = attribution
            .profile
            .as_deref()
            .filter(|profile| policy.profiles.contains_key(*profile))
            .map(|profile| {
                engine.evaluate(
                    profile,
                    &Action {
                        action_type,
                        context: ActionContext {
                            timestamp: record.timestamp,
                            agent_id: attribution.agent_id.clone(),
                            pid: pid.unwrap_or(0),
                            ppid: ppid.unwrap_or(0),
                            uid: uid.unwrap_or(0),
                            profile: profile.to_string(),
                        },
                        resource: resource.clone(),
                    },
                )
            });
        let (reason, rule_id, note) = self.reconcile(record, evaluation);

        let mut context = record_context(record, &attribution);
        match action_type {
            ActionType::ProcKill => {
                context.signal = record.signal_number();
                context.target_pid = record.peer_pid;
            }
            ActionType::ProcPtrace => context.target_pid = record.peer_pid,
            ActionType::ProcCapable => context.capability = record.capability,
            _ => {}
        }

        Some(AuditEvent {
            timestamp: record.timestamp,
            agent_id: attribution.agent_id.clone(),
            pid,
            ppid,
            uid,
            action_type,
            decision: record.decision(),
            reason,
            rule_id,
            resource,
            profile: attribution.profile_name(),
            policy_version: policy.version.clone(),
            message: record_message(record, note),
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context,
        })
    }

    /// The Mercury decision reason for a kernel verdict, cross-checked
    /// against the Mercury policy when the profile is known.
    fn reconcile(
        &self,
        record: &ParsedAuditRecord,
        evaluation: Option<DecisionResult>,
    ) -> (DecisionReason, Option<String>, Option<&'static str>) {
        let decision = record.decision();
        let Some(evaluation) = evaluation else {
            return (
                kernel_reason(&record.verdict),
                None,
                Some("mercury profile unknown; not cross-checked"),
            );
        };
        if evaluation.decision == decision {
            return (evaluation.reason, evaluation.rule_id, None);
        }
        bump(&self.counters.verdict_mismatches, 1);
        if record.verdict == Verdict::Audit {
            // Allowed by a rule every generated profile carries (shared
            // libraries, abstractions/base). Expected, not an enforcement
            // failure.
            return (
                DecisionReason::AllowByRule,
                Some(BASELINE_RULE_ID.to_string()),
                Some("allowed by AppArmor baseline rule; Mercury policy would deny"),
            );
        }
        self.set_error(format!(
            "AppArmor verdict mismatch for pid {} path {}: kernel={:?} mercury={:?}",
            record.pid.unwrap_or(0),
            record.path,
            decision,
            evaluation.decision
        ));
        (
            DecisionReason::ErrorEnforcementUnavailable,
            None,
            Some("kernel verdict disagrees with Mercury policy"),
        )
    }

    fn resource_for(
        &self,
        record: &ParsedAuditRecord,
        action: AppArmorAction,
        pid: Option<u32>,
    ) -> (ActionType, Resource) {
        match action {
            AppArmorAction::File(action_type, op) => (
                action_type,
                Resource::File(FileResource {
                    path: record.path.clone(),
                    resolved_path: Some(record.path.clone()),
                    op,
                    source_path: None,
                }),
            ),
            AppArmorAction::Exec => (
                ActionType::ProcExec,
                Resource::Exec(ExecResource {
                    path: record.path.clone(),
                    argv_hash: None,
                    // The record carries no cwd; read it from the live task
                    // or leave it empty rather than guess.
                    cwd: pid
                        .and_then(|pid| self.live_cwd(pid, record.label.as_str()))
                        .unwrap_or_default(),
                    argv: Vec::new(),
                    argv_truncated: false,
                }),
            ),
            AppArmorAction::Process(action_type, path) => (
                action_type,
                Resource::Exec(ExecResource {
                    path: path.to_string(),
                    argv_hash: process_metadata_hash(action_type, record),
                    cwd: String::new(),
                    argv: Vec::new(),
                    argv_truncated: false,
                }),
            ),
            AppArmorAction::Network(action_type) => (
                action_type,
                Resource::Network(network_resource_from_record(action_type, record)),
            ),
        }
    }

    fn attribute(&self, record: &ParsedAuditRecord) -> Option<Attribution> {
        if let Some(subject) = self.lookup_subject(record.pid.unwrap_or(0), record.label.as_str()) {
            return Some(Attribution {
                agent_id: subject.agent_id.to_string(),
                profile: Some(subject.profile),
                root_pid: Some(subject.pid),
                root_ppid: Some(subject.ppid).filter(|ppid| *ppid != 0),
                uid: Some(subject.uid),
                bootstrap_until: subject.bootstrap_until,
            });
        }
        let info = self.label_info(record.label.as_str())?;
        Some(Attribution {
            agent_id: info.agent_id.to_string(),
            profile: info.profile,
            root_pid: info.root_pid,
            root_ppid: info.root_ppid,
            uid: None,
            bootstrap_until: None,
        })
    }

    /// Agent and profile for a label: cached, else recovered from the label
    /// itself (`mercury-agent-<uuid>`) and the generated profile's header.
    fn label_info(&self, label: &str) -> Option<LabelInfo> {
        if let Some(info) = self.state.read().labels.get(label) {
            return Some(info.clone());
        }
        let path = self.profile_path(label);
        let (header_agent, profile) = read_profile_header(&path);
        let agent_id = header_agent.or_else(|| agent_id_from_label(label))?;
        let info = LabelInfo {
            agent_id,
            profile,
            root_pid: None,
            root_ppid: None,
            removed_at: None,
        };
        self.state
            .write()
            .labels
            .insert(label.to_string(), info.clone());
        Some(info)
    }

    fn resolve_ppid(
        &self,
        pid: Option<u32>,
        label: &str,
        attribution: &Attribution,
    ) -> Option<u32> {
        let pid = pid?;
        if Some(pid) == attribution.root_pid
            && let Some(ppid) = attribution.root_ppid
        {
            return Some(ppid);
        }
        self.live_proc(pid, label).map(|facts| facts.ppid)
    }

    /// Facts about `pid` if it is alive and still confined by `label` (so a
    /// recycled pid is never mistaken for the audited task).
    fn live_proc(&self, pid: u32, label: &str) -> Option<ProcFacts> {
        let now = Instant::now();
        if let Some(cached) = self.proc_cache.lock().get(&pid)
            && now.duration_since(cached.at) < PROC_CACHE_TTL
        {
            return cached.facts;
        }

        let facts = fs::read_to_string(self.host.proc_root.join(format!("{pid}/stat")))
            .ok()
            .and_then(|stat| parse_proc_stat(stat.as_str()))
            .filter(|_| {
                read_proc_label(&self.host.proc_root, pid)
                    .is_none_or(|current| base_label(current.as_str()) == label)
            })
            .map(|(_, ppid)| ProcFacts { ppid });

        let mut cache = self.proc_cache.lock();
        if cache.len() >= PROC_CACHE_MAX {
            cache.clear();
        }
        cache.insert(pid, CachedProc { facts, at: now });
        facts
    }

    fn live_cwd(&self, pid: u32, label: &str) -> Option<String> {
        self.live_proc(pid, label)?;
        fs::read_link(self.host.proc_root.join(format!("{pid}/cwd")))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn status_event(
        &self,
        record: &ParsedAuditRecord,
        attribution: &Attribution,
        policy_version: &str,
    ) -> AuditEvent {
        let operation = record
            .operation
            .strip_prefix("profile_")
            .unwrap_or(record.operation.as_str());
        let mut resource = SystemResource::new(format!(
            "apparmor_profile_{}",
            sanitize_event_suffix(operation)
        ))
        .detail(record.label.clone())
        .attr("label", record.label.clone())
        .attr("operation", record.operation.clone());
        if let Some(info) = record.info.as_ref() {
            resource = resource.attr("info", info.clone());
        }
        if let Some(error) = record.error.as_ref() {
            resource = resource.attr("error", error.clone());
        }
        let mut event = AuditEvent::system(
            EVENT_SOURCE,
            resource,
            policy_version,
            record_message(record, None),
        );
        event.timestamp = record.timestamp;
        event.agent_id = attribution.agent_id.clone();
        event.profile = attribution.profile_name();
        event.pid = record.pid;
        event.uid = record.uid;
        event.context = record_context(record, attribution);
        event
    }

    fn unmapped_event(
        &self,
        record: &ParsedAuditRecord,
        attribution: &Attribution,
        pid: Option<u32>,
        ppid: Option<u32>,
        policy_version: &str,
    ) -> AuditEvent {
        let mut resource = SystemResource::new("apparmor_unmapped_operation")
            .detail(record.operation.clone())
            .attr("operation", record.operation.clone())
            .attr("apparmor", record.verdict_raw.clone())
            .attr("label", record.raw_label.clone())
            .attr("path", record.path.clone());
        for (key, value) in [
            ("class", &record.class),
            ("requested_mask", &record.requested_mask),
            ("denied_mask", &record.denied_mask),
            ("info", &record.info),
            ("error", &record.error),
            ("peer", &record.peer),
            ("family", &record.family),
            ("sock_type", &record.sock_type),
            ("addr", &record.addr),
            ("peer_addr", &record.peer_addr),
        ] {
            if let Some(value) = value {
                resource = resource.attr(key, value.clone());
            }
        }
        let mut event = AuditEvent::system(
            EVENT_SOURCE,
            resource,
            policy_version,
            record_message(record, Some("no Mercury action type for this operation")),
        );
        event.timestamp = record.timestamp;
        event.agent_id = attribution.agent_id.clone();
        event.profile = attribution.profile_name();
        event.pid = pid;
        event.ppid = ppid;
        event.uid = record.uid.or(attribution.uid);
        event.decision = record.decision();
        event.reason = kernel_reason(&record.verdict);
        event.context = record_context(record, attribution);
        event.context.target_pid = record.peer_pid;
        event
    }

    fn loss_event(
        &self,
        line: &RawAuditLine,
        notice: LossNotice,
        policy_version: &str,
    ) -> Option<AuditEvent> {
        let count = match notice.total {
            Some(total) => {
                // audit_lost= is cumulative since boot; report the increase.
                let previous = self.state.write().last_audit_lost.replace(total);
                match previous {
                    Some(previous) if total >= previous => total - previous,
                    _ => total,
                }
            }
            None => notice.count,
        };
        if count == 0 {
            return None;
        }
        if notice.source == "kernel_printk" {
            bump(&self.counters.kernel_suppressed_callbacks, count);
        } else {
            bump(&self.counters.kernel_audit_lost, count);
        }

        let audit_transport_active = self.audit_transport_seen.load(Ordering::Relaxed);
        let mut resource = SystemResource::new("telemetry_loss")
            .detail(notice.detail.clone())
            .attr("source", notice.source)
            .attr("count", count)
            .attr("origin", line.origin.as_str())
            // Printk suppression loses nothing when the same records also
            // arrive over journald's audit transport.
            .attr("audit_transport_active", audit_transport_active);
        if let Some(total) = notice.total {
            resource = resource.attr("audit_lost_total", total);
        }
        let mut event = AuditEvent::system(
            EVENT_SOURCE,
            resource,
            policy_version,
            format!(
                "kernel reported {count} lost/suppressed audit records ({})",
                notice.source
            ),
        );
        if let Some(received) = line.receive_time() {
            event.timestamp = received;
        }
        Some(event)
    }

    fn cursor_reset_event(&self, reset: &CursorReset, policy_version: &str) -> AuditEvent {
        bump(&self.counters.cursor_resets, 1);
        let mut resource = SystemResource::new("apparmor_cursor_reset")
            .detail(reset.detail.clone())
            .attr("source", reset.source)
            .attr("reason", reset.reason);
        if let Some(gap_start) = reset
            .gap_start_us
            .and_then(|micros| Utc.timestamp_micros(micros).single())
        {
            resource = resource.attr("gap_start", gap_start.to_rfc3339());
        }
        AuditEvent::system(
            EVENT_SOURCE,
            resource,
            policy_version,
            format!(
                "AppArmor {} source lost its position ({}); records may be missing",
                reset.source, reset.reason
            ),
        )
    }

    fn agent_exited_event(
        &self,
        label: &str,
        retiring: &RetiringProfile,
        unload_error: Option<String>,
    ) -> AuditEvent {
        let mut resource = SystemResource::new("agent_exited")
            .detail(format!("no task is confined by {label} any more"))
            .attr("label", label)
            .attr("agent_id", retiring.agent_id.to_string())
            .attr("confined_after_root_exit", retiring.max_confined as u64)
            .attr("deferred_checks", retiring.checks)
            .attr("retired_secs", retiring.since.elapsed().as_secs())
            .attr("profile_removed", unload_error.is_none());
        if let Some(root_pid) = retiring.root_pid {
            resource = resource.attr("root_pid", root_pid);
        }
        if let Some(profile) = retiring.profile.as_ref() {
            resource = resource.attr("profile", profile.clone());
        }
        if let Some(error) = unload_error.as_ref() {
            resource = resource.attr("error", error.clone());
        }
        let mut event = AuditEvent::system(
            EVENT_SOURCE,
            resource,
            self.policy_version(),
            format!(
                "agent {} exited; {} task(s) outlived the enrollment root",
                retiring.agent_id, retiring.max_confined
            ),
        );
        event.agent_id = retiring.agent_id.to_string();
        event.profile = retiring
            .profile
            .clone()
            .unwrap_or_else(|| UNKNOWN_PROFILE.to_string());
        event.pid = retiring.root_pid;
        event.context.root_pid = retiring.root_pid;
        event
    }

    fn source_error(
        &self,
        source: &'static str,
        stage: &'static str,
        err: &anyhow::Error,
        events: &mut Vec<AuditEvent>,
    ) {
        let counter = if stage == "cursor_persist" {
            &self.counters.cursor_persist_errors
        } else {
            &self.counters.source_errors
        };
        bump(counter, 1);
        let message = format!("{err:#}");
        warn!(source, stage, error = %message, "AppArmor audit source failed");

        let announce = {
            let mut state = self.state.write();
            let repeat = state
                .source_error_marks
                .get(source)
                .is_some_and(|(last, at)| *last == message && at.elapsed() < SOURCE_ERROR_REPEAT);
            if !repeat {
                state
                    .source_error_marks
                    .insert(source, (message.clone(), Instant::now()));
            }
            !repeat
        };
        if announce {
            events.push(AuditEvent::system(
                EVENT_SOURCE,
                SystemResource::new("apparmor_source_error")
                    .detail(message.clone())
                    .attr("source", source)
                    .attr("stage", stage),
                self.policy_version(),
                format!("AppArmor {source} {stage} failed: {message}"),
            ));
        }
    }

    pub(crate) fn telemetry_stats(&self) -> AppArmorTelemetryStats {
        let counters = &self.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        AppArmorTelemetryStats {
            records_parsed: load(&counters.records_parsed),
            records_emitted: load(&counters.records_emitted),
            records_unmapped: load(&counters.records_unmapped),
            records_unattributed: load(&counters.records_unattributed),
            records_deduplicated: load(&counters.records_deduplicated),
            records_suppressed_bootstrap: load(&counters.records_suppressed_bootstrap),
            verdict_mismatches: load(&counters.verdict_mismatches),
            parse_errors: load(&counters.parse_errors),
            source_errors: load(&counters.source_errors),
            cursor_persist_errors: load(&counters.cursor_persist_errors),
            cursor_resets: load(&counters.cursor_resets),
            kernel_suppressed_callbacks: load(&counters.kernel_suppressed_callbacks),
            kernel_audit_lost: load(&counters.kernel_audit_lost),
            overflow_carried: 0,
            profiles_pending_removal: self.state.read().retiring.len() as u64,
            profiles_removed: load(&counters.profiles_removed),
        }
    }

    pub(crate) fn last_error(&self) -> Option<String> {
        self.state.read().last_error.clone()
    }

    fn policy_version(&self) -> String {
        self.state
            .read()
            .active_policy
            .as_ref()
            .map(|policy| policy.version.clone())
            .unwrap_or_else(|| "unloaded".to_string())
    }

    fn clear_error(&self) {
        self.state.write().last_error = None;
    }

    fn set_error(&self, message: String) {
        self.state.write().last_error = Some(message);
    }

    fn lookup_subject(&self, pid: u32, label: &str) -> Option<AppArmorSubject> {
        let state = self.state.read();
        state
            .subjects
            .get(&pid)
            .filter(|subject| subject.label == label)
            .cloned()
            .or_else(|| {
                state
                    .tombstones
                    .get(&pid)
                    .map(|tombstone| tombstone.subject.clone())
                    .filter(|subject| subject.label == label)
            })
            .or_else(|| {
                state
                    .subjects
                    .values()
                    .find(|subject| subject.label == label)
                    .cloned()
            })
            .or_else(|| {
                state
                    .tombstones
                    .values()
                    .map(|tombstone| &tombstone.subject)
                    .find(|subject| subject.label == label)
                    .cloned()
            })
    }

    fn current_profile_matches(&self, pid: u32, expected_label: &str) -> anyhow::Result<bool> {
        let current = read_proc_label(&self.host.proc_root, pid)
            .ok_or_else(|| anyhow!("read AppArmor label of pid {pid} from /proc"))?;
        Ok(base_label(current.as_str()) == expected_label)
    }

    fn ensure_profile_loaded(&self, agent_id: Uuid, profile: &str) -> anyhow::Result<()> {
        let policy = self.state.read().active_policy.clone().ok_or_else(|| {
            anyhow!("cannot render AppArmor profile without an active Mercury policy")
        })?;
        let label = profile_label(agent_id);
        let profile_text = render_profile_with_capabilities(
            &policy,
            label.as_str(),
            agent_id,
            profile,
            &self.capabilities,
        )?;
        let profile_path = self.profile_path(label.as_str());
        fs::write(&profile_path, profile_text)
            .with_context(|| format!("write AppArmor policy {}", profile_path.display()))?;
        run_apparmor_parser(
            self.config.parser_path.as_str(),
            &["--replace", "--skip-cache"],
            profile_path.as_path(),
        )
    }

    fn unload_profile_by_label(&self, label: &str) -> Result<(), String> {
        let profile_path = self.profile_path(label);
        if !profile_path.exists() {
            return Ok(());
        }
        let result = run_apparmor_parser(
            self.config.parser_path.as_str(),
            &["--remove"],
            profile_path.as_path(),
        )
        .map_err(|err| {
            warn!(error = %err, label, "failed to remove AppArmor profile");
            format!("{err:#}")
        });
        let _ = fs::remove_file(&profile_path);
        result
    }

    fn generated_policy_dir(&self) -> PathBuf {
        PathBuf::from(&self.config.generated_policy_dir)
    }

    fn profile_path(&self, label: &str) -> PathBuf {
        self.generated_policy_dir()
            .join(format!("{label}.apparmor"))
    }
}

fn build_sources(config: &AppArmorConfig, host: &HostPaths) -> AuditSources {
    let state_dir = PathBuf::from(&config.generated_policy_dir);
    let journald = |selection| {
        Some(JournaldReader::new(
            host.journalctl.clone(),
            selection,
            state_dir.as_path(),
        ))
    };
    let audit_log = |optional| {
        Some(AuditLogReader::new(
            PathBuf::from(&config.audit_log_path),
            state_dir.as_path(),
            optional,
        ))
    };
    match config.audit_source {
        AppArmorAuditSource::Auto => AuditSources {
            journald: journald(JournalSelection::AuditAndKernel),
            audit_log: audit_log(true),
            audit_log_optional: true,
        },
        AppArmorAuditSource::JournaldAudit => AuditSources {
            journald: journald(JournalSelection::Audit),
            ..AuditSources::default()
        },
        AppArmorAuditSource::JournaldKernel => AuditSources {
            journald: journald(JournalSelection::Kernel),
            ..AuditSources::default()
        },
        AppArmorAuditSource::AuditLog => AuditSources {
            audit_log: audit_log(false),
            ..AuditSources::default()
        },
    }
}

/// Journal entries (or log lines) read per drain for an event budget.
/// Irrelevant kernel lines are read too, so allow some headroom.
fn read_limit(budget: usize) -> usize {
    budget.saturating_mul(4).clamp(256, 32_768)
}

/// Records the launcher itself produces right after a pre-exec launch:
/// by the enrollment root, not a deny, within the bootstrap window, and
/// either from `mercury-run` or the file descriptors it handed over.
fn is_launcher_bootstrap(record: &ParsedAuditRecord, attribution: &Attribution) -> bool {
    let in_window = attribution
        .bootstrap_until
        .is_some_and(|until| Instant::now() < until);
    if !in_window || record.decision() == Decision::Deny {
        return false;
    }
    if record.pid.is_some() && record.pid != attribution.root_pid {
        return false;
    }
    record.comm.as_deref() == Some(LAUNCHER_COMM)
        || record
            .name
            .as_deref()
            .is_some_and(|name| name.rsplit('/').next() == Some(LAUNCHER_COMM))
        || record.operation == "file_inherit"
}

/// Reason for a kernel verdict that could not be cross-checked.
fn kernel_reason(verdict: &Verdict) -> DecisionReason {
    match verdict {
        Verdict::Denied | Verdict::Killed => DecisionReason::DenyByRule,
        Verdict::Allowed => DecisionReason::AllowByObserveMode,
        Verdict::Audit => DecisionReason::AllowByRule,
        Verdict::Status | Verdict::Unknown => DecisionReason::Informational,
    }
}

fn record_context(record: &ParsedAuditRecord, attribution: &Attribution) -> EventContext {
    EventContext {
        source: Some(EVENT_SOURCE.to_string()),
        comm: record.comm.clone(),
        root_pid: attribution.root_pid,
        correlation_id: record.stamp.map(|stamp| stamp.correlation_id()),
        ..EventContext::default()
    }
}

fn record_message(record: &ParsedAuditRecord, note: Option<&str>) -> String {
    let verb = match record.decision() {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    };
    let mut details = vec![format!("apparmor={}", record.verdict_raw)];
    for (key, value) in [
        ("class", &record.class),
        ("requested_mask", &record.requested_mask),
        ("denied_mask", &record.denied_mask),
        ("info", &record.info),
        ("error", &record.error),
        ("peer", &record.peer),
    ] {
        if let Some(value) = value {
            details.push(format!("{key}=\"{value}\""));
        }
    }
    details.push(format!("label={}", record.raw_label));
    let mut message = format!(
        "AppArmor {verb} {} {} [{}]",
        record.operation,
        record.path,
        details.join(" ")
    );
    if let Some(note) = note {
        message.push_str(" (");
        message.push_str(note);
        message.push(')');
    }
    message
}

fn sanitize_event_suffix(operation: &str) -> String {
    operation
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn agent_id_from_label(label: &str) -> Option<Uuid> {
    Uuid::parse_str(label.strip_prefix(PROFILE_PREFIX)?).ok()
}

/// `# mercury_agent_id=` / `# mercury_profile=` from a generated profile.
fn read_profile_header(path: &Path) -> (Option<Uuid>, Option<String>) {
    let Ok(text) = fs::read_to_string(path) else {
        return (None, None);
    };
    let mut agent_id = None;
    let mut profile = None;
    for line in text.lines().take(16) {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("# mercury_agent_id=") {
            agent_id = Uuid::parse_str(value.trim()).ok();
        } else if let Some(value) = line.strip_prefix("# mercury_profile=") {
            profile = Some(value.trim().to_string()).filter(|value| !value.is_empty());
        }
    }
    (agent_id, profile)
}

/// The AppArmor label of `pid`: the LSM-specific file first (stacked LSM
/// kernels), then the generic one.
fn read_proc_label(proc_root: &Path, pid: u32) -> Option<String> {
    ["attr/apparmor/current", "attr/current"]
        .iter()
        .find_map(|file| fs::read_to_string(proc_root.join(format!("{pid}/{file}"))).ok())
        .map(|value| value.trim_end_matches(['\0', '\n']).trim().to_string())
        .filter(|value| !value.is_empty())
}

/// `(state, ppid)` from `/proc/<pid>/stat` (comm may contain spaces).
fn parse_proc_stat(stat: &str) -> Option<(char, u32)> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;
    Some((state, ppid))
}

fn prune_tombstones(state: &mut AppArmorState) {
    let now = Instant::now();
    state
        .tombstones
        .retain(|_, tombstone| tombstone.expires_at > now);
}

fn process_metadata_hash(action_type: ActionType, record: &ParsedAuditRecord) -> Option<String> {
    match action_type {
        ActionType::ProcKill => record
            .signal
            .as_ref()
            .map(|signal| format!("signal={signal}")),
        ActionType::ProcCapable => record
            .capname
            .as_ref()
            .map(|capability| format!("cap={capability}"))
            .or_else(|| {
                record
                    .capability
                    .map(|capability| format!("cap={capability}"))
            }),
        ActionType::ProcPtrace => record
            .requested_mask
            .as_ref()
            .map(|mask| format!("ptrace={mask}")),
        ActionType::ProcMount => {
            let parts = [
                ("mountpoint", &record.name),
                ("src", &record.srcname),
                ("fstype", &record.fstype),
                ("flags", &record.flags),
            ]
            .into_iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
            .collect::<Vec<_>>();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

fn network_resource_from_record(
    action_type: ActionType,
    record: &ParsedAuditRecord,
) -> NetworkResource {
    let protocol = network_protocol_from_record(record);
    let base = NetworkResource {
        dest_host: None,
        dest_ip: None,
        dest_port: 0,
        protocol,
        full_url: None,
        scheme: None,
        method: None,
        path: None,
        query: None,
        socket_path: None,
        family: record.family.clone(),
    };

    if record.is_unix_socket() {
        let peer_side = matches!(action_type, ActionType::NetConnect | ActionType::NetSendmsg);
        return NetworkResource {
            socket_path: record.unix_socket_path(peer_side),
            family: Some("unix".to_string()),
            ..base
        };
    }

    match action_type {
        ActionType::NetConnect | ActionType::NetSendmsg => NetworkResource {
            dest_ip: record.peer_ip.clone().or_else(|| record.local_ip.clone()),
            dest_port: record.peer_port.or(record.local_port).unwrap_or(0),
            ..base
        },
        ActionType::NetBind => NetworkResource {
            dest_ip: record.local_ip.clone().or_else(|| record.peer_ip.clone()),
            dest_port: record.local_port.or(record.peer_port).unwrap_or(0),
            ..base
        },
        ActionType::NetListen | ActionType::NetAccept => NetworkResource {
            dest_ip: record.local_ip.clone(),
            dest_port: record.local_port.or(record.peer_port).unwrap_or(0),
            ..base
        },
        // Pre-v2 consumers read the address family code from dest_port.
        ActionType::NetCreate => NetworkResource {
            dest_port: network_family_code(record),
            ..base
        },
        _ => base,
    }
}

fn network_protocol_from_record(record: &ParsedAuditRecord) -> NetworkProtocol {
    let raw = record
        .protocol
        .as_deref()
        .or(record.sock_type.as_deref())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match raw.as_str() {
        "udp" | "dgram" | "17" => NetworkProtocol::Udp,
        _ => NetworkProtocol::Tcp,
    }
}

fn network_family_code(record: &ParsedAuditRecord) -> u16 {
    match record
        .family
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "unix" | "1" => 1,
        "inet" | "2" => 2,
        "inet6" | "10" => 10,
        _ => 0,
    }
}

fn detect_capabilities(parser_path: &str) -> AppArmorCapabilities {
    let enabled = fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|value| value.trim().eq_ignore_ascii_case("y"))
        .unwrap_or_else(|_| Path::new("/sys/kernel/security/apparmor/profiles").exists());
    let parser_present = Path::new(parser_path).exists();
    AppArmorCapabilities {
        enabled,
        parser_present,
        supports_fine_grained_network: parser_present
            && parser_supports_fine_grained_network(parser_path),
    }
}

fn parser_supports_fine_grained_network(parser_path: &str) -> bool {
    detect_parser_version(parser_path)
        .map(|version| version.major >= 4)
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AppArmorParserVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

fn detect_parser_version(parser_path: &str) -> Option<AppArmorParserVersion> {
    let output = Command::new(parser_path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .split_whitespace()
        .find_map(parse_parser_version_token)
}

fn parse_parser_version_token(token: &str) -> Option<AppArmorParserVersion> {
    let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some(AppArmorParserVersion {
        major,
        minor,
        patch,
    })
}

fn profile_label(agent_id: Uuid) -> String {
    format!("{PROFILE_PREFIX}{}", agent_id.simple())
}

#[cfg(test)]
fn render_profile(
    policy: &CompiledPolicy,
    label: &str,
    agent_id: Uuid,
    profile_name: &str,
) -> anyhow::Result<String> {
    render_profile_with_capabilities(
        policy,
        label,
        agent_id,
        profile_name,
        &AppArmorCapabilities {
            enabled: true,
            parser_present: true,
            supports_fine_grained_network: true,
        },
    )
}

fn render_profile_with_capabilities(
    policy: &CompiledPolicy,
    label: &str,
    agent_id: Uuid,
    profile_name: &str,
    capabilities: &AppArmorCapabilities,
) -> anyhow::Result<String> {
    let profile = policy
        .profiles
        .get(profile_name)
        .ok_or_else(|| anyhow!("profile '{profile_name}' not found in active Mercury policy"))?;

    let apparmor_mode = apparmor_enforcement_mode(profile_name, profile)?;
    let mut flags = vec!["audit", "attach_disconnected", "mediate_deleted"];
    if apparmor_mode == EnforcementMode::Observe {
        flags.push("complain");
    }

    let mut out = String::new();
    out.push_str("include <tunables/global>\n\n");
    out.push_str(&format!("profile {label} flags=({}) {{\n", flags.join(",")));
    out.push_str(&format!("  # mercury_profile={profile_name}\n"));
    out.push_str(&format!("  # mercury_agent_id={agent_id}\n"));
    out.push_str("  include <abstractions/base>\n");
    out.push_str("  /lib/** mr,\n");
    out.push_str("  /lib64/** mr,\n");
    out.push_str("  /usr/lib/** mr,\n");
    out.push_str("  /usr/lib64/** mr,\n");
    out.push_str("  /etc/ld.so.cache mr,\n");

    for root in &profile.workspace_roots {
        for rule in workspace_root_rules(root.as_str()) {
            out.push_str("  ");
            out.push_str(rule.as_str());
            out.push('\n');
        }
    }

    for rule in &profile.file_allow {
        out.push_str("  ");
        out.push_str(render_path_rule(rule.pattern.as_str(), false).as_str());
        out.push('\n');
    }
    for rule in &profile.file_deny {
        for line in render_path_deny_rule(rule.pattern.as_str()) {
            out.push_str("  ");
            out.push_str(line.as_str());
            out.push('\n');
        }
    }
    for rule in &profile.exec_allow {
        if is_kernel_process_sentinel(rule.path.as_str()) {
            continue;
        }
        out.push_str("  ");
        out.push_str(render_exec_allow_rule(rule.path.as_str()).as_str());
        out.push('\n');
    }
    for rule in implicit_exec_runtime_rules(&profile.exec_allow) {
        out.push_str("  ");
        out.push_str(rule.as_str());
        out.push('\n');
    }
    for rule in &profile.exec_deny {
        if is_kernel_process_sentinel(rule.path.as_str()) {
            continue;
        }
        out.push_str("  ");
        out.push_str(render_exec_deny_rule(rule.path.as_str()).as_str());
        out.push('\n');
    }
    for rule in render_process_rules(policy.defaults.decision, profile) {
        out.push_str("  ");
        out.push_str(rule.as_str());
        out.push('\n');
    }
    for rule in render_network_rules(
        policy.defaults.decision,
        profile,
        capabilities.supports_fine_grained_network,
    ) {
        out.push_str("  ");
        out.push_str(rule.as_str());
        out.push('\n');
    }
    if policy.defaults.decision == DefaultDecision::Allow {
        out.push_str("  /** rwklm,\n");
        out.push_str("  /** rix,\n");
    }

    out.push_str("}\n");
    Ok(out)
}

fn apparmor_enforcement_mode(
    profile_name: &str,
    profile: &policy_engine::CompiledProfile,
) -> anyhow::Result<EnforcementMode> {
    if profile.enforcement.file != profile.enforcement.process
        || profile.enforcement.file != profile.enforcement.network
    {
        return Err(anyhow!(
            "profile '{profile_name}' uses different file/process/network enforcement modes; AppArmor backend requires them to match"
        ));
    }
    Ok(profile.enforcement.file)
}

fn workspace_root_rules(root: &str) -> Vec<String> {
    let escaped = escape_apparmor_pattern(root);
    if root == "/" {
        return vec!["/** rwklm,".to_string()];
    }
    vec![format!("{escaped}/ rw,"), format!("{escaped}/** rwklm,")]
}

fn render_path_rule(pattern: &str, deny: bool) -> String {
    let escaped = escape_apparmor_pattern(pattern);
    let perms = if deny { "rwklmx" } else { "rwklm" };
    if deny {
        format!("deny {escaped} {perms},")
    } else {
        format!("{escaped} {perms},")
    }
}

// `<dir>/**` semantically means "everything under <dir>" — but the AppArmor
// glob `<dir>/**` does not cover the directory inode itself, so `ls <dir>`
// (readdir + getattr) would still succeed and leak entry names. Emit extra
// deny lines for the bare directory so the rule matches operator intent.
fn render_path_deny_rule(pattern: &str) -> Vec<String> {
    let mut lines = vec![render_path_rule(pattern, true)];
    if let Some(dir) = pattern.strip_suffix("/**")
        && !dir.is_empty()
        && !dir.contains(['*', '?', '['])
    {
        let escaped = escape_apparmor_pattern(dir);
        lines.push(format!("deny {escaped} rwklm,"));
        lines.push(format!("deny {escaped}/ rwklm,"));
    }
    lines
}

fn render_exec_allow_rule(path: &str) -> String {
    let escaped = escape_apparmor_pattern(path);
    // Exec permission must not grant file reads outside workspace_roots or
    // file_allow. The kernel checks execute separately from ordinary reads.
    format!("{escaped} ix,")
}

fn render_exec_deny_rule(path: &str) -> String {
    let escaped = escape_apparmor_pattern(path);
    format!("deny {escaped} x,")
}

fn implicit_exec_runtime_rules(exec_allow: &[policy_engine::CompiledExecRule]) -> Vec<String> {
    let mut rules = BTreeSet::new();

    for rule in exec_allow {
        let path = rule.path.as_str();
        if is_kernel_process_sentinel(path) {
            continue;
        }

        let Some(prefix) = runtime_prefix_for_exec(path) else {
            continue;
        };
        let escaped = escape_apparmor_pattern(prefix.as_str());
        rules.insert(format!("{escaped}/lib/ r,"));
        rules.insert(format!("{escaped}/lib/** mr,"));
        rules.insert(format!("{escaped}/lib64/ r,"));
        rules.insert(format!("{escaped}/lib64/** mr,"));
        rules.insert(format!("{escaped}/share/ r,"));
        rules.insert(format!("{escaped}/share/** r,"));
    }

    rules.into_iter().collect()
}

fn render_process_rules(
    default_decision: DefaultDecision,
    profile: &policy_engine::CompiledProfile,
) -> Vec<String> {
    let mut rules = Vec::new();
    let allow_by_default = default_decision == DefaultDecision::Allow;

    if allow_by_default || has_process_sentinel(&profile.exec_allow, "<ptrace>") {
        rules.push("ptrace,".to_string());
    }
    if has_process_sentinel(&profile.exec_deny, "<ptrace>") {
        rules.push("deny ptrace,".to_string());
    }

    if allow_by_default || has_process_sentinel(&profile.exec_allow, "<task-kill>") {
        rules.push("signal (send, receive),".to_string());
    }
    if has_process_sentinel(&profile.exec_deny, "<task-kill>") {
        rules.push("deny signal (send, receive),".to_string());
    }

    if allow_by_default || has_process_sentinel(&profile.exec_allow, "<capable>") {
        rules.push("capability,".to_string());
    }
    if has_process_sentinel(&profile.exec_deny, "<capable>") {
        rules.push("deny capability,".to_string());
    }

    rules
}

fn render_network_rules(
    default_decision: DefaultDecision,
    profile: &policy_engine::CompiledProfile,
    supports_fine_grained_network: bool,
) -> Vec<String> {
    let mut rules = BTreeSet::new();

    if default_decision == DefaultDecision::Allow {
        rules.insert("network,".to_string());
    }

    for rule in &profile.network_allow {
        for rendered in render_network_rule(rule, false, supports_fine_grained_network) {
            rules.insert(rendered);
        }
    }
    for rule in &profile.network_deny {
        for rendered in render_network_rule(rule, true, supports_fine_grained_network) {
            rules.insert(rendered);
        }
    }

    rules.into_iter().collect()
}

fn render_network_rule(
    rule: &core_types::NetworkRule,
    deny: bool,
    supports_fine_grained_network: bool,
) -> Vec<String> {
    if !supports_fine_grained_network {
        return render_coarse_network_rule(rule, deny).into_iter().collect();
    }

    if !can_render_network_rule(rule) {
        return Vec::new();
    }

    let mut rendered = BTreeSet::new();
    for access in [
        ("create", false),
        ("bind", false),
        ("listen", false),
        ("accept", false),
        ("connect", true),
        ("send", true),
        ("receive", true),
    ] {
        if let Some(rule_text) = render_network_access_rule(access.0, rule, deny, access.1) {
            rendered.insert(rule_text);
        }
    }

    rendered.into_iter().collect()
}

fn render_coarse_network_rule(rule: &core_types::NetworkRule, deny: bool) -> Option<String> {
    if rule.host_glob.is_some() || rule.cidr.is_some() || rule.port.is_some() {
        return None;
    }

    let mut parts = Vec::new();
    if deny {
        parts.push("deny".to_string());
    }
    parts.push("network".to_string());
    if let Some(domain) = apparmor_network_domain(rule) {
        parts.push(domain.to_string());
    }
    if let Some(protocol) = apparmor_network_protocol(rule) {
        parts.push(protocol.to_string());
    }

    Some(format!("{},", parts.join(" ")))
}

fn can_render_network_rule(rule: &core_types::NetworkRule) -> bool {
    rule.host_glob.is_none()
        && rule
            .cidr
            .as_ref()
            .map(|cidr| apparmor_single_ip(cidr).is_some())
            .unwrap_or(true)
}

fn render_network_access_rule(
    access: &str,
    rule: &core_types::NetworkRule,
    deny: bool,
    peer: bool,
) -> Option<String> {
    if !can_render_network_rule(rule) {
        return None;
    }

    let mut parts = Vec::new();
    if deny {
        parts.push("deny".to_string());
    }
    parts.push("network".to_string());
    parts.push(access.to_string());
    if let Some(domain) = apparmor_network_domain(rule) {
        parts.push(domain.to_string());
    }
    if let Some(protocol) = apparmor_network_protocol(rule) {
        parts.push(protocol.to_string());
    }
    if peer {
        if let Some(expression) = apparmor_network_peer_expression(rule) {
            parts.push(expression);
        }
    } else if let Some(expression) = apparmor_network_local_expression(rule) {
        parts.push(expression);
    }

    Some(format!("{},", parts.join(" ")))
}

fn apparmor_network_domain(rule: &core_types::NetworkRule) -> Option<&'static str> {
    match rule.cidr.as_ref().map(|cidr| cidr.addr()) {
        Some(std::net::IpAddr::V4(_)) => Some("inet"),
        Some(std::net::IpAddr::V6(_)) => Some("inet6"),
        None => None,
    }
}

fn apparmor_network_protocol(rule: &core_types::NetworkRule) -> Option<&'static str> {
    match rule.protocol {
        Some(NetworkProtocol::Tcp) => Some("tcp"),
        Some(NetworkProtocol::Udp) => Some("udp"),
        None => None,
    }
}

fn apparmor_network_local_expression(rule: &core_types::NetworkRule) -> Option<String> {
    let mut conditions = Vec::new();
    if let Some(cidr) = rule.cidr.as_ref().and_then(apparmor_single_ip) {
        conditions.push(format!("ip={cidr}"));
    }
    if let Some(port) = rule.port {
        conditions.push(format!("port={port}"));
    }
    (!conditions.is_empty()).then(|| conditions.join(" "))
}

fn apparmor_network_peer_expression(rule: &core_types::NetworkRule) -> Option<String> {
    apparmor_network_local_expression(rule).map(|expression| format!("peer=({expression})"))
}

fn apparmor_single_ip(cidr: &ipnet::IpNet) -> Option<String> {
    let prefix_len = cidr.prefix_len();
    let max_prefix_len = match cidr.addr() {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    (prefix_len == max_prefix_len).then(|| cidr.addr().to_string())
}

fn has_process_sentinel(rules: &[policy_engine::CompiledExecRule], sentinel: &str) -> bool {
    rules.iter().any(|rule| rule.path == sentinel)
}

fn runtime_prefix_for_exec(path: &str) -> Option<String> {
    if path.contains('*') || !path.starts_with('/') {
        return None;
    }

    let prefix = path
        .strip_suffix("/bin/python3")
        .or_else(|| path.strip_suffix("/bin/python3.11"))
        .or_else(|| path.strip_suffix("/bin/python"))
        .or_else(|| path.rsplit_once("/bin/").map(|(prefix, _)| prefix))?;

    if prefix.is_empty() || prefix == "/" || prefix == "/usr" {
        return None;
    }

    Some(prefix.to_string())
}

fn is_kernel_process_sentinel(path: &str) -> bool {
    path.starts_with('<') && path.ends_with('>')
}

fn escape_apparmor_pattern(pattern: &str) -> String {
    pattern
        .replace('\\', "\\\\")
        .replace(' ', "\\ ")
        .replace(',', "\\,")
}

fn run_apparmor_parser(
    parser_path: &str,
    args: &[&str],
    profile_path: &Path,
) -> anyhow::Result<()> {
    let output = Command::new(parser_path)
        .args(args)
        .arg(profile_path)
        .output()
        .with_context(|| format!("run {}", parser_path))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "apparmor_parser failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use core_types::FileOp;

    use super::*;
    use crate::apparmor_sources::tests::fake_journalctl;

    #[test]
    fn render_profile_includes_workspace_and_deny_rules() {
        let policy = policy_engine::load_policy_from_str(
            r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    workspace_roots: ["/workspace"]
    file_allow:
      - id: allow-src
        pattern: /workspace/src/**
    file_deny:
      - id: deny-secret
        pattern: /workspace/secrets/**
    exec_allow:
      - id: allow-echo
        path: /usr/bin/echo
    exec_deny:
      - id: deny-rm
        path: /bin/rm
"#,
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered =
            render_profile(&policy, "mercury-agent-test", Uuid::nil(), "default").expect("render");
        assert!(rendered.contains("/workspace/** rwklm,"));
        assert!(rendered.contains("/workspace/src/** rwklm,"));
        assert!(rendered.contains("deny /workspace/secrets/** rwklmx,"));
        // `<dir>/**` must also block listing/stat'ing the dir itself,
        // otherwise `ls /workspace/secrets/` leaks every entry name.
        assert!(rendered.contains("deny /workspace/secrets rwklm,"));
        assert!(rendered.contains("deny /workspace/secrets/ rwklm,"));
        assert!(rendered.contains("/usr/bin/echo ix,"));
        assert!(rendered.contains("deny /bin/rm x,"));
        assert!(!rendered.contains("/** ix,"));
    }

    #[test]
    fn render_path_deny_rule_skips_dir_expansion_when_no_recursive_suffix() {
        // A bare-path deny (`/foo/secret`) targets a single inode — don't
        // synthesize extra parent-dir lines for it.
        let lines = render_path_deny_rule("/foo/secret");
        assert_eq!(lines, vec!["deny /foo/secret rwklmx,".to_string()]);

        // A non-recursive glob (`/foo/*`) also doesn't expand — only `/**`.
        let lines = render_path_deny_rule("/foo/*");
        assert_eq!(lines, vec!["deny /foo/* rwklmx,".to_string()]);

        // `/foo/bar/**` expands into 3 lines: contents, dir-no-slash, dir-slash.
        let lines = render_path_deny_rule("/foo/bar/**");
        assert_eq!(
            lines,
            vec![
                "deny /foo/bar/** rwklmx,".to_string(),
                "deny /foo/bar rwklm,".to_string(),
                "deny /foo/bar/ rwklm,".to_string(),
            ]
        );
    }

    #[test]
    fn render_profile_includes_runtime_rules_for_exec_prefixes() {
        let policy = policy_engine::load_policy_from_str(
            r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    exec_allow:
      - id: allow-conda-python
        path: /opt/example-conda/bin/python3
"#,
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered =
            render_profile(&policy, "mercury-agent-test", Uuid::nil(), "default").expect("render");
        assert!(rendered.contains("/opt/example-conda/bin/python3 ix,"));
        assert!(rendered.contains("/opt/example-conda/lib/** mr,"));
        assert!(rendered.contains("/opt/example-conda/share/** r,"));
    }

    #[test]
    fn render_profile_allow_default_uses_explicit_fallback_rules() {
        let policy = policy_engine::load_policy_from_str(
            r#"
version: v1
defaults:
  decision: allow
profiles:
  default:
    file_deny:
      - id: deny-secret
        pattern: /workspace/secrets/**
    exec_deny:
      - id: deny-rm
        path: /bin/rm
"#,
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered =
            render_profile(&policy, "mercury-agent-test", Uuid::nil(), "default").expect("render");
        assert!(!rendered.contains("default_allow"));
        assert!(rendered.contains("/** rwklm,"));
        assert!(rendered.contains("/** rix,"));
        assert!(rendered.contains("deny /workspace/secrets/** rwklmx,"));
        assert!(rendered.contains("deny /bin/rm x,"));
    }

    #[test]
    fn render_profile_includes_process_mediation_rules() {
        let policy = policy_engine::load_policy_from_str(
            r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    exec_allow:
      - id: allow-ptrace
        path: "<ptrace>"
      - id: allow-kill
        path: "<task-kill>"
    exec_deny:
      - id: deny-cap
        path: "<capable>"
"#,
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered =
            render_profile(&policy, "mercury-agent-test", Uuid::nil(), "default").expect("render");
        assert!(rendered.contains("ptrace,"));
        assert!(rendered.contains("signal (send, receive),"));
        assert!(rendered.contains("deny capability,"));
    }

    #[test]
    fn render_profile_includes_network_mediation_rules() {
        let policy = policy_engine::load_policy_from_str(
            concat!(
                "version: v1\n",
                "defaults:\n",
                "  decision: deny\n",
                "profiles:\n",
                "  default:\n",
                "    network_allow:\n",
                "      - id: allow-api\n",
                "        cidr: 203.0.113.10/32\n",
                "        protocol: TCP\n",
                "        port: 443\n",
                "    network_deny:\n",
                "      - id: deny-dns\n",
                "        cidr: 203.0.113.53/32\n",
                "        protocol: UDP\n",
                "        port: 53\n",
            ),
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered = render_profile_with_capabilities(
            &policy,
            "mercury-agent-test",
            Uuid::nil(),
            "default",
            &AppArmorCapabilities {
                enabled: true,
                parser_present: true,
                supports_fine_grained_network: true,
            },
        )
        .expect("render");
        assert!(rendered.contains("network connect inet tcp peer=(ip=203.0.113.10 port=443),"));
        assert!(rendered.contains("network bind inet tcp ip=203.0.113.10 port=443,"));
        assert!(rendered.contains("deny network connect inet udp peer=(ip=203.0.113.53 port=53),"));
    }

    #[test]
    fn render_profile_skips_unrepresentable_network_rules_on_legacy_parser() {
        let policy = policy_engine::load_policy_from_str(
            concat!(
                "version: v1\n",
                "defaults:\n",
                "  decision: deny\n",
                "profiles:\n",
                "  default:\n",
                "    network_allow:\n",
                "      - id: allow-local\n",
                "        cidr: 127.0.0.1/32\n",
                "        protocol: TCP\n",
                "        port: 443\n",
            ),
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled;

        let rendered = render_profile_with_capabilities(
            &policy,
            "mercury-agent-test",
            Uuid::nil(),
            "default",
            &AppArmorCapabilities {
                enabled: true,
                parser_present: true,
                supports_fine_grained_network: false,
            },
        )
        .expect("render");

        assert!(!rendered.contains("network connect inet tcp peer=(ip=127.0.0.1 port=443),"));
        assert!(!rendered.contains("network bind inet tcp ip=127.0.0.1 port=443,"));
    }

    #[test]
    fn policy_rejects_mismatched_file_and_process_modes() {
        let err = policy_engine::load_policy_from_str(
            r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    exec_allow:
      - id: allow-echo
        path: /usr/bin/echo
    enforcement:
      file: enforce
      process: observe
      network: enforce
"#,
            policy_engine::SignatureVerification::Disabled,
        )
        .expect_err("mixed modes should be rejected");
        assert!(
            err.to_string()
                .contains("enforcement.file and enforcement.process must match")
        );
    }

    fn parsed(text: &str) -> ParsedAuditRecord {
        match parse_line(&RawAuditLine::kernel(text)) {
            ParsedLine::Record(record) => *record,
            other => panic!("expected record, got {other:?}"),
        }
    }

    #[test]
    fn parse_apparmor_audit_line_extracts_file_access() {
        let record = parsed(
            r#"audit: type=1400 audit(1.0:2): apparmor="DENIED" operation="open" profile="mercury-agent-abc" name="/workspace/secrets/x" pid=42 fsuid=1000 requested_mask="r" denied_mask="r""#,
        );
        assert_eq!(record.decision(), Decision::Deny);
        assert_eq!(record.path, "/workspace/secrets/x");
        assert_eq!(record.pid, Some(42));
        assert_eq!(record.uid, Some(1000));
    }

    #[test]
    fn parse_apparmor_network_record_uses_peer_fallback_path() {
        let record = parsed(
            r#"audit: type=1400 audit(1.0:2): apparmor="DENIED" operation="connect" profile="mercury-agent-abc" pid=42 fsuid=1000 family="inet" sock_type="stream" protocol="tcp" peer_addr="203.0.113.10" peer_port=443"#,
        );
        assert_eq!(record.path, "203.0.113.10:443");
        assert_eq!(record.peer_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(record.peer_port, Some(443));
        let resource = network_resource_from_record(ActionType::NetConnect, &record);
        assert_eq!(resource.dest_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(resource.dest_port, 443);
        assert_eq!(resource.family.as_deref(), Some("inet"));
        assert_eq!(resource.socket_path, None);
    }

    #[test]
    fn unix_socket_records_carry_socket_path_and_family() {
        let record = parsed(
            r#"audit: type=1400 audit(1.0:2): apparmor="DENIED" operation="connect" class="net" family="unix" sock_type="stream" protocol=0 profile="mercury-agent-abc" pid=42 requested_mask="send connect" addr=none peer_addr="@/tmp/.X11-unix/X0" peer="unconfined""#,
        );
        assert_eq!(
            action_from_record(&record),
            Some(AppArmorAction::Network(ActionType::NetConnect))
        );
        let resource = network_resource_from_record(ActionType::NetConnect, &record);
        assert_eq!(resource.family.as_deref(), Some("unix"));
        assert_eq!(resource.socket_path.as_deref(), Some("@/tmp/.X11-unix/X0"));
        assert_eq!(resource.dest_ip, None);
    }

    #[test]
    fn action_mapping_handles_mutations() {
        assert_eq!(
            action_from_operation("rename_src", None),
            Some(AppArmorAction::File(ActionType::FileRename, FileOp::Rename))
        );
        assert_eq!(
            action_from_operation("open", Some("c")),
            Some(AppArmorAction::File(ActionType::FileCreate, FileOp::Create))
        );
        assert_eq!(
            action_from_operation("open", Some("w")),
            Some(AppArmorAction::File(ActionType::FileWrite, FileOp::Write))
        );
        assert_eq!(
            action_from_operation("exec", Some("x")),
            Some(AppArmorAction::Exec)
        );
        assert_eq!(
            action_from_operation("ptrace", None),
            Some(AppArmorAction::Process(ActionType::ProcPtrace, "<ptrace>"))
        );
        assert_eq!(
            action_from_operation("signal", None),
            Some(AppArmorAction::Process(ActionType::ProcKill, "<task-kill>"))
        );
        assert_eq!(
            action_from_operation("capable", None),
            Some(AppArmorAction::Process(
                ActionType::ProcCapable,
                "<capable>"
            ))
        );

        let network_record = ParsedAuditRecord {
            timestamp: Utc.timestamp_micros(0).single().expect("timestamp"),
            verdict: Verdict::Denied,
            operation: "connect".to_string(),
            path: "203.0.113.10:443".to_string(),
            pid: Some(42),
            uid: Some(1000),
            label: "mercury-agent-abc".to_string(),
            family: Some("inet".to_string()),
            sock_type: Some("stream".to_string()),
            protocol: Some("tcp".to_string()),
            peer_ip: Some("203.0.113.10".to_string()),
            peer_port: Some(443),
            ..ParsedAuditRecord::default()
        };
        assert_eq!(
            action_from_record(&network_record),
            Some(AppArmorAction::Network(ActionType::NetConnect))
        );
    }

    #[test]
    fn file_create_is_not_mistaken_for_socket_create() {
        // Every kernel-transport message carries `type=1400`, which used to be
        // read as a socket type and turned file creates into NET_CREATE.
        let record = parsed(
            r#"audit: type=1400 audit(1.0:2): apparmor="AUDIT" operation="create" class="file" profile="mercury-agent-abc" name="/workspace/new.txt" pid=42 requested_mask="c""#,
        );
        assert_eq!(
            action_from_record(&record),
            Some(AppArmorAction::File(ActionType::FileCreate, FileOp::Create))
        );
    }

    #[test]
    fn parse_process_audit_record_uses_process_fallback_path() {
        let record = parsed(
            r#"audit: type=1400 audit(1.0:2): apparmor="DENIED" operation="signal" profile="mercury-agent-abc" pid=42 fsuid=1000 signal="term""#,
        );
        assert_eq!(record.path, "<task-kill>");
        assert_eq!(record.signal.as_deref(), Some("term"));
        assert_eq!(record.signal_number(), Some(15));
    }

    const AGENT: &str = "0123456789abcdef0123456789abcdef";

    fn agent_uuid() -> Uuid {
        Uuid::parse_str(AGENT).expect("uuid")
    }

    fn agent_label() -> String {
        format!("{PROFILE_PREFIX}{AGENT}")
    }

    fn test_policy(enforcement: &str) -> CompiledPolicy {
        policy_engine::load_policy_from_str(
            &format!(
                r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    workspace_roots: ["/workspace"]
    file_deny:
      - id: deny-secret
        pattern: /workspace/secrets/**
    exec_allow:
      - id: allow-echo
        path: /usr/bin/echo
    enforcement:
      file: {enforcement}
      process: {enforcement}
      network: {enforcement}
"#
            ),
            policy_engine::SignatureVerification::Disabled,
        )
        .expect("load policy")
        .compiled
    }

    fn fake_parser(dir: &Path) -> PathBuf {
        let script = dir.join("apparmor_parser");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\n\
                 if [ \"$1\" = \"--version\" ]; then echo 'AppArmor parser version 4.0.1'; fi\n",
                dir.join("parser.args").display()
            ),
        )
        .expect("write parser");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        script
    }

    fn test_manager(
        dir: &Path,
        source: AppArmorAuditSource,
        backend: FilesystemBackend,
        journal_fixture: &str,
        journal_exit: i32,
    ) -> AppArmorManager {
        let policy_dir = dir.join("policy");
        let proc_root = dir.join("proc");
        fs::create_dir_all(&policy_dir).expect("policy dir");
        fs::create_dir_all(&proc_root).expect("proc dir");
        let journalctl = fake_journalctl(dir, journal_fixture, "s=tail", journal_exit, "boom");
        AppArmorManager::new_with_host(
            AppArmorConfig {
                parser_path: fake_parser(dir).display().to_string(),
                generated_policy_dir: policy_dir.display().to_string(),
                audit_source: source,
                audit_log_path: dir.join("audit.log").display().to_string(),
            },
            backend,
            HostPaths {
                journalctl,
                proc_root,
            },
        )
    }

    fn kernel_entry(cursor: &str, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": "1790684427000000",
            "_TRANSPORT": "kernel",
            "MESSAGE": message,
        })
        .to_string()
    }

    fn audit_entry(cursor: &str, audit_id: u64, source_us: i64, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": "1790684427000000",
            "_TRANSPORT": "audit",
            "_AUDIT_ID": audit_id.to_string(),
            "_SOURCE_REALTIME_TIMESTAMP": source_us.to_string(),
            "MESSAGE": message,
        })
        .to_string()
    }

    fn avc(stamp: &str, body: &str) -> String {
        format!("audit: type=1400 audit({stamp}): {body}")
    }

    fn system_event<'a>(events: &'a [AuditEvent], name: &str) -> Option<&'a AuditEvent> {
        events.iter().find(|event| match &event.resource {
            Resource::System(system) => system.event == name,
            _ => false,
        })
    }

    fn event_for_path<'a>(events: &'a [AuditEvent], path: &str) -> &'a AuditEvent {
        events
            .iter()
            .find(|event| match &event.resource {
                Resource::File(file) => file.path == path,
                Resource::Exec(exec) => exec.path == path,
                _ => false,
            })
            .unwrap_or_else(|| panic!("no event for {path}: {events:#?}"))
    }

    fn write_profile_file(dir: &Path, label: &str, agent_id: Uuid, profile: &str) {
        fs::write(
            dir.join("policy").join(format!("{label}.apparmor")),
            format!(
                "include <tunables/global>\n\nprofile {label} flags=(audit) {{\n  # mercury_profile={profile}\n  # mercury_agent_id={agent_id}\n}}\n"
            ),
        )
        .expect("write profile");
    }

    #[test]
    fn drain_turns_every_record_kind_into_an_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let audit_body = format!(
            r#"apparmor="AUDIT" operation="open" class="file" profile="{label}" name="/workspace/src/a.rs" pid=4242 comm="python3" requested_mask="r" fsuid=1000 ouid=0"#
        );
        let fixture = [
            kernel_entry("s=1;i=1", &avc("1790684426.065:100", &audit_body)),
            // The same record over journald's audit transport.
            audit_entry("s=1;i=2", 100, 1_790_684_426_065_000, &format!("AVC {audit_body}")),
            kernel_entry(
                "s=1;i=3",
                &avc(
                    "1790684426.070:101",
                    &format!(
                        r#"apparmor="DENIED" operation="open" class="file" info="Failed name lookup" error=-13 profile="{label}" name="/workspace/secrets/key" pid=4242 comm="python3" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0"#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=4",
                &avc(
                    "1790684426.071:102",
                    &format!(
                        r#"apparmor="AUDIT" operation="file_mmap" class="file" profile="{label}" name="/usr/lib/x86_64-linux-gnu/libc.so.6" pid=4242 comm="python3" requested_mask="mr" fsuid=1000 ouid=0"#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=5",
                &avc(
                    "1790684426.072:103",
                    &format!(
                        r#"apparmor="STATUS" operation="profile_load" profile="unconfined" name="{label}" pid=10 comm="apparmor_parser""#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=6",
                &avc(
                    "1790684426.073:104",
                    &format!(
                        r#"apparmor="DENIED" operation="change_profile" class="file" profile="{label}" name="unconfined" pid=4242 comm="python3""#
                    ),
                ),
            ),
            kernel_entry("s=1;i=7", "kauditd_printk_skb: 12 callbacks suppressed"),
            kernel_entry(
                "s=1;i=8",
                &avc(
                    "1790684426.074:105",
                    r#"apparmor="DENIED" operation="open" class="file" profile="mercury-agent-not-a-uuid" name="/etc/shadow" pid=99 requested_mask="r" denied_mask="r""#,
                ),
            ),
            kernel_entry(
                "s=1;i=9",
                &avc(
                    "1790684426.075:106",
                    &format!(
                        // "/workspace/secrets/a b.txt", hex-encoded by the kernel.
                        r#"apparmor="DENIED" operation="open" class="file" profile="{label}" name=2F776F726B73706163652F736563726574732F6120622E747874 pid=4242 comm="python3" requested_mask="r" denied_mask="r""#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=10",
                &avc(
                    "1790684426.076:107",
                    &format!(
                        r#"apparmor="DENIED" operation="signal" class="signal" profile="{label}" pid=4242 comm="python3" requested_mask="send" denied_mask="send" signal=term peer="unconfined""#
                    ),
                ),
            ),
        ]
        .join("\n");

        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::Auto,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        // Written by a previous daemon run; no subject is registered now.
        write_profile_file(dir.path(), &label, agent_uuid(), "default");
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");

        let events = manager.drain_audit_events_limited(100);
        assert_eq!(events.len(), 9, "{events:#?}");

        let allowed = event_for_path(&events, "/workspace/src/a.rs");
        assert_eq!(allowed.decision, Decision::Allow);
        assert_eq!(allowed.reason, DecisionReason::AllowByRule);
        assert_eq!(allowed.action_type, ActionType::FileRead);
        assert_eq!(allowed.agent_id, agent_uuid().to_string());
        assert_eq!(allowed.profile, "default");
        assert_eq!(allowed.timestamp.timestamp_millis(), 1_790_684_426_065);
        assert_eq!(allowed.uid, Some(1000));
        assert_eq!(allowed.pid, Some(4242));
        assert_eq!(allowed.ppid, None, "dead task: ppid unknown, not guessed");
        assert_eq!(allowed.context.source.as_deref(), Some("apparmor"));
        assert_eq!(allowed.context.comm.as_deref(), Some("python3"));
        assert_eq!(
            allowed.context.correlation_id.as_deref(),
            Some("audit(1790684426.065:100)")
        );

        let denied = event_for_path(&events, "/workspace/secrets/key");
        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(denied.reason, DecisionReason::DenyByRule);
        assert_eq!(denied.rule_id.as_deref(), Some("deny-secret"));
        assert!(denied.message.contains("info=\"Failed name lookup\""));
        assert!(denied.message.contains("error=\"-13\""));
        assert!(denied.message.contains("denied_mask=\"r\""));

        let baseline = event_for_path(&events, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(baseline.action_type, ActionType::FileMmap);
        assert_eq!(baseline.decision, Decision::Allow);
        assert_eq!(baseline.rule_id.as_deref(), Some(BASELINE_RULE_ID));
        assert_eq!(manager.last_error(), None, "baseline allows are not errors");

        let hex = event_for_path(&events, "/workspace/secrets/a b.txt");
        assert_eq!(hex.decision, Decision::Deny);

        let signal = event_for_path(&events, "<task-kill>");
        assert_eq!(signal.action_type, ActionType::ProcKill);
        assert_eq!(signal.context.signal, Some(15));

        let status = system_event(&events, "apparmor_profile_load").expect("status event");
        assert_eq!(status.agent_id, agent_uuid().to_string());
        assert_eq!(status.reason, DecisionReason::Informational);

        let unmapped =
            system_event(&events, "apparmor_unmapped_operation").expect("unmapped event");
        assert_eq!(unmapped.decision, Decision::Deny);
        assert_eq!(unmapped.reason, DecisionReason::DenyByRule);
        assert_eq!(unmapped.detail_operation(), "change_profile");

        let loss = system_event(&events, "telemetry_loss").expect("loss event");
        let Resource::System(loss_resource) = &loss.resource else {
            unreachable!()
        };
        assert_eq!(loss_resource.attributes["source"], "kernel_printk");
        assert_eq!(loss_resource.attributes["count"], 12);

        let unattributed = event_for_path(&events, "/etc/shadow");
        assert_eq!(unattributed.agent_id, "mercury-agent-not-a-uuid");
        assert_eq!(unattributed.profile, UNKNOWN_PROFILE);
        assert_eq!(unattributed.decision, Decision::Deny);

        let stats = manager.telemetry_stats();
        assert_eq!(stats.records_parsed, 9);
        assert_eq!(stats.records_deduplicated, 1);
        assert_eq!(stats.records_emitted, 8);
        assert_eq!(stats.records_unmapped, 1);
        assert_eq!(stats.records_unattributed, 1);
        assert_eq!(stats.kernel_suppressed_callbacks, 12);
        assert_eq!(stats.verdict_mismatches, 1);

        let cursor = manager
            .sources
            .lock()
            .journald
            .as_ref()
            .and_then(|reader| reader.cursor().map(str::to_string));
        assert_eq!(cursor.as_deref(), Some("s=1;i=10"));
        assert!(manager.drain_audit_events_limited(100).is_empty());
    }

    trait SystemDetail {
        fn detail_operation(&self) -> String;
    }

    impl SystemDetail for AuditEvent {
        fn detail_operation(&self) -> String {
            match &self.resource {
                Resource::System(system) => system.attributes["operation"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                _ => String::new(),
            }
        }
    }

    #[test]
    fn drain_budget_leaves_the_rest_for_the_next_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let fixture = (1..=5)
            .map(|idx| {
                kernel_entry(
                    &format!("s=1;i={idx}"),
                    &avc(
                        &format!("1790684426.000:{idx}"),
                        &format!(
                            r#"apparmor="DENIED" operation="open" profile="{label}" name="/workspace/secrets/{idx}" pid=7 requested_mask="r" denied_mask="r""#
                        ),
                    ),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");

        let mut paths = Vec::new();
        for expected in [2, 2, 1, 0] {
            let events = manager.drain_audit_events_limited(2);
            assert_eq!(events.len(), expected);
            paths.extend(events.into_iter().map(|event| match event.resource {
                Resource::File(file) => file.path,
                other => panic!("unexpected {other:?}"),
            }));
        }
        assert_eq!(
            paths,
            (1..=5)
                .map(|idx| format!("/workspace/secrets/{idx}"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_failure_is_reported_once_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            "",
            1,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");

        let events = manager.drain_audit_events_limited(10);
        assert_eq!(events.len(), 1);
        let event = system_event(&events, "apparmor_source_error").expect("error event");
        assert!(event.message.contains("boom"));
        assert!(manager.drain_audit_events_limited(10).is_empty());
        assert_eq!(manager.telemetry_stats().source_errors, 2);
    }

    #[test]
    fn cursor_persist_failure_keeps_the_batch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let fixture = kernel_entry(
            "s=1;i=1",
            &avc(
                "1790684426.000:1",
                &format!(
                    r#"apparmor="DENIED" operation="open" profile="{label}" name="/workspace/secrets/x" pid=7 requested_mask="r" denied_mask="r""#
                ),
            ),
        );
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        // A non-empty directory where the cursor file belongs makes the
        // final rename fail.
        let cursor_path = dir.path().join("policy").join("journal.cursor");
        fs::create_dir_all(cursor_path.join("blocker")).expect("block cursor path");

        let events = manager.drain_audit_events_limited(10);
        assert_eq!(events.len(), 2, "{events:#?}");
        event_for_path(&events, "/workspace/secrets/x");
        let error = system_event(&events, "apparmor_source_error").expect("persist error");
        let Resource::System(resource) = &error.resource else {
            unreachable!()
        };
        assert_eq!(resource.attributes["stage"], "cursor_persist");
        assert_eq!(manager.telemetry_stats().cursor_persist_errors, 1);

        // The in-memory cursor advanced, so the record is not emitted again.
        assert!(manager.drain_audit_events_limited(10).is_empty());
    }

    #[test]
    fn corrupt_cursor_at_start_emits_a_reset_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            "",
            0,
        );
        fs::write(
            dir.path().join("policy").join("journal.cursor"),
            vec![0u8; 64],
        )
        .expect("corrupt cursor");
        manager.start_sources().expect("start sources");

        // Queued events are delivered even before a policy is loaded.
        let events = manager.drain_audit_events_limited(10);
        let reset = system_event(&events, "apparmor_cursor_reset").expect("reset event");
        let Resource::System(resource) = &reset.resource else {
            unreachable!()
        };
        assert_eq!(resource.attributes["reason"], "corrupt_cursor_file");
        assert_eq!(manager.telemetry_stats().cursor_resets, 1);
    }

    #[test]
    fn audit_lost_reports_the_increase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = [
            kernel_entry(
                "s=1;i=1",
                "audit: audit_lost=5 audit_rate_limit=0 audit_backlog_limit=64",
            ),
            kernel_entry(
                "s=1;i=2",
                "audit: audit_lost=8 audit_rate_limit=0 audit_backlog_limit=64",
            ),
            kernel_entry("s=1;i=3", "audit: backlog limit exceeded"),
        ]
        .join("\n");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        let counts = manager
            .drain_audit_events_limited(10)
            .iter()
            .map(|event| match &event.resource {
                Resource::System(system) => (
                    system.attributes["source"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    system.attributes["count"].as_u64().unwrap_or_default(),
                ),
                other => panic!("unexpected {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            counts,
            vec![
                ("kernel_audit_lost".to_string(), 5),
                ("kernel_audit_lost".to_string(), 3),
                ("kernel_audit_backlog".to_string(), 1),
            ]
        );
        assert_eq!(manager.telemetry_stats().kernel_audit_lost, 9);
    }

    fn fake_process(dir: &Path, pid: u32, ppid: u32, state: char, label: &str, cwd: Option<&Path>) {
        let proc_dir = dir.join("proc").join(pid.to_string());
        fs::create_dir_all(proc_dir.join("attr")).expect("proc dir");
        fs::write(
            proc_dir.join("stat"),
            format!("{pid} (my (odd) comm) {state} {ppid} 1 1 0 -1 4194304"),
        )
        .expect("stat");
        fs::write(
            proc_dir.join("attr").join("current"),
            format!("{label} (enforce)\n"),
        )
        .expect("attr");
        if let Some(cwd) = cwd {
            std::os::unix::fs::symlink(cwd, proc_dir.join("cwd")).expect("cwd link");
        }
    }

    #[test]
    fn ppid_and_cwd_come_from_live_tasks_with_the_same_label() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(&workspace).expect("workspace");
        fake_process(dir.path(), 4242, 777, 'S', &label, Some(&workspace));
        // A recycled pid now running under another label.
        fake_process(dir.path(), 5000, 1, 'S', "unconfined", None);

        let fixture = [
            kernel_entry(
                "s=1;i=1",
                &avc(
                    "1790684426.000:1",
                    &format!(
                        r#"apparmor="AUDIT" operation="exec" class="file" profile="{label}" name="/usr/bin/echo" pid=4242 comm="sh" requested_mask="x" target="{label}""#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=2",
                &avc(
                    "1790684426.000:2",
                    &format!(
                        r#"apparmor="AUDIT" operation="open" class="file" profile="{label}" name="/workspace/y" pid=5000 comm="sh" requested_mask="r""#
                    ),
                ),
            ),
        ]
        .join("\n");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        write_profile_file(dir.path(), &label, agent_uuid(), "default");
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        let events = manager.drain_audit_events_limited(10);

        let exec = event_for_path(&events, "/usr/bin/echo");
        assert_eq!(exec.action_type, ActionType::ProcExec);
        assert_eq!(exec.ppid, Some(777));
        let Resource::Exec(resource) = &exec.resource else {
            unreachable!()
        };
        assert_eq!(resource.cwd, workspace.display().to_string());

        let recycled = event_for_path(&events, "/workspace/y");
        assert_eq!(recycled.ppid, None);
    }

    fn register_launch(manager: &AppArmorManager, pid: u32) {
        let prepared = manager
            .prepare_profile(agent_uuid(), "default")
            .expect("prepare")
            .expect("apparmor backend");
        manager
            .register_subject(
                pid,
                1,
                1000,
                0,
                agent_uuid(),
                "default",
                &prepared,
                SubjectRegistrationMode::PreExecLaunch,
            )
            .expect("register");
    }

    #[test]
    fn profile_stays_loaded_until_the_last_confined_task_exits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            "",
            0,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        register_launch(&manager, 100);
        let profile_file = dir.path().join("policy").join(format!("{label}.apparmor"));
        assert!(profile_file.exists());

        // The root exited; a daemonized child survives, plus a zombie.
        fake_process(dir.path(), 200, 1, 'S', &label, None);
        fake_process(dir.path(), 300, 1, 'Z', &label, None);
        assert!(manager.unregister_subject(100).expect("unregister"));

        let parser_args = || fs::read_to_string(dir.path().join("parser.args")).unwrap_or_default();
        assert!(!parser_args().contains("--remove"));
        assert!(profile_file.exists());
        assert_eq!(manager.prune_retired_profiles(), 0);
        assert_eq!(manager.telemetry_stats().profiles_pending_removal, 1);
        assert!(system_event(&manager.drain_audit_events_limited(10), "agent_exited").is_none());

        fs::remove_dir_all(dir.path().join("proc").join("200")).expect("child exits");
        assert_eq!(manager.prune_retired_profiles(), 1);
        assert!(parser_args().contains("--remove"));
        assert!(!profile_file.exists());

        let events = manager.drain_audit_events_limited(10);
        let exited = system_event(&events, "agent_exited").expect("agent_exited");
        assert_eq!(exited.agent_id, agent_uuid().to_string());
        assert_eq!(exited.context.root_pid, Some(100));
        let Resource::System(resource) = &exited.resource else {
            unreachable!()
        };
        assert_eq!(resource.attributes["confined_after_root_exit"], 1);
        assert_eq!(resource.attributes["deferred_checks"], 2);
        assert_eq!(resource.attributes["profile_removed"], true);
        let stats = manager.telemetry_stats();
        assert_eq!(stats.profiles_pending_removal, 0);
        assert_eq!(stats.profiles_removed, 1);
    }

    #[test]
    fn profile_without_survivors_is_removed_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            "",
            0,
        );
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        register_launch(&manager, 100);
        assert!(manager.unregister_subject(100).expect("unregister"));
        let events = manager.drain_audit_events_limited(10);
        assert!(system_event(&events, "agent_exited").is_some());
        assert_eq!(manager.telemetry_stats().profiles_removed, 1);
    }

    #[test]
    fn bootstrap_window_only_hides_launcher_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let fixture = [
            kernel_entry(
                "s=1;i=1",
                &avc(
                    "1790684426.000:1",
                    &format!(
                        r#"apparmor="ALLOWED" operation="open" class="file" profile="{label}" name="/etc/mercury/run.conf" pid=100 comm="mercury-run" requested_mask="r" denied_mask="r""#
                    ),
                ),
            ),
            kernel_entry(
                "s=1;i=2",
                &avc(
                    "1790684426.000:2",
                    &format!(
                        r#"apparmor="ALLOWED" operation="open" class="file" profile="{label}" name="/workspace/secrets/token" pid=100 comm="python3" requested_mask="r" denied_mask="r""#
                    ),
                ),
            ),
        ]
        .join("\n");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        manager
            .load_policy(&test_policy("observe"))
            .expect("policy");
        register_launch(&manager, 100);

        let events = manager.drain_audit_events_limited(10);
        assert_eq!(events.len(), 1, "{events:#?}");
        let would_deny = event_for_path(&events, "/workspace/secrets/token");
        assert_eq!(would_deny.decision, Decision::Allow);
        assert_eq!(would_deny.reason, DecisionReason::AllowByObserveMode);
        assert_eq!(would_deny.context.root_pid, Some(100));
        assert_eq!(manager.telemetry_stats().records_suppressed_bootstrap, 1);
    }

    #[test]
    fn orphaned_profiles_are_adopted_then_retired() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::JournaldKernel,
            FilesystemBackend::AppArmor,
            "",
            0,
        );
        write_profile_file(dir.path(), &label, agent_uuid(), "default");
        fake_process(dir.path(), 200, 1, 'S', &label, None);
        manager.adopt_orphan_profiles();
        assert_eq!(manager.telemetry_stats().profiles_pending_removal, 1);
        assert_eq!(
            manager.label_info(&label).and_then(|info| info.profile),
            Some("default".to_string())
        );
        assert_eq!(manager.prune_retired_profiles(), 0);

        fs::remove_dir_all(dir.path().join("proc").join("200")).expect("exit");
        assert_eq!(manager.prune_retired_profiles(), 1);
        let events = manager.drain_audit_events_limited(10);
        assert!(system_event(&events, "agent_exited").is_some());
    }

    #[test]
    fn audit_log_source_and_auto_dedupe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let label = agent_label();
        let body = format!(
            r#"apparmor="DENIED" operation="open" class="file" profile="{label}" name="/workspace/secrets/k" pid=7 requested_mask="r" denied_mask="r""#
        );
        fs::write(
            dir.path().join("audit.log"),
            format!("type=AVC msg=audit(1790684426.500:9): {body}\n"),
        )
        .expect("audit log");
        let fixture = kernel_entry("s=1;i=1", &avc("1790684426.500:9", &body));

        // Explicit audit_log mode reads only the file.
        let file_only = test_manager(
            dir.path(),
            AppArmorAuditSource::AuditLog,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        file_only
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        let events = file_only.drain_audit_events_limited(10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp.timestamp_millis(), 1_790_684_426_500);
        assert!(!dir.path().join("journalctl.args").exists());

        // auto reads journald and the file; the shared record is emitted once.
        fs::remove_file(dir.path().join("policy").join("auditlog.cursor")).expect("reset cursor");
        let auto = test_manager(
            dir.path(),
            AppArmorAuditSource::Auto,
            FilesystemBackend::AppArmor,
            &fixture,
            0,
        );
        auto.load_policy(&test_policy("enforce")).expect("policy");
        assert_eq!(auto.drain_audit_events_limited(10).len(), 1);
        assert_eq!(auto.telemetry_stats().records_deduplicated, 1);
    }

    #[test]
    fn ebpf_filesystem_backend_keeps_apparmor_paths_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = test_manager(
            dir.path(),
            AppArmorAuditSource::Auto,
            FilesystemBackend::EbpfLsm,
            "",
            0,
        );
        manager.start().expect("start is a no-op");
        manager
            .load_policy(&test_policy("enforce"))
            .expect("policy");
        assert!(
            manager
                .prepare_profile(agent_uuid(), "default")
                .expect("prepare")
                .is_none()
        );
        assert!(!manager.unregister_subject(1).expect("unregister"));
        assert_eq!(manager.prune_retired_profiles(), 0);
        assert!(manager.drain_audit_events_limited(10).is_empty());
        assert!(!dir.path().join("journalctl.args").exists());
        let parser_args = fs::read_to_string(dir.path().join("parser.args")).unwrap_or_default();
        assert!(!parser_args.contains("--replace") && !parser_args.contains("--remove"));
    }

    #[test]
    fn legacy_journald_audit_source_means_auto() {
        let config: AppArmorConfig =
            serde_json::from_str(r#"{"audit_source":"journald"}"#).expect("config");
        assert_eq!(config.audit_source, AppArmorAuditSource::Auto);
        assert_eq!(config.audit_log_path, "/var/log/audit/audit.log");
        for (raw, expected) in [
            ("auto", AppArmorAuditSource::Auto),
            ("journald_audit", AppArmorAuditSource::JournaldAudit),
            ("journald_kernel", AppArmorAuditSource::JournaldKernel),
            ("audit_log", AppArmorAuditSource::AuditLog),
        ] {
            let parsed: AppArmorAuditSource =
                serde_json::from_str(&format!("\"{raw}\"")).expect("source");
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn telemetry_stats_serialize_as_flat_counters() {
        let json = serde_json::to_value(AppArmorTelemetryStats::default()).expect("serialize");
        for key in [
            "records_parsed",
            "records_emitted",
            "records_unmapped",
            "records_unattributed",
            "parse_errors",
            "source_errors",
            "cursor_resets",
            "kernel_suppressed_callbacks",
            "overflow_carried",
        ] {
            assert_eq!(json[key], 0, "{key}");
        }
    }
}
