#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use core_types::AuditEvent;
use kernel_runtime::{
    BackendMode, EnrollmentSource, FilesystemBackend, KernelRuntime, KernelRuntimeConfig,
    KernelRuntimeHealth, UnmatchedHostMode,
};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use policy_engine::CompiledPolicy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

mod apparmor;
mod apparmor_records;
mod apparmor_sources;
pub use apparmor::{AppArmorAuditSource, AppArmorConfig, AppArmorTelemetryStats};
use apparmor::{AppArmorManager, PreparedProfile, SubjectRegistrationMode};

pub trait EventSourceAdapter: Send + Sync {
    fn start(&self) -> Result<(), AdapterError>;
}

pub trait EnforcementAdapter: Send + Sync {
    fn load_policy(&self, policy: &CompiledPolicy) -> Result<(), AdapterError>;
    fn status(&self) -> AdapterHookStatus;
    fn check_capabilities(&self) -> CapabilityReport;
    fn runtime_health(&self) -> AdapterRuntimeHealth;
    fn drain_audit_events_limited(
        &self,
        max_events: usize,
    ) -> Result<Vec<AuditEvent>, AdapterError>;
    fn drain_audit_events(&self) -> Result<Vec<AuditEvent>, AdapterError>;
}

pub trait PathResolver: Send + Sync {
    fn resolve_path(&self, path: &str) -> Result<String, AdapterError>;
}

pub trait ProcessTagger: Send + Sync {
    fn register_agent_pid(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
    ) -> Result<ProcessRegistration, AdapterError>;
    fn is_pid_tagged(&self, pid: u32) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub pid: u32,
    pub agent_id: Uuid,
    pub profile: String,
    pub uid: u32,
    pub cgroup_id: String,
    pub source: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterHookStatus {
    pub exec_hook: HookBackend,
    pub network_hook: HookBackend,
    pub filesystem_hook: HookBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookBackend {
    EbpfLsm,
    EbpfCgroup,
    AppArmor,
    ObserveOnly,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityReport {
    pub kernel_release: String,
    pub kernel_version_ok: bool,
    pub bpf_fs_present: bool,
    pub bpf_lsm_available: bool,
    pub cgroup_v2: bool,
    pub apparmor_enabled: bool,
    pub apparmor_parser_present: bool,
    pub selected_filesystem_backend: HookBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterRuntimeHealth {
    pub backend_mode: BackendMode,
    pub kernel_ready: bool,
    pub kernel_program_version: String,
    pub auto_enroll_active_rules: usize,
    pub unmatched_mode: UnmatchedHostMode,
    pub unenrolled_events_suppressed_total: u64,
    pub events_dropped_ringbuf_total: u64,
    pub events_rate_limited_total: u64,
    pub deny_events_dropped_total: u64,
    /// Optional LSM hooks the kernel could not attach (coverage gap).
    pub unavailable_hooks: Vec<String>,
    pub enrollment_sync_error: Option<String>,
}

#[derive(Debug, Clone)]
struct CompatEnrollment {
    record: EnrollmentRecord,
    proc_start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRegistration {
    pub cgroup_id: String,
    #[serde(default)]
    pub filesystem_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinuxAdapterConfig {
    pub cgroup_base: PathBuf,
    pub backend_mode: BackendMode,
    pub kernel: KernelRuntimeConfig,
    pub filesystem_backend: FilesystemBackend,
    pub apparmor: AppArmorConfig,
}

impl Default for LinuxAdapterConfig {
    fn default() -> Self {
        Self {
            cgroup_base: PathBuf::from("/sys/fs/cgroup/mercury/agents"),
            backend_mode: BackendMode::KernelStrict,
            kernel: KernelRuntimeConfig::default(),
            filesystem_backend: FilesystemBackend::AppArmor,
            apparmor: AppArmorConfig::default(),
        }
    }
}

#[derive(Debug)]
pub struct LinuxAdapter {
    config: LinuxAdapterConfig,
    runtime: Arc<KernelRuntime>,
    apparmor: AppArmorManager,
    state: RwLock<LinuxAdapterState>,
    overflow_carried: AtomicU64,
}

#[derive(Debug)]
struct LinuxAdapterState {
    pid_tags: HashMap<u32, Uuid>,
    compat_enrollments: HashMap<u32, CompatEnrollment>,
    status: AdapterHookStatus,
    capabilities: CapabilityReport,
    runtime_health: AdapterRuntimeHealth,
    auto_enroll_watcher: Option<AutoEnrollWatcher>,
    /// Events drained from a source but beyond a caller's limit; returned
    /// first by the next drain instead of being discarded.
    overflow: Vec<AuditEvent>,
}

struct AutoEnrollWatcher {
    _watcher: RecommendedWatcher,
}

impl std::fmt::Debug for AutoEnrollWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoEnrollWatcher").finish_non_exhaustive()
    }
}

impl LinuxAdapter {
    pub fn new(config: LinuxAdapterConfig) -> Self {
        let runtime = Arc::new(KernelRuntime::new(
            config.kernel.clone(),
            config.filesystem_backend,
        ));
        let apparmor = AppArmorManager::new(config.apparmor.clone(), config.filesystem_backend);
        let capabilities = map_capabilities(
            runtime.check_capabilities(),
            apparmor.capabilities(),
            config.filesystem_backend,
        );
        let initial_health = runtime.health();
        let status = map_hook_status(
            config.backend_mode,
            config.filesystem_backend,
            initial_health.clone(),
        );
        let runtime_health = map_runtime_health(
            config.backend_mode,
            config.filesystem_backend,
            initial_health,
            apparmor.last_error(),
        );

        Self {
            config,
            runtime,
            apparmor,
            state: RwLock::new(LinuxAdapterState {
                pid_tags: HashMap::new(),
                compat_enrollments: HashMap::new(),
                status,
                capabilities,
                runtime_health,
                auto_enroll_watcher: None,
                overflow: Vec::new(),
            }),
            overflow_carried: AtomicU64::new(0),
        }
    }

    fn install_auto_enroll_watcher(&self) -> Result<(), AdapterError> {
        if self.config.backend_mode != BackendMode::KernelStrict
            || self.config.kernel.auto_enroll_rules.is_empty()
        {
            self.state.write().auto_enroll_watcher = None;
            return Ok(());
        }

        let root = PathBuf::from(&self.config.kernel.cgroup_root);
        if !root.exists() {
            self.state.write().auto_enroll_watcher = None;
            return Ok(());
        }

        let runtime = Arc::clone(&self.runtime);
        let watcher_root = root.clone();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<Event>| match result {
                Ok(event) if should_trigger_auto_enroll_scan(&event) => {
                    if let Err(err) = runtime.scan_auto_enroll() {
                        warn!(
                            error = %err,
                            root = %watcher_root.display(),
                            "failed to refresh auto-enrollment after cgroup change"
                        );
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        error = %err,
                        root = %watcher_root.display(),
                        "auto-enrollment watcher reported an error"
                    );
                }
            })
            .context("create cgroup auto-enrollment watcher")?;
        watcher
            .watch(root.as_path(), RecursiveMode::Recursive)
            .with_context(|| format!("watch cgroup root {}", root.display()))?;

        self.state.write().auto_enroll_watcher = Some(AutoEnrollWatcher { _watcher: watcher });
        Ok(())
    }

    /// Re-enrolls an agent that survived a daemon restart. `members` are the
    /// live pids of its cgroup; `root_pid` must be one of them. Only the eBPF
    /// runtime needs this: AppArmor confinement lives in the kernel and the
    /// AppArmor backend adopts leftover profiles on start.
    pub fn restore_enrollment(
        &self,
        root_pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
        cgroup_id: &str,
        members: &[u32],
    ) -> Result<Option<u32>, AdapterError> {
        match self.config.backend_mode {
            BackendMode::KernelStrict => self
                .runtime
                .restore_enrollment(root_pid, agent_id, profile, uid, cgroup_id, members)
                .map(Some)
                .map_err(AdapterError::Runtime),
            BackendMode::LinuxCompat => Ok(None),
        }
    }

    pub fn register_launching_pid(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
    ) -> Result<ProcessRegistration, AdapterError> {
        let registration = self.prepare_process_registration(agent_id, profile)?;
        self.finalize_process_registration(
            pid,
            agent_id,
            profile,
            uid,
            &registration,
            SubjectRegistrationMode::PreExecLaunch,
        )?;
        Ok(registration)
    }

    pub fn register_existing_pid(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
    ) -> Result<ProcessRegistration, AdapterError> {
        let registration = self.prepare_process_registration(agent_id, profile)?;
        self.finalize_process_registration(
            pid,
            agent_id,
            profile,
            uid,
            &registration,
            SubjectRegistrationMode::ExistingProcess,
        )?;
        Ok(registration)
    }

    pub fn prepare_agent_launch(
        &self,
        agent_id: Uuid,
        profile: &str,
    ) -> Result<ProcessRegistration, AdapterError> {
        self.prepare_process_registration(agent_id, profile)
    }

    pub fn finalize_agent_launch(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
        registration: &ProcessRegistration,
    ) -> Result<(), AdapterError> {
        self.finalize_process_registration(
            pid,
            agent_id,
            profile,
            uid,
            registration,
            SubjectRegistrationMode::ExistingProcess,
        )
    }

    fn prepare_process_registration(
        &self,
        agent_id: Uuid,
        profile: &str,
    ) -> Result<ProcessRegistration, AdapterError> {
        let cgroup_id = format!("ai-{}", agent_id.simple());
        let cgroup_path = self.config.cgroup_base.join(&cgroup_id);
        fs::create_dir_all(&cgroup_path)
            .with_context(|| format!("create cgroup path {}", cgroup_path.display()))
            .map_err(AdapterError::Other)?;

        let filesystem_label = self
            .apparmor
            .prepare_profile(agent_id, profile)
            .map_err(AdapterError::Other)?
            .map(|prepared| prepared.label);

        Ok(ProcessRegistration {
            cgroup_id,
            filesystem_label,
        })
    }

    fn finalize_process_registration(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
        registration: &ProcessRegistration,
        mode: SubjectRegistrationMode,
    ) -> Result<(), AdapterError> {
        let proc_start_time = kernel_runtime::read_proc_start_time(pid).ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "read process start time for pid {pid} from /proc/{pid}/stat"
            ))
        })?;
        let ppid = read_proc_ppid(pid).unwrap_or(0);

        if let Some(label) = registration.filesystem_label.as_ref() {
            self.apparmor
                .register_subject(
                    pid,
                    ppid,
                    uid,
                    proc_start_time,
                    agent_id,
                    profile,
                    &PreparedProfile {
                        label: label.clone(),
                    },
                    mode,
                )
                .map_err(AdapterError::Other)?;
        }

        let procs_path = self
            .config
            .cgroup_base
            .join(&registration.cgroup_id)
            .join("cgroup.procs");
        fs::write(&procs_path, format!("{pid}\n"))
            .with_context(|| format!("write pid to {}", procs_path.display()))
            .map_err(AdapterError::Other)?;

        match self.config.backend_mode {
            BackendMode::KernelStrict => {
                self.runtime
                    .register_ai_run_pid(
                        pid,
                        agent_id,
                        profile,
                        uid,
                        registration.cgroup_id.as_str(),
                    )
                    .map_err(AdapterError::Runtime)?;
            }
            BackendMode::LinuxCompat => {
                self.state.write().compat_enrollments.insert(
                    pid,
                    CompatEnrollment {
                        record: EnrollmentRecord {
                            pid,
                            agent_id,
                            profile: profile.to_string(),
                            uid,
                            cgroup_id: registration.cgroup_id.clone(),
                            source: "ai_run".to_string(),
                            mode: "enforce".to_string(),
                        },
                        proc_start_time,
                    },
                );
            }
        }

        self.state.write().pid_tags.insert(pid, agent_id);
        Ok(())
    }

    pub fn list_enrollments(&self) -> Vec<EnrollmentRecord> {
        match self.config.backend_mode {
            BackendMode::KernelStrict => self
                .runtime
                .list_enrollments()
                .into_iter()
                .map(|(pid, enrollment)| EnrollmentRecord {
                    pid,
                    agent_id: enrollment.agent_id,
                    profile: enrollment.profile,
                    uid: enrollment.uid,
                    cgroup_id: enrollment.cgroup_id,
                    source: match enrollment.source {
                        EnrollmentSource::AiRun => "ai_run".to_string(),
                        EnrollmentSource::AutoEnroll => "auto_enroll".to_string(),
                        EnrollmentSource::Restored => "restored".to_string(),
                    },
                    mode: match enrollment.mode {
                        kernel_runtime::EnrollmentMode::Enforce => "enforce".to_string(),
                        kernel_runtime::EnrollmentMode::Observe => "observe".to_string(),
                    },
                })
                .collect(),
            BackendMode::LinuxCompat => self
                .state
                .read()
                .compat_enrollments
                .values()
                .map(|entry| entry.record.clone())
                .collect(),
        }
    }

    pub fn ignore_pid(&self, pid: u32) {
        if self.config.backend_mode == BackendMode::KernelStrict {
            self.runtime.ignore_pid(pid);
        }
    }

    pub fn enrollment_for_pid(&self, pid: u32) -> Option<EnrollmentRecord> {
        match self.config.backend_mode {
            BackendMode::KernelStrict => {
                let enrollment = self.runtime.enrollment_for_pid(pid)?;
                if kernel_runtime::read_proc_start_time(pid) != Some(enrollment.proc_start_time) {
                    let _ = self.runtime.remove_pid_enrollment(pid);
                    let _ = self.apparmor.unregister_subject(pid);
                    self.state.write().pid_tags.remove(&pid);
                    return None;
                }

                Some(EnrollmentRecord {
                    pid,
                    agent_id: enrollment.agent_id,
                    profile: enrollment.profile,
                    uid: enrollment.uid,
                    cgroup_id: enrollment.cgroup_id,
                    source: match enrollment.source {
                        EnrollmentSource::AiRun => "ai_run".to_string(),
                        EnrollmentSource::AutoEnroll => "auto_enroll".to_string(),
                        EnrollmentSource::Restored => "restored".to_string(),
                    },
                    mode: match enrollment.mode {
                        kernel_runtime::EnrollmentMode::Enforce => "enforce".to_string(),
                        kernel_runtime::EnrollmentMode::Observe => "observe".to_string(),
                    },
                })
            }
            BackendMode::LinuxCompat => {
                let enrollment = self.state.read().compat_enrollments.get(&pid).cloned()?;
                if kernel_runtime::read_proc_start_time(pid) != Some(enrollment.proc_start_time) {
                    let _ = self.remove_pid_enrollment(pid);
                    return None;
                }
                Some(enrollment.record)
            }
        }
    }

    pub fn remove_pid_enrollment(&self, pid: u32) -> Result<bool, AdapterError> {
        let removed = match self.config.backend_mode {
            BackendMode::KernelStrict => self.runtime.remove_pid_enrollment(pid)?,
            BackendMode::LinuxCompat => {
                self.state.write().compat_enrollments.remove(&pid).is_some()
            }
        };
        if removed {
            let _ = self.apparmor.unregister_subject(pid);
            self.state.write().pid_tags.remove(&pid);
        }
        Ok(removed)
    }

    pub fn prune_stale_enrollments(&self) -> Result<usize, AdapterError> {
        let stale_pids: Vec<u32> = match self.config.backend_mode {
            BackendMode::KernelStrict => self
                .runtime
                .list_enrollments()
                .into_iter()
                .filter_map(|(pid, enrollment)| {
                    (kernel_runtime::read_proc_start_time(pid) != Some(enrollment.proc_start_time))
                        .then_some(pid)
                })
                .collect(),
            BackendMode::LinuxCompat => self
                .state
                .read()
                .compat_enrollments
                .iter()
                .filter_map(|(pid, enrollment)| {
                    (kernel_runtime::read_proc_start_time(*pid) != Some(enrollment.proc_start_time))
                        .then_some(*pid)
                })
                .collect(),
        };

        let mut removed = 0;
        for pid in stale_pids {
            // Handles both backends; linux_compat enrollments live here, not
            // in the kernel runtime.
            if self.remove_pid_enrollment(pid)? {
                removed += 1;
            }
        }

        self.prune_apparmor_profiles();
        Ok(removed)
    }

    /// Unloads AppArmor profiles of exited agents once no task is confined
    /// by them any more, queueing a `SYSTEM_EVENT agent_exited` for each
    /// (delivered by the next drain). Profiles that still confine
    /// daemonized/double-forked children stay loaded and are re-checked on
    /// the next call. Called by [`Self::prune_stale_enrollments`]; returns
    /// the number of profiles removed. No-op unless
    /// `filesystem_backend: apparmor`.
    pub fn prune_apparmor_profiles(&self) -> usize {
        self.apparmor.prune_retired_profiles()
    }

    /// Counters for AppArmor audit ingestion and profile lifecycle.
    pub fn apparmor_telemetry_stats(&self) -> AppArmorTelemetryStats {
        AppArmorTelemetryStats {
            overflow_carried: self.overflow_carried.load(Ordering::Relaxed),
            ..self.apparmor.telemetry_stats()
        }
    }
}

impl EventSourceAdapter for LinuxAdapter {
    fn start(&self) -> Result<(), AdapterError> {
        fs::create_dir_all(&self.config.cgroup_base)
            .with_context(|| format!("create cgroup base {}", self.config.cgroup_base.display()))
            .map_err(AdapterError::Other)?;
        self.apparmor.start().map_err(AdapterError::Other)?;

        if self.config.backend_mode == BackendMode::LinuxCompat
            && self.config.filesystem_backend != FilesystemBackend::AppArmor
        {
            return Err(AdapterError::Unsupported(
                "linux_compat requires filesystem_backend=apparmor".to_string(),
            ));
        }

        if self.config.backend_mode == BackendMode::KernelStrict {
            self.runtime.start().map_err(AdapterError::Runtime)?;
            self.install_auto_enroll_watcher()?;
            if let Err(err) = self.runtime.scan_auto_enroll() {
                return Err(AdapterError::Runtime(err));
            }
        }

        let runtime_health = self.runtime.health();
        let mut state = self.state.write();
        state.status = map_hook_status(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health.clone(),
        );
        state.runtime_health = map_runtime_health(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health,
            self.apparmor.last_error(),
        );

        Ok(())
    }
}

impl EnforcementAdapter for LinuxAdapter {
    fn load_policy(&self, policy: &CompiledPolicy) -> Result<(), AdapterError> {
        if self.config.backend_mode == BackendMode::KernelStrict {
            self.runtime
                .load_policy(policy)
                .map_err(AdapterError::Runtime)?;
        }
        self.apparmor
            .load_policy(policy)
            .map_err(AdapterError::Other)?;

        let mut state = self.state.write();
        let runtime_health = self.runtime.health();
        state.status = map_hook_status(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health.clone(),
        );
        state.runtime_health = map_runtime_health(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health,
            self.apparmor.last_error(),
        );
        Ok(())
    }

    fn status(&self) -> AdapterHookStatus {
        self.state.read().status.clone()
    }

    fn check_capabilities(&self) -> CapabilityReport {
        self.state.read().capabilities.clone()
    }

    fn runtime_health(&self) -> AdapterRuntimeHealth {
        let runtime_health = self.runtime.health();
        let mapped = map_runtime_health(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health.clone(),
            self.apparmor.last_error(),
        );
        let mut state = self.state.write();
        state.status = map_hook_status(
            self.config.backend_mode,
            self.config.filesystem_backend,
            runtime_health,
        );
        state.runtime_health = mapped.clone();
        mapped
    }

    fn drain_audit_events_limited(
        &self,
        max_events: usize,
    ) -> Result<Vec<AuditEvent>, AdapterError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        let mut events = std::mem::take(&mut self.state.write().overflow);
        // Sources are only asked for what fits next to the carried events,
        // which bounds the carry at `max_events`.
        let budget = max_events.saturating_sub(events.len());
        if budget > 0 {
            if self.config.backend_mode == BackendMode::KernelStrict {
                match self.runtime.drain_audit_events_limited(budget) {
                    Ok(mut kernel_events) => events.append(&mut kernel_events),
                    Err(err) => {
                        self.state.write().overflow = events;
                        return Err(AdapterError::Runtime(err));
                    }
                }
            }
            events.append(&mut self.apparmor.drain_audit_events_limited(budget));
        }

        let (events, carry) = split_with_carry(events, max_events);
        if !carry.is_empty() {
            self.overflow_carried
                .fetch_add(carry.len() as u64, Ordering::Relaxed);
            self.state.write().overflow = carry;
        }
        Ok(events)
    }

    fn drain_audit_events(&self) -> Result<Vec<AuditEvent>, AdapterError> {
        self.drain_audit_events_limited(usize::MAX)
    }
}

impl ProcessTagger for LinuxAdapter {
    fn register_agent_pid(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
    ) -> Result<ProcessRegistration, AdapterError> {
        self.register_launching_pid(pid, agent_id, profile, uid)
    }

    fn is_pid_tagged(&self, pid: u32) -> bool {
        self.state.read().pid_tags.contains_key(&pid)
    }
}

impl PathResolver for LinuxAdapter {
    fn resolve_path(&self, path: &str) -> Result<String, AdapterError> {
        let canonical = Path::new(path)
            .canonicalize()
            .with_context(|| format!("canonicalize path {path}"))
            .map_err(AdapterError::Other)?;
        Ok(canonical.to_string_lossy().to_string())
    }
}

/// Orders events by time and splits off everything past `max_events`.
fn split_with_carry(
    mut events: Vec<AuditEvent>,
    max_events: usize,
) -> (Vec<AuditEvent>, Vec<AuditEvent>) {
    events.sort_by_key(|event| event.timestamp);
    let carry = if events.len() > max_events {
        events.split_off(max_events)
    } else {
        Vec::new()
    };
    (events, carry)
}

fn read_proc_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|line| line.starts_with("PPid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
}

fn should_trigger_auto_enroll_scan(event: &Event) -> bool {
    match event.kind {
        EventKind::Any | EventKind::Create(_) | EventKind::Remove(_) => true,
        EventKind::Modify(_) => event.paths.iter().any(|path| is_cgroup_procs_path(path)),
        _ => false,
    }
}

fn is_cgroup_procs_path(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("cgroup.procs")
}

fn map_capabilities(
    cap: kernel_runtime::KernelCapabilityReport,
    apparmor: apparmor::AppArmorCapabilities,
    filesystem_backend: FilesystemBackend,
) -> CapabilityReport {
    let selected_filesystem_backend = match filesystem_backend {
        FilesystemBackend::EbpfLsm if cap.bpf_lsm_available => HookBackend::EbpfLsm,
        FilesystemBackend::AppArmor if apparmor.enabled && apparmor.parser_present => {
            HookBackend::AppArmor
        }
        _ => HookBackend::Unavailable,
    };

    CapabilityReport {
        kernel_release: cap.kernel_release,
        kernel_version_ok: cap.kernel_version_ok,
        bpf_fs_present: cap.bpf_fs_present,
        bpf_lsm_available: cap.bpf_lsm_available,
        cgroup_v2: cap.cgroup_v2,
        apparmor_enabled: apparmor.enabled,
        apparmor_parser_present: apparmor.parser_present,
        selected_filesystem_backend,
    }
}

fn map_hook_status(
    backend_mode: BackendMode,
    filesystem_backend: FilesystemBackend,
    health: KernelRuntimeHealth,
) -> AdapterHookStatus {
    match backend_mode {
        BackendMode::KernelStrict => AdapterHookStatus {
            exec_hook: map_backend(health.hook_status.exec_hook),
            network_hook: map_backend(health.hook_status.network_hook),
            filesystem_hook: map_backend(health.hook_status.filesystem_hook),
        },
        BackendMode::LinuxCompat => AdapterHookStatus {
            exec_hook: match filesystem_backend {
                FilesystemBackend::AppArmor => HookBackend::AppArmor,
                FilesystemBackend::EbpfLsm => HookBackend::Unavailable,
            },
            network_hook: match filesystem_backend {
                FilesystemBackend::AppArmor => HookBackend::AppArmor,
                FilesystemBackend::EbpfLsm => HookBackend::Unavailable,
            },
            filesystem_hook: match filesystem_backend {
                FilesystemBackend::AppArmor => HookBackend::AppArmor,
                FilesystemBackend::EbpfLsm => HookBackend::Unavailable,
            },
        },
    }
}

fn map_backend(backend: kernel_runtime::HookBackend) -> HookBackend {
    match backend {
        kernel_runtime::HookBackend::EbpfLsm => HookBackend::EbpfLsm,
        kernel_runtime::HookBackend::EbpfCgroup => HookBackend::EbpfCgroup,
        kernel_runtime::HookBackend::AppArmor => HookBackend::AppArmor,
        kernel_runtime::HookBackend::ObserveOnly => HookBackend::ObserveOnly,
        kernel_runtime::HookBackend::Unavailable => HookBackend::Unavailable,
    }
}

fn map_runtime_health(
    backend_mode: BackendMode,
    filesystem_backend: FilesystemBackend,
    health: KernelRuntimeHealth,
    apparmor_error: Option<String>,
) -> AdapterRuntimeHealth {
    AdapterRuntimeHealth {
        backend_mode,
        kernel_ready: backend_mode == BackendMode::KernelStrict && health.kernel_ready,
        kernel_program_version: match backend_mode {
            BackendMode::KernelStrict => health.kernel_program_version,
            BackendMode::LinuxCompat => match filesystem_backend {
                FilesystemBackend::AppArmor => "linux-compat-apparmor".to_string(),
                FilesystemBackend::EbpfLsm => "linux-compat".to_string(),
            },
        },
        auto_enroll_active_rules: match backend_mode {
            BackendMode::KernelStrict => health.auto_enroll_active_rules,
            BackendMode::LinuxCompat => 0,
        },
        unmatched_mode: health.unmatched_mode,
        unenrolled_events_suppressed_total: match backend_mode {
            BackendMode::KernelStrict => health.unenrolled_events_suppressed_total,
            BackendMode::LinuxCompat => 0,
        },
        events_dropped_ringbuf_total: health.events_dropped_ringbuf_total,
        events_rate_limited_total: health.events_rate_limited_total,
        deny_events_dropped_total: health.deny_events_dropped_total,
        unavailable_hooks: health.unavailable_hooks,
        enrollment_sync_error: health.enrollment_sync_error.or(apparmor_error),
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("kernel runtime: {0}")]
    Runtime(#[from] kernel_runtime::KernelRuntimeError),
    // `{0:#}` prints the full anyhow context chain, not just the outermost message.
    #[error("internal: {0:#}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn cgroup_registration_works_with_temp_path() {
        let temp = tempdir().expect("tempdir");
        let adapter = LinuxAdapter::new(LinuxAdapterConfig {
            cgroup_base: temp.path().join("agents"),
            backend_mode: BackendMode::KernelStrict,
            kernel: KernelRuntimeConfig {
                bpffs_path: temp.path().join("bpffs").to_string_lossy().to_string(),
                cgroup_root: temp
                    .path()
                    .join("cgroup-root")
                    .to_string_lossy()
                    .to_string(),
                ..KernelRuntimeConfig::default()
            },
            filesystem_backend: FilesystemBackend::EbpfLsm,
            apparmor: AppArmorConfig::default(),
        });

        let registration = adapter
            .register_agent_pid(std::process::id(), Uuid::nil(), "default", 1000)
            .expect("register pid");
        assert!(registration.cgroup_id.starts_with("ai-"));
        assert!(adapter.is_pid_tagged(std::process::id()));
    }

    #[test]
    fn stale_enrollment_is_pruned() {
        let temp = tempdir().expect("tempdir");
        let adapter = LinuxAdapter::new(LinuxAdapterConfig {
            cgroup_base: temp.path().join("agents"),
            backend_mode: BackendMode::KernelStrict,
            kernel: KernelRuntimeConfig {
                bpffs_path: temp.path().join("bpffs").to_string_lossy().to_string(),
                cgroup_root: temp
                    .path()
                    .join("cgroup-root")
                    .to_string_lossy()
                    .to_string(),
                ..KernelRuntimeConfig::default()
            },
            filesystem_backend: FilesystemBackend::EbpfLsm,
            apparmor: AppArmorConfig::default(),
        });

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        adapter
            .register_agent_pid(pid, Uuid::nil(), "default", 1000)
            .expect("register child");

        child.kill().expect("kill child");
        child.wait().expect("wait child");

        let removed = adapter.prune_stale_enrollments().expect("prune");
        assert_eq!(removed, 1);
        assert!(adapter.enrollment_for_pid(pid).is_none());
        assert!(!adapter.is_pid_tagged(pid));
    }

    #[test]
    fn stale_linux_compat_enrollment_is_pruned() {
        let temp = tempdir().expect("tempdir");
        let adapter = LinuxAdapter::new(LinuxAdapterConfig {
            cgroup_base: temp.path().join("agents"),
            backend_mode: BackendMode::LinuxCompat,
            kernel: KernelRuntimeConfig::default(),
            filesystem_backend: FilesystemBackend::EbpfLsm,
            apparmor: AppArmorConfig::default(),
        });

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        adapter
            .register_agent_pid(pid, Uuid::nil(), "default", 1000)
            .expect("register child");
        assert_eq!(adapter.list_enrollments().len(), 1);
        assert_eq!(adapter.prune_stale_enrollments().expect("prune"), 0);

        child.kill().expect("kill child");
        child.wait().expect("wait child");

        assert_eq!(adapter.prune_stale_enrollments().expect("prune"), 1);
        assert!(adapter.list_enrollments().is_empty());
        assert!(!adapter.is_pid_tagged(pid));
    }

    fn event_at(millis: i64) -> AuditEvent {
        let mut event = AuditEvent::system(
            "test",
            core_types::SystemResource::new("tick"),
            "v1",
            millis.to_string(),
        );
        event.timestamp = chrono::DateTime::from_timestamp_millis(millis).expect("timestamp");
        event
    }

    #[test]
    fn drain_overflow_is_carried_not_dropped() {
        let (events, carry) = split_with_carry(vec![event_at(3), event_at(1), event_at(2)], 2);
        let order = |events: &[AuditEvent]| {
            events
                .iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(order(&events), vec!["1", "2"]);
        assert_eq!(order(&carry), vec!["3"]);

        let (events, carry) = split_with_carry(vec![event_at(1)], 2);
        assert_eq!(events.len(), 1);
        assert!(carry.is_empty());
    }

    #[test]
    fn apparmor_paths_are_inert_with_ebpf_filesystem_backend() {
        let temp = tempdir().expect("tempdir");
        let adapter = LinuxAdapter::new(LinuxAdapterConfig {
            cgroup_base: temp.path().join("agents"),
            backend_mode: BackendMode::LinuxCompat,
            kernel: KernelRuntimeConfig::default(),
            filesystem_backend: FilesystemBackend::EbpfLsm,
            apparmor: AppArmorConfig {
                generated_policy_dir: temp.path().join("apparmor").display().to_string(),
                ..AppArmorConfig::default()
            },
        });
        assert!(
            adapter
                .drain_audit_events_limited(10)
                .expect("drain")
                .is_empty()
        );
        assert_eq!(adapter.prune_apparmor_profiles(), 0);
        assert_eq!(
            adapter.apparmor_telemetry_stats(),
            AppArmorTelemetryStats::default()
        );
    }

    #[test]
    fn auto_enroll_watcher_filters_relevant_events() {
        let cgroup_procs = PathBuf::from("/sys/fs/cgroup/workload.slice/cgroup.procs");
        let unrelated = PathBuf::from("/sys/fs/cgroup/cgroup.controllers");

        assert!(should_trigger_auto_enroll_scan(&Event {
            kind: EventKind::Create(notify::event::CreateKind::Any),
            paths: vec![PathBuf::from("/sys/fs/cgroup/workload.slice")],
            attrs: Default::default(),
        }));
        assert!(should_trigger_auto_enroll_scan(&Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )),
            paths: vec![cgroup_procs],
            attrs: Default::default(),
        }));
        assert!(!should_trigger_auto_enroll_scan(&Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Metadata(
                notify::event::MetadataKind::Any,
            )),
            paths: vec![unrelated],
            attrs: Default::default(),
        }));
    }
}
