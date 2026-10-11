//! Platform-agnostic traits for Mercury enforcement adapters.
//!
//! Each target OS provides a concrete adapter crate that
//! implements these traits.  The daemon and other consumer crates depend only
//! on these traits so the same binary structure compiles on every platform.

use core_types::AuditEvent;
use policy_engine::CompiledPolicy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

// ---------------------------------------------------------------------------
// Process registration result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRegistration {
    /// Platform-specific group identifier (cgroup ID on Linux).
    pub group_id: String,
    /// Optional filesystem enforcement label (e.g. AppArmor label on Linux).
    #[serde(default)]
    pub filesystem_label: Option<String>,
}

// ---------------------------------------------------------------------------
// Enrollment record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub pid: u32,
    pub agent_id: Uuid,
    pub profile: String,
    pub uid: u32,
    /// Platform-specific group id (cgroup on Linux).
    pub group_id: String,
    pub source: String,
    pub mode: String,
}

// ---------------------------------------------------------------------------
// Hook / capability reporting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterHookStatus {
    pub exec_hook: HookBackend,
    pub network_hook: HookBackend,
    pub filesystem_hook: HookBackend,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookBackend {
    EbpfLsm,
    EbpfCgroup,
    AppArmor,
    ObserveOnly,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityReport {
    pub os: String,
    pub os_version: String,
    pub enforcement_available: bool,
    pub network_filtering_available: bool,
    pub process_tagging_available: bool,
    /// Per-platform detail keys (e.g. "bpf_lsm_available", "apparmor_enabled",
    /// "minifilter_loaded", …).
    pub details: std::collections::HashMap<String, String>,
    pub selected_filesystem_backend: HookBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterRuntimeHealth {
    pub ready: bool,
    pub program_version: String,
    pub auto_enroll_active_rules: usize,
    pub unenrolled_events_suppressed_total: u64,
    pub enrollment_sync_error: Option<String>,
    /// Per-platform health details.
    pub details: std::collections::HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Core enforcement trait
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Process tagging trait
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Path resolver trait
// ---------------------------------------------------------------------------

pub trait PathResolver: Send + Sync {
    fn resolve_path(&self, path: &str) -> Result<String, AdapterError>;
}

// ---------------------------------------------------------------------------
// Process info helpers (cross-platform)
// ---------------------------------------------------------------------------

/// Return the parent PID of an arbitrary process.
///
/// Returns `None` if the process cannot be found.
pub fn parent_pid_of(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("PPid:") {
                return value.trim().parse::<u32>().ok();
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        _ = pid;
        None
    }
}

/// Return the current process's parent PID.
pub fn parent_pid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: libc call has no preconditions.
        unsafe { libc::getppid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Return the current process's user ID (UID on Unix, 0 elsewhere).
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: libc call has no preconditions.
        unsafe { libc::getuid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Return the current process's group ID (GID on Unix, 0 elsewhere).
pub fn current_gid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: libc call has no preconditions.
        unsafe { libc::getgid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Runtime configuration enums (platform-neutral definitions)
// ---------------------------------------------------------------------------

/// Enforcement strictness mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    #[default]
    KernelStrict,
    LinuxCompat,
}

/// Which filesystem enforcement mechanism to use.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum FilesystemBackend {
    #[serde(rename = "ebpf_lsm")]
    EbpfLsm,
    #[default]
    #[serde(rename = "apparmor", alias = "app_armor")]
    AppArmor,
}

/// How to handle processes on the host that are NOT enrolled in any Mercury
/// profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedHostMode {
    #[default]
    Observe,
}

/// Enrollment mode for auto-enroll rules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentMode {
    #[default]
    Enforce,
    Observe,
}

/// A single auto-enroll rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoEnrollRule {
    pub id: String,
    pub cgroup_pattern: String,
    pub profile: String,
    #[serde(default)]
    pub mode: EnrollmentMode,
}

/// Kernel runtime configuration (eBPF ring buffer, cgroup root, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelRuntimeConfig {
    #[serde(default = "default_bpffs_path")]
    pub bpffs_path: String,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: String,
    #[serde(default = "default_event_buffer_pages")]
    pub event_buffer_pages: u32,
    #[serde(default)]
    pub auto_enroll_rules: Vec<AutoEnrollRule>,
    #[serde(default)]
    pub unmatched_host_mode: UnmatchedHostMode,
    #[serde(default = "default_url_proxy_port")]
    pub url_proxy_port: u16,
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: u32,
}

impl Default for KernelRuntimeConfig {
    fn default() -> Self {
        Self {
            bpffs_path: default_bpffs_path(),
            cgroup_root: default_cgroup_root(),
            event_buffer_pages: default_event_buffer_pages(),
            auto_enroll_rules: Vec::new(),
            unmatched_host_mode: UnmatchedHostMode::Observe,
            url_proxy_port: default_url_proxy_port(),
            rate_limit_per_sec: default_rate_limit_per_sec(),
        }
    }
}

fn default_bpffs_path() -> String {
    "/sys/fs/bpf".to_string()
}
fn default_cgroup_root() -> String {
    "/sys/fs/cgroup".to_string()
}
fn default_event_buffer_pages() -> u32 {
    256
}
fn default_url_proxy_port() -> u16 {
    19080
}
fn default_rate_limit_per_sec() -> u32 {
    1000
}

/// AppArmor-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppArmorConfig {
    #[serde(default = "default_parser_path")]
    pub parser_path: String,
    #[serde(default = "default_generated_policy_dir")]
    pub generated_policy_dir: String,
    #[serde(default)]
    pub audit_source: AppArmorAuditSource,
    /// auditd log tailed by `audit_source: audit_log`, and by `auto` when the
    /// file exists and is readable.
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: String,
}

impl Default for AppArmorConfig {
    fn default() -> Self {
        Self {
            parser_path: default_parser_path(),
            generated_policy_dir: default_generated_policy_dir(),
            audit_source: AppArmorAuditSource::Auto,
            audit_log_path: default_audit_log_path(),
        }
    }
}

/// Where AppArmor audit records are read from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppArmorAuditSource {
    /// journald `_TRANSPORT=audit` (delivered even while auditd runs) and
    /// `_TRANSPORT=kernel` (printk, rate-limited), plus the auditd log when
    /// readable. Records seen on more than one path are deduplicated.
    /// `journald` is accepted for configs written before the split.
    #[default]
    #[serde(alias = "journald")]
    Auto,
    /// Only journald `_TRANSPORT=audit`.
    JournaldAudit,
    /// Only journald `_TRANSPORT=kernel` (the pre-v2 behavior).
    JournaldKernel,
    /// Only the auditd log file at `audit_log_path`.
    AuditLog,
}

fn default_parser_path() -> String {
    "/usr/sbin/apparmor_parser".to_string()
}
fn default_generated_policy_dir() -> String {
    "/var/lib/mercury/apparmor".to_string()
}
fn default_audit_log_path() -> String {
    "/var/log/audit/audit.log".to_string()
}
