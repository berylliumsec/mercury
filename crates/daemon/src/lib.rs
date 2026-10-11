#![recursion_limit = "512"]

use std::collections::HashMap;
#[cfg(all(unix, feature = "linux"))]
use std::ffi::CString;
use std::fs;
#[cfg(all(unix, feature = "linux"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(all(unix, feature = "linux"))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration as StdDuration, Instant};

use audit::{AuditConfig, AuditLogger};
use chrono::{DateTime, Utc};
use control_api::{
    AuthorizeMcpResourceReadResponse, AuthorizeMcpToolCallResponse, CaCertResponse,
    CompleteMcpToolCallResponse, ControlErrorPayload, ControlRequest, ControlResponse,
    CoverageStatus, HealthResponse, HookStatus, KernelLimitsInfo, McpToolCallAuthorizationDecision,
    McpToolCallCompletionStatus, PolicyReloadResponse, RegisterAgentResponse,
    RegisterMcpServerResponse, WaitMcpApprovalResponse, decode_request, encode_response,
};
use core_types::{
    API_VERSION, Action, ActionContext, ActionType, AgentRegistration, AuditEvent, Decision,
    DecisionReason, DecisionResult, FailMode, McpAuditContext, McpResourceReadResource,
    McpToolResource, McpTransport, NetworkResource, Resource, SystemResource,
};
use dashboard::{DashboardConfig, DashboardService, DashboardStatus, DashboardStatusResponse};
use hmac::{Hmac, Mac};
#[cfg(all(feature = "linux", unix))]
use linux_adapter::{
    AdapterHookStatus, EnforcementAdapter, EventSourceAdapter, HookBackend, LinuxAdapter,
    LinuxAdapterConfig,
};
use parking_lot::{Condvar, Mutex, RwLock};
#[cfg(not(all(feature = "linux", unix)))]
use platform_traits::{AdapterHookStatus, EnforcementAdapter, HookBackend};
use platform_traits::{
    AppArmorConfig, BackendMode, FilesystemBackend, KernelRuntimeConfig, UnmatchedHostMode,
};
use policy_engine::{
    CompiledPolicy, EngineOptions, McpEvaluationDecision, PolicyEngine, SignatureVerification,
    load_policy_from_str, validate_policy_limits,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};
use uuid::Uuid;

pub mod alerts;
#[cfg(all(feature = "linux", unix))]
#[path = "dashboard.rs"]
mod dashboard;
#[cfg(not(all(feature = "linux", unix)))]
#[path = "dashboard_stub.rs"]
mod dashboard;
#[cfg(feature = "linux")]
mod gateway_audit;
#[cfg(all(feature = "linux", unix))]
mod model_capture;
mod policy_sync;
pub mod secrets;
#[cfg(all(feature = "linux", unix))]
mod url_gateway;
#[cfg(not(all(feature = "linux", unix)))]
#[path = "url_gateway_stub.rs"]
mod url_gateway;
use policy_sync::{PolicySyncConfig, PolicySyncStatus, PolicySyncWorker};
use url_gateway::{UrlGatewayConfig, UrlGatewayStatus};

const KERNEL_DRAIN_BATCH_MAX: usize = 1024;
const INGEST_LOW_QUEUE_CAPACITY: usize = 8192;
const INGEST_DASHBOARD_BATCH_MAX: usize = 64;
/// How often loss counters are compared and reported as telemetry_loss.
const TELEMETRY_LOSS_REPORT_INTERVAL: StdDuration = StdDuration::from_secs(5);
const PROCESS_PRUNE_INTERVAL: Duration = Duration::from_secs(30);
const MCP_APPROVAL_TTL: StdDuration = StdDuration::from_secs(300);
const MCP_ARGUMENT_SUMMARY_MAX_CHARS: usize = 160;
/// Hard cap on arguments_json length accepted by AuthorizeMcpToolCall.
/// Prevents memory exhaustion from oversized payloads stored in pending-approval records.
const MAX_ARGUMENTS_JSON_BYTES: usize = 64 * 1024; // 64 KiB

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    #[serde(default = "default_policy_path")]
    pub policy_path: String,
    #[serde(default = "default_audit_path")]
    pub audit_jsonl_path: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub mirror_to_journald: bool,
    #[serde(default)]
    pub signature_verification: SignatureModeConfig,
    /// Path to a file containing the 64-character hex-encoded HMAC-SHA256 signing key.
    /// Required when `signature_verification = require_valid`; ignored otherwise.
    /// Generate with: openssl rand -hex 32 > /etc/mercury/policy-signing-key && chmod 600 ...
    #[serde(default)]
    pub signature_key_path: Option<String>,
    /// Key identifier written into the `signature.key_id` field when the daemon auto-signs
    /// a reloaded policy before persisting it to disk.  Defaults to "default".
    #[serde(default = "default_signature_key_id")]
    pub signature_key_id: String,
    #[serde(default)]
    pub policy_unavailable_mode: FailMode,
    #[serde(default = "default_cgroup_base")]
    pub cgroup_base: String,
    #[serde(default)]
    pub backend_mode: BackendMode,
    #[serde(default)]
    pub filesystem_backend: FilesystemBackend,
    #[serde(default)]
    pub kernel: KernelRuntimeConfig,
    #[serde(default)]
    pub apparmor: AppArmorConfig,
    #[serde(default)]
    pub dashboard: DashboardConfig,
    #[serde(default)]
    pub url_gateway: UrlGatewayConfig,
    /// 64-char hex-encoded HMAC key for the audit log integrity chain.
    /// Accepts a file path, or a secret reference: env:VAR, creds:NAME, literal:HEX
    /// (resolved in memory, never written to disk). When unset, the key at
    /// /var/lib/mercury/audit-integrity.key is used, generated (0600) on first start.
    #[serde(default)]
    pub audit_integrity_key_path: Option<String>,
    /// Sign audit records with a chained HMAC. Set to false to opt out.
    #[serde(default = "default_true")]
    pub audit_integrity: bool,
    /// When the audit log is fdatasync'ed: none | interval | always.
    #[serde(default)]
    pub audit_fsync: audit::FsyncMode,
    /// Rotate the audit log when it reaches this many bytes.
    #[serde(default = "default_audit_max_file_bytes")]
    pub audit_max_file_bytes: u64,
    /// Rotated audit files kept besides the active one.
    #[serde(default = "default_audit_max_files")]
    pub audit_max_files: usize,
    /// journald mirror protocol: native | syslog (pre-v2 behavior).
    #[serde(default)]
    pub journald_mirror_mode: audit::JournaldMirrorMode,
    #[serde(default)]
    pub kernel_limits: KernelLimitsConfig,
    #[serde(default)]
    pub policy_sync: Option<PolicySyncConfig>,
    /// Optional webhook alerting for denies, telemetry loss and tamper events.
    #[serde(default)]
    pub alerts: alerts::AlertsConfig,
    /// Where live enrollments are persisted so they can be restored after a
    /// daemon restart (the eBPF maps do not survive the daemon).
    #[serde(default = "default_enrollment_state_path")]
    pub enrollment_state_path: String,
}

fn default_enrollment_state_path() -> String {
    "/var/lib/mercury/enrollments.json".to_string()
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            policy_path: default_policy_path(),
            audit_jsonl_path: default_audit_path(),
            log_level: default_log_level(),
            mirror_to_journald: true,
            signature_verification: SignatureModeConfig::WarnOnInvalid,
            signature_key_path: None,
            signature_key_id: default_signature_key_id(),
            policy_unavailable_mode: FailMode::FailClosed,
            cgroup_base: default_cgroup_base(),
            backend_mode: BackendMode::KernelStrict,
            filesystem_backend: FilesystemBackend::AppArmor,
            kernel: KernelRuntimeConfig::default(),
            apparmor: AppArmorConfig::default(),
            dashboard: DashboardConfig::default(),
            url_gateway: UrlGatewayConfig::default(),
            audit_integrity_key_path: None,
            audit_integrity: true,
            audit_fsync: audit::FsyncMode::default(),
            audit_max_file_bytes: default_audit_max_file_bytes(),
            audit_max_files: default_audit_max_files(),
            journald_mirror_mode: audit::JournaldMirrorMode::default(),
            kernel_limits: KernelLimitsConfig::default(),
            policy_sync: None,
            alerts: alerts::AlertsConfig::default(),
            enrollment_state_path: default_enrollment_state_path(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureModeConfig {
    Disabled,
    #[default]
    WarnOnInvalid,
    RequireValid,
}

impl SignatureModeConfig {
    pub(crate) fn as_engine_mode(self, hmac_key: Option<Vec<u8>>) -> SignatureVerification {
        match self {
            Self::Disabled => SignatureVerification::Disabled,
            Self::WarnOnInvalid => SignatureVerification::WarnOnInvalid,
            Self::RequireValid => SignatureVerification::RequireValid {
                hmac_key: hmac_key.unwrap_or_default(),
            },
        }
    }
}

/// Configurable limits for eBPF kernel map sizes and policy validation.
#[derive(Debug, Clone, Deserialize)]
pub struct KernelLimitsConfig {
    /// Maximum number of rules per class (file_allow, file_deny, etc.). Default: 32.
    #[serde(default = "default_max_rules_per_class")]
    pub max_rules_per_class: u32,
    /// Maximum number of profiles. Default: 128.
    #[serde(default = "default_max_profiles")]
    pub max_profiles: u32,
    /// Maximum number of workspace roots per profile. Default: 64.
    #[serde(default = "default_max_workspace_roots")]
    pub max_workspace_roots: u32,
}

impl Default for KernelLimitsConfig {
    fn default() -> Self {
        Self {
            max_rules_per_class: default_max_rules_per_class(),
            max_profiles: default_max_profiles(),
            max_workspace_roots: default_max_workspace_roots(),
        }
    }
}

fn default_max_rules_per_class() -> u32 {
    32 // Must match MAX_RULES_PER_CLASS in mercury_kern.c
}

fn default_max_profiles() -> u32 {
    128 // Must match max_entries of mercury_profiles in mercury_kern.c
}

fn default_max_workspace_roots() -> u32 {
    64 // Must match MAX_WORKSPACE_ROOTS in mercury_kern.c
}

fn default_socket_path() -> String {
    control_api::SOCKET_PATH.to_string()
}

#[cfg(all(unix, feature = "linux"))]
fn optional_group_gid(group_name: &str) -> Option<u32> {
    let group_name = CString::new(group_name).ok()?;
    let entry = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if entry.is_null() {
        return None;
    }

    Some(unsafe { (*entry).gr_gid })
}

fn default_policy_path() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/policy.yaml".to_string()
    }
}

fn default_audit_path() -> String {
    #[cfg(unix)]
    {
        "/var/log/mercury/audit.jsonl".to_string()
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_signature_key_id() -> String {
    "default".to_string()
}

fn default_audit_max_file_bytes() -> u64 {
    audit::DEFAULT_MAX_FILE_BYTES
}

fn default_audit_max_files() -> usize {
    audit::DEFAULT_MAX_FILES
}

/// Selects the audit integrity key. A plain path must hold a valid key;
/// secret references (env:, creds:, literal:) are resolved in memory; when
/// unset, the key at `audit::DEFAULT_INTEGRITY_KEY_PATH` is generated on
/// first start.
#[cfg(feature = "linux")]
fn resolve_audit_integrity_key(
    config: &DaemonConfig,
) -> Result<audit::IntegrityKeySource, DaemonError> {
    if !config.audit_integrity {
        return Ok(audit::IntegrityKeySource::Disabled);
    }
    let Some(ref reference) = config.audit_integrity_key_path else {
        return Ok(audit::IntegrityKeySource::AutoGenerate(PathBuf::from(
            audit::DEFAULT_INTEGRITY_KEY_PATH,
        )));
    };
    // If it's a plain file path (no prefix), pass directly — existing behavior.
    if !reference.starts_with("env:")
        && !reference.starts_with("creds:")
        && !reference.starts_with("literal:")
    {
        return Ok(audit::IntegrityKeySource::File(PathBuf::from(reference)));
    }
    let key_hex = secrets::resolve_secret(reference)
        .map_err(|e| DaemonError::Config(format!("failed to resolve audit integrity key: {e}")))?;
    Ok(audit::IntegrityKeySource::Hex(key_hex.trim().to_string()))
}

/// Re-sign `raw_yaml` with `hmac_key`, returning signed YAML.
/// Strips any existing `signature:` block before computing the HMAC so the
/// result is idempotent regardless of whether the input was already signed.
#[cfg(feature = "linux")]
fn sign_policy_yaml(raw_yaml: &str, hmac_key: &[u8], key_id: &str) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(raw_yaml).map_err(|e| format!("parse policy yaml: {e}"))?;
    if let Some(map) = doc.as_mapping_mut() {
        map.remove("signature");
    }
    let canonical =
        serde_yaml::to_string(&doc).map_err(|e| format!("serialize canonical yaml: {e}"))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key)
        .map_err(|e| format!("invalid hmac key: {e}"))?;
    mac.update(canonical.as_bytes());
    let sig_hex = hex::encode(mac.finalize().into_bytes());
    if let Some(map) = doc.as_mapping_mut() {
        map.insert(
            serde_yaml::Value::String("signature".to_string()),
            serde_yaml::Value::Mapping({
                let mut m = serde_yaml::Mapping::new();
                m.insert(
                    serde_yaml::Value::String("key_id".to_string()),
                    serde_yaml::Value::String(key_id.to_string()),
                );
                m.insert(
                    serde_yaml::Value::String("alg".to_string()),
                    serde_yaml::Value::String("hmac-sha256".to_string()),
                );
                m.insert(
                    serde_yaml::Value::String("sig".to_string()),
                    serde_yaml::Value::String(sig_hex),
                );
                m
            }),
        );
    }
    serde_yaml::to_string(&doc).map_err(|e| format!("serialize signed yaml: {e}"))
}

fn default_cgroup_base() -> String {
    #[cfg(unix)]
    {
        "/sys/fs/cgroup/mercury/agents".to_string()
    }
}

fn parse_bind_port(bind_addr: &str) -> Result<u16, String> {
    bind_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.port())
        .map_err(|err| err.to_string())
}

#[cfg(feature = "linux")]
fn parent_pid_for(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("PPid:") {
                return value.trim().parse::<u32>().ok();
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        platform_traits::parent_pid_of(pid)
    }
}

#[cfg(feature = "linux")]
fn pid_owned_by(caller_uid: u32, pid: u32) -> bool {
    #[cfg(unix)]
    {
        if caller_uid == 0 {
            return true;
        }
        let status_path = format!("/proc/{pid}/status");
        fs::read_to_string(status_path)
            .map(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|value| value.parse::<u32>().ok())
                    .map(|pid_uid| pid_uid == caller_uid)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // No per-process ownership information off Unix; trust local callers.
        _ = (caller_uid, pid);
        true
    }
}

#[cfg(feature = "linux")]
fn pid_matches_owner_and_start_time(caller_uid: u32, pid: u32, proc_start_time: u64) -> bool {
    if caller_uid == 0 {
        return true;
    }

    if !pid_owned_by(caller_uid, pid) {
        return false;
    }

    kernel_runtime::read_proc_start_time(pid) == Some(proc_start_time)
}

#[cfg(feature = "linux")]
fn resolve_process_executable_path(pid: u32) -> Result<String, String> {
    let link = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|err| format!("read /proc/{pid}/exe: {err}"))?;
    let normalized = match policy_engine::canonicalize_for_enforcement(&link) {
        Ok(path) => path,
        Err(_) => link,
    };
    Ok(normalized.to_string_lossy().to_string())
}

#[cfg(feature = "linux")]
fn hash_arguments_json(arguments_json: &str) -> String {
    let digest = Sha256::digest(arguments_json.as_bytes());
    hex::encode(digest)
}

#[cfg(feature = "linux")]
fn summarize_arguments(arguments_json: &str, provided_summary: Option<&str>) -> Option<String> {
    let candidate = provided_summary
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .or_else(|| {
            let compact = arguments_json.trim();
            (!compact.is_empty()).then(|| compact.to_string())
        })?;

    // Redacted, and cut on a character boundary.
    Some(gateway_audit::summarize_text(
        candidate.as_str(),
        MCP_ARGUMENT_SUMMARY_MAX_CHARS,
    ))
}

pub fn load_config(path: impl AsRef<Path>) -> Result<DaemonConfig, DaemonError> {
    let raw = fs::read_to_string(path).map_err(DaemonError::Io)?;
    let raw_doc: serde_yaml::Value =
        serde_yaml::from_str(&raw).map_err(DaemonError::ConfigDeserialize)?;
    let mut config: DaemonConfig =
        serde_yaml::from_str(&raw).map_err(DaemonError::ConfigDeserialize)?;

    if !top_level_key_present(&raw_doc, "filesystem_backend")
        && !config.kernel.auto_enroll_rules.is_empty()
    {
        config.filesystem_backend = FilesystemBackend::EbpfLsm;
    }

    // Semantic validation: catch values that deserialize successfully but are
    // logically unusable, causing hard-to-diagnose runtime failures.
    if config.audit_max_file_bytes == 0 {
        return Err(DaemonError::Config(
            "audit_max_file_bytes must be > 0 (0 rotates on every record)".into(),
        ));
    }
    if config.enrollment_state_path.trim().is_empty() {
        return Err(DaemonError::Config(
            "enrollment_state_path must not be empty".into(),
        ));
    }
    if config.dashboard.enabled {
        let d = &config.dashboard;
        if d.auth.session_ttl_minutes == 0 {
            return Err(DaemonError::Config(
                "dashboard.auth.session_ttl_minutes must be > 0 (0 makes all logins expire immediately)".into()
            ));
        }
        if d.retention_days == 0 {
            return Err(DaemonError::Config(
                "dashboard.retention_days must be > 0 (0 deletes all events on every prune cycle)"
                    .into(),
            ));
        }
        if d.request_rate_limit_rps == 0 {
            return Err(DaemonError::Config(
                "dashboard.request_rate_limit_rps must be > 0 (0 rate-limits every request)".into(),
            ));
        }
        d.bind_addr.parse::<std::net::SocketAddr>().map_err(|err| {
            DaemonError::Config(format!(
                "dashboard.bind_addr '{}' is not a valid socket address: {}",
                d.bind_addr, err
            ))
        })?;
    }

    Ok(config)
}

fn top_level_key_present(document: &serde_yaml::Value, key: &str) -> bool {
    let serde_yaml::Value::Mapping(mapping) = document else {
        return false;
    };

    mapping
        .keys()
        .any(|entry| matches!(entry, serde_yaml::Value::String(value) if value == key))
}

#[cfg(all(feature = "linux", unix))]
#[derive(Debug)]
pub struct GuardDaemon {
    config: DaemonConfig,
    engine: Arc<RwLock<PolicyEngine>>,
    active_policy: Arc<RwLock<Option<CompiledPolicy>>>,
    active_policy_yaml: Arc<RwLock<Option<String>>>,
    registrations: Arc<RwLock<HashMap<u32, AgentRegistration>>>,
    mcp_sessions: Arc<RwLock<HashMap<String, RegisteredMcpServer>>>,
    /// Keyed by agent_id string; Vec because concurrent tool calls are legal per MCP spec.
    active_mcp_calls: Arc<RwLock<HashMap<String, Vec<ActiveMcpToolCall>>>>,
    pending_mcp_approvals: Arc<RwLock<HashMap<String, PendingMcpApprovalRecord>>>,
    proxy_auth_tokens: Arc<RwLock<HashMap<String, ProxySubject>>>,
    adapter: Arc<LinuxAdapter>,
    audit: Arc<AuditLogger>,
    dashboard: Option<Arc<DashboardService>>,
    dashboard_status: Arc<RwLock<DashboardStatus>>,
    url_gateway_status: Arc<RwLock<UrlGatewayStatus>>,
    ingest_metrics: Arc<IngestMetrics>,
    backpressure: Arc<BackpressureState>,
    policy_reloads_total: Arc<AtomicU64>,
    policy_reload_failures_total: Arc<AtomicU64>,
    /// Loss counters already reported as telemetry_loss records.
    reported_loss: Mutex<LossCounters>,
    /// Last enrollment-state persistence error (logged once per change).
    enrollment_state_error: Mutex<Option<String>>,
    policy_sync_status: Arc<Mutex<PolicySyncStatus>>,
}

#[derive(Debug, Default)]
struct IngestMetrics {
    events_ingested_total: AtomicU64,
    events_dropped_queue_total: AtomicU64,
    events_dropped_ringbuf_total: AtomicU64,
    ingest_backlog_len: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
struct IngestMetricsSnapshot {
    events_ingested_total: u64,
    events_dropped_queue_total: u64,
    events_dropped_ringbuf_total: u64,
    ingest_backlog_len: usize,
}

/// Live registrations persisted for restart recovery.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedEnrollmentState {
    #[serde(default)]
    heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    registrations: Vec<AgentRegistration>,
}

/// Writes `value` as JSON to a 0600 temp file and renames it into place.
fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

/// Monotonic loss counters, compared between telemetry_loss reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LossCounters {
    kernel_ringbuf_dropped: u64,
    kernel_deny_dropped: u64,
    kernel_rate_limited: u64,
    ingest_queue_dropped: u64,
}

impl LossCounters {
    fn since(self, earlier: LossCounters) -> LossCounters {
        LossCounters {
            kernel_ringbuf_dropped: self
                .kernel_ringbuf_dropped
                .saturating_sub(earlier.kernel_ringbuf_dropped),
            kernel_deny_dropped: self
                .kernel_deny_dropped
                .saturating_sub(earlier.kernel_deny_dropped),
            kernel_rate_limited: self
                .kernel_rate_limited
                .saturating_sub(earlier.kernel_rate_limited),
            ingest_queue_dropped: self
                .ingest_queue_dropped
                .saturating_sub(earlier.ingest_queue_dropped),
        }
    }

    fn is_zero(self) -> bool {
        self == LossCounters::default()
    }
}

#[derive(Debug)]
struct BackpressureState {
    /// True when the system is under backpressure.
    active: AtomicBool,
    /// Timestamp when backpressure was last activated.
    activated_at: Mutex<Option<Instant>>,
    /// Number of times backpressure was activated.
    activations_total: AtomicU64,
}

impl Default for BackpressureState {
    fn default() -> Self {
        Self {
            active: AtomicBool::new(false),
            activated_at: Mutex::new(None),
            activations_total: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PrometheusMetrics {
    pub(crate) events_ingested_total: u64,
    pub(crate) events_dropped_queue_total: u64,
    pub(crate) ingest_backlog_len: usize,
    pub(crate) unenrolled_events_suppressed_total: u64,
    pub(crate) enrolled_agents: usize,
    pub(crate) active_mcp_sessions: usize,
    pub(crate) pending_mcp_approvals: usize,
    pub(crate) policy_reloads_total: u64,
    pub(crate) dashboard_sqlite_bytes: u64,
    pub(crate) active_sse_clients: usize,
    pub(crate) kernel_ready: bool,
    pub(crate) version: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxySubject {
    pub agent_id: String,
    pub profile: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: String,
}

#[derive(Debug, Clone)]
struct RegisteredMcpServer {
    mcp_session_id: String,
    pid: u32,
    /// Start time of the registered process from /proc/<pid>/stat field 22 (jiffies).
    /// Stored so that PID reuse can be detected: a recycled PID gets a different start time.
    proc_start_time: u64,
    profile: String,
    agent_id: Uuid,
    server_id: String,
    transport: McpTransport,
    http_base_url: Option<String>,
    http_gateway_token: Option<String>,
}

#[derive(Debug, Clone)]
struct ActiveMcpToolCall {
    mcp_session_id: String,
    server_id: String,
    transport: McpTransport,
    tool_name: String,
    tool_call_id: String,
}

impl ActiveMcpToolCall {
    fn audit_context(&self) -> McpAuditContext {
        McpAuditContext {
            server_id: self.server_id.clone(),
            transport: self.transport,
            resource_uri: None,
            tool_name: self.tool_name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            mcp_session_id: self.mcp_session_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct PendingMcpApprovalResolution {
    decision: McpToolCallAuthorizationDecision,
    rule_id: Option<String>,
    resolved_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct PendingMcpApprovalState {
    resolution: Option<PendingMcpApprovalResolution>,
}

#[derive(Debug, Default)]
struct PendingMcpApprovalShared {
    state: Mutex<PendingMcpApprovalState>,
    condvar: Condvar,
}

#[derive(Debug, Clone)]
struct PendingMcpApprovalRecord {
    deadline: Instant,
    profile: String,
    agent_id: String,
    pid: u32,
    proc_start_time: u64,
    server_id: String,
    transport: McpTransport,
    mcp_session_id: String,
    resource_uri: Option<String>,
    client_request_id: Option<String>,
    tool_name: Option<String>,
    tool_call_id: String,
    arguments_sha256: Option<String>,
    arguments_summary: Option<String>,
    rule_id: Option<String>,
    shared: Arc<PendingMcpApprovalShared>,
}

#[cfg(feature = "linux")]
fn mcp_resource_call_kind(uri: &str) -> &'static str {
    if uri.starts_with("prompt://") {
        "prompt"
    } else {
        "resource"
    }
}

#[cfg(feature = "linux")]
impl GuardDaemon {
    #[cfg(all(feature = "linux", unix))]
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        let mut config = config;
        if config.filesystem_backend == FilesystemBackend::AppArmor
            && !config.kernel.auto_enroll_rules.is_empty()
        {
            return Err(DaemonError::Config(
                "kernel.auto_enroll_rules is unsupported when filesystem_backend=apparmor"
                    .to_string(),
            ));
        }
        if config.url_gateway.enabled {
            let proxy_port =
                parse_bind_port(config.url_gateway.bind_addr.as_str()).map_err(|err| {
                    DaemonError::Config(format!(
                        "invalid url gateway bind_addr '{}': {err}",
                        config.url_gateway.bind_addr
                    ))
                })?;
            config.kernel.url_proxy_port = proxy_port;
        }

        let adapter = Arc::new(LinuxAdapter::new(LinuxAdapterConfig {
            cgroup_base: PathBuf::from(&config.cgroup_base),
            backend_mode: config.backend_mode,
            kernel: config.kernel.clone(),
            filesystem_backend: config.filesystem_backend,
            apparmor: config.apparmor.clone(),
        }));
        let audit = Arc::new(
            AuditLogger::new(AuditConfig {
                jsonl_path: PathBuf::from(&config.audit_jsonl_path),
                max_bytes: config.audit_max_file_bytes,
                max_files: config.audit_max_files,
                mirror_to_journald: config.mirror_to_journald,
                journald_mirror_mode: config.journald_mirror_mode,
                integrity: resolve_audit_integrity_key(&config)?,
                fsync: config.audit_fsync,
                ..AuditConfig::default()
            })
            .map_err(DaemonError::Audit)?,
        );

        let engine = Arc::new(RwLock::new(PolicyEngine::new(EngineOptions {
            policy_unavailable_mode: config.policy_unavailable_mode,
            max_rules_per_class: config.kernel_limits.max_rules_per_class as usize,
            max_profiles: config.kernel_limits.max_profiles as usize,
            max_workspace_roots: config.kernel_limits.max_workspace_roots as usize,
        })));

        let mut dashboard_status = DashboardStatus {
            enabled: config.dashboard.enabled,
            ready: false,
            url: None,
            error: None,
        };

        let dashboard = if config.dashboard.enabled {
            match DashboardService::new(config.dashboard.clone()) {
                Ok(service) => {
                    dashboard_status.ready = true;
                    dashboard_status.url = Some(service.dashboard_url());
                    Some(Arc::new(service))
                }
                Err(err) => {
                    dashboard_status.error = Some(err.to_string());
                    if config.dashboard.required {
                        return Err(DaemonError::Dashboard(err.to_string()));
                    }
                    warn!(
                        error = %err,
                        "dashboard initialization failed; continuing with enforcement runtime only"
                    );
                    None
                }
            }
        } else {
            None
        };

        let url_gateway_status = UrlGatewayStatus::from_config(&config.url_gateway);

        let policy_sync_enabled = config.policy_sync.is_some();
        Ok(Self {
            config,
            engine,
            active_policy: Arc::new(RwLock::new(None)),
            active_policy_yaml: Arc::new(RwLock::new(None)),
            registrations: Arc::new(RwLock::new(HashMap::new())),
            mcp_sessions: Arc::new(RwLock::new(HashMap::new())),
            active_mcp_calls: Arc::new(RwLock::new(HashMap::new())),
            pending_mcp_approvals: Arc::new(RwLock::new(HashMap::new())),
            proxy_auth_tokens: Arc::new(RwLock::new(HashMap::new())),
            adapter,
            audit,
            dashboard,
            dashboard_status: Arc::new(RwLock::new(dashboard_status)),
            url_gateway_status: Arc::new(RwLock::new(url_gateway_status)),
            ingest_metrics: Arc::new(IngestMetrics::default()),
            backpressure: Arc::new(BackpressureState::default()),
            policy_reloads_total: Arc::new(AtomicU64::new(0)),
            policy_reload_failures_total: Arc::new(AtomicU64::new(0)),
            reported_loss: Mutex::new(LossCounters::default()),
            enrollment_state_error: Mutex::new(None),
            policy_sync_status: Arc::new(Mutex::new(PolicySyncStatus {
                enabled: policy_sync_enabled,
                ..PolicySyncStatus::default()
            })),
        })
    }

    #[cfg(all(feature = "linux", unix))]
    pub fn initialize(&self) -> Result<(), DaemonError> {
        if let Some(sink) = alerts::AlertSink::new(&self.config.alerts) {
            alerts::install_global(sink);
            info!("alert webhook enabled");
        }
        match self.config.backend_mode {
            BackendMode::KernelStrict => {
                self.adapter.start().map_err(DaemonError::Adapter)?;
                self.adapter.ignore_pid(std::process::id());
            }
            BackendMode::LinuxCompat => {
                self.adapter.start().map_err(DaemonError::Adapter)?;
            }
        }

        let response = self.apply_policy_from_path(self.config.policy_path.as_str());
        if !response.success {
            return Err(DaemonError::PolicyLoad(format!(
                "initial policy load failed: {}",
                response.errors.join("; ")
            )));
        }
        self.restore_enrollments();

        self.record_audit_event(AuditEvent::system(
            "daemon",
            SystemResource::new("daemon_start")
                .attr("pid", std::process::id())
                .attr("backend", backend_mode_string(self.config.backend_mode)),
            self.policy_version(),
            "Mercury daemon initialized",
        ));

        Ok(())
    }

    pub fn policy_version(&self) -> String {
        self.engine
            .read()
            .policy_version()
            .unwrap_or("unloaded")
            .to_string()
    }

    pub fn apply_policy_from_path(&self, path: &str) -> PolicyReloadResponse {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) => {
                self.policy_reload_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                let mut event = AuditEvent::system(
                    "daemon",
                    SystemResource::new("policy_reload").attr("result", "failed"),
                    self.policy_version(),
                    "Policy file could not be read",
                );
                event.decision = Decision::Deny;
                self.record_audit_event(event);
                return PolicyReloadResponse {
                    version: self.policy_version(),
                    success: false,
                    errors: vec![format!("read policy file {path}: {err}")],
                    persist_warning: None,
                };
            }
        };
        self.apply_policy_from_yaml(raw.as_str())
    }

    pub fn apply_policy_from_yaml(&self, raw_policy: &str) -> PolicyReloadResponse {
        let response = self.apply_policy_from_yaml_inner(raw_policy);
        if !response.success {
            self.policy_reload_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
        let mut event = AuditEvent::system(
            "daemon",
            SystemResource::new("policy_reload")
                .attr(
                    "result",
                    if response.success {
                        "applied"
                    } else {
                        "failed"
                    },
                )
                .attr("version", response.version.clone()),
            response.version.clone(),
            if response.success {
                "Policy applied"
            } else {
                "Policy reload failed"
            },
        );
        if !response.success {
            event.decision = Decision::Deny;
        }
        self.record_audit_event(event);
        response
    }

    fn apply_policy_from_yaml_inner(&self, raw_policy: &str) -> PolicyReloadResponse {
        match load_policy_from_str(raw_policy, self.signature_verification()) {
            Ok(loaded) => {
                for warning in &loaded.warnings {
                    warn!(
                        policy_path = %self.config.policy_path,
                        warning = %warning,
                        "policy warning"
                    );
                }

                // Validate policy against configured kernel limits before loading.
                {
                    let eng = self.engine.read();
                    let (max_rpc, max_prof, max_ws) = eng.kernel_limits();
                    let opts = EngineOptions {
                        policy_unavailable_mode: self.config.policy_unavailable_mode,
                        max_rules_per_class: max_rpc,
                        max_profiles: max_prof,
                        max_workspace_roots: max_ws,
                    };
                    if let Err(err) = validate_policy_limits(&loaded.compiled, &opts) {
                        return PolicyReloadResponse {
                            version: self.policy_version(),
                            success: false,
                            errors: vec![format!("policy exceeds kernel limits: {err}")],
                            persist_warning: None,
                        };
                    }
                }

                if let Err(err) = self.adapter.load_policy(&loaded.compiled) {
                    return PolicyReloadResponse {
                        version: self.policy_version(),
                        success: false,
                        errors: vec![format!("adapter rejected policy: {err}")],
                        persist_warning: None,
                    };
                }

                self.engine.write().set_policy(loaded.compiled.clone());
                *self.active_policy.write() = Some(loaded.compiled.clone());
                *self.active_policy_yaml.write() = Some(raw_policy.to_string());
                self.policy_reloads_total.fetch_add(1, Ordering::Relaxed);

                // Evict mcp_sessions whose profile or server is no longer present in the
                // reloaded policy. Without this, removed MCP config would silently allow
                // all tool calls (evaluate_mcp returns Allow when profile.mcp.is_none()).
                // Use `loaded.compiled` directly rather than re-reading `active_policy`
                // to avoid an unnecessary extra lock acquisition.
                {
                    let new_policy = Some(&loaded.compiled);
                    let dead_sessions: Vec<(String, String)> = self
                        .mcp_sessions
                        .read()
                        .values()
                        .filter(|session| {
                            new_policy.is_none_or(|p| {
                                p.profiles
                                    .get(session.profile.as_str())
                                    .and_then(|prof| prof.mcp.as_ref())
                                    .is_none_or(|mcp| {
                                        !mcp.servers.iter().any(|s| {
                                            s.id == session.server_id
                                                && s.transport == session.transport
                                        })
                                    })
                            })
                        })
                        .map(|s| (s.mcp_session_id.clone(), s.agent_id.to_string()))
                        .collect();
                    if !dead_sessions.is_empty() {
                        let mut sessions = self.mcp_sessions.write();
                        let mut calls = self.active_mcp_calls.write();
                        for (sid, aid) in &dead_sessions {
                            sessions.remove(sid.as_str());
                            calls.remove(aid.as_str());
                            warn!(
                                mcp_session_id = sid,
                                "evicted MCP session: server no longer permitted by updated policy"
                            );
                        }
                    }
                }

                // If a signing key is configured, re-sign the accepted policy before
                // persisting so that the on-disk file always carries a valid HMAC
                // regardless of whether the incoming payload was already signed.
                let to_persist = match self.load_signature_key() {
                    Some(key) => sign_policy_yaml(raw_policy, &key, &self.config.signature_key_id)
                        .unwrap_or_else(|e| {
                            warn!(error = %e, "failed to auto-sign policy before persist; writing as-is");
                            raw_policy.to_string()
                        }),
                    None => raw_policy.to_string(),
                };
                // M5: atomic write via tmp + rename(2) so the on-disk file is
                // either the old version or the new version — never a partial write.
                let tmp_path = format!("{}.tmp", self.config.policy_path);
                let persist_result = fs::write(&tmp_path, &to_persist)
                    .and_then(|_| fs::rename(&tmp_path, self.config.policy_path.as_str()));
                if let Err(err) = persist_result {
                    let _ = fs::remove_file(&tmp_path);
                    error!(error = %err, path = %self.config.policy_path,
                        "failed to persist applied policy to configured policy path; \
                        enforcement uses the new policy but disk still holds the old one. \
                        A daemon restart will revert enforcement until this is corrected.");
                    return PolicyReloadResponse {
                        version: loaded.compiled.version,
                        success: true,
                        errors: Vec::new(),
                        persist_warning: Some(format!(
                            "policy is live but could not be written to {}: {}",
                            self.config.policy_path, err
                        )),
                    };
                }

                PolicyReloadResponse {
                    version: loaded.compiled.version,
                    success: true,
                    errors: Vec::new(),
                    persist_warning: None,
                }
            }
            Err(err) => PolicyReloadResponse {
                version: self.policy_version(),
                success: false,
                errors: vec![err.to_string()],
                persist_warning: None,
            },
        }
    }

    /// Returns the fully-resolved SignatureVerification, including the HMAC key loaded from disk.
    /// Callers that need to verify a policy should use `signature_verification()` rather than
    /// constructing one manually.
    pub(crate) fn signature_verification(&self) -> SignatureVerification {
        self.config
            .signature_verification
            .as_engine_mode(self.load_signature_key())
    }

    fn load_signature_key(&self) -> Option<Vec<u8>> {
        let reference = self.config.signature_key_path.as_deref()?;
        secrets::resolve_hex_key(reference)
            .map_err(|e| warn!(reference, error = %e, "failed to resolve policy signing key"))
            .ok()
    }

    fn ensure_url_gateway_ready_for_profile(
        &self,
        profile: &str,
    ) -> Result<bool, ControlErrorPayload> {
        let profile_uses_url_gateway = self.profile_has_url_rules(profile);
        if profile_uses_url_gateway {
            let gateway = self.url_gateway_status_snapshot();
            if !gateway.enabled || !gateway.ready {
                return Err(ControlErrorPayload {
                    code: "URL_GATEWAY_UNAVAILABLE".to_string(),
                    message: gateway.error.unwrap_or_else(|| {
                        "url gateway is required for this profile but is not ready".to_string()
                    }),
                });
            }
        }

        Ok(profile_uses_url_gateway)
    }

    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn build_registration_proxy_fields(
        &self,
        profile: &str,
        profile_uses_url_gateway: bool,
        agent_id: Uuid,
        cgroup_id: &str,
        pid: u32,
        ppid: u32,
        uid: u32,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        let gateway = self.url_gateway_status_snapshot();
        if profile_uses_url_gateway && gateway.ready {
            let proxy_auth_token = Uuid::new_v4().to_string();
            let proxy_subject = ProxySubject {
                agent_id: agent_id.to_string(),
                profile: profile.to_string(),
                pid,
                ppid,
                uid,
                cgroup_id: cgroup_id.to_string(),
            };
            self.proxy_auth_tokens
                .write()
                .insert(proxy_auth_token.clone(), proxy_subject);
            let ca_cert_pem =
                gateway
                    .ca_cert_path
                    .as_deref()
                    .and_then(|path| match fs::read_to_string(path) {
                        Ok(pem) => Some(pem),
                        Err(err) => {
                            warn!(
                                ca_cert_file = %path,
                                error = %err,
                                "failed to read URL gateway CA cert for registration payload"
                            );
                            None
                        }
                    });

            (
                gateway.http_proxy.clone(),
                gateway.https_proxy.clone(),
                gateway.no_proxy.clone(),
                Some(proxy_auth_token),
                gateway.ca_cert_path.clone(),
                ca_cert_pem,
            )
        } else {
            (None, None, None, None, None, None)
        }
    }

    fn validate_mcp_server_registration(
        &self,
        profile: &str,
        server_id: &str,
        resolved_exec_path: &str,
    ) -> Result<(McpTransport, Option<String>), String> {
        let policy_guard = self.active_policy.read();
        let policy = policy_guard
            .as_ref()
            .ok_or_else(|| "no active policy loaded".to_string())?;
        let compiled_profile = policy
            .profiles
            .get(profile)
            .ok_or_else(|| format!("profile '{profile}' not found in active policy"))?;
        let mcp_policy = compiled_profile
            .mcp
            .as_ref()
            .ok_or_else(|| format!("profile '{profile}' has no MCP policy"))?;
        let server = mcp_policy
            .servers
            .iter()
            .find(|server| server.id == server_id)
            .ok_or_else(|| {
                format!("profile '{profile}' does not allow MCP server '{server_id}'")
            })?;

        match server.transport {
            McpTransport::Stdio => {
                let exec_path_glob = server.exec_path_glob.as_deref().ok_or_else(|| {
                    format!("MCP server '{server_id}' is missing exec_path_glob in compiled policy")
                })?;
                let exec_path_matcher = server.exec_path_matcher.as_ref().ok_or_else(|| {
                    format!(
                        "MCP server '{server_id}' is missing exec_path matcher in compiled policy"
                    )
                })?;
                if !exec_path_matcher.is_match(resolved_exec_path) {
                    return Err(format!(
                        "resolved executable path '{}' does not match MCP server '{}' exec_path_glob '{}'",
                        resolved_exec_path, server_id, exec_path_glob
                    ));
                }
                Ok((McpTransport::Stdio, None))
            }
            McpTransport::Http => Ok((McpTransport::Http, server.base_url.clone())),
        }
    }

    fn active_mcp_context_for_agent(&self, agent_id: &str) -> Option<McpAuditContext> {
        self.active_mcp_calls
            .read()
            .get(agent_id)
            .and_then(|calls| calls.last())
            .map(ActiveMcpToolCall::audit_context)
    }

    fn enrich_audit_event_with_mcp_context(&self, event: &mut AuditEvent) {
        if event.action_type == ActionType::McpToolCall {
            return;
        }
        if event.mcp.is_none() {
            event.mcp = self.active_mcp_context_for_agent(event.agent_id.as_str());
        }
        /*
         * Kernel events resolve agent_id to the launching run; add the parent
         * agent so an MCP server's side effects chain back to its client.
         */
        if event.context.parent_agent_id.is_none() && Uuid::parse_str(&event.agent_id).is_ok() {
            let (root_pid, parent_agent_id) = self.agent_lineage(event.agent_id.as_str());
            event.context.parent_agent_id = parent_agent_id;
            if event.context.root_pid.is_none() {
                event.context.root_pid = root_pid;
            }
        }
    }

    pub(crate) fn record_audit_event(&self, mut audit_event: AuditEvent) {
        stamp_event_id(&mut audit_event);
        if let Err(err) = self.audit.log(&audit_event) {
            error!(error = %err, "failed to write audit event");
        }
        alerts::offer_global(&audit_event);
        if let Some(dashboard) = self.dashboard.as_ref() {
            if let Err(err) = dashboard.ingest_event(&audit_event) {
                dashboard.set_error(err.to_string());
                warn!(error = %err, "dashboard ingest failed for userspace audit event");
            } else {
                dashboard.set_ready();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_mcp_tool_authorization_audit(
        &self,
        agent_id: &str,
        profile: &str,
        registration_pid: Option<u32>,
        resource: McpToolResource,
        decision: Decision,
        reason: DecisionReason,
        rule_id: Option<String>,
    ) {
        let audit_event = AuditEvent {
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            pid: registration_pid,
            ppid: None,
            uid: None,
            action_type: ActionType::McpToolCall,
            decision,
            reason,
            rule_id: rule_id.clone(),
            resource: Resource::McpTool(resource.clone()),
            profile: profile.to_string(),
            policy_version: self.policy_version(),
            message: format!(
                "mcp tool authorization decision={decision:?} reason={reason} server={} tool={}",
                resource.server_id, resource.tool_name
            ),
            mcp: Some(McpAuditContext {
                server_id: resource.server_id,
                transport: resource.transport,
                resource_uri: None,
                tool_name: resource.tool_name,
                tool_call_id: resource.tool_call_id,
                mcp_session_id: resource.mcp_session_id,
            }),
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: self.mcp_agent_context(agent_id),
        };
        self.record_audit_event(audit_event);
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_mcp_resource_authorization_audit(
        &self,
        agent_id: &str,
        profile: &str,
        registration_pid: Option<u32>,
        resource: McpResourceReadResource,
        decision: Decision,
        reason: DecisionReason,
        rule_id: Option<String>,
    ) {
        let audit_event = AuditEvent {
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            pid: registration_pid,
            ppid: None,
            uid: None,
            action_type: ActionType::McpResourceRead,
            decision,
            reason,
            rule_id: rule_id.clone(),
            resource: Resource::McpResource(resource.clone()),
            profile: profile.to_string(),
            policy_version: self.policy_version(),
            message: format!(
                "mcp resource authorization decision={decision:?} reason={reason} server={} uri={}",
                resource.server_id, resource.uri
            ),
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: self.mcp_agent_context(agent_id),
        };
        self.record_audit_event(audit_event);
    }

    pub(crate) fn active_policy_yaml(&self) -> Option<String> {
        self.active_policy_yaml.read().clone()
    }

    #[cfg(all(feature = "linux", unix))]
    pub(crate) fn dashboard_enrollments_snapshot(&self) -> Vec<linux_adapter::EnrollmentRecord> {
        self.adapter.list_enrollments()
    }

    pub(crate) fn validate_dashboard_agent_launch_profile(
        &self,
        profile: &str,
    ) -> Result<(), String> {
        // Verify the profile exists in the active policy.
        {
            let policy_guard = self.active_policy.read();
            let policy = policy_guard
                .as_ref()
                .ok_or_else(|| "no active policy loaded".to_string())?;
            if !policy.profiles.contains_key(profile) {
                return Err(format!("profile '{profile}' not found in active policy"));
            }
        }

        self.ensure_url_gateway_ready_for_profile(profile)
            .map(|_| ())
            .map_err(|err| err.message)
    }

    pub(crate) fn registration_snapshot(&self) -> Vec<AgentRegistration> {
        self.registrations.read().values().cloned().collect()
    }

    pub(crate) fn registration_for_pid(&self, pid: u32) -> Option<AgentRegistration> {
        self.registrations.read().get(&pid).cloned()
    }

    pub(crate) fn control_socket_path(&self) -> String {
        self.config.socket_path.clone()
    }

    pub(crate) fn cleanup_dashboard_process_state(&self, pid: u32) {
        self.registrations.write().remove(&pid);
        let _ = self.adapter.remove_pid_enrollment(pid);
        self.proxy_auth_tokens
            .write()
            .retain(|_, subject| subject.pid != pid);
    }

    pub(crate) fn dashboard_status_snapshot(&self) -> DashboardStatusResponse {
        let mut status = self.dashboard_status.read().clone();
        let mut operational = None;
        if let Some(service) = self.dashboard.as_ref() {
            let (ready, last_error) = service.readiness();
            status.ready = ready;
            status.error = last_error;
            status.url = Some(service.dashboard_url());
            status.enabled = true;
            if let Ok(snapshot) = service.operational_snapshot() {
                operational = Some(snapshot);
            }
        }

        let tls_cert_info = self
            .dashboard
            .as_ref()
            .and_then(|svc| svc.tls_cert_info.read().clone());

        let mut resp = DashboardStatusResponse::from_daemon(self, status);
        if let Some(snapshot) = operational {
            resp.dashboard_schema_version = snapshot.schema_version;
            resp.policy_versions_total = snapshot.policy_versions_total;
            resp.pending_mcp_approvals = snapshot.pending_mcp_approvals;
            resp.active_dashboard_sessions = snapshot.active_dashboard_sessions;
            resp.active_sse_clients = snapshot.active_sse_clients;
            resp.dashboard_sqlite_bytes = snapshot.dashboard_sqlite_bytes;
        }
        resp.tls_cert_info = tls_cert_info;
        resp
    }

    pub(crate) fn ingest_metrics_snapshot(&self) -> IngestMetricsSnapshot {
        IngestMetricsSnapshot {
            events_ingested_total: self
                .ingest_metrics
                .events_ingested_total
                .load(Ordering::Relaxed),
            events_dropped_queue_total: self
                .ingest_metrics
                .events_dropped_queue_total
                .load(Ordering::Relaxed),
            events_dropped_ringbuf_total: self
                .ingest_metrics
                .events_dropped_ringbuf_total
                .load(Ordering::Relaxed),
            ingest_backlog_len: self
                .ingest_metrics
                .ingest_backlog_len
                .load(Ordering::Relaxed),
        }
    }

    /// Collect all metrics needed by the Prometheus /metrics endpoint.
    pub(crate) fn prometheus_metrics(&self) -> PrometheusMetrics {
        let ingest = self.ingest_metrics_snapshot();
        let runtime = self.adapter.runtime_health();
        let mut operational = None;
        if let Some(service) = self.dashboard.as_ref() {
            operational = service.operational_snapshot().ok();
        }

        PrometheusMetrics {
            events_ingested_total: ingest.events_ingested_total,
            events_dropped_queue_total: ingest.events_dropped_queue_total,
            ingest_backlog_len: ingest.ingest_backlog_len,
            unenrolled_events_suppressed_total: runtime.unenrolled_events_suppressed_total,
            enrolled_agents: self.registrations.read().len(),
            active_mcp_sessions: self.mcp_sessions.read().len(),
            pending_mcp_approvals: operational
                .as_ref()
                .map(|o| o.pending_mcp_approvals)
                .unwrap_or(0),
            policy_reloads_total: self.policy_reloads_total.load(Ordering::Relaxed),
            dashboard_sqlite_bytes: operational
                .as_ref()
                .map(|o| o.dashboard_sqlite_bytes)
                .unwrap_or(0),
            active_sse_clients: operational
                .as_ref()
                .map(|o| o.active_sse_clients)
                .unwrap_or(0),
            #[cfg(all(feature = "linux", unix))]
            kernel_ready: runtime.kernel_ready,
            #[cfg(not(all(feature = "linux", unix)))]
            kernel_ready: runtime.ready,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub(crate) fn url_gateway_config(&self) -> UrlGatewayConfig {
        self.config.url_gateway.clone()
    }

    pub(crate) fn url_gateway_status_snapshot(&self) -> UrlGatewayStatus {
        self.url_gateway_status.read().clone()
    }

    pub(crate) fn set_url_gateway_status(&self, status: UrlGatewayStatus) {
        *self.url_gateway_status.write() = status;
    }

    pub(crate) fn profile_has_url_rules(&self, profile: &str) -> bool {
        self.active_policy
            .read()
            .as_ref()
            .and_then(|compiled| compiled.profiles.get(profile))
            .map(|policy| !policy.url_allow.is_empty() || !policy.url_deny.is_empty())
            .unwrap_or(false)
    }

    pub(crate) fn resolve_proxy_subject_for_pid(&self, pid: u32) -> Option<ProxySubject> {
        let registration = { self.registrations.read().get(&pid).cloned() };
        if let Some(registration) = registration {
            if kernel_runtime::read_proc_start_time(pid) == Some(registration.proc_start_time) {
                return Some(ProxySubject {
                    agent_id: registration.agent_id.to_string(),
                    profile: registration.profile,
                    pid,
                    ppid: registration.ppid,
                    uid: registration.uid,
                    cgroup_id: registration.cgroup_id,
                });
            }

            self.registrations.write().remove(&pid);
        }

        let enrollment = self.adapter.enrollment_for_pid(pid)?;
        Some(ProxySubject {
            agent_id: enrollment.agent_id.to_string(),
            profile: enrollment.profile,
            pid,
            ppid: parent_pid_for(pid).unwrap_or(0),
            uid: enrollment.uid,
            #[cfg(all(feature = "linux", unix))]
            cgroup_id: enrollment.cgroup_id,
            #[cfg(not(all(feature = "linux", unix)))]
            cgroup_id: enrollment.group_id,
        })
    }

    pub(crate) fn resolve_proxy_subject_for_token(&self, token: &str) -> Option<ProxySubject> {
        let subject = self.proxy_auth_tokens.read().get(token).cloned()?;
        if self.cgroup_has_live_members(subject.cgroup_id.as_str()) {
            return Some(subject);
        }

        self.proxy_auth_tokens.write().remove(token);
        None
    }

    fn cgroup_has_live_members(&self, cgroup_id: &str) -> bool {
        let procs_path = Path::new(self.config.cgroup_base.as_str())
            .join(cgroup_id)
            .join("cgroup.procs");
        let contents = match fs::read_to_string(&procs_path) {
            Ok(contents) => contents,
            Err(_) => return false,
        };

        contents
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .any(|pid| kernel_runtime::read_proc_start_time(pid).is_some())
    }

    fn prune_stale_registrations(&self) -> usize {
        let stale_pids: Vec<u32> = self
            .registrations
            .read()
            .iter()
            .filter_map(|(pid, registration)| {
                (kernel_runtime::read_proc_start_time(*pid) != Some(registration.proc_start_time))
                    .then_some(*pid)
            })
            .collect();
        if stale_pids.is_empty() {
            return 0;
        }

        let removed: Vec<AgentRegistration> = {
            let mut registrations = self.registrations.write();
            stale_pids
                .iter()
                .filter_map(|pid| registrations.remove(pid))
                .collect()
        };
        for registration in &removed {
            self.record_enrollment_event("agent_unenrolled", registration, u32::MAX);
        }
        removed.len()
    }

    /// agent_enrolled / agent_unenrolled records: who launched what, where,
    /// under which profile. cmdline/cwd are as reported by the launcher; the
    /// kernel's PROC_START records carry the argv actually exec'd.
    fn record_enrollment_event(
        &self,
        name: &str,
        registration: &AgentRegistration,
        caller_uid: u32,
    ) {
        let live_members = self
            .live_cgroup_members(registration.cgroup_id.as_str())
            .len();
        let mut resource = SystemResource::new(name)
            .attr("agent_id", registration.agent_id.to_string())
            .attr("profile", registration.profile.clone())
            .attr("pid", registration.pid)
            .attr("ppid", registration.ppid)
            .attr("uid", registration.uid)
            .attr("gid", registration.gid)
            .attr("cgroup_id", registration.cgroup_id.clone())
            .attr("cmdline", registration.cmdline.clone())
            .attr("cwd", registration.cwd.clone())
            .attr("cgroup_live_members", live_members);
        if let Some(server_id) = registration.server_id.as_ref() {
            resource = resource.attr("mcp_server_id", server_id.clone());
        }
        if name == "agent_unenrolled" && live_members > 0 {
            resource = resource.detail("enrollment root exited; descendants still running");
        }
        let mut event = AuditEvent::system(
            "daemon",
            resource,
            self.policy_version(),
            format!(
                "{name} agent={} pid={} profile={}",
                registration.agent_id, registration.pid, registration.profile
            ),
        );
        event.agent_id = registration.agent_id.to_string();
        event.pid = Some(registration.pid);
        event.ppid = Some(registration.ppid);
        event.uid = Some(registration.uid);
        event.profile = registration.profile.clone();
        event.context.root_pid = Some(registration.pid);
        event.context.parent_agent_id = registration.parent_agent_id.map(|id| id.to_string());
        if caller_uid != u32::MAX {
            event.context.actor = Some(format!("uid:{caller_uid}"));
        }
        self.record_audit_event(event);
    }

    /// Live pids in the agent's cgroup (every process the launch created,
    /// unless it moved itself out).
    fn live_cgroup_members(&self, cgroup_id: &str) -> Vec<u32> {
        if cgroup_id.is_empty() || cgroup_id.contains('/') || cgroup_id.contains("..") {
            return Vec::new();
        }
        let procs_path = Path::new(self.config.cgroup_base.as_str())
            .join(cgroup_id)
            .join("cgroup.procs");
        fs::read_to_string(&procs_path)
            .map(|contents| {
                contents
                    .lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .filter(|pid| kernel_runtime::read_proc_start_time(*pid).is_some())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persists live registrations plus a heartbeat so a restarted daemon can
    /// re-enroll surviving agents and report how long it was gone.
    fn persist_enrollment_state(&self) {
        let state = PersistedEnrollmentState {
            heartbeat: Some(Utc::now()),
            registrations: self.registrations.read().values().cloned().collect(),
        };
        let path = Path::new(self.config.enrollment_state_path.as_str());
        if let Err(err) = write_json_atomically(path, &state) {
            let mut last = self.enrollment_state_error.lock();
            let message = err.to_string();
            if last.as_deref() != Some(message.as_str()) {
                warn!(path = %path.display(), error = %message, "failed to persist enrollment state");
                *last = Some(message);
            }
        } else {
            *self.enrollment_state_error.lock() = None;
        }
    }

    /// Re-enrolls agents that outlived the previous daemon (their eBPF map
    /// entries died with it) and records the downtime as a telemetry gap.
    #[cfg(all(feature = "linux", unix))]
    fn restore_enrollments(&self) {
        let path = Path::new(self.config.enrollment_state_path.as_str());
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(path = %path.display(), error = %err, "cannot read enrollment state");
                return;
            }
        };
        let state: PersistedEnrollmentState = match serde_json::from_slice(&raw) {
            Ok(state) => state,
            Err(err) => {
                warn!(path = %path.display(), error = %err, "ignoring unreadable enrollment state");
                return;
            }
        };

        let mut restored = 0usize;
        let mut exited = 0usize;
        let mut failed = 0usize;
        for registration in state.registrations {
            let members = self.live_cgroup_members(registration.cgroup_id.as_str());
            let root_alive = kernel_runtime::read_proc_start_time(registration.pid)
                == Some(registration.proc_start_time);
            let root = if root_alive {
                Some(registration.pid)
            } else {
                members.first().copied()
            };
            let Some(root) = root else {
                exited += 1;
                self.record_enrollment_event("agent_unenrolled", &registration, u32::MAX);
                continue;
            };
            match self.adapter.restore_enrollment(
                root,
                registration.agent_id,
                registration.profile.as_str(),
                registration.uid,
                registration.cgroup_id.as_str(),
                &members,
            ) {
                Ok(_) => {
                    restored += 1;
                    let mut event = AuditEvent::system(
                        "daemon",
                        SystemResource::new("enrollment_restored")
                            .attr("agent_id", registration.agent_id.to_string())
                            .attr("root_pid", root)
                            .attr("root_alive", root_alive)
                            .attr("members", members.clone()),
                        self.policy_version(),
                        format!(
                            "re-enrolled agent {} ({} live processes) after daemon restart",
                            registration.agent_id,
                            members.len()
                        ),
                    );
                    event.agent_id = registration.agent_id.to_string();
                    event.profile = registration.profile.clone();
                    event.context.root_pid = Some(root);
                    self.record_audit_event(event);
                    if root_alive {
                        self.registrations
                            .write()
                            .insert(registration.pid, registration);
                    }
                }
                Err(err) => {
                    failed += 1;
                    let mut event = AuditEvent::system(
                        "daemon",
                        SystemResource::new("enrollment_restore_failed")
                            .detail(err.to_string())
                            .attr("agent_id", registration.agent_id.to_string())
                            .attr("members", members.clone()),
                        self.policy_version(),
                        format!(
                            "could not re-enroll agent {}; its processes are unmonitored",
                            registration.agent_id
                        ),
                    );
                    event.decision = Decision::Deny;
                    event.agent_id = registration.agent_id.to_string();
                    self.record_audit_event(event);
                }
            }
        }

        let mut gap = SystemResource::new("telemetry_loss")
            .detail("mercuryd was not running; kernel hooks were detached")
            .attr("cause", "daemon_downtime")
            .attr("agents_restored", restored)
            .attr("agents_exited", exited)
            .attr("agents_restore_failed", failed);
        if let Some(heartbeat) = state.heartbeat {
            gap = gap
                .attr("gap_start", heartbeat.to_rfc3339())
                .attr("gap_end", Utc::now().to_rfc3339());
        }
        let mut event = AuditEvent::system(
            "daemon",
            gap,
            self.policy_version(),
            "telemetry and eBPF enforcement gap while the daemon was down",
        );
        if restored + failed > 0 {
            event.decision = Decision::Deny;
        }
        self.record_audit_event(event);
        self.persist_enrollment_state();
    }

    fn prune_stale_proxy_tokens(&self) -> usize {
        let stale_tokens: Vec<String> = self
            .proxy_auth_tokens
            .read()
            .iter()
            .filter_map(|(token, subject)| {
                (!self.cgroup_has_live_members(subject.cgroup_id.as_str())).then_some(token.clone())
            })
            .collect();
        if stale_tokens.is_empty() {
            return 0;
        }

        let mut tokens = self.proxy_auth_tokens.write();
        for token in &stale_tokens {
            tokens.remove(token);
        }
        stale_tokens.len()
    }

    /// Garbage-collect mcp_sessions / active_mcp_calls / pending_mcp_approvals for
    /// server processes that have exited, and expire approval records past their TTL.
    fn prune_stale_mcp_state(&self) {
        let now = Instant::now();

        // Collect sessions whose server process has exited *or* whose PID has been
        // recycled by a different process (start time mismatch catches PID reuse).
        let dead_sessions: Vec<(String, String)> = self
            .mcp_sessions
            .read()
            .values()
            .filter(|s| kernel_runtime::read_proc_start_time(s.pid) != Some(s.proc_start_time))
            .map(|s| (s.mcp_session_id.clone(), s.agent_id.to_string()))
            .collect();

        let dead_agent_ids: std::collections::HashSet<String> =
            dead_sessions.iter().map(|(_, aid)| aid.clone()).collect();

        let dead_sessions_count = dead_sessions.len();
        if dead_sessions_count > 0 {
            let mut mcp_sessions = self.mcp_sessions.write();
            let mut active_calls = self.active_mcp_calls.write();
            for (sid, aid) in &dead_sessions {
                mcp_sessions.remove(sid.as_str());
                active_calls.remove(aid.as_str());
            }
        }

        // Expire pending approvals whose agent has exited or whose TTL has elapsed.
        let expired_ids: Vec<String> = self
            .pending_mcp_approvals
            .read()
            .iter()
            .filter(|(_, r)| dead_agent_ids.contains(&r.agent_id) || now >= r.deadline)
            .map(|(id, _)| id.clone())
            .collect();

        let expired_count = expired_ids.len();
        for request_id in &expired_ids {
            // Signal any condvar waiter; idempotent if already resolved.
            let _ = self.resolve_mcp_approval(
                request_id,
                McpToolCallAuthorizationDecision::Deny,
                DecisionReason::DenyApprovalExpired,
                None,
            );
            // Remove so memory is freed whether or not anyone was waiting.
            self.pending_mcp_approvals
                .write()
                .remove(request_id.as_str());
        }

        if dead_sessions_count > 0 || expired_count > 0 {
            info!(
                dead_sessions = dead_sessions_count,
                expired_approvals = expired_count,
                "pruned stale MCP state"
            );
        }
    }

    /// Writes a telemetry_loss record when any loss counter moved since the
    /// last report, so gaps are visible in the audit stream itself (and to
    /// SIEM/alerting), not only in health counters. Per-pid rate-limit
    /// summaries are emitted by the kernel; this is the host-wide total.
    #[cfg(all(feature = "linux", unix))]
    fn report_telemetry_loss(&self) {
        let health = self.adapter.runtime_health();
        let ingest = self.ingest_metrics_snapshot();
        let current = LossCounters {
            kernel_ringbuf_dropped: health.events_dropped_ringbuf_total,
            kernel_deny_dropped: health.deny_events_dropped_total,
            kernel_rate_limited: health.events_rate_limited_total,
            ingest_queue_dropped: ingest.events_dropped_queue_total,
        };
        let delta = {
            let mut reported = self.reported_loss.lock();
            let delta = current.since(*reported);
            *reported = current;
            delta
        };
        if delta.is_zero() {
            return;
        }
        let mut event = AuditEvent::system(
            "daemon",
            SystemResource::new("telemetry_loss")
                .detail("kernel or ingest events were not recorded")
                .attr("kernel_ringbuf_dropped", delta.kernel_ringbuf_dropped)
                .attr("kernel_deny_dropped", delta.kernel_deny_dropped)
                .attr("kernel_rate_limited", delta.kernel_rate_limited)
                .attr("ingest_queue_dropped", delta.ingest_queue_dropped),
            self.policy_version(),
            format!(
                "telemetry loss: ringbuf={} deny={} rate_limited={} ingest_queue={}",
                delta.kernel_ringbuf_dropped,
                delta.kernel_deny_dropped,
                delta.kernel_rate_limited,
                delta.ingest_queue_dropped
            ),
        );
        // Enforced-but-unlogged denies are the most serious form of loss.
        if delta.kernel_deny_dropped > 0 {
            event.decision = Decision::Deny;
        }
        self.record_audit_event(event);
    }

    fn prune_stale_process_state(&self) {
        // Heartbeat + current registrations for restart recovery.
        self.persist_enrollment_state();
        // Run MCP prune first so expiry audit events can still look up PIDs
        // from `registrations` before the next step removes them.
        self.prune_stale_mcp_state();

        let stale_registrations = self.prune_stale_registrations();
        let stale_enrollments = match self.adapter.prune_stale_enrollments() {
            Ok(removed) => removed,
            Err(err) => {
                warn!(error = %err, "failed to prune stale adapter enrollments");
                0
            }
        };
        let stale_tokens = self.prune_stale_proxy_tokens();

        if stale_registrations > 0 || stale_enrollments > 0 || stale_tokens > 0 {
            info!(
                stale_registrations,
                stale_enrollments, stale_tokens, "pruned stale daemon process state"
            );
        }
    }

    /// Evaluate a proxied request without auditing it. The URL gateway
    /// writes the decision record itself, once the upstream address is
    /// resolved and checked, and a matching outcome record when the request
    /// completes. Returns the decision and the policy version that made it.
    pub(crate) fn evaluate_proxy_request(
        &self,
        subject: &ProxySubject,
        pid: u32,
        ppid: u32,
        resource: NetworkResource,
    ) -> (DecisionResult, String) {
        let action = Action {
            action_type: ActionType::NetConnect,
            context: ActionContext {
                timestamp: Utc::now(),
                agent_id: subject.agent_id.clone(),
                pid,
                ppid,
                uid: subject.uid,
                profile: subject.profile.clone(),
            },
            resource: Resource::Network(resource),
        };

        let guard = self.engine.read();
        let decision = guard.evaluate(subject.profile.as_str(), &action);
        let policy_version = guard.policy_version().unwrap_or("unloaded").to_string();
        (decision, policy_version)
    }

    pub fn evaluate_action(&self, profile: &str, action: &Action) -> DecisionResult {
        evaluate_and_audit(
            &self.engine,
            &self.audit,
            self.dashboard.as_ref(),
            profile,
            action,
            self.active_mcp_context_for_agent(action.context.agent_id.as_str()),
            core_types::EventContext::default(),
        )
    }

    /// Dry-run evaluation requested over the control socket. The record is
    /// marked `simulated` and names the caller: the socket is group-writable,
    /// so the agent/pid/resource fields are caller-supplied and must not be
    /// mistaken for observed activity.
    pub fn evaluate_action_simulated(
        &self,
        profile: &str,
        action: &Action,
        caller_uid: u32,
    ) -> DecisionResult {
        evaluate_and_audit(
            &self.engine,
            &self.audit,
            self.dashboard.as_ref(),
            profile,
            action,
            None,
            core_types::EventContext {
                source: Some("control-api".to_string()),
                actor: Some(format!("uid:{caller_uid}")),
                simulated: Some(true),
                ..core_types::EventContext::default()
            },
        )
    }

    pub(crate) fn approve_mcp_approval(&self, request_id: &str, actor: &str) -> Result<(), String> {
        self.resolve_mcp_approval(
            request_id,
            McpToolCallAuthorizationDecision::Allow,
            DecisionReason::AllowByApproval,
            Some(actor.to_string()),
        )
        .map(|_| ())
    }

    pub(crate) fn deny_mcp_approval(&self, request_id: &str, actor: &str) -> Result<(), String> {
        self.resolve_mcp_approval(
            request_id,
            McpToolCallAuthorizationDecision::Deny,
            DecisionReason::DenyByApproval,
            Some(actor.to_string()),
        )
        .map(|_| ())
    }

    fn resolve_mcp_approval(
        &self,
        request_id: &str,
        decision: McpToolCallAuthorizationDecision,
        reason: DecisionReason,
        actor: Option<String>,
    ) -> Result<PendingMcpApprovalResolution, String> {
        let record = self
            .pending_mcp_approvals
            .read()
            .get(request_id)
            .cloned()
            .ok_or_else(|| format!("pending MCP approval request '{request_id}' not found"))?;

        let mut state = record.shared.state.lock();
        if let Some(existing) = state.resolution.clone() {
            return Ok(existing);
        }

        let resolution = PendingMcpApprovalResolution {
            decision,
            rule_id: record.rule_id.clone(),
            resolved_at: Utc::now(),
        };
        state.resolution = Some(resolution.clone());
        record.shared.condvar.notify_all();
        drop(state);

        match decision {
            McpToolCallAuthorizationDecision::Allow => {
                if let Some(tool_name) = record.tool_name.as_ref() {
                    self.active_mcp_calls
                        .write()
                        .entry(record.agent_id.clone())
                        .or_default()
                        .push(ActiveMcpToolCall {
                            mcp_session_id: record.mcp_session_id.clone(),
                            server_id: record.server_id.clone(),
                            transport: record.transport,
                            tool_name: tool_name.clone(),
                            tool_call_id: record.tool_call_id.clone(),
                        });
                }
            }
            McpToolCallAuthorizationDecision::Deny
            | McpToolCallAuthorizationDecision::PendingApproval => {}
        }

        if let Some(dashboard) = self.dashboard.as_ref() {
            let approval_state = match reason {
                DecisionReason::AllowByApproval => "approved",
                DecisionReason::DenyByApproval => "denied",
                DecisionReason::DenyApprovalExpired => "expired",
                _ => "resolved",
            };
            if let Err(err) = dashboard.set_mcp_tool_call_resolution(
                request_id,
                approval_state,
                match decision {
                    McpToolCallAuthorizationDecision::Allow => "allow",
                    McpToolCallAuthorizationDecision::Deny => "deny",
                    McpToolCallAuthorizationDecision::PendingApproval => "pending_approval",
                },
                reason.to_string().as_str(),
                actor.as_deref(),
                resolution.resolved_at,
            ) {
                warn!(error = %err, request_id, "failed to persist MCP approval resolution");
            }
        }

        let registration_pid = self
            .registrations
            .read()
            .values()
            .find(|registration| registration.agent_id.to_string() == record.agent_id)
            .map(|registration| registration.pid);
        let audit_decision = match decision {
            McpToolCallAuthorizationDecision::Allow => Decision::Allow,
            McpToolCallAuthorizationDecision::Deny => Decision::Deny,
            McpToolCallAuthorizationDecision::PendingApproval => Decision::Deny,
        };
        self.record_mcp_approval_resolution(
            request_id,
            &record,
            registration_pid,
            audit_decision,
            reason,
            actor.as_deref(),
        );

        Ok(resolution)
    }

    fn handle_register_agent(
        &self,
        register: control_api::RegisterAgentRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        // Reject new enrollments when under sustained backpressure (>30s).
        if self.backpressure.active.load(Ordering::Relaxed) {
            let activated_at = self.backpressure.activated_at.lock();
            if activated_at.is_some_and(|ts| ts.elapsed() > StdDuration::from_secs(30)) {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "BACKPRESSURE".to_string(),
                    message: "system under sustained backpressure; try again later".to_string(),
                });
            }
        }

        if !pid_owned_by(caller_uid, register.pid) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own pid {}",
                    caller_uid, register.pid
                ),
            });
        }

        let profile_uses_url_gateway =
            match self.ensure_url_gateway_ready_for_profile(register.profile.as_str()) {
                Ok(value) => value,
                Err(err) => return ControlResponse::Error(err),
            };

        let agent_id = Uuid::new_v4();
        let Some(proc_start_time) = kernel_runtime::read_proc_start_time(register.pid) else {
            return ControlResponse::Error(ControlErrorPayload {
                code: "REGISTER_FAILED".to_string(),
                message: format!(
                    "read process start time for pid {} from /proc/{}/stat",
                    register.pid, register.pid
                ),
            });
        };

        match self.adapter.register_launching_pid(
            register.pid,
            agent_id,
            register.profile.as_str(),
            register.uid,
        ) {
            Ok(registration_result) => {
                // Evict any prior MCP session for this PID before overwriting the
                // registration entry (e.g. a process that previously registered as an
                // MCP server now re-registers as a plain agent). Without this, the old
                // mcp_session_id is orphaned in `mcp_sessions` and `active_mcp_calls`.
                if let Some(prior) = self.registrations.read().get(&register.pid)
                    && let Some(ref old_sid) = prior.mcp_session_id
                {
                    self.mcp_sessions.write().remove(old_sid.as_str());
                    self.active_mcp_calls
                        .write()
                        .remove(&prior.agent_id.to_string());
                }

                let registration = AgentRegistration {
                    agent_id,
                    profile: register.profile.clone(),
                    pid: register.pid,
                    ppid: register.ppid,
                    uid: register.uid,
                    proc_start_time,
                    gid: register.gid,
                    cgroup_id: registration_result.cgroup_id.clone(),
                    cmdline: register.cmdline,
                    cwd: register.cwd,
                    mcp_session_id: None,
                    server_id: None,
                    client_name: None,
                    parent_agent_id: None,
                    resolved_exec_path: None,
                };
                self.record_enrollment_event("agent_enrolled", &registration, caller_uid);
                self.registrations
                    .write()
                    .insert(registration.pid, registration);
                self.persist_enrollment_state();

                let (
                    url_proxy_http,
                    url_proxy_https,
                    url_proxy_no_proxy,
                    url_proxy_auth_token,
                    url_proxy_ca_cert_path,
                    url_proxy_ca_cert_pem,
                ) = self.build_registration_proxy_fields(
                    register.profile.as_str(),
                    profile_uses_url_gateway,
                    agent_id,
                    registration_result.cgroup_id.as_str(),
                    register.pid,
                    register.ppid,
                    register.uid,
                );

                ControlResponse::RegisterAgent(RegisterAgentResponse {
                    agent_id,
                    cgroup_id: registration_result.cgroup_id,
                    filesystem_label: registration_result.filesystem_label,
                    url_proxy_http,
                    url_proxy_https,
                    url_proxy_no_proxy,
                    url_proxy_auth_token,
                    url_proxy_ca_cert_path,
                    url_proxy_ca_cert_pem,
                })
            }
            Err(err) => ControlResponse::Error(ControlErrorPayload {
                code: "REGISTER_FAILED".to_string(),
                message: err.to_string(),
            }),
        }
    }

    fn handle_register_mcp_server(
        &self,
        register: control_api::RegisterMcpServerRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        if !pid_owned_by(caller_uid, register.pid) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own pid {}",
                    caller_uid, register.pid
                ),
            });
        }

        let profile_uses_url_gateway =
            match self.ensure_url_gateway_ready_for_profile(register.profile.as_str()) {
                Ok(value) => value,
                Err(err) => return ControlResponse::Error(err),
            };

        let resolved_exec_path = match resolve_process_executable_path(register.pid) {
            Ok(path) => path,
            Err(message) => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "REGISTER_FAILED".to_string(),
                    message,
                });
            }
        };

        let (transport, mcp_http_base_url) = match self.validate_mcp_server_registration(
            register.profile.as_str(),
            register.server_id.as_str(),
            resolved_exec_path.as_str(),
        ) {
            Ok(value) => value,
            Err(message) => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "MCP_SERVER_REJECTED".to_string(),
                    message,
                });
            }
        };

        // Evict any prior MCP session for this PID to prevent orphaned sessions when the
        // same process calls RegisterMcpServer more than once (e.g. on reconnect).
        if let Some(prior) = self.registrations.read().get(&register.pid)
            && let Some(ref old_sid) = prior.mcp_session_id
        {
            self.mcp_sessions.write().remove(old_sid.as_str());
            self.active_mcp_calls
                .write()
                .remove(&prior.agent_id.to_string());
        }

        let agent_id = Uuid::new_v4();
        let mcp_session_id = Uuid::new_v4().to_string();
        let (mcp_http_gateway_url, mcp_http_gateway_token) = match transport {
            McpTransport::Stdio => (None, None),
            McpTransport::Http => {
                let Some(dashboard) = self.dashboard.as_ref() else {
                    return ControlResponse::Error(ControlErrorPayload {
                        code: "MCP_HTTP_GATEWAY_UNAVAILABLE".to_string(),
                        message: "HTTP MCP transport requires the Mercury dashboard HTTP listener"
                            .to_string(),
                    });
                };
                (
                    Some(format!(
                        "{}/api/v1/mcp/http/{}",
                        dashboard.dashboard_url(),
                        mcp_session_id
                    )),
                    Some(Uuid::new_v4().to_string()),
                )
            }
        };
        let Some(proc_start_time) = kernel_runtime::read_proc_start_time(register.pid) else {
            return ControlResponse::Error(ControlErrorPayload {
                code: "REGISTER_FAILED".to_string(),
                message: format!(
                    "read process start time for pid {} from /proc/{}/stat",
                    register.pid, register.pid
                ),
            });
        };

        match self.adapter.register_existing_pid(
            register.pid,
            agent_id,
            register.profile.as_str(),
            register.uid,
        ) {
            Ok(registration_result) => {
                let registration = AgentRegistration {
                    agent_id,
                    profile: register.profile.clone(),
                    pid: register.pid,
                    ppid: register.ppid,
                    uid: register.uid,
                    proc_start_time,
                    gid: register.gid,
                    cgroup_id: registration_result.cgroup_id.clone(),
                    cmdline: register.cmdline,
                    cwd: register.cwd,
                    mcp_session_id: Some(mcp_session_id.clone()),
                    server_id: Some(register.server_id.clone()),
                    client_name: register.client_name.clone(),
                    parent_agent_id: register.parent_agent_id,
                    resolved_exec_path: Some(resolved_exec_path.clone()),
                };

                self.record_enrollment_event("agent_enrolled", &registration, caller_uid);
                self.registrations
                    .write()
                    .insert(registration.pid, registration);
                self.persist_enrollment_state();
                self.mcp_sessions.write().insert(
                    mcp_session_id.clone(),
                    RegisteredMcpServer {
                        mcp_session_id: mcp_session_id.clone(),
                        pid: register.pid,
                        proc_start_time,
                        profile: register.profile.clone(),
                        agent_id,
                        server_id: register.server_id.clone(),
                        transport,
                        http_base_url: mcp_http_base_url.clone(),
                        http_gateway_token: mcp_http_gateway_token.clone(),
                    },
                );

                let (
                    url_proxy_http,
                    url_proxy_https,
                    url_proxy_no_proxy,
                    url_proxy_auth_token,
                    url_proxy_ca_cert_path,
                    url_proxy_ca_cert_pem,
                ) = self.build_registration_proxy_fields(
                    register.profile.as_str(),
                    profile_uses_url_gateway,
                    agent_id,
                    registration_result.cgroup_id.as_str(),
                    register.pid,
                    register.ppid,
                    register.uid,
                );

                ControlResponse::RegisterMcpServer(RegisterMcpServerResponse {
                    agent_id,
                    cgroup_id: registration_result.cgroup_id,
                    filesystem_label: registration_result.filesystem_label,
                    mcp_session_id,
                    url_proxy_http,
                    url_proxy_https,
                    url_proxy_no_proxy,
                    url_proxy_auth_token,
                    url_proxy_ca_cert_path,
                    url_proxy_ca_cert_pem,
                    mcp_http_gateway_url,
                    mcp_http_gateway_token,
                })
            }
            Err(err) => ControlResponse::Error(ControlErrorPayload {
                code: "REGISTER_FAILED".to_string(),
                message: err.to_string(),
            }),
        }
    }

    fn handle_authorize_mcp_tool_call(
        &self,
        request: control_api::AuthorizeMcpToolCallRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        let tool_name = request.tool_name.trim().to_string();
        if tool_name.is_empty() {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: "tool_name must not be empty".to_string(),
            });
        }
        let tool_call_id = request.tool_call_id.trim().to_string();
        if tool_call_id.is_empty() {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: "tool_call_id must not be empty".to_string(),
            });
        }

        // Reject oversized payloads before they reach the pending-approval in-memory store.
        if request.arguments_json.len() > MAX_ARGUMENTS_JSON_BYTES {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: format!(
                    "arguments_json exceeds maximum allowed size of {} bytes",
                    MAX_ARGUMENTS_JSON_BYTES
                ),
            });
        }

        // Validate that arguments_json is well-formed JSON to prevent log-injection
        // and corrupt dashboard approval records.
        if serde_json::from_str::<serde_json::Value>(request.arguments_json.as_str()).is_err() {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: "arguments_json must be valid JSON".to_string(),
            });
        }

        let session = match self
            .mcp_sessions
            .read()
            .get(request.mcp_session_id.as_str())
            .cloned()
        {
            Some(session) => session,
            None => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "MCP_SESSION_NOT_FOUND".to_string(),
                    message: format!("unknown MCP session '{}'", request.mcp_session_id),
                });
            }
        };

        if !pid_matches_owner_and_start_time(caller_uid, session.pid, session.proc_start_time) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own MCP session pid {}",
                    caller_uid, session.pid
                ),
            });
        }

        let arguments_sha256 = hash_arguments_json(request.arguments_json.as_str());
        let arguments_summary = summarize_arguments(
            request.arguments_json.as_str(),
            request.arguments_summary.as_deref(),
        );
        let resource = McpToolResource {
            server_id: session.server_id.clone(),
            transport: session.transport,
            tool_name: tool_name.clone(),
            tool_call_id: tool_call_id.clone(),
            mcp_session_id: session.mcp_session_id.clone(),
            arguments_sha256: arguments_sha256.clone(),
            arguments_summary: arguments_summary.clone(),
        };

        let evaluation = self
            .engine
            .read()
            .evaluate_mcp_tool_call(session.profile.as_str(), &resource);

        match evaluation.decision {
            McpEvaluationDecision::Allow => {
                // Idempotent dedup + push under a single write lock to prevent a TOCTOU
                // race where two concurrent calls with the same tool_call_id both pass a
                // read-lock check and then both push duplicate entries.
                let duplicate = {
                    let mut calls = self.active_mcp_calls.write();
                    let agent_calls = calls.entry(session.agent_id.to_string()).or_default();
                    if agent_calls.iter().any(|c| c.tool_call_id == tool_call_id) {
                        true
                    } else {
                        // Concurrent tool calls per agent are legal per MCP spec.
                        agent_calls.push(ActiveMcpToolCall {
                            mcp_session_id: session.mcp_session_id.clone(),
                            server_id: session.server_id.clone(),
                            transport: session.transport,
                            tool_name: tool_name.clone(),
                            tool_call_id: tool_call_id.clone(),
                        });
                        false
                    }
                };
                if duplicate {
                    // Still audited: the repeat carries its own arguments.
                    let event = self.mcp_tool_audit_event(
                        session.agent_id.to_string().as_str(),
                        session.profile.as_str(),
                        Some(session.pid),
                        resource,
                        Decision::Allow,
                        DecisionReason::AllowByRule,
                        evaluation.rule_id.clone(),
                        format!(
                            "mcp tool authorization repeated for active tool_call_id={tool_call_id}; no new call started"
                        ),
                    );
                    self.record_audit_event(event);
                    return ControlResponse::AuthorizeMcpToolCall(AuthorizeMcpToolCallResponse {
                        decision: McpToolCallAuthorizationDecision::Allow,
                        rule_id: evaluation.rule_id,
                        request_id: None,
                    });
                }

                if let Some(dashboard) = self.dashboard.as_ref() {
                    let record = dashboard::StoredMcpToolCall {
                        kind: "tool".to_string(),
                        request_id: None,
                        created_at: Utc::now(),
                        expires_at: None,
                        agent_id: session.agent_id.to_string(),
                        profile: session.profile.clone(),
                        server_id: session.server_id.clone(),
                        transport: session.transport,
                        mcp_session_id: session.mcp_session_id.clone(),
                        resource_uri: None,
                        client_request_id: None,
                        tool_name: tool_name.clone(),
                        tool_call_id: tool_call_id.clone(),
                        arguments_json: request.arguments_json.clone(),
                        arguments_sha256: arguments_sha256.clone(),
                        arguments_summary: arguments_summary.clone(),
                        rule_id: evaluation.rule_id.clone(),
                        approval_state: "not_required".to_string(),
                        final_decision: Some("allow".to_string()),
                        reason: Some(DecisionReason::AllowByRule.to_string()),
                        resolved_by: None,
                        resolved_at: Some(Utc::now()),
                        completion_status: None,
                        completion_error: None,
                    };
                    if let Err(err) = dashboard.upsert_mcp_tool_call(&record) {
                        warn!(error = %err, "failed to persist allowed MCP tool call");
                    }
                }

                self.emit_mcp_tool_authorization_audit(
                    session.agent_id.to_string().as_str(),
                    session.profile.as_str(),
                    Some(session.pid),
                    resource,
                    Decision::Allow,
                    DecisionReason::AllowByRule,
                    evaluation.rule_id.clone(),
                );

                ControlResponse::AuthorizeMcpToolCall(AuthorizeMcpToolCallResponse {
                    decision: McpToolCallAuthorizationDecision::Allow,
                    rule_id: evaluation.rule_id,
                    request_id: None,
                })
            }
            McpEvaluationDecision::Deny => {
                if let Some(dashboard) = self.dashboard.as_ref() {
                    let record = dashboard::StoredMcpToolCall {
                        kind: "tool".to_string(),
                        request_id: None,
                        created_at: Utc::now(),
                        expires_at: None,
                        agent_id: session.agent_id.to_string(),
                        profile: session.profile.clone(),
                        server_id: session.server_id.clone(),
                        transport: session.transport,
                        mcp_session_id: session.mcp_session_id.clone(),
                        resource_uri: None,
                        client_request_id: None,
                        tool_name: tool_name.clone(),
                        tool_call_id: tool_call_id.clone(),
                        arguments_json: request.arguments_json.clone(),
                        arguments_sha256: arguments_sha256.clone(),
                        arguments_summary: arguments_summary.clone(),
                        rule_id: evaluation.rule_id.clone(),
                        approval_state: "not_required".to_string(),
                        final_decision: Some("deny".to_string()),
                        reason: Some(DecisionReason::DenyByRule.to_string()),
                        resolved_by: None,
                        resolved_at: Some(Utc::now()),
                        completion_status: None,
                        completion_error: None,
                    };
                    if let Err(err) = dashboard.upsert_mcp_tool_call(&record) {
                        warn!(error = %err, "failed to persist denied MCP tool call");
                    }
                }

                self.emit_mcp_tool_authorization_audit(
                    session.agent_id.to_string().as_str(),
                    session.profile.as_str(),
                    Some(session.pid),
                    resource,
                    Decision::Deny,
                    DecisionReason::DenyByRule,
                    evaluation.rule_id.clone(),
                );

                ControlResponse::AuthorizeMcpToolCall(AuthorizeMcpToolCallResponse {
                    decision: McpToolCallAuthorizationDecision::Deny,
                    rule_id: evaluation.rule_id,
                    request_id: None,
                })
            }
            McpEvaluationDecision::RequireApproval => {
                let Some(dashboard) = self.dashboard.as_ref() else {
                    self.record_mcp_approvals_unavailable(
                        &session,
                        Resource::McpTool(resource),
                        evaluation.rule_id.clone(),
                    );
                    return ControlResponse::Error(ControlErrorPayload {
                        code: "APPROVALS_UNAVAILABLE".to_string(),
                        message: "MCP tool approval is required but the dashboard is unavailable"
                            .to_string(),
                    });
                };

                // Idempotent: if a pending approval already exists for this
                // (mcp_session_id, tool_call_id), return the existing request_id rather
                // than creating a second record that leaks until TTL expiry.
                {
                    let approvals = self.pending_mcp_approvals.read();
                    if let Some((existing_id, _)) = approvals.iter().find(|(_, r)| {
                        r.mcp_session_id == session.mcp_session_id && r.tool_call_id == tool_call_id
                    }) {
                        return ControlResponse::AuthorizeMcpToolCall(
                            AuthorizeMcpToolCallResponse {
                                decision: McpToolCallAuthorizationDecision::PendingApproval,
                                rule_id: evaluation.rule_id,
                                request_id: Some(existing_id.clone()),
                            },
                        );
                    }
                }

                let request_id = Uuid::new_v4().to_string();
                let created_at = Utc::now();
                let expires_at = created_at
                    + chrono::Duration::from_std(MCP_APPROVAL_TTL)
                        .unwrap_or_else(|_| chrono::Duration::seconds(300));
                let record = PendingMcpApprovalRecord {
                    deadline: Instant::now() + MCP_APPROVAL_TTL,
                    profile: session.profile.clone(),
                    agent_id: session.agent_id.to_string(),
                    pid: session.pid,
                    proc_start_time: session.proc_start_time,
                    server_id: session.server_id.clone(),
                    transport: session.transport,
                    mcp_session_id: session.mcp_session_id.clone(),
                    resource_uri: None,
                    client_request_id: None,
                    tool_name: Some(tool_name.clone()),
                    tool_call_id: tool_call_id.clone(),
                    arguments_sha256: Some(arguments_sha256.clone()),
                    arguments_summary: arguments_summary.clone(),
                    rule_id: evaluation.rule_id.clone(),
                    shared: Arc::new(PendingMcpApprovalShared::default()),
                };
                self.pending_mcp_approvals
                    .write()
                    .insert(request_id.clone(), record.clone());
                self.record_mcp_approval_requested(&request_id, &record, expires_at);

                let dashboard_record = dashboard::StoredMcpToolCall {
                    kind: "tool".to_string(),
                    request_id: Some(request_id.clone()),
                    created_at,
                    expires_at: Some(expires_at),
                    agent_id: session.agent_id.to_string(),
                    profile: session.profile.clone(),
                    server_id: session.server_id.clone(),
                    transport: session.transport,
                    mcp_session_id: session.mcp_session_id.clone(),
                    resource_uri: None,
                    client_request_id: None,
                    tool_name,
                    tool_call_id,
                    arguments_json: request.arguments_json,
                    arguments_sha256,
                    arguments_summary,
                    rule_id: evaluation.rule_id.clone(),
                    approval_state: "pending".to_string(),
                    final_decision: None,
                    reason: None,
                    resolved_by: None,
                    resolved_at: None,
                    completion_status: None,
                    completion_error: None,
                };
                if let Err(err) = dashboard.upsert_mcp_tool_call(&dashboard_record) {
                    warn!(error = %err, request_id, "failed to persist pending MCP approval");
                }

                ControlResponse::AuthorizeMcpToolCall(AuthorizeMcpToolCallResponse {
                    decision: McpToolCallAuthorizationDecision::PendingApproval,
                    rule_id: evaluation.rule_id,
                    request_id: Some(request_id),
                })
            }
        }
    }

    fn handle_authorize_mcp_resource_read(
        &self,
        request: control_api::AuthorizeMcpResourceReadRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        let uri = request.uri.trim().to_string();
        if uri.is_empty() {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: "uri must not be empty".to_string(),
            });
        }
        let resource_call_id = request.resource_call_id.trim().to_string();
        if resource_call_id.is_empty() {
            return ControlResponse::Error(ControlErrorPayload {
                code: "INVALID_REQUEST".to_string(),
                message: "resource_call_id must not be empty".to_string(),
            });
        }

        let session = match self
            .mcp_sessions
            .read()
            .get(request.mcp_session_id.as_str())
            .cloned()
        {
            Some(session) => session,
            None => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "MCP_SESSION_NOT_FOUND".to_string(),
                    message: format!("unknown MCP session '{}'", request.mcp_session_id),
                });
            }
        };

        if !pid_matches_owner_and_start_time(caller_uid, session.pid, session.proc_start_time) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own MCP session pid {}",
                    caller_uid, session.pid
                ),
            });
        }

        let dashboard_arguments_json = serde_json::json!({
            "uri": uri,
            "client_request_id": request.client_request_id,
        })
        .to_string();
        let resource_summary = Some(uri.clone());
        let resource = McpResourceReadResource {
            server_id: session.server_id.clone(),
            transport: session.transport,
            uri: uri.clone(),
            mcp_session_id: session.mcp_session_id.clone(),
            request_id: request.client_request_id.clone(),
            resource_call_id: Some(resource_call_id.clone()),
        };

        let evaluation = self
            .engine
            .read()
            .evaluate_mcp_resource_read(session.profile.as_str(), &resource);

        match evaluation.decision {
            McpEvaluationDecision::Allow => {
                if let Some(dashboard) = self.dashboard.as_ref() {
                    let record = dashboard::StoredMcpToolCall {
                        kind: mcp_resource_call_kind(uri.as_str()).to_string(),
                        request_id: None,
                        created_at: Utc::now(),
                        expires_at: None,
                        agent_id: session.agent_id.to_string(),
                        profile: session.profile.clone(),
                        server_id: session.server_id.clone(),
                        transport: session.transport,
                        mcp_session_id: session.mcp_session_id.clone(),
                        resource_uri: Some(uri.clone()),
                        client_request_id: request.client_request_id.clone(),
                        tool_name: String::new(),
                        tool_call_id: resource_call_id.clone(),
                        arguments_json: dashboard_arguments_json.clone(),
                        arguments_sha256: hash_arguments_json(dashboard_arguments_json.as_str()),
                        arguments_summary: resource_summary.clone(),
                        rule_id: evaluation.rule_id.clone(),
                        approval_state: "not_required".to_string(),
                        final_decision: Some("allow".to_string()),
                        reason: Some(DecisionReason::AllowByRule.to_string()),
                        resolved_by: None,
                        resolved_at: Some(Utc::now()),
                        completion_status: None,
                        completion_error: None,
                    };
                    if let Err(err) = dashboard.upsert_mcp_tool_call(&record) {
                        warn!(error = %err, "failed to persist allowed MCP resource read");
                    }
                }

                self.emit_mcp_resource_authorization_audit(
                    session.agent_id.to_string().as_str(),
                    session.profile.as_str(),
                    Some(session.pid),
                    resource,
                    Decision::Allow,
                    DecisionReason::AllowByRule,
                    evaluation.rule_id.clone(),
                );

                ControlResponse::AuthorizeMcpResourceRead(AuthorizeMcpResourceReadResponse {
                    decision: McpToolCallAuthorizationDecision::Allow,
                    rule_id: evaluation.rule_id,
                    request_id: None,
                })
            }
            McpEvaluationDecision::Deny => {
                if let Some(dashboard) = self.dashboard.as_ref() {
                    let record = dashboard::StoredMcpToolCall {
                        kind: mcp_resource_call_kind(uri.as_str()).to_string(),
                        request_id: None,
                        created_at: Utc::now(),
                        expires_at: None,
                        agent_id: session.agent_id.to_string(),
                        profile: session.profile.clone(),
                        server_id: session.server_id.clone(),
                        transport: session.transport,
                        mcp_session_id: session.mcp_session_id.clone(),
                        resource_uri: Some(uri.clone()),
                        client_request_id: request.client_request_id.clone(),
                        tool_name: String::new(),
                        tool_call_id: resource_call_id.clone(),
                        arguments_json: dashboard_arguments_json.clone(),
                        arguments_sha256: hash_arguments_json(dashboard_arguments_json.as_str()),
                        arguments_summary: resource_summary.clone(),
                        rule_id: evaluation.rule_id.clone(),
                        approval_state: "not_required".to_string(),
                        final_decision: Some("deny".to_string()),
                        reason: Some(DecisionReason::DenyByRule.to_string()),
                        resolved_by: None,
                        resolved_at: Some(Utc::now()),
                        completion_status: None,
                        completion_error: None,
                    };
                    if let Err(err) = dashboard.upsert_mcp_tool_call(&record) {
                        warn!(error = %err, "failed to persist denied MCP resource read");
                    }
                }

                self.emit_mcp_resource_authorization_audit(
                    session.agent_id.to_string().as_str(),
                    session.profile.as_str(),
                    Some(session.pid),
                    resource,
                    Decision::Deny,
                    DecisionReason::DenyByRule,
                    evaluation.rule_id.clone(),
                );

                ControlResponse::AuthorizeMcpResourceRead(AuthorizeMcpResourceReadResponse {
                    decision: McpToolCallAuthorizationDecision::Deny,
                    rule_id: evaluation.rule_id,
                    request_id: None,
                })
            }
            McpEvaluationDecision::RequireApproval => {
                let Some(dashboard) = self.dashboard.as_ref() else {
                    self.record_mcp_approvals_unavailable(
                        &session,
                        Resource::McpResource(resource),
                        evaluation.rule_id.clone(),
                    );
                    return ControlResponse::Error(ControlErrorPayload {
                        code: "APPROVALS_UNAVAILABLE".to_string(),
                        message:
                            "MCP resource approval is required but the dashboard is unavailable"
                                .to_string(),
                    });
                };

                {
                    let approvals = self.pending_mcp_approvals.read();
                    if let Some((existing_id, _)) = approvals.iter().find(|(_, r)| {
                        r.mcp_session_id == session.mcp_session_id
                            && r.tool_call_id == resource_call_id
                    }) {
                        return ControlResponse::AuthorizeMcpResourceRead(
                            AuthorizeMcpResourceReadResponse {
                                decision: McpToolCallAuthorizationDecision::PendingApproval,
                                rule_id: evaluation.rule_id,
                                request_id: Some(existing_id.clone()),
                            },
                        );
                    }
                }

                let request_id = Uuid::new_v4().to_string();
                let created_at = Utc::now();
                let expires_at = created_at
                    + chrono::Duration::from_std(MCP_APPROVAL_TTL)
                        .unwrap_or_else(|_| chrono::Duration::seconds(300));
                let arguments_sha256 = hash_arguments_json(dashboard_arguments_json.as_str());
                let record = PendingMcpApprovalRecord {
                    deadline: Instant::now() + MCP_APPROVAL_TTL,
                    profile: session.profile.clone(),
                    agent_id: session.agent_id.to_string(),
                    pid: session.pid,
                    proc_start_time: session.proc_start_time,
                    server_id: session.server_id.clone(),
                    transport: session.transport,
                    mcp_session_id: session.mcp_session_id.clone(),
                    resource_uri: Some(uri.clone()),
                    client_request_id: request.client_request_id.clone(),
                    tool_name: None,
                    tool_call_id: resource_call_id.clone(),
                    arguments_sha256: Some(arguments_sha256.clone()),
                    arguments_summary: resource_summary.clone(),
                    rule_id: evaluation.rule_id.clone(),
                    shared: Arc::new(PendingMcpApprovalShared::default()),
                };
                self.pending_mcp_approvals
                    .write()
                    .insert(request_id.clone(), record.clone());
                self.record_mcp_approval_requested(&request_id, &record, expires_at);

                let dashboard_record = dashboard::StoredMcpToolCall {
                    kind: mcp_resource_call_kind(uri.as_str()).to_string(),
                    request_id: Some(request_id.clone()),
                    created_at,
                    expires_at: Some(expires_at),
                    agent_id: session.agent_id.to_string(),
                    profile: session.profile.clone(),
                    server_id: session.server_id.clone(),
                    transport: session.transport,
                    mcp_session_id: session.mcp_session_id.clone(),
                    resource_uri: Some(uri),
                    client_request_id: request.client_request_id,
                    tool_name: String::new(),
                    tool_call_id: resource_call_id,
                    arguments_json: dashboard_arguments_json,
                    arguments_sha256,
                    arguments_summary: resource_summary,
                    rule_id: evaluation.rule_id.clone(),
                    approval_state: "pending".to_string(),
                    final_decision: None,
                    reason: None,
                    resolved_by: None,
                    resolved_at: None,
                    completion_status: None,
                    completion_error: None,
                };
                if let Err(err) = dashboard.upsert_mcp_tool_call(&dashboard_record) {
                    warn!(error = %err, request_id, "failed to persist pending MCP resource approval");
                }

                ControlResponse::AuthorizeMcpResourceRead(AuthorizeMcpResourceReadResponse {
                    decision: McpToolCallAuthorizationDecision::PendingApproval,
                    rule_id: evaluation.rule_id,
                    request_id: Some(request_id),
                })
            }
        }
    }

    fn handle_wait_mcp_approval(
        &self,
        request: control_api::WaitMcpApprovalRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        let record = match self
            .pending_mcp_approvals
            .read()
            .get(request.request_id.as_str())
            .cloned()
        {
            Some(record) => record,
            None => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "MCP_APPROVAL_NOT_FOUND".to_string(),
                    message: format!("unknown MCP approval request '{}'", request.request_id),
                });
            }
        };

        if !pid_matches_owner_and_start_time(caller_uid, record.pid, record.proc_start_time) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own MCP approval pid {}",
                    caller_uid, record.pid
                ),
            });
        }

        loop {
            let mut state = record.shared.state.lock();
            if let Some(resolution) = state.resolution.clone() {
                drop(state);
                self.pending_mcp_approvals
                    .write()
                    .remove(request.request_id.as_str());
                return ControlResponse::WaitMcpApproval(WaitMcpApprovalResponse {
                    decision: resolution.decision,
                    rule_id: resolution.rule_id,
                    request_id: Some(request.request_id),
                });
            }

            let now = Instant::now();
            if now >= record.deadline {
                drop(state);
                match self.resolve_mcp_approval(
                    request.request_id.as_str(),
                    McpToolCallAuthorizationDecision::Deny,
                    DecisionReason::DenyApprovalExpired,
                    None,
                ) {
                    Ok(_) => continue,
                    Err(err) => {
                        return ControlResponse::Error(ControlErrorPayload {
                            code: "MCP_APPROVAL_EXPIRE_FAILED".to_string(),
                            message: err,
                        });
                    }
                }
            }

            record
                .shared
                .condvar
                .wait_for(&mut state, record.deadline - now);
        }
    }

    fn handle_complete_mcp_tool_call(
        &self,
        request: control_api::CompleteMcpToolCallRequest,
        caller_uid: u32,
    ) -> ControlResponse {
        let session = match self
            .mcp_sessions
            .read()
            .get(request.mcp_session_id.as_str())
            .cloned()
        {
            Some(session) => session,
            None => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "MCP_SESSION_NOT_FOUND".to_string(),
                    message: format!("unknown MCP session '{}'", request.mcp_session_id),
                });
            }
        };

        if !pid_matches_owner_and_start_time(caller_uid, session.pid, session.proc_start_time) {
            return ControlResponse::Error(ControlErrorPayload {
                code: "UNAUTHORIZED".to_string(),
                message: format!(
                    "caller uid {} does not own MCP session pid {}",
                    caller_uid, session.pid
                ),
            });
        }

        let mut active_calls = self.active_mcp_calls.write();
        let agent_key = session.agent_id.to_string();
        // Find and remove the specific call by tool_call_id within the agent's Vec.
        let completed = if let Some(calls) = active_calls.get_mut(&agent_key) {
            if let Some(pos) = calls
                .iter()
                .position(|c| c.tool_call_id == request.tool_call_id)
            {
                calls.remove(pos);
                if calls.is_empty() {
                    active_calls.remove(&agent_key);
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        drop(active_calls);

        // Guard first: a phantom/replayed CompleteMcpToolCall must not overwrite the
        // dashboard completion record of a legitimately active call sharing the same IDs.
        if !completed {
            return ControlResponse::Error(ControlErrorPayload {
                code: "MCP_TOOL_CALL_NOT_FOUND".to_string(),
                message: format!(
                    "no active tool call '{}' found for MCP session '{}'",
                    request.tool_call_id, request.mcp_session_id
                ),
            });
        }

        if let Some(dashboard) = self.dashboard.as_ref() {
            let status = match request.status {
                McpToolCallCompletionStatus::Success => "success",
                McpToolCallCompletionStatus::Error => "error",
                McpToolCallCompletionStatus::Cancelled => "cancelled",
            };
            if let Err(err) = dashboard.set_mcp_tool_call_completion(
                request.mcp_session_id.as_str(),
                request.tool_call_id.as_str(),
                status,
                request.error_message.as_deref(),
            ) {
                warn!(error = %err, "failed to persist MCP tool completion");
            }
        }

        ControlResponse::CompleteMcpToolCall(CompleteMcpToolCallResponse { completed })
    }

    pub async fn serve(self) -> Result<(), DaemonError> {
        let daemon = Arc::new(self);

        if let Some(dashboard) = daemon.dashboard.as_ref()
            && let Err(err) =
                dashboard::spawn_dashboard_server(Arc::clone(&daemon), Arc::clone(dashboard)).await
        {
            let message = err.to_string();
            let mut status = daemon.dashboard_status.write();
            status.ready = false;
            status.error = Some(message.clone());
            if daemon.config.dashboard.required {
                return Err(DaemonError::Dashboard(message));
            }
            warn!(
                error = %err,
                "dashboard server failed to start; continuing without dashboard"
            );
        }

        if daemon.config.url_gateway.enabled
            && let Err(err) = url_gateway::spawn_url_gateway(Arc::clone(&daemon)).await
        {
            let mut status = daemon.url_gateway_status_snapshot();
            status.ready = false;
            status.error = Some(err.to_string());
            daemon.set_url_gateway_status(status);
            if daemon.config.url_gateway.required {
                return Err(DaemonError::Config(format!(
                    "url gateway startup failed: {err}"
                )));
            }
            warn!(
                error = %err,
                "url gateway startup failed; continuing with gateway disabled"
            );
        }

        #[cfg(unix)]
        let listener = {
            let socket_path = Path::new(&daemon.config.socket_path);
            if let Some(parent) = socket_path.parent() {
                fs::create_dir_all(parent).map_err(DaemonError::Io)?;
            }
            if socket_path.exists() {
                fs::remove_file(socket_path).map_err(DaemonError::Io)?;
            }

            let listener = UnixListener::bind(socket_path).map_err(DaemonError::Io)?;
            if let Some(gid) = optional_group_gid("mercury") {
                match CString::new(socket_path.as_os_str().as_bytes()) {
                    Ok(raw_path) => {
                        if unsafe { libc::chown(raw_path.as_ptr(), u32::MAX, gid) } != 0 {
                            let err = std::io::Error::last_os_error();
                            warn!(path = %socket_path.display(), gid, error = %err, "failed to chown daemon socket group");
                        }
                    }
                    Err(_) => {
                        warn!(path = %socket_path.display(), "failed to chown daemon socket group because the path contains interior NUL bytes");
                    }
                }
            }
            fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))
                .map_err(DaemonError::Io)?;

            // H2: write a pidfile alongside the socket so mercury-run can narrow
            // PR_SET_PTRACER to the daemon PID rather than using PR_SET_PTRACER_ANY.
            let pid_path = socket_path
                .parent()
                .unwrap_or(Path::new("/run/mercury"))
                .join("mercuryd.pid");
            if let Err(err) = fs::write(&pid_path, format!("{}\n", std::process::id())) {
                warn!(path = %pid_path.display(), error = %err, "failed to write daemon pidfile");
            }
            listener
        };

        let (high_priority_tx, high_priority_rx) = mpsc::unbounded_channel::<AuditEvent>();
        let (low_priority_tx, low_priority_rx) =
            mpsc::channel::<AuditEvent>(INGEST_LOW_QUEUE_CAPACITY);
        spawn_ingest_worker(
            Arc::clone(&daemon.audit),
            daemon.dashboard.clone(),
            Arc::clone(&daemon.ingest_metrics),
            high_priority_rx,
            low_priority_rx,
        );

        {
            let daemon = Arc::clone(&daemon);
            let high_priority_tx = high_priority_tx.clone();
            let low_priority_tx = low_priority_tx.clone();
            tokio::spawn(async move {
                let normal_interval = Duration::from_millis(50);
                let backpressure_interval = Duration::from_millis(10);
                let mut ticker = interval(normal_interval);
                let mut last_loss_report = Instant::now();
                loop {
                    ticker.tick().await;

                    if last_loss_report.elapsed() >= TELEMETRY_LOSS_REPORT_INTERVAL {
                        last_loss_report = Instant::now();
                        daemon.report_telemetry_loss();
                    }

                    // Detect backpressure based on ingest queue depth.
                    let backlog = daemon
                        .ingest_metrics
                        .ingest_backlog_len
                        .load(Ordering::Relaxed);
                    let threshold_high = INGEST_LOW_QUEUE_CAPACITY * 3 / 4; // 75%
                    let threshold_low = INGEST_LOW_QUEUE_CAPACITY / 4; // 25%

                    if backlog > threshold_high
                        && !daemon.backpressure.active.load(Ordering::Relaxed)
                    {
                        daemon.backpressure.active.store(true, Ordering::Relaxed);
                        daemon
                            .backpressure
                            .activations_total
                            .fetch_add(1, Ordering::Relaxed);
                        *daemon.backpressure.activated_at.lock() = Some(Instant::now());
                        warn!(
                            backlog,
                            "backpressure activated: ingest queue is {:.0}% full",
                            backlog as f64 / INGEST_LOW_QUEUE_CAPACITY as f64 * 100.0
                        );
                        // Switch to faster drain interval.
                        ticker = interval(backpressure_interval);
                        ticker.reset();
                    }

                    if backlog < threshold_low && daemon.backpressure.active.load(Ordering::Relaxed)
                    {
                        daemon.backpressure.active.store(false, Ordering::Relaxed);
                        info!(backlog, "backpressure deactivated: ingest queue drained");
                        // Restore normal drain interval.
                        ticker = interval(normal_interval);
                        ticker.reset();
                    }

                    let batch_max = if daemon.backpressure.active.load(Ordering::Relaxed) {
                        KERNEL_DRAIN_BATCH_MAX * 4 // 4096
                    } else {
                        KERNEL_DRAIN_BATCH_MAX // 1024
                    };
                    daemon.drain_kernel_audit_events_adaptive(
                        &high_priority_tx,
                        &low_priority_tx,
                        batch_max,
                    );
                }
            });
        }

        {
            let daemon = Arc::clone(&daemon);
            tokio::spawn(async move {
                let mut ticker = interval(PROCESS_PRUNE_INTERVAL);
                loop {
                    ticker.tick().await;
                    daemon.prune_stale_process_state();
                }
            });
        }

        // Periodic session cleanup — replaces the per-request cleanup_sessions()
        // calls that caused write-lock contention and SQLite pressure.
        if let Some(dashboard) = daemon.dashboard.as_ref() {
            let dashboard = Arc::clone(dashboard);
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(60));
                ticker.tick().await; // discard immediate first tick
                loop {
                    ticker.tick().await;
                    dashboard.cleanup_sessions();
                }
            });
        }

        // Policy sync — periodically fetch policy from a remote URL if configured.
        if let Some(ref sync_config) = daemon.config.policy_sync {
            let worker = Arc::new(PolicySyncWorker::new(
                sync_config.clone(),
                PathBuf::from(&daemon.config.policy_path),
                Arc::clone(&daemon.policy_sync_status),
            ));
            let sync_interval = Duration::from_secs(sync_config.interval_secs);
            let daemon = Arc::clone(&daemon);
            tokio::spawn(async move {
                let mut ticker = interval(sync_interval);
                ticker.tick().await; // discard immediate first tick
                loop {
                    ticker.tick().await;
                    match worker.check_and_update().await {
                        Ok(true) => {
                            info!("policy sync: remote policy changed, reloading");
                            let response =
                                daemon.apply_policy_from_path(&daemon.config.policy_path);
                            if response.success {
                                info!(
                                    version = %response.version,
                                    "policy sync: policy reloaded successfully"
                                );
                            } else {
                                warn!(
                                    errors = ?response.errors,
                                    "policy sync: fetched policy failed to load"
                                );
                                daemon.policy_sync_status.lock().last_error =
                                    Some(response.errors.join("; "));
                            }
                        }
                        Ok(false) => {
                            // No change — nothing to do.
                        }
                        Err(err) => {
                            warn!(error = %err, "policy sync: check failed");
                            daemon.policy_sync_status.lock().last_error = Some(err.to_string());
                        }
                    }
                }
            });
            info!("policy sync worker started");
        }

        info!(socket = %daemon.config.socket_path, "mercury daemon listening");

        #[cfg(unix)]
        {
            let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .map_err(DaemonError::Io)?;
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(DaemonError::Io)?;
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result.map_err(DaemonError::Io)?;
                        let daemon = Arc::clone(&daemon);
                        tokio::spawn(async move {
                            if let Err(err) = daemon.handle_stream(stream).await {
                                error!(error = %err, "control stream error");
                            }
                        });
                    }
                    _ = sighup.recv() => {
                        info!("SIGHUP received; reloading TLS certificate and reopening audit log");
                        if let Some(dashboard) = daemon.dashboard.as_ref() {
                            dashboard.reload_tls_cert().await;
                        }
                        if let Err(err) = daemon.audit.reopen() {
                            error!(error = %err, "failed to reopen audit log after SIGHUP");
                        } else {
                            info!(path = %daemon.config.audit_jsonl_path, "audit log file descriptor reopened");
                        }
                    }
                    _ = sigterm.recv() => {
                        daemon.record_audit_event(AuditEvent::system(
                            "daemon",
                            SystemResource::new("daemon_stop")
                                .attr("signal", "SIGTERM")
                                .attr("pid", std::process::id()),
                            daemon.policy_version(),
                            "Mercury daemon stopping",
                        ));
                        daemon.audit.sync().map_err(DaemonError::Audit)?;
                        break;
                    }
                }
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    async fn handle_stream(self: Arc<Self>, stream: UnixStream) -> Result<(), DaemonError> {
        let caller_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
        let (read_half, write_half) = stream.into_split();
        self.handle_pipe_stream(read_half, write_half, caller_uid)
            .await
    }

    /// Process a single request/response exchange on any AsyncRead+AsyncWrite pair.
    async fn handle_pipe_stream<R, W>(
        self: Arc<Self>,
        read_half: R,
        mut write_half: W,
        caller_uid: u32,
    ) -> Result<(), DaemonError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(read_half);
        let mut line = Vec::new();
        let bytes = reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(DaemonError::Io)?;

        if bytes == 0 {
            return Ok(());
        }

        let request = decode_request(&line).map_err(DaemonError::ControlApi)?;
        // WaitMcpApproval blocks on a parking_lot condvar for up to MCP_APPROVAL_TTL.
        // Run it on the blocking thread pool so it does not starve the Tokio runtime.
        let response = if matches!(request, ControlRequest::WaitMcpApproval(_)) {
            let daemon = Arc::clone(&self);
            tokio::task::spawn_blocking(move || daemon.handle_request(request, caller_uid))
                .await
                .map_err(|e| {
                    DaemonError::Io(std::io::Error::other(format!(
                        "wait-mcp-approval blocking task panicked: {e}"
                    )))
                })?
        } else {
            self.handle_request(request, caller_uid)
        };
        let encoded = encode_response(&response).map_err(DaemonError::ControlApi)?;
        write_half
            .write_all(&encoded)
            .await
            .map_err(DaemonError::Io)?;
        write_half.flush().await.map_err(DaemonError::Io)?;
        Ok(())
    }

    fn drain_kernel_audit_events_adaptive(
        &self,
        high_priority_tx: &mpsc::UnboundedSender<AuditEvent>,
        low_priority_tx: &mpsc::Sender<AuditEvent>,
        batch_max: usize,
    ) {
        let events = match self.adapter.drain_audit_events_limited(batch_max) {
            Ok(events) => events,
            Err(err) => {
                warn!(error = %err, "failed to drain kernel audit events");
                return;
            }
        };

        for mut event in events {
            if let Some(dropped) = event.events_dropped.filter(|&d| d > 0) {
                warn!(
                    events_dropped = dropped,
                    "kernel ring buffer dropped events since last successful emit"
                );
                self.ingest_metrics
                    .events_dropped_ringbuf_total
                    .fetch_add(dropped, Ordering::Relaxed);
            }
            self.enrich_audit_event_with_mcp_context(&mut event);
            if event.decision == Decision::Deny {
                if high_priority_tx.send(event).is_ok() {
                    self.ingest_metrics
                        .ingest_backlog_len
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.ingest_metrics
                        .events_dropped_queue_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("high-priority ingest channel closed; dropped deny event");
                }
                continue;
            }

            match low_priority_tx.try_send(event) {
                Ok(()) => {
                    self.ingest_metrics
                        .ingest_backlog_len
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.ingest_metrics
                        .events_dropped_queue_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.ingest_metrics
                        .events_dropped_queue_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("low-priority ingest channel closed; dropped allow/observe event");
                }
            }
        }
    }

    fn handle_request(&self, request: ControlRequest, caller_uid: u32) -> ControlResponse {
        match request {
            ControlRequest::RegisterAgent(register) => {
                self.handle_register_agent(register, caller_uid)
            }
            ControlRequest::RegisterMcpServer(register) => {
                self.handle_register_mcp_server(register, caller_uid)
            }
            ControlRequest::PolicyReload(reload) => {
                // C1: non-root callers on the socket may only reload the daemon's
                // configured policy_path, not an arbitrary path.  Root (uid 0) is
                // trusted unconditionally so that system scripts can still trigger
                // an in-place reload.
                if caller_uid != 0 {
                    let requested = fs::canonicalize(&reload.path).ok();
                    let configured = fs::canonicalize(&self.config.policy_path).ok();
                    if requested.is_none() || requested != configured {
                        return ControlResponse::Error(ControlErrorPayload {
                            code: "UNAUTHORIZED".to_string(),
                            message:
                                "PolicyReload path must match the daemon configured policy_path"
                                    .to_string(),
                        });
                    }
                }
                ControlResponse::PolicyReload(self.apply_policy_from_path(&reload.path))
            }
            ControlRequest::Health => {
                #[cfg(all(feature = "linux", unix))]
                {
                    let status = self.adapter.status();
                    let runtime = self.adapter.runtime_health();
                    let capabilities = self.adapter.check_capabilities();
                    let dashboard_status = self.dashboard_status_snapshot();
                    let gateway_status = self.url_gateway_status_snapshot();
                    let ingest = self.ingest_metrics_snapshot();
                    let policy_sync_status = self.policy_sync_status.lock().clone();
                    ControlResponse::Health(HealthResponse {
                        daemon_up: true,
                        policy_version: self.policy_version(),
                        backend_mode: backend_mode_string(runtime.backend_mode),
                        kernel_ready: runtime.kernel_ready,
                        kernel_program_version: runtime.kernel_program_version,
                        auto_enroll_active_rules: runtime.auto_enroll_active_rules,
                        unmatched_mode: unmatched_mode_string(runtime.unmatched_mode),
                        hook_status: map_hook_status(status),
                        apparmor_enabled: capabilities.apparmor_enabled,
                        apparmor_parser_present: capabilities.apparmor_parser_present,
                        dashboard_enabled: dashboard_status.dashboard_enabled,
                        dashboard_ready: dashboard_status.dashboard_ready,
                        dashboard_url: dashboard_status.dashboard_url,
                        dashboard_error: dashboard_status.dashboard_error,
                        url_gateway_enabled: gateway_status.enabled,
                        url_gateway_ready: gateway_status.ready,
                        url_gateway_http_proxy: gateway_status.http_proxy,
                        url_gateway_https_proxy: gateway_status.https_proxy,
                        url_gateway_error: gateway_status.error,
                        events_ingested_total: ingest.events_ingested_total,
                        events_dropped_queue_total: ingest.events_dropped_queue_total,
                        unenrolled_events_suppressed_total: runtime
                            .unenrolled_events_suppressed_total,
                        events_dropped_ringbuf_total: dashboard_status
                            .events_dropped_ringbuf_total
                            .max(ingest.events_dropped_ringbuf_total),
                        ingest_backlog_len: ingest.ingest_backlog_len,
                        enrollment_sync_error: runtime.enrollment_sync_error,
                        dashboard_schema_version: dashboard_status.dashboard_schema_version,
                        policy_versions_total: dashboard_status.policy_versions_total,
                        pending_mcp_approvals: dashboard_status.pending_mcp_approvals,
                        active_dashboard_sessions: dashboard_status.active_dashboard_sessions,
                        active_sse_clients: dashboard_status.active_sse_clients,
                        active_mcp_sessions: dashboard_status.active_mcp_sessions,
                        dashboard_sqlite_bytes: dashboard_status.dashboard_sqlite_bytes,
                        coverage: dashboard_status.coverage,
                        kernel_limits: Some(KernelLimitsInfo {
                            max_rules_per_class: self.config.kernel_limits.max_rules_per_class,
                            max_profiles: self.config.kernel_limits.max_profiles,
                            max_workspace_roots: self.config.kernel_limits.max_workspace_roots,
                        }),
                        policy_sync_enabled: policy_sync_status.enabled,
                        policy_sync_last_check: policy_sync_status.last_check,
                        policy_sync_last_error: policy_sync_status.last_error,
                        backpressure_active: self.backpressure.active.load(Ordering::Relaxed),
                        backpressure_activations_total: self
                            .backpressure
                            .activations_total
                            .load(Ordering::Relaxed),
                        // Filled from dashboard::telemetry_counters().
                        kernel_events_rate_limited_total: dashboard_status
                            .kernel_events_rate_limited_total,
                        kernel_deny_events_dropped_total: dashboard_status
                            .kernel_deny_events_dropped_total,
                        audit_write_failures_total: dashboard_status.audit_write_failures_total,
                        audit_mirror_failures_total: dashboard_status.audit_mirror_failures_total,
                        apparmor_records_lost_total: dashboard_status.apparmor_records_lost_total,
                        policy_reload_failures_total: dashboard_status.policy_reload_failures_total,
                        telemetry_degraded_reasons: dashboard_status.telemetry_degraded_reasons,
                    })
                }
            }
            ControlRequest::TestDecision(test) => {
                let decision =
                    self.evaluate_action_simulated(test.profile.as_str(), &test.action, caller_uid);
                ControlResponse::TestDecision(decision)
            }
            ControlRequest::AuthorizeMcpToolCall(request) => {
                self.handle_authorize_mcp_tool_call(request, caller_uid)
            }
            ControlRequest::AuthorizeMcpResourceRead(request) => {
                self.handle_authorize_mcp_resource_read(request, caller_uid)
            }
            ControlRequest::WaitMcpApproval(request) => {
                self.handle_wait_mcp_approval(request, caller_uid)
            }
            ControlRequest::CompleteMcpToolCall(request) => {
                self.handle_complete_mcp_tool_call(request, caller_uid)
            }
            ControlRequest::GetCaCert => self.handle_get_ca_cert(),
        }
    }

    fn handle_get_ca_cert(&self) -> ControlResponse {
        let ca_cert_path = &self.config.url_gateway.ca_cert_file;
        let pem = match fs::read_to_string(ca_cert_path) {
            Ok(pem) => pem,
            Err(e) => {
                return ControlResponse::Error(ControlErrorPayload {
                    code: "CA_CERT_UNAVAILABLE".to_string(),
                    message: format!("failed to read CA cert from {ca_cert_path}: {e}"),
                });
            }
        };

        // SHA-256 fingerprint of the PEM content for identification
        let fingerprint_sha256 = hex::encode(<Sha256 as Digest>::digest(pem.as_bytes()));

        ControlResponse::CaCert(CaCertResponse {
            pem,
            fingerprint_sha256,
            not_after: "see certificate".to_string(),
        })
    }
}

#[cfg(feature = "linux")]
fn evaluate_and_audit(
    engine: &Arc<RwLock<PolicyEngine>>,
    audit: &Arc<AuditLogger>,
    dashboard: Option<&Arc<DashboardService>>,
    profile: &str,
    action: &Action,
    mcp_context: Option<McpAuditContext>,
    context: core_types::EventContext,
) -> DecisionResult {
    let (result, policy_version) = {
        let guard = engine.read();
        let result = guard.evaluate(profile, action);
        let policy_version = guard.policy_version().unwrap_or("unloaded").to_string();
        (result, policy_version)
    };

    let audit_event = AuditEvent {
        timestamp: Utc::now(),
        agent_id: action.context.agent_id.clone(),
        pid: Some(action.context.pid),
        ppid: Some(action.context.ppid),
        uid: Some(action.context.uid),
        action_type: action.action_type,
        decision: result.decision,
        reason: result.reason,
        rule_id: result.rule_id.clone(),
        resource: action.resource.clone(),
        profile: profile.to_string(),
        policy_version,
        message: if context.simulated == Some(true) {
            format!(
                "simulated decision={:?} reason={}",
                result.decision, result.reason
            )
        } else {
            format!("decision={:?} reason={}", result.decision, result.reason)
        },
        mcp: mcp_context,
        kernel_seq: None,
        events_dropped: None,
        model: None,
        context,
    };

    write_userspace_audit(audit, dashboard, audit_event);
    result
}

/// Assigns the record id shared by the JSONL line, the journald mirror, the
/// dashboard copy and alerts, so one record can be followed across sinks.
fn stamp_event_id(event: &mut AuditEvent) {
    if event.context.event_id.is_none() {
        event.context.event_id = Some(Uuid::new_v4().to_string());
    }
}

fn write_userspace_audit(
    audit: &Arc<AuditLogger>,
    dashboard: Option<&Arc<DashboardService>>,
    audit_event: AuditEvent,
) {
    let mut audit_event = audit_event;
    stamp_event_id(&mut audit_event);
    let audit_event = &audit_event;
    if let Err(err) = audit.log(audit_event) {
        error!(error = %err, "failed to write audit event");
    }
    alerts::offer_global(audit_event);
    if let Some(dashboard) = dashboard {
        if let Err(err) = dashboard.ingest_event(audit_event) {
            dashboard.set_error(err.to_string());
            warn!(error = %err, "dashboard ingest failed for userspace audit event");
        } else {
            dashboard.set_ready();
        }
    }
}

#[cfg(feature = "linux")]
fn spawn_ingest_worker(
    audit: Arc<AuditLogger>,
    dashboard: Option<Arc<DashboardService>>,
    metrics: Arc<IngestMetrics>,
    mut high_priority_rx: mpsc::UnboundedReceiver<AuditEvent>,
    mut low_priority_rx: mpsc::Receiver<AuditEvent>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                Some(event) = high_priority_rx.recv() => {
                    let mut batch = vec![event];
                    extend_ingest_batch(&mut high_priority_rx, &mut low_priority_rx, &mut batch);
                    consume_ingest_batch(&audit, dashboard.as_ref(), &metrics, batch);
                }
                Some(event) = low_priority_rx.recv() => {
                    let mut batch = vec![event];
                    extend_ingest_batch(&mut high_priority_rx, &mut low_priority_rx, &mut batch);
                    consume_ingest_batch(&audit, dashboard.as_ref(), &metrics, batch);
                }
                else => break,
            }
        }
    });
}

#[cfg(feature = "linux")]
fn extend_ingest_batch(
    high_priority_rx: &mut mpsc::UnboundedReceiver<AuditEvent>,
    low_priority_rx: &mut mpsc::Receiver<AuditEvent>,
    batch: &mut Vec<AuditEvent>,
) {
    // Interleave high- and low-priority events so that allow/observe events
    // are never starved by a continuous stream of deny events.
    loop {
        if batch.len() >= INGEST_DASHBOARD_BATCH_MAX {
            break;
        }
        let got_high = if let Ok(event) = high_priority_rx.try_recv() {
            batch.push(event);
            true
        } else {
            false
        };
        if batch.len() < INGEST_DASHBOARD_BATCH_MAX {
            if let Ok(event) = low_priority_rx.try_recv() {
                batch.push(event);
                if !got_high {
                    // Both channels were empty before this; keep draining low.
                    continue;
                }
            } else if !got_high {
                break;
            }
        } else if !got_high {
            break;
        }
    }
}

#[cfg(feature = "linux")]
fn consume_ingest_batch(
    audit: &AuditLogger,
    dashboard: Option<&Arc<DashboardService>>,
    metrics: &IngestMetrics,
    events: Vec<AuditEvent>,
) {
    let batch_len = events.len();
    if batch_len == 0 {
        return;
    }

    metrics
        .ingest_backlog_len
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(batch_len))
        })
        .ok();

    let mut events = events;
    for event in &mut events {
        stamp_event_id(event);
    }
    for event in &events {
        if let Err(err) = audit.log(event) {
            error!(error = %err, "failed to write kernel audit event");
        }
        alerts::offer_global(event);
    }

    if let Some(dashboard) = dashboard {
        if let Err(err) = dashboard.ingest_events_batch(events.as_slice()) {
            dashboard.set_error(err.to_string());
            warn!(error = %err, "dashboard ingest failed for kernel event");
        } else {
            dashboard.set_ready();
        }
    }

    metrics
        .events_ingested_total
        .fetch_add(batch_len as u64, Ordering::Relaxed);
}

#[cfg(all(feature = "linux", unix))]
fn map_hook_status(status: AdapterHookStatus) -> HookStatus {
    HookStatus {
        exec_hook: hook_backend_name(status.exec_hook).to_string(),
        network_hook: hook_backend_name(status.network_hook).to_string(),
        filesystem_hook: hook_backend_name(status.filesystem_hook).to_string(),
    }
}

#[cfg(all(feature = "linux", unix))]
pub(crate) fn hook_backend_name(backend: linux_adapter::HookBackend) -> &'static str {
    match backend {
        linux_adapter::HookBackend::EbpfLsm => "EbpfLsm",
        linux_adapter::HookBackend::EbpfCgroup => "EbpfCgroup",
        linux_adapter::HookBackend::AppArmor => "AppArmor",
        linux_adapter::HookBackend::ObserveOnly => "ObserveOnly",
        linux_adapter::HookBackend::Unavailable => "Unavailable",
    }
}

#[cfg(all(feature = "linux", unix))]
fn backend_mode_string(mode: BackendMode) -> String {
    match mode {
        BackendMode::KernelStrict => "kernel_strict".to_string(),
        BackendMode::LinuxCompat => "linux_compat".to_string(),
    }
}

#[cfg(all(feature = "linux", unix))]
fn filesystem_backend_string(mode: FilesystemBackend) -> &'static str {
    match mode {
        FilesystemBackend::EbpfLsm => "ebpf_lsm",
        FilesystemBackend::AppArmor => "apparmor",
    }
}

#[cfg(all(feature = "linux", unix))]
fn unmatched_mode_string(mode: UnmatchedHostMode) -> String {
    match mode {
        UnmatchedHostMode::Observe => "observe".to_string(),
    }
}

#[cfg(all(feature = "linux", unix))]
pub(crate) fn build_coverage_status(
    backend_mode: BackendMode,
    hook_status: &AdapterHookStatus,
    gateway_status: &UrlGatewayStatus,
) -> Vec<CoverageStatus> {
    let mut coverage = Vec::new();

    let file_backend = hook_backend_string(hook_status.filesystem_hook.clone());
    for action in [
        "FILE_READ",
        "FILE_WRITE",
        "FILE_DELETE",
        "FILE_MMAP",
        "FILE_RENAME",
        "FILE_LINK",
        "FILE_SYMLINK",
        "FILE_MKDIR",
        "FILE_RMDIR",
        "FILE_CREATE",
        "FILE_CHMOD",
        "FILE_CHOWN",
        "FILE_TRUNCATE",
    ] {
        coverage.push(CoverageStatus {
            action_type: action.to_string(),
            action_class: "file".to_string(),
            backend: file_backend.to_string(),
            status: coverage_from_backend(hook_status.filesystem_hook.clone()).to_string(),
        });
    }

    coverage.push(CoverageStatus {
        action_type: "PROC_EXEC".to_string(),
        action_class: "process".to_string(),
        backend: hook_backend_string(hook_status.exec_hook.clone()).to_string(),
        status: coverage_from_backend(hook_status.exec_hook.clone()).to_string(),
    });
    for action in ["PROC_PTRACE", "PROC_KILL"] {
        coverage.push(CoverageStatus {
            action_type: action.to_string(),
            action_class: "process".to_string(),
            backend: match backend_mode {
                BackendMode::KernelStrict => "ebpf_lsm".to_string(),
                BackendMode::LinuxCompat => "apparmor".to_string(),
            },
            status: match backend_mode {
                BackendMode::KernelStrict => "enforced".to_string(),
                BackendMode::LinuxCompat => "enforced".to_string(),
            },
        });
    }
    coverage.push(CoverageStatus {
        action_type: "PROC_CAPABLE".to_string(),
        action_class: "process".to_string(),
        backend: match backend_mode {
            BackendMode::KernelStrict => "ebpf_lsm".to_string(),
            BackendMode::LinuxCompat => "apparmor".to_string(),
        },
        status: match backend_mode {
            BackendMode::KernelStrict => "observe_only".to_string(),
            BackendMode::LinuxCompat => "enforced".to_string(),
        },
    });

    for action in ["NET_CONNECT", "NET_SENDMSG", "NET_BIND", "NET_CREATE"] {
        coverage.push(CoverageStatus {
            action_type: action.to_string(),
            action_class: "network".to_string(),
            backend: hook_backend_string(hook_status.network_hook.clone()).to_string(),
            status: match backend_mode {
                BackendMode::KernelStrict => {
                    coverage_from_backend(hook_status.network_hook.clone()).to_string()
                }
                BackendMode::LinuxCompat => "enforced".to_string(),
            },
        });
    }
    for action in ["NET_LISTEN", "NET_ACCEPT"] {
        coverage.push(CoverageStatus {
            action_type: action.to_string(),
            action_class: "network".to_string(),
            backend: hook_backend_string(hook_status.network_hook.clone()).to_string(),
            status: match backend_mode {
                BackendMode::KernelStrict => "observe_only".to_string(),
                BackendMode::LinuxCompat => "enforced".to_string(),
            },
        });
    }
    coverage.push(CoverageStatus {
        action_type: "URL_REQUEST".to_string(),
        action_class: "network".to_string(),
        backend: "userspace_gateway".to_string(),
        status: if gateway_status.enabled && gateway_status.ready {
            "enforced".to_string()
        } else {
            "unavailable".to_string()
        },
    });
    for action in ["MCP_TOOL_CALL", "MCP_RESOURCE_READ"] {
        coverage.push(CoverageStatus {
            action_type: action.to_string(),
            action_class: "mcp".to_string(),
            backend: "daemon".to_string(),
            status: "enforced".to_string(),
        });
    }

    coverage
}

#[cfg(all(feature = "linux", unix))]
fn coverage_from_backend(backend: HookBackend) -> &'static str {
    match backend {
        HookBackend::EbpfLsm | HookBackend::EbpfCgroup | HookBackend::AppArmor => "enforced",
        HookBackend::ObserveOnly => "observe_only",
        HookBackend::Unavailable => "unavailable",
    }
}

#[cfg(all(feature = "linux", unix))]
fn hook_backend_string(backend: HookBackend) -> &'static str {
    match backend {
        HookBackend::EbpfLsm => "ebpf_lsm",
        HookBackend::EbpfCgroup => "ebpf_cgroup",
        HookBackend::AppArmor => "apparmor",
        HookBackend::ObserveOnly => "observe_only",
        HookBackend::Unavailable => "unavailable",
    }
}

pub fn init_tracing(filter: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .json()
        .try_init();
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("config parse: {0}")]
    ConfigDeserialize(serde_yaml::Error),
    #[error("control api: {0}")]
    ControlApi(control_api::ControlApiError),
    #[error("policy load: {0}")]
    PolicyLoad(String),
    #[error("adapter: {0}")]
    #[cfg(all(feature = "linux", unix))]
    Adapter(linux_adapter::AdapterError),
    #[error("adapter: {0}")]
    #[cfg(not(all(feature = "linux", unix)))]
    Adapter(platform_traits::AdapterError),
    #[error("audit: {0}")]
    Audit(audit::AuditError),
    #[error("dashboard: {0}")]
    Dashboard(String),
    #[error("config: {0}")]
    Config(String),
    #[error("internal: {0}")]
    Internal(anyhow::Error),
}

#[cfg(all(feature = "linux", unix))]
pub async fn run_from_config_path(path: impl AsRef<Path>) -> Result<(), DaemonError> {
    let config_path = path.as_ref().to_path_buf();
    let config = load_config(&config_path)?;
    init_tracing(config.log_level.as_str());

    let daemon = GuardDaemon::new(config.clone())?;
    daemon.initialize()?;
    info!(
        api_version = API_VERSION,
        config_path = %config_path.display(),
        backend_mode = %backend_mode_string(config.backend_mode),
        filesystem_backend = %filesystem_backend_string(config.filesystem_backend),
        policy_version = daemon.policy_version(),
        "ai guard daemon initialized"
    );

    daemon.serve().await
}

#[cfg(not(feature = "linux"))]
pub async fn run_from_config_path(_path: impl AsRef<Path>) -> Result<(), DaemonError> {
    Err(DaemonError::Config(
        "daemon requires the 'linux' feature".into(),
    ))
}

#[cfg(all(test, feature = "linux", unix))]
mod tests {
    use std::fs;
    use std::path::Path;

    use control_api::{
        AuthorizeMcpToolCallRequest, CompleteMcpToolCallRequest, McpToolCallAuthorizationDecision,
        McpToolCallCompletionStatus, PolicyReloadRequest, RegisterMcpServerRequest,
        TestDecisionRequest,
    };
    use tempfile::tempdir;

    use super::*;

    const VALID_POLICY: &str = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    workspace_roots:
      - /workspace
"#;

    const INVALID_POLICY: &str = r#"
version: v1
profiles:
  default:
    network_allow:
      - id: n1
"#;

    const STRICT_POLICY: &str = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    workspace_roots:
      - /workspace
    file_deny:
      - id: deny_secret
        pattern: /workspace/secret/**
"#;

    fn test_daemon(root: &Path) -> GuardDaemon {
        let config = DaemonConfig {
            socket_path: root.join("mercuryd.sock").to_string_lossy().to_string(),
            policy_path: root.join("policy.yaml").to_string_lossy().to_string(),
            audit_jsonl_path: root.join("audit.jsonl").to_string_lossy().to_string(),
            audit_integrity: false,
            enrollment_state_path: root.join("enrollments.json").to_string_lossy().to_string(),
            mirror_to_journald: false,
            cgroup_base: root.join("cgroup").to_string_lossy().to_string(),
            filesystem_backend: FilesystemBackend::EbpfLsm,
            kernel: KernelRuntimeConfig {
                bpffs_path: root.join("bpffs").to_string_lossy().to_string(),
                cgroup_root: root.join("cgroup-root").to_string_lossy().to_string(),
                ..KernelRuntimeConfig::default()
            },
            dashboard: DashboardConfig {
                enabled: false,
                ..DashboardConfig::default()
            },
            url_gateway: UrlGatewayConfig {
                enabled: false,
                required: false,
                ..UrlGatewayConfig::default()
            },
            ..DaemonConfig::default()
        };

        GuardDaemon::new(config).expect("daemon")
    }

    fn audit_records(root: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(root.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn system_records<'a>(
        records: &'a [serde_json::Value],
        name: &str,
    ) -> Vec<&'a serde_json::Value> {
        records
            .iter()
            .filter(|record| record["resource"]["event"] == name)
            .collect()
    }

    #[test]
    fn restore_reenrolls_survivors_and_reports_downtime_gap() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let pid = std::process::id();
        let proc_start_time = kernel_runtime::read_proc_start_time(pid).expect("start time");
        let cgroup = tmp.path().join("cgroup").join("ai-live");
        fs::create_dir_all(&cgroup).expect("cgroup dir");
        fs::write(cgroup.join("cgroup.procs"), format!("{pid}\n")).expect("procs");

        let registration = |agent_pid: u32, start: u64, cgroup_id: &str| AgentRegistration {
            agent_id: Uuid::new_v4(),
            profile: "default".to_string(),
            pid: agent_pid,
            proc_start_time: start,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            cgroup_id: cgroup_id.to_string(),
            cmdline: vec!["agent".to_string()],
            cwd: "/work".to_string(),
            mcp_session_id: None,
            server_id: None,
            client_name: None,
            parent_agent_id: None,
            resolved_exec_path: None,
        };
        let live = registration(pid, proc_start_time, "ai-live");
        let gone = registration(u32::MAX - 7, 1, "ai-gone");
        let state = PersistedEnrollmentState {
            heartbeat: Some(Utc::now() - chrono::Duration::seconds(90)),
            registrations: vec![live.clone(), gone],
        };
        write_json_atomically(
            Path::new(daemon.config.enrollment_state_path.as_str()),
            &state,
        )
        .expect("state");

        daemon.restore_enrollments();

        let records = audit_records(tmp.path());
        let restored = system_records(&records, "enrollment_restored");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0]["agent_id"], live.agent_id.to_string());
        assert_eq!(restored[0]["resource"]["attributes"]["root_alive"], true);
        assert_eq!(system_records(&records, "agent_unenrolled").len(), 1);
        let gap = system_records(&records, "telemetry_loss");
        assert_eq!(gap.len(), 1);
        assert_eq!(gap[0]["resource"]["attributes"]["cause"], "daemon_downtime");
        assert_eq!(gap[0]["resource"]["attributes"]["agents_restored"], 1);
        assert_eq!(gap[0]["decision"], "DENY");
        assert!(gap[0]["resource"]["attributes"]["gap_start"].is_string());
        assert!(daemon.registrations.read().contains_key(&pid));

        let persisted: PersistedEnrollmentState = serde_json::from_slice(
            &fs::read(daemon.config.enrollment_state_path.as_str()).expect("state"),
        )
        .expect("parse state");
        assert_eq!(
            persisted.registrations.len(),
            1,
            "exited agents are dropped"
        );
        let mode = fs::metadata(daemon.config.enrollment_state_path.as_str())
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn simulated_decisions_are_marked_and_attributed_to_the_caller() {
        let tmp = tempdir().expect("tempdir");
        fs::write(
            tmp.path().join("policy.yaml"),
            "version: v1\ndefaults:\n  decision: deny\nprofiles:\n  default: {}\n",
        )
        .expect("policy");
        let daemon = test_daemon(tmp.path());
        assert!(
            daemon
                .apply_policy_from_path(tmp.path().join("policy.yaml").to_string_lossy().as_ref())
                .success
        );
        let action = Action {
            action_type: ActionType::FileRead,
            context: ActionContext {
                timestamp: Utc::now(),
                agent_id: "forged-agent".to_string(),
                pid: 4242,
                ppid: 1,
                uid: 0,
                profile: "default".to_string(),
            },
            resource: Resource::File(core_types::FileResource {
                path: "/etc/shadow".to_string(),
                resolved_path: None,
                op: core_types::FileOp::Read,
                source_path: None,
            }),
        };
        daemon.evaluate_action_simulated("default", &action, 1000);

        let records = audit_records(tmp.path());
        let record = records
            .iter()
            .find(|record| record["action_type"] == "FILE_READ")
            .expect("simulated record");
        assert_eq!(record["simulated"], true);
        assert_eq!(record["actor"], "uid:1000");
        assert_eq!(record["source"], "control-api");
        assert!(record["message"].as_str().unwrap().starts_with("simulated"));
    }

    #[test]
    fn recorded_events_carry_a_stable_event_id() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        daemon.record_audit_event(AuditEvent::system(
            "daemon",
            SystemResource::new("daemon_start"),
            "v1",
            "start",
        ));
        let records = audit_records(tmp.path());
        let record = system_records(&records, "daemon_start")[0];
        let id = record["event_id"].as_str().expect("event id");
        assert!(Uuid::parse_str(id).is_ok());
    }

    #[test]
    fn sample_config_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/config.yaml");
        let config = load_config(&path).expect("samples/config.yaml must load");
        assert_eq!(
            config.enrollment_state_path,
            "/var/lib/mercury/enrollments.json"
        );
        assert!(config.alerts.webhook_url.is_none());
        assert!(config.audit_integrity);
    }

    #[test]
    fn loss_counter_deltas() {
        let earlier = LossCounters {
            kernel_ringbuf_dropped: 5,
            kernel_deny_dropped: 1,
            kernel_rate_limited: 10,
            ingest_queue_dropped: 0,
        };
        assert!(earlier.since(earlier).is_zero());
        let later = LossCounters {
            kernel_deny_dropped: 3,
            ..earlier
        };
        let delta = later.since(earlier);
        assert_eq!(delta.kernel_deny_dropped, 2);
        assert_eq!(delta.kernel_ringbuf_dropped, 0);
        assert!(!delta.is_zero());
    }

    #[test]
    fn reload_keeps_last_good_policy_on_failure() {
        let tmp = tempdir().expect("tempdir");
        let policy_good = tmp.path().join("good.yaml");
        let policy_bad = tmp.path().join("bad.yaml");

        fs::write(&policy_good, VALID_POLICY).expect("write good policy");
        fs::write(&policy_bad, INVALID_POLICY).expect("write bad policy");

        let config = DaemonConfig {
            socket_path: tmp
                .path()
                .join("mercuryd.sock")
                .to_string_lossy()
                .to_string(),
            policy_path: policy_good.to_string_lossy().to_string(),
            audit_jsonl_path: tmp.path().join("audit.jsonl").to_string_lossy().to_string(),
            audit_integrity: false,
            enrollment_state_path: tmp
                .path()
                .join("enrollments.json")
                .to_string_lossy()
                .to_string(),
            mirror_to_journald: false,
            cgroup_base: tmp.path().join("cgroup").to_string_lossy().to_string(),
            kernel: KernelRuntimeConfig {
                bpffs_path: tmp.path().join("bpffs").to_string_lossy().to_string(),
                cgroup_root: tmp.path().join("cgroup-root").to_string_lossy().to_string(),
                ..KernelRuntimeConfig::default()
            },
            ..DaemonConfig::default()
        };

        let daemon = GuardDaemon::new(config).expect("daemon");

        let first = daemon.apply_policy_from_path(policy_good.to_string_lossy().as_ref());
        assert!(first.success);
        assert_eq!(daemon.policy_version(), "v1");

        let second = daemon.apply_policy_from_path(policy_bad.to_string_lossy().as_ref());
        assert!(!second.success);
        assert_eq!(daemon.policy_version(), "v1");
        assert_eq!(
            daemon.policy_reload_failures_total.load(Ordering::Relaxed),
            1
        );
        let audit = fs::read_to_string(tmp.path().join("audit.jsonl")).expect("audit log");
        assert!(audit.contains("policy_reload"));
        assert!(audit.contains("failed"));
    }

    #[test]
    fn control_flow_register_reload_and_test_decision() {
        let tmp = tempdir().expect("tempdir");
        let policy_base = tmp.path().join("policy-base.yaml");
        let policy_strict = tmp.path().join("policy-strict.yaml");

        fs::write(&policy_base, VALID_POLICY).expect("write base policy");
        fs::write(&policy_strict, STRICT_POLICY).expect("write strict policy");

        let config = DaemonConfig {
            socket_path: tmp
                .path()
                .join("mercuryd.sock")
                .to_string_lossy()
                .to_string(),
            policy_path: policy_base.to_string_lossy().to_string(),
            audit_jsonl_path: tmp.path().join("audit.jsonl").to_string_lossy().to_string(),
            audit_integrity: false,
            enrollment_state_path: tmp
                .path()
                .join("enrollments.json")
                .to_string_lossy()
                .to_string(),
            mirror_to_journald: false,
            cgroup_base: tmp.path().join("cgroup").to_string_lossy().to_string(),
            filesystem_backend: FilesystemBackend::EbpfLsm,
            kernel: KernelRuntimeConfig {
                bpffs_path: tmp.path().join("bpffs").to_string_lossy().to_string(),
                cgroup_root: tmp.path().join("cgroup-root").to_string_lossy().to_string(),
                ..KernelRuntimeConfig::default()
            },
            dashboard: DashboardConfig {
                enabled: false,
                ..DashboardConfig::default()
            },
            url_gateway: UrlGatewayConfig {
                enabled: false,
                required: false,
                ..UrlGatewayConfig::default()
            },
            ..DaemonConfig::default()
        };

        let daemon = GuardDaemon::new(config).expect("daemon");

        let reload = daemon.handle_request(
            ControlRequest::PolicyReload(PolicyReloadRequest {
                path: policy_base.to_string_lossy().to_string(),
            }),
            0,
        );
        match reload {
            ControlResponse::PolicyReload(payload) => assert!(payload.success),
            other => panic!("unexpected reload response: {other:?}"),
        }

        let register = daemon.handle_request(
            ControlRequest::RegisterAgent(control_api::RegisterAgentRequest {
                pid: std::process::id(),
                ppid: 1,
                uid: 1000,
                gid: 1000,
                profile: "default".to_string(),
                cmdline: vec!["/usr/bin/env".to_string()],
                cwd: "/tmp".to_string(),
            }),
            0,
        );
        match register {
            ControlResponse::RegisterAgent(payload) => {
                assert!(payload.cgroup_id.starts_with("ai-"));
                assert!(payload.url_proxy_http.is_none());
                assert!(payload.url_proxy_https.is_none());
                assert!(payload.url_proxy_auth_token.is_none());
            }
            other => panic!("unexpected register response: {other:?}"),
        }

        let strict_reload = daemon.handle_request(
            ControlRequest::PolicyReload(PolicyReloadRequest {
                path: policy_strict.to_string_lossy().to_string(),
            }),
            0,
        );
        match strict_reload {
            ControlResponse::PolicyReload(payload) => assert!(payload.success),
            other => panic!("unexpected strict reload response: {other:?}"),
        }

        let action = Action {
            action_type: ActionType::FileRead,
            context: ActionContext {
                timestamp: Utc::now(),
                agent_id: "test-agent".to_string(),
                pid: 123,
                ppid: 1,
                uid: 1000,
                profile: "default".to_string(),
            },
            resource: Resource::File(core_types::FileResource {
                path: "/workspace/secret/data.txt".to_string(),
                resolved_path: None,
                op: core_types::FileOp::Read,
                source_path: None,
            }),
        };
        let decision = daemon.handle_request(
            ControlRequest::TestDecision(TestDecisionRequest {
                profile: "default".to_string(),
                action,
            }),
            0,
        );
        match decision {
            ControlResponse::TestDecision(result) => {
                assert_eq!(result.decision, Decision::Deny);
                assert_eq!(result.rule_id.as_deref(), Some("deny_secret"));
            }
            other => panic!("unexpected test decision response: {other:?}"),
        }
    }

    #[test]
    fn loads_config_yaml() {
        let tmp = tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.yaml");

        fs::write(
            &config_path,
            r#"
socket_path: /tmp/mercury.sock
policy_path: /tmp/policy.yaml
audit_jsonl_path: /tmp/audit.jsonl
"#,
        )
        .expect("write config");

        let config = load_config(&config_path).expect("load config");
        assert_eq!(config.socket_path, "/tmp/mercury.sock");
        assert_eq!(config.backend_mode, BackendMode::KernelStrict);
        assert_eq!(config.filesystem_backend, FilesystemBackend::AppArmor);
    }

    #[test]
    fn apparmor_block_without_filesystem_backend_defaults_to_apparmor() {
        let tmp = tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.yaml");

        fs::write(
            &config_path,
            r#"
socket_path: /tmp/mercury.sock
policy_path: /tmp/policy.yaml
apparmor:
  parser_path: /usr/sbin/apparmor_parser
"#,
        )
        .expect("write config");

        let config = load_config(&config_path).expect("config should load");
        assert_eq!(config.filesystem_backend, FilesystemBackend::AppArmor);
    }

    #[test]
    fn missing_filesystem_backend_with_auto_enroll_rules_defaults_to_ebpf_lsm() {
        let tmp = tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.yaml");

        fs::write(
            &config_path,
            r#"
socket_path: /tmp/mercury.sock
policy_path: /tmp/policy.yaml
kernel:
  auto_enroll_rules:
    - id: ide-agent
      cgroup_pattern: "**/user.slice/**/code-*.scope/cgroup.procs"
      profile: default
"#,
        )
        .expect("write config");

        let config = load_config(&config_path).expect("config should load");
        assert_eq!(config.filesystem_backend, FilesystemBackend::EbpfLsm);
    }

    #[test]
    fn accepts_apparmor_filesystem_backend_value() {
        let tmp = tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.yaml");

        fs::write(
            &config_path,
            r#"
socket_path: /tmp/mercury.sock
policy_path: /tmp/policy.yaml
filesystem_backend: apparmor
apparmor:
  parser_path: /usr/sbin/apparmor_parser
"#,
        )
        .expect("write config");

        let config = load_config(&config_path).expect("load config");
        assert_eq!(config.filesystem_backend, FilesystemBackend::AppArmor);
    }

    #[test]
    fn accepts_legacy_app_armor_filesystem_backend_alias() {
        let tmp = tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.yaml");

        fs::write(
            &config_path,
            r#"
socket_path: /tmp/mercury.sock
policy_path: /tmp/policy.yaml
filesystem_backend: app_armor
"#,
        )
        .expect("write config");

        let config = load_config(&config_path).expect("load config");
        assert_eq!(config.filesystem_backend, FilesystemBackend::AppArmor);
    }

    #[test]
    fn stale_registration_is_evicted_on_pid_lookup() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let pid = std::process::id();

        daemon.registrations.write().insert(
            pid,
            AgentRegistration {
                agent_id: Uuid::nil(),
                profile: "default".to_string(),
                pid,
                ppid: 1,
                uid: 1000,
                proc_start_time: 0,
                gid: 1000,
                cgroup_id: "ai-stale".to_string(),
                cmdline: vec!["/usr/bin/env".to_string()],
                cwd: "/tmp".to_string(),
                mcp_session_id: None,
                server_id: None,
                client_name: None,
                parent_agent_id: None,
                resolved_exec_path: None,
            },
        );

        assert!(daemon.resolve_proxy_subject_for_pid(pid).is_none());
        assert!(!daemon.registrations.read().contains_key(&pid));
    }

    #[test]
    fn proxy_token_is_evicted_when_agent_cgroup_is_empty() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let cgroup_id = "ai-token";
        let cgroup_dir = tmp.path().join("cgroup").join(cgroup_id);
        fs::create_dir_all(&cgroup_dir).expect("create cgroup");
        fs::write(
            cgroup_dir.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("write cgroup procs");

        daemon.proxy_auth_tokens.write().insert(
            "token-1".to_string(),
            ProxySubject {
                agent_id: "agent-1".to_string(),
                profile: "default".to_string(),
                pid: std::process::id(),
                ppid: 1,
                uid: 1000,
                cgroup_id: cgroup_id.to_string(),
            },
        );

        assert!(daemon.resolve_proxy_subject_for_token("token-1").is_some());

        fs::write(cgroup_dir.join("cgroup.procs"), "").expect("empty cgroup");
        assert!(daemon.resolve_proxy_subject_for_token("token-1").is_none());
        assert!(!daemon.proxy_auth_tokens.read().contains_key("token-1"));
    }

    const MCP_DENY_POLICY: &str = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    mcp:
      default_tool_action: deny
      servers:
        - id: test_mcp_server
          transport: stdio
          exec_path_glob: "/**"
          tools:
            allow:
              - safe_tool
            require_approval:
              - write_file
"#;

    fn register_mcp_server_for_test(daemon: &GuardDaemon, policy_path: &std::path::Path) -> String {
        let reload = daemon.handle_request(
            ControlRequest::PolicyReload(PolicyReloadRequest {
                path: policy_path.to_string_lossy().to_string(),
            }),
            0,
        );
        assert!(
            matches!(reload, ControlResponse::PolicyReload(ref r) if r.success),
            "policy reload failed: {reload:?}"
        );

        let resp = daemon.handle_request(
            ControlRequest::RegisterMcpServer(RegisterMcpServerRequest {
                pid: std::process::id(),
                ppid: 1,
                uid: 0,
                gid: 0,
                profile: "default".to_string(),
                cmdline: vec!["test_binary".to_string()],
                cwd: "/tmp".to_string(),
                server_id: "test_mcp_server".to_string(),
                client_name: None,
                parent_agent_id: None,
            }),
            0,
        );
        match resp {
            ControlResponse::RegisterMcpServer(r) => {
                assert!(
                    !r.mcp_session_id.is_empty(),
                    "mcp_session_id should not be empty"
                );
                r.mcp_session_id
            }
            other => panic!("expected RegisterMcpServer response, got: {other:?}"),
        }
    }

    #[test]
    fn mcp_server_register_returns_session_id() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);
        assert!(!session_id.is_empty());
        // Session must appear in the MCP sessions map
        assert!(
            daemon.mcp_sessions.read().contains_key(&session_id),
            "session not found in mcp_sessions map"
        );
    }

    #[test]
    fn mcp_tool_call_denied_by_default_action() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        let resp = daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id,
                tool_name: "unknown_tool".to_string(),
                tool_call_id: "tc-deny-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            0,
        );
        match resp {
            ControlResponse::AuthorizeMcpToolCall(r) => {
                assert_eq!(r.decision, McpToolCallAuthorizationDecision::Deny);
            }
            other => panic!("expected AuthorizeMcpToolCall response, got: {other:?}"),
        }
    }

    #[test]
    fn mcp_tool_call_allowed_by_tool_list() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        let resp = daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id,
                tool_name: "safe_tool".to_string(),
                tool_call_id: "tc-allow-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            0,
        );
        match resp {
            ControlResponse::AuthorizeMcpToolCall(r) => {
                assert_eq!(r.decision, McpToolCallAuthorizationDecision::Allow);
            }
            other => panic!("expected AuthorizeMcpToolCall response, got: {other:?}"),
        }
    }

    #[test]
    fn mcp_authorize_rejects_non_owner_uid() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        let resp = daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id,
                tool_name: "safe_tool".to_string(),
                tool_call_id: "tc-owner-check-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            u32::MAX,
        );
        match resp {
            ControlResponse::Error(e) => assert_eq!(e.code, "UNAUTHORIZED"),
            other => panic!("expected UNAUTHORIZED error, got: {other:?}"),
        }
    }

    #[test]
    fn mcp_require_approval_returns_error_when_dashboard_disabled() {
        // The require_approval evaluation path requires a live dashboard to store
        // the pending approval record.  When the dashboard is disabled (as in all
        // unit tests) the daemon must return APPROVALS_UNAVAILABLE, not panic or
        // silently deny.
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        let resp = daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id,
                tool_name: "write_file".to_string(),
                tool_call_id: "tc-approval-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            0,
        );
        match resp {
            ControlResponse::Error(e) => {
                assert_eq!(e.code, "APPROVALS_UNAVAILABLE");
            }
            other => panic!("expected APPROVALS_UNAVAILABLE error, got: {other:?}"),
        }
    }

    #[test]
    fn complete_mcp_tool_call_is_idempotent() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        // Authorize safe_tool so it appears in active_mcp_calls
        daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id.clone(),
                tool_name: "safe_tool".to_string(),
                tool_call_id: "tc-complete-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            0,
        );

        let complete = || {
            ControlRequest::CompleteMcpToolCall(CompleteMcpToolCallRequest {
                mcp_session_id: session_id.clone(),
                tool_call_id: "tc-complete-1".to_string(),
                status: McpToolCallCompletionStatus::Success,
                error_message: None,
            })
        };

        // First completion should succeed
        let first = daemon.handle_request(complete(), 0);
        match first {
            ControlResponse::CompleteMcpToolCall(r) => {
                assert!(
                    r.completed,
                    "first CompleteMcpToolCall should complete the call"
                );
            }
            other => panic!("expected CompleteMcpToolCall response, got: {other:?}"),
        }

        // Second completion of the same call must return an error (call no longer in active list)
        let second = daemon.handle_request(complete(), 0);
        match second {
            ControlResponse::Error(e) => {
                assert_eq!(e.code, "MCP_TOOL_CALL_NOT_FOUND");
            }
            other => panic!(
                "expected MCP_TOOL_CALL_NOT_FOUND error on duplicate complete, got: {other:?}"
            ),
        }
    }

    #[test]
    fn complete_mcp_tool_call_rejects_non_owner_uid() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);

        daemon.handle_request(
            ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                mcp_session_id: session_id.clone(),
                tool_name: "safe_tool".to_string(),
                tool_call_id: "tc-complete-owner-check-1".to_string(),
                arguments_json: "{}".to_string(),
                arguments_summary: None,
            }),
            0,
        );

        let resp = daemon.handle_request(
            ControlRequest::CompleteMcpToolCall(CompleteMcpToolCallRequest {
                mcp_session_id: session_id,
                tool_call_id: "tc-complete-owner-check-1".to_string(),
                status: McpToolCallCompletionStatus::Success,
                error_message: None,
            }),
            u32::MAX,
        );

        match resp {
            ControlResponse::Error(e) => assert_eq!(e.code, "UNAUTHORIZED"),
            other => panic!("expected UNAUTHORIZED error, got: {other:?}"),
        }
    }

    #[test]
    fn wait_mcp_approval_rejects_non_owner_uid() {
        let tmp = tempdir().expect("tempdir");
        let policy_path = tmp.path().join("mcp-policy.yaml");
        fs::write(&policy_path, MCP_DENY_POLICY).expect("write mcp policy");

        let daemon = test_daemon(tmp.path());
        let session_id = register_mcp_server_for_test(&daemon, &policy_path);
        let session = daemon
            .mcp_sessions
            .read()
            .get(&session_id)
            .cloned()
            .expect("session");

        daemon.pending_mcp_approvals.write().insert(
            "approval-1".to_string(),
            PendingMcpApprovalRecord {
                deadline: Instant::now() + MCP_APPROVAL_TTL,
                profile: session.profile.clone(),
                agent_id: session.agent_id.to_string(),
                pid: session.pid,
                proc_start_time: session.proc_start_time,
                server_id: session.server_id.clone(),
                transport: session.transport,
                mcp_session_id: session.mcp_session_id.clone(),
                resource_uri: None,
                client_request_id: None,
                tool_name: Some("write_file".to_string()),
                tool_call_id: "tc-pending-1".to_string(),
                arguments_sha256: Some("abc".to_string()),
                arguments_summary: None,
                rule_id: Some("rule-1".to_string()),
                shared: Arc::new(PendingMcpApprovalShared::default()),
            },
        );

        let resp = daemon.handle_request(
            ControlRequest::WaitMcpApproval(control_api::WaitMcpApprovalRequest {
                request_id: "approval-1".to_string(),
            }),
            u32::MAX,
        );

        match resp {
            ControlResponse::Error(e) => assert_eq!(e.code, "UNAUTHORIZED"),
            other => panic!("expected UNAUTHORIZED error, got: {other:?}"),
        }
    }
}
