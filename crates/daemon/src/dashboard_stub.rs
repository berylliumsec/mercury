//! Stub dashboard module for non-Linux builds.
//!
//! Provides the minimal types that `DaemonConfig` and `load_config` need so
//! the daemon crate compiles on platforms where the full dashboard (which
//! depends on `GuardDaemon` / Linux adapter) is not available.

use control_api::CoverageStatus as ApiCoverageStatus;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Config types (must match the real dashboard module's serde layout)
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_dashboard_bind_addr() -> String {
    "127.0.0.1:7480".to_string()
}

fn default_dashboard_static_dir() -> String {
    #[cfg(unix)]
    {
        "/usr/share/mercury/dashboard".to_string()
    }
    #[cfg(not(unix))]
    {
        "dashboard".to_string()
    }
}

fn default_dashboard_sqlite_path() -> String {
    #[cfg(unix)]
    {
        "/var/lib/mercury/dashboard.db".to_string()
    }
    #[cfg(not(unix))]
    {
        "dashboard.db".to_string()
    }
}

fn default_dashboard_retention_days() -> u32 {
    14
}
fn default_dashboard_sse_clients_max() -> usize {
    200
}
fn default_dashboard_request_rate_limit_rps() -> u32 {
    50
}
fn default_dashboard_launch_history_limit() -> usize {
    25
}
fn default_dashboard_stop_grace_seconds() -> u64 {
    5
}
fn default_dashboard_health_telemetry_loss_window_minutes() -> u32 {
    10
}
fn default_dashboard_username() -> String {
    "admin".to_string()
}

fn default_dashboard_password_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/dashboard.password".to_string()
    }
    #[cfg(not(unix))]
    {
        "dashboard.password".to_string()
    }
}

fn default_dashboard_session_ttl_minutes() -> u32 {
    30
}

fn default_dashboard_tls_cert_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/dashboard.crt".to_string()
    }
    #[cfg(not(unix))]
    {
        "dashboard.crt".to_string()
    }
}

fn default_dashboard_tls_key_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/dashboard.key".to_string()
    }
    #[cfg(not(unix))]
    {
        "dashboard.key".to_string()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardAuthConfig {
    #[serde(default = "default_dashboard_username")]
    pub username: String,
    #[serde(default = "default_dashboard_password_file")]
    pub password_file: String,
    #[serde(default = "default_dashboard_session_ttl_minutes")]
    pub session_ttl_minutes: u32,
}

impl Default for DashboardAuthConfig {
    fn default() -> Self {
        Self {
            username: default_dashboard_username(),
            password_file: default_dashboard_password_file(),
            session_ttl_minutes: default_dashboard_session_ttl_minutes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dashboard_tls_cert_file")]
    pub cert_file: String,
    #[serde(default = "default_dashboard_tls_key_file")]
    pub key_file: String,
    #[serde(default = "default_true")]
    pub auto_generate_self_signed: bool,
}

impl Default for DashboardTlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_file: default_dashboard_tls_cert_file(),
            key_file: default_dashboard_tls_key_file(),
            auto_generate_self_signed: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardLaunchConfig {
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub launcher_path: String,
    #[serde(default = "default_dashboard_launch_history_limit")]
    pub history_limit: usize,
    #[serde(default = "default_dashboard_stop_grace_seconds")]
    pub stop_grace_seconds: u64,
}

impl Default for DashboardLaunchConfig {
    fn default() -> Self {
        Self {
            user: String::new(),
            group: String::new(),
            launcher_path: String::new(),
            history_limit: default_dashboard_launch_history_limit(),
            stop_grace_seconds: default_dashboard_stop_grace_seconds(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_dashboard_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_dashboard_static_dir")]
    pub static_dir: String,
    #[serde(default = "default_dashboard_sqlite_path")]
    pub sqlite_path: String,
    #[serde(default = "default_dashboard_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_dashboard_sse_clients_max")]
    pub sse_clients_max: usize,
    #[serde(default = "default_dashboard_request_rate_limit_rps")]
    pub request_rate_limit_rps: u32,
    #[serde(default)]
    pub auth: DashboardAuthConfig,
    #[serde(default)]
    pub launch: DashboardLaunchConfig,
    #[serde(default)]
    pub tls: DashboardTlsConfig,
    #[serde(default = "default_dashboard_health_telemetry_loss_window_minutes")]
    pub health_telemetry_loss_window_minutes: u32,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: false,
            bind_addr: default_dashboard_bind_addr(),
            static_dir: default_dashboard_static_dir(),
            sqlite_path: default_dashboard_sqlite_path(),
            retention_days: default_dashboard_retention_days(),
            sse_clients_max: default_dashboard_sse_clients_max(),
            request_rate_limit_rps: default_dashboard_request_rate_limit_rps(),
            auth: DashboardAuthConfig::default(),
            launch: DashboardLaunchConfig::default(),
            tls: DashboardTlsConfig::default(),
            health_telemetry_loss_window_minutes:
                default_dashboard_health_telemetry_loss_window_minutes(),
        }
    }
}

// ---------------------------------------------------------------------------
// Status types (used by DaemonConfig / health / control API)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DashboardStatus {
    pub enabled: bool,
    pub ready: bool,
    pub url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCertInfo {
    pub cert_file: String,
    pub key_file: String,
    pub expires_at: String,
    pub issuer: String,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardHookStatus {
    pub exec_hook: String,
    pub network_hook: String,
    pub filesystem_hook: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardStatusResponse {
    pub daemon_up: bool,
    pub policy_version: String,
    pub backend_mode: String,
    pub kernel_ready: bool,
    pub kernel_program_version: String,
    pub auto_enroll_active_rules: usize,
    pub unmatched_mode: String,
    pub hook_status: DashboardHookStatus,
    pub apparmor_enabled: bool,
    pub apparmor_parser_present: bool,
    pub dashboard_enabled: bool,
    pub dashboard_ready: bool,
    pub dashboard_url: Option<String>,
    pub dashboard_error: Option<String>,
    pub url_gateway_enabled: bool,
    pub url_gateway_ready: bool,
    pub url_gateway_http_proxy: Option<String>,
    pub url_gateway_https_proxy: Option<String>,
    pub url_gateway_error: Option<String>,
    pub events_ingested_total: u64,
    pub events_dropped_queue_total: u64,
    pub unenrolled_events_suppressed_total: u64,
    pub ingest_backlog_len: usize,
    pub enrollment_sync_error: Option<String>,
    pub dashboard_schema_version: String,
    pub policy_versions_total: usize,
    pub pending_mcp_approvals: usize,
    pub active_dashboard_sessions: usize,
    pub active_sse_clients: usize,
    pub active_mcp_sessions: usize,
    pub dashboard_sqlite_bytes: u64,
    pub coverage: Vec<ApiCoverageStatus>,
    pub tls_cert_info: Option<TlsCertInfo>,
    pub events_dropped_ringbuf_total: u64,
    pub kernel_events_rate_limited_total: u64,
    pub kernel_deny_events_dropped_total: u64,
    pub audit_write_failures_total: u64,
    pub audit_mirror_failures_total: u64,
    pub apparmor_records_lost_total: u64,
    pub policy_reload_failures_total: u64,
    pub policy_sync_last_error: Option<String>,
    pub telemetry_degraded_reasons: Vec<String>,
    pub backpressure_active: bool,
    pub backpressure_activations_total: u64,
    pub auth_failures_total: u64,
    pub dashboard_action_record_failures_total: u64,
    pub sse_events_skipped_total: u64,
    pub degraded_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// DashboardError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DashboardError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("dashboard unavailable: {0}")]
    Unavailable(String),
}

// ---------------------------------------------------------------------------
// DashboardService stub — provides all methods the daemon impl calls
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct DashboardService {
    pub tls_cert_info: parking_lot::RwLock<Option<TlsCertInfo>>,
}

impl DashboardService {
    pub fn new(_config: DashboardConfig) -> Result<Self, DashboardError> {
        Err(DashboardError::Unavailable(
            "dashboard is not available on this platform".to_string(),
        ))
    }

    pub fn dashboard_url(&self) -> String {
        String::new()
    }

    pub fn cleanup_sessions(&self) {}

    pub async fn reload_tls_cert(&self) {}

    pub fn ingest_event(&self, _event: &core_types::AuditEvent) -> Result<(), DashboardError> {
        Ok(())
    }

    pub fn ingest_events_batch(
        &self,
        _events: &[core_types::AuditEvent],
    ) -> Result<(), DashboardError> {
        Ok(())
    }

    pub fn readiness(&self) -> (bool, Option<String>) {
        (false, Some("not available on this platform".to_string()))
    }

    pub fn set_error(&self, _message: impl Into<String>) {}
    pub fn set_ready(&self) {}

    pub fn operational_snapshot(&self) -> Result<DashboardOperationalSnapshot, DashboardError> {
        Ok(DashboardOperationalSnapshot::default())
    }

    pub fn upsert_mcp_tool_call(&self, _record: &StoredMcpToolCall) -> Result<(), DashboardError> {
        Ok(())
    }

    pub fn set_mcp_tool_call_resolution(
        &self,
        _request_id: &str,
        _approval_state: &str,
        _final_decision: &str,
        _reason: &str,
        _resolved_by: Option<&str>,
        _resolved_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DashboardError> {
        Ok(())
    }

    pub fn set_mcp_tool_call_completion(
        &self,
        _mcp_session_id: &str,
        _tool_call_id: &str,
        _completion_status: &str,
        _completion_error: Option<&str>,
    ) -> Result<(), DashboardError> {
        Ok(())
    }
}

pub(crate) struct DashboardOperationalSnapshot {
    pub(crate) schema_version: String,
    pub(crate) policy_versions_total: usize,
    pub(crate) pending_mcp_approvals: usize,
    pub(crate) active_dashboard_sessions: usize,
    pub(crate) active_sse_clients: usize,
    pub(crate) dashboard_sqlite_bytes: u64,
}

impl Default for DashboardOperationalSnapshot {
    fn default() -> Self {
        Self {
            schema_version: "stub".to_string(),
            policy_versions_total: 0,
            pending_mcp_approvals: 0,
            active_dashboard_sessions: 0,
            active_sse_clients: 0,
            dashboard_sqlite_bytes: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StoredMcpToolCall {
    pub kind: String,
    pub request_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub agent_id: String,
    pub profile: String,
    pub server_id: String,
    pub transport: core_types::McpTransport,
    pub mcp_session_id: String,
    pub resource_uri: Option<String>,
    pub client_request_id: Option<String>,
    pub tool_name: String,
    pub tool_call_id: String,
    pub arguments_json: String,
    pub arguments_sha256: String,
    pub arguments_summary: Option<String>,
    pub rule_id: Option<String>,
    pub approval_state: String,
    pub final_decision: Option<String>,
    pub reason: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completion_status: Option<String>,
    pub completion_error: Option<String>,
}

pub async fn spawn_dashboard_server(
    _daemon: std::sync::Arc<()>,
    _dashboard: std::sync::Arc<DashboardService>,
) -> Result<(), DashboardError> {
    Err(DashboardError::Unavailable(
        "dashboard is not available on this platform".to_string(),
    ))
}
