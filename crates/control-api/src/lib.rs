use core_types::{Action, DecisionResult};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Default control socket path on Linux (Unix domain socket).
#[cfg(unix)]
pub const SOCKET_PATH: &str = "/run/mercury/mercuryd.sock";

/// Fallback for other platforms.
#[cfg(not(unix))]
pub const SOCKET_PATH: &str = "/run/mercury/mercuryd.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterAgentRequest {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub profile: String,
    pub cmdline: Vec<String>,
    pub cwd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterAgentResponse {
    pub agent_id: Uuid,
    pub cgroup_id: String,
    #[serde(default)]
    pub filesystem_label: Option<String>,
    #[serde(default)]
    pub url_proxy_http: Option<String>,
    #[serde(default)]
    pub url_proxy_https: Option<String>,
    #[serde(default)]
    pub url_proxy_no_proxy: Option<String>,
    #[serde(default)]
    pub url_proxy_auth_token: Option<String>,
    #[serde(default)]
    pub url_proxy_ca_cert_path: Option<String>,
    #[serde(default)]
    pub url_proxy_ca_cert_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterMcpServerRequest {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub profile: String,
    pub cmdline: Vec<String>,
    pub cwd: String,
    pub server_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub parent_agent_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterMcpServerResponse {
    pub agent_id: Uuid,
    pub cgroup_id: String,
    #[serde(default)]
    pub filesystem_label: Option<String>,
    pub mcp_session_id: String,
    #[serde(default)]
    pub url_proxy_http: Option<String>,
    #[serde(default)]
    pub url_proxy_https: Option<String>,
    #[serde(default)]
    pub url_proxy_no_proxy: Option<String>,
    #[serde(default)]
    pub url_proxy_auth_token: Option<String>,
    #[serde(default)]
    pub url_proxy_ca_cert_path: Option<String>,
    #[serde(default)]
    pub url_proxy_ca_cert_pem: Option<String>,
    #[serde(default)]
    pub mcp_http_gateway_url: Option<String>,
    #[serde(default)]
    pub mcp_http_gateway_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyReloadRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyReloadResponse {
    pub version: String,
    pub success: bool,
    pub errors: Vec<String>,
    /// Non-fatal advisory: policy is live but the on-disk file could not be updated.
    /// The running enforcement uses the new policy; the file still holds the old one.
    /// A daemon restart will revert enforcement to the file version until it is fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookStatus {
    pub exec_hook: String,
    pub network_hook: String,
    pub filesystem_hook: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageStatus {
    pub action_type: String,
    pub action_class: String,
    pub backend: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub daemon_up: bool,
    pub policy_version: String,
    pub backend_mode: String,
    pub kernel_ready: bool,
    pub kernel_program_version: String,
    pub auto_enroll_active_rules: usize,
    pub unmatched_mode: String,
    pub hook_status: HookStatus,
    #[serde(default)]
    pub apparmor_enabled: bool,
    #[serde(default)]
    pub apparmor_parser_present: bool,
    pub dashboard_enabled: bool,
    pub dashboard_ready: bool,
    #[serde(default)]
    pub dashboard_url: Option<String>,
    #[serde(default)]
    pub dashboard_error: Option<String>,
    #[serde(default)]
    pub url_gateway_enabled: bool,
    #[serde(default)]
    pub url_gateway_ready: bool,
    #[serde(default)]
    pub url_gateway_http_proxy: Option<String>,
    #[serde(default)]
    pub url_gateway_https_proxy: Option<String>,
    #[serde(default)]
    pub url_gateway_error: Option<String>,
    pub events_ingested_total: u64,
    pub events_dropped_queue_total: u64,
    pub unenrolled_events_suppressed_total: u64,
    pub ingest_backlog_len: usize,
    pub enrollment_sync_error: Option<String>,
    #[serde(default)]
    pub dashboard_schema_version: String,
    #[serde(default)]
    pub policy_versions_total: usize,
    #[serde(default)]
    pub pending_mcp_approvals: usize,
    #[serde(default)]
    pub active_dashboard_sessions: usize,
    #[serde(default)]
    pub active_sse_clients: usize,
    #[serde(default)]
    pub active_mcp_sessions: usize,
    #[serde(default)]
    pub dashboard_sqlite_bytes: u64,
    #[serde(default)]
    pub coverage: Vec<CoverageStatus>,
    #[serde(default)]
    pub backpressure_active: bool,
    #[serde(default)]
    pub backpressure_activations_total: u64,
    #[serde(default)]
    pub policy_sync_enabled: bool,
    #[serde(default)]
    pub policy_sync_last_check: Option<String>,
    #[serde(default)]
    pub policy_sync_last_error: Option<String>,
    #[serde(default)]
    pub kernel_limits: Option<KernelLimitsInfo>,
    #[serde(default)]
    pub events_dropped_ringbuf_total: u64,
    /// Kernel events discarded by the in-kernel per-agent rate limiter.
    #[serde(default)]
    pub kernel_events_rate_limited_total: u64,
    /// DENY events the kernel could not deliver (ring buffer full while
    /// the decision was already enforced).
    #[serde(default)]
    pub kernel_deny_events_dropped_total: u64,
    /// Audit records that could not be written to the JSONL file.
    #[serde(default)]
    pub audit_write_failures_total: u64,
    /// Audit records that could not be mirrored (journald / remote).
    #[serde(default)]
    pub audit_mirror_failures_total: u64,
    /// AppArmor audit records lost (journal cursor gaps, kernel rate limit).
    #[serde(default)]
    pub apparmor_records_lost_total: u64,
    #[serde(default)]
    pub policy_reload_failures_total: u64,
    /// Human-readable telemetry-loss conditions currently in effect.
    #[serde(default)]
    pub telemetry_degraded_reasons: Vec<String>,
}

impl HealthResponse {
    /// Conditions under which Mercury is not enforcing or not recording
    /// completely. Empty when healthy.
    pub fn degraded_reasons(&self) -> Vec<String> {
        degraded_reasons(&DegradedSignals {
            backend_mode: self.backend_mode.as_str(),
            kernel_ready: self.kernel_ready,
            url_gateway_enabled: self.url_gateway_enabled,
            url_gateway_ready: self.url_gateway_ready,
            url_gateway_error: self.url_gateway_error.as_deref(),
            audit_write_failures_total: self.audit_write_failures_total,
            enrollment_sync_error: self.enrollment_sync_error.as_deref(),
            telemetry_degraded_reasons: self.telemetry_degraded_reasons.as_slice(),
        })
    }
}

/// Inputs shared by every degraded-state check (`mercury-status`, the
/// dashboard health endpoint and the dashboard overview).
#[derive(Debug, Clone, Copy, Default)]
pub struct DegradedSignals<'a> {
    pub backend_mode: &'a str,
    pub kernel_ready: bool,
    pub url_gateway_enabled: bool,
    pub url_gateway_ready: bool,
    pub url_gateway_error: Option<&'a str>,
    pub audit_write_failures_total: u64,
    pub enrollment_sync_error: Option<&'a str>,
    pub telemetry_degraded_reasons: &'a [String],
}

/// Returns one reason per degraded condition, in a stable order.
pub fn degraded_reasons(signals: &DegradedSignals<'_>) -> Vec<String> {
    let mut reasons = Vec::new();
    // linux_compat never loads the kernel program; only kernel_strict needs it.
    if signals.backend_mode == "kernel_strict" && !signals.kernel_ready {
        reasons.push("kernel enforcement is not ready".to_string());
    }
    if signals.url_gateway_enabled && !signals.url_gateway_ready {
        reasons.push(match signals.url_gateway_error {
            Some(error) if !error.is_empty() => {
                format!("url gateway is enabled but not ready: {error}")
            }
            _ => "url gateway is enabled but not ready".to_string(),
        });
    }
    if signals.audit_write_failures_total > 0 {
        reasons.push(format!(
            "{} audit write failures since start",
            signals.audit_write_failures_total
        ));
    }
    if let Some(error) = signals.enrollment_sync_error
        && !error.is_empty()
    {
        reasons.push(format!("enrollment sync error: {error}"));
    }
    reasons.extend(
        signals
            .telemetry_degraded_reasons
            .iter()
            .filter(|reason| !reason.is_empty())
            .cloned(),
    );
    reasons
}

/// Configured kernel limits exposed through the health endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelLimitsInfo {
    pub max_rules_per_class: u32,
    pub max_profiles: u32,
    pub max_workspace_roots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaCertResponse {
    pub pem: String,
    pub fingerprint_sha256: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestDecisionRequest {
    pub profile: String,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpToolCallAuthorizationDecision {
    Allow,
    Deny,
    PendingApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeMcpToolCallRequest {
    pub mcp_session_id: String,
    pub tool_name: String,
    pub tool_call_id: String,
    pub arguments_json: String,
    #[serde(default)]
    pub arguments_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeMcpToolCallResponse {
    pub decision: McpToolCallAuthorizationDecision,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeMcpResourceReadRequest {
    pub mcp_session_id: String,
    pub uri: String,
    pub resource_call_id: String,
    #[serde(default)]
    pub client_request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeMcpResourceReadResponse {
    pub decision: McpToolCallAuthorizationDecision,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaitMcpApprovalRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaitMcpApprovalResponse {
    pub decision: McpToolCallAuthorizationDecision,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpToolCallCompletionStatus {
    Success,
    Error,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompleteMcpToolCallRequest {
    pub mcp_session_id: String,
    pub tool_call_id: String,
    pub status: McpToolCallCompletionStatus,
    #[serde(default)]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompleteMcpToolCallResponse {
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlRequest {
    RegisterAgent(RegisterAgentRequest),
    RegisterMcpServer(RegisterMcpServerRequest),
    PolicyReload(PolicyReloadRequest),
    Health,
    TestDecision(TestDecisionRequest),
    AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest),
    AuthorizeMcpResourceRead(AuthorizeMcpResourceReadRequest),
    WaitMcpApproval(WaitMcpApprovalRequest),
    CompleteMcpToolCall(CompleteMcpToolCallRequest),
    GetCaCert,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// Keep this enum unboxed to preserve straightforward wire framing and avoid extra allocations.
#[allow(clippy::large_enum_variant)]
pub enum ControlResponse {
    RegisterAgent(RegisterAgentResponse),
    RegisterMcpServer(RegisterMcpServerResponse),
    PolicyReload(PolicyReloadResponse),
    Health(HealthResponse),
    TestDecision(DecisionResult),
    AuthorizeMcpToolCall(AuthorizeMcpToolCallResponse),
    AuthorizeMcpResourceRead(AuthorizeMcpResourceReadResponse),
    WaitMcpApproval(WaitMcpApprovalResponse),
    CompleteMcpToolCall(CompleteMcpToolCallResponse),
    CaCert(CaCertResponse),
    Error(ControlErrorPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum ControlApiError {
    #[error("serialize frame: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid frame: missing newline terminator")]
    MissingNewline,
}

pub fn encode_request(request: &ControlRequest) -> Result<Vec<u8>, ControlApiError> {
    let mut body = serde_json::to_vec(request)?;
    body.push(b'\n');
    Ok(body)
}

pub fn decode_request(frame: &[u8]) -> Result<ControlRequest, ControlApiError> {
    if !frame.ends_with(b"\n") {
        return Err(ControlApiError::MissingNewline);
    }

    let request = serde_json::from_slice(&frame[..frame.len() - 1])?;
    Ok(request)
}

pub fn encode_response(response: &ControlResponse) -> Result<Vec<u8>, ControlApiError> {
    let mut body = serde_json::to_vec(response)?;
    body.push(b'\n');
    Ok(body)
}

pub fn decode_response(frame: &[u8]) -> Result<ControlResponse, ControlApiError> {
    if !frame.ends_with(b"\n") {
        return Err(ControlApiError::MissingNewline);
    }

    let response = serde_json::from_slice(&frame[..frame.len() - 1])?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_request_codec() {
        let request = ControlRequest::Health;
        let encoded = encode_request(&request).expect("encode");
        let decoded = decode_request(&encoded).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn reject_non_terminated_frame() {
        let result = decode_request(b"{}");
        assert!(matches!(result, Err(ControlApiError::MissingNewline)));
    }

    #[test]
    fn decode_health_response_with_missing_url_gateway_fields() {
        let frame = br#"{"Health":{"daemon_up":true,"policy_version":"v1","backend_mode":"kernel_strict","kernel_ready":true,"kernel_program_version":"kernel-ebpf-v16","auto_enroll_active_rules":1,"unmatched_mode":"observe","hook_status":{"exec_hook":"EbpfLsm","network_hook":"EbpfLsm","filesystem_hook":"EbpfLsm"},"dashboard_enabled":true,"dashboard_ready":true,"dashboard_url":"https://0.0.0.0:7480","dashboard_error":null,"events_ingested_total":0,"events_dropped_queue_total":0,"unenrolled_events_suppressed_total":0,"ingest_backlog_len":0,"enrollment_sync_error":null}}
"#;
        let response = decode_response(frame).expect("decode");
        match response {
            ControlResponse::Health(payload) => {
                assert!(!payload.url_gateway_enabled);
                assert!(!payload.url_gateway_ready);
                assert!(payload.url_gateway_http_proxy.is_none());
                assert!(payload.url_gateway_https_proxy.is_none());
                assert!(payload.url_gateway_error.is_none());
            }
            _ => panic!("unexpected response variant"),
        }
    }

    fn healthy_response() -> HealthResponse {
        let frame = br#"{"Health":{"daemon_up":true,"policy_version":"v1","backend_mode":"kernel_strict","kernel_ready":true,"kernel_program_version":"kernel-ebpf-v16","auto_enroll_active_rules":1,"unmatched_mode":"observe","hook_status":{"exec_hook":"EbpfLsm","network_hook":"EbpfLsm","filesystem_hook":"EbpfLsm"},"dashboard_enabled":true,"dashboard_ready":true,"events_ingested_total":0,"events_dropped_queue_total":0,"unenrolled_events_suppressed_total":0,"ingest_backlog_len":0,"enrollment_sync_error":null}}
"#;
        match decode_response(frame).expect("decode") {
            ControlResponse::Health(payload) => payload,
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn old_health_frames_default_telemetry_fields() {
        let payload = healthy_response();
        assert_eq!(payload.audit_write_failures_total, 0);
        assert_eq!(payload.kernel_events_rate_limited_total, 0);
        assert!(payload.telemetry_degraded_reasons.is_empty());
        assert!(payload.degraded_reasons().is_empty());
    }

    #[test]
    fn degraded_reasons_cover_every_condition() {
        let mut payload = healthy_response();
        payload.kernel_ready = false;
        payload.url_gateway_enabled = true;
        payload.url_gateway_error = Some("bind failed".to_string());
        payload.audit_write_failures_total = 3;
        payload.enrollment_sync_error = Some("cgroup gone".to_string());
        payload.telemetry_degraded_reasons = vec!["ring buffer overflow".to_string()];
        assert_eq!(
            payload.degraded_reasons(),
            vec![
                "kernel enforcement is not ready".to_string(),
                "url gateway is enabled but not ready: bind failed".to_string(),
                "3 audit write failures since start".to_string(),
                "enrollment sync error: cgroup gone".to_string(),
                "ring buffer overflow".to_string(),
            ]
        );
    }

    #[test]
    fn linux_compat_is_not_degraded_by_missing_kernel_program() {
        let mut payload = healthy_response();
        payload.backend_mode = "linux_compat".to_string();
        payload.kernel_ready = false;
        assert!(payload.degraded_reasons().is_empty());
    }

    #[test]
    fn decode_register_response_with_missing_proxy_fields() {
        let frame = br#"{"RegisterAgent":{"agent_id":"123e4567-e89b-12d3-a456-426614174000","cgroup_id":"cg-1"}}
"#;
        let response = decode_response(frame).expect("decode");
        match response {
            ControlResponse::RegisterAgent(payload) => {
                assert!(payload.url_proxy_http.is_none());
                assert!(payload.url_proxy_https.is_none());
                assert!(payload.url_proxy_no_proxy.is_none());
                assert!(payload.url_proxy_auth_token.is_none());
                assert!(payload.url_proxy_ca_cert_path.is_none());
                assert!(payload.url_proxy_ca_cert_pem.is_none());
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn round_trip_authorize_mcp_tool_call_codec() {
        let request = ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
            mcp_session_id: "session-1".to_string(),
            tool_name: "create_pull_request".to_string(),
            tool_call_id: "call-1".to_string(),
            arguments_json: "{\"title\":\"Test\"}".to_string(),
            arguments_summary: Some("title=Test".to_string()),
        });
        let encoded = encode_request(&request).expect("encode");
        let decoded = decode_request(&encoded).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn round_trip_authorize_mcp_resource_read_codec() {
        let request = ControlRequest::AuthorizeMcpResourceRead(AuthorizeMcpResourceReadRequest {
            mcp_session_id: "session-1".to_string(),
            uri: "repo://openai/mercury/pulls/5".to_string(),
            resource_call_id: "resource-1".to_string(),
            client_request_id: Some("req-1".to_string()),
        });
        let encoded = encode_request(&request).expect("encode");
        let decoded = decode_request(&encoded).expect("decode");
        assert_eq!(decoded, request);
    }
}
