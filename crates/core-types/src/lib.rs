use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const API_VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    FileRead,
    FileWrite,
    FileDelete,
    ProcExec,
    NetConnect,
    McpToolCall,
    McpResourceRead,
    /// Writable MAP_SHARED file-backed mmap (caught by lsm/mmap_file).
    FileMmap,
    /// UDP sendto with explicit destination (caught by lsm/socket_sendmsg).
    NetSendmsg,
    /* ── file-mutation hooks ── */
    FileRename,
    FileLink,
    FileSymlink,
    FileMkdir,
    FileRmdir,
    FileCreate,
    FileChmod,
    FileChown,
    FileTruncate,
    /* ── network server-side hooks ── */
    NetBind,
    NetListen,
    NetAccept,
    NetCreate,
    /* ── process supervision hooks ── */
    ProcPtrace,
    ProcKill,
    ProcCapable,
    /* ── process lifecycle (kernel tracepoints) ── */
    /// An execve() that committed; carries argv.
    ProcStart,
    /// A thread group exited; carries the exit status.
    ProcExit,
    /* ── privileged / tamper-relevant kernel operations ── */
    /// bpf(2) syscall (loading programs, touching maps).
    ProcBpf,
    /// Kernel module load (init_module / finit_module).
    ProcModuleLoad,
    /// mount(2) / move_mount(2).
    ProcMount,
    /// User namespace creation (unshare / clone with CLONE_NEWUSER).
    ProcUserns,
    /* ── MCP traffic that is observed but not policy-evaluated ── */
    McpRequest,
    /* ── Mercury's own lifecycle and telemetry health ── */
    SystemEvent,
}

impl ActionType {
    pub fn class(self) -> ActionClass {
        match self {
            Self::FileRead
            | Self::FileWrite
            | Self::FileDelete
            | Self::FileMmap
            | Self::FileRename
            | Self::FileLink
            | Self::FileSymlink
            | Self::FileMkdir
            | Self::FileRmdir
            | Self::FileCreate
            | Self::FileChmod
            | Self::FileChown
            | Self::FileTruncate => ActionClass::File,
            Self::ProcExec
            | Self::ProcPtrace
            | Self::ProcKill
            | Self::ProcCapable
            | Self::ProcStart
            | Self::ProcExit
            | Self::ProcBpf
            | Self::ProcModuleLoad
            | Self::ProcMount
            | Self::ProcUserns => ActionClass::Process,
            Self::NetConnect
            | Self::NetSendmsg
            | Self::NetBind
            | Self::NetListen
            | Self::NetAccept
            | Self::NetCreate => ActionClass::Network,
            Self::McpToolCall | Self::McpResourceRead | Self::McpRequest => ActionClass::Mcp,
            Self::SystemEvent => ActionClass::System,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionClass {
    File,
    Process,
    Network,
    Mcp,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionContext {
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Resource {
    File(FileResource),
    Exec(ExecResource),
    Network(NetworkResource),
    McpTool(McpToolResource),
    McpResource(McpResourceReadResource),
    System(SystemResource),
}

/// Mercury-internal event: daemon lifecycle, policy changes, enrollment
/// changes, and telemetry loss. `event` is a stable snake_case identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SystemResource {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

impl SystemResource {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
            event: event.into(),
            ..Self::default()
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn attr(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileResource {
    pub path: String,
    pub resolved_path: Option<String>,
    pub op: FileOp,
    /// Source path for rename/link (the destination is `path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileOp {
    Read,
    Write,
    Delete,
    Rename,
    Link,
    Symlink,
    Mkdir,
    Rmdir,
    Create,
    Chmod,
    Chown,
    Truncate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecResource {
    pub path: String,
    pub argv_hash: Option<String>,
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// True when argv exceeded the kernel capture buffer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub argv_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkResource {
    pub dest_host: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_port: u16,
    pub protocol: NetworkProtocol,
    #[serde(default)]
    pub full_url: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    /// Filesystem path (or `@abstract` name) for AF_UNIX sockets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    /// Address family: `inet`, `inet6`, `unix`, or the raw number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolResource {
    pub server_id: String,
    pub transport: McpTransport,
    pub tool_name: String,
    pub tool_call_id: String,
    pub mcp_session_id: String,
    pub arguments_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpResourceReadResource {
    pub server_id: String,
    pub transport: McpTransport,
    pub uri: String,
    pub mcp_session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_call_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    Stdio,
    Http,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    pub action_type: ActionType,
    pub context: ActionContext,
    pub resource: Resource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    AllowByObserveMode,
    AllowUnenrolledObserve,
    AllowByRule,
    AllowByApproval,
    AllowByDefault,
    DenyByRule,
    DenyByApproval,
    DenyApprovalExpired,
    DenyByDefault,
    AllowFailOpen,
    DenyFailClosed,
    ErrorInvalidAction,
    ErrorPolicyUnavailable,
    ErrorEnforcementUnavailable,
    /// Record carries no policy decision (lifecycle, telemetry health).
    Informational,
}

impl Display for DecisionReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::AllowByObserveMode => "ALLOW_BY_OBSERVE_MODE",
            Self::AllowUnenrolledObserve => "ALLOW_UNENROLLED_OBSERVE",
            Self::AllowByRule => "ALLOW_BY_RULE",
            Self::AllowByApproval => "ALLOW_BY_APPROVAL",
            Self::AllowByDefault => "ALLOW_BY_DEFAULT",
            Self::DenyByRule => "DENY_BY_RULE",
            Self::DenyByApproval => "DENY_BY_APPROVAL",
            Self::DenyApprovalExpired => "DENY_APPROVAL_EXPIRED",
            Self::DenyByDefault => "DENY_BY_DEFAULT",
            Self::AllowFailOpen => "ALLOW_FAIL_OPEN",
            Self::DenyFailClosed => "DENY_FAIL_CLOSED",
            Self::ErrorInvalidAction => "ERROR_INVALID_ACTION",
            Self::ErrorPolicyUnavailable => "ERROR_POLICY_UNAVAILABLE",
            Self::ErrorEnforcementUnavailable => "ERROR_ENFORCEMENT_UNAVAILABLE",
            Self::Informational => "INFORMATIONAL",
        };

        write!(f, "{text}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionResult {
    pub decision: Decision,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultDecision {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailOpen,
    #[default]
    FailClosed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    Errors,
    Denies,
    #[default]
    All,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Observe,
    #[default]
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnforcementSettings {
    #[serde(default)]
    pub file: EnforcementMode,
    #[serde(default)]
    pub process: EnforcementMode,
    #[serde(default)]
    pub network: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyDefaults {
    #[serde(default)]
    pub decision: DefaultDecision,
    #[serde(default)]
    pub fail_mode: FailMode,
    #[serde(default)]
    pub audit_level: AuditLevel,
    #[serde(default)]
    pub enforcement: EnforcementSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyDocument {
    pub version: String,
    #[serde(default)]
    pub defaults: PolicyDefaults,
    #[serde(default)]
    pub profiles: HashMap<String, ProfilePolicy>,
    pub signature: Option<PolicySignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySignature {
    pub key_id: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProfilePolicy {
    #[serde(default)]
    pub workspace_roots: Vec<String>,
    #[serde(default)]
    pub file_allow: Vec<PathRule>,
    #[serde(default)]
    pub file_deny: Vec<PathRule>,
    #[serde(default)]
    pub exec_allow: Vec<ExecRule>,
    #[serde(default)]
    pub exec_deny: Vec<ExecRule>,
    #[serde(default)]
    pub network_allow: Vec<NetworkRule>,
    #[serde(default)]
    pub network_deny: Vec<NetworkRule>,
    #[serde(default)]
    pub url_allow: Vec<UrlRule>,
    #[serde(default)]
    pub url_deny: Vec<UrlRule>,
    #[serde(default)]
    pub mcp: Option<McpPolicy>,
    pub enforcement: Option<EnforcementSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct McpPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_tool_action: Option<McpToolAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_resource_action: Option<McpToolAction>,
    #[serde(default)]
    pub servers: Vec<McpServerPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpServerPolicy {
    pub id: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_path_glob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_tool_action: Option<McpToolAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_resource_action: Option<McpToolAction>,
    #[serde(default)]
    pub tools: McpToolPolicy,
    #[serde(default)]
    pub resources: McpResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct McpToolPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct McpResourcePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpToolAction {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathRule {
    pub id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRule {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    pub id: String,
    pub host_glob: Option<String>,
    pub cidr: Option<IpNet>,
    pub port: Option<u16>,
    pub protocol: Option<NetworkProtocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UrlRule {
    pub id: String,
    pub scheme: Option<String>,
    pub host_glob: String,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub path_glob: String,
    pub query_glob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub action_type: ActionType,
    pub decision: Decision,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
    pub resource: Resource,
    pub profile: String,
    pub policy_version: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpAuditContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelCallAuditContext>,
    #[serde(flatten)]
    pub context: EventContext,
}

/// `agent_id` used for records Mercury emits about itself.
pub const SYSTEM_AGENT_ID: &str = "mercuryd";
/// `profile` used for records Mercury emits about itself.
pub const SYSTEM_PROFILE: &str = "system";

impl AuditEvent {
    /// Builds a `SYSTEM_EVENT` record (daemon lifecycle, policy change,
    /// enrollment change, telemetry loss). Callers set `decision`/`reason`
    /// when the record describes a rejection.
    pub fn system(
        source: &str,
        resource: SystemResource,
        policy_version: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            agent_id: SYSTEM_AGENT_ID.to_string(),
            pid: None,
            ppid: None,
            uid: None,
            action_type: ActionType::SystemEvent,
            decision: Decision::Allow,
            reason: DecisionReason::Informational,
            rule_id: None,
            resource: Resource::System(resource),
            profile: SYSTEM_PROFILE.to_string(),
            policy_version: policy_version.into(),
            message: message.into(),
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: EventContext {
                source: Some(source.to_string()),
                ..EventContext::default()
            },
        }
    }
}

/// Current audit record schema version, stamped by the audit writer.
pub const AUDIT_SCHEMA_VERSION: u32 = 2;

/// Optional context carried by every audit record. Serialized flat into the
/// top level of the JSON object; every field is omitted when unset so v1
/// consumers keep working.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EventContext {
    /// Unique id for this record, assigned by the audit writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Emitting subsystem: `kernel-ebpf`, `apparmor`, `url-gateway`, `mcp`,
    /// `daemon`, `dashboard`, `control-api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Principal that caused the event when it was not the agent itself
    /// (dashboard user, control-socket peer uid, policy sync).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Kernel task name (`comm`, max 15 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,
    /// Pid of the enrollment root (the process that was registered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_id: Option<String>,
    /// Target of ptrace / kill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<u32>,
    /// Kernel policy epoch that produced the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_epoch: Option<u64>,
    /// Joins related records (gateway decision and outcome, approval
    /// request and resolution, model call and its tool calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Outcome of an allowed proxied request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<RequestOutcome>,
    /// The resource could not be fully resolved (path too long, unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// Produced by a dry-run (`TestDecision`); nothing was enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RequestOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub bytes_received: u64,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// One model API exchange observed by the URL gateway.
///
/// Metadata fields (model, tools, usage, finish reason, sizes) are recorded at
/// `capture: metadata`. The content fields (`system`, `messages`,
/// `output_text`, `reasoning_text`, tool call `arguments`) are only populated
/// at `capture: content`, after secret redaction and truncation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ModelCallAuditContext {
    pub call_id: String,
    pub provider: String,
    pub api: String,
    /// `http`, `sse`, or `websocket`.
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_offered: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ModelToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<ModelUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<ModelMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_text: Option<String>,
    /// True when any captured field or buffered body hit a size limit.
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why part of the exchange could not be decoded (encoding, framing, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ModelToolCall {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ModelUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ModelMessage {
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpAuditContext {
    pub server_id: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_uri: Option<String>,
    pub tool_name: String,
    pub tool_call_id: String,
    pub mcp_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegistration {
    pub agent_id: Uuid,
    pub profile: String,
    pub pid: u32,
    pub proc_start_time: u64,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: String,
    pub cmdline: Vec<String>,
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_exec_path: Option<String>,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid action resource for {0:?}")]
    InvalidAction(ActionType),
    #[error("missing profile: {0}")]
    MissingProfile(String),
    #[error("policy version mismatch: expected {expected}, got {got}")]
    PolicyVersionMismatch { expected: &'static str, got: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_type_round_trip_json() {
        let value = ActionType::ProcExec;
        let json = serde_json::to_string(&value).expect("serialize action type");
        assert_eq!(json, "\"PROC_EXEC\"");

        let decoded: ActionType = serde_json::from_str(&json).expect("deserialize action type");
        assert_eq!(decoded, ActionType::ProcExec);
    }

    fn sample_event() -> AuditEvent {
        AuditEvent {
            timestamp: DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            agent_id: "agent-1".to_string(),
            pid: Some(10),
            ppid: Some(1),
            uid: Some(1000),
            action_type: ActionType::FileRename,
            decision: Decision::Deny,
            reason: DecisionReason::DenyByRule,
            rule_id: Some("deny-ssh".to_string()),
            resource: Resource::File(FileResource {
                path: "/tmp/x".to_string(),
                resolved_path: None,
                op: FileOp::Rename,
                source_path: None,
            }),
            profile: "default".to_string(),
            policy_version: "v1".to_string(),
            message: "blocked".to_string(),
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: EventContext::default(),
        }
    }

    #[test]
    fn empty_context_serializes_like_v1() {
        let json = serde_json::to_value(sample_event()).expect("serialize");
        let object = json.as_object().expect("object");
        for key in [
            "event_id",
            "schema_version",
            "comm",
            "context",
            "source_path",
        ] {
            assert!(!object.contains_key(key), "unexpected key {key}");
        }
        assert!(
            !json["resource"]
                .as_object()
                .unwrap()
                .contains_key("source_path")
        );
    }

    #[test]
    fn context_fields_are_flattened_and_round_trip() {
        let mut event = sample_event();
        event.context.comm = Some("bash".to_string());
        event.context.cgroup_id = Some(42);
        event.context.schema_version = Some(AUDIT_SCHEMA_VERSION);
        event.context.outcome = Some(RequestOutcome {
            status: Some(200),
            bytes_sent: 10,
            bytes_received: 20,
            duration_ms: 5,
            error: None,
        });
        if let Resource::File(file) = &mut event.resource {
            file.source_path = Some("/home/u/.ssh/id_rsa".to_string());
        }
        let json = serde_json::to_value(&event).expect("serialize");
        assert_eq!(json["comm"], "bash");
        assert_eq!(json["cgroup_id"], 42);
        assert_eq!(json["outcome"]["status"], 200);
        assert_eq!(json["resource"]["source_path"], "/home/u/.ssh/id_rsa");
        let decoded: AuditEvent = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, event);
    }

    #[test]
    fn v1_record_still_deserializes() {
        let line = r#"{"timestamp":"2026-09-19T00:00:00Z","agent_id":"kernel-pid-7","pid":7,"ppid":null,"uid":0,"action_type":"PROC_EXEC","decision":"ALLOW","reason":"ALLOW_BY_RULE","rule_id":null,"resource":{"kind":"EXEC","path":"/bin/ls","argv_hash":null,"cwd":"/"},"profile":"default","policy_version":"v1","message":"m","kernel_seq":3}"#;
        let decoded: AuditEvent = serde_json::from_str(line).expect("deserialize v1");
        assert_eq!(decoded.context, EventContext::default());
        match decoded.resource {
            Resource::Exec(exec) => assert!(exec.argv.is_empty()),
            other => panic!("unexpected resource {other:?}"),
        }
    }

    #[test]
    fn system_resource_serializes_with_kind_tag() {
        let resource = Resource::System(
            SystemResource::new("telemetry_loss")
                .detail("kernel ring buffer full")
                .attr("dropped", 12u64),
        );
        let json = serde_json::to_value(resource).expect("serialize");
        assert_eq!(json["kind"], "SYSTEM");
        assert_eq!(json["event"], "telemetry_loss");
        assert_eq!(json["attributes"]["dropped"], 12);
        assert_eq!(ActionType::SystemEvent.class(), ActionClass::System);
        assert_eq!(ActionType::ProcBpf.class(), ActionClass::Process);
    }

    #[test]
    fn default_policy_is_deny() {
        let defaults = PolicyDefaults::default();
        assert_eq!(defaults.decision, DefaultDecision::Deny);
        assert_eq!(defaults.fail_mode, FailMode::FailClosed);
    }
}
