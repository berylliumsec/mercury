export type HookStatus = {
  exec_hook: string;
  network_hook: string;
  filesystem_hook: string;
};

export type CoverageStatus = {
  action_type: string;
  action_class: string;
  backend: string;
  status: string;
};

export type TlsCertInfo = {
  cert_file: string;
  key_file: string;
  /** RFC 3339 expiry timestamp */
  expires_at: string;
  issuer: string;
  is_self_signed: boolean;
};

export type StatusSummary = {
  daemon_up: boolean;
  policy_version: string;
  backend_mode: string;
  kernel_ready: boolean;
  kernel_program_version: string;
  auto_enroll_active_rules: number;
  unmatched_mode: string;
  hook_status: HookStatus;
  dashboard_enabled: boolean;
  dashboard_ready: boolean;
  dashboard_url?: string;
  dashboard_error?: string;
  url_gateway_enabled: boolean;
  url_gateway_ready: boolean;
  url_gateway_http_proxy?: string;
  url_gateway_https_proxy?: string;
  url_gateway_error?: string;
  events_ingested_total: number;
  events_dropped_queue_total: number;
  unenrolled_events_suppressed_total: number;
  ingest_backlog_len: number;
  enrollment_sync_error?: string;
  dashboard_schema_version: string;
  policy_versions_total: number;
  pending_mcp_approvals: number;
  active_dashboard_sessions: number;
  active_sse_clients: number;
  active_mcp_sessions: number;
  dashboard_sqlite_bytes: number;
  coverage: CoverageStatus[];
  tls_cert_info?: TlsCertInfo;
  apparmor_enabled: boolean;
  apparmor_parser_present: boolean;
  /* Telemetry-loss and audit health (absent on older daemons). */
  events_dropped_ringbuf_total?: number;
  kernel_events_rate_limited_total?: number;
  kernel_deny_events_dropped_total?: number;
  audit_write_failures_total?: number;
  audit_mirror_failures_total?: number;
  apparmor_records_lost_total?: number;
  policy_reload_failures_total?: number;
  policy_sync_last_error?: string | null;
  telemetry_degraded_reasons?: string[];
  backpressure_active?: boolean;
  backpressure_activations_total?: number;
  auth_failures_total?: number;
  dashboard_action_record_failures_total?: number;
  sse_events_skipped_total?: number;
  /** Conditions under which enforcement or recording is incomplete; empty when healthy. */
  degraded_reasons?: string[];
};

export type PolicyDraft = {
  id: string;
  etag: string;
  document: unknown;
  yaml?: string;
  created_at: string;
  updated_at: string;
};

export type ApplyPolicyResponse = {
  success: boolean;
  version: string;
  version_id: string | null;
  errors: string[];
  warnings: string[];
};

export type EventListResponse<T> = {
  total: number;
  items: T[];
};

export type StatsBucket = {
  minute: string;
  allow: number;
  deny: number;
  observe: number;
};

export type StatsResponse = {
  buckets: StatsBucket[];
  top_blocked_resources: Array<{ resource: string; count: number }>;
};

export type Enrollment = {
  pid: number;
  profile: string;
  source: string;
  mode: string;
  cgroup_id: string;
  agent_id: string;
  uid: number;
};

export type PolicyVersion = {
  id: string;
  created_at: string;
  created_by: string;
  source_draft_id?: string;
  checksum: string;
  summary: string;
  rolled_back_from?: string;
  active: boolean;
};

export type DashboardActionItem = {
  id: number;
  ts: string;
  action: string;
  actor: string;
  details: string;
  /** "success" or "failure"; absent on older daemons. */
  outcome?: string;
  source_ip?: string | null;
  user_agent?: string | null;
  session_id_hash?: string | null;
};

export type ValidationResult = {
  valid: boolean;
  warnings: string[];
  errors: string[];
};

export type LoginResponse = {
  csrf_token: string;
  expires_at: string;
};

export type AuthMeResponse = {
  authenticated: boolean;
  setup_required: boolean;
  username?: string;
  expires_at?: string;
  csrf_token?: string;
};

export type StreamStatus = "connecting" | "connected" | "reconnecting" | "disconnected";

export type LaunchAgentRequest = {
  profile: string;
  executable?: string;
  args?: string[];
  command?: string[];
  cwd?: string;
};

export type LaunchAgentResponse = {
  agent_id: string;
  pid: number;
  cgroup_id: string;
};

export type RunningAgent = {
  agent_id: string;
  pid: number;
  profile: string;
  cmdline: string[];
  cwd: string;
  uid: number;
};

export type RecentAgentLaunch = {
  launch_id: string;
  agent_id?: string | null;
  pid?: number | null;
  profile: string;
  cmdline: string[];
  cwd: string;
  operator: string;
  launch_user: string;
  started_at: string;
  finished_at: string;
  status: string;
  exit_code?: number | null;
  signal?: number | null;
  error?: string | null;
  stderr_tail?: string | null;
};

export type McpApproval = {
  kind: string;
  request_id: string;
  created_at: string;
  expires_at: string;
  agent_id: string;
  profile: string;
  server_id: string;
  transport: string;
  mcp_session_id: string;
  resource_uri?: string;
  client_request_id?: string;
  tool_name: string;
  tool_call_id: string;
  arguments_json: string;
  arguments_sha256: string;
  arguments_summary?: string;
  rule_id?: string;
};
