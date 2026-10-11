import yaml from "js-yaml";

import type {
  AuthMeResponse,
  DashboardActionItem,
  Enrollment,
  EventListResponse,
  LoginResponse,
  McpApproval,
  PolicyDraft,
  PolicyVersion,
  RecentAgentLaunch,
  RunningAgent,
  StatsResponse,
  StatusSummary,
  TlsCertInfo,
  ValidationResult
} from "../dashboardTypes";
import { buildActionsCsv } from "../actionsCsv";
import { csvEscape } from "../dashboardUi";
import type { EventItem } from "../eventHelpers";
import { eventMatchesFilters, type EventFilters } from "../eventsSearch";
import {
  emptyProfilePolicy,
  normalizePolicyDocument,
  type ExecRule,
  type NetworkRule,
  type PathRule,
  type PolicyDocument,
  type ProfilePolicy,
  type UrlRule
} from "../policyHelpers";
import { isStaticDemoMode } from "./demoMode";

type DemoDraftRecord = PolicyDraft & {
  document: PolicyDocument;
};

type DemoVersionRecord = PolicyVersion & {
  document: PolicyDocument;
};

type DemoState = {
  authenticated: boolean;
  username: string;
  password: string;
  csrfToken: string;
  activePolicy: PolicyDocument;
  drafts: Record<string, DemoDraftRecord>;
  versions: DemoVersionRecord[];
  actions: DashboardActionItem[];
  approvals: McpApproval[];
  enrollments: Enrollment[];
  agents: RunningAgent[];
  launchHistory: RecentAgentLaunch[];
  events: EventItem[];
  tlsCertInfo: TlsCertInfo;
  nextActionId: number;
  nextEventId: number;
  nextPid: number;
};

type QuickRuleResponse = {
  success: boolean;
  already_exists: boolean;
  version: string;
  errors: string[];
  rule_description: string;
};

type DemoQuickRuleTarget = {
  action_type: string;
  resource_json: string;
  profile: string;
  direction: "allow" | "deny" | "require_approval";
};

type EventSubscriber = (item: EventItem) => void;

const JSON_HEADERS = { "Content-Type": "application/json" };
const STREAM_HEADERS = {
  "Content-Type": "text/event-stream",
  "Cache-Control": "no-store",
  Connection: "keep-alive"
};
const ONE_MINUTE = 60_000;
const ONE_DAY = 24 * 60 * ONE_MINUTE;
const STREAM_INTERVAL_MS = 4_000;
const MAX_EVENT_COUNT = 180;

let demoState: DemoState | null = null;
let liveTemplateCursor = 0;
let liveTicker: ReturnType<typeof setInterval> | null = null;
const eventSubscribers = new Set<EventSubscriber>();

function clone<T>(value: T): T {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value)) as T;
}

function nextId(prefix: string): string {
  const random = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${random}`;
}

function nowIso(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function toPolicyVersion(version: DemoVersionRecord): PolicyVersion {
  return {
    id: version.id,
    created_at: version.created_at,
    created_by: version.created_by,
    source_draft_id: version.source_draft_id,
    checksum: version.checksum,
    summary: version.summary,
    rolled_back_from: version.rolled_back_from,
    active: version.active
  };
}

function withMinutesAgo(minutesAgo: number, seconds = 0): string {
  return new Date(Date.now() - minutesAgo * ONE_MINUTE - seconds * 1000).toISOString();
}

function fileResource(path: string) {
  return { kind: "FILE", path };
}

function execResource(path: string) {
  return { kind: "EXEC", path };
}

function networkResource(host: string, port: number, fullUrl?: string) {
  return fullUrl
    ? { kind: "NETWORK", dest_host: host, dest_port: port, full_url: fullUrl }
    : { kind: "NETWORK", dest_host: host, dest_port: port };
}

function mcpResource(serverId: string, toolName: string) {
  return { kind: "MCP_TOOL", server_id: serverId, tool_name: toolName };
}

function formatResource(resource: Record<string, unknown>): string {
  const kind = String(resource.kind ?? "").toUpperCase();
  if (kind === "FILE" || kind === "EXEC") {
    return `${kind === "FILE" ? "file" : "exec"}:${String(resource.path ?? "")}`;
  }
  if (kind === "NETWORK") {
    if (typeof resource.full_url === "string" && resource.full_url.length > 0) {
      return `url:${resource.full_url}`;
    }
    const host = String(resource.dest_host ?? "");
    const port = String(resource.dest_port ?? "");
    return `net:${host}${port ? `:${port}` : ""}`;
  }
  if (kind === "MCP_TOOL") {
    return `mcp:${String(resource.server_id ?? "server")}:${String(resource.tool_name ?? "tool")}`;
  }
  return JSON.stringify(resource);
}

/** Adds audit schema v2 context fields (comm, actor, ...) to a seeded event's raw record. */
function withContext(item: EventItem, context: Record<string, unknown>): EventItem {
  return {
    ...item,
    raw_json: { ...(item.raw_json as Record<string, unknown>), ...context }
  };
}

function createEvent(
  id: number,
  config: {
    timestamp: string;
    effectiveDecision: "allow" | "deny" | "observe";
    actionClass: string;
    actionType: string;
    profile: string;
    pid?: number;
    agentId?: string;
    ruleId?: string;
    resource: Record<string, unknown>;
    reason: string;
    message: string;
    model?: Record<string, unknown>;
  }
): EventItem {
  return {
    id,
    timestamp: config.timestamp,
    decision: config.effectiveDecision,
    effective_decision: config.effectiveDecision,
    action_class: config.actionClass,
    action_type: config.actionType,
    profile: config.profile,
    pid: config.pid,
    agent_id: config.agentId,
    rule_id: config.ruleId,
    resource: formatResource(config.resource),
    resource_json: JSON.stringify(config.resource),
    reason: config.reason,
    message: config.message,
    raw_json: {
      timestamp: config.timestamp,
      effective_decision: config.effectiveDecision,
      action_class: config.actionClass,
      action_type: config.actionType,
      profile: config.profile,
      pid: config.pid,
      agent_id: config.agentId,
      rule_id: config.ruleId,
      resource: config.resource,
      reason: config.reason,
      message: config.message,
      model: config.model
    }
  };
}

// Model-call contexts as the URL gateway records them: the assistant call was
// captured at `content` level, the summariser at `metadata` level.
const DEMO_CONTENT_MODEL_CALL = {
  call_id: "mc_9d41f0",
  provider: "anthropic",
  api: "anthropic.messages",
  transport: "sse",
  model: "claude-opus-5",
  stream: true,
  status: 200,
  duration_ms: 8123,
  request_bytes: 18_944,
  response_bytes: 6_210,
  request_sha256: "9f2c41ab7d0e5c18",
  message_count: 14,
  tools_offered: ["Bash", "Read", "Write"],
  tool_calls: [
    {
      name: "Read",
      id: "toolu_014c",
      arguments: '{"path":"/workspace/assistant/docs/architecture.md"}'
    }
  ],
  finish_reason: "tool_use",
  usage: {
    input_tokens: 5120,
    output_tokens: 210,
    cache_read_tokens: 4800,
    reasoning_tokens: 64
  },
  system: "You are the release assistant for the demo workspace. Never read secrets.",
  messages: [
    {
      role: "user",
      text: "Summarise the architecture doc and tell me which services changed this week."
    },
    {
      role: "assistant",
      text: 'I\'ll read the doc first.\n[tool_use Read] {"path":"/workspace/assistant/docs/architecture.md"}'
    },
    {
      role: "tool",
      text: "[tool_result] # Architecture\nThe gateway terminates TLS and forwards to the policy engine…"
    },
    {
      role: "user",
      text: "Also check whether the release bucket is still reachable. My token is [REDACTED]."
    }
  ],
  output_text:
    "The architecture doc covers three services: the URL gateway, the policy engine and the dashboard. Reading the workspace notes next.",
  reasoning_text: "The doc is short enough to read in one pass before answering.",
  truncated: true
};

const DEMO_METADATA_MODEL_CALL = {
  call_id: "mc_31b7ac",
  provider: "openai",
  api: "openai.responses",
  transport: "http",
  model: "gpt-5-mini",
  stream: false,
  status: 200,
  duration_ms: 940,
  request_bytes: 3_120,
  response_bytes: 1_480,
  request_sha256: "41c8ee90b2a35d77",
  message_count: 3,
  tools_offered: [],
  tool_calls: [],
  finish_reason: "stop",
  usage: { input_tokens: 812, output_tokens: 96, total_tokens: 908 },
  messages: [],
  truncated: false
};

function createSeedPolicy(): PolicyDocument {
  return {
    version: "v1",
    defaults: {
      decision: "deny",
      fail_mode: "fail_closed",
      audit_level: "all",
      enforcement: {
        file: "enforce",
        process: "enforce",
        network: "enforce"
      }
    },
    profiles: {
      default: {
        workspace_roots: ["/workspace/assistant", "/workspace/releases"],
        file_allow: [
          { id: "allow_workspace_docs", pattern: "/workspace/assistant/**" },
          { id: "allow_release_notes", pattern: "/workspace/releases/**" }
        ],
        file_deny: [{ id: "deny_operator_secrets", pattern: "/workspace/assistant/secrets/**" }],
        exec_allow: [
          { id: "allow_python", path: "/usr/bin/python3" },
          { id: "allow_git", path: "/usr/bin/git" }
        ],
        exec_deny: [{ id: "deny_netcat", path: "/usr/bin/nc" }],
        network_allow: [
          { id: "allow_openai_api", host_glob: "*api.openai.com*", port: 443, protocol: "TCP" },
          { id: "allow_github_https", host_glob: "*github.com*", port: 443, protocol: "TCP" }
        ],
        network_deny: [
          { id: "deny_demo_database", cidr: "10.20.0.0/16", port: 5432, protocol: "TCP" }
        ],
        url_allow: [
          {
            id: "allow_internal_guides",
            scheme: "https",
            host_glob: "docs.example.internal",
            port: 443,
            method: "GET",
            path_glob: "/guides/**"
          }
        ],
        url_deny: [
          {
            id: "deny_release_bucket",
            scheme: "https",
            host_glob: "releases.example.test",
            port: 443,
            method: "GET",
            path_glob: "/blocked/**"
          }
        ],
        mcp: {
          default_tool_action: "require_approval",
          default_resource_action: "deny",
          servers: [
            {
              id: "github",
              transport: "stdio",
              exec_path_glob: "/usr/bin/github-mcp",
              default_tool_action: "require_approval",
              default_resource_action: "require_approval",
              tools: {
                allow: ["search_issues", "list_pull_requests"],
                deny: ["delete_repository"],
                require_approval: ["create_pull_request", "merge_pull_request"]
              },
              resources: {
                allow: ["repo://openai/mercury/issues/**"],
                deny: ["repo://openai/mercury/secrets/**"],
                require_approval: ["repo://openai/mercury/pulls/**"]
              }
            }
          ]
        },
        enforcement: {
          file: "enforce",
          process: "enforce",
          network: "enforce"
        }
      },
      browser_agent: {
        workspace_roots: ["/workspace/browser"],
        file_allow: [{ id: "allow_browser_workspace", pattern: "/workspace/browser/**" }],
        file_deny: [{ id: "deny_browser_tokens", pattern: "/workspace/browser/tokens/**" }],
        exec_allow: [
          { id: "allow_chromium", path: "/usr/bin/chromium-browser" },
          { id: "allow_node", path: "/usr/bin/node" }
        ],
        exec_deny: [{ id: "deny_shell_out", path: "/usr/bin/bash" }],
        network_allow: [
          {
            id: "allow_customer_portal",
            host_glob: "*customer.example.com*",
            port: 443,
            protocol: "TCP"
          }
        ],
        network_deny: [
          { id: "deny_metadata_ip", cidr: "169.254.169.254/32", port: 80, protocol: "TCP" }
        ],
        url_allow: [
          {
            id: "allow_customer_docs",
            scheme: "https",
            host_glob: "customer.example.com",
            port: 443,
            method: "GET",
            path_glob: "/docs/**"
          }
        ],
        url_deny: [
          {
            id: "deny_social_media",
            scheme: "https",
            host_glob: "*.social.example",
            port: 443,
            method: "GET",
            path_glob: "/**"
          }
        ],
        enforcement: {
          file: "enforce",
          process: "observe",
          network: "enforce"
        }
      },
      release_bot: {
        workspace_roots: ["/workspace/releases"],
        file_allow: [{ id: "allow_release_workspace", pattern: "/workspace/releases/**" }],
        file_deny: [{ id: "deny_prod_keys", pattern: "/workspace/releases/keys/**" }],
        exec_allow: [
          { id: "allow_tar", path: "/usr/bin/tar" },
          { id: "allow_sha256sum", path: "/usr/bin/sha256sum" }
        ],
        exec_deny: [{ id: "deny_curl_release_bot", path: "/usr/bin/curl" }],
        network_allow: [
          {
            id: "allow_release_registry",
            host_glob: "*packages.example.test*",
            port: 443,
            protocol: "TCP"
          }
        ],
        network_deny: [{ id: "deny_public_uploads", cidr: "0.0.0.0/0", port: 21, protocol: "TCP" }],
        url_allow: [
          {
            id: "allow_release_upload",
            scheme: "https",
            host_glob: "packages.example.test",
            port: 443,
            method: "PUT",
            path_glob: "/artifacts/**"
          }
        ],
        url_deny: [
          {
            id: "deny_release_delete",
            scheme: "https",
            host_glob: "packages.example.test",
            port: 443,
            method: "DELETE",
            path_glob: "/artifacts/**"
          }
        ],
        enforcement: {
          file: "enforce",
          process: "enforce",
          network: "enforce"
        }
      }
    },
    signature: null
  };
}

function createPolicyVariant(summaryRuleId: string): PolicyDocument {
  const policy = createSeedPolicy();
  if (summaryRuleId === "pre_release_guard") {
    policy.profiles.release_bot.network_deny.push({
      id: "deny_staging_registry",
      host_glob: "*staging-packages.example.test*",
      port: 443,
      protocol: "TCP"
    });
  }
  if (summaryRuleId === "browser_lockdown") {
    policy.profiles.browser_agent.url_deny.push({
      id: "deny_browser_uploads",
      scheme: "https",
      host_glob: "customer.example.com",
      port: 443,
      method: "POST",
      path_glob: "/upload/**"
    });
  }
  return policy;
}

function createSeedEvents(): EventItem[] {
  const rows = [
    createEvent(4103, {
      timestamp: withMinutesAgo(0, 12),
      effectiveDecision: "allow",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "allow_model_apis",
      resource: networkResource("api.anthropic.com", 443, "https://api.anthropic.com/v1/messages"),
      reason: "ALLOW_BY_RULE",
      message: "model call provider=anthropic model=claude-opus-5 status=200 duration_ms=8123",
      model: DEMO_CONTENT_MODEL_CALL
    }),
    createEvent(4102, {
      timestamp: withMinutesAgo(0, 26),
      effectiveDecision: "allow",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "browser_agent",
      pid: 4930,
      agentId: "agt_demo_browser",
      ruleId: "allow_model_apis",
      resource: networkResource("api.openai.com", 443, "https://api.openai.com/v1/responses"),
      reason: "ALLOW_BY_RULE",
      message: "model call provider=openai model=gpt-5-mini status=200 duration_ms=940",
      model: DEMO_METADATA_MODEL_CALL
    }),
    createEvent(4101, {
      timestamp: withMinutesAgo(0, 35),
      effectiveDecision: "deny",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "deny_release_bucket",
      resource: networkResource(
        "releases.example.test",
        443,
        "https://releases.example.test/blocked/changelog.json"
      ),
      reason: "DENY_BY_RULE",
      message: "URL deny rule blocked a release bucket request."
    }),
    createEvent(4100, {
      timestamp: withMinutesAgo(1, 8),
      effectiveDecision: "deny",
      actionClass: "file",
      actionType: "FILE_READ",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "deny_operator_secrets",
      resource: fileResource("/workspace/assistant/secrets/prod.env"),
      reason: "DENY_BY_RULE",
      message: "Secret material stayed blocked inside the assistant workspace."
    }),
    createEvent(4099, {
      timestamp: withMinutesAgo(1, 44),
      effectiveDecision: "allow",
      actionClass: "process",
      actionType: "PROC_EXEC",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "allow_git",
      resource: execResource("/usr/bin/git"),
      reason: "ALLOW_BY_RULE",
      message: "Git stayed available for repository operations."
    }),
    createEvent(4098, {
      timestamp: withMinutesAgo(2, 10),
      effectiveDecision: "deny",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "deny_demo_database",
      resource: networkResource("10.20.14.22", 5432),
      reason: "DENY_BY_RULE",
      message: "Direct database access was denied by network policy."
    }),
    createEvent(4097, {
      timestamp: withMinutesAgo(2, 45),
      effectiveDecision: "observe",
      actionClass: "mcp",
      actionType: "MCP_TOOL_CALL",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      resource: mcpResource("github", "create_pull_request"),
      reason: "REQUIRES_APPROVAL",
      message: "The GitHub MCP server requested approval before opening a pull request."
    }),
    createEvent(4096, {
      timestamp: withMinutesAgo(3, 14),
      effectiveDecision: "allow",
      actionClass: "file",
      actionType: "FILE_READ",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "allow_workspace_docs",
      resource: fileResource("/workspace/assistant/docs/architecture.md"),
      reason: "ALLOW_BY_RULE",
      message: "Documentation reads are allowed inside the workspace."
    }),
    createEvent(4095, {
      timestamp: withMinutesAgo(4, 5),
      effectiveDecision: "deny",
      actionClass: "process",
      actionType: "PROC_EXEC",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      ruleId: "deny_netcat",
      resource: execResource("/usr/bin/nc"),
      reason: "DENY_BY_RULE",
      message: "Unexpected socket tooling stayed blocked."
    }),
    createEvent(4094, {
      timestamp: withMinutesAgo(5, 20),
      effectiveDecision: "allow",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "browser_agent",
      pid: 4930,
      agentId: "agt_demo_browser",
      ruleId: "allow_customer_docs",
      resource: networkResource(
        "customer.example.com",
        443,
        "https://customer.example.com/docs/getting-started"
      ),
      reason: "ALLOW_BY_RULE",
      message: "Customer documentation remained reachable."
    }),
    createEvent(4093, {
      timestamp: withMinutesAgo(6, 10),
      effectiveDecision: "deny",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "browser_agent",
      pid: 4930,
      agentId: "agt_demo_browser",
      ruleId: "deny_social_media",
      resource: networkResource("feed.social.example", 443, "https://feed.social.example/home"),
      reason: "DENY_BY_RULE",
      message: "A social-media destination was blocked during browsing."
    }),
    createEvent(4092, {
      timestamp: withMinutesAgo(7, 6),
      effectiveDecision: "deny",
      actionClass: "file",
      actionType: "FILE_READ",
      profile: "browser_agent",
      pid: 4930,
      agentId: "agt_demo_browser",
      ruleId: "deny_browser_tokens",
      resource: fileResource("/workspace/browser/tokens/session.json"),
      reason: "DENY_BY_RULE",
      message: "Browser session tokens stayed protected."
    }),
    createEvent(4091, {
      timestamp: withMinutesAgo(8, 12),
      effectiveDecision: "allow",
      actionClass: "process",
      actionType: "PROC_EXEC",
      profile: "release_bot",
      pid: 5051,
      agentId: "agt_demo_release",
      ruleId: "allow_tar",
      resource: execResource("/usr/bin/tar"),
      reason: "ALLOW_BY_RULE",
      message: "Release packaging continued under explicit exec allow rules."
    }),
    createEvent(4090, {
      timestamp: withMinutesAgo(9, 28),
      effectiveDecision: "deny",
      actionClass: "network",
      actionType: "NET_CONNECT",
      profile: "release_bot",
      pid: 5051,
      agentId: "agt_demo_release",
      ruleId: "deny_release_delete",
      resource: networkResource(
        "packages.example.test",
        443,
        "https://packages.example.test/artifacts/v1.4.2"
      ),
      reason: "DENY_BY_RULE",
      message: "Release deletion was blocked by URL policy."
    }),
    createEvent(4089, {
      timestamp: withMinutesAgo(10, 18),
      effectiveDecision: "observe",
      actionClass: "network",
      actionType: "NET_SENDMSG",
      profile: "default",
      pid: 4812,
      agentId: "agt_demo_assistant",
      resource: networkResource("8.8.8.8", 53),
      reason: "OBSERVE_ONLY",
      message: "DNS telemetry was observed for investigation."
    }),
    createEvent(4088, {
      timestamp: withMinutesAgo(11, 5),
      effectiveDecision: "allow",
      actionClass: "file",
      actionType: "FILE_WRITE",
      profile: "release_bot",
      pid: 5051,
      agentId: "agt_demo_release",
      ruleId: "allow_release_workspace",
      resource: fileResource("/workspace/releases/out/build.sha256"),
      reason: "ALLOW_BY_RULE",
      message: "Release output writes remained in the approved workspace."
    }),
    withContext(
      createEvent(4087, {
        timestamp: withMinutesAgo(11, 40),
        effectiveDecision: "allow",
        actionClass: "process",
        actionType: "PROC_START",
        profile: "release_bot",
        pid: 5051,
        agentId: "agt_demo_release",
        resource: {
          kind: "EXEC",
          path: "/usr/bin/make",
          argv_hash: null,
          cwd: "/workspace/releases",
          argv: ["make", "-j4", "release", "VERSION=1.8.0"]
        },
        reason: "ALLOW_BY_RULE",
        message: "process started"
      }),
      { comm: "make", ppid: 5020, tid: 5051, cgroup_id: 18244, source: "kernel-ebpf" }
    ),
    withContext(
      createEvent(4086, {
        timestamp: withMinutesAgo(12, 2),
        effectiveDecision: "allow",
        actionClass: "system",
        actionType: "SYSTEM_EVENT",
        profile: "system",
        agentId: "mercuryd",
        resource: {
          kind: "SYSTEM",
          event: "dashboard_action",
          detail: "policy_apply",
          attributes: {
            action: "policy_apply",
            outcome: "success",
            source_ip: "10.20.0.14",
            user_agent: "Mozilla/5.0",
            details: "draft_id=demo version=ver_demo_current_9f6cbf21"
          }
        },
        reason: "INFORMATIONAL",
        message: "dashboard action policy_apply by demo.operator (success)"
      }),
      { actor: "demo.operator", source: "dashboard" }
    )
  ];

  return rows.sort((left, right) => right.id - left.id);
}

function createSeedVersions(): DemoVersionRecord[] {
  const oldest = createPolicyVariant("browser_lockdown");
  const middle = createPolicyVariant("pre_release_guard");
  const current = createSeedPolicy();
  return [
    {
      id: "ver_demo_current_9f6cbf21",
      created_at: nowIso(-12 * ONE_MINUTE),
      created_by: "demo.operator",
      checksum: "1b5b7c3d4a7f-demo-current",
      summary: "Locked release bucket URL path and tightened default secrets deny.",
      active: true,
      document: current
    },
    {
      id: "ver_demo_prev_42aa9e10",
      created_at: nowIso(-48 * ONE_MINUTE),
      created_by: "release.bot",
      checksum: "c337a0f102bb-demo-prev",
      summary: "Added staging registry and packaging guardrails for release bot.",
      active: false,
      document: middle
    },
    {
      id: "ver_demo_bootstrap_140e3d77",
      created_at: nowIso(-130 * ONE_MINUTE),
      created_by: "bootstrap",
      checksum: "09117d0af873-demo-bootstrap",
      summary: "Initial hosted demo policy with browser lockdown examples.",
      active: false,
      document: oldest
    }
  ];
}

function createSeedActions(): DashboardActionItem[] {
  return [
    {
      id: 3014,
      ts: nowIso(-8 * ONE_MINUTE),
      action: "policy.apply",
      actor: "demo.operator",
      details: "Applied ver_demo_current_9f6cbf21 with release bucket deny update"
    },
    {
      id: 3013,
      ts: nowIso(-17 * ONE_MINUTE),
      action: "quick_rule.deny",
      actor: "demo.operator",
      details: "Blocked /workspace/assistant/secrets/prod.env from live event"
    },
    {
      id: 3012,
      ts: nowIso(-38 * ONE_MINUTE),
      action: "approval.approve",
      actor: "release.lead",
      details: "Approved github/create_pull_request for profile default"
    },
    {
      id: 3011,
      ts: nowIso(-56 * ONE_MINUTE),
      action: "policy.rollback",
      actor: "demo.operator",
      details: "Rolled back ver_demo_prev_42aa9e10 after browser upload regression"
    },
    {
      id: 3010,
      ts: nowIso(-71 * ONE_MINUTE),
      action: "login_failed",
      actor: "anonymous",
      details: "invalid credentials attempted_user=root",
      outcome: "failure",
      source_ip: "203.0.113.9",
      user_agent: "python-requests/2.32"
    }
  ];
}

function createSeedApprovals(): McpApproval[] {
  return [
    {
      kind: "tool",
      request_id: "apr_demo_pr_01",
      created_at: nowIso(-2 * ONE_MINUTE),
      expires_at: nowIso(18 * ONE_MINUTE),
      agent_id: "agt_demo_assistant",
      profile: "default",
      server_id: "github",
      transport: "stdio",
      mcp_session_id: "mcp_demo_session_1",
      tool_name: "create_pull_request",
      tool_call_id: "call_demo_pr_1",
      arguments_json: JSON.stringify(
        {
          repo: "openai/mercury",
          title: "Lock release bucket by URL rule",
          base: "main",
          head: "demo/release-guard"
        },
        null,
        2
      ),
      arguments_sha256: "5f4c0c56a4d5d7c2d6c4f8f8f4f32d56",
      arguments_summary: "create_pull_request openai/mercury demo/release-guard",
      rule_id: "github_require_approval"
    },
    {
      kind: "tool",
      request_id: "apr_demo_merge_02",
      created_at: nowIso(-1 * ONE_MINUTE),
      expires_at: nowIso(25 * ONE_MINUTE),
      agent_id: "agt_demo_release",
      profile: "release_bot",
      server_id: "github",
      transport: "stdio",
      mcp_session_id: "mcp_demo_session_2",
      tool_name: "merge_pull_request",
      tool_call_id: "call_demo_merge_2",
      arguments_json: JSON.stringify(
        {
          repo: "openai/mercury",
          pull_number: 142,
          merge_method: "squash"
        },
        null,
        2
      ),
      arguments_sha256: "8a4ec347eb0e93417d9e8af7d8af2719",
      arguments_summary: "merge_pull_request openai/mercury #142",
      rule_id: "github_require_approval"
    }
  ];
}

function createSeedEnrollments(): Enrollment[] {
  return [
    {
      pid: 4812,
      profile: "default",
      source: "mercury-run",
      mode: "enforce",
      cgroup_id: "mercury/agents/ai-demo-assistant",
      agent_id: "agt_demo_assistant",
      uid: 1000
    },
    {
      pid: 4930,
      profile: "browser_agent",
      source: "mercury-run",
      mode: "enforce",
      cgroup_id: "mercury/agents/ai-demo-browser",
      agent_id: "agt_demo_browser",
      uid: 1000
    },
    {
      pid: 5051,
      profile: "release_bot",
      source: "auto_enroll",
      mode: "enforce",
      cgroup_id: "mercury/agents/ai-demo-release",
      agent_id: "agt_demo_release",
      uid: 1001
    },
    {
      pid: 5178,
      profile: "default",
      source: "auto_enroll",
      mode: "observe",
      cgroup_id: "mercury/agents/ai-demo-worker",
      agent_id: "agt_demo_worker",
      uid: 1000
    }
  ];
}

function createSeedAgents(): RunningAgent[] {
  return [
    {
      agent_id: "agt_demo_assistant",
      pid: 4812,
      profile: "default",
      cmdline: ["/usr/bin/python3", "-m", "assistant.server", "--port", "8088"],
      cwd: "/workspace/assistant",
      uid: 1000
    },
    {
      agent_id: "agt_demo_browser",
      pid: 4930,
      profile: "browser_agent",
      cmdline: ["/usr/bin/node", "/workspace/browser/worker.mjs"],
      cwd: "/workspace/browser",
      uid: 1000
    }
  ];
}

function createSeedLaunchHistory(): RecentAgentLaunch[] {
  return [
    {
      launch_id: "launch_demo_1",
      agent_id: "agt_demo_release",
      pid: 5051,
      profile: "release_bot",
      cmdline: ["/usr/bin/python3", "-m", "release.publisher", "--channel", "stable"],
      cwd: "/workspace/releases",
      operator: "demo.operator",
      launch_user: "mercury",
      started_at: nowIso(-55 * ONE_MINUTE),
      finished_at: nowIso(-51 * ONE_MINUTE),
      status: "exited",
      exit_code: 0,
      signal: null,
      error: null,
      stderr_tail: null
    },
    {
      launch_id: "launch_demo_2",
      agent_id: null,
      pid: null,
      profile: "default",
      cmdline: ["/usr/bin/python3", "-m", "assistant.check"],
      cwd: "/workspace/assistant",
      operator: "demo.operator",
      launch_user: "mercury",
      started_at: nowIso(-94 * ONE_MINUTE),
      finished_at: nowIso(-94 * ONE_MINUTE + 12_000),
      status: "failed",
      exit_code: null,
      signal: null,
      error: "Executable path was denied by policy before launch.",
      stderr_tail: "permission denied"
    }
  ];
}

function createSeedTlsInfo(): TlsCertInfo {
  return {
    cert_file: "/etc/mercury/dashboard.crt",
    key_file: "/etc/mercury/dashboard.key",
    expires_at: nowIso(41 * ONE_DAY),
    issuer: "Demo Internal CA",
    is_self_signed: false
  };
}

function createInitialState(): DemoState {
  const versions = createSeedVersions();
  const activeVersion = versions.find((version) => version.active) ?? versions[0];
  const events = createSeedEvents();
  const actions = createSeedActions();

  return {
    authenticated: true,
    username: "admin",
    password: "mercury-demo",
    csrfToken: nextId("csrf"),
    activePolicy: clone(activeVersion.document),
    drafts: {},
    versions,
    actions,
    approvals: createSeedApprovals(),
    enrollments: createSeedEnrollments(),
    agents: createSeedAgents(),
    launchHistory: createSeedLaunchHistory(),
    events,
    tlsCertInfo: createSeedTlsInfo(),
    nextActionId: Math.max(...actions.map((item) => item.id)) + 1,
    nextEventId: Math.max(...events.map((item) => item.id)) + 1,
    nextPid: 5300
  };
}

function getState(): DemoState {
  if (!demoState) {
    demoState = createInitialState();
  }
  return demoState;
}

export function resetStaticDemoState(): void {
  demoState = createInitialState();
  liveTemplateCursor = 0;
}

function jsonResponse(payload: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      ...JSON_HEADERS,
      ...(init?.headers ?? {})
    }
  });
}

function noContent(init?: ResponseInit): Response {
  return new Response(null, {
    status: 204,
    ...init
  });
}

function badRequest(message: string, status = 400): Response {
  return jsonResponse({ message }, { status });
}

function getRequestHeaders(init?: RequestInit): Headers {
  return new Headers(init?.headers ?? {});
}

function requireCsrf(state: DemoState, headers: Headers): Response | null {
  const csrf = headers.get("x-csrf-token")?.trim();
  if (!csrf || csrf !== state.csrfToken) {
    return badRequest("Missing or invalid CSRF token.", 403);
  }
  return null;
}

function parseRequestBody(init?: RequestInit): unknown {
  const raw = init?.body;
  if (raw == null) {
    return null;
  }
  if (typeof raw === "string") {
    return raw.length ? JSON.parse(raw) : null;
  }
  return null;
}

function serializePolicy(document: PolicyDocument): string {
  return yaml.dump(document, { lineWidth: 120, noRefs: true, sortKeys: false });
}

function addAction(
  state: DemoState,
  action: string,
  details: string,
  actor = "demo.operator"
): void {
  state.actions.unshift({
    id: state.nextActionId,
    ts: nowIso(),
    action,
    actor,
    details,
    outcome: "success",
    source_ip: "10.20.0.14",
    user_agent: "Mozilla/5.0"
  });
  state.nextActionId += 1;
  state.actions = state.actions.slice(0, 40);
}

function addEvent(
  state: DemoState,
  event: Omit<EventItem, "id" | "timestamp"> & { timestamp?: string }
): EventItem {
  const item: EventItem = {
    ...event,
    id: state.nextEventId,
    timestamp: event.timestamp ?? nowIso()
  };
  state.nextEventId += 1;
  state.events.unshift(item);
  state.events = state.events.slice(0, MAX_EVENT_COUNT);
  return item;
}

function buildStats(events: EventItem[]): StatsResponse {
  const bucketCount = 12;
  const now = Date.now();
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    minute: new Date(now - (bucketCount - index - 1) * ONE_MINUTE).toISOString(),
    allow: 0,
    deny: 0,
    observe: 0
  }));

  for (const event of events) {
    const ts = new Date(event.timestamp).getTime();
    if (Number.isNaN(ts)) {
      continue;
    }
    const minutesAgo = Math.floor((now - ts) / ONE_MINUTE);
    if (minutesAgo < 0 || minutesAgo >= bucketCount) {
      continue;
    }
    const target = buckets[bucketCount - minutesAgo - 1];
    if (event.effective_decision === "allow") {
      target.allow += 1;
    } else if (event.effective_decision === "deny") {
      target.deny += 1;
    } else {
      target.observe += 1;
    }
  }

  const topBlockedResources = Array.from(
    events
      .filter((event) => event.effective_decision === "deny")
      .reduce((counts, event) => {
        counts.set(event.resource, (counts.get(event.resource) ?? 0) + 1);
        return counts;
      }, new Map<string, number>())
      .entries()
  )
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 5)
    .map(([resource, count]) => ({ resource, count }));

  return {
    buckets,
    top_blocked_resources: topBlockedResources
  };
}

function buildStatusSummary(state: DemoState): StatusSummary {
  const activeVersion = state.versions.find((version) => version.active) ?? state.versions[0];

  return {
    daemon_up: true,
    policy_version: activeVersion?.id.slice(0, 8) ?? "demo",
    backend_mode: "kernel_strict",
    kernel_ready: true,
    kernel_program_version: "demo-static-v1",
    auto_enroll_active_rules: 2,
    unmatched_mode: "observe",
    hook_status: {
      exec_hook: "EbpfLsm",
      network_hook: "EbpfLsm",
      filesystem_hook: "EbpfLsm"
    },
    dashboard_enabled: true,
    dashboard_ready: true,
    dashboard_url: "Static guided build",
    url_gateway_enabled: true,
    url_gateway_ready: true,
    url_gateway_http_proxy: "Fixture-backed URL demo",
    url_gateway_https_proxy: "Fixture-backed URL demo",
    events_ingested_total: state.events.length,
    events_dropped_queue_total: 0,
    unenrolled_events_suppressed_total: 52,
    ingest_backlog_len: 0,
    enrollment_sync_error: "",
    dashboard_schema_version: "3",
    policy_versions_total: state.versions.length,
    pending_mcp_approvals: state.approvals.length,
    active_dashboard_sessions: 3,
    active_sse_clients: eventSubscribers.size,
    active_mcp_sessions: 2,
    dashboard_sqlite_bytes: 262144,
    coverage: [
      { action_type: "FILE_READ", action_class: "file", backend: "ebpf_lsm", status: "enforced" },
      {
        action_type: "PROC_EXEC",
        action_class: "process",
        backend: "ebpf_lsm",
        status: "enforced"
      },
      {
        action_type: "NET_CONNECT",
        action_class: "network",
        backend: "ebpf_lsm",
        status: "enforced"
      },
      {
        action_type: "NET_LISTEN",
        action_class: "network",
        backend: "ebpf_lsm",
        status: "observe_only"
      },
      {
        action_type: "URL_REQUEST",
        action_class: "network",
        backend: "userspace_gateway",
        status: "enforced"
      },
      { action_type: "MCP_TOOL_CALL", action_class: "mcp", backend: "daemon", status: "enforced" },
      {
        action_type: "MCP_RESOURCE_READ",
        action_class: "mcp",
        backend: "daemon",
        status: "enforced"
      }
    ],
    tls_cert_info: state.tlsCertInfo,
    apparmor_enabled: true,
    apparmor_parser_present: true,
    events_dropped_ringbuf_total: 0,
    kernel_events_rate_limited_total: 0,
    kernel_deny_events_dropped_total: 0,
    audit_write_failures_total: 0,
    audit_mirror_failures_total: 0,
    apparmor_records_lost_total: 0,
    policy_reload_failures_total: 0,
    policy_sync_last_error: null,
    telemetry_degraded_reasons: [],
    backpressure_active: false,
    backpressure_activations_total: 0,
    auth_failures_total: 1,
    dashboard_action_record_failures_total: 0,
    sse_events_skipped_total: 0,
    degraded_reasons: []
  };
}

function buildAuthMe(state: DemoState): AuthMeResponse {
  return {
    authenticated: state.authenticated,
    setup_required: false,
    username: state.username,
    expires_at: nowIso(8 * 60 * ONE_MINUTE),
    csrf_token: state.authenticated ? state.csrfToken : undefined
  };
}

function isMutation(method: string): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
}

function matchPolicyDraftApply(pathname: string): string | null {
  const match = pathname.match(/^\/policy\/drafts\/([^/]+)\/apply$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchPolicyDraftValidate(pathname: string): string | null {
  const match = pathname.match(/^\/policy\/drafts\/([^/]+)\/validate$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchPolicyVersionRollback(pathname: string): string | null {
  const match = pathname.match(/^\/policy\/versions\/([^/]+)\/rollback$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function matchApprovalDecision(
  pathname: string
): { requestId: string; decision: "approve" | "deny" } | null {
  const match = pathname.match(/^\/mcp\/approvals\/([^/]+)\/(approve|deny)$/);
  return match
    ? {
        requestId: decodeURIComponent(match[1]),
        decision: match[2] as "approve" | "deny"
      }
    : null;
}

function matchAgentDelete(pathname: string): string | null {
  const match = pathname.match(/^\/agents\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

function validatePolicy(document: PolicyDocument): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const profileNames = Object.keys(document.profiles);

  if (!profileNames.length) {
    errors.push("At least one profile is required.");
  }

  const ruleIds = new Set<string>();
  const requireUniqueId = (profileName: string, id: string, label: string) => {
    const key = `${profileName}:${id}`;
    if (!id.trim()) {
      errors.push(`${profileName} ${label} is missing an id.`);
      return;
    }
    if (ruleIds.has(key)) {
      errors.push(`${profileName} contains duplicate rule id ${id}.`);
      return;
    }
    ruleIds.add(key);
  };

  for (const [profileName, profile] of Object.entries(document.profiles)) {
    const validatePathRules = (rules: PathRule[], label: string) => {
      for (const rule of rules) {
        requireUniqueId(profileName, rule.id, label);
        if (!rule.pattern.trim()) {
          errors.push(`${profileName} ${label} ${rule.id} is missing a path pattern.`);
        }
      }
    };
    const validateExecRules = (rules: ExecRule[], label: string) => {
      for (const rule of rules) {
        requireUniqueId(profileName, rule.id, label);
        if (!rule.path.trim()) {
          errors.push(`${profileName} ${label} ${rule.id} is missing an executable path.`);
        } else if (!rule.path.startsWith("/")) {
          warnings.push(`${profileName} ${label} ${rule.id} is not an absolute path.`);
        }
      }
    };
    const validateNetworkRules = (rules: NetworkRule[], label: string) => {
      for (const rule of rules) {
        requireUniqueId(profileName, rule.id, label);
        if (!rule.cidr && !rule.host_glob) {
          errors.push(`${profileName} ${label} ${rule.id} needs a CIDR or host glob.`);
        }
        if (rule.port != null && (rule.port < 1 || rule.port > 65535)) {
          errors.push(`${profileName} ${label} ${rule.id} has an invalid port.`);
        }
      }
    };
    const validateUrlRules = (rules: UrlRule[], label: string) => {
      for (const rule of rules) {
        requireUniqueId(profileName, rule.id, label);
        if (!rule.host_glob.trim()) {
          errors.push(`${profileName} ${label} ${rule.id} needs a host glob.`);
        }
        if (!rule.path_glob.trim()) {
          errors.push(`${profileName} ${label} ${rule.id} needs a path glob.`);
        }
      }
    };

    validatePathRules(profile.file_allow, "file allow rule");
    validatePathRules(profile.file_deny, "file deny rule");
    validateExecRules(profile.exec_allow, "exec allow rule");
    validateExecRules(profile.exec_deny, "exec deny rule");
    validateNetworkRules(profile.network_allow, "network allow rule");
    validateNetworkRules(profile.network_deny, "network deny rule");
    validateUrlRules(profile.url_allow, "URL allow rule");
    validateUrlRules(profile.url_deny, "URL deny rule");

    if (!profile.workspace_roots.length) {
      warnings.push(`${profileName} has no workspace roots configured.`);
    }
  }

  return {
    valid: errors.length === 0,
    warnings,
    errors
  };
}

function applyVersion(
  state: DemoState,
  document: PolicyDocument,
  summary: string,
  actor: string,
  rolledBackFrom?: string
): string {
  const versionId = nextId("ver_demo");
  for (const version of state.versions) {
    version.active = false;
  }
  const record: DemoVersionRecord = {
    id: versionId,
    created_at: nowIso(),
    created_by: actor,
    source_draft_id: undefined,
    checksum: nextId("sha"),
    summary,
    rolled_back_from: rolledBackFrom,
    active: true,
    document: clone(document)
  };
  state.versions.unshift(record);
  state.versions = state.versions.slice(0, 12);
  state.activePolicy = clone(document);
  return versionId;
}

function findDraft(state: DemoState, draftId: string): DemoDraftRecord | null {
  return state.drafts[draftId] ?? null;
}

function buildLoginResponse(state: DemoState): LoginResponse {
  return {
    csrf_token: state.csrfToken,
    expires_at: nowIso(8 * 60 * ONE_MINUTE)
  };
}

function createSseFrame(item: EventItem): string {
  return `id: ${item.id}\nevent: decision\ndata: ${JSON.stringify(item)}\n\n`;
}

const liveEventTemplates = [
  {
    effectiveDecision: "deny" as const,
    actionClass: "network",
    actionType: "NET_CONNECT",
    profile: "default",
    pid: 4812,
    agentId: "agt_demo_assistant",
    ruleId: "deny_release_bucket",
    resource: networkResource(
      "releases.example.test",
      443,
      "https://releases.example.test/blocked/manifest.json"
    ),
    reason: "DENY_BY_RULE",
    message: "Another blocked release request hit the live stream."
  },
  {
    effectiveDecision: "allow" as const,
    actionClass: "file",
    actionType: "FILE_READ",
    profile: "default",
    pid: 4812,
    agentId: "agt_demo_assistant",
    ruleId: "allow_workspace_docs",
    resource: fileResource("/workspace/assistant/tasks/today.md"),
    reason: "ALLOW_BY_RULE",
    message: "Workspace reads continue under the allow policy."
  },
  {
    effectiveDecision: "observe" as const,
    actionClass: "mcp",
    actionType: "MCP_TOOL_CALL",
    profile: "default",
    pid: 4812,
    agentId: "agt_demo_assistant",
    resource: mcpResource("github", "create_pull_request"),
    reason: "REQUIRES_APPROVAL",
    message: "A new MCP approval request appeared in the live stream."
  },
  {
    effectiveDecision: "deny" as const,
    actionClass: "process",
    actionType: "PROC_EXEC",
    profile: "default",
    pid: 4812,
    agentId: "agt_demo_assistant",
    ruleId: "deny_netcat",
    resource: execResource("/usr/bin/nc"),
    reason: "DENY_BY_RULE",
    message: "Netcat remains blocked during the static demo."
  }
];

function emitLiveEventFromTemplate(): EventItem {
  const state = getState();
  const template = liveEventTemplates[liveTemplateCursor % liveEventTemplates.length];
  liveTemplateCursor += 1;
  const event = addEvent(state, {
    effective_decision: template.effectiveDecision,
    decision: template.effectiveDecision,
    action_class: template.actionClass,
    action_type: template.actionType,
    profile: template.profile,
    pid: template.pid,
    agent_id: template.agentId,
    rule_id: template.ruleId,
    resource: formatResource(template.resource),
    resource_json: JSON.stringify(template.resource),
    reason: template.reason,
    message: template.message,
    raw_json: {
      timestamp: nowIso(),
      effective_decision: template.effectiveDecision,
      action_class: template.actionClass,
      action_type: template.actionType,
      profile: template.profile,
      pid: template.pid,
      agent_id: template.agentId,
      rule_id: template.ruleId,
      resource: template.resource,
      reason: template.reason,
      message: template.message
    }
  });
  for (const subscriber of eventSubscribers) {
    subscriber(event);
  }
  return event;
}

function syncLiveTicker(): void {
  if (eventSubscribers.size === 0) {
    if (liveTicker != null) {
      globalThis.clearInterval(liveTicker);
      liveTicker = null;
    }
    return;
  }

  if (liveTicker != null) {
    return;
  }

  liveTicker = globalThis.setInterval(() => {
    emitLiveEventFromTemplate();
  }, STREAM_INTERVAL_MS);
}

function createStreamResponse(signal?: AbortSignal): Response {
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false;
      const heartbeat = globalThis.setInterval(() => {
        controller.enqueue(encoder.encode(`: heartbeat ${Date.now()}\n\n`));
      }, 15_000);

      const subscriber: EventSubscriber = (item) => {
        controller.enqueue(encoder.encode(createSseFrame(item)));
      };

      eventSubscribers.add(subscriber);
      syncLiveTicker();
      controller.enqueue(encoder.encode(": connected\n\n"));

      const close = () => {
        if (closed) {
          return;
        }
        closed = true;
        globalThis.clearInterval(heartbeat);
        eventSubscribers.delete(subscriber);
        syncLiveTicker();
        try {
          controller.close();
        } catch {
          // The consumer may already have closed the stream.
        }
      };

      signal?.addEventListener(
        "abort",
        () => {
          close();
        },
        { once: true }
      );
    },
    cancel() {
      syncLiveTicker();
    }
  });

  return new Response(stream, {
    headers: STREAM_HEADERS
  });
}

function buildEventsResponse(state: DemoState, url: URL): EventListResponse<EventItem> {
  const filtered = filterDemoEvents(state, url);
  const rawLimit = Number(url.searchParams.get("limit") ?? "120");
  const rawOffset = Number(url.searchParams.get("offset") ?? "0");
  const rawBeforeId = Number(url.searchParams.get("before_id") ?? "NaN");
  const limit = Number.isFinite(rawLimit) ? Math.max(rawLimit, 0) : 120;
  const offset = Number.isFinite(rawOffset) ? Math.max(rawOffset, 0) : 0;
  const page = Number.isFinite(rawBeforeId)
    ? filtered.filter((item) => item.id < rawBeforeId)
    : filtered;

  return {
    total: filtered.length,
    items: page.slice(offset, offset + limit)
  };
}

function filterDemoEvents(state: DemoState, url: URL): EventItem[] {
  const filters: EventFilters = {
    decision: url.searchParams.get("decision") ?? "all",
    actionClass: url.searchParams.get("class") ?? "all",
    text: url.searchParams.get("text") ?? "",
    actionType: url.searchParams.get("action_type") ?? "all",
    agentId: url.searchParams.get("agent_id") ?? ""
  };
  return state.events.filter((item) => eventMatchesFilters(item, filters));
}

/** Mirrors /events/export: oldest first, JSONL of raw records or CSV rows. */
function buildEventsExport(state: DemoState, url: URL): Response {
  const rows = [...filterDemoEvents(state, url)].reverse();
  const format = url.searchParams.get("format") === "csv" ? "csv" : "jsonl";
  const body =
    format === "csv"
      ? [
          "id,timestamp,decision,effective_decision,reason,action_type,action_class,profile,pid,agent_id,rule_id,resource,message,policy_version",
          ...rows.map((item) =>
            [
              item.id,
              item.timestamp,
              item.decision,
              item.effective_decision,
              item.reason,
              item.action_type,
              item.action_class,
              item.profile,
              item.pid,
              item.agent_id,
              item.rule_id,
              item.resource,
              item.message,
              item.policy_version
            ]
              .map(csvEscape)
              .join(",")
          )
        ].join("\n") + "\n"
      : rows.map((item) => `${JSON.stringify(item.raw_json ?? item)}\n`).join("");
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": format === "csv" ? "text/csv; charset=utf-8" : "application/x-ndjson",
      "Content-Disposition": `attachment; filename="mercury-events-demo.${format}"`
    }
  });
}

function extractResource(raw: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function ensureProfile(state: DemoState, profileName: string): ProfilePolicy | null {
  return state.activePolicy.profiles[profileName] ?? null;
}

function hasPathRule(list: PathRule[], pattern: string): boolean {
  return list.some((rule) => rule.pattern === pattern);
}

function hasExecRule(list: ExecRule[], path: string): boolean {
  return list.some((rule) => rule.path === path);
}

function hasNetworkRule(
  list: NetworkRule[],
  hostGlob: string | undefined,
  cidr: string | undefined,
  port: number | undefined
): boolean {
  return list.some(
    (rule) => rule.host_glob === hostGlob && rule.cidr === cidr && rule.port === port
  );
}

function applyQuickRule(state: DemoState, payload: DemoQuickRuleTarget): QuickRuleResponse {
  const profile = ensureProfile(state, payload.profile);
  if (!profile) {
    return {
      success: false,
      already_exists: false,
      version: "",
      errors: [`Unknown profile ${payload.profile}.`],
      rule_description: ""
    };
  }

  const resource = extractResource(payload.resource_json);
  if (!resource) {
    return {
      success: false,
      already_exists: false,
      version: "",
      errors: ["Unable to parse the selected event resource."],
      rule_description: ""
    };
  }

  const directionLabel =
    payload.direction === "allow"
      ? "allow"
      : payload.direction === "deny"
        ? "deny"
        : "require approval";
  let ruleDescription = "";
  let alreadyExists = false;
  const nextPolicy = clone(state.activePolicy);
  const targetProfile = nextPolicy.profiles[payload.profile] ?? emptyProfilePolicy();
  const kind = String(resource.kind ?? "").toUpperCase();

  if (
    (kind === "FILE" || payload.action_type.startsWith("FILE_")) &&
    typeof resource.path === "string"
  ) {
    const pattern = resource.path;
    const list = payload.direction === "allow" ? targetProfile.file_allow : targetProfile.file_deny;
    alreadyExists = hasPathRule(list, pattern);
    if (!alreadyExists) {
      list.push({
        id: nextId(`${payload.direction}_file`),
        pattern
      });
    }
    ruleDescription = `${directionLabel} file ${pattern}`;
  } else if (
    (kind === "EXEC" || payload.action_type.startsWith("PROC_")) &&
    typeof resource.path === "string"
  ) {
    const path = resource.path;
    const list = payload.direction === "allow" ? targetProfile.exec_allow : targetProfile.exec_deny;
    alreadyExists = hasExecRule(list, path);
    if (!alreadyExists) {
      list.push({
        id: nextId(`${payload.direction}_exec`),
        path
      });
    }
    ruleDescription = `${directionLabel} exec ${path}`;
  } else if (
    (kind === "NETWORK" || payload.action_type.startsWith("NET_")) &&
    (typeof resource.dest_host === "string" || typeof resource.dest_port === "number")
  ) {
    if (
      payload.direction !== "require_approval" &&
      (typeof resource.full_url === "string" ||
        typeof resource.path === "string" ||
        typeof resource.method === "string" ||
        typeof resource.scheme === "string")
    ) {
      const host = typeof resource.dest_host === "string" ? resource.dest_host : "";
      const path = typeof resource.path === "string" ? resource.path : "/";
      const method = typeof resource.method === "string" ? resource.method : undefined;
      const scheme = typeof resource.scheme === "string" ? resource.scheme : undefined;
      const query = typeof resource.query === "string" ? resource.query : undefined;
      const port = typeof resource.dest_port === "number" ? resource.dest_port : undefined;
      const list = payload.direction === "allow" ? targetProfile.url_allow : targetProfile.url_deny;
      alreadyExists = list.some(
        (rule) =>
          rule.host_glob === host &&
          rule.path_glob === path &&
          rule.method === method &&
          rule.scheme === scheme &&
          rule.query_glob === query &&
          rule.port === port
      );
      if (!alreadyExists) {
        list.push({
          id: nextId(`${payload.direction}_url`),
          host_glob: host,
          path_glob: path,
          method,
          scheme,
          query_glob: query,
          port
        });
      }
      ruleDescription = `${directionLabel} url ${host}${path}`;
    } else if (payload.direction !== "require_approval") {
      const hostGlob =
        typeof resource.dest_host === "string" ? `*${resource.dest_host}*` : undefined;
      const port = typeof resource.dest_port === "number" ? resource.dest_port : undefined;
      const list =
        payload.direction === "allow" ? targetProfile.network_allow : targetProfile.network_deny;
      alreadyExists = hasNetworkRule(list, hostGlob, undefined, port);
      if (!alreadyExists) {
        list.push({
          id: nextId(`${payload.direction}_net`),
          host_glob: hostGlob,
          port,
          protocol: "TCP"
        });
      }
      ruleDescription = `${directionLabel} network ${hostGlob ?? "host"}${port != null ? `:${port}` : ""}`;
    } else {
      return {
        success: false,
        already_exists: false,
        version: "",
        errors: [
          "require_approval quick rules are only supported for MCP events in the static demo."
        ],
        rule_description: ""
      };
    }
  } else if (
    (kind === "MCP_TOOL" || payload.action_type === "MCP_TOOL_CALL") &&
    typeof resource.server_id === "string" &&
    typeof resource.tool_name === "string"
  ) {
    const transport = resource.transport === "http" ? "http" : "stdio";
    targetProfile.mcp ??= {
      default_tool_action: undefined,
      default_resource_action: undefined,
      servers: []
    };
    const server = targetProfile.mcp.servers.find(
      (entry) => entry.id === resource.server_id && entry.transport === transport
    );
    if (!server) {
      return {
        success: false,
        already_exists: false,
        version: "",
        errors: ["The static demo only allows MCP quick rules for configured MCP servers."],
        rule_description: ""
      };
    }
    const toolName = resource.tool_name;
    const targetList =
      payload.direction === "allow"
        ? server.tools.allow
        : payload.direction === "deny"
          ? server.tools.deny
          : server.tools.require_approval;
    alreadyExists = targetList.includes(toolName);
    if (!alreadyExists) {
      server.tools.allow = server.tools.allow.filter((value) => value !== toolName);
      server.tools.deny = server.tools.deny.filter((value) => value !== toolName);
      server.tools.require_approval = server.tools.require_approval.filter(
        (value) => value !== toolName
      );
      targetList.push(toolName);
    }
    ruleDescription = `${directionLabel} mcp ${resource.server_id}/${toolName}`;
  } else {
    return {
      success: false,
      already_exists: false,
      version: "",
      errors: ["This event type is not supported by quick rules in the static demo."],
      rule_description: ""
    };
  }

  if (!alreadyExists) {
    const versionId = applyVersion(
      state,
      nextPolicy,
      `Quick rule: ${ruleDescription}`,
      "demo.operator"
    );
    addAction(state, `quick_rule.${payload.direction}`, `Applied ${ruleDescription}`);
    return {
      success: true,
      already_exists: false,
      version: versionId,
      errors: [],
      rule_description: ruleDescription
    };
  }

  return {
    success: true,
    already_exists: true,
    version: state.versions.find((version) => version.active)?.id ?? "",
    errors: [],
    rule_description: ruleDescription
  };
}

async function maybeDelay(method: string, pathname: string): Promise<void> {
  if (pathname === "/events/stream") {
    return;
  }
  const delayMs = method === "GET" ? 40 : 85;
  await new Promise((resolve) => globalThis.setTimeout(resolve, delayMs));
}

export async function handleStaticDemoRequest(
  path: string,
  init: RequestInit = {}
): Promise<Response> {
  const method = (init.method ?? "GET").toUpperCase();
  const url = new URL(path, "https://demo.mercury.local");
  const pathname = url.pathname;
  const state = getState();
  const headers = getRequestHeaders(init);

  await maybeDelay(method, pathname);

  if (!state.authenticated && !pathname.startsWith("/auth/")) {
    return badRequest("Session expired, please log in again.", 401);
  }

  if (pathname === "/auth/me" && method === "GET") {
    return jsonResponse(buildAuthMe(state));
  }

  if (pathname === "/auth/login" && method === "POST") {
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const username = String(body.username ?? "").trim() || state.username;
    const password = String(body.password ?? "").trim();
    if (!password) {
      return badRequest("Enter any password to reopen the static demo.");
    }
    state.authenticated = true;
    state.username = username;
    state.csrfToken = nextId("csrf");
    return jsonResponse(buildLoginResponse(state));
  }

  if (pathname === "/auth/signup" && method === "POST") {
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const username = String(body.username ?? "").trim() || state.username;
    const password = String(body.password ?? "").trim();
    const confirm = String(body.confirm_password ?? "").trim();
    if (!password || password !== confirm) {
      return badRequest("Password confirmation does not match.");
    }
    state.authenticated = true;
    state.username = username;
    state.password = password;
    state.csrfToken = nextId("csrf");
    return jsonResponse(buildLoginResponse(state));
  }

  if (pathname === "/auth/logout" && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    state.authenticated = false;
    state.csrfToken = nextId("csrf");
    return jsonResponse({ ok: true });
  }

  if (pathname === "/auth/password/change" && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const nextPassword = String(body.new_password ?? "");
    const confirm = String(body.confirm_password ?? "");
    if (!nextPassword || nextPassword !== confirm) {
      return badRequest("New password confirmation does not match.");
    }
    state.password = nextPassword;
    state.csrfToken = nextId("csrf");
    addAction(
      state,
      "auth.password_change",
      "Updated demo password for this browser session",
      state.username
    );
    return jsonResponse(buildLoginResponse(state));
  }

  if (pathname === "/status/summary" && method === "GET") {
    return jsonResponse(buildStatusSummary(state));
  }

  if (pathname === "/events/stats" && method === "GET") {
    return jsonResponse(buildStats(state.events));
  }

  if (pathname === "/policy/active" && method === "GET") {
    const activeVersion = state.versions.find((version) => version.active) ?? state.versions[0];
    return jsonResponse({
      yaml: serializePolicy(state.activePolicy),
      version: activeVersion?.id ?? "demo"
    });
  }

  if (pathname === "/policy/versions" && method === "GET") {
    return jsonResponse(state.versions.map(toPolicyVersion));
  }

  if (pathname === "/actions" && method === "GET") {
    const rawLimit = Number(url.searchParams.get("limit") ?? "200");
    const rawBeforeId = Number(url.searchParams.get("before_id") ?? "NaN");
    const limit = Number.isFinite(rawLimit) ? Math.max(rawLimit, 1) : 200;
    const page = Number.isFinite(rawBeforeId)
      ? state.actions.filter((item) => item.id < rawBeforeId)
      : state.actions;
    return jsonResponse(page.slice(0, limit));
  }

  if (pathname === "/actions/export" && method === "GET") {
    const start = url.searchParams.get("start");
    const rows = state.actions
      .filter((item) => !start || item.ts >= start)
      .slice()
      .reverse();
    return new Response(buildActionsCsv(rows), {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="dashboard-actions-demo.csv"'
      }
    });
  }

  if (pathname === "/events/export" && method === "GET") {
    return buildEventsExport(state, url);
  }

  if (pathname === "/policy/drafts" && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const incomingId = String(body.id ?? "").trim();
    const normalized = normalizePolicyDocument(body.document);
    const yamlText = serializePolicy(normalized);
    const draftId = incomingId || nextId("draft_demo");
    const existing = state.drafts[draftId];
    const draft: DemoDraftRecord = {
      id: draftId,
      etag: nextId("etag"),
      document: normalized,
      yaml: yamlText,
      created_at: existing?.created_at ?? nowIso(),
      updated_at: nowIso()
    };
    state.drafts[draftId] = draft;
    return jsonResponse(draft);
  }

  const validateDraftId = matchPolicyDraftValidate(pathname);
  if (validateDraftId && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const draft = findDraft(state, validateDraftId);
    if (!draft) {
      return badRequest("Draft not found.", 404);
    }
    return jsonResponse(validatePolicy(draft.document));
  }

  const applyDraftId = matchPolicyDraftApply(pathname);
  if (applyDraftId && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const draft = findDraft(state, applyDraftId);
    if (!draft) {
      return badRequest("Draft not found.", 404);
    }
    const validation = validatePolicy(draft.document);
    if (!validation.valid) {
      return jsonResponse(
        {
          success: false,
          version: "v1",
          version_id: null,
          errors: validation.errors,
          warnings: validation.warnings
        },
        { status: 200 }
      );
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const note = String(body.note ?? "").trim();
    const versionId = applyVersion(
      state,
      draft.document,
      note || "Applied hosted static demo draft",
      state.username
    );
    addAction(
      state,
      "policy.apply",
      `Applied ${versionId}${note ? ` (${note})` : ""}`,
      state.username
    );
    return jsonResponse({
      success: true,
      version: "v1",
      version_id: versionId,
      errors: [],
      warnings: validation.warnings
    });
  }

  const rollbackVersionId = matchPolicyVersionRollback(pathname);
  if (rollbackVersionId && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const version = state.versions.find((entry) => entry.id === rollbackVersionId);
    if (!version) {
      return badRequest("Version not found.", 404);
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const note = String(body.note ?? "").trim();
    const versionId = applyVersion(
      state,
      version.document,
      note || `Rollback to ${rollbackVersionId.slice(0, 8)}`,
      state.username,
      rollbackVersionId
    );
    addAction(
      state,
      "policy.rollback",
      `Rolled back to ${rollbackVersionId.slice(0, 8)}`,
      state.username
    );
    return jsonResponse({
      success: true,
      version: "v1",
      version_id: versionId,
      errors: [],
      warnings: []
    });
  }

  if (pathname === "/events" && method === "GET") {
    return jsonResponse(buildEventsResponse(state, url));
  }

  if (pathname === "/events/stream" && method === "GET") {
    return createStreamResponse(init.signal ?? undefined);
  }

  if (pathname === "/policy/quick-rule" && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const body = (parseRequestBody(init) ?? {}) as DemoQuickRuleTarget;
    return jsonResponse(applyQuickRule(state, body));
  }

  if (pathname === "/mcp/approvals" && method === "GET") {
    return jsonResponse(state.approvals);
  }

  const approvalDecision = matchApprovalDecision(pathname);
  if (approvalDecision && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const index = state.approvals.findIndex(
      (item) => item.request_id === approvalDecision.requestId
    );
    if (index === -1) {
      return badRequest("Approval request not found.", 404);
    }
    const [approval] = state.approvals.splice(index, 1);
    addAction(
      state,
      `approval.${approvalDecision.decision}`,
      `${approvalDecision.decision}d ${approval.server_id}/${approval.tool_name}`,
      state.username
    );
    const eventResource = mcpResource(approval.server_id, approval.tool_name);
    const event = addEvent(state, {
      effective_decision: approvalDecision.decision === "approve" ? "allow" : "deny",
      decision: approvalDecision.decision === "approve" ? "allow" : "deny",
      action_class: "mcp",
      action_type: "MCP_TOOL_CALL",
      profile: approval.profile,
      pid: 4812,
      agent_id: approval.agent_id,
      resource: formatResource(eventResource),
      resource_json: JSON.stringify(eventResource),
      reason:
        approvalDecision.decision === "approve" ? "APPROVED_BY_OPERATOR" : "DENIED_BY_OPERATOR",
      message:
        approvalDecision.decision === "approve"
          ? `Operator approved ${approval.tool_name}.`
          : `Operator denied ${approval.tool_name}.`,
      raw_json: {
        effective_decision: approvalDecision.decision === "approve" ? "allow" : "deny",
        action_class: "mcp",
        action_type: "MCP_TOOL_CALL",
        profile: approval.profile,
        agent_id: approval.agent_id,
        resource: eventResource
      }
    });
    for (const subscriber of eventSubscribers) {
      subscriber(event);
    }
    return jsonResponse({ ok: true });
  }

  if (pathname === "/enrollments" && method === "GET") {
    return jsonResponse(state.enrollments);
  }

  if (pathname === "/settings/tls" && method === "PUT") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    state.tlsCertInfo = {
      cert_file: String(body.cert_file ?? state.tlsCertInfo.cert_file),
      key_file: String(body.key_file ?? state.tlsCertInfo.key_file),
      expires_at: nowIso(92 * ONE_DAY),
      issuer: "Hosted Demo CA",
      is_self_signed: false
    };
    addAction(
      state,
      "settings.tls_reload",
      `Reloaded TLS certificate ${state.tlsCertInfo.cert_file}`,
      state.username
    );
    return jsonResponse(state.tlsCertInfo);
  }

  if (pathname === "/agents" && method === "GET") {
    return jsonResponse(state.agents);
  }

  if (pathname === "/agents/history" && method === "GET") {
    return jsonResponse(state.launchHistory);
  }

  if (pathname === "/agents/launch" && method === "POST") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    const body = (parseRequestBody(init) ?? {}) as Record<string, unknown>;
    const executable = String(body.executable ?? "");
    const args = Array.isArray(body.args) ? body.args.map((item) => String(item)) : [];
    const profile = String(body.profile ?? "default");
    const cwd = String(body.cwd ?? `/workspace/${profile}`);
    const agentId = nextId("agt_demo");
    const pid = state.nextPid;
    state.nextPid += 11;
    const running: RunningAgent = {
      agent_id: agentId,
      pid,
      profile,
      cmdline: [executable, ...args].filter(Boolean),
      cwd,
      uid: 1000
    };
    state.agents.unshift(running);
    state.enrollments.unshift({
      pid,
      profile,
      source: "mercury-run",
      mode: "enforce",
      cgroup_id: `mercury/agents/${agentId}`,
      agent_id: agentId,
      uid: 1000
    });
    state.launchHistory.unshift({
      launch_id: nextId("launch_demo"),
      agent_id: agentId,
      pid,
      profile,
      cmdline: running.cmdline,
      cwd,
      operator: state.username,
      launch_user: "mercury",
      started_at: nowIso(),
      finished_at: "",
      status: "running",
      exit_code: null,
      signal: null,
      error: null,
      stderr_tail: null
    });
    addAction(
      state,
      "agent.launch",
      `Launched ${executable} under profile ${profile}`,
      state.username
    );
    const eventResource = execResource(executable);
    const event = addEvent(state, {
      effective_decision: "allow",
      decision: "allow",
      action_class: "process",
      action_type: "PROC_EXEC",
      profile,
      pid,
      agent_id: agentId,
      resource: formatResource(eventResource),
      resource_json: JSON.stringify(eventResource),
      reason: "ALLOW_BY_RULE",
      message: "A new demo agent launch was allowed.",
      raw_json: {
        effective_decision: "allow",
        action_class: "process",
        action_type: "PROC_EXEC",
        profile,
        pid,
        agent_id: agentId,
        resource: eventResource
      }
    });
    for (const subscriber of eventSubscribers) {
      subscriber(event);
    }
    return jsonResponse({
      agent_id: agentId,
      pid,
      cgroup_id: `mercury/agents/${agentId}`
    });
  }

  const deleteAgentId = matchAgentDelete(pathname);
  if (deleteAgentId && method === "DELETE") {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
    state.agents = state.agents.filter((agent) => agent.agent_id !== deleteAgentId);
    state.enrollments = state.enrollments.filter((item) => item.agent_id !== deleteAgentId);
    state.launchHistory = state.launchHistory.map((entry) =>
      entry.agent_id === deleteAgentId && entry.status === "running"
        ? {
            ...entry,
            finished_at: nowIso(),
            status: "stopped",
            signal: 15
          }
        : entry
    );
    addAction(state, "agent.stop", `Stopped ${deleteAgentId.slice(0, 8)}`, state.username);
    return noContent();
  }

  if (isMutation(method)) {
    const csrfError = requireCsrf(state, headers);
    if (csrfError) {
      return csrfError;
    }
  }

  return badRequest(`Unknown static demo endpoint: ${method} ${pathname}`, 404);
}

export { isStaticDemoMode };
