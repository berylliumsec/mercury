export type EnforcementMode = "enforce" | "observe";
export type DecisionMode = "allow" | "deny";
export type FailMode = "fail_open" | "fail_closed";
export type AuditLevel = "errors" | "denies" | "all";
export type NetworkProtocol = "TCP" | "UDP";

export type EnforcementSettings = {
  file: EnforcementMode;
  process: EnforcementMode;
  network: EnforcementMode;
};

export type PolicyDefaults = {
  decision: DecisionMode;
  fail_mode: FailMode;
  audit_level: AuditLevel;
  enforcement: EnforcementSettings;
};

export type PathRule = {
  id: string;
  pattern: string;
};

export type ExecRule = {
  id: string;
  path: string;
};

export type NetworkRule = {
  id: string;
  host_glob?: string;
  cidr?: string;
  port?: number;
  protocol?: NetworkProtocol;
};

export type UrlRule = {
  id: string;
  scheme?: string;
  host_glob: string;
  port?: number;
  method?: string;
  path_glob: string;
  query_glob?: string;
};

export type McpToolAction = "allow" | "deny" | "require_approval";
export type McpTransport = "stdio" | "http";

export type McpToolPolicy = {
  allow: string[];
  deny: string[];
  require_approval: string[];
};

export type McpResourcePolicy = {
  allow: string[];
  deny: string[];
  require_approval: string[];
};

export type McpServerPolicy = {
  id: string;
  transport: McpTransport;
  exec_path_glob?: string;
  base_url?: string;
  default_tool_action?: McpToolAction;
  default_resource_action?: McpToolAction;
  tools: McpToolPolicy;
  resources: McpResourcePolicy;
};

export type McpPolicy = {
  default_tool_action?: McpToolAction;
  default_resource_action?: McpToolAction;
  servers: McpServerPolicy[];
};

export type ProfilePolicy = {
  workspace_roots: string[];
  file_allow: PathRule[];
  file_deny: PathRule[];
  exec_allow: ExecRule[];
  exec_deny: ExecRule[];
  network_allow: NetworkRule[];
  network_deny: NetworkRule[];
  url_allow: UrlRule[];
  url_deny: UrlRule[];
  mcp?: McpPolicy;
  enforcement?: EnforcementSettings;
};

export type PolicySignature = {
  key_id: string;
  alg: string;
  sig: string;
};

export type PolicyDocument = {
  version: string;
  defaults: PolicyDefaults;
  profiles: Record<string, ProfilePolicy>;
  signature?: PolicySignature | null;
};

export const DEFAULT_ENFORCEMENT: EnforcementSettings = {
  file: "enforce",
  process: "enforce",
  network: "enforce"
};

export function emptyProfilePolicy(): ProfilePolicy {
  return {
    workspace_roots: [],
    file_allow: [],
    file_deny: [],
    exec_allow: [],
    exec_deny: [],
    network_allow: [],
    network_deny: [],
    url_allow: [],
    url_deny: [],
    mcp: undefined,
    enforcement: { ...DEFAULT_ENFORCEMENT }
  };
}

export function emptyPolicyDocument(): PolicyDocument {
  return {
    version: "v1",
    defaults: {
      decision: "deny",
      fail_mode: "fail_closed",
      audit_level: "all",
      enforcement: { ...DEFAULT_ENFORCEMENT }
    },
    profiles: {
      default: emptyProfilePolicy()
    },
    signature: null
  };
}

export function normalizeEnforcement(raw: unknown): EnforcementSettings {
  const value = (raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {}) as Record<
    string,
    unknown
  >;
  const mode = (input: unknown): EnforcementMode => {
    if (input === "observe" || input === "enforce") {
      return input;
    }
    return "enforce";
  };
  return {
    file: mode(value.file),
    process: mode(value.process),
    network: mode(value.network)
  };
}

function normalizeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw
    .map((item) => (typeof item === "string" ? item.trim() : String(item ?? "").trim()))
    .filter((item) => item.length > 0);
}

function normalizePathRules(raw: unknown, prefix: string): PathRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((item, index) => {
    const value = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
    const id = String(value.id ?? `${prefix}_${index + 1}`).trim();
    const pattern = String(value.pattern ?? "").trim();
    return {
      id: id || `${prefix}_${index + 1}`,
      pattern
    };
  });
}

function normalizeExecRules(raw: unknown, prefix: string): ExecRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((item, index) => {
    const value = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
    const id = String(value.id ?? `${prefix}_${index + 1}`).trim();
    const path = String(value.path ?? "").trim();
    return {
      id: id || `${prefix}_${index + 1}`,
      path
    };
  });
}

function normalizeNetworkRules(raw: unknown, prefix: string): NetworkRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((item, index) => {
    const value = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
    const id = String(value.id ?? `${prefix}_${index + 1}`).trim() || `${prefix}_${index + 1}`;
    const hostGlob = value.host_glob == null ? "" : String(value.host_glob).trim();
    const cidr = value.cidr == null ? "" : String(value.cidr).trim();

    let port: number | undefined;
    if (typeof value.port === "number" && Number.isFinite(value.port)) {
      port = value.port;
    } else if (typeof value.port === "string" && value.port.trim().length > 0) {
      const parsed = Number(value.port.trim());
      if (Number.isFinite(parsed)) {
        port = parsed;
      }
    }

    const protocolRaw = String(value.protocol ?? "").toUpperCase();
    const protocol: NetworkProtocol | undefined =
      protocolRaw === "TCP" || protocolRaw === "UDP" ? (protocolRaw as NetworkProtocol) : undefined;

    return {
      id,
      host_glob: hostGlob || undefined,
      cidr: cidr || undefined,
      port,
      protocol
    };
  });
}

function normalizeUrlRules(raw: unknown, prefix: string): UrlRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((item, index) => {
    const value = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
    const id = String(value.id ?? `${prefix}_${index + 1}`).trim() || `${prefix}_${index + 1}`;
    const scheme = value.scheme == null ? "" : String(value.scheme).trim();
    const host_glob = String(value.host_glob ?? "").trim();
    const path_glob = String(value.path_glob ?? "").trim();
    const method = value.method == null ? "" : String(value.method).trim();
    const query_glob = value.query_glob == null ? "" : String(value.query_glob).trim();

    let port: number | undefined;
    if (typeof value.port === "number" && Number.isFinite(value.port)) {
      port = value.port;
    } else if (typeof value.port === "string" && value.port.trim().length > 0) {
      const parsed = Number(value.port.trim());
      if (Number.isFinite(parsed)) {
        port = parsed;
      }
    }

    return {
      id,
      scheme: scheme || undefined,
      host_glob,
      port,
      method: method || undefined,
      path_glob,
      query_glob: query_glob || undefined
    };
  });
}

function normalizeProfile(raw: unknown): ProfilePolicy {
  const value = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    workspace_roots: normalizeStringArray(value.workspace_roots),
    file_allow: normalizePathRules(value.file_allow, "file_allow"),
    file_deny: normalizePathRules(value.file_deny, "file_deny"),
    exec_allow: normalizeExecRules(value.exec_allow, "exec_allow"),
    exec_deny: normalizeExecRules(value.exec_deny, "exec_deny"),
    network_allow: normalizeNetworkRules(value.network_allow, "network_allow"),
    network_deny: normalizeNetworkRules(value.network_deny, "network_deny"),
    url_allow: normalizeUrlRules(value.url_allow, "url_allow"),
    url_deny: normalizeUrlRules(value.url_deny, "url_deny"),
    mcp: normalizeMcpPolicy(value.mcp),
    enforcement: value.enforcement ? normalizeEnforcement(value.enforcement) : undefined
  };
}

function normalizeMcpToolPolicy(raw: unknown): McpToolPolicy {
  const value = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    allow: normalizeStringArray(value.allow),
    deny: normalizeStringArray(value.deny),
    require_approval: normalizeStringArray(value.require_approval)
  };
}

function normalizeMcpResourcePolicy(raw: unknown): McpResourcePolicy {
  const value = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    allow: normalizeStringArray(value.allow),
    deny: normalizeStringArray(value.deny),
    require_approval: normalizeStringArray(value.require_approval)
  };
}

function normalizeMcpPolicy(raw: unknown): McpPolicy | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const value = raw as Record<string, unknown>;
  const defaultAction = String(value.default_tool_action ?? "").trim();
  const defaultResourceAction = String(value.default_resource_action ?? "").trim();
  const servers = Array.isArray(value.servers)
    ? value.servers.map((item) => {
        const server = item && typeof item === "object" ? (item as Record<string, unknown>) : {};
        const serverDefault = String(server.default_tool_action ?? "").trim();
        const serverDefaultResource = String(server.default_resource_action ?? "").trim();
        const transportRaw = String(server.transport ?? "stdio").trim();
        return {
          id: String(server.id ?? "").trim(),
          transport: transportRaw === "http" ? ("http" as const) : ("stdio" as const),
          exec_path_glob: String(server.exec_path_glob ?? "").trim() || undefined,
          base_url: String(server.base_url ?? "").trim() || undefined,
          default_tool_action:
            serverDefault === "allow" ||
            serverDefault === "deny" ||
            serverDefault === "require_approval"
              ? (serverDefault as McpToolAction)
              : undefined,
          default_resource_action:
            serverDefaultResource === "allow" ||
            serverDefaultResource === "deny" ||
            serverDefaultResource === "require_approval"
              ? (serverDefaultResource as McpToolAction)
              : undefined,
          tools: normalizeMcpToolPolicy(server.tools),
          resources: normalizeMcpResourcePolicy(server.resources)
        };
      })
    : [];

  return {
    default_tool_action:
      defaultAction === "allow" || defaultAction === "deny" || defaultAction === "require_approval"
        ? (defaultAction as McpToolAction)
        : undefined,
    default_resource_action:
      defaultResourceAction === "allow" ||
      defaultResourceAction === "deny" ||
      defaultResourceAction === "require_approval"
        ? (defaultResourceAction as McpToolAction)
        : undefined,
    servers
  };
}

export function normalizePolicyDocument(raw: unknown): PolicyDocument {
  const fallback = emptyPolicyDocument();
  if (!raw || typeof raw !== "object") {
    return fallback;
  }

  const value = raw as Record<string, unknown>;
  const defaultsRaw =
    value.defaults && typeof value.defaults === "object"
      ? (value.defaults as Record<string, unknown>)
      : {};
  const decision: DecisionMode = defaultsRaw.decision === "allow" ? "allow" : "deny";
  const failMode: FailMode = defaultsRaw.fail_mode === "fail_open" ? "fail_open" : "fail_closed";
  const auditLevel: AuditLevel =
    defaultsRaw.audit_level === "errors" ||
    defaultsRaw.audit_level === "denies" ||
    defaultsRaw.audit_level === "all"
      ? (defaultsRaw.audit_level as AuditLevel)
      : "all";

  const profilesRaw =
    value.profiles && typeof value.profiles === "object"
      ? (value.profiles as Record<string, unknown>)
      : {};
  const profiles: Record<string, ProfilePolicy> = {};
  for (const [name, profile] of Object.entries(profilesRaw)) {
    profiles[name] = normalizeProfile(profile);
  }
  if (Object.keys(profiles).length === 0) {
    profiles.default = emptyProfilePolicy();
  }

  const signature =
    value.signature && typeof value.signature === "object"
      ? {
          key_id: String((value.signature as Record<string, unknown>).key_id ?? ""),
          alg: String((value.signature as Record<string, unknown>).alg ?? ""),
          sig: String((value.signature as Record<string, unknown>).sig ?? "")
        }
      : null;

  return {
    version:
      typeof value.version === "string" && value.version.trim().length > 0
        ? value.version.trim()
        : "v1",
    defaults: {
      decision,
      fail_mode: failMode,
      audit_level: auditLevel,
      enforcement: normalizeEnforcement(defaultsRaw.enforcement)
    },
    profiles,
    signature
  };
}

export function nextRuleId(existing: string[], prefix: string): string {
  let index = 1;
  while (existing.includes(`${prefix}_${index}`)) {
    index += 1;
  }
  return `${prefix}_${index}`;
}
