export type EventItem = {
  id: number;
  timestamp: string;
  decision?: string;
  effective_decision: "allow" | "deny" | "observe" | string;
  action_class: string;
  action_type: string;
  profile: string;
  pid?: number;
  agent_id?: string;
  rule_id?: string;
  resource: string;
  /** Raw JSON string of the Resource payload (for example {"kind":"FILE","path":"/etc/passwd"}). */
  resource_json?: string;
  reason: string;
  message: string;
  policy_version?: string;
  raw_json?: unknown;
};

export type DecisionEventEnvelope = {
  id?: number;
  effective_decision?: string;
  action_class?: string;
  event?: Record<string, unknown> | null;
};

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function asJsonString(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (!value || typeof value !== "object") {
    return undefined;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return undefined;
  }
}

function asResourceText(resource: unknown): string {
  if (typeof resource === "string") {
    return resource;
  }
  if (resource == null) {
    return "";
  }
  if (resource && typeof resource === "object") {
    const r = resource as Record<string, unknown>;
    const kind = typeof r["kind"] === "string" ? (r["kind"] as string).toLowerCase() : null;
    const path = typeof r["path"] === "string" ? r["path"] : null;
    const host = typeof r["dest_host"] === "string" ? r["dest_host"] : null;
    const port = r["dest_port"] != null ? r["dest_port"] : null;
    if (kind === "file" || kind === "exec") {
      return path ? `${kind}:${path}` : kind;
    }
    if (kind === "network") {
      const fullUrl = typeof r["full_url"] === "string" ? r["full_url"] : null;
      if (fullUrl) {
        return `url:${fullUrl}`;
      }
      const addr = host && port != null ? `${host}:${port}` : (host ?? String(port ?? ""));
      return addr ? `net:${addr}` : "network";
    }
    if (kind === "mcptool" || kind === "mcp_tool") {
      const serverId = typeof r["server_id"] === "string" ? r["server_id"] : "server";
      const toolName = typeof r["tool_name"] === "string" ? r["tool_name"] : "tool";
      return `mcp:${serverId}:${toolName}`;
    }
    if (kind === "mcpresource" || kind === "mcp_resource") {
      const serverId = typeof r["server_id"] === "string" ? r["server_id"] : "server";
      const uri = typeof r["uri"] === "string" ? r["uri"] : "resource";
      return `mcp:${serverId}:${uri}`;
    }
    if (kind) {
      return path ? `${kind}:${path}` : kind;
    }
  }
  try {
    return JSON.stringify(resource);
  } catch {
    return String(resource);
  }
}

function deriveResource(resource: unknown, resourceJson: unknown, rawJson: unknown): string {
  const direct = asResourceText(resource);
  if (direct) {
    return direct;
  }

  if (typeof resourceJson === "string") {
    try {
      return asResourceText(JSON.parse(resourceJson));
    } catch {
      return "";
    }
  }

  const rawRecord = asRecord(rawJson);
  return rawRecord ? asResourceText(rawRecord["resource"]) : "";
}

function mapDirectDecisionEvent(value: Record<string, unknown>): EventItem {
  return {
    id: asNumber(value["id"]) ?? 0,
    timestamp: asString(value["timestamp"], new Date().toISOString()),
    decision: asString(value["decision"]),
    effective_decision: asString(value["effective_decision"], "observe"),
    action_class: asString(value["action_class"]),
    action_type: asString(value["action_type"]),
    profile: asString(value["profile"]),
    pid: asNumber(value["pid"]),
    agent_id: asString(value["agent_id"]),
    rule_id: asString(value["rule_id"]),
    resource: deriveResource(value["resource"], value["resource_json"], value["raw_json"]),
    resource_json:
      asJsonString(value["resource_json"]) ??
      asJsonString(asRecord(value["raw_json"])?.["resource"]),
    reason: asString(value["reason"]),
    message: asString(value["message"]),
    policy_version: asString(value["policy_version"]),
    raw_json: value["raw_json"]
  };
}

export function mapDecisionEvent(envelope: DecisionEventEnvelope): EventItem {
  const event = envelope.event ?? {};
  const eventId = asNumber((event as { id?: unknown }).id);
  const id = envelope.id ?? eventId ?? 0;

  const rawResource = (event as { resource?: unknown }).resource;
  const resourceJsonStr = asJsonString(rawResource);

  return {
    id,
    timestamp: asString((event as { timestamp?: unknown }).timestamp, new Date().toISOString()),
    effective_decision:
      envelope.effective_decision ??
      asString((event as { effective_decision?: unknown }).effective_decision, "observe"),
    action_class:
      envelope.action_class ?? asString((event as { action_class?: unknown }).action_class),
    action_type: asString((event as { action_type?: unknown }).action_type),
    profile: asString((event as { profile?: unknown }).profile),
    pid: asNumber((event as { pid?: unknown }).pid),
    resource: asResourceText(rawResource),
    resource_json: resourceJsonStr,
    reason: asString((event as { reason?: unknown }).reason),
    message: asString((event as { message?: unknown }).message),
    raw_json: event
  };
}

export function parseDecisionEvent(payload: unknown): EventItem | null {
  const value = asRecord(payload);
  if (!value) {
    return null;
  }

  if ("event" in value) {
    return mapDecisionEvent(value as DecisionEventEnvelope);
  }

  return mapDirectDecisionEvent(value);
}
