import { actionTypeLabel } from "./actionTypes";
import type { EventItem } from "./eventHelpers";

export type EventDetailField = {
  key: string;
  label: string;
  value: string;
  mono?: boolean;
};

const SIGNAL_NAMES: Record<number, string> = {
  1: "SIGHUP",
  2: "SIGINT",
  3: "SIGQUIT",
  4: "SIGILL",
  6: "SIGABRT",
  7: "SIGBUS",
  8: "SIGFPE",
  9: "SIGKILL",
  10: "SIGUSR1",
  11: "SIGSEGV",
  12: "SIGUSR2",
  13: "SIGPIPE",
  14: "SIGALRM",
  15: "SIGTERM",
  17: "SIGCHLD",
  18: "SIGCONT",
  19: "SIGSTOP",
  20: "SIGTSTP",
  31: "SIGSYS"
};

const CAPABILITY_NAMES = [
  "CAP_CHOWN",
  "CAP_DAC_OVERRIDE",
  "CAP_DAC_READ_SEARCH",
  "CAP_FOWNER",
  "CAP_FSETID",
  "CAP_KILL",
  "CAP_SETGID",
  "CAP_SETUID",
  "CAP_SETPCAP",
  "CAP_LINUX_IMMUTABLE",
  "CAP_NET_BIND_SERVICE",
  "CAP_NET_BROADCAST",
  "CAP_NET_ADMIN",
  "CAP_NET_RAW",
  "CAP_IPC_LOCK",
  "CAP_IPC_OWNER",
  "CAP_SYS_MODULE",
  "CAP_SYS_RAWIO",
  "CAP_SYS_CHROOT",
  "CAP_SYS_PTRACE",
  "CAP_SYS_PACCT",
  "CAP_SYS_ADMIN",
  "CAP_SYS_BOOT",
  "CAP_SYS_NICE",
  "CAP_SYS_RESOURCE",
  "CAP_SYS_TIME",
  "CAP_SYS_TTY_CONFIG",
  "CAP_MKNOD",
  "CAP_LEASE",
  "CAP_AUDIT_WRITE",
  "CAP_AUDIT_CONTROL",
  "CAP_SETFCAP",
  "CAP_MAC_OVERRIDE",
  "CAP_MAC_ADMIN",
  "CAP_SYSLOG",
  "CAP_WAKE_ALARM",
  "CAP_BLOCK_SUSPEND",
  "CAP_AUDIT_READ",
  "CAP_PERFMON",
  "CAP_BPF",
  "CAP_CHECKPOINT_RESTORE"
];

export function signalName(signal: number): string {
  const name = SIGNAL_NAMES[signal];
  return name ? `${name} (${signal})` : String(signal);
}

export function capabilityName(capability: number): string {
  const name = CAPABILITY_NAMES[capability];
  return name ? `${name} (${capability})` : String(capability);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "string") {
    return asRecord(value);
  }
  try {
    return asRecord(JSON.parse(value));
  } catch {
    return null;
  }
}

/** The original audit record behind a live-view row ({} when unavailable). */
export function eventRecord(item: EventItem): Record<string, unknown> {
  return parseRecord(item.raw_json) ?? {};
}

function present(value: unknown): boolean {
  if (value == null || value === "") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  return true;
}

function formatScalar(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** Shell-style argv: arguments with whitespace or quotes are JSON-quoted. */
export function formatArgv(argv: unknown[]): string {
  return argv
    .map((arg) => {
      const text = formatScalar(arg);
      return /[\s"'\\]/.test(text) || text === "" ? JSON.stringify(text) : text;
    })
    .join(" ");
}

/**
 * Every schema field present on an event, in reading order: what happened,
 * who did it, the process, the resource, then outcome and data-quality flags.
 * Fields that are absent are omitted rather than shown empty.
 */
export function eventDetailFields(item: EventItem): EventDetailField[] {
  const raw = eventRecord(item);
  const resource = asRecord(raw["resource"]) ?? parseRecord(item.resource_json) ?? {};
  const fields: EventDetailField[] = [];
  const push = (key: string, label: string, value: unknown, mono = false) => {
    if (present(value)) {
      fields.push({ key, label, value: formatScalar(value), mono });
    }
  };
  const pushNumber = (
    key: string,
    label: string,
    value: unknown,
    format: (n: number) => string
  ) => {
    if (typeof value === "number" && Number.isFinite(value)) {
      fields.push({ key, label, value: format(value) });
    }
  };

  push("action_type", "Action", `${actionTypeLabel(item.action_type)} (${item.action_type})`);
  push("decision", "Decision", item.decision || item.effective_decision);
  push("reason", "Reason", item.reason);
  push("rule_id", "Rule", item.rule_id, true);
  push("message", "Message", item.message);

  push("source", "Source", raw["source"]);
  push("actor", "Actor", raw["actor"]);
  push("host", "Host", raw["host"]);
  push("event_id", "Event ID", raw["event_id"], true);
  push("correlation_id", "Correlation ID", raw["correlation_id"], true);
  push("policy_version", "Policy version", item.policy_version || raw["policy_version"], true);
  push("policy_epoch", "Policy epoch", raw["policy_epoch"]);

  push("agent_id", "Agent", item.agent_id || raw["agent_id"], true);
  push("parent_agent_id", "Parent agent", raw["parent_agent_id"], true);
  push("profile", "Profile", item.profile);
  push("pid", "PID", item.pid ?? raw["pid"]);
  push("ppid", "PPID", raw["ppid"]);
  push("tid", "TID", raw["tid"]);
  push("uid", "UID", raw["uid"]);
  push("gid", "GID", raw["gid"]);
  push("comm", "Comm", raw["comm"], true);
  push("cgroup_id", "Cgroup ID", raw["cgroup_id"], true);
  push("root_pid", "Root PID", raw["root_pid"]);

  push("target_pid", "Target PID", raw["target_pid"]);
  pushNumber("signal", "Signal", raw["signal"], signalName);
  pushNumber("capability", "Capability", raw["capability"], capabilityName);
  push("exit_code", "Exit code", raw["exit_code"]);
  pushNumber("exit_signal", "Exit signal", raw["exit_signal"], signalName);

  const kind = typeof resource["kind"] === "string" ? resource["kind"] : "";
  if (kind !== "SYSTEM") {
    push("resource.path", kind === "NETWORK" ? "URL path" : "Path", resource["path"], true);
  }
  push("resource.source_path", "Source path", resource["source_path"], true);
  push("resource.resolved_path", "Resolved path", resource["resolved_path"], true);
  if (Array.isArray(resource["argv"]) && resource["argv"].length) {
    push("resource.argv", "Argv", formatArgv(resource["argv"] as unknown[]), true);
  }
  if (resource["argv_truncated"] === true) {
    push("resource.argv_truncated", "Argv truncated", "yes (kernel capture limit)");
  }
  push("resource.cwd", "Working directory", resource["cwd"], true);
  push("resource.socket_path", "Socket path", resource["socket_path"], true);
  push("resource.family", "Address family", resource["family"]);
  push("resource.dest_host", "Destination host", resource["dest_host"], true);
  push("resource.dest_ip", "Destination IP", resource["dest_ip"], true);
  if (kind === "NETWORK") {
    push("resource.dest_port", "Destination port", resource["dest_port"]);
    push("resource.protocol", "Protocol", resource["protocol"]);
  }
  push("resource.full_url", "URL", resource["full_url"], true);
  push("resource.method", "Method", resource["method"]);
  push("resource.server_id", "MCP server", resource["server_id"], true);
  push("resource.tool_name", "MCP tool", resource["tool_name"], true);
  push("resource.uri", "MCP URI", resource["uri"], true);

  if (kind === "SYSTEM") {
    push("resource.event", "System event", resource["event"], true);
    push("resource.detail", "Detail", resource["detail"]);
    const attributes = asRecord(resource["attributes"]) ?? {};
    for (const [key, value] of Object.entries(attributes).sort(([a], [b]) => a.localeCompare(b))) {
      push(
        `attr.${key}`,
        key.replace(/_/g, " "),
        value,
        typeof value !== "string" || key.endsWith("_id") || key.endsWith("_hash")
      );
    }
  }

  const outcome = asRecord(raw["outcome"]);
  if (outcome) {
    push("outcome.status", "Upstream status", outcome["status"]);
    pushNumber("outcome.bytes", "Bytes sent", outcome["bytes_sent"], (n) => n.toLocaleString());
    pushNumber("outcome.bytes_received", "Bytes received", outcome["bytes_received"], (n) =>
      n.toLocaleString()
    );
    pushNumber("outcome.duration_ms", "Duration", outcome["duration_ms"], (n) => `${n} ms`);
    push("outcome.error", "Upstream error", outcome["error"]);
  }

  push("events_dropped", "Events dropped before this one", raw["events_dropped"]);
  push("kernel_seq", "Kernel sequence", raw["kernel_seq"]);
  if (raw["truncated"] === true) {
    push("truncated", "Truncated", "yes (resource could not be fully resolved)");
  }
  if (raw["simulated"] === true) {
    push("simulated", "Simulated", "yes (dry run, nothing was enforced)");
  }
  return fields;
}
