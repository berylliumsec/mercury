import type { EventItem } from "./eventHelpers";

/** Every audit action type, in display order, with an operator-facing label. */
export const ACTION_TYPE_LABELS: Record<string, string> = {
  FILE_READ: "File read",
  FILE_WRITE: "File write",
  FILE_DELETE: "File delete",
  FILE_MMAP: "Shared file mmap",
  FILE_RENAME: "File rename",
  FILE_LINK: "Hard link",
  FILE_SYMLINK: "Symlink",
  FILE_MKDIR: "Directory create",
  FILE_RMDIR: "Directory remove",
  FILE_CREATE: "File create",
  FILE_CHMOD: "Permission change",
  FILE_CHOWN: "Owner change",
  FILE_TRUNCATE: "File truncate",
  PROC_EXEC: "Process exec",
  PROC_START: "Process start",
  PROC_EXIT: "Process exit",
  PROC_PTRACE: "Ptrace",
  PROC_KILL: "Signal",
  PROC_CAPABLE: "Capability use",
  PROC_BPF: "BPF syscall",
  PROC_MODULE_LOAD: "Kernel module load",
  PROC_MOUNT: "Mount",
  PROC_USERNS: "User namespace",
  NET_CONNECT: "Network connect",
  NET_SENDMSG: "UDP send",
  NET_BIND: "Socket bind",
  NET_LISTEN: "Socket listen",
  NET_ACCEPT: "Socket accept",
  NET_CREATE: "Socket create",
  MCP_TOOL_CALL: "MCP tool call",
  MCP_RESOURCE_READ: "MCP resource read",
  MCP_REQUEST: "MCP request",
  SYSTEM_EVENT: "System event"
};

export const ACTION_TYPES = Object.keys(ACTION_TYPE_LABELS);

/** Privileged operations that can be used to tamper with enforcement. */
export const TAMPER_ACTION_TYPES = new Set(["PROC_BPF", "PROC_MODULE_LOAD", "PROC_MOUNT"]);

export const ACTION_CLASS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "file", label: "FILE" },
  { value: "process", label: "EXEC" },
  { value: "network", label: "NET" },
  { value: "mcp", label: "MCP" },
  { value: "system", label: "SYSTEM" }
];

export function actionTypeLabel(actionType: string): string {
  return ACTION_TYPE_LABELS[actionType] ?? actionType.replace(/_/g, " ").toLowerCase();
}

/** Mercury's own records (lifecycle, telemetry, operator actions) carry no policy decision. */
export function isInformational(item: Pick<EventItem, "action_type" | "reason">): boolean {
  return item.action_type === "SYSTEM_EVENT" || item.reason === "INFORMATIONAL";
}

/** Decision pill text: "info" for informational allows, otherwise the effective decision. */
export function decisionLabel(
  item: Pick<EventItem, "action_type" | "reason" | "effective_decision">
): string {
  if (isInformational(item) && item.effective_decision !== "deny") {
    return "info";
  }
  return item.effective_decision;
}
