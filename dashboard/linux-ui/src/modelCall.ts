/**
 * Model-call context carried on gateway audit events.
 *
 * The daemon attaches a `model` object to the audit event of a recognised model
 * API exchange when `url_gateway.model_traffic.capture` is `metadata` or
 * `content` (crates/daemon/src/model_capture.rs). Captured text reaches the
 * dashboard already redacted and truncated by the gateway, so the UI renders it
 * as-is and only reports the limits that were hit.
 */

export type ModelUsage = {
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
  reasoning_tokens?: number;
  total_tokens?: number;
};

export type ModelToolCall = {
  name: string;
  id?: string;
  arguments?: string;
};

export type ModelMessage = {
  role: string;
  text: string;
};

export type ModelCall = {
  call_id: string;
  provider: string;
  api: string;
  /** `http`, `sse`, or `websocket`. */
  transport: string;
  model?: string;
  stream: boolean;
  status?: number;
  duration_ms: number;
  request_bytes: number;
  response_bytes: number;
  request_sha256?: string;
  message_count?: number;
  tools_offered: string[];
  tool_calls: ModelToolCall[];
  finish_reason?: string;
  usage?: ModelUsage;
  system?: string;
  messages: ModelMessage[];
  output_text?: string;
  reasoning_text?: string;
  truncated: boolean;
  error?: string;
  capture_note?: string;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function strList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function toolCalls(value: unknown): ModelToolCall[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((entry) => {
    const record = asRecord(entry);
    const name = record ? str(record["name"]) : undefined;
    if (!name) {
      return [];
    }
    return [{ name, id: str(record?.["id"]), arguments: str(record?.["arguments"]) }];
  });
}

function messages(value: unknown): ModelMessage[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((entry) => {
    const record = asRecord(entry);
    if (!record) {
      return [];
    }
    return [
      {
        role: str(record["role"]) ?? "unknown",
        text: typeof record["text"] === "string" ? record["text"] : ""
      }
    ];
  });
}

function usage(value: unknown): ModelUsage | undefined {
  const record = asRecord(value);
  if (!record) {
    return undefined;
  }
  const parsed: ModelUsage = {
    input_tokens: num(record["input_tokens"]),
    output_tokens: num(record["output_tokens"]),
    cache_read_tokens: num(record["cache_read_tokens"]),
    cache_write_tokens: num(record["cache_write_tokens"]),
    reasoning_tokens: num(record["reasoning_tokens"]),
    total_tokens: num(record["total_tokens"])
  };
  return Object.values(parsed).some((entry) => entry != null) ? parsed : undefined;
}

/** The `model` context of an audit event, or null when the event is not a model call. */
export function parseModelCall(rawJson: unknown): ModelCall | null {
  let source: unknown = rawJson;
  if (typeof source === "string") {
    try {
      source = JSON.parse(source);
    } catch {
      return null;
    }
  }

  const event = asRecord(source);
  const model = event ? asRecord(event["model"]) : null;
  if (!model) {
    return null;
  }

  const provider = str(model["provider"]);
  if (!provider) {
    return null;
  }

  return {
    call_id: str(model["call_id"]) ?? "",
    provider,
    api: str(model["api"]) ?? "",
    transport: str(model["transport"]) ?? "http",
    model: str(model["model"]),
    stream: model["stream"] === true,
    status: num(model["status"]),
    duration_ms: num(model["duration_ms"]) ?? 0,
    request_bytes: num(model["request_bytes"]) ?? 0,
    response_bytes: num(model["response_bytes"]) ?? 0,
    request_sha256: str(model["request_sha256"]),
    message_count: num(model["message_count"]),
    tools_offered: strList(model["tools_offered"]),
    tool_calls: toolCalls(model["tool_calls"]),
    finish_reason: str(model["finish_reason"]),
    usage: usage(model["usage"]),
    system: str(model["system"]),
    messages: messages(model["messages"]),
    output_text: str(model["output_text"]),
    reasoning_text: str(model["reasoning_text"]),
    truncated: model["truncated"] === true,
    error: str(model["error"]),
    capture_note: str(model["capture_note"])
  };
}

/** True when the gateway ran at `capture: content` and kept some text. */
export function hasCapturedContent(call: ModelCall): boolean {
  return Boolean(call.messages.length || call.system || call.output_text || call.reasoning_text);
}

/** Short label for the events table, e.g. `anthropic · claude-opus-5`. */
export function modelCallLabel(call: ModelCall): string {
  return call.model ? `${call.provider} · ${call.model}` : call.provider;
}

export function transportLabel(call: ModelCall): string {
  return call.stream ? `${call.transport} · streamed` : call.transport;
}

export function formatDurationMs(ms: number): string {
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  if (ms < 60_000) {
    return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  }
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function formatTokens(usage: ModelUsage | undefined): string {
  if (!usage) {
    return "not reported";
  }
  const parts: string[] = [];
  if (usage.input_tokens != null) {
    parts.push(`${usage.input_tokens.toLocaleString()} in`);
  }
  if (usage.output_tokens != null) {
    parts.push(`${usage.output_tokens.toLocaleString()} out`);
  }
  if (usage.reasoning_tokens != null) {
    parts.push(`${usage.reasoning_tokens.toLocaleString()} reasoning`);
  }
  if (usage.cache_read_tokens != null) {
    parts.push(`${usage.cache_read_tokens.toLocaleString()} cache read`);
  }
  if (usage.cache_write_tokens != null) {
    parts.push(`${usage.cache_write_tokens.toLocaleString()} cache write`);
  }
  if (!parts.length && usage.total_tokens != null) {
    parts.push(`${usage.total_tokens.toLocaleString()} total`);
  }
  return parts.length ? parts.join(" · ") : "not reported";
}

/**
 * What the operator needs to know about the fidelity of what they are reading:
 * the gateway drops thinking blocks, clips long fields and keeps only the most
 * recent messages, so a transcript is never a verbatim copy of the exchange.
 */
export function captureNotices(call: ModelCall): string[] {
  const notices: string[] = [];
  if (call.error) {
    notices.push(`Exchange error: ${call.error}`);
  }
  if (call.truncated) {
    notices.push("Some captured text hit the gateway's size limits and was clipped.");
  }
  if (call.capture_note) {
    notices.push(call.capture_note);
  }
  if (!hasCapturedContent(call)) {
    notices.push(
      "Captured at metadata level — set url_gateway.model_traffic.capture to content to record prompts and output."
    );
  } else if (call.message_count != null && call.message_count > call.messages.length) {
    notices.push(
      `Showing the last ${call.messages.length} of ${call.message_count} messages (max_messages).`
    );
  }
  return notices;
}

/** Role display name; anything unrecognised is shown as reported. */
export function roleLabel(role: string): string {
  switch (role.toLowerCase()) {
    case "user":
      return "User";
    case "assistant":
    case "model":
      return "Assistant";
    case "system":
      return "System";
    case "tool":
    case "function":
      return "Tool";
    default:
      return role;
  }
}
