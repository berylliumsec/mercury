import { describe, expect, it } from "vitest";
import {
  captureNotices,
  formatBytes,
  formatDurationMs,
  formatTokens,
  hasCapturedContent,
  modelCallLabel,
  parseModelCall,
  roleLabel,
  transportLabel
} from "./modelCall";

function rawEvent(model: unknown): Record<string, unknown> {
  return {
    timestamp: "2026-09-19T12:00:00Z",
    action_type: "NET_CONNECT",
    resource: { kind: "NETWORK", full_url: "https://api.anthropic.com/v1/messages" },
    message: "model call provider=anthropic model=claude-opus-5 status=200 duration_ms=8123",
    model
  };
}

const contentCall = rawEvent({
  call_id: "mc_7f2c",
  provider: "anthropic",
  api: "anthropic.messages",
  transport: "sse",
  model: "claude-opus-5",
  stream: true,
  status: 200,
  duration_ms: 8123,
  request_bytes: 12_400,
  response_bytes: 4_096,
  request_sha256: "a2f1c4",
  message_count: 14,
  tools_offered: ["Bash", "Read"],
  tool_calls: [{ name: "Bash", id: "toolu_01", arguments: '{"command":"ls -la"}' }],
  finish_reason: "tool_use",
  usage: { input_tokens: 5120, output_tokens: 210, cache_read_tokens: 4800 },
  system: "You are a release assistant.",
  messages: [
    { role: "user", text: "List the workspace" },
    { role: "assistant", text: '[tool_use Bash] {"command":"ls -la"}' }
  ],
  output_text: "Running ls -la now.",
  reasoning_text: "The user wants a directory listing.",
  truncated: true
});

describe("parseModelCall", () => {
  it("reads the model context off an audit event", () => {
    const call = parseModelCall(contentCall);
    expect(call).not.toBeNull();
    expect(call?.provider).toBe("anthropic");
    expect(call?.model).toBe("claude-opus-5");
    expect(call?.stream).toBe(true);
    expect(call?.messages).toHaveLength(2);
    expect(call?.tool_calls[0]).toEqual({
      name: "Bash",
      id: "toolu_01",
      arguments: '{"command":"ls -la"}'
    });
    expect(call?.usage?.cache_read_tokens).toBe(4800);
  });

  it("accepts a raw_json string payload", () => {
    const call = parseModelCall(JSON.stringify(contentCall));
    expect(call?.api).toBe("anthropic.messages");
  });

  it("returns null for events without a model context", () => {
    expect(parseModelCall({ action_type: "FILE_READ" })).toBeNull();
    expect(parseModelCall(null)).toBeNull();
    expect(parseModelCall("not json")).toBeNull();
    expect(parseModelCall({ model: { api: "openai.chat" } })).toBeNull();
  });

  it("fills defaults for a metadata-only capture", () => {
    const call = parseModelCall(
      rawEvent({ provider: "openai", api: "openai.chat", transport: "http", duration_ms: 940 })
    );
    expect(call?.stream).toBe(false);
    expect(call?.truncated).toBe(false);
    expect(call?.messages).toEqual([]);
    expect(call?.tools_offered).toEqual([]);
    expect(call?.usage).toBeUndefined();
    expect(hasCapturedContent(call!)).toBe(false);
  });

  it("drops malformed tool calls and messages", () => {
    const call = parseModelCall(
      rawEvent({
        provider: "openai",
        api: "openai.chat",
        transport: "http",
        tool_calls: [{ id: "no_name" }, { name: "Read" }],
        messages: ["plain string", { role: "user" }]
      })
    );
    expect(call?.tool_calls).toEqual([{ name: "Read", id: undefined, arguments: undefined }]);
    expect(call?.messages).toEqual([{ role: "user", text: "" }]);
  });
});

describe("captureNotices", () => {
  it("reports clipping, omitted messages and gateway notes", () => {
    const notices = captureNotices(parseModelCall(contentCall)!);
    expect(notices.some((note) => note.includes("clipped"))).toBe(true);
    expect(notices.some((note) => note.includes("last 2 of 14 messages"))).toBe(true);
  });

  it("explains a metadata-only capture", () => {
    const call = parseModelCall(
      rawEvent({ provider: "openai", api: "openai.chat", transport: "http" })
    )!;
    expect(captureNotices(call)).toEqual([
      "Captured at metadata level — set url_gateway.model_traffic.capture to content to record prompts and output."
    ]);
  });

  it("surfaces exchange errors and capture notes", () => {
    const call = parseModelCall(
      rawEvent({
        provider: "bedrock",
        api: "bedrock.invoke",
        transport: "http",
        error: "upstream reset",
        capture_note: "response body was zstd encoded"
      })
    )!;
    expect(captureNotices(call)[0]).toBe("Exchange error: upstream reset");
    expect(captureNotices(call)).toContain("response body was zstd encoded");
  });
});

describe("formatting", () => {
  it("labels the call and transport", () => {
    const call = parseModelCall(contentCall)!;
    expect(modelCallLabel(call)).toBe("anthropic · claude-opus-5");
    expect(transportLabel(call)).toBe("sse · streamed");
    expect(transportLabel({ ...call, stream: false })).toBe("sse");
    expect(modelCallLabel({ ...call, model: undefined })).toBe("anthropic");
  });

  it("formats durations, bytes and token usage", () => {
    expect(formatDurationMs(940)).toBe("940 ms");
    expect(formatDurationMs(8123)).toBe("8.1 s");
    expect(formatDurationMs(42_000)).toBe("42 s");
    expect(formatDurationMs(125_000)).toBe("2m 5s");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(12_400)).toBe("12.1 KiB");
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MiB");
    expect(formatTokens(undefined)).toBe("not reported");
    expect(formatTokens({ total_tokens: 900 })).toBe("900 total");
    expect(formatTokens({ input_tokens: 5120, output_tokens: 210 })).toBe("5,120 in · 210 out");
  });

  it("names known roles and passes through the rest", () => {
    expect(roleLabel("user")).toBe("User");
    expect(roleLabel("model")).toBe("Assistant");
    expect(roleLabel("developer")).toBe("developer");
  });
});
