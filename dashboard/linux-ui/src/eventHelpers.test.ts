import { describe, expect, it } from "vitest";
import { mapDecisionEvent, parseDecisionEvent, type DecisionEventEnvelope } from "./eventHelpers";

describe("mapDecisionEvent", () => {
  it("overrides event identity/decision fields from envelope", () => {
    const envelope: DecisionEventEnvelope = {
      id: 99,
      effective_decision: "deny",
      action_class: "network",
      event: {
        id: 1,
        timestamp: "2026-01-01T00:00:00Z",
        effective_decision: "allow",
        action_class: "file",
        action_type: "NET_CONNECT",
        profile: "default",
        pid: 4242,
        resource: "net:example.com:443",
        reason: "DENY_BY_RULE",
        message: "blocked"
      }
    };

    const mapped = mapDecisionEvent(envelope);
    expect(mapped.id).toBe(99);
    expect(mapped.effective_decision).toBe("deny");
    expect(mapped.action_class).toBe("network");
    expect(mapped.timestamp).toBe("2026-01-01T00:00:00Z");
    expect(mapped.resource).toBe("net:example.com:443");
  });

  it("uses canonical url resource text for structured network payloads", () => {
    const envelope: DecisionEventEnvelope = {
      id: 42,
      effective_decision: "allow",
      action_class: "network",
      event: {
        timestamp: "2026-01-01T00:00:00Z",
        action_type: "NET_CONNECT",
        profile: "default",
        resource: {
          kind: "NETWORK",
          dest_host: "example.com",
          dest_port: 443,
          full_url: "https://example.com/admin"
        },
        reason: "ALLOW_BY_RULE"
      }
    };

    const mapped = mapDecisionEvent(envelope);
    expect(mapped.id).toBe(42);
    expect(mapped.resource).toBe("url:https://example.com/admin");
    expect(mapped.action_class).toBe("network");
    expect(mapped.resource_json).toContain('"full_url":"https://example.com/admin"');
  });

  it("does not throw when envelope event is null", () => {
    const mapped = mapDecisionEvent({
      id: 7,
      effective_decision: "observe",
      action_class: "file",
      event: null
    });

    expect(mapped.id).toBe(7);
    expect(mapped.action_class).toBe("file");
    expect(mapped.effective_decision).toBe("observe");
    expect(mapped.resource).toBe("");
  });
});

describe("parseDecisionEvent", () => {
  it("accepts canonical decision event payloads from the SSE stream", () => {
    const payload = {
      id: 77,
      timestamp: "2026-01-01T00:00:00Z",
      decision: "deny",
      effective_decision: "deny",
      action_class: "network",
      action_type: "NET_CONNECT",
      profile: "default",
      pid: 99,
      agent_id: "agent-1",
      rule_id: "rule-1",
      resource: "url:https://example.com/blocked",
      resource_json:
        '{"kind":"NETWORK","dest_host":"example.com","dest_port":443,"full_url":"https://example.com/blocked"}',
      reason: "DENY_BY_RULE",
      message: "blocked",
      policy_version: "v1",
      raw_json: {
        action_type: "NET_CONNECT",
        resource: {
          kind: "NETWORK",
          dest_host: "example.com",
          dest_port: 443,
          full_url: "https://example.com/blocked"
        }
      }
    };

    const parsed = parseDecisionEvent(payload);
    expect(parsed).not.toBeNull();
    expect(parsed?.id).toBe(77);
    expect(parsed?.resource).toBe("url:https://example.com/blocked");
    expect(parsed?.resource_json).toContain('"full_url":"https://example.com/blocked"');
    expect(parsed?.raw_json).toEqual(payload.raw_json);
  });
});
