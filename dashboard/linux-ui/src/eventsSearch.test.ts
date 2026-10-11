import { describe, expect, it } from "vitest";

import type { EventItem } from "./eventHelpers";
import {
  buildEventsExportPath,
  buildEventsQueryParams,
  eventMatchesFilters,
  LatestRequestController,
  parseGapSkipped
} from "./eventsSearch";

describe("buildEventsQueryParams", () => {
  it("serializes the active event filters for the backend query", () => {
    const query = buildEventsQueryParams({
      decision: "deny",
      actionClass: "network",
      text: "  https://example.com/blocked  "
    });

    expect(query.toString()).toBe(
      "limit=120&offset=0&decision=deny&class=network&text=https%3A%2F%2Fexample.com%2Fblocked"
    );
  });
});

describe("event filters for agent and action type", () => {
  const filters = {
    decision: "all",
    actionClass: "system",
    text: "",
    actionType: "SYSTEM_EVENT",
    agentId: " mercuryd "
  };

  it("sends agent, action type and paging cursor to the backend", () => {
    expect(buildEventsQueryParams(filters, 50, 0, 900).toString()).toBe(
      "limit=50&offset=0&before_id=900&class=system&action_type=SYSTEM_EVENT&agent_id=mercuryd"
    );
    expect(buildEventsExportPath(filters, "csv")).toBe(
      "/events/export?class=system&action_type=SYSTEM_EVENT&agent_id=mercuryd&format=csv"
    );
  });

  it("applies agent and action type to live events", () => {
    const item: EventItem = {
      id: 5,
      timestamp: "2026-01-01T00:00:00Z",
      effective_decision: "allow",
      action_class: "system",
      action_type: "SYSTEM_EVENT",
      profile: "system",
      agent_id: "mercuryd",
      resource: "system:dashboard_action:login_success",
      reason: "INFORMATIONAL",
      message: "login"
    };
    expect(eventMatchesFilters(item, filters)).toBe(true);
    expect(eventMatchesFilters(item, { ...filters, agentId: "agent-2" })).toBe(false);
    expect(eventMatchesFilters(item, { ...filters, actionType: "PROC_START" })).toBe(false);
  });
});

describe("parseGapSkipped", () => {
  it("reads the skipped count from gap frames", () => {
    expect(parseGapSkipped('{"skipped":37,"reason":"lagged"}')).toBe(37);
    expect(parseGapSkipped('{"skipped":0}')).toBe(0);
    expect(parseGapSkipped("not json")).toBe(0);
  });
});

describe("eventMatchesFilters", () => {
  it("matches url events the same way history queries do", () => {
    const item: EventItem = {
      id: 1,
      timestamp: "2026-01-01T00:00:00Z",
      effective_decision: "deny",
      action_class: "network",
      action_type: "NET_CONNECT",
      profile: "default",
      resource: "url:https://example.com/blocked",
      resource_json:
        '{"kind":"NETWORK","dest_host":"example.com","dest_port":443,"full_url":"https://example.com/blocked"}',
      reason: "DENY_BY_RULE",
      message: "blocked by url policy",
      raw_json: {
        action_type: "NET_CONNECT",
        resource: {
          kind: "NETWORK",
          full_url: "https://example.com/blocked"
        }
      }
    };

    expect(
      eventMatchesFilters(item, {
        decision: "deny",
        actionClass: "network",
        text: "https://example.com/blocked"
      })
    ).toBe(true);
  });
});

describe("LatestRequestController", () => {
  it("aborts the previous request and marks it stale when a new query starts", () => {
    const controller = new LatestRequestController();
    const first = controller.begin();
    const second = controller.begin();

    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(false);
    expect(controller.isCurrent(first.requestId)).toBe(false);
    expect(controller.isCurrent(second.requestId)).toBe(true);
  });
});
