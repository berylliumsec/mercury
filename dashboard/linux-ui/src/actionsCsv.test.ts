import { describe, expect, it } from "vitest";

import { buildActionsCsv } from "./actionsCsv";

describe("buildActionsCsv", () => {
  it("escapes commas, quotes, and newlines", () => {
    const csv = buildActionsCsv([
      {
        id: 1,
        ts: "2026-03-08T10:15:00Z",
        action: "policy_apply",
        actor: 'ops,"team"',
        details: "line one\nline two"
      }
    ]);

    expect(csv).toContain(
      "id,time,action,outcome,actor,source_ip,user_agent,session_id_hash,details"
    );
    expect(csv).toContain('"ops,""team"""');
    expect(csv).toContain('"line one\nline two"');
  });

  it("includes outcome and request origin columns", () => {
    const csv = buildActionsCsv([
      {
        id: 7,
        ts: "2026-03-08T10:15:00Z",
        action: "login_failed",
        actor: "anonymous",
        details: "invalid credentials attempted_user=root",
        outcome: "failure",
        source_ip: "203.0.113.9",
        user_agent: "curl/8",
        session_id_hash: null
      }
    ]);

    expect(csv.split("\n")[1]).toBe(
      "7,2026-03-08T10:15:00Z,login_failed,failure,anonymous,203.0.113.9,curl/8,,invalid credentials attempted_user=root"
    );
  });
});
