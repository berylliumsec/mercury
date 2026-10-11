import { describe, expect, it } from "vitest";

import { capabilityName, eventDetailFields, formatArgv, signalName } from "./eventDetails";
import type { EventItem } from "./eventHelpers";

function item(raw: Record<string, unknown>, overrides: Partial<EventItem> = {}): EventItem {
  return {
    id: 1,
    timestamp: "2026-09-29T00:00:00Z",
    decision: "deny",
    effective_decision: "deny",
    action_class: "process",
    action_type: String(raw["action_type"] ?? "PROC_EXEC"),
    profile: "default",
    pid: 42,
    agent_id: "agent-1",
    resource: "x",
    reason: "DENY_BY_RULE",
    message: "m",
    raw_json: raw,
    ...overrides
  };
}

function fieldMap(event: EventItem): Record<string, string> {
  return Object.fromEntries(eventDetailFields(event).map((field) => [field.key, field.value]));
}

describe("eventDetailFields", () => {
  it("shows process context, argv and exit status of lifecycle events", () => {
    const fields = fieldMap(
      item({
        action_type: "PROC_EXIT",
        ppid: 7,
        tid: 43,
        comm: "python3",
        cgroup_id: 991,
        exit_code: 1,
        exit_signal: 9,
        correlation_id: "corr-1",
        resource: {
          kind: "EXEC",
          path: "/usr/bin/python3",
          cwd: "/work",
          argv: ["python3", "-c", "print('hi there')"],
          argv_truncated: true
        }
      })
    );
    expect(fields["action_type"]).toBe("Process exit (PROC_EXIT)");
    expect(fields["ppid"]).toBe("7");
    expect(fields["tid"]).toBe("43");
    expect(fields["comm"]).toBe("python3");
    expect(fields["cgroup_id"]).toBe("991");
    expect(fields["exit_code"]).toBe("1");
    expect(fields["exit_signal"]).toBe("SIGKILL (9)");
    expect(fields["correlation_id"]).toBe("corr-1");
    expect(fields["resource.argv"]).toBe(`python3 -c "print('hi there')"`);
    expect(fields["resource.argv_truncated"]).toContain("yes");
    expect(fields["resource.path"]).toBe("/usr/bin/python3");
  });

  it("shows kill targets, capabilities, rename sources and unix sockets", () => {
    expect(fieldMap(item({ action_type: "PROC_KILL", target_pid: 77, signal: 15 }))).toMatchObject({
      target_pid: "77",
      signal: "SIGTERM (15)"
    });
    expect(fieldMap(item({ action_type: "PROC_CAPABLE", capability: 21 }))["capability"]).toBe(
      "CAP_SYS_ADMIN (21)"
    );
    expect(
      fieldMap(
        item({
          action_type: "FILE_RENAME",
          resource: {
            kind: "FILE",
            path: "/tmp/b",
            source_path: "/home/u/.ssh/id_rsa",
            op: "RENAME"
          }
        })
      )["resource.source_path"]
    ).toBe("/home/u/.ssh/id_rsa");
    expect(
      fieldMap(
        item({
          action_type: "NET_CONNECT",
          resource: {
            kind: "NETWORK",
            socket_path: "/run/docker.sock",
            family: "unix",
            dest_port: 0
          }
        })
      )
    ).toMatchObject({ "resource.socket_path": "/run/docker.sock", "resource.family": "unix" });
  });

  it("shows actor, outcome, simulation and truncation flags", () => {
    const fields = fieldMap(
      item({
        action_type: "NET_CONNECT",
        actor: "admin",
        simulated: true,
        truncated: true,
        outcome: {
          status: 502,
          bytes_sent: 10,
          bytes_received: 2048,
          duration_ms: 31,
          error: "bad gateway"
        }
      })
    );
    expect(fields["actor"]).toBe("admin");
    expect(fields["outcome.status"]).toBe("502");
    expect(fields["outcome.duration_ms"]).toBe("31 ms");
    expect(fields["outcome.error"]).toBe("bad gateway");
    expect(fields["simulated"]).toContain("dry run");
    expect(fields["truncated"]).toContain("yes");
  });

  it("lists system event attributes and omits absent fields", () => {
    const fields = eventDetailFields(
      item(
        {
          action_type: "SYSTEM_EVENT",
          source: "dashboard",
          resource: {
            kind: "SYSTEM",
            event: "auth_failure",
            detail: "login_failed",
            attributes: { attempted_user: "root", source_ip: "203.0.113.9" }
          }
        },
        { reason: "DENY_BY_DEFAULT", pid: undefined, action_class: "system" }
      )
    );
    const byKey = Object.fromEntries(fields.map((field) => [field.key, field]));
    expect(byKey["resource.event"].value).toBe("auth_failure");
    expect(byKey["attr.attempted_user"].value).toBe("root");
    expect(byKey["attr.source_ip"].label).toBe("source ip");
    expect(byKey["source"].value).toBe("dashboard");
    expect(byKey["pid"]).toBeUndefined();
    expect(byKey["signal"]).toBeUndefined();
    expect(byKey["resource.path"]).toBeUndefined();
  });

  it("falls back to resource_json when the raw record is missing", () => {
    const fields = fieldMap(
      item(
        {},
        {
          raw_json: undefined,
          resource_json: '{"kind":"FILE","path":"/etc/shadow","op":"READ"}'
        }
      )
    );
    expect(fields["resource.path"]).toBe("/etc/shadow");
  });
});

describe("formatting helpers", () => {
  it("names signals and capabilities and quotes argv", () => {
    expect(signalName(99)).toBe("99");
    expect(capabilityName(39)).toBe("CAP_BPF (39)");
    expect(formatArgv(["ls", "-la", "my dir", ""])).toBe('ls -la "my dir" ""');
  });
});
