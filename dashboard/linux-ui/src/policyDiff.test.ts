import { describe, expect, it } from "vitest";

import { diffPolicyDocuments } from "./policyDiff";
import { emptyPolicyDocument, normalizePolicyDocument, type PolicyDocument } from "./policyHelpers";

describe("diffPolicyDocuments", () => {
  it("reports added, removed, and changed policy entries", () => {
    const active = emptyPolicyDocument();
    active.defaults.decision = "deny";
    active.profiles.default.file_deny.push({ id: "deny_secret", pattern: "/tmp/secret" });
    active.profiles.default.workspace_roots.push("/workspace/a");

    const draft = emptyPolicyDocument();
    draft.defaults.decision = "allow";
    draft.profiles.default.file_deny = [];
    draft.profiles.default.file_allow.push({ id: "allow_readme", pattern: "/tmp/readme" });

    const diff = diffPolicyDocuments(active, draft);

    expect(diff.changed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          label: "Default decision",
          before: "deny",
          after: "allow"
        })
      ])
    );
    expect(diff.removed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          label: "Profile default file deny",
          before: "deny_secret /tmp/secret"
        }),
        expect.objectContaining({
          label: "Profile default workspace root",
          before: "/workspace/a"
        })
      ])
    );
    expect(diff.added).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          label: "Profile default file allow",
          after: "allow_readme /tmp/readme"
        })
      ])
    );
  });
});

describe("diffPolicyDocuments MCP", () => {
  it("reports added, removed, and changed MCP servers and tool lists", () => {
    const active = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          mcp: {
            default_tool_action: "deny",
            servers: [
              {
                id: "old_server",
                transport: "stdio",
                exec_path_glob: "/usr/bin/python3",
                tools: { allow: ["safe_tool"], deny: [], require_approval: [] }
              }
            ]
          }
        }
      }
    }) as PolicyDocument;

    const draft = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          mcp: {
            default_tool_action: "deny",
            servers: [
              {
                id: "new_server",
                transport: "stdio",
                exec_path_glob: "/usr/bin/node",
                tools: { allow: [], deny: [], require_approval: ["write_file"] }
              }
            ]
          }
        }
      }
    }) as PolicyDocument;

    const diff = diffPolicyDocuments(active, draft);

    // Old server entry should be removed
    expect(diff.removed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: expect.stringContaining("MCP server old_server") })
      ])
    );
    // Old server allow tool should be removed
    expect(diff.removed).toEqual(
      expect.arrayContaining([expect.objectContaining({ before: "safe_tool" })])
    );
    // New server entry should be added
    expect(diff.added).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: expect.stringContaining("MCP server new_server") })
      ])
    );
    // New server require_approval tool should be added
    expect(diff.added).toEqual(
      expect.arrayContaining([expect.objectContaining({ after: "write_file" })])
    );
    // Default tool action unchanged — should not appear in changed
    const mcpDefaultChanged = diff.changed.filter((e) =>
      e.label.includes("MCP default tool action")
    );
    expect(mcpDefaultChanged).toHaveLength(0);
  });

  it("reports changed MCP default tool action", () => {
    const active = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: { default: { mcp: { default_tool_action: "allow", servers: [] } } }
    }) as PolicyDocument;

    const draft = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: { default: { mcp: { default_tool_action: "deny", servers: [] } } }
    }) as PolicyDocument;

    const diff = diffPolicyDocuments(active, draft);

    expect(diff.changed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          label: expect.stringContaining("MCP default tool action"),
          before: "allow",
          after: "deny"
        })
      ])
    );
  });
});
