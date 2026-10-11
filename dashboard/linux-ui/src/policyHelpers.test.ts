import { describe, expect, it } from "vitest";
import {
  emptyPolicyDocument,
  nextRuleId,
  normalizePolicyDocument,
  type PolicyDocument
} from "./policyHelpers";

describe("normalizePolicyDocument", () => {
  it("returns defaults for invalid input", () => {
    const normalized = normalizePolicyDocument(null);
    const defaults = emptyPolicyDocument();
    expect(normalized).toEqual(defaults);
  });

  it("normalizes profile rules and ignores removed top-level rules", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: { decision: "allow", fail_mode: "fail_open", audit_level: "errors" },
      profiles: {
        default: {
          workspace_roots: [" /workspace "],
          file_allow: [{ pattern: "/workspace/**" }],
          network_allow: [{ id: "allow_net", host_glob: " example.com " }]
        }
      },
      rules: [{ id: "allow_shell", description: " shell " }, { description: "missing-id" }]
    }) as PolicyDocument;

    expect(normalized.defaults.decision).toBe("allow");
    expect(normalized.defaults.fail_mode).toBe("fail_open");
    expect(normalized.defaults.audit_level).toBe("errors");
    expect(normalized.profiles.default.workspace_roots).toEqual(["/workspace"]);
    expect(normalized.profiles.default.file_allow[0]?.id).toBe("file_allow_1");
    expect(normalized.profiles.default.file_allow[0]?.pattern).toBe("/workspace/**");
    expect(normalized.profiles.default.network_allow[0]?.host_glob).toBe("example.com");
    expect("rules" in normalized).toBe(false);
  });

  it("normalizes URL and numeric fields", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          url_allow: [
            {
              id: "allow_docs",
              host_glob: "docs.example.com",
              path_glob: "/v1/**",
              method: "GET",
              port: "443"
            }
          ]
        }
      }
    }) as PolicyDocument;

    const rule = normalized.profiles.default.url_allow[0];
    expect(rule?.id).toBe("allow_docs");
    expect(rule?.port).toBe(443);
    expect(rule?.method).toBe("GET");
  });
});

describe("nextRuleId", () => {
  it("returns the next available sequence", () => {
    expect(nextRuleId(["file_allow_1", "file_allow_2"], "file_allow")).toBe("file_allow_3");
  });
});

describe("normalizeMcpPolicy", () => {
  it("preserves valid MCP server with tool lists", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          mcp: {
            default_tool_action: "deny",
            servers: [
              {
                id: "python_mcp",
                transport: "stdio",
                exec_path_glob: "/usr/bin/python3",
                default_tool_action: "deny",
                tools: {
                  allow: ["safe_tool"],
                  deny: ["rm_tool"],
                  require_approval: ["write_file"]
                }
              }
            ]
          }
        }
      }
    }) as PolicyDocument;

    const mcp = normalized.profiles.default.mcp;
    expect(mcp).toBeDefined();
    expect(mcp?.default_tool_action).toBe("deny");
    expect(mcp?.servers).toHaveLength(1);
    const server = mcp?.servers[0];
    expect(server?.id).toBe("python_mcp");
    expect(server?.exec_path_glob).toBe("/usr/bin/python3");
    expect(server?.default_tool_action).toBe("deny");
    expect(server?.tools.allow).toEqual(["safe_tool"]);
    expect(server?.tools.deny).toEqual(["rm_tool"]);
    expect(server?.tools.require_approval).toEqual(["write_file"]);
  });

  it("returns undefined mcp when input is missing or not an object", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: { default: { mcp: null } }
    }) as PolicyDocument;
    expect(normalized.profiles.default.mcp).toBeUndefined();
  });

  it("trims whitespace in tool names and server fields", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          mcp: {
            servers: [
              {
                id: "  trimmed_server  ",
                exec_path_glob: "  /usr/bin/node  ",
                tools: {
                  allow: ["  tool_a  ", "  tool_b  "],
                  deny: [],
                  require_approval: []
                }
              }
            ]
          }
        }
      }
    }) as PolicyDocument;

    const server = normalized.profiles.default.mcp?.servers[0];
    expect(server?.id).toBe("trimmed_server");
    expect(server?.exec_path_glob).toBe("/usr/bin/node");
    expect(server?.tools.allow).toEqual(["tool_a", "tool_b"]);
  });

  it("leaves default_tool_action undefined for unrecognized values", () => {
    const normalized = normalizePolicyDocument({
      version: "v1",
      defaults: {},
      profiles: {
        default: {
          mcp: {
            default_tool_action: "bogus_value",
            servers: []
          }
        }
      }
    }) as PolicyDocument;

    expect(normalized.profiles.default.mcp?.default_tool_action).toBeUndefined();
  });
});
