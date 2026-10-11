import type { NetworkRule, PolicyDocument, ProfilePolicy, UrlRule } from "./policyHelpers";

export type PolicyDiffEntry = {
  key: string;
  label: string;
  before?: string;
  after?: string;
};

export type PolicyDiffSummary = {
  added: PolicyDiffEntry[];
  removed: PolicyDiffEntry[];
  changed: PolicyDiffEntry[];
};

type FlattenedEntry = {
  label: string;
  value: string;
};

function formatNetworkRule(rule: NetworkRule): string {
  const parts = [`id=${rule.id}`];
  if (rule.host_glob) parts.push(`host=${rule.host_glob}`);
  if (rule.cidr) parts.push(`cidr=${rule.cidr}`);
  if (rule.port != null) parts.push(`port=${rule.port}`);
  if (rule.protocol) parts.push(`protocol=${rule.protocol}`);
  return parts.join(" ");
}

function formatUrlRule(rule: UrlRule): string {
  const parts = [`id=${rule.id}`];
  if (rule.scheme) parts.push(`scheme=${rule.scheme}`);
  parts.push(`host=${rule.host_glob}`);
  if (rule.port != null) parts.push(`port=${rule.port}`);
  if (rule.method) parts.push(`method=${rule.method}`);
  parts.push(`path=${rule.path_glob}`);
  if (rule.query_glob) parts.push(`query=${rule.query_glob}`);
  return parts.join(" ");
}

function addRuleCollection(
  entries: Map<string, FlattenedEntry>,
  profileName: string,
  scope: string,
  values: string[]
): void {
  for (const value of values) {
    entries.set(`${profileName}:${scope}:${value}`, {
      label: `Profile ${profileName} ${scope.replace(/_/g, " ")}`,
      value
    });
  }
}

function flattenProfile(
  entries: Map<string, FlattenedEntry>,
  profileName: string,
  profile: ProfilePolicy
): void {
  entries.set(`${profileName}:profile`, {
    label: `Profile ${profileName}`,
    value: "present"
  });

  addRuleCollection(entries, profileName, "workspace_root", [...profile.workspace_roots].sort());
  addRuleCollection(
    entries,
    profileName,
    "file allow",
    profile.file_allow.map((rule) => `${rule.id} ${rule.pattern}`).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "file deny",
    profile.file_deny.map((rule) => `${rule.id} ${rule.pattern}`).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "exec allow",
    profile.exec_allow.map((rule) => `${rule.id} ${rule.path}`).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "exec deny",
    profile.exec_deny.map((rule) => `${rule.id} ${rule.path}`).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "network allow",
    profile.network_allow.map((rule) => formatNetworkRule(rule)).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "network deny",
    profile.network_deny.map((rule) => formatNetworkRule(rule)).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "url allow",
    profile.url_allow.map((rule) => formatUrlRule(rule)).sort()
  );
  addRuleCollection(
    entries,
    profileName,
    "url deny",
    profile.url_deny.map((rule) => formatUrlRule(rule)).sort()
  );

  if (profile.mcp) {
    if (profile.mcp.default_tool_action) {
      entries.set(`${profileName}:mcp:default_tool_action`, {
        label: `Profile ${profileName} MCP default tool action`,
        value: profile.mcp.default_tool_action
      });
    }
    if (profile.mcp.default_resource_action) {
      entries.set(`${profileName}:mcp:default_resource_action`, {
        label: `Profile ${profileName} MCP default resource action`,
        value: profile.mcp.default_resource_action
      });
    }
    for (const server of profile.mcp.servers) {
      entries.set(`${profileName}:mcp:server:${server.id}`, {
        label: `Profile ${profileName} MCP server ${server.id}`,
        value: [
          `transport=${server.transport}`,
          server.exec_path_glob ? `exec=${server.exec_path_glob}` : undefined,
          server.base_url ? `base_url=${server.base_url}` : undefined,
          `tool_default=${server.default_tool_action ?? "inherit"}`,
          `resource_default=${server.default_resource_action ?? "inherit"}`
        ]
          .filter(Boolean)
          .join(" ")
      });
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} allow`,
        [...server.tools.allow].sort()
      );
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} deny`,
        [...server.tools.deny].sort()
      );
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} require_approval`,
        [...server.tools.require_approval].sort()
      );
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} resource allow`,
        [...server.resources.allow].sort()
      );
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} resource deny`,
        [...server.resources.deny].sort()
      );
      addRuleCollection(
        entries,
        profileName,
        `mcp server ${server.id} resource require_approval`,
        [...server.resources.require_approval].sort()
      );
    }
  }

  if (profile.enforcement) {
    entries.set(`${profileName}:enforcement:file`, {
      label: `Profile ${profileName} file enforcement`,
      value: profile.enforcement.file
    });
    entries.set(`${profileName}:enforcement:process`, {
      label: `Profile ${profileName} process enforcement`,
      value: profile.enforcement.process
    });
    entries.set(`${profileName}:enforcement:network`, {
      label: `Profile ${profileName} network enforcement`,
      value: profile.enforcement.network
    });
  }
}

function flattenPolicyDocument(document: PolicyDocument): Map<string, FlattenedEntry> {
  const entries = new Map<string, FlattenedEntry>();

  entries.set("defaults:decision", {
    label: "Default decision",
    value: document.defaults.decision
  });
  entries.set("defaults:fail_mode", {
    label: "Fail mode",
    value: document.defaults.fail_mode
  });
  entries.set("defaults:audit_level", {
    label: "Audit level",
    value: document.defaults.audit_level
  });
  entries.set("defaults:enforcement:file", {
    label: "Default file enforcement",
    value: document.defaults.enforcement.file
  });
  entries.set("defaults:enforcement:process", {
    label: "Default process enforcement",
    value: document.defaults.enforcement.process
  });
  entries.set("defaults:enforcement:network", {
    label: "Default network enforcement",
    value: document.defaults.enforcement.network
  });

  for (const [profileName, profile] of Object.entries(document.profiles).sort(([left], [right]) =>
    left.localeCompare(right)
  )) {
    flattenProfile(entries, profileName, profile);
  }

  return entries;
}

function sortEntries(entries: PolicyDiffEntry[]): PolicyDiffEntry[] {
  return [...entries].sort(
    (left, right) => left.label.localeCompare(right.label) || left.key.localeCompare(right.key)
  );
}

export function diffPolicyDocuments(
  active: PolicyDocument,
  draft: PolicyDocument
): PolicyDiffSummary {
  const current = flattenPolicyDocument(active);
  const next = flattenPolicyDocument(draft);
  const added: PolicyDiffEntry[] = [];
  const removed: PolicyDiffEntry[] = [];
  const changed: PolicyDiffEntry[] = [];
  const keys = new Set([...current.keys(), ...next.keys()]);

  for (const key of keys) {
    const before = current.get(key);
    const after = next.get(key);
    if (!before && after) {
      added.push({
        key,
        label: after.label,
        after: after.value
      });
      continue;
    }
    if (before && !after) {
      removed.push({
        key,
        label: before.label,
        before: before.value
      });
      continue;
    }
    if (before && after && before.value !== after.value) {
      changed.push({
        key,
        label: after.label,
        before: before.value,
        after: after.value
      });
    }
  }

  return {
    added: sortEntries(added),
    removed: sortEntries(removed),
    changed: sortEntries(changed)
  };
}
