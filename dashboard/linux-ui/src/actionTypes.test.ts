import { describe, expect, it } from "vitest";

import {
  ACTION_CLASS_OPTIONS,
  ACTION_TYPES,
  actionTypeLabel,
  decisionLabel,
  isInformational
} from "./actionTypes";

describe("action types", () => {
  it("labels the lifecycle, tamper, MCP request and system action types", () => {
    for (const actionType of [
      "PROC_START",
      "PROC_EXIT",
      "PROC_BPF",
      "PROC_MODULE_LOAD",
      "PROC_MOUNT",
      "PROC_USERNS",
      "MCP_REQUEST",
      "SYSTEM_EVENT"
    ]) {
      expect(ACTION_TYPES).toContain(actionType);
    }
    expect(actionTypeLabel("PROC_MODULE_LOAD")).toBe("Kernel module load");
    expect(actionTypeLabel("SOMETHING_NEW")).toBe("something new");
    expect(ACTION_CLASS_OPTIONS.map((option) => option.value)).toContain("system");
  });

  it("shows informational records as info unless they were denied", () => {
    const system = {
      action_type: "SYSTEM_EVENT",
      reason: "INFORMATIONAL",
      effective_decision: "allow"
    };
    expect(isInformational(system)).toBe(true);
    expect(decisionLabel(system)).toBe("info");
    expect(
      decisionLabel({ ...system, reason: "DENY_BY_DEFAULT", effective_decision: "deny" })
    ).toBe("deny");
    expect(
      decisionLabel({
        action_type: "FILE_READ",
        reason: "ALLOW_BY_RULE",
        effective_decision: "allow"
      })
    ).toBe("allow");
  });
});
