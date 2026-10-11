import { expect, type Page, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { sendControlRequest } from "../support/mcp";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

async function login(page: Page) {
  await page.goto(e2e.baseUrl);
  // Accept either signup (first-time) or login form
  const isSignup = await page
    .getByTestId("signup-form")
    .isVisible()
    .catch(() => false);
  const usernameInput = page.getByTestId("auth-username-input");
  if (isSignup) {
    if (await usernameInput.isEditable().catch(() => false)) {
      await usernameInput.fill(e2e.username);
    }
    await page.getByTestId("auth-password-input").fill(e2e.password);
    await page.getByTestId("auth-password-confirm-input").fill(e2e.password);
    await page.getByTestId("signup-submit").click();
  } else {
    await usernameInput.fill(e2e.username);
    await page.getByTestId("auth-password-input").fill(e2e.password);
    await page.getByTestId("login-submit").click();
  }
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

test("MCP policy editor: add server, apply, verify YAML, remove server", async ({ page }) => {
  await login(page);
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  // Add an MCP server entry
  await page.getByTestId("mcp-section-add").click();
  await expect(page.getByTestId("mcp-server-row-0")).toBeVisible();

  // Fill server fields
  await page.getByTestId("mcp-server-id-0").fill("test_python_mcp");
  await page.getByTestId("mcp-server-exec-0").fill("/usr/bin/python3");
  await page.getByTestId("mcp-server-default-action-0").selectOption("deny");
  await page.getByTestId("mcp-server-allow-tools-0").fill("safe_read\nlist_files");
  await page.getByTestId("mcp-server-approval-tools-0").fill("write_file");

  // Save draft
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");

  // Validate draft
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");

  // Apply draft — check diff modal contains MCP entries
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await expect(page.getByTestId("apply-confirm-modal")).toContainText("test_python_mcp");
  await page.getByTestId("apply-note-input").fill("add mcp server test");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  // Verify active YAML contains the server
  await expect(page.getByTestId("active-policy-yaml")).toContainText("test_python_mcp");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("safe_read");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("write_file");

  // Remove the server
  await page.getByTestId("mcp-server-remove-0").click();
  await expect(page.getByTestId("mcp-server-row-0")).not.toBeVisible();

  // Save → validate → apply removal
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  // Verify server removed from YAML
  await expect(page.getByTestId("active-policy-yaml")).not.toContainText("test_python_mcp");
});

test("MCP policy: global default tool action change is shown in diff modal", async ({ page }) => {
  await login(page);
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  // Set global MCP default action
  await page.getByTestId("mcp-default-action").selectOption("deny");

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await expect(page.getByTestId("apply-confirm-modal")).toContainText("MCP default tool action");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("default_tool_action");

  // Reset: clear MCP default action back to inherit
  await page.getByTestId("mcp-default-action").selectOption("");
  await page.getByTestId("save-draft-button").click();
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
});

test("MCP events: socket-level authorize shows in event stream", async ({ page }) => {
  await login(page);

  // Load a policy that denies all MCP tools by default
  // The daemon is already running with a policy; use the UI to add an MCP deny-all default
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  await page.getByTestId("mcp-section-add").click();
  await expect(page.getByTestId("mcp-server-row-0")).toBeVisible();
  await page.getByTestId("mcp-server-id-0").fill("events_test_mcp");
  await page.getByTestId("mcp-server-exec-0").fill("/**");
  await page.getByTestId("mcp-server-default-action-0").selectOption("deny");

  await page.getByTestId("save-draft-button").click();
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  // Navigate to events tab and connect
  await page.getByTestId("tab-events").click();
  await expect(page.getByTestId("stream-status")).toContainText("connected");

  // Register an MCP server and fire a tool call via the control socket
  const regResp = await sendControlRequest(e2e.socketPath, {
    RegisterMcpServer: {
      pid: process.pid,
      ppid: process.ppid ?? 1,
      uid: 0,
      gid: 0,
      profile: "default",
      cmdline: ["node"],
      cwd: "/tmp",
      server_id: "events_test_mcp"
    }
  });
  expect(regResp.RegisterMcpServer).toBeDefined();
  const regPayload = regResp.RegisterMcpServer as Record<string, unknown>;
  const mcpSessionId = regPayload.mcp_session_id as string;

  const authResp = await sendControlRequest(e2e.socketPath, {
    AuthorizeMcpToolCall: {
      mcp_session_id: mcpSessionId,
      tool_name: "blocked_tool",
      tool_call_id: `tc-e2e-${Date.now()}`,
      arguments_json: "{}"
    }
  });
  const authPayload = authResp.AuthorizeMcpToolCall as Record<string, unknown> | undefined;
  expect(authPayload?.decision).toBe("deny");

  // Verify the deny event appears in the stream
  const eventRows = page.locator('[data-testid="events-table"] tbody tr');
  await expect(eventRows.filter({ hasText: "blocked_tool" })).toHaveCount(1, { timeout: 15_000 });
  await expect(eventRows.filter({ hasText: "blocked_tool" }).first()).toContainText("deny");

  // Cleanup: remove MCP server from policy
  await page.getByTestId("tab-policy").click();
  await page.getByTestId("mcp-server-remove-0").click();
  await page.getByTestId("save-draft-button").click();
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
});
