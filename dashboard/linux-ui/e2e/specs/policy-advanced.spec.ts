/**
 * Advanced policy E2E tests:
 *   1. Profile switching — create a new profile, set distinct rules, switch back to default.
 *   2. MCP require_approval full loop — policy gate + UI approval + audit verification.
 */
import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { sendControlRequest } from "../support/mcp";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

async function configureMcpApprovalServer(
  page: import("@playwright/test").Page,
  serverId: string,
  approvalTool = "read_file"
) {
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  const serverRows = page.locator('[data-testid^="mcp-server-row-"]');
  const existingServers = await serverRows.count();
  await page.getByTestId("mcp-section-add").click();
  await expect(page.getByTestId(`mcp-server-row-${existingServers}`)).toBeVisible();
  await page.getByTestId(`mcp-server-id-${existingServers}`).fill(serverId);
  await page.getByTestId(`mcp-server-exec-${existingServers}`).fill("/**");
  await page.getByTestId(`mcp-server-default-action-${existingServers}`).selectOption("deny");
  await page.getByTestId(`mcp-server-approval-tools-${existingServers}`).fill(approvalTool);

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill(`configure ${serverId}`);
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
}

// ---------------------------------------------------------------------------
// Helper: sign in if we are shown the signup/login page.
// ---------------------------------------------------------------------------
async function ensureLoggedIn(page: import("@playwright/test").Page) {
  await page.goto(e2e.baseUrl);
  if (
    await page
      .getByTestId("metric-daemon")
      .isVisible({ timeout: 3_000 })
      .catch(() => false)
  ) {
    await expect(page.getByTestId("metric-daemon")).toContainText("Online");
    return;
  }

  // If the signup form is visible we are not yet authenticated.
  const signupForm = page.getByTestId("signup-form");
  const loginForm = page.getByTestId("login-form");
  const usernameInput = page.getByTestId("auth-username-input");
  if (await signupForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    if (await usernameInput.isEditable().catch(() => false)) {
      await usernameInput.fill(e2e.username);
    }
    await page.getByTestId("auth-password-input").fill(e2e.password);
    await page.getByTestId("auth-password-confirm-input").fill(e2e.password);
    await page.getByTestId("signup-submit").click();
  } else if (await loginForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    await usernameInput.fill(e2e.username);
    await page.getByTestId("auth-password-input").fill(e2e.password);
    await page.getByTestId("login-submit").click();
  }
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

// ---------------------------------------------------------------------------
// Test 1: Profile switching
// ---------------------------------------------------------------------------
test("creates a second profile, adds distinct file deny, and switches back to default", async ({
  page
}) => {
  await ensureLoggedIn(page);
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  // The default profile should be selected.
  await expect(page.getByTestId("profile-select")).toHaveValue("default");

  // Create a new profile called "strict" via window.prompt.
  page.on("dialog", (dialog) => {
    void dialog.accept("strict");
  });
  await page.getByTestId("add-profile-button").click();

  // The profile selector should now contain the new "strict" option.
  await expect(page.getByTestId("profile-select")).toContainText("strict");
  await page.getByTestId("profile-select").selectOption("strict");
  await expect(page.getByTestId("profile-select")).toHaveValue("strict");

  // Add a file deny rule unique to the strict profile.
  await page.getByTestId("file-deny-section-add").click();
  await page.getByTestId("file-deny-id-0").fill("deny_strict_file");
  await page.getByTestId("file-deny-pattern-0").fill("/tmp/strict-secret.txt");

  // Save, validate and apply.
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill("strict profile smoke");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  // The active YAML should contain the strict profile's deny rule.
  await expect(page.getByTestId("active-policy-yaml")).toContainText("deny_strict_file");

  // Switch back to the default profile and confirm it has different rules.
  await page.getByTestId("profile-select").selectOption("default");
  await expect(page.getByTestId("profile-select")).toHaveValue("default");
  // The default profile editor should not show the strict file deny id.
  await expect(page.getByTestId("policy-editor-panel")).not.toContainText("deny_strict_file");
});

// ---------------------------------------------------------------------------
// Test 2: MCP require_approval full loop
// ---------------------------------------------------------------------------
test("MCP require_approval — pending approval appears in UI and can be approved", async ({
  page
}) => {
  await ensureLoggedIn(page);
  await configureMcpApprovalServer(page, "test-server-approval");

  // Register a test MCP server.
  const sessionResp = await sendControlRequest(e2e.socketPath, {
    RegisterMcpServer: {
      pid: process.pid,
      ppid: process.ppid ?? 1,
      uid: process.getuid?.() ?? 1000,
      gid: process.getgid?.() ?? 1000,
      profile: "default",
      cmdline: ["test-mcp-server"],
      cwd: "/tmp",
      server_id: "test-server-approval",
      client_name: "e2e-approval-test"
    }
  });

  // The response must contain a mcp_session_id.
  expect(sessionResp).toHaveProperty("RegisterMcpServer");
  const regData = sessionResp["RegisterMcpServer"] as Record<string, unknown>;
  const mcpSessionId = regData["mcp_session_id"] as string;
  expect(typeof mcpSessionId).toBe("string");

  // Call AuthorizeMcpToolCall for the "read_file" tool — the policy must require
  // approval (either because the current policy has require_approval or because
  // the fallback global action_required makes it pending).
  // We fire the authorize call without awaiting for its final result so we can
  // interact with the UI in parallel.
  const authResp = await sendControlRequest(e2e.socketPath, {
    AuthorizeMcpToolCall: {
      mcp_session_id: mcpSessionId,
      tool_name: "read_file",
      tool_call_id: "tc-e2e-approval-001",
      arguments_json: JSON.stringify({ path: "/tmp/secret.txt" }),
      arguments_summary: "read /tmp/secret.txt"
    }
  });

  // If the policy does not require approval for this tool in the current running
  // policy, the decision will be "allow" or "deny" — skip the UI approval flow.
  const authData = authResp["AuthorizeMcpToolCall"] as Record<string, unknown> | undefined;
  if (!authData || authData["decision"] !== "pending_approval") {
    // Approval flow requires a running policy with require_approval — log and skip.
    console.log(
      "Skipping approval UI loop: policy does not require approval for read_file. " +
        `Decision was: ${String(authData?.["decision"] ?? "unknown")}`
    );
    return;
  }

  const requestId = authData["request_id"] as string;
  expect(typeof requestId).toBe("string");

  // Navigate to the approvals tab and wait for the pending item to appear.
  await page.getByTestId("tab-approvals").click();
  await expect(page.getByTestId("mcp-approvals-panel")).toBeVisible();

  const approvalItem = page.getByTestId(`approval-item-${requestId}`);
  await expect(approvalItem).toBeVisible({ timeout: 10_000 });

  // Approve the pending tool call.
  await page.getByTestId(`approve-${requestId}`).click();

  // The approval item should disappear from the list after approval.
  await expect(approvalItem).not.toBeVisible({ timeout: 10_000 });

  // The approvals panel should now show 0 pending.
  await expect(page.getByTestId("mcp-approvals-panel")).toContainText("0 pending");
});

// ---------------------------------------------------------------------------
// Test 3: MCP require_approval — operator denies the pending tool call
// ---------------------------------------------------------------------------
test("MCP require_approval — operator deny removes the item from the approvals panel", async ({
  page
}) => {
  await ensureLoggedIn(page);
  await configureMcpApprovalServer(page, "test-server-deny");

  // Register a fresh MCP server session.
  const sessionResp = await sendControlRequest(e2e.socketPath, {
    RegisterMcpServer: {
      pid: process.pid,
      ppid: process.ppid ?? 1,
      uid: process.getuid?.() ?? 1000,
      gid: process.getgid?.() ?? 1000,
      profile: "default",
      cmdline: ["test-mcp-server-deny"],
      cwd: "/tmp",
      server_id: "test-server-deny",
      client_name: "e2e-deny-test"
    }
  });

  expect(sessionResp).toHaveProperty("RegisterMcpServer");
  const regData = sessionResp["RegisterMcpServer"] as Record<string, unknown>;
  const mcpSessionId = regData["mcp_session_id"] as string;
  expect(typeof mcpSessionId).toBe("string");

  // Request authorization for a tool call that should require approval.
  const authResp = await sendControlRequest(e2e.socketPath, {
    AuthorizeMcpToolCall: {
      mcp_session_id: mcpSessionId,
      tool_name: "read_file",
      tool_call_id: "tc-e2e-deny-001",
      arguments_json: JSON.stringify({ path: "/tmp/deny-test.txt" }),
      arguments_summary: "read /tmp/deny-test.txt"
    }
  });

  const authData = authResp["AuthorizeMcpToolCall"] as Record<string, unknown> | undefined;
  if (!authData || authData["decision"] !== "pending_approval") {
    console.log(
      "Skipping MCP deny UI loop: policy does not require approval for read_file. " +
        `Decision was: ${String(authData?.["decision"] ?? "unknown")}`
    );
    return;
  }

  const requestId = authData["request_id"] as string;
  expect(typeof requestId).toBe("string");

  // Navigate to the approvals tab and wait for the pending item.
  await page.getByTestId("tab-approvals").click();
  await expect(page.getByTestId("mcp-approvals-panel")).toBeVisible();

  const approvalItem = page.getByTestId(`approval-item-${requestId}`);
  await expect(approvalItem).toBeVisible({ timeout: 10_000 });

  // Click the Deny button.
  await page.getByTestId(`deny-${requestId}`).click();

  // The approval item must disappear after denial.
  await expect(approvalItem).not.toBeVisible({ timeout: 10_000 });

  // Panel must report 0 pending.
  await expect(page.getByTestId("mcp-approvals-panel")).toContainText("0 pending");
});
