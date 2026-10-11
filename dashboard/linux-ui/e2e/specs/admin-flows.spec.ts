/**
 * Admin workflow E2E tests (serial):
 *   1. Logout — verifies the session is destroyed and the login wall reappears.
 *   2. Password change — changes the password and changes it back.
 *   3. Actions export — verifies the CSV download is triggered.
 *   4. Quick-rule from events table — clicks quick-allow on a deny event and
 *      confirms the policy is updated automatically.
 */
import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { runAiRun } from "../support/runtime";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

// ---------------------------------------------------------------------------
// Helper: ensure authenticated (handles both signup-on-first-boot and login).
// ---------------------------------------------------------------------------
async function ensureLoggedIn(
  page: import("@playwright/test").Page,
  username = e2e.username,
  password = e2e.password
) {
  await page.goto(e2e.baseUrl);
  const signupForm = page.getByTestId("signup-form");
  const loginForm = page.getByTestId("login-form");
  const usernameInput = page.getByTestId("auth-username-input");

  if (await signupForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    if (await usernameInput.isEditable().catch(() => false)) {
      await usernameInput.fill(username);
    }
    await page.getByTestId("auth-password-input").fill(password);
    await page.getByTestId("auth-password-confirm-input").fill(password);
    await page.getByTestId("signup-submit").click();
  } else if (await loginForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    await usernameInput.fill(username);
    await page.getByTestId("auth-password-input").fill(password);
    await page.getByTestId("login-submit").click();
  }
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

async function logout(page: import("@playwright/test").Page) {
  await page.getByTestId("logout-button").click();
  await expect(page.getByTestId("login-form").or(page.getByTestId("signup-form"))).toBeVisible({
    timeout: 8_000
  });
}

// ---------------------------------------------------------------------------
// Test 1: Logout
// ---------------------------------------------------------------------------
test("logout destroys session and shows login page", async ({ page }) => {
  await ensureLoggedIn(page);

  await logout(page);

  // Log back in so subsequent serial tests start authenticated.
  await ensureLoggedIn(page);
});

// ---------------------------------------------------------------------------
// Test 2: Password change
// ---------------------------------------------------------------------------
test("changes password and changes it back", async ({ page }) => {
  await ensureLoggedIn(page);

  const newPassword = `${e2e.password}_changed`;

  // Open the password panel.
  await page.getByTestId("toggle-password-panel-button").click();
  await expect(page.getByTestId("password-panel")).toBeVisible();

  // Fill and submit the change form.
  await page.getByTestId("current-password-input").fill(e2e.password);
  await page.getByTestId("new-password-input").fill(newPassword);
  await page.getByTestId("new-password-confirm-input").fill(newPassword);
  await page.getByTestId("password-update-submit").click();

  await expect(page.getByTestId("password-panel")).not.toBeVisible();
  await logout(page);
  await ensureLoggedIn(page, e2e.username, newPassword);

  // Change the password back so subsequent test runs are not broken.
  await page.getByTestId("toggle-password-panel-button").click();
  await expect(page.getByTestId("password-panel")).toBeVisible();
  await page.getByTestId("current-password-input").fill(newPassword);
  await page.getByTestId("new-password-input").fill(e2e.password);
  await page.getByTestId("new-password-confirm-input").fill(e2e.password);
  await page.getByTestId("password-update-submit").click();

  await expect(page.getByTestId("password-panel")).not.toBeVisible();
  await logout(page);
  await ensureLoggedIn(page);
});

// ---------------------------------------------------------------------------
// Test 3: Actions export — clicking the button triggers a CSV download
// ---------------------------------------------------------------------------
test("actions export triggers a CSV file download", async ({ page }) => {
  await ensureLoggedIn(page);

  // Navigate to the policy tab to ensure at least one policy action exists in
  // the log (the previous tests will have applied policies).
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-actions-panel")).toBeVisible();

  // Wait until the export button is enabled (requires ≥1 action in the log).
  await expect(page.getByTestId("actions-export-button")).toBeEnabled({ timeout: 10_000 });

  // Intercept the download triggered by the in-memory Blob + anchor-click mechanism.
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 10_000 }),
    page.getByTestId("actions-export-button").click()
  ]);

  expect(download.suggestedFilename()).toMatch(/dashboard-actions-.*\.csv/);
});

// ---------------------------------------------------------------------------
// Test 4: Quick-rule from events table
// ---------------------------------------------------------------------------
test("quick-allow button on a deny event adds an allow rule to the policy", async ({ page }) => {
  await ensureLoggedIn(page);

  const denyRuleId = `deny_quick_allow_${Date.now().toString().slice(-6)}`;

  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  const existingFileDenyRules = await page.locator('[data-testid^="file-deny-id-"]').count();
  await page.getByTestId("file-deny-section-add").click();
  await page.getByTestId(`file-deny-id-${existingFileDenyRules}`).fill(denyRuleId);
  await page.getByTestId(`file-deny-pattern-${existingFileDenyRules}`).fill(e2e.fileDenyPath);

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill("quick allow smoke");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  // Go to the events tab, make sure the stream is up.
  await page.getByTestId("tab-events").click();
  await expect(page.getByTestId("stream-status")).toContainText("connected");

  // Set the filter to "deny" so only deny events are shown.
  await page.getByTestId("events-decision-filter").selectOption("deny");

  // Trigger a deny event by running a blocked binary.
  await runAiRun(e2e, ["/bin/sh", "-c", `cat '${e2e.fileDenyPath}' >/dev/null`], 15_000);

  await page.getByTestId("events-resource-filter").fill(e2e.fileDenyPath);

  const eventRows = page.locator('[data-testid="events-table"] tbody tr:not(.empty-row)');
  await expect(eventRows).toHaveCount(1, { timeout: 15_000 });

  const quickAllowBtn = eventRows.first().locator('[data-testid^="quick-allow-"]');
  await expect(quickAllowBtn).toBeVisible({ timeout: 10_000 });

  // Click quick-allow — this opens the quick-rule modal.
  await quickAllowBtn.click();
  await expect(page.getByTestId("quick-rule-modal")).toBeVisible();

  // Confirm the quick rule creation.
  await page.getByTestId("quick-rule-confirm").click();

  // A success toast must appear.
  await expect(page.getByTestId("quick-rule-toast")).toBeVisible({ timeout: 10_000 });

  // Navigate to the policy tab and verify the active policy YAML was updated.
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("active-policy-yaml")).toContainText(e2e.fileDenyPath, {
    timeout: 10_000
  });
});
