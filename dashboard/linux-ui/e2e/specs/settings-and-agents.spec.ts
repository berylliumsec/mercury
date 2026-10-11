/**
 * Settings & Agents E2E tests (serial):
 *   1. TLS settings panel — renders correctly; if TLS env vars are provided,
 *      also exercises the Save & Reload form.
 *   2. Agent launch and stop — launches a python worker via the Agents panel,
 *      verifies non-root execution and mercury-run env injection, then stops it.
 */
import fs from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

// ---------------------------------------------------------------------------
// Helper: ensure authenticated.
// ---------------------------------------------------------------------------
async function ensureLoggedIn(page: import("@playwright/test").Page) {
  await page.goto(e2e.baseUrl);
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
    if (await usernameInput.isEditable().catch(() => false)) {
      await usernameInput.fill(e2e.username);
    }
    await page.getByTestId("auth-password-input").fill(e2e.password);
    await page.getByTestId("login-submit").click();
  }
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

// ---------------------------------------------------------------------------
// Test 1: TLS Settings panel
// ---------------------------------------------------------------------------
test("settings panel renders and TLS form saves when cert/key env vars are set", async ({
  page
}) => {
  await ensureLoggedIn(page);

  await page.getByTestId("tab-settings").click();
  await expect(page.getByTestId("settings-panel")).toBeVisible();

  // The TLS form inputs must always be present.
  await expect(page.getByTestId("tls-cert-file-input")).toBeVisible();
  await expect(page.getByTestId("tls-key-file-input")).toBeVisible();
  await expect(page.getByTestId("tls-submit-button")).toBeVisible();

  // If TLS cert/key env vars are provided, exercise the Save & Reload form.
  if (e2e.tlsCertFile && e2e.tlsKeyFile) {
    await page.getByTestId("tls-cert-file-input").fill(e2e.tlsCertFile);
    await page.getByTestId("tls-key-file-input").fill(e2e.tlsKeyFile);
    await page.getByTestId("tls-submit-button").click();

    // A status message must appear (success or error — either proves the route
    // and UI feedback plumbing work end to end).
    await expect(page.getByTestId("tls-status-message")).toBeVisible({ timeout: 10_000 });
  }
});

// ---------------------------------------------------------------------------
// Test 2: Agent launch and stop
// ---------------------------------------------------------------------------
test("launches an agent via the Agents panel and stops it", async ({ page }) => {
  await ensureLoggedIn(page);

  await page.getByTestId("tab-agents").click();

  // The profile selector and launch inputs must be visible.
  await expect(page.getByTestId("agent-profile-select")).toBeVisible();
  await expect(page.getByTestId("agent-command-input")).toBeVisible();
  await expect(page.getByTestId("agent-args-input")).toBeVisible();

  const pythonCode = [
    "import json, os, pathlib, time",
    `pathlib.Path(${JSON.stringify(e2e.launchMarker)}).write_text(json.dumps({'uid': os.getuid(), 'user': os.environ.get('USER'), 'agent_id': os.environ.get('MERCURY_AGENT_ID'), 'profile': os.environ.get('MERCURY_PROFILE'), 'cgroup_id': os.environ.get('MERCURY_CGROUP_ID'), 'http_proxy': os.environ.get('HTTP_PROXY')}))`,
    "time.sleep(60)"
  ].join("; ");

  await page.getByTestId("agent-profile-select").selectOption("url-agent");
  await page.getByTestId("agent-command-input").fill("/usr/bin/python3");
  await page.getByTestId("agent-args-input").fill(`-c ${JSON.stringify(pythonCode)}`);
  await page.getByTestId("agent-cwd-input").fill("/tmp");

  await page.getByTestId("agent-launch-button").click();

  // A Stop button for the newly launched agent must appear.
  const stopBtn = page.locator('[data-testid^="agent-stop-"]').first();
  await expect(stopBtn).toBeVisible({ timeout: 10_000 });

  // Extract the agent_id from the testid so we can assert it disappears.
  const stopId = await stopBtn.getAttribute("data-testid");
  const agentId = stopId?.replace("agent-stop-", "") ?? "";
  expect(agentId).not.toBe("");

  await expect
    .poll(async () => {
      try {
        return await fs.readFile(e2e.launchMarker, "utf8");
      } catch {
        return "";
      }
    })
    .not.toBe("");

  const marker = JSON.parse(await fs.readFile(e2e.launchMarker, "utf8"));
  expect(String(marker.uid)).toBe(e2e.launchUid);
  expect(marker.user).toBe(e2e.launchUser);
  expect(marker.agent_id).toBeTruthy();
  expect(marker.profile).toBe("url-agent");
  expect(marker.cgroup_id).toBeTruthy();
  expect(marker.http_proxy).toBeTruthy();

  // Stop the agent.
  await stopBtn.click();

  // The Stop button (and its row) must disappear once the process is killed.
  await expect(page.getByTestId(`agent-stop-${agentId}`)).not.toBeVisible({
    timeout: 10_000
  });

  const historyPanel = page.getByTestId("agents-history-panel");
  await expect(historyPanel).toContainText(e2e.launchUser, { timeout: 10_000 });
  await expect(historyPanel).toContainText("url-agent", { timeout: 10_000 });
});
