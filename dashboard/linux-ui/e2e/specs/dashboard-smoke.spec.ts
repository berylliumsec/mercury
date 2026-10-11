import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { runAiRun, spawnAiRun } from "../support/runtime";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

async function ensureLoggedIn(page: import("@playwright/test").Page, password = e2e.password) {
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

  const signupForm = page.getByTestId("signup-form");
  const loginForm = page.getByTestId("login-form");
  const usernameInput = page.getByTestId("auth-username-input");

  if (await signupForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    if (await usernameInput.isEditable().catch(() => false)) {
      await usernameInput.fill(e2e.username);
    }
    await page.getByTestId("auth-password-input").fill(password);
    await page.getByTestId("auth-password-confirm-input").fill(password);
    await page.getByTestId("signup-submit").click();
  } else if (await loginForm.isVisible({ timeout: 3_000 }).catch(() => false)) {
    await usernameInput.fill(e2e.username);
    await page.getByTestId("auth-password-input").fill(password);
    await page.getByTestId("login-submit").click();
  }

  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

test("bootstraps, applies policy changes, streams events, shows enrollments, and rolls back", async ({
  page
}) => {
  const httpBlocked = new URL(e2e.httpBlockedUrl);

  await ensureLoggedIn(page);

  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
  await expect(page.getByTestId("metric-url-gateway")).toContainText("Ready");

  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  await page.getByTestId("policy-mode-select").selectOption("deny");
  await expect(page.getByTestId("policy-mode-select")).toHaveValue("deny");
  await page.getByTestId("policy-mode-select").selectOption("allow");
  await expect(page.getByTestId("policy-mode-select")).toHaveValue("allow");

  await page.getByTestId("file-deny-section-add").click();
  await page.getByTestId("file-deny-id-0").fill("deny_ui_secret");
  await page.getByTestId("file-deny-pattern-0").fill(e2e.fileDenyPath);

  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill("smoke test apply");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await expect(page.getByTestId("active-policy-yaml")).toContainText(e2e.fileDenyPath);

  await page.getByTestId("url-deny-section-add").click();
  await page.getByTestId("url-deny-id-0").fill("deny_ui_http_blocked");
  await page.getByTestId("url-deny-scheme-0").fill(httpBlocked.protocol.replace(":", ""));
  await page.getByTestId("url-deny-host-0").fill(httpBlocked.hostname);
  await page.getByTestId("url-deny-port-0").fill(httpBlocked.port);
  await page.getByTestId("url-deny-port-0").blur();
  await page.getByTestId("url-deny-path-0").fill("/blocked/**");

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("deny_ui_http_blocked");

  const sleeper = spawnAiRun(e2e, ["/bin/sh", "-c", "sleep 15"], 25_000);
  try {
    await page.getByTestId("tab-enrollment").click();
    await page.getByTestId("refresh-button").click();
    await expect(page.getByTestId("enrollments-table")).toContainText("ai_run");
    await expect(page.getByTestId("enrollments-table")).toContainText("default");
    await page.getByTestId("enrollments-filter-input").fill("default");
    await expect(page.getByTestId("enrollments-filter-count")).toContainText("of");

    await page.getByTestId("tab-events").click();
    await expect(page.getByTestId("stream-status")).toContainText("connected");

    const deniedRead = await runAiRun(
      e2e,
      ["/bin/sh", "-c", `cat '${e2e.fileDenyPath}' >/dev/null`],
      20_000
    );
    expect(deniedRead.code).not.toBe(0);

    await expect(page.getByTestId("events-table")).toContainText(e2e.fileDenyPath);
    await expect(page.getByTestId("events-table")).toContainText("deny");
    await page.getByTestId("events-decision-filter").selectOption("deny");
    await page.getByTestId("events-resource-filter").fill(e2e.fileDenyPath);
    const eventRows = page.locator('[data-testid="events-table"] tbody tr');
    const deniedFileRows = eventRows.filter({ hasText: e2e.fileDenyPath });
    await expect(deniedFileRows.first()).toContainText(e2e.fileDenyPath);

    await page.getByTestId("events-resource-filter").fill(e2e.httpBlockedUrl);
    await expect(page.locator('[data-testid="events-table"] tbody td.empty')).toContainText(
      "No events match that filter."
    );

    const blockedHttp = await runAiRun(
      e2e,
      ["/usr/bin/curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", e2e.httpBlockedUrl],
      20_000
    );
    expect(`${blockedHttp.code}:${blockedHttp.stdout.trim()}`).not.toBe("0:200");

    const deniedUrlRows = eventRows.filter({ hasText: e2e.httpBlockedUrl });
    await expect(deniedUrlRows.first()).toContainText(e2e.httpBlockedUrl);
    await expect(deniedUrlRows.first()).toContainText("url:");

    const deniedReadWhileUrlFiltered = await runAiRun(
      e2e,
      ["/bin/sh", "-c", `cat '${e2e.fileDenyPath}' >/dev/null`],
      20_000
    );
    expect(deniedReadWhileUrlFiltered.code).not.toBe(0);

    await expect(deniedUrlRows.first()).toContainText(e2e.httpBlockedUrl);
    await expect(page.getByTestId("events-table")).not.toContainText(e2e.fileDenyPath);
  } finally {
    sleeper.child.kill("SIGTERM");
    await sleeper.wait().catch(() => undefined);
  }

  await page.getByTestId("tab-policy").click();
  const rollbackButtons = page.locator('[data-testid^="rollback-"]');
  await expect(rollbackButtons.nth(1)).toBeVisible();
  await rollbackButtons.nth(1).click();
  await expect(page.getByTestId("rollback-confirm-modal")).toBeVisible();
  await page.getByTestId("rollback-note-input").fill("smoke rollback");
  await page.getByTestId("rollback-confirm-button").click();

  await expect(page.getByTestId("policy-message")).toContainText("Rolled back");
  await expect(page.getByTestId("active-policy-yaml")).toContainText(e2e.fileDenyPath);
  await expect(page.getByTestId("active-policy-yaml")).not.toContainText("deny_ui_http_blocked");
  await expect(page.getByTestId("actions-export-button")).toBeEnabled();
});

test("adds exec deny rule via UI, applies policy, and blocks binary", async ({ page }) => {
  await ensureLoggedIn(page);

  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  // Collapse any existing sections to scroll to exec deny faster.
  await page.getByTestId("exec-deny-section-add").click();
  await page.getByTestId("exec-deny-id-0").fill("deny_curl_ui");
  await page.getByTestId("exec-deny-path-0").fill("/usr/bin/curl");

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill("exec deny smoke");
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("deny_curl_ui");

  await page.getByTestId("tab-events").click();
  await expect(page.getByTestId("stream-status")).toContainText("connected");

  // Running /usr/bin/curl under mercury-run should be blocked by exec_deny.
  const blockedExec = await runAiRun(e2e, ["/usr/bin/curl", "--version"], 20_000);
  expect(blockedExec.code).not.toBe(0);

  // The events table should show a deny event for the curl binary.
  await page.getByTestId("events-decision-filter").selectOption("deny");
  await page.getByTestId("events-resource-filter").fill("/usr/bin/curl");
  await expect(page.locator('[data-testid="events-table"] tbody tr')).toHaveCount(1);
  await expect(page.locator('[data-testid="events-table"] tbody tr').first()).toContainText(
    "/usr/bin/curl"
  );

  await page.getByTestId("tab-policy").click();
  await page.getByTestId("exec-deny-remove-0").click();
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await expect(page.getByTestId("active-policy-yaml")).not.toContainText("deny_curl_ui");
});

test("mercury-run with HTTPS blocked URL produces deny event in stream", async ({ page }) => {
  const httpsBlocked = new URL(e2e.httpsBlockedUrl);

  await ensureLoggedIn(page);

  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();

  // Add a URL deny rule for the HTTPS blocked URL.
  await page.getByTestId("url-deny-section-add").click();
  await page.getByTestId("url-deny-id-0").fill("deny_https_smoke");
  await page.getByTestId("url-deny-scheme-0").fill("https");
  await page.getByTestId("url-deny-host-0").fill(httpsBlocked.hostname);
  await page.getByTestId("url-deny-port-0").fill(httpsBlocked.port);
  await page.getByTestId("url-deny-port-0").blur();
  await page.getByTestId("url-deny-path-0").fill("/blocked/**");

  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");

  await page.getByTestId("tab-events").click();
  await expect(page.getByTestId("stream-status")).toContainText("connected");

  // Attempt HTTPS request to the blocked URL — expect non-200 response via proxy.
  const blockedHttps = await runAiRun(
    e2e,
    ["/usr/bin/curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", e2e.httpsBlockedUrl],
    20_000
  );
  expect(`${blockedHttps.code}:${blockedHttps.stdout.trim()}`).not.toBe("0:200");

  // Deny event for the HTTPS blocked URL must appear in the event stream.
  await page.getByTestId("events-decision-filter").selectOption("deny");
  await page.getByTestId("events-resource-filter").fill(e2e.httpsBlockedUrl);
  const eventRows = page.locator('[data-testid="events-table"] tbody tr');
  await expect(eventRows).toHaveCount(1);
  await expect(eventRows.first()).toContainText(e2e.httpsBlockedUrl);
  await expect(eventRows.first()).toContainText("url:");
});
