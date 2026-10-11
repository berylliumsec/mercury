import { expect, type Page, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { runAiRun } from "../support/runtime";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

async function ensureLoggedIn(page: Page) {
  await page.goto(e2e.baseUrl);
  const usernameInput = page.getByTestId("auth-username-input");
  const passwordInput = page.getByTestId("auth-password-input");
  const signupSubmit = page.getByTestId("signup-submit");
  const loginSubmit = page.getByTestId("login-submit");

  if (
    await page
      .getByTestId("metric-daemon")
      .isVisible({ timeout: 3_000 })
      .catch(() => false)
  ) {
    await expect(page.getByTestId("metric-daemon")).toContainText("Online");
    return;
  }

  if (await signupSubmit.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await passwordInput.fill(e2e.password);
    await page.getByTestId("auth-password-confirm-input").fill(e2e.password);
    await signupSubmit.click();
  } else if (await loginSubmit.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await expect(usernameInput).toBeEnabled();
    await usernameInput.fill(e2e.username);
    await passwordInput.fill(e2e.password);
    await loginSubmit.click();
  }

  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
}

async function openPolicyTab(page: Page) {
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();
}

async function saveValidateApply(page: Page, note: string) {
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill(note);
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
}

async function ensureVersionHistoryExpanded(page: Page) {
  const toggle = page.getByTestId("versions-collapse-button");
  await toggle.scrollIntoViewIfNeeded();
  if ((await toggle.getAttribute("aria-expanded")) !== "true") {
    await toggle.click();
  }
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
}

async function policyVersionCount(page: Page) {
  await ensureVersionHistoryExpanded(page);
  return await page.locator('[data-testid^="policy-version-"]').count();
}

async function addExecDenyRule(page: Page, ruleId: string, path: string) {
  const existing = await page.locator('[data-testid^="exec-deny-id-"]').count();
  await page.getByTestId("exec-deny-section-add").click();
  await page.getByTestId(`exec-deny-id-${existing}`).fill(ruleId);
  await page.getByTestId(`exec-deny-path-${existing}`).fill(path);
  return existing;
}

test("policy apply succeeds when exec deny rules shrink and versions remain rollbackable", async ({
  page
}) => {
  const suffix = Date.now().toString().slice(-6);
  const firstRuleId = `deny_exec_shrink_curl_${suffix}`;
  const secondRuleId = `deny_exec_shrink_wget_${suffix}`;

  await ensureLoggedIn(page);
  await openPolicyTab(page);

  const initialVersionCount = await policyVersionCount(page);
  const firstIndex = await addExecDenyRule(page, firstRuleId, "/usr/bin/curl");
  const secondIndex = await addExecDenyRule(page, secondRuleId, "/usr/bin/wget");
  expect(secondIndex).toBe(firstIndex + 1);

  await saveValidateApply(page, "regression: add shrinking exec deny set");
  await expect(page.getByTestId("active-policy-yaml")).toContainText(firstRuleId);
  await expect(page.getByTestId("active-policy-yaml")).toContainText(secondRuleId);

  const afterFirstApplyCount = await policyVersionCount(page);
  expect(afterFirstApplyCount).toBeGreaterThan(initialVersionCount);

  await page.getByTestId(`exec-deny-remove-${secondIndex}`).click();
  await saveValidateApply(page, "regression: remove stale exec deny key");
  await expect(page.getByTestId("active-policy-yaml")).toContainText(firstRuleId);
  await expect(page.getByTestId("active-policy-yaml")).not.toContainText(secondRuleId);

  const afterSecondApplyCount = await policyVersionCount(page);
  expect(afterSecondApplyCount).toBeGreaterThan(afterFirstApplyCount);
  await expect(page.locator('[data-testid^="rollback-"]').first()).toBeVisible();
});

test("mercury-run launches system and virtualenv python under allow-default policy", async ({
  page
}) => {
  await ensureLoggedIn(page);
  await openPolicyTab(page);

  const policyMode = page.getByTestId("policy-mode-select");
  await expect(policyMode).toHaveValue(/allow|deny/);
  if ((await policyMode.inputValue()) !== "allow") {
    await policyMode.selectOption("allow");
    await saveValidateApply(page, "regression: force allow default for python launcher");
  }

  const systemPython = await runAiRun(
    e2e,
    [e2e.systemPython, "-c", 'print("system-python-playwright")'],
    20_000
  );
  expect(systemPython.code).toBe(0);
  expect(systemPython.stdout).toContain("system-python-playwright");

  const venvPython = await runAiRun(
    e2e,
    [e2e.venvPython, "-c", 'print("venv-python-playwright")'],
    20_000
  );
  expect(venvPython.code).toBe(0);
  expect(venvPython.stdout).toContain("venv-python-playwright");
});
