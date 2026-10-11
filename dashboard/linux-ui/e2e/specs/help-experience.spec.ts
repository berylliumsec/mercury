import { expect, type Page, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";

const e2e = loadE2eEnv();

test.describe.configure({ mode: "serial" });

async function ensureLoggedIn(page: Page) {
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

test("header help button opens the Help Hub and guided tour can return there", async ({ page }) => {
  await ensureLoggedIn(page);

  await page.getByTestId("open-help-button").click();
  await expect(page.getByTestId("help-screen-panel")).toBeVisible();
  await expect(page.getByTestId("help-tour-outline")).toBeVisible();

  await page.getByTestId("help-start-tour-button").click();

  const guidedTourPanel = page.getByTestId("guided-tour-panel");
  await expect(guidedTourPanel).toBeVisible();
  await expect(guidedTourPanel).toContainText(/1\s*\/\s*\d+/);

  await guidedTourPanel.getByRole("button", { name: "Next" }).click();
  await expect(guidedTourPanel).toContainText(/2\s*\/\s*\d+/);

  await guidedTourPanel.getByRole("button", { name: "Open Help Hub" }).click();
  await expect(guidedTourPanel).not.toBeVisible();
  await expect(page.getByTestId("help-screen-panel")).toBeVisible();
});

test("help bar opens contextual help and can start a section tour", async ({ page }) => {
  await ensureLoggedIn(page);

  await page.getByTestId("tab-settings").click();
  await expect(page.getByTestId("settings-panel")).toBeVisible();

  await page.getByTestId("help-bar-toggle").click();
  const helpBarPanel = page.getByTestId("help-bar-panel");
  await expect(helpBarPanel).toBeVisible();
  await expect(helpBarPanel).toContainText("Settings");

  await helpBarPanel.getByRole("button", { name: "Tour This Tab" }).click();

  const guidedTourPanel = page.getByTestId("guided-tour-panel");
  await expect(guidedTourPanel).toBeVisible();
  await expect(guidedTourPanel).toContainText("Showing Settings");

  await guidedTourPanel.getByRole("button", { name: "Next" }).click();
  await expect(guidedTourPanel).toContainText(/\d+\s*\/\s*\d+/);

  await guidedTourPanel.getByRole("button", { name: "Open Help Hub" }).click();
  await expect(page.getByTestId("help-screen-panel")).toBeVisible();
  await expect(page.getByTestId("help-screen-panel")).toContainText("Settings");

  await page.getByTestId("help-start-current-tour-button").click();
  await expect(guidedTourPanel).toBeVisible();
  await expect(guidedTourPanel).toContainText("Showing Settings");
});
