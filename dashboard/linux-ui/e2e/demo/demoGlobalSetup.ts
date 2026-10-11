import { mkdir } from "node:fs/promises";

import { chromium, expect, type FullConfig } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { demoAuthStatePath, ensureDemoArtifactDirs } from "./demoArtifacts";

export default async function demoGlobalSetup(_config: FullConfig) {
  const env = loadE2eEnv();
  await ensureDemoArtifactDirs(env);
  await mkdir(env.demoArtifactDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  try {
    await page.goto(env.baseUrl);
    if (
      await page
        .getByTestId("signup-submit")
        .isVisible()
        .catch(() => false)
    ) {
      await page.getByTestId("auth-password-input").fill(env.password);
      await page.getByTestId("auth-password-confirm-input").fill(env.password);
      await page.getByTestId("signup-submit").click();
    } else {
      await page.getByTestId("auth-username-input").fill(env.username);
      await page.getByTestId("auth-password-input").fill(env.password);
      await page.getByTestId("login-submit").click();
    }

    await expect(page.getByTestId("metric-daemon")).toContainText("Online");
    await page.context().storageState({ path: demoAuthStatePath(env) });
  } finally {
    await page.close().catch(() => undefined);
    await browser.close();
  }
}
