import path from "node:path";

import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.MERCURY_E2E_BASE_URL ?? "http://127.0.0.1:7480";
const artifactDir =
  process.env.MERCURY_E2E_DEMO_ARTIFACT_DIR ?? path.resolve(process.cwd(), "demo-artifacts");
const outputDir = process.env.MERCURY_E2E_OUTPUT_DIR ?? path.join(artifactDir, "playwright-output");
const htmlReportDir =
  process.env.PLAYWRIGHT_HTML_REPORT ?? path.join(artifactDir, "playwright-report");

export default defineConfig({
  testDir: "./e2e/demo",
  outputDir,
  globalSetup: "./e2e/demo/demoGlobalSetup.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    [process.env.CI ? "line" : "list"],
    ["html", { open: "never", outputFolder: htmlReportDir }]
  ],
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    viewport: { width: 1280, height: 720 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: {
      mode: "on",
      size: { width: 1280, height: 720 }
    },
    testIdAttribute: "data-testid"
  }
});
