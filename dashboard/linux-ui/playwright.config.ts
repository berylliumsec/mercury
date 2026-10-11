import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.MERCURY_E2E_BASE_URL ?? "http://127.0.0.1:7480";
const htmlReportDir = process.env.PLAYWRIGHT_HTML_REPORT ?? "playwright-report";
const outputDir = process.env.MERCURY_E2E_OUTPUT_DIR ?? "test-results";

export default defineConfig({
  testDir: "./e2e/specs",
  outputDir,
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
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    testIdAttribute: "data-testid"
  }
});
