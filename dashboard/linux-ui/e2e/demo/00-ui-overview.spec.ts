import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { finalizeScenarioRecording } from "./demoArtifacts";
import {
  applyRepresentativeRules,
  DEFAULT_OVERVIEW_FRAMES,
  DEMO_FPS,
  ensureAuthenticated,
  openEvents,
  openOverview,
  pause
} from "./demoSupport";

const e2e = loadE2eEnv();

test.use({ storageState: undefined });

test("records the policy studio overview clip", async ({ page }, testInfo) => {
  await ensureAuthenticated(page, e2e);
  await pause(page, 1_600);
  await openEvents(page);
  await pause(page, 1_200);
  await openOverview(page);
  await pause(page, 1_000);
  await applyRepresentativeRules(page, e2e);
  await expect(page.getByTestId("active-policy-yaml")).toContainText("demo_exec_curl");
  await pause(page, 2_200);

  await finalizeScenarioRecording({
    env: e2e,
    page,
    testInfo,
    entry: {
      id: "ui-overview",
      order: 1,
      title: "Policy Studio Overview",
      summary: "Log in, author representative deny rules, validate the draft, and apply it.",
      resultLabel: "Draft validated and applied",
      eventEvidence: "Active policy YAML shows file, port, URL, and exec deny rules.",
      evidenceFilter: "demo_exec_curl",
      trimBeforeFrames: 8,
      introDurationInFrames: Math.round(DEMO_FPS * 2.5),
      videoDurationInFrames: DEFAULT_OVERVIEW_FRAMES,
      posterFrame: Math.floor(DEFAULT_OVERVIEW_FRAMES / 2),
      includeInOverview: true,
      readmeEmbed: false
    },
    transcript: {
      kind: "note",
      displayCommand: "Policy Studio walkthrough",
      command: [],
      exitCode: 0,
      stdout: [
        "Added representative deny rules:",
        `- file_deny: ${e2e.blockedDir}/**`,
        `- network_deny: 127.0.0.1/32:${e2e.blockedTcpPort}`,
        `- url_deny: ${e2e.httpBlockedUrl}`,
        "- exec_deny: /usr/bin/curl"
      ].join("\n"),
      stderr: "",
      expected: "The dashboard should validate and apply the edited policy.",
      observed: "Policy applied and visible in the active YAML preview."
    }
  });
});
