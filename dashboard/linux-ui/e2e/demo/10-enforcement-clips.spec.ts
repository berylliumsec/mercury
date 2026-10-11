import { expect, test } from "@playwright/test";

import { loadE2eEnv } from "../support/env";
import { runAiRun, runMercuryPolicyTest, runMercuryStatus } from "../support/runtime";
import { demoAuthStatePath, finalizeScenarioRecording } from "./demoArtifacts";
import {
  buildExecDenyPolicy,
  buildFolderDenyPolicy,
  buildNetworkPortDenyPolicy,
  buildUrlDenyPolicy,
  DEFAULT_SCENARIO_FRAMES,
  DEMO_FPS,
  expectStatusReady,
  filterDenyEvent,
  formatCommand,
  openEvents,
  openPolicyStudio,
  pause,
  reloadScenarioPolicy
} from "./demoSupport";

const e2e = loadE2eEnv();

test.use({ storageState: demoAuthStatePath(e2e) });
test.describe.configure({ mode: "serial" });

test("records the blocked website clip", async ({ page }, testInfo) => {
  await reloadScenarioPolicy(e2e, "url-deny-website", buildUrlDenyPolicy(e2e));

  await page.goto(e2e.baseUrl);
  await expectStatusReady(page);
  await pause(page, 1_600);
  await openEvents(page);
  await pause(page, 1_300);

  const policyTestArgs = [
    "--action",
    "net-connect",
    "--url",
    e2e.httpBlockedUrl,
    "--method",
    "GET"
  ];
  const policyCheck = await runMercuryPolicyTest(e2e, policyTestArgs, 20_000);
  expect(policyCheck.code).toBe(0);
  expect(policyCheck.stdout).toContain("decision=Deny");
  expect(policyCheck.stdout).toContain('rule_id=Some("deny_http_local")');

  const command = [
    "/usr/bin/curl",
    "-sS",
    "-o",
    "/dev/null",
    "-w",
    "%{http_code}",
    e2e.httpBlockedUrl
  ];
  const result = await runAiRun(e2e, command, 20_000);
  expect(`${result.code}:${result.stdout.trim()}`).not.toBe("0:200");

  await filterDenyEvent(page, "net:", ["net:", "DENY_BY_RULE"]);
  await pause(page, 1_400);

  await finalizeScenarioRecording({
    env: e2e,
    page,
    testInfo,
    entry: {
      id: "url-deny-website",
      order: 2,
      title: "Blocked Website Request",
      summary:
        "A URL deny rule rejects the blocked target, and the live request fails under mercury-run.",
      resultLabel: "URL rule denies and request fails",
      eventEvidence: "Events show the deny emitted during the blocked request attempt.",
      evidenceFilter: "net:",
      trimBeforeFrames: 8,
      introDurationInFrames: Math.round(DEMO_FPS * 2.5),
      videoDurationInFrames: DEFAULT_SCENARIO_FRAMES,
      posterFrame: Math.floor(DEFAULT_SCENARIO_FRAMES / 2),
      includeInOverview: true,
      readmeEmbed: true
    },
    transcript: {
      kind: "command",
      displayCommand: `mercury-policy test --socket ${e2e.socketPath} --profile default ${policyTestArgs.join(" ")}`,
      command: [
        "mercury-policy",
        "test",
        "--socket",
        e2e.socketPath,
        "--profile",
        "default",
        ...policyTestArgs
      ],
      exitCode: result.code,
      stdout: `${policyCheck.stdout.trim()}\ncurl_exit=${result.code ?? -1}\ncurl_http=${result.stdout.trim() || "000"}`,
      stderr: result.stderr.trim(),
      expected:
        "The policy test should deny the blocked URL, and the live request should not succeed.",
      observed: `mercury-policy test denied the URL, and curl exited ${result.code ?? -1} with HTTP ${result.stdout.trim() || "000"}.`
    }
  });
});

test("records the blocked port clip", async ({ page }, testInfo) => {
  await reloadScenarioPolicy(e2e, "network-port-deny", buildNetworkPortDenyPolicy(e2e));

  await page.goto(e2e.baseUrl);
  await expectStatusReady(page);
  await pause(page, 1_600);
  await openEvents(page);
  await pause(page, 1_300);

  const policyTestArgs = [
    "--action",
    "net-connect",
    "--dest-ip",
    "127.0.0.1",
    "--dest-port",
    e2e.blockedTcpPort,
    "--protocol",
    "tcp"
  ];
  const policyCheck = await runMercuryPolicyTest(e2e, policyTestArgs, 20_000);
  expect(policyCheck.code).toBe(0);
  expect(policyCheck.stdout).toContain("decision=Deny");
  expect(policyCheck.stdout).toContain('rule_id=Some("deny_demo_port")');

  const command = [
    e2e.systemPython,
    "-c",
    [
      "import socket, sys",
      "sock = None",
      "try:",
      "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
      "    sock.settimeout(2)",
      "    port = int(sys.argv[1])",
      "    sock.connect(('127.0.0.1', port))",
      "    print('connected')",
      "    sys.exit(0)",
      "except PermissionError:",
      "    print('denied')",
      "    sys.exit(1)",
      "finally:",
      "    if sock is not None:",
      "        sock.close()"
    ].join("\n"),
    e2e.blockedTcpPort
  ];
  const result = await runAiRun(e2e, command, 20_000);
  expect(result.code).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain("denied");

  await filterDenyEvent(page, "net:", ["net:", "DENY_BY_RULE"]);
  await pause(page, 1_400);

  await finalizeScenarioRecording({
    env: e2e,
    page,
    testInfo,
    entry: {
      id: "network-port-deny",
      order: 3,
      title: "Blocked TCP Port",
      summary: "A network deny rule rejects the demo TCP port, and the live connect probe fails.",
      resultLabel: "Port connect denied",
      eventEvidence: "Events show the deny emitted during the blocked port probe.",
      evidenceFilter: "net:",
      trimBeforeFrames: 8,
      introDurationInFrames: Math.round(DEMO_FPS * 2.5),
      videoDurationInFrames: DEFAULT_SCENARIO_FRAMES,
      posterFrame: Math.floor(DEFAULT_SCENARIO_FRAMES / 2),
      includeInOverview: true,
      readmeEmbed: true
    },
    transcript: {
      kind: "command",
      displayCommand: `mercury-policy test --socket ${e2e.socketPath} --profile default ${policyTestArgs.join(" ")}`,
      command: [
        "mercury-policy",
        "test",
        "--socket",
        e2e.socketPath,
        "--profile",
        "default",
        ...policyTestArgs
      ],
      exitCode: result.code,
      stdout: `${policyCheck.stdout.trim()}\nprobe_stdout=${result.stdout.trim() || "(empty)"}`,
      stderr: result.stderr.trim(),
      expected: "The policy test should deny the blocked port, and the live TCP probe should fail.",
      observed: `mercury-policy test denied the port, and the live probe exited ${result.code ?? -1}.`
    }
  });
});

test("records the blocked folder clip", async ({ page }, testInfo) => {
  await reloadScenarioPolicy(e2e, "folder-deny", buildFolderDenyPolicy(e2e));

  await page.goto(e2e.baseUrl);
  await expectStatusReady(page);
  await pause(page, 1_600);
  await openPolicyStudio(page);
  await expect(page.getByTestId("active-policy-yaml")).toContainText("deny_demo_folder");
  await pause(page, 1_300);

  const policyTestArgs = ["--action", "file-read", "--path", e2e.blockedFile];
  const policyCheck = await runMercuryPolicyTest(e2e, policyTestArgs, 20_000);
  expect(policyCheck.code).toBe(0);
  expect(policyCheck.stdout).toContain("decision=Deny");
  expect(policyCheck.stdout).toContain('rule_id=Some("deny_demo_folder")');

  const command = ["/bin/cat", e2e.blockedFile];
  const result = await runAiRun(e2e, command, 20_000);
  expect(result.code).not.toBe(0);
  await pause(page, 1_600);

  await finalizeScenarioRecording({
    env: e2e,
    page,
    testInfo,
    entry: {
      id: "folder-deny",
      order: 4,
      title: "Blocked Folder Read",
      summary: "A file deny rule blocks reading a file inside the protected demo directory tree.",
      resultLabel: "Read denied",
      eventEvidence:
        "The active policy YAML includes the denied folder rule, and the live read fails.",
      evidenceFilter: "deny_demo_folder",
      trimBeforeFrames: 8,
      introDurationInFrames: Math.round(DEMO_FPS * 2.5),
      videoDurationInFrames: DEFAULT_SCENARIO_FRAMES,
      posterFrame: Math.floor(DEFAULT_SCENARIO_FRAMES / 2),
      includeInOverview: true,
      readmeEmbed: true
    },
    transcript: {
      kind: "command",
      displayCommand: `mercury-policy test --socket ${e2e.socketPath} --profile default ${policyTestArgs.join(" ")}`,
      command: [
        "mercury-policy",
        "test",
        "--socket",
        e2e.socketPath,
        "--profile",
        "default",
        ...policyTestArgs
      ],
      exitCode: result.code,
      stdout: `${policyCheck.stdout.trim()}\ncat_stdout=${result.stdout.trim() || "(empty)"}`,
      stderr: result.stderr.trim(),
      expected: "The policy test should deny the protected file, and the live read should fail.",
      observed: `mercury-policy test denied the file, and cat exited ${result.code ?? -1}.`
    }
  });
});

test("records the exec deny clip", async ({ page }, testInfo) => {
  await reloadScenarioPolicy(e2e, "exec-deny", buildExecDenyPolicy());

  await page.goto(e2e.baseUrl);
  await expectStatusReady(page);
  await pause(page, 1_600);
  await openPolicyStudio(page);
  await expect(page.getByTestId("active-policy-yaml")).toContainText("deny_demo_exec");
  await pause(page, 1_300);

  const status = await runMercuryStatus(e2e, 20_000);
  expect(status.code).toBe(0);

  const policyTestArgs = ["--action", "proc-exec", "--path", "/usr/bin/curl"];
  const policyCheck = await runMercuryPolicyTest(e2e, policyTestArgs, 20_000);
  expect(policyCheck.code).toBe(0);
  expect(policyCheck.stdout).toContain("decision=Deny");
  expect(policyCheck.stdout).toContain('rule_id=Some("deny_demo_exec")');

  let resultLabel = "Exec rule denied";
  let eventEvidence = "The active policy YAML includes the exec deny rule for /usr/bin/curl.";
  let transcriptStdout = policyCheck.stdout.trim();
  let transcriptStderr = "";
  let transcriptExitCode: number | null = policyCheck.code;
  let observed = "mercury-policy test denied /usr/bin/curl.";

  if (status.stdout.includes("exec_hook=EbpfLsm")) {
    await openEvents(page);
    await pause(page, 900);

    const command = ["/usr/bin/curl", "--version"];
    const result = await runAiRun(e2e, command, 20_000);
    expect(result.code).not.toBe(0);

    await filterDenyEvent(page, "/usr/bin/curl", ["/usr/bin/curl"]);
    await pause(page, 1_400);

    resultLabel = "Execution denied";
    eventEvidence = "Events show a deny for exec:/usr/bin/curl.";
    transcriptStdout = `${policyCheck.stdout.trim()}\nprobe_stdout=${result.stdout.trim() || "(empty)"}`;
    transcriptStderr = result.stderr.trim();
    transcriptExitCode = result.code;
    observed = `mercury-policy test denied /usr/bin/curl, and the live execution probe exited ${result.code ?? -1}.`;
  } else {
    await pause(page, 1_600);
    resultLabel = "Exec rule denied in policy test";
    eventEvidence =
      "This AppArmor-backed runtime does not expose the eBPF exec hook, so this clip uses policy-test proof instead of live PROC_EXEC enforcement.";
  }

  await finalizeScenarioRecording({
    env: e2e,
    page,
    testInfo,
    entry: {
      id: "exec-deny",
      order: 5,
      title: "Blocked Binary Execution",
      summary:
        "An exec deny rule is loaded for /usr/bin/curl, with live enforcement shown when the kernel exec hook is available.",
      resultLabel,
      eventEvidence,
      evidenceFilter: "deny_demo_exec",
      trimBeforeFrames: 8,
      introDurationInFrames: Math.round(DEMO_FPS * 2.5),
      videoDurationInFrames: DEFAULT_SCENARIO_FRAMES,
      posterFrame: Math.floor(DEFAULT_SCENARIO_FRAMES / 2),
      includeInOverview: true,
      readmeEmbed: false
    },
    transcript: {
      kind: "command",
      displayCommand: `mercury-policy test --socket ${e2e.socketPath} --profile default ${policyTestArgs.join(" ")}`,
      command: [
        "mercury-policy",
        "test",
        "--socket",
        e2e.socketPath,
        "--profile",
        "default",
        ...policyTestArgs
      ],
      exitCode: transcriptExitCode,
      stdout: transcriptStdout,
      stderr: transcriptStderr,
      expected:
        "The policy test should deny /usr/bin/curl, and live execution is also checked when the kernel exec hook is available.",
      observed
    }
  });
});
