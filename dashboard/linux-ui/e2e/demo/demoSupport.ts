import { expect, type Locator, type Page } from "@playwright/test";

import type { DemoScenarioId } from "../../demo-pipeline/types";
import type { E2eEnv } from "../support/env";
import { runMercuryPolicyReload } from "../support/runtime";
import { writeDemoPolicy } from "./demoArtifacts";

export const DEMO_FPS = 24;
export const DEFAULT_SCENARIO_FRAMES = 12 * DEMO_FPS;
export const DEFAULT_OVERVIEW_FRAMES = 14 * DEMO_FPS;

function quote(arg: string) {
  return /[^A-Za-z0-9_./:=+-]/.test(arg) ? JSON.stringify(arg) : arg;
}

export function formatCommand(command: string[]) {
  return command.map(quote).join(" ");
}

export async function pause(page: Page, ms = 450) {
  await page.waitForTimeout(ms);
}

export async function openOverview(page: Page) {
  await page.getByTestId("tab-overview").click();
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
  await pause(page, 600);
}

export async function ensureAuthenticated(page: Page, env: E2eEnv) {
  await page.goto(env.baseUrl);

  if (
    await page
      .getByTestId("metric-daemon")
      .isVisible()
      .catch(() => false)
  ) {
    await expect(page.getByTestId("metric-daemon")).toContainText("Online");
    return;
  }

  if (
    await page
      .getByTestId("login-submit")
      .isVisible()
      .catch(() => false)
  ) {
    await page.getByTestId("auth-username-input").fill(env.username);
    await pause(page, 250);
    await page.getByTestId("auth-password-input").fill(env.password);
    await pause(page, 250);
    await page.getByTestId("login-submit").click();
  } else {
    await page.getByTestId("auth-password-input").fill(env.password);
    await page.getByTestId("auth-password-confirm-input").fill(env.password);
    await pause(page, 250);
    await page.getByTestId("signup-submit").click();
  }

  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
  await expect(page.getByTestId("metric-url-gateway")).toContainText("Ready");
}

export async function openPolicyStudio(page: Page) {
  await page.getByTestId("tab-policy").click();
  await expect(page.getByTestId("policy-editor-panel")).toBeVisible();
  await pause(page, 700);
}

export async function openEvents(page: Page) {
  await page.getByTestId("tab-events").click();
  await expect(page.getByTestId("stream-status")).toContainText("connected");
  await pause(page, 700);
}

export async function saveValidateApply(page: Page, note: string) {
  await page.getByTestId("save-draft-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Draft saved");
  await pause(page);
  await page.getByTestId("validate-draft-button").click();
  await expect(page.getByTestId("policy-validation-box")).toContainText("Validation passed");
  await pause(page);
  await page.getByTestId("apply-draft-button").click();
  await expect(page.getByTestId("apply-confirm-modal")).toBeVisible();
  await page.getByTestId("apply-note-input").fill(note);
  await pause(page, 250);
  await page.getByTestId("apply-confirm-button").click();
  await expect(page.getByTestId("policy-message")).toContainText("Policy applied");
  await pause(page, 700);
}

export async function applyRepresentativeRules(page: Page, env: E2eEnv) {
  await openPolicyStudio(page);

  await page.getByTestId("file-deny-section-add").click();
  await pause(page, 250);
  await page.getByTestId("file-deny-id-0").fill("demo_file_secret");
  await page.getByTestId("file-deny-pattern-0").fill(`${env.blockedDir}/**`);
  await pause(page, 300);

  await page.getByTestId("network-deny-section-add").click();
  await pause(page, 250);
  await page.getByTestId("network-deny-id-0").fill("demo_port_block");
  await page.getByTestId("network-deny-cidr-0").fill("127.0.0.1/32");
  await page
    .locator('[data-testid="network-deny-section"] input[placeholder="port"]')
    .first()
    .fill(env.blockedTcpPort);
  await page.locator('[data-testid="network-deny-section"] select').first().selectOption("TCP");
  await pause(page, 300);

  await page.getByTestId("url-deny-section-add").click();
  await pause(page, 250);
  await page.getByTestId("url-deny-id-0").fill("demo_blocked_site");
  await page.getByTestId("url-deny-scheme-0").fill("http");
  await page.getByTestId("url-deny-host-0").fill("127.0.0.1");
  await page.getByTestId("url-deny-port-0").fill(new URL(env.httpBlockedUrl).port);
  await page.getByTestId("url-deny-port-0").blur();
  await page.getByTestId("url-deny-path-0").fill("/blocked/**");
  await pause(page, 300);

  await page.getByTestId("exec-deny-section-add").click();
  await pause(page, 250);
  await page.getByTestId("exec-deny-id-0").fill("demo_exec_curl");
  await page.getByTestId("exec-deny-path-0").fill("/usr/bin/curl");
  await pause(page, 300);

  await saveValidateApply(page, "README demo overview");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("demo_blocked_site");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("demo_port_block");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("demo_file_secret");
  await expect(page.getByTestId("active-policy-yaml")).toContainText("demo_exec_curl");
}

export async function filterDenyEvent(page: Page, resourceFilter: string, expectedText: string[]) {
  await page.getByTestId("events-decision-filter").selectOption("deny");
  await pause(page, 250);
  await page.getByTestId("events-resource-filter").fill(resourceFilter);
  const rows = page.locator('[data-testid="events-table"] tbody tr');
  await expect(rows.first()).toContainText("deny");
  for (const value of expectedText) {
    await expect(rows.first()).toContainText(value);
  }
  await pause(page, 900);
  return rows.first();
}

export async function reloadScenarioPolicy(env: E2eEnv, id: DemoScenarioId, yaml: string) {
  const file = await writeDemoPolicy(env, id, yaml);
  const result = await runMercuryPolicyReload(env, file, 30_000);
  expect(result.code).toBe(0);
  expect(result.stdout).toContain("reload success=true");
  return file;
}

function baseHeader() {
  return `version: v1
defaults:
  decision: deny
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default:
    file_allow:
      - id: allow_abs
        pattern: /**
    exec_allow:
      - id: allow_exec_abs
        path: /**
`;
}

export function buildUrlDenyPolicy(env: E2eEnv) {
  const blocked = new URL(env.httpBlockedUrl);
  const allowed = new URL(env.httpAllowedUrl);

  return `${baseHeader()}    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    url_allow:
      - id: allow_http_local
        scheme: ${allowed.protocol.replace(":", "")}
        host_glob: ${allowed.hostname}
        port: ${allowed.port}
        method: GET
        path_glob: /allowed/**
    url_deny:
      - id: deny_http_local
        scheme: ${blocked.protocol.replace(":", "")}
        host_glob: ${blocked.hostname}
        port: ${blocked.port}
        method: GET
        path_glob: /blocked/**
`;
}

export function buildNetworkPortDenyPolicy(env: E2eEnv) {
  return `${baseHeader()}    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    network_deny:
      - id: deny_demo_port
        cidr: 127.0.0.1/32
        port: ${env.blockedTcpPort}
        protocol: TCP
`;
}

export function buildFolderDenyPolicy(env: E2eEnv) {
  return `${baseHeader()}    file_deny:
      - id: deny_demo_folder
        pattern: ${env.blockedDir}/**
`;
}

export function buildExecDenyPolicy() {
  return `${baseHeader()}    exec_deny:
      - id: deny_demo_exec
        path: /usr/bin/curl
`;
}

export async function expectStatusReady(page: Page) {
  await expect(page.getByTestId("metric-daemon")).toContainText("Online");
  await expect(page.getByTestId("metric-url-gateway")).toContainText("Ready");
}

export async function firstEventRow(page: Page): Promise<Locator> {
  const row = page.locator('[data-testid="events-table"] tbody tr').first();
  await expect(row).toBeVisible();
  return row;
}
