import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import type { Page, TestInfo } from "@playwright/test";

import type {
  DemoManifest,
  DemoManifestEntry,
  DemoScenarioId,
  DemoTranscript
} from "../../demo-pipeline/types";
import type { E2eEnv } from "../support/env";

function demoRoot(env: E2eEnv) {
  return env.demoArtifactDir;
}

export function demoManifestPath(env: E2eEnv) {
  return path.join(demoRoot(env), "manifest.json");
}

export function demoAuthStatePath(env: E2eEnv) {
  return path.join(demoRoot(env), "auth-state.json");
}

export function demoPolicyPath(env: E2eEnv, id: DemoScenarioId) {
  return path.join(demoRoot(env), "policies", `${id}.yaml`);
}

export async function ensureDemoArtifactDirs(env: E2eEnv) {
  await Promise.all([
    mkdir(demoRoot(env), { recursive: true }),
    mkdir(path.join(demoRoot(env), "raw-videos"), { recursive: true }),
    mkdir(path.join(demoRoot(env), "transcripts"), { recursive: true }),
    mkdir(path.join(demoRoot(env), "rendered"), { recursive: true }),
    mkdir(path.join(demoRoot(env), "readme"), { recursive: true }),
    mkdir(path.join(demoRoot(env), "policies"), { recursive: true })
  ]);
}

export async function loadDemoManifest(env: E2eEnv): Promise<DemoManifest> {
  try {
    const raw = await readFile(demoManifestPath(env), "utf8");
    return JSON.parse(raw) as DemoManifest;
  } catch {
    return {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      scenarios: []
    };
  }
}

export async function writeDemoManifest(env: E2eEnv, manifest: DemoManifest) {
  manifest.generatedAt = new Date().toISOString();
  await writeFile(demoManifestPath(env), JSON.stringify(manifest, null, 2));
}

export async function writeDemoPolicy(env: E2eEnv, id: DemoScenarioId, yaml: string) {
  const file = demoPolicyPath(env, id);
  await writeFile(file, yaml);
  return file;
}

export async function writeTranscript(env: E2eEnv, id: DemoScenarioId, transcript: DemoTranscript) {
  const file = path.join(demoRoot(env), "transcripts", `${id}.json`);
  await writeFile(file, JSON.stringify(transcript, null, 2));
  return file;
}

export async function upsertManifestEntry(env: E2eEnv, entry: DemoManifestEntry) {
  const manifest = await loadDemoManifest(env);
  manifest.scenarios = manifest.scenarios.filter((scenario) => scenario.id !== entry.id);
  manifest.scenarios.push(entry);
  manifest.scenarios.sort((left, right) => left.order - right.order);
  await writeDemoManifest(env, manifest);
}

export async function finalizeScenarioRecording({
  env,
  page,
  testInfo,
  entry,
  transcript
}: {
  env: E2eEnv;
  page: Page;
  testInfo: TestInfo;
  entry: Omit<DemoManifestEntry, "transcriptPath" | "rawVideoPath" | "rawVideoPublicPath">;
  transcript: DemoTranscript;
}) {
  await ensureDemoArtifactDirs(env);
  const rawVideoPath = path.join(demoRoot(env), "raw-videos", `${entry.id}.webm`);
  const transcriptPath = await writeTranscript(env, entry.id, transcript);
  const video = page.video();

  if (!video) {
    throw new Error(`Playwright video was not enabled for ${entry.id}`);
  }

  await page.context().close();
  await video.saveAs(rawVideoPath);
  await upsertManifestEntry(env, {
    ...entry,
    transcriptPath,
    rawVideoPath,
    rawVideoPublicPath: `/raw-videos/${entry.id}.webm`
  });

  await testInfo.attach(`${entry.id}-transcript`, {
    path: transcriptPath,
    contentType: "application/json"
  });
  await testInfo.attach(`${entry.id}-video`, {
    path: rawVideoPath,
    contentType: "video/webm"
  });
}
