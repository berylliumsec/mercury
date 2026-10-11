import { spawn } from "node:child_process";
import path from "node:path";

import type { E2eEnv } from "./env";

function binaryPath(binDir: string, name: string): string {
  return path.join(binDir, name);
}

export type CommandResult = {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
};

export type SpawnedProcess = {
  child: ReturnType<typeof spawn>;
  wait: () => Promise<CommandResult>;
};

export function spawnBinary(
  env: E2eEnv,
  binary: string,
  args: string[],
  options: { timeoutMs?: number } = {}
): SpawnedProcess {
  const child = spawn(binaryPath(env.binDir, binary), args, {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timeout: NodeJS.Timeout | undefined;

  child.stdout?.on("data", (chunk: Buffer | string) => {
    stdout += chunk.toString();
  });
  child.stderr?.on("data", (chunk: Buffer | string) => {
    stderr += chunk.toString();
  });

  if (options.timeoutMs) {
    timeout = setTimeout(() => {
      child.kill("SIGKILL");
    }, options.timeoutMs);
  }

  return {
    child,
    wait: async () =>
      await new Promise<CommandResult>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => {
          if (timeout) {
            clearTimeout(timeout);
          }
          resolve({ code, signal, stdout, stderr });
        });
      })
  };
}

export async function runAiRun(env: E2eEnv, command: string[], timeoutMs = 20_000) {
  const spawned = spawnBinary(
    env,
    "mercury-run",
    ["--socket", env.socketPath, "--profile", "default", "--", ...command],
    { timeoutMs }
  );
  return await spawned.wait();
}

export function spawnAiRun(env: E2eEnv, command: string[], timeoutMs = 20_000) {
  return spawnBinary(
    env,
    "mercury-run",
    ["--socket", env.socketPath, "--profile", "default", "--", ...command],
    { timeoutMs }
  );
}

export async function runMercuryPolicyReload(env: E2eEnv, file: string, timeoutMs = 20_000) {
  const spawned = spawnBinary(
    env,
    "mercury-policy",
    ["reload", "--socket", env.socketPath, "--file", file],
    { timeoutMs }
  );
  return await spawned.wait();
}

export async function runMercuryPolicyTest(env: E2eEnv, args: string[], timeoutMs = 20_000) {
  const spawned = spawnBinary(
    env,
    "mercury-policy",
    ["test", "--socket", env.socketPath, "--profile", "default", ...args],
    { timeoutMs }
  );
  return await spawned.wait();
}

export async function runMercuryStatus(env: E2eEnv, timeoutMs = 20_000) {
  const spawned = spawnBinary(env, "mercury-status", ["--socket", env.socketPath, "--dashboard"], {
    timeoutMs
  });
  return await spawned.wait();
}
