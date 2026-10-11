import path from "node:path";
import { fileURLToPath } from "node:url";

export type E2eEnv = {
  baseUrl: string;
  socketPath: string;
  username: string;
  password: string;
  launchUser: string;
  launchUid: string;
  launchMarker: string;
  systemPython: string;
  venvPython: string;
  fileDenyPath: string;
  httpAllowedUrl: string;
  httpBlockedUrl: string;
  httpsAllowedUrl: string;
  httpsBlockedUrl: string;
  blockedDir: string;
  blockedFile: string;
  blockedTcpPort: string;
  demoArtifactDir: string;
  binDir: string;
  /** Optional: absolute paths to a TLS cert/key on the test server. Empty string when not configured. */
  tlsCertFile: string;
  tlsKeyFile: string;
};

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

export function loadE2eEnv(): E2eEnv {
  const supportDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(supportDir, "../../../..");

  return {
    baseUrl: requireEnv("MERCURY_E2E_BASE_URL"),
    socketPath: requireEnv("MERCURY_E2E_SOCKET"),
    username: requireEnv("MERCURY_E2E_USERNAME"),
    password: requireEnv("MERCURY_E2E_PASSWORD"),
    launchUser: requireEnv("MERCURY_E2E_LAUNCH_USER"),
    launchUid: requireEnv("MERCURY_E2E_LAUNCH_UID"),
    launchMarker: requireEnv("MERCURY_E2E_LAUNCH_MARKER"),
    systemPython: process.env.MERCURY_E2E_SYSTEM_PYTHON ?? "/usr/bin/python3",
    venvPython:
      process.env.MERCURY_E2E_VENV_PYTHON ?? path.join(repoRoot, ".venv-agent-test/bin/python"),
    fileDenyPath: requireEnv("MERCURY_E2E_FILE_DENY_PATH"),
    httpAllowedUrl: requireEnv("MERCURY_E2E_HTTP_ALLOWED_URL"),
    httpBlockedUrl: requireEnv("MERCURY_E2E_HTTP_BLOCKED_URL"),
    httpsAllowedUrl: requireEnv("MERCURY_E2E_HTTPS_ALLOWED_URL"),
    httpsBlockedUrl: requireEnv("MERCURY_E2E_HTTPS_BLOCKED_URL"),
    blockedDir: process.env.MERCURY_E2E_BLOCKED_DIR ?? path.join(repoRoot, "tmp/demo-secrets"),
    blockedFile: process.env.MERCURY_E2E_BLOCKED_FILE ?? requireEnv("MERCURY_E2E_FILE_DENY_PATH"),
    blockedTcpPort: process.env.MERCURY_E2E_BLOCKED_TCP_PORT ?? "0",
    demoArtifactDir:
      process.env.MERCURY_E2E_DEMO_ARTIFACT_DIR ?? path.join(repoRoot, "tmp/demo-artifacts"),
    binDir: process.env.MERCURY_E2E_BIN_DIR ?? path.join(repoRoot, "target/release"),
    tlsCertFile: process.env.MERCURY_E2E_TLS_CERT_FILE ?? "",
    tlsKeyFile: process.env.MERCURY_E2E_TLS_KEY_FILE ?? ""
  };
}
