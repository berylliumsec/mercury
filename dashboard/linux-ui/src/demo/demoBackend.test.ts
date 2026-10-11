import { describe, expect, it } from "vitest";
import yaml from "js-yaml";

import { handleStaticDemoRequest, resetStaticDemoState } from "./demoBackend";
import { normalizePolicyDocument } from "../policyHelpers";

async function readJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

describe("static demo backend", () => {
  it("serves seeded authenticated dashboard data", async () => {
    resetStaticDemoState();

    const auth = await readJson<{ authenticated: boolean; csrf_token?: string }>(
      await handleStaticDemoRequest("/auth/me")
    );
    const status = await readJson<{ daemon_up: boolean; dashboard_url?: string }>(
      await handleStaticDemoRequest("/status/summary")
    );
    const events = await readJson<{ total: number; items: Array<{ id: number }> }>(
      await handleStaticDemoRequest("/events?limit=5&offset=0")
    );

    expect(auth.authenticated).toBe(true);
    expect(auth.csrf_token).toBeTruthy();
    expect(status.daemon_up).toBe(true);
    expect(status.dashboard_url).toBe("Static guided build");
    expect(events.total).toBeGreaterThan(5);
    expect(events.items).toHaveLength(5);
  });

  it("saves, validates, and applies a draft in demo mode", async () => {
    resetStaticDemoState();

    const auth = await readJson<{ csrf_token: string }>(await handleStaticDemoRequest("/auth/me"));
    const active = await readJson<{ yaml: string }>(
      await handleStaticDemoRequest("/policy/active")
    );
    const document = normalizePolicyDocument(yaml.load(active.yaml));
    document.profiles.default.file_deny.push({
      id: "deny_demo_notes",
      pattern: "/workspace/assistant/notes/private/**"
    });

    const draft = await readJson<{ id: string }>(
      await handleStaticDemoRequest("/policy/drafts", {
        method: "POST",
        headers: { "x-csrf-token": auth.csrf_token },
        body: JSON.stringify({ document })
      })
    );

    const validation = await readJson<{ valid: boolean }>(
      await handleStaticDemoRequest(`/policy/drafts/${draft.id}/validate`, {
        method: "POST",
        headers: { "x-csrf-token": auth.csrf_token }
      })
    );

    const apply = await readJson<{ success: boolean; version_id: string | null }>(
      await handleStaticDemoRequest(`/policy/drafts/${draft.id}/apply`, {
        method: "POST",
        headers: { "x-csrf-token": auth.csrf_token },
        body: JSON.stringify({ note: "test apply" })
      })
    );

    const refreshed = await readJson<{ yaml: string }>(
      await handleStaticDemoRequest("/policy/active")
    );

    expect(validation.valid).toBe(true);
    expect(apply.success).toBe(true);
    expect(apply.version_id).toBeTruthy();
    expect(refreshed.yaml).toContain("deny_demo_notes");
  });
});
