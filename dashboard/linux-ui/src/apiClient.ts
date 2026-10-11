import type {
  LaunchAgentRequest,
  LaunchAgentResponse,
  RecentAgentLaunch,
  RunningAgent
} from "./dashboardTypes";
import { handleStaticDemoRequest, isStaticDemoMode } from "./demo/demoBackend";

const API_BASE = "/api/v1";

type ApiErrorPayload = {
  code?: string;
  message?: string;
  details?: string | null;
};

type ApiRequestOptions = RequestInit & {
  suppressAuthRedirect?: boolean;
};

let unauthorizedHandler: ((error: AuthRequiredError) => void) | null = null;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export class AuthRequiredError extends Error {
  constructor(message = "Session expired, please log in again.") {
    super(message);
    this.name = "AuthRequiredError";
  }
}

export function setUnauthorizedHandler(handler: ((error: AuthRequiredError) => void) | null): void {
  unauthorizedHandler = handler;
}

function isAuthRoute(path: string): boolean {
  return path.startsWith("/auth/");
}

async function parseErrorMessage(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const payload = (await response.json()) as ApiErrorPayload;
      if (payload.details) {
        return `${payload.message ?? "request failed"}: ${payload.details}`;
      }
      if (payload.message) {
        return payload.message;
      }
    } catch {
      // Fall through to the text parser.
    }
  }

  try {
    const body = await response.text();
    if (body) {
      return body;
    }
  } catch {
    // Ignore body read failures.
  }

  return `request failed: ${response.status}`;
}

export async function request(path: string, init: ApiRequestOptions = {}): Promise<Response> {
  const { suppressAuthRedirect = false, ...requestInit } = init;
  const headers = new Headers(requestInit.headers ?? {});
  if (requestInit.body != null && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (isStaticDemoMode()) {
    const response = await handleStaticDemoRequest(path, {
      ...requestInit,
      headers
    });

    if (response.status === 401) {
      const error = new AuthRequiredError();
      if (!suppressAuthRedirect && !isAuthRoute(path)) {
        unauthorizedHandler?.(error);
      }
      throw error;
    }

    return response;
  }

  const fetchWithCredentials = () =>
    fetch(`${API_BASE}${path}`, {
      ...requestInit,
      credentials: "include",
      headers
    });

  let response = await fetchWithCredentials();

  // Some browsers can briefly race cookie persistence immediately after login.
  // Retry one time before surfacing a session-expired UX.
  if (response.status === 401 && !isAuthRoute(path)) {
    await sleep(150);
    response = await fetchWithCredentials();
  }

  if (response.status === 401) {
    const error = new AuthRequiredError();
    if (!suppressAuthRedirect && !isAuthRoute(path)) {
      unauthorizedHandler?.(error);
    }
    throw error;
  }

  return response;
}

export async function api<T>(path: string, init: ApiRequestOptions = {}): Promise<T> {
  const response = await request(path, init);
  if (!response.ok) {
    throw new Error(await parseErrorMessage(response));
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export async function launchAgent(
  req: LaunchAgentRequest,
  csrfToken: string
): Promise<LaunchAgentResponse> {
  return api<LaunchAgentResponse>("/agents/launch", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(req)
  });
}

export async function listAgents(): Promise<RunningAgent[]> {
  return api<RunningAgent[]>("/agents");
}

export async function listAgentLaunchHistory(): Promise<RecentAgentLaunch[]> {
  return api<RecentAgentLaunch[]>("/agents/history");
}

export async function stopAgent(agentId: string, csrfToken: string): Promise<void> {
  return api<void>(`/agents/${agentId}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken }
  });
}
