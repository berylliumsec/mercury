import type { EventItem } from "./eventHelpers";

export type EventFilters = {
  decision: string;
  actionClass: string;
  text: string;
  /** Exact action type (e.g. PROC_START); "all" or absent for any. */
  actionType?: string;
  /** Exact agent id; empty or absent for any. */
  agentId?: string;
};

/** Rows fetched per history page. */
export const EVENTS_PAGE_LIMIT = 120;
/** Rows kept in the live table; older rows stay reachable via "Load older" and export. */
export const LIVE_EVENTS_LIMIT = 1000;
export const EVENTS_SEARCH_DEBOUNCE_MS = 250;

function normalizeText(value: string): string {
  return value.trim().toLowerCase();
}

function stringifyRawJson(value: unknown): string {
  if (value == null) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function eventMatchesFilters(item: EventItem, filters: EventFilters): boolean {
  if (filters.decision !== "all" && item.effective_decision !== filters.decision) {
    return false;
  }
  if (filters.actionClass !== "all" && item.action_class !== filters.actionClass) {
    return false;
  }
  if (
    filters.actionType &&
    filters.actionType !== "all" &&
    item.action_type !== filters.actionType
  ) {
    return false;
  }
  const agentId = filters.agentId?.trim();
  if (agentId && item.agent_id !== agentId) {
    return false;
  }

  const normalized = normalizeText(filters.text);
  if (!normalized) {
    return true;
  }

  return [item.resource, item.message, stringifyRawJson(item.raw_json)]
    .join(" ")
    .toLowerCase()
    .includes(normalized);
}

/** Server-side filter parameters shared by /events and /events/export. */
export function buildEventFilterParams(filters: EventFilters): URLSearchParams {
  const query = new URLSearchParams();
  if (filters.decision !== "all") {
    query.set("decision", filters.decision);
  }
  if (filters.actionClass !== "all") {
    query.set("class", filters.actionClass);
  }
  if (filters.actionType && filters.actionType !== "all") {
    query.set("action_type", filters.actionType);
  }
  const agentId = filters.agentId?.trim();
  if (agentId) {
    query.set("agent_id", agentId);
  }

  const text = filters.text.trim();
  if (text) {
    query.set("text", text);
  }

  return query;
}

export function buildEventsQueryParams(
  filters: EventFilters,
  limit = EVENTS_PAGE_LIMIT,
  offset = 0,
  beforeId?: number
): URLSearchParams {
  const query = new URLSearchParams({
    limit: String(limit),
    offset: String(offset)
  });
  if (beforeId != null) {
    query.set("before_id", String(beforeId));
  }
  for (const [key, value] of buildEventFilterParams(filters)) {
    query.set(key, value);
  }
  return query;
}

export function buildEventsExportPath(filters: EventFilters, format: "jsonl" | "csv"): string {
  const query = buildEventFilterParams(filters);
  query.set("format", format);
  return `/events/export?${query.toString()}`;
}

/** Number of events a `gap` SSE frame reports as not delivered (0 if malformed). */
export function parseGapSkipped(data: string): number {
  try {
    const payload = JSON.parse(data) as { skipped?: unknown };
    const skipped = Number(payload.skipped);
    return Number.isFinite(skipped) && skipped > 0 ? Math.floor(skipped) : 0;
  } catch {
    return 0;
  }
}

export class LatestRequestController {
  private requestId = 0;
  private abortController: AbortController | null = null;

  begin(): { requestId: number; signal: AbortSignal } {
    this.abortController?.abort();
    this.abortController = new AbortController();
    this.requestId += 1;

    return {
      requestId: this.requestId,
      signal: this.abortController.signal
    };
  }

  isCurrent(requestId: number): boolean {
    return requestId === this.requestId;
  }

  clear(requestId: number): void {
    if (this.isCurrent(requestId)) {
      this.abortController = null;
    }
  }

  abortCurrent(): void {
    this.abortController?.abort();
    this.abortController = null;
  }
}
