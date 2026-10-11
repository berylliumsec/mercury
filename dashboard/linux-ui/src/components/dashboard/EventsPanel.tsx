import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  ACTION_CLASS_OPTIONS,
  ACTION_TYPES,
  actionTypeLabel,
  decisionLabel,
  isInformational,
  TAMPER_ACTION_TYPES
} from "../../actionTypes";
import { AuthRequiredError, api, request } from "../../apiClient";
import type { EventListResponse, StreamStatus } from "../../dashboardTypes";
import { fmt, fmtTime, statusBadge, streamBadgeClass } from "../../dashboardUi";
import { downloadExport } from "../../downloads";
import { parseDecisionEvent, type EventItem } from "../../eventHelpers";
import {
  buildEventsExportPath,
  buildEventsQueryParams,
  eventMatchesFilters,
  EVENTS_PAGE_LIMIT,
  EVENTS_SEARCH_DEBOUNCE_MS,
  LatestRequestController,
  LIVE_EVENTS_LIMIT,
  parseGapSkipped,
  type EventFilters
} from "../../eventsSearch";
import {
  hasCapturedContent,
  modelCallLabel,
  parseModelCall,
  type ModelCall
} from "../../modelCall";
import type { PolicyDocument } from "../../policyHelpers";
import { AppIcon, type AppIconName } from "./AppIcon";
import { EventDetailsModal } from "./EventDetailsModal";
import { ModelCallModal } from "./ModelCallModal";
import { PanelCard } from "./PanelCard";

type QuickRuleTarget = {
  item: EventItem;
  direction: "allow" | "deny" | "require_approval";
};

type ModelCallTarget = {
  item: EventItem;
  call: ModelCall;
};

type EventsPanelProps = {
  csrfToken: string;
  policyDoc: PolicyDocument;
  refreshNonce: number;
  onPolicyChanged: () => void;
};

type ParsedSseMessage = {
  id?: string;
  event: string;
  data: string;
};

const QUICK_RULE_FILE_ACTIONS = new Set([
  "FILE_READ",
  "FILE_WRITE",
  "FILE_DELETE",
  "FILE_MMAP",
  "FILE_RENAME",
  "FILE_LINK",
  "FILE_SYMLINK",
  "FILE_MKDIR",
  "FILE_RMDIR",
  "FILE_CREATE",
  "FILE_CHMOD",
  "FILE_CHOWN",
  "FILE_TRUNCATE"
]);

const QUICK_RULE_PROCESS_ACTIONS = new Set([
  "PROC_EXEC",
  "PROC_PTRACE",
  "PROC_KILL",
  "PROC_CAPABLE"
]);

const QUICK_RULE_NETWORK_ACTIONS = new Set(["NET_CONNECT", "NET_SENDMSG"]);
const QUICK_RULE_MCP_ACTIONS = new Set(["MCP_TOOL_CALL"]);

function supportsQuickRuleAction(actionType: string): boolean {
  return (
    QUICK_RULE_FILE_ACTIONS.has(actionType) ||
    QUICK_RULE_PROCESS_ACTIONS.has(actionType) ||
    QUICK_RULE_NETWORK_ACTIONS.has(actionType) ||
    QUICK_RULE_MCP_ACTIONS.has(actionType)
  );
}

function parseSseMessage(block: string): ParsedSseMessage | null {
  const lines = block.split("\n");
  const dataLines: string[] = [];
  let id: string | undefined;
  let event = "message";

  for (const line of lines) {
    if (!line || line.startsWith(":")) {
      continue;
    }

    const separator = line.indexOf(":");
    const field = separator === -1 ? line : line.slice(0, separator);
    const rawValue = separator === -1 ? "" : line.slice(separator + 1).replace(/^ /, "");
    switch (field) {
      case "id":
        id = rawValue;
        break;
      case "event":
        event = rawValue || "message";
        break;
      case "data":
        dataLines.push(rawValue);
        break;
      default:
        break;
    }
  }

  if (!dataLines.length) {
    return null;
  }

  return {
    id,
    event,
    data: dataLines.join("\n")
  };
}

function mergeEvents(
  previous: EventItem[],
  incoming: EventItem[],
  limit = LIVE_EVENTS_LIMIT
): EventItem[] {
  const seen = new Set<number>();
  const merged: EventItem[] = [];

  for (const item of [...incoming, ...previous]) {
    if (seen.has(item.id)) {
      continue;
    }
    seen.add(item.id);
    merged.push(item);
    if (merged.length >= limit) {
      break;
    }
  }

  return merged;
}

/** Appends an older page below the rows already shown, skipping duplicates. */
function appendOlderEvents(previous: EventItem[], older: EventItem[]): EventItem[] {
  const seen = new Set(previous.map((item) => item.id));
  return [...previous, ...older.filter((item) => !seen.has(item.id))];
}

function eventRowClass(item: EventItem): string {
  const classes = ["event-row"];
  if (item.effective_decision === "deny") {
    classes.push("event-row-deny");
  } else if (isInformational(item)) {
    classes.push("event-row-system");
  }
  if (TAMPER_ACTION_TYPES.has(item.action_type)) {
    classes.push("event-row-tamper");
  }
  return classes.join(" ");
}

function globMatches(pattern: string, value: string): boolean {
  const re = pattern
    .split(/(\*\*)/)
    .map((part, index) =>
      index % 2 === 1
        ? ".*"
        : part
            .replace(/[.+^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, "[^/]*")
            .replace(/\?/g, "[^/]")
    )
    .join("");
  try {
    return new RegExp(`^${re}$`).test(value);
  } catch {
    return pattern === value;
  }
}

function actionClassIconName(actionClass: string): AppIconName {
  switch (actionClass) {
    case "file":
      return "file";
    case "process":
      return "terminal";
    case "network":
      return "network";
    case "mcp":
      return "event";
    case "system":
      return "settings";
    default:
      return "event";
  }
}

function actionClassLabel(actionClass: string): string {
  switch (actionClass) {
    case "file":
      return "FILE";
    case "process":
      return "EXEC";
    case "network":
      return "NET";
    case "mcp":
      return "MCP";
    case "system":
      return "SYSTEM";
    default:
      return actionClass.toUpperCase();
  }
}

function hasRule(
  item: EventItem,
  direction: "allow" | "deny" | "require_approval",
  policyDoc: PolicyDocument
): boolean {
  const profile = policyDoc.profiles[item.profile];
  if (!profile || !item.resource_json) {
    return false;
  }

  let resource: Record<string, unknown>;
  try {
    resource = JSON.parse(item.resource_json) as Record<string, unknown>;
  } catch {
    return false;
  }

  if (!supportsQuickRuleAction(item.action_type)) {
    return false;
  }

  const kind = resource["kind"] as string | undefined;
  const path = resource["path"] as string | undefined;
  if ((kind === "FILE" || QUICK_RULE_FILE_ACTIONS.has(item.action_type)) && path) {
    const list = direction === "allow" ? profile.file_allow : profile.file_deny;
    return list.some((rule) => globMatches(rule.pattern, path));
  }
  if ((kind === "EXEC" || QUICK_RULE_PROCESS_ACTIONS.has(item.action_type)) && path) {
    const list = direction === "allow" ? profile.exec_allow : profile.exec_deny;
    return list.some((rule) => globMatches(rule.path, path));
  }
  if (kind === "NETWORK" || QUICK_RULE_NETWORK_ACTIONS.has(item.action_type)) {
    const fullUrl = resource["full_url"] as string | undefined;
    const urlHost = resource["dest_host"] as string | undefined;
    const urlPath = resource["path"] as string | undefined;
    if (
      direction !== "require_approval" &&
      (fullUrl || urlPath || resource["scheme"] || resource["method"])
    ) {
      const method = resource["method"] as string | undefined;
      const scheme = resource["scheme"] as string | undefined;
      const query = resource["query"] as string | undefined;
      const port = resource["dest_port"] as number | undefined;
      const list = direction === "allow" ? profile.url_allow : profile.url_deny;
      return list.some(
        (rule) =>
          rule.host_glob === urlHost &&
          rule.port === port &&
          rule.method === method &&
          rule.scheme === scheme &&
          rule.path_glob === (urlPath ?? "/") &&
          rule.query_glob === (query || undefined)
      );
    }
    if (direction === "require_approval") {
      return false;
    }
    const host = resource["dest_host"] as string | undefined;
    const port = resource["dest_port"] as number | undefined;
    const glob = host ? `*${host}*` : undefined;
    const list = direction === "allow" ? profile.network_allow : profile.network_deny;
    return list.some((rule) => rule.host_glob === glob && rule.port === port);
  }
  if (kind === "MCP_TOOL" || QUICK_RULE_MCP_ACTIONS.has(item.action_type)) {
    const serverId = resource["server_id"] as string | undefined;
    const toolName = resource["tool_name"] as string | undefined;
    const transport = (resource["transport"] as string | undefined) ?? "stdio";
    if (!serverId || !toolName || !profile.mcp) {
      return false;
    }
    const server = profile.mcp.servers.find(
      (entry) => entry.id === serverId && entry.transport === transport
    );
    if (!server) {
      return false;
    }
    const list =
      direction === "allow"
        ? server.tools.allow
        : direction === "deny"
          ? server.tools.deny
          : server.tools.require_approval;
    return list.includes(toolName);
  }
  return false;
}

function QuickRuleModal({
  target,
  profileNames,
  csrfToken,
  onClose,
  onApplied
}: {
  target: QuickRuleTarget;
  profileNames: string[];
  csrfToken: string;
  onClose: () => void;
  onApplied: (message: string) => void;
}) {
  const { item, direction } = target;
  const [selectedProfile, setSelectedProfile] = useState(
    item.profile || profileNames[0] || "default"
  );
  const [applying, setApplying] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [alreadyExists, setAlreadyExists] = useState(false);

  async function handleApply() {
    if (!item.resource_json) {
      setErrors(["Event has no resource data to create a rule from."]);
      return;
    }

    setApplying(true);
    setErrors([]);
    setAlreadyExists(false);
    try {
      const response = await api<{
        success: boolean;
        already_exists: boolean;
        version: string;
        errors: string[];
        rule_description: string;
      }>("/policy/quick-rule", {
        method: "POST",
        headers: { "x-csrf-token": csrfToken },
        body: JSON.stringify({
          action_type: item.action_type,
          resource_json: item.resource_json,
          profile: selectedProfile,
          direction
        })
      });

      if (response.already_exists) {
        setAlreadyExists(true);
      } else if (response.success) {
        onApplied(`Rule applied: ${response.rule_description} (policy ${response.version})`);
      } else {
        setErrors(response.errors.length ? response.errors : ["Unknown error"]);
      }
    } catch (err) {
      if (err instanceof AuthRequiredError) {
        return;
      }
      setErrors([(err as Error).message]);
    } finally {
      setApplying(false);
    }
  }

  const directionLabel =
    direction === "allow" ? "Allow" : direction === "deny" ? "Block" : "Require approval";
  const directionClass =
    direction === "allow" ? "pill-allow" : direction === "deny" ? "pill-deny" : "pill-observe";

  return (
    <div className="modal-overlay" data-testid="quick-rule-modal">
      <div className="modal-card">
        <div className="modal-header">
          <h3>
            Quick Rule <span className={`pill ${directionClass}`}>{directionLabel}</span>
          </h3>
          <button
            className="ghost icon-only-button"
            onClick={onClose}
            aria-label="Close"
            title="Close"
          >
            <AppIcon name="close" className="app-icon-sm" />
            <span className="sr-only">Close</span>
          </button>
        </div>
        <div className="modal-body">
          <p>
            <strong>Event:</strong> {item.action_type} <span className="mono">{item.resource}</span>
          </p>
          <p>
            <strong>Decision:</strong>{" "}
            <span className={statusBadge(item.effective_decision)}>{item.effective_decision}</span>
          </p>
          <div className="form-group">
            <label htmlFor="quick-rule-profile">Apply to profile</label>
            <select
              id="quick-rule-profile"
              value={selectedProfile}
              onChange={(event) => setSelectedProfile(event.target.value)}
            >
              {profileNames.map((profileName) => (
                <option key={profileName} value={profileName}>
                  {profileName}
                </option>
              ))}
            </select>
          </div>
          {alreadyExists ? (
            <p className="info">This rule already exists in the active policy.</p>
          ) : null}
          {errors.length ? (
            <ul className="validation-inline-list">
              {errors.map((error) => (
                <li key={error} className="error">
                  {error}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="modal-footer">
          <button className="ghost" onClick={onClose} disabled={applying}>
            <span className="button-with-icon">
              <AppIcon name="close" className="app-icon-sm" />
              <span>Cancel</span>
            </span>
          </button>
          <button
            className={
              direction === "allow" ? "primary" : direction === "deny" ? "danger" : "ghost"
            }
            onClick={() => void handleApply()}
            disabled={applying || !item.resource_json || alreadyExists}
            data-testid="quick-rule-confirm"
          >
            <span className="button-with-icon">
              <AppIcon
                name={direction === "allow" ? "check" : direction === "deny" ? "close" : "event"}
                className="app-icon-sm"
              />
              <span>
                {applying
                  ? "Applying..."
                  : alreadyExists
                    ? "Already exists"
                    : `${directionLabel} this resource`}
              </span>
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}

export const EventsPanel = memo(function EventsPanel({
  csrfToken,
  policyDoc,
  refreshNonce,
  onPolicyChanged
}: EventsPanelProps) {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [streamStatus, setStreamStatus] = useState<StreamStatus>("disconnected");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [actionClassFilter, setActionClassFilter] = useState("all");
  const [actionTypeFilter, setActionTypeFilter] = useState("all");
  const [resourceInput, setResourceInput] = useState("");
  const [resourceFilter, setResourceFilter] = useState("");
  const [agentInput, setAgentInput] = useState("");
  const [agentFilter, setAgentFilter] = useState("");
  const [quickRuleTarget, setQuickRuleTarget] = useState<QuickRuleTarget | null>(null);
  const [modelCallTarget, setModelCallTarget] = useState<ModelCallTarget | null>(null);
  const [detailsTarget, setDetailsTarget] = useState<EventItem | null>(null);
  /** Events the live stream reported as not delivered (gap frames). */
  const [skippedEvents, setSkippedEvents] = useState(0);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [exportFormat, setExportFormat] = useState<"jsonl" | "csv">("jsonl");
  const [exporting, setExporting] = useState(false);
  const [quickRuleMessage, setQuickRuleMessage] = useState<string | null>(null);
  const [streamReady, setStreamReady] = useState(false);
  const streamCursorRef = useRef<string | null>(null);
  const activeFiltersRef = useRef<EventFilters>({
    decision: "all",
    actionClass: "all",
    text: "",
    actionType: "all",
    agentId: ""
  });
  const queryPendingRef = useRef(false);
  const pendingLiveEventsRef = useRef<Map<number, EventItem>>(new Map());
  const requestControllerRef = useRef(new LatestRequestController());

  const profileNames = useMemo(() => Object.keys(policyDoc.profiles), [policyDoc]);
  // Parsed once per event page so filter typing and stream ticks do not re-walk
  // every raw audit payload.
  const modelCalls = useMemo(() => {
    const parsed = new Map<number, ModelCall>();
    for (const item of events) {
      const call = parseModelCall(item.raw_json);
      if (call) {
        parsed.set(item.id, call);
      }
    }
    return parsed;
  }, [events]);
  const activeFilters = useMemo(
    () => ({
      decision: decisionFilter,
      actionClass: actionClassFilter,
      text: resourceFilter,
      actionType: actionTypeFilter,
      agentId: agentFilter
    }),
    [decisionFilter, actionClassFilter, resourceFilter, actionTypeFilter, agentFilter]
  );

  useEffect(() => {
    if (!quickRuleMessage) {
      return;
    }

    const timer = window.setTimeout(() => setQuickRuleMessage(null), 5000);
    return () => window.clearTimeout(timer);
  }, [quickRuleMessage]);

  useEffect(() => {
    const timer = window.setTimeout(
      () => setResourceFilter(resourceInput),
      EVENTS_SEARCH_DEBOUNCE_MS
    );
    return () => window.clearTimeout(timer);
  }, [resourceInput]);

  useEffect(() => {
    const timer = window.setTimeout(() => setAgentFilter(agentInput), EVENTS_SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [agentInput]);

  useEffect(() => {
    activeFiltersRef.current = activeFilters;
  }, [activeFilters]);

  const refreshEvents = useCallback(async (filters: EventFilters) => {
    const requestControl = requestControllerRef.current.begin();
    queryPendingRef.current = true;
    pendingLiveEventsRef.current = new Map();
    setEventsLoading(true);
    try {
      const query = buildEventsQueryParams(filters);
      const response = await api<EventListResponse<EventItem>>(`/events?${query.toString()}`, {
        signal: requestControl.signal
      });
      if (!requestControllerRef.current.isCurrent(requestControl.requestId)) {
        return;
      }

      const responseItemIds = new Set(response.items.map((item) => item.id));
      const pendingLiveEvents = Array.from(pendingLiveEventsRef.current.values()).filter(
        (item) => !responseItemIds.has(item.id)
      );

      setEvents(mergeEvents(response.items, pendingLiveEvents));
      setEventsTotal(response.total + pendingLiveEvents.length);
      setEventsError(null);
    } catch (err) {
      if (
        requestControl.signal.aborted ||
        !requestControllerRef.current.isCurrent(requestControl.requestId)
      ) {
        return;
      }
      if (!(err instanceof AuthRequiredError)) {
        setEventsError((err as Error).message);
      }
    } finally {
      if (requestControllerRef.current.isCurrent(requestControl.requestId)) {
        queryPendingRef.current = false;
        pendingLiveEventsRef.current.clear();
        requestControllerRef.current.clear(requestControl.requestId);
        setEventsLoading(false);
      }
    }
  }, []);

  const loadOlderEvents = useCallback(async () => {
    const oldest = events.length ? events[events.length - 1].id : undefined;
    if (oldest == null) {
      return;
    }
    setLoadingOlder(true);
    try {
      const query = buildEventsQueryParams(activeFiltersRef.current, EVENTS_PAGE_LIMIT, 0, oldest);
      const response = await api<EventListResponse<EventItem>>(`/events?${query.toString()}`);
      setEvents((previous) => appendOlderEvents(previous, response.items));
      setEventsError(null);
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setEventsError((err as Error).message);
      }
    } finally {
      setLoadingOlder(false);
    }
  }, [events]);

  const exportEvents = useCallback(async () => {
    setExporting(true);
    try {
      await downloadExport(
        buildEventsExportPath(activeFiltersRef.current, exportFormat),
        `mercury-events.${exportFormat}`
      );
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setEventsError(`Export failed: ${(err as Error).message}`);
      }
    } finally {
      setExporting(false);
    }
  }, [exportFormat]);

  const ensureStreamCursor = useCallback(async (): Promise<void> => {
    if (streamCursorRef.current !== null) {
      return;
    }

    try {
      const response = await api<EventListResponse<EventItem>>(
        `/events?${new URLSearchParams({ limit: "1", offset: "0" }).toString()}`
      );
      streamCursorRef.current = response.items.length ? String(response.items[0].id) : "0";
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setEventsError((err as Error).message);
      }
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const requestController = requestControllerRef.current;

    async function loadEvents(): Promise<void> {
      await ensureStreamCursor();
      if (cancelled) {
        return;
      }
      await refreshEvents(activeFilters);
      if (!cancelled && streamCursorRef.current !== null) {
        setStreamReady(true);
      }
    }

    void loadEvents();

    return () => {
      cancelled = true;
      requestController.abortCurrent();
    };
  }, [activeFilters, ensureStreamCursor, refreshEvents, refreshNonce]);

  useEffect(() => {
    if (!streamReady) {
      return;
    }

    let cancelled = false;
    const abortController = new AbortController();

    async function readStream(response: Response): Promise<void> {
      if (!response.body) {
        throw new Error("Live event stream is unavailable.");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      try {
        while (!cancelled) {
          const { done, value } = await reader.read();
          if (done) {
            return;
          }
          buffer += decoder.decode(value, { stream: true });
          buffer = buffer.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

          let boundaryIndex = buffer.indexOf("\n\n");
          while (boundaryIndex >= 0) {
            const block = buffer.slice(0, boundaryIndex);
            buffer = buffer.slice(boundaryIndex + 2);
            const message = parseSseMessage(block);
            if (message?.id) {
              streamCursorRef.current = message.id;
            }
            if (message?.event === "gap") {
              const skipped = parseGapSkipped(message.data);
              if (skipped > 0) {
                setSkippedEvents((total) => total + skipped);
              }
            }
            if (message?.event === "decision") {
              try {
                const item = parseDecisionEvent(JSON.parse(message.data));
                if (!item) {
                  boundaryIndex = buffer.indexOf("\n\n");
                  continue;
                }
                if (item.id > 0) {
                  const nextCursor = Number(streamCursorRef.current ?? "0");
                  if (!Number.isNaN(nextCursor) && item.id > nextCursor) {
                    streamCursorRef.current = String(item.id);
                  }
                }

                if (eventMatchesFilters(item, activeFiltersRef.current)) {
                  if (queryPendingRef.current) {
                    pendingLiveEventsRef.current.set(item.id, item);
                  }
                  setEvents((previous) =>
                    mergeEvents(previous, [item], Math.max(LIVE_EVENTS_LIMIT, previous.length))
                  );
                  setEventsTotal((total) => total + 1);
                }
                setEventsError(null);
              } catch {
                // Ignore malformed frames.
              }
            }
            boundaryIndex = buffer.indexOf("\n\n");
          }
        }
      } finally {
        reader.releaseLock();
      }
    }

    async function connect(): Promise<void> {
      let backoffMs = 1000;
      setStreamStatus("connecting");

      while (!cancelled) {
        try {
          const headers = new Headers({ Accept: "text/event-stream" });
          if (streamCursorRef.current) {
            headers.set("last-event-id", streamCursorRef.current);
          }

          const response = await request("/events/stream", {
            headers,
            signal: abortController.signal
          });
          if (!response.ok) {
            const body = await response.text();
            throw new Error(body || `Live event stream failed: ${response.status}`);
          }

          setStreamStatus("connected");
          backoffMs = 1000;
          await readStream(response);

          if (!cancelled) {
            setStreamStatus("reconnecting");
          }
        } catch (err) {
          if (cancelled || abortController.signal.aborted || err instanceof AuthRequiredError) {
            return;
          }
          setStreamStatus("reconnecting");
          setEventsError((err as Error).message);
          await new Promise((resolve) => window.setTimeout(resolve, backoffMs));
          backoffMs = Math.min(backoffMs * 2, 30_000);
        }
      }
    }

    void connect();
    return () => {
      cancelled = true;
      abortController.abort();
      setStreamStatus("disconnected");
    };
  }, [streamReady]);

  return (
    <>
      <PanelCard
        title={
          <span className="heading-with-icon">
            <AppIcon name="event" className="app-icon-lg" />
            <span>Live Decision Stream</span>
          </span>
        }
        subtitle="Newest events first. Auto-updates from SSE."
        className="events-panel"
        testId="events-panel"
      >
        <div className="events-toolbar">
          <span className={streamBadgeClass(streamStatus)} data-testid="stream-status">
            {streamStatus}
          </span>
          <button
            className="ghost icon-only-button"
            data-testid="events-retry-button"
            onClick={() => void refreshEvents(activeFiltersRef.current)}
            aria-label="Retry event query"
            title="Retry event query"
          >
            <AppIcon name="refresh" className="app-icon-sm" />
            <span className="sr-only">Retry event query</span>
          </button>
          <div className="select-control events-export-control">
            <select
              value={exportFormat}
              onChange={(event) => setExportFormat(event.target.value as "jsonl" | "csv")}
              aria-label="Export format"
              data-testid="events-export-format"
            >
              <option value="jsonl">JSONL</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <button
            className="ghost"
            type="button"
            onClick={() => void exportEvents()}
            disabled={exporting}
            title="Export every stored event matching the current filters"
            data-testid="events-export-button"
          >
            <span className="button-with-icon">
              <AppIcon name="download" className="app-icon-sm" />
              <span>{exporting ? "Exporting..." : "Export"}</span>
            </span>
          </button>
        </div>
        {streamStatus === "reconnecting" ? (
          <p className="warn reconnect-banner" data-testid="events-reconnecting-banner">
            Reconnecting to the live event stream...
          </p>
        ) : null}
        {skippedEvents > 0 ? (
          <div className="events-gap-banner" role="status" data-testid="events-gap-banner">
            <AppIcon name="warning" className="app-icon-sm" />
            <span>
              {skippedEvents.toLocaleString()} {skippedEvents === 1 ? "event was" : "events were"}{" "}
              skipped by the live stream. They are stored: reload or export to review them.
            </span>
            <button
              type="button"
              className="ghost btn-sm"
              data-testid="events-gap-reload"
              onClick={() => {
                setSkippedEvents(0);
                void refreshEvents(activeFiltersRef.current);
              }}
            >
              Reload
            </button>
          </div>
        ) : null}
        <div className="panel-toolbar">
          <div className="select-control">
            <AppIcon name="filter" className="app-icon-sm" />
            <select
              value={decisionFilter}
              onChange={(event) => setDecisionFilter(event.target.value)}
              aria-label="Filter events by decision"
              data-testid="events-decision-filter"
            >
              <option value="all">All decisions</option>
              <option value="deny">Deny</option>
              <option value="allow">Allow</option>
              <option value="observe">Observe</option>
            </select>
          </div>
          <div className="select-control">
            <AppIcon name="filter" className="app-icon-sm" />
            <select
              value={actionClassFilter}
              onChange={(event) => setActionClassFilter(event.target.value)}
              aria-label="Filter events by action class"
              data-testid="events-class-filter"
            >
              <option value="all">All classes</option>
              {ACTION_CLASS_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="select-control">
            <AppIcon name="filter" className="app-icon-sm" />
            <select
              value={actionTypeFilter}
              onChange={(event) => setActionTypeFilter(event.target.value)}
              aria-label="Filter events by action type"
              data-testid="events-type-filter"
            >
              <option value="all">All action types</option>
              {ACTION_TYPES.map((actionType) => (
                <option key={actionType} value={actionType}>
                  {actionTypeLabel(actionType)}
                </option>
              ))}
            </select>
          </div>
          <label className="input-with-icon table-filter-input events-agent-filter">
            <AppIcon name="user" className="app-icon-sm" />
            <input
              type="search"
              value={agentInput}
              onChange={(event) => setAgentInput(event.target.value)}
              placeholder="Agent id"
              aria-label="Filter events by agent id"
              data-testid="events-agent-filter"
            />
          </label>
          <label className="input-with-icon table-filter-input">
            <AppIcon name="search" className="app-icon-sm" />
            <input
              type="search"
              value={resourceInput}
              onChange={(event) => setResourceInput(event.target.value)}
              placeholder="Search resource text"
              aria-label="Search event resource text"
              data-testid="events-resource-filter"
            />
          </label>
          <span className="meta" data-testid="events-filter-count">
            {events.length} of {eventsTotal}
          </span>
        </div>
        {eventsError ? <p className="error">Live events query failed: {eventsError}</p> : null}
        <div className="table-wrap">
          <table data-testid="events-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Decision</th>
                <th>Class</th>
                <th>Profile</th>
                <th>PID</th>
                <th>Resource</th>
                <th>Reason</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.map((item) => {
                const modelCall = modelCalls.get(item.id) ?? null;
                const alreadyAllowed = item.effective_decision === "allow";
                const alreadyDenied = item.effective_decision === "deny";
                const quickRuleUnsupported = !supportsQuickRuleAction(item.action_type);
                const ruleAllowExists = hasRule(item, "allow", policyDoc);
                const ruleDenyExists = hasRule(item, "deny", policyDoc);
                const ruleApprovalExists = hasRule(item, "require_approval", policyDoc);
                const supportsApproval = QUICK_RULE_MCP_ACTIONS.has(item.action_type);
                const allowTitle = alreadyAllowed
                  ? "Event is already being allowed by the active policy"
                  : quickRuleUnsupported
                    ? `Quick rules do not support ${item.action_type} events`
                    : ruleAllowExists
                      ? "An allow rule already covers this resource"
                      : "Create rule from this event";
                const denyTitle = alreadyDenied
                  ? "Event is already being denied by the active policy"
                  : quickRuleUnsupported
                    ? `Quick rules do not support ${item.action_type} events`
                    : ruleDenyExists
                      ? "A deny rule already covers this resource"
                      : "Create rule from this event";
                const approvalTitle = supportsApproval
                  ? ruleApprovalExists
                    ? "A require_approval rule already covers this MCP tool"
                    : "Require operator approval for this MCP tool"
                  : `Quick rules do not support require_approval for ${item.action_type} events`;

                const informational = isInformational(item);
                return (
                  <tr
                    key={item.id}
                    className={eventRowClass(item)}
                    data-testid={`event-row-${item.id}`}
                  >
                    <td title={fmt(item.timestamp)}>{fmtTime(item.timestamp)}</td>
                    <td>
                      <span
                        className={
                          informational && item.effective_decision !== "deny"
                            ? "pill pill-info"
                            : statusBadge(item.effective_decision)
                        }
                      >
                        {decisionLabel(item)}
                      </span>
                    </td>
                    <td>
                      <span className="table-icon-label">
                        <AppIcon
                          name={actionClassIconName(item.action_class)}
                          className="app-icon-sm"
                        />
                        <span>{actionClassLabel(item.action_class)}</span>
                      </span>
                      <span className="event-action-type" title={item.action_type}>
                        {actionTypeLabel(item.action_type)}
                      </span>
                    </td>
                    <td>{item.profile}</td>
                    <td>{item.pid ?? "-"}</td>
                    <td className="mono event-resource" title={item.resource}>
                      {item.resource}
                      {modelCall ? (
                        <span
                          className="pill pill-model"
                          data-testid={`model-call-badge-${item.id}`}
                        >
                          <AppIcon name="transcript" className="app-icon-sm" />
                          <span>{modelCallLabel(modelCall)}</span>
                        </span>
                      ) : null}
                    </td>
                    <td>{item.reason}</td>
                    <td className="quick-rule-actions">
                      {item.effective_decision === "deny" ? (
                        <span className="quick-rule-hint">Create rule from this event</span>
                      ) : null}
                      <button
                        className="ghost"
                        title="Show every recorded field of this event"
                        data-testid={`event-details-${item.id}`}
                        onClick={() => setDetailsTarget(item)}
                      >
                        <span className="button-with-icon">
                          <AppIcon name="info" className="app-icon-sm" />
                          <span>Details</span>
                        </span>
                      </button>
                      {modelCall ? (
                        <button
                          className="ghost"
                          title={
                            hasCapturedContent(modelCall)
                              ? "Show the captured prompt and output for this model call"
                              : "Show what the gateway captured for this model call"
                          }
                          data-testid={`model-call-${item.id}`}
                          onClick={() => setModelCallTarget({ item, call: modelCall })}
                        >
                          <span className="button-with-icon">
                            <AppIcon name="transcript" className="app-icon-sm" />
                            <span>
                              {hasCapturedContent(modelCall) ? "Transcript" : "Model call"}
                            </span>
                          </span>
                        </button>
                      ) : null}
                      <button
                        className="ghost quick-allow"
                        title={allowTitle}
                        data-testid={`quick-allow-${item.id}`}
                        disabled={alreadyAllowed || ruleAllowExists || quickRuleUnsupported}
                        onClick={() => setQuickRuleTarget({ item, direction: "allow" })}
                      >
                        <span className="button-with-icon">
                          <AppIcon name="check" className="app-icon-sm" />
                          <span>Allow</span>
                        </span>
                      </button>
                      <button
                        className="ghost quick-deny"
                        title={denyTitle}
                        data-testid={`quick-deny-${item.id}`}
                        disabled={alreadyDenied || ruleDenyExists || quickRuleUnsupported}
                        onClick={() => setQuickRuleTarget({ item, direction: "deny" })}
                      >
                        <span className="button-with-icon">
                          <AppIcon name="close" className="app-icon-sm" />
                          <span>Block</span>
                        </span>
                      </button>
                      {supportsApproval ? (
                        <button
                          className="ghost"
                          title={approvalTitle}
                          data-testid={`quick-approve-${item.id}`}
                          disabled={ruleApprovalExists || quickRuleUnsupported}
                          onClick={() =>
                            setQuickRuleTarget({ item, direction: "require_approval" })
                          }
                        >
                          <span className="button-with-icon">
                            <AppIcon name="event" className="app-icon-sm" />
                            <span>Approval</span>
                          </span>
                        </button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
              {!events.length ? (
                <tr>
                  <td colSpan={8} className="empty">
                    {eventsLoading
                      ? "Loading events..."
                      : eventsTotal === 0 &&
                          (decisionFilter !== "all" ||
                            actionClassFilter !== "all" ||
                            actionTypeFilter !== "all" ||
                            agentFilter.trim() !== "" ||
                            resourceFilter.trim() !== "")
                        ? "No events match that filter."
                        : "No events yet."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {events.length > 0 && events.length < eventsTotal ? (
          <div className="events-load-older">
            <button
              type="button"
              className="ghost"
              onClick={() => void loadOlderEvents()}
              disabled={loadingOlder}
              data-testid="events-load-older"
            >
              {loadingOlder ? "Loading..." : "Load older events"}
            </button>
          </div>
        ) : null}
      </PanelCard>

      {detailsTarget ? (
        <EventDetailsModal item={detailsTarget} onClose={() => setDetailsTarget(null)} />
      ) : null}

      {quickRuleMessage ? (
        <div className="quick-rule-toast" data-testid="quick-rule-toast">
          <span className="button-with-icon">
            <AppIcon name="check" className="app-icon-sm" />
            <span>{quickRuleMessage}</span>
          </span>
          <button
            className="ghost icon-only-button"
            onClick={() => setQuickRuleMessage(null)}
            aria-label="Dismiss"
            title="Dismiss"
          >
            <AppIcon name="close" className="app-icon-sm" />
            <span className="sr-only">Dismiss</span>
          </button>
        </div>
      ) : null}

      {modelCallTarget ? (
        <ModelCallModal
          item={modelCallTarget.item}
          call={modelCallTarget.call}
          onClose={() => setModelCallTarget(null)}
        />
      ) : null}

      {quickRuleTarget ? (
        <QuickRuleModal
          target={quickRuleTarget}
          profileNames={profileNames}
          csrfToken={csrfToken}
          onClose={() => setQuickRuleTarget(null)}
          onApplied={(message) => {
            setQuickRuleTarget(null);
            setQuickRuleMessage(message);
            onPolicyChanged();
          }}
        />
      ) : null}
    </>
  );
});
