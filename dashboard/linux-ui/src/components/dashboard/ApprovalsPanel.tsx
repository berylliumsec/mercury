import { memo, useEffect, useState } from "react";

import { AuthRequiredError, api } from "../../apiClient";
import type { McpApproval } from "../../dashboardTypes";
import { fmt } from "../../dashboardUi";
import { AppIcon } from "./AppIcon";
import { PanelCard } from "./PanelCard";

type ApprovalsPanelProps = {
  csrfToken: string;
  refreshNonce: number;
  onResolved: () => void;
};

export const ApprovalsPanel = memo(function ApprovalsPanel({
  csrfToken,
  refreshNonce,
  onResolved
}: ApprovalsPanelProps) {
  const [items, setItems] = useState<McpApproval[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyRequestId, setBusyRequestId] = useState<string | null>(null);

  async function refreshApprovals() {
    setLoading(true);
    try {
      const response = await api<McpApproval[]>("/mcp/approvals");
      setItems(response);
      setError(null);
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  async function submitDecision(requestId: string, decision: "approve" | "deny") {
    setBusyRequestId(requestId);
    try {
      await api<{ ok: boolean }>(`/mcp/approvals/${requestId}/${decision}`, {
        method: "POST",
        headers: { "x-csrf-token": csrfToken }
      });
      await refreshApprovals();
      onResolved();
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setError((err as Error).message);
      }
    } finally {
      setBusyRequestId(null);
    }
  }

  useEffect(() => {
    void refreshApprovals();
  }, [refreshNonce]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      void refreshApprovals();
    }, 2000);
    return () => window.clearInterval(interval);
  }, []);

  return (
    <PanelCard
      title={
        <span className="heading-with-icon">
          <AppIcon name="event" className="app-icon-lg" />
          <span>MCP Approvals</span>
        </span>
      }
      subtitle="Pending MCP tool calls and resource reads waiting for an operator decision."
      testId="mcp-approvals-panel"
    >
      <div className="events-toolbar">
        <span className="meta">{loading ? "refreshing" : `${items.length} pending`}</span>
        <button
          className="ghost icon-only-button"
          onClick={() => void refreshApprovals()}
          aria-label="Refresh approvals"
          title="Refresh approvals"
        >
          <AppIcon name="refresh" className="app-icon-sm" />
          <span className="sr-only">Refresh approvals</span>
        </button>
      </div>
      {error ? <p className="error">Approval query failed: {error}</p> : null}
      {!items.length ? (
        <p className="meta">No pending MCP approvals.</p>
      ) : (
        <div className="stack-list">
          {items.map((item) => {
            const busy = busyRequestId === item.request_id;
            return (
              <article
                key={item.request_id}
                data-testid={`approval-item-${item.request_id}`}
                className="card panel"
              >
                <div className="card-header">
                  <div>
                    <h3>
                      {item.kind === "resource"
                        ? `${item.server_id} / ${item.resource_uri ?? item.tool_call_id}`
                        : `${item.server_id} / ${item.tool_name}`}
                    </h3>
                    <p>
                      {item.profile} · {item.kind} · expires {fmt(item.expires_at)}
                    </p>
                  </div>
                  <span className="pill pill-observe">{item.transport}</span>
                </div>
                <div className="stack-list">
                  <p className="mono">{item.arguments_summary ?? item.arguments_sha256}</p>
                  <details>
                    <summary>{item.kind === "resource" ? "Read payload" : "Arguments"}</summary>
                    <pre className="code-block">{item.arguments_json}</pre>
                  </details>
                  <div className="quick-rule-actions">
                    <button
                      data-testid={`approve-${item.request_id}`}
                      className="primary"
                      disabled={busy}
                      onClick={() => void submitDecision(item.request_id, "approve")}
                    >
                      <span className="button-with-icon">
                        <AppIcon name="check" className="app-icon-sm" />
                        <span>{busy ? "Working..." : "Approve"}</span>
                      </span>
                    </button>
                    <button
                      data-testid={`deny-${item.request_id}`}
                      className="danger"
                      disabled={busy}
                      onClick={() => void submitDecision(item.request_id, "deny")}
                    >
                      <span className="button-with-icon">
                        <AppIcon name="close" className="app-icon-sm" />
                        <span>{busy ? "Working..." : "Deny"}</span>
                      </span>
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </PanelCard>
  );
});
