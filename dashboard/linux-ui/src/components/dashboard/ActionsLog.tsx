import { memo, useState } from "react";

import { AuthRequiredError } from "../../apiClient";
import type { DashboardActionItem } from "../../dashboardTypes";
import { fmt } from "../../dashboardUi";
import { actionsExportPath, downloadExport } from "../../downloads";
import { AppIcon } from "./AppIcon";

const EXPORT_RANGES: Array<{ value: string; label: string }> = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "all", label: "Everything retained" }
];

function outcomeClass(outcome: string | undefined): string {
  return outcome === "failure" ? "pill pill-deny" : "pill pill-allow";
}

export const ActionsLog = memo(function ActionsLog({
  actions,
  collapsed,
  onToggleCollapsed,
  error,
  onRetry,
  hasMore = false,
  loadingMore = false,
  onLoadMore
}: {
  actions: DashboardActionItem[];
  collapsed: boolean;
  onToggleCollapsed: () => void;
  /** If set, the panel shows a non-blocking error banner instead of an empty table. */
  error?: string | null;
  /** Called when the user clicks "Retry" in the error banner. */
  onRetry?: () => void;
  /** True when older actions exist beyond the loaded pages. */
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
}) {
  const [exportRange, setExportRange] = useState("7d");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  async function handleExport() {
    setExporting(true);
    setExportError(null);
    try {
      await downloadExport(actionsExportPath(exportRange), "dashboard-actions.csv");
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setExportError((err as Error).message);
      }
    } finally {
      setExporting(false);
    }
  }

  return (
    <article className="card panel policy-actions-panel" data-testid="policy-actions-panel">
      <div className="card-header card-header-actions">
        <div className="card-header-copy">
          <h3 className="heading-with-icon">
            <AppIcon name="event" className="app-icon-lg" />
            <span>Action Audit Trail</span>
          </h3>
          <p>Operator actions and rejected sign-ins, with source address and outcome</p>
        </div>
        <div className="card-header-controls">
          <div className="select-control">
            <select
              value={exportRange}
              onChange={(event) => setExportRange(event.target.value)}
              aria-label="Action export time range"
              data-testid="actions-export-range"
            >
              {EXPORT_RANGES.map((range) => (
                <option key={range.value} value={range.value}>
                  {range.label}
                </option>
              ))}
            </select>
          </div>
          <button
            className="ghost icon-only-button"
            type="button"
            onClick={() => void handleExport()}
            disabled={exporting}
            aria-label="Export action audit trail as CSV"
            title="Export action audit trail as CSV"
            data-testid="actions-export-button"
          >
            <AppIcon name="download" className="app-icon-sm" />
            <span className="sr-only">Export action audit trail as CSV</span>
          </button>
          <button
            className="ghost icon-only-button"
            type="button"
            onClick={onToggleCollapsed}
            aria-expanded={!collapsed}
            aria-controls="actions-log-content"
            aria-label={collapsed ? "Expand action audit trail" : "Collapse action audit trail"}
            title={collapsed ? "Expand action audit trail" : "Collapse action audit trail"}
            data-testid="actions-collapse-button"
          >
            <AppIcon name="chevron" className="app-icon-chevron" />
            <span className="sr-only">
              {collapsed ? "Expand action audit trail" : "Collapse action audit trail"}
            </span>
          </button>
        </div>
      </div>
      <div id="actions-log-content" hidden={collapsed}>
        {error ? (
          <div className="panel-fetch-error" role="alert" data-testid="actions-fetch-error">
            <span>Action history failed to load: {error}</span>
            {onRetry ? (
              <button
                type="button"
                className="ghost"
                onClick={onRetry}
                data-testid="actions-retry-button"
              >
                Retry
              </button>
            ) : null}
          </div>
        ) : null}
        {exportError ? (
          <div className="panel-fetch-error" role="alert" data-testid="actions-export-error">
            <span>Action export failed: {exportError}</span>
          </div>
        ) : null}
        <div className="table-wrap">
          <table data-testid="actions-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Source</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((action) => (
                <tr key={action.id} data-testid={`action-${action.id}`}>
                  <td>{fmt(action.ts)}</td>
                  <td>
                    <span className="pill">{action.action}</span>
                  </td>
                  <td>
                    <span className={outcomeClass(action.outcome)}>
                      {action.outcome ?? "success"}
                    </span>
                  </td>
                  <td>{action.actor}</td>
                  <td className="mono" title={action.user_agent ?? undefined}>
                    {action.source_ip ?? "-"}
                  </td>
                  <td className="mono">{action.details}</td>
                </tr>
              ))}
              {!actions.length ? (
                <tr>
                  <td colSpan={6} className="empty">
                    No actions recorded yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {hasMore && onLoadMore ? (
          <div className="events-load-older">
            <button
              type="button"
              className="ghost"
              onClick={onLoadMore}
              disabled={loadingMore}
              data-testid="actions-load-more"
            >
              {loadingMore ? "Loading..." : "Load older actions"}
            </button>
          </div>
        ) : null}
      </div>
      {collapsed ? (
        <p className="meta collapsible-summary" data-testid="actions-collapsed-summary">
          {actions.length ? `${actions.length} actions hidden.` : "Section collapsed."}
        </p>
      ) : null}
    </article>
  );
});
