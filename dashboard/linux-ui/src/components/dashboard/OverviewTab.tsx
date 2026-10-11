import { memo, useMemo } from "react";
import type { CoverageStatus, StatsResponse, StatusSummary } from "../../dashboardTypes";
import { AppIcon, type AppIconName } from "./AppIcon";
import { MetricCard, type Tone } from "./MetricCard";
import { PanelCard } from "./PanelCard";
import type { DashboardTabKey } from "./TabRail";
import { ChartLegend, ThroughputChart } from "./ThroughputChart";

const COVERAGE_CLASS_ORDER = ["file", "proc", "process", "net", "network", "url", "mcp"] as const;
const DAY_MS = 24 * 60 * 60 * 1000;

function pluralize(count: number, singular: string, plural: string): string {
  return count === 1 ? singular : plural;
}

function formatBytes(bytes: number | undefined): string {
  if (bytes == null || !Number.isFinite(bytes)) {
    return "unknown";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatCoverageClassLabel(actionClass: string): string {
  switch (actionClass.toLowerCase()) {
    case "file":
      return "File";
    case "proc":
      return "Process";
    case "net":
      return "Network";
    case "url":
      return "URL";
    case "mcp":
      return "MCP";
    default:
      return actionClass.replace(/[_-]+/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
  }
}

const ACTION_PREFIXES: Array<{ prefix: string; label: string; icon: AppIconName }> = [
  { prefix: "FILE_", label: "File", icon: "file" },
  { prefix: "PROC_", label: "Process", icon: "terminal" },
  { prefix: "EXEC_", label: "Process", icon: "terminal" },
  { prefix: "NET_", label: "Network", icon: "globe" },
  { prefix: "URL_", label: "URL", icon: "link" },
  { prefix: "MCP_", label: "MCP", icon: "box" }
];

// Label coverage chips from the action type itself (e.g. NET_CONNECT -> "Network connect"),
// falling back to the reported class, since daemons report classes as "net" or "network".
function describeCoverageAction(actionType: string, actionClass: string) {
  const upper = actionType.toUpperCase();
  const match = ACTION_PREFIXES.find((entry) => upper.startsWith(entry.prefix));
  if (match) {
    const rest = upper.slice(match.prefix.length).replace(/_/g, " ").toLowerCase();
    return { label: `${match.label} ${rest}`.trim(), icon: match.icon };
  }
  return {
    label: `${formatCoverageClassLabel(actionClass)} ${actionType.replace(/_/g, " ").toLowerCase()}`,
    icon: "info" as AppIconName
  };
}

function buildCoverageChips(entries: CoverageStatus[]) {
  const rank = (actionClass: string) => {
    const index = COVERAGE_CLASS_ORDER.indexOf(
      actionClass as (typeof COVERAGE_CLASS_ORDER)[number]
    );
    return index === -1 ? COVERAGE_CLASS_ORDER.length : index;
  };
  return [...entries]
    .sort(
      (left, right) =>
        rank(left.action_class) - rank(right.action_class) ||
        left.action_type.localeCompare(right.action_type)
    )
    .map((entry) => ({
      key: entry.action_type,
      title: `${entry.action_type} · ${entry.backend}`,
      ...describeCoverageAction(entry.action_type, entry.action_class)
    }));
}

function splitResource(resource: string): { kind: string; target: string } {
  const match = /^([a-z]+):(.*)$/i.exec(resource);
  return match ? { kind: match[1], target: match[2] } : { kind: "", target: resource };
}

type AttentionItem = {
  key: string;
  tone: Tone;
  icon: AppIconName;
  title: string;
  detail: string;
  action?: { label: string; tab: DashboardTabKey };
};

function buildAttentionItems(
  status: StatusSummary | null,
  stats: StatsResponse | null
): AttentionItem[] {
  if (!status) {
    return [];
  }
  const items: AttentionItem[] = [];
  if (!status.kernel_ready) {
    items.push({
      key: "kernel",
      tone: "danger",
      icon: "alert",
      title: "Kernel backend is not ready",
      detail: `${status.backend_mode} · enforcement results may be incomplete`,
      action: { label: "Coverage", tab: "enrollment" }
    });
  }
  if (status.pending_mcp_approvals > 0) {
    items.push({
      key: "approvals",
      tone: "warning",
      icon: "approvals",
      title: `${status.pending_mcp_approvals} MCP ${pluralize(status.pending_mcp_approvals, "approval", "approvals")} waiting`,
      detail: "Agents are blocked until an operator decides",
      action: { label: "Review", tab: "approvals" }
    });
  }
  if (status.url_gateway_enabled && status.url_gateway_error) {
    items.push({
      key: "gateway",
      tone: "danger",
      icon: "link",
      title: "URL gateway reported an error",
      detail: status.url_gateway_error
    });
  }
  if (status.dashboard_error) {
    items.push({
      key: "dashboard",
      tone: "danger",
      icon: "alert",
      title: "Dashboard reported an error",
      detail: status.dashboard_error
    });
  }
  if (status.enrollment_sync_error) {
    items.push({
      key: "enrollment-sync",
      tone: "danger",
      icon: "enrollment",
      title: "Enrollment sync failed",
      detail: status.enrollment_sync_error,
      action: { label: "Enrollments", tab: "enrollment" }
    });
  }
  if (status.events_dropped_queue_total > 0) {
    items.push({
      key: "dropped",
      tone: "warning",
      icon: "activity",
      title: `${status.events_dropped_queue_total.toLocaleString()} events dropped`,
      detail: `Low-priority queue overflow · backlog ${status.ingest_backlog_len}`
    });
  }
  const cert = status.tls_cert_info;
  if (cert) {
    const daysLeft = Math.floor((new Date(cert.expires_at).getTime() - Date.now()) / DAY_MS);
    if (Number.isFinite(daysLeft) && daysLeft <= 30) {
      items.push({
        key: "tls",
        tone: daysLeft <= 7 ? "danger" : "info",
        icon: "lock",
        title:
          daysLeft < 0
            ? "Dashboard certificate has expired"
            : `Dashboard certificate expires in ${daysLeft} ${pluralize(daysLeft, "day", "days")}`,
        detail: cert.cert_file,
        action: { label: "Rotate", tab: "settings" }
      });
    } else if (cert.is_self_signed) {
      items.push({
        key: "tls-self-signed",
        tone: "info",
        icon: "lock",
        title: "Dashboard uses a self-signed certificate",
        detail: "Browsers will warn until a trusted certificate is installed",
        action: { label: "Settings", tab: "settings" }
      });
    }
  }
  const hottest = stats?.top_blocked_resources[0];
  if (hottest && hottest.count >= 10) {
    items.push({
      key: "hotspot",
      tone: "danger",
      icon: "policy",
      title: `Repeated denies on ${splitResource(hottest.resource).target}`,
      detail: `${hottest.count} denies in the current window`,
      action: { label: "Investigate", tab: "events" }
    });
  }
  return items;
}

/** Events lost before they were recorded, summed across every loss counter. */
function telemetryLossTotal(status: StatusSummary): number {
  return (
    (status.events_dropped_ringbuf_total ?? 0) +
    (status.kernel_events_rate_limited_total ?? 0) +
    (status.kernel_deny_events_dropped_total ?? 0) +
    (status.apparmor_records_lost_total ?? 0) +
    status.events_dropped_queue_total
  );
}

type HealthRow = {
  key: string;
  testId: string;
  label: string;
  value: string;
  detail: string;
  tone: Tone;
};

function buildHealthRows(status: StatusSummary | null): HealthRow[] {
  if (!status) {
    return [];
  }
  return [
    {
      key: "apparmor",
      testId: "metric-apparmor",
      label: "AppArmor",
      value: status.apparmor_enabled ? "Enabled" : "Disabled",
      detail: status.apparmor_parser_present ? "Parser present" : "Parser missing",
      tone: status.apparmor_enabled ? "success" : "warning"
    },
    {
      key: "gateway",
      testId: "metric-url-gateway",
      label: "URL gateway",
      value: status.url_gateway_ready ? "Ready" : "Degraded",
      detail:
        status.url_gateway_error ||
        status.url_gateway_http_proxy ||
        status.url_gateway_https_proxy ||
        "Disabled",
      tone: status.url_gateway_ready ? "success" : status.url_gateway_enabled ? "danger" : "neutral"
    },
    {
      key: "dashboard",
      testId: "metric-dashboard",
      label: "Dashboard",
      value: status.dashboard_ready ? "Ready" : "Degraded",
      detail: `Schema v${status.dashboard_schema_version} · ${formatBytes(status.dashboard_sqlite_bytes)}`,
      tone: status.dashboard_ready ? "success" : "danger"
    },
    {
      key: "ingest",
      testId: "metric-events-ingested",
      label: "Event pipeline",
      value: status.events_ingested_total.toLocaleString(),
      detail: `ingested · backlog ${status.ingest_backlog_len}`,
      tone: "success"
    },
    {
      key: "dropped",
      testId: "metric-events-dropped",
      label: "Dropped events",
      value: status.events_dropped_queue_total.toLocaleString(),
      detail: "Low-priority queue overflow",
      tone: status.events_dropped_queue_total > 0 ? "warning" : "success"
    },
    {
      key: "telemetry-loss",
      testId: "metric-telemetry-loss",
      label: "Telemetry loss",
      value: telemetryLossTotal(status).toLocaleString(),
      detail: `ring buffer ${status.events_dropped_ringbuf_total ?? 0} · rate-limited ${status.kernel_events_rate_limited_total ?? 0} · deny events ${status.kernel_deny_events_dropped_total ?? 0} · AppArmor ${status.apparmor_records_lost_total ?? 0}`,
      tone: telemetryLossTotal(status) > 0 ? "warning" : "success"
    },
    {
      key: "audit",
      testId: "metric-audit-log",
      label: "Audit log",
      value:
        (status.audit_write_failures_total ?? 0) > 0
          ? `${(status.audit_write_failures_total ?? 0).toLocaleString()} write failures`
          : "Writing",
      detail: `mirror failures ${status.audit_mirror_failures_total ?? 0} · action trail failures ${status.dashboard_action_record_failures_total ?? 0}`,
      tone: (status.audit_write_failures_total ?? 0) > 0 ? "danger" : "success"
    },
    {
      key: "auth-failures",
      testId: "metric-auth-failures",
      label: "Sign-in failures",
      value: (status.auth_failures_total ?? 0).toLocaleString(),
      detail: "failed logins, lockouts and rejected CSRF checks since start",
      tone: (status.auth_failures_total ?? 0) > 0 ? "warning" : "neutral"
    },
    {
      key: "unenrolled",
      testId: "metric-unenrolled-suppressed",
      label: "Unenrolled activity",
      value: status.unenrolled_events_suppressed_total.toLocaleString(),
      detail: status.enrollment_sync_error || "suppressed · kernel map sync healthy",
      tone: status.enrollment_sync_error ? "danger" : "neutral"
    },
    {
      key: "sessions",
      testId: "metric-sessions",
      label: "Interactive load",
      value: `${status.active_dashboard_sessions}`,
      detail: `sessions · ${status.active_sse_clients} SSE · ${status.active_mcp_sessions} MCP`,
      tone: "neutral"
    }
  ];
}

export const OverviewTab = memo(function OverviewTab({
  status,
  statusError,
  stats,
  onNavigate
}: {
  status: StatusSummary | null;
  statusError: string | null;
  stats: StatsResponse | null;
  onNavigate: (tab: DashboardTabKey) => void;
}) {
  const totals = useMemo(
    () => ({
      allow: stats?.buckets.reduce((acc, item) => acc + item.allow, 0) ?? 0,
      deny: stats?.buckets.reduce((acc, item) => acc + item.deny, 0) ?? 0,
      observe: stats?.buckets.reduce((acc, item) => acc + item.observe, 0) ?? 0
    }),
    [stats]
  );
  const decisionsTotal = totals.allow + totals.deny + totals.observe;
  const attention = useMemo(() => buildAttentionItems(status, stats), [status, stats]);
  const health = useMemo(() => buildHealthRows(status), [status]);
  const coverageSections = useMemo(
    () =>
      [
        { key: "enforced", label: "Enforced", tone: "success" },
        { key: "observe_only", label: "Observe only", tone: "warning" },
        { key: "unavailable", label: "Unavailable", tone: "neutral" }
      ].map((section) => {
        const entries = status?.coverage.filter((entry) => entry.status === section.key) ?? [];
        return { ...section, count: entries.length, chips: buildCoverageChips(entries) };
      }),
    [status?.coverage]
  );
  const topBlocked = stats?.top_blocked_resources ?? [];
  const topBlockedMax = Math.max(1, ...topBlocked.map((item) => item.count));
  const pending = status?.pending_mcp_approvals ?? 0;
  const degradedReasons = status?.degraded_reasons ?? [];

  return (
    <section className="overview" data-testid="overview-grid">
      {statusError ? (
        <div className="callout callout-danger" role="alert">
          <AppIcon name="alert" className="app-icon-sm" />
          <span>Status refresh failed: {statusError}</span>
        </div>
      ) : null}

      {degradedReasons.length ? (
        <div
          className="callout callout-warning degraded-callout"
          role="alert"
          data-testid="degraded-callout"
        >
          <AppIcon name="warning" className="app-icon-sm" />
          <div>
            <strong>Mercury is degraded: enforcement or recording may be incomplete.</strong>
            <ul className="degraded-reasons">
              {degradedReasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      <div className="kpi-row">
        <MetricCard
          label="Daemon"
          icon="activity"
          value={status?.daemon_up ? "Online" : status ? "Offline" : "…"}
          meta={status ? `Policy ${status.policy_version}` : "Waiting for status…"}
          badge={
            status
              ? !status.daemon_up
                ? { tone: "danger", label: "Down" }
                : degradedReasons.length
                  ? { tone: "warning", label: "Degraded" }
                  : { tone: "success", label: "Healthy" }
              : null
          }
          testId="metric-daemon"
        />
        <MetricCard
          label="Kernel backend"
          icon="shield"
          value={status?.backend_mode ?? "unknown"}
          meta={`Program ${status?.kernel_program_version ?? "unknown"} · ${status?.auto_enroll_active_rules ?? 0} auto-enroll rules`}
          badge={
            status
              ? status.kernel_ready
                ? { tone: "accent", label: "Enforcing" }
                : { tone: "warning", label: "Not ready" }
              : null
          }
          testId="metric-kernel-backend"
        />
        <MetricCard
          label="Decisions"
          icon="event"
          value={decisionsTotal.toLocaleString()}
          meta={`${totals.allow.toLocaleString()} allow · ${totals.deny.toLocaleString()} deny · ${totals.observe.toLocaleString()} observe`}
          badge={
            totals.deny > 0
              ? {
                  tone: "danger",
                  label: `${Math.round((totals.deny / Math.max(decisionsTotal, 1)) * 100)}% denied`
                }
              : null
          }
          testId="metric-decisions"
        />
        <MetricCard
          label="Approvals"
          icon="approvals"
          value={pending}
          meta={pending ? "Waiting for an operator decision" : "Nothing waiting"}
          badge={pending ? { tone: "warning", label: "Action needed" } : null}
          testId="metric-approvals"
        />
      </div>

      <div className="overview-row overview-row-wide">
        <article className="card panel trend-card" data-testid="decision-throughput-panel">
          <div className="card-header">
            <div className="card-header-copy">
              <h3>Decision throughput</h3>
              <p>Allow, deny and observe decisions per minute</p>
            </div>
          </div>
          <ChartLegend totals={totals} />
          <ThroughputChart buckets={stats?.buckets ?? []} />
        </article>

        <PanelCard
          title="Needs attention"
          actions={
            attention.length ? (
              <span className="pill pill-warning">{attention.length} open</span>
            ) : (
              <span className="pill pill-success">All clear</span>
            )
          }
          className="attention-card"
          testId="needs-attention-panel"
        >
          {attention.length ? (
            <ul className="attention-list">
              {attention.map((item) => (
                <li key={item.key} className="attention-item">
                  <span className={`icon-tile icon-tile-${item.tone}`} aria-hidden="true">
                    <AppIcon name={item.icon} className="app-icon-sm" />
                  </span>
                  <div className="attention-copy">
                    <p className="attention-title">{item.title}</p>
                    <p className="attention-detail" title={item.detail}>
                      {item.detail}
                    </p>
                  </div>
                  {item.action ? (
                    <button
                      type="button"
                      className="ghost btn-sm"
                      onClick={() => item.action && onNavigate(item.action.tab)}
                    >
                      {item.action.label}
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">
              <span className="icon-tile icon-tile-success" aria-hidden="true">
                <AppIcon name="check" className="app-icon-sm" />
              </span>
              <p>Nothing needs attention right now.</p>
            </div>
          )}
        </PanelCard>
      </div>

      <div className="overview-row overview-row-wide">
        <PanelCard
          title="Top blocked resources"
          subtitle="Most frequent deny targets"
          actions={
            <button type="button" className="ghost btn-sm" onClick={() => onNavigate("events")}>
              View in events
            </button>
          }
          className="top-blocked"
          testId="top-blocked-panel"
        >
          {topBlocked.length ? (
            <ul className="bar-list">
              {topBlocked.map((item) => {
                const { kind, target } = splitResource(item.resource);
                return (
                  <li key={item.resource} className="bar-list-item">
                    <div className="bar-list-top">
                      {kind ? <span className="kind-chip">{kind}</span> : null}
                      <code className="bar-list-target" title={item.resource}>
                        {target}
                      </code>
                      <strong>{item.count}</strong>
                    </div>
                    <div className="bar-track">
                      <span
                        className="bar-fill"
                        style={{ width: `${Math.max(4, (item.count / topBlockedMax) * 100)}%` }}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="empty-state">
              <span className="icon-tile icon-tile-success" aria-hidden="true">
                <AppIcon name="check" className="app-icon-sm" />
              </span>
              <p>No blocked actions yet.</p>
            </div>
          )}
        </PanelCard>

        <PanelCard
          title="System health"
          subtitle="Components reported by mercuryd"
          className="health-card"
          testId="system-health-panel"
        >
          <ul className="health-list">
            {health.map((row) => (
              <li key={row.key} className="health-row" data-testid={row.testId}>
                <span className={`status-dot status-dot-${row.tone}`} aria-hidden="true" />
                <span className="health-label">{row.label}</span>
                <span className="health-detail" title={row.detail}>
                  {row.detail}
                </span>
                <strong className="health-value">{row.value}</strong>
              </li>
            ))}
            {!health.length ? <li className="empty">Waiting for status…</li> : null}
          </ul>
        </PanelCard>
      </div>

      <PanelCard
        title="Enforcement coverage"
        subtitle="Which action classes the kernel backend can enforce on this host"
        className="coverage-summary-card"
        testId="coverage-panel"
      >
        <div className="coverage-matrix">
          {coverageSections.map((section) => (
            <section className="coverage-section" key={section.key}>
              <div className="coverage-section-title">
                <span className={`pill pill-${section.tone}`}>{section.label}</span>
                <span className="coverage-section-count">
                  {section.count} {pluralize(section.count, "action", "actions")}
                </span>
              </div>
              {section.chips.length ? (
                <div className="coverage-chip-list">
                  {section.chips.map((chip) => (
                    <span className="coverage-chip" key={chip.key} title={chip.title}>
                      <AppIcon name={chip.icon} className="app-icon-sm" />
                      {chip.label}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="coverage-empty">None reported.</p>
              )}
            </section>
          ))}
        </div>
      </PanelCard>
    </section>
  );
});
