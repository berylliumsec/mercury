import { memo, useEffect, useMemo, useState } from "react";

import { AuthRequiredError, api } from "../../apiClient";
import type { Enrollment } from "../../dashboardTypes";
import { AppIcon } from "./AppIcon";
import { PanelCard } from "./PanelCard";

function enrollmentMatches(entry: Enrollment, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  return [
    String(entry.pid),
    entry.profile,
    entry.source,
    entry.mode,
    String(entry.uid),
    entry.cgroup_id,
    entry.agent_id
  ].some((field) => field.toLowerCase().includes(normalized));
}

export const EnrollmentsPanel = memo(function EnrollmentsPanel({
  refreshNonce
}: {
  refreshNonce: number;
}) {
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function refreshEnrollments() {
      setLoading(true);
      try {
        const response = await api<Enrollment[]>("/enrollments");
        if (!cancelled) {
          setEnrollments(response);
          setError(null);
        }
      } catch (err) {
        if (!cancelled && !(err instanceof AuthRequiredError)) {
          setError((err as Error).message);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void refreshEnrollments();
    const poll = window.setInterval(() => {
      void refreshEnrollments();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(poll);
    };
  }, [refreshNonce]);

  const filteredEnrollments = useMemo(
    () => enrollments.filter((entry) => enrollmentMatches(entry, query)),
    [enrollments, query]
  );

  return (
    <PanelCard
      title={
        <span className="heading-with-icon">
          <AppIcon name="enrollment" className="app-icon-lg" />
          <span>Active Enrollments</span>
        </span>
      }
      subtitle="Hybrid mercury-run and auto-enrolled process coverage"
      className="enrollment-panel"
      testId="enrollments-panel"
    >
      <div className="panel-toolbar">
        <label className="input-with-icon table-filter-input">
          <AppIcon name="search" className="app-icon-sm" />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by profile, PID, UID, cgroup, or agent"
            aria-label="Filter enrollments"
            data-testid="enrollments-filter-input"
          />
        </label>
        <span className="meta" data-testid="enrollments-filter-count">
          {filteredEnrollments.length} of {enrollments.length}
        </span>
      </div>
      {error ? <p className="error">Enrollment refresh failed: {error}</p> : null}
      <div className="table-wrap">
        <table data-testid="enrollments-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Profile</th>
              <th>Source</th>
              <th>Mode</th>
              <th>UID</th>
              <th>Cgroup</th>
            </tr>
          </thead>
          <tbody>
            {filteredEnrollments.map((entry) => (
              <tr key={`${entry.pid}-${entry.agent_id}`}>
                <td className="mono">{entry.pid}</td>
                <td className="mono">{entry.profile}</td>
                <td>
                  <span
                    className={
                      entry.source === "mercury-run" ? "pill pill-accent" : "pill pill-neutral"
                    }
                  >
                    {entry.source}
                  </span>
                </td>
                <td>
                  <span
                    className={entry.mode === "enforce" ? "pill pill-success" : "pill pill-warning"}
                  >
                    {entry.mode}
                  </span>
                </td>
                <td className="mono">{entry.uid}</td>
                <td className="mono">{entry.cgroup_id}</td>
              </tr>
            ))}
            {!filteredEnrollments.length ? (
              <tr>
                <td colSpan={6} className="empty">
                  {loading
                    ? "Loading enrollments..."
                    : query
                      ? "No enrollments match that filter."
                      : "No active enrollments."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </PanelCard>
  );
});
