import type { DashboardActionItem } from "./dashboardTypes";
import { csvEscape } from "./dashboardUi";

/** Same columns as the daemon's /actions/export (used by the static demo). */
export function buildActionsCsv(actions: DashboardActionItem[]): string {
  const header = [
    "id",
    "time",
    "action",
    "outcome",
    "actor",
    "source_ip",
    "user_agent",
    "session_id_hash",
    "details"
  ];
  const rows = actions.map((item) =>
    [
      item.id,
      item.ts,
      item.action,
      item.outcome ?? "success",
      item.actor,
      item.source_ip,
      item.user_agent,
      item.session_id_hash,
      item.details
    ]
      .map(csvEscape)
      .join(",")
  );
  return [header.join(","), ...rows].join("\n");
}
