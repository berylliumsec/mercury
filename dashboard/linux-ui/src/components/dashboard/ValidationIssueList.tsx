import { memo } from "react";

import { AppIcon } from "./AppIcon";

export const ValidationIssueList = memo(function ValidationIssueList({
  issues,
  tone,
  title
}: {
  issues: string[];
  tone: "warn" | "error";
  title: string;
}) {
  if (!issues.length) {
    return null;
  }

  return (
    <div className={`validation-issues validation-issues-${tone}`}>
      <p className={tone}>
        {title} ({issues.length})
      </p>
      <ul>
        {issues.map((issue) => (
          <li key={issue}>
            <span className="validation-issue-icon" aria-hidden="true">
              <AppIcon name={tone === "error" ? "warning" : "info"} className="app-icon-sm" />
            </span>
            <span>{issue}</span>
          </li>
        ))}
      </ul>
    </div>
  );
});
