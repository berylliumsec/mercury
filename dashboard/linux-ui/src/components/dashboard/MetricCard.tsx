import type { ReactNode } from "react";
import { AppIcon, type AppIconName } from "./AppIcon";

export type Tone = "success" | "danger" | "warning" | "info" | "neutral" | "accent";

type MetricCardProps = {
  label: string;
  value: ReactNode;
  meta: ReactNode;
  testId?: string;
  icon?: AppIconName;
  badge?: { tone: Tone; label: string } | null;
};

export function MetricCard({ label, value, meta, testId, icon, badge }: MetricCardProps) {
  return (
    <article className="card metric-card" data-testid={testId}>
      <div className="metric-card-top">
        {icon ? (
          <span className="icon-tile" aria-hidden="true">
            <AppIcon name={icon} className="app-icon-sm" />
          </span>
        ) : null}
        <p className="label">{label}</p>
        {badge ? <span className={`pill pill-${badge.tone}`}>{badge.label}</span> : null}
      </div>
      <p className="metric-value">{value}</p>
      <p className="meta">{meta}</p>
    </article>
  );
}
