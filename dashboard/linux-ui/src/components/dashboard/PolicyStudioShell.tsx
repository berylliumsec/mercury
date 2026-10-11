import { memo, type ReactNode } from "react";

export type PolicyStatusTone = "synced" | "dirty" | "validated";

const STATUS_TONE: Record<PolicyStatusTone, "success" | "warning" | "accent"> = {
  synced: "success",
  dirty: "warning",
  validated: "accent"
};

type PolicyStudioShellProps = {
  statusLabel: string;
  statusTone: PolicyStatusTone;
  subtitle: string;
  statusMeta?: ReactNode;
  actionBar: ReactNode;
  feedback?: ReactNode;
  validation?: ReactNode;
  defaultsPanel: ReactNode;
  profileToolbar: ReactNode;
  reviewRail: ReactNode;
  children: ReactNode;
};

export const PolicyStudioShell = memo(function PolicyStudioShell({
  statusLabel,
  statusTone,
  subtitle,
  statusMeta,
  actionBar,
  feedback,
  validation,
  defaultsPanel,
  profileToolbar,
  reviewRail,
  children
}: PolicyStudioShellProps) {
  const tone = STATUS_TONE[statusTone];

  return (
    <section className="policy-grid policy-studio-shell">
      <article className="policy-studio-main" data-testid="policy-editor-panel">
        <div className="card policy-studio-sticky draft-bar">
          <span className={`pill pill-${tone} policy-status-pill policy-status-pill-${statusTone}`}>
            {statusLabel}
          </span>
          <div className="draft-bar-copy">
            {statusMeta ? <div className="policy-studio-meta-copy">{statusMeta}</div> : null}
            <p className="meta">{subtitle}</p>
          </div>
          {actionBar}
        </div>
        {feedback ? <div className="policy-feedback">{feedback}</div> : null}
        {validation ? <div className="policy-validation-wrap">{validation}</div> : null}
        {defaultsPanel}
        {profileToolbar}
        <div className="policy-rule-stack">{children}</div>
      </article>

      {reviewRail}
    </section>
  );
});
