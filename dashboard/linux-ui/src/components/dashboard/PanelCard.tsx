import type { ReactNode } from "react";

type PanelCardProps = {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
  testId?: string;
};

export function PanelCard({
  title,
  subtitle,
  actions,
  className,
  children,
  testId
}: PanelCardProps) {
  const panelClassName = className ? `card panel panel-card ${className}` : "card panel panel-card";

  return (
    <section className={panelClassName} data-testid={testId}>
      <div className="card-header">
        <div className="card-header-copy">
          <h3>{title}</h3>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {actions ? <div className="card-header-controls">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
