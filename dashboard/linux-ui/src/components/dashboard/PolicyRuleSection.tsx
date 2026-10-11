import type { ReactNode } from "react";

import { AppIcon, type AppIconName } from "./AppIcon";

type PolicyRuleSectionProps = {
  title: string;
  iconName?: AppIconName;
  count: number;
  summary: string;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  addLabel: string;
  onAdd: () => void;
  children: ReactNode;
  testId?: string;
};

export function PolicyRuleSection({
  title,
  iconName,
  count,
  summary,
  collapsed,
  onToggleCollapsed,
  addLabel,
  onAdd,
  children,
  testId
}: PolicyRuleSectionProps) {
  const contentId = testId ? `${testId}-content` : undefined;

  return (
    <section
      className={collapsed ? "rule-section rule-section-collapsed" : "rule-section"}
      data-testid={testId}
    >
      <div className="rule-section-header">
        <button
          type="button"
          className="rule-section-toggle"
          aria-expanded={!collapsed}
          aria-controls={contentId}
          title={summary}
          onClick={onToggleCollapsed}
        >
          <span className="rule-section-copy">
            <span className="rule-section-title">
              <span className="heading-with-icon">
                {iconName ? <AppIcon name={iconName} className="app-icon-sm" /> : null}
                <span>{title}</span>
              </span>
              <span className="rule-count">{count}</span>
            </span>
          </span>
        </button>
        <div className="rule-section-actions">
          <button
            type="button"
            className="ghost icon-only-button policy-icon-button policy-section-chevron"
            aria-expanded={!collapsed}
            aria-controls={contentId}
            aria-label={collapsed ? `Expand ${title}` : `Collapse ${title}`}
            title={collapsed ? `Expand ${title}` : `Collapse ${title}`}
            onClick={onToggleCollapsed}
          >
            <AppIcon name="chevron" className="app-icon-chevron" />
            <span className="sr-only">{collapsed ? `Expand ${title}` : `Collapse ${title}`}</span>
          </button>
          <button
            type="button"
            className="ghost icon-only-button policy-icon-button rule-section-add"
            data-testid={testId ? `${testId}-add` : undefined}
            aria-label={addLabel}
            title={addLabel}
            onClick={() => {
              // Reveal the section so the newly added row is visible and editable.
              if (collapsed) {
                onToggleCollapsed();
              }
              onAdd();
            }}
          >
            <AppIcon name="add" className="app-icon-sm" />
            <span className="sr-only">{addLabel}</span>
          </button>
        </div>
      </div>
      <div id={contentId} className="rule-section-body" hidden={collapsed}>
        {children}
      </div>
    </section>
  );
}
