import { memo, type ReactNode } from "react";

import { AppIcon } from "./AppIcon";

type PolicyReviewMode = "active" | "generated";

type PolicyReviewRailProps = {
  previewMode: PolicyReviewMode;
  onPreviewModeChange: (mode: PolicyReviewMode) => void;
  activePolicyYaml: string;
  generatedPolicyYaml: string;
  versionsSection: ReactNode;
  actionsSection: ReactNode;
};

export const PolicyReviewRail = memo(function PolicyReviewRail({
  previewMode,
  onPreviewModeChange,
  activePolicyYaml,
  generatedPolicyYaml,
  versionsSection,
  actionsSection
}: PolicyReviewRailProps) {
  return (
    <aside className="policy-review-rail">
      <section className="policy-surface policy-preview-panel" data-testid="policy-preview-panel">
        <div className="policy-section-header">
          <div className="policy-section-copy">
            <p className="policy-kicker">Reference rail</p>
            <h3 className="heading-with-icon">
              <AppIcon name="eye" className="app-icon-lg" />
              <span>YAML preview</span>
            </h3>
            <p>Compare draft and active YAML.</p>
          </div>
          <span className="policy-section-chip policy-section-chip-muted">Read only</span>
        </div>

        <div className="policy-review-toggle" role="tablist" aria-label="Policy preview mode">
          <button
            type="button"
            className={previewMode === "generated" ? "active" : ""}
            aria-pressed={previewMode === "generated"}
            onClick={() => onPreviewModeChange("generated")}
          >
            Draft
          </button>
          <button
            type="button"
            className={previewMode === "active" ? "active" : ""}
            aria-pressed={previewMode === "active"}
            onClick={() => onPreviewModeChange("active")}
          >
            Active
          </button>
        </div>

        <div className="policy-code-frame">
          <div hidden={previewMode !== "generated"}>
            <h4>Draft</h4>
            <pre data-testid="generated-policy-yaml">{generatedPolicyYaml}</pre>
          </div>
          <div hidden={previewMode !== "active"}>
            <h4>Active</h4>
            <pre data-testid="active-policy-yaml">{activePolicyYaml}</pre>
          </div>
        </div>
      </section>

      <div className="policy-review-stack">
        {versionsSection}
        {actionsSection}
      </div>
    </aside>
  );
});
