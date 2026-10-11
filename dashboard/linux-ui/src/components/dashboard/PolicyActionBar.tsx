import { memo } from "react";

import { AppIcon } from "./AppIcon";

type PolicyActionBarProps = {
  onSave: () => void;
  onValidate: () => void;
  onApply: () => void;
  onDiscard: () => void;
  discardDisabled: boolean;
};

export const PolicyActionBar = memo(function PolicyActionBar({
  onSave,
  onValidate,
  onApply,
  onDiscard,
  discardDisabled
}: PolicyActionBarProps) {
  return (
    <div className="policy-action-bar actions" data-testid="policy-actions">
      <button
        type="button"
        className="ghost borderless policy-action-tertiary"
        data-testid="discard-edits-button"
        onClick={onDiscard}
        disabled={discardDisabled}
      >
        <span className="button-with-icon">
          <AppIcon name="undo" className="app-icon-sm" />
          <span>Discard</span>
        </span>
      </button>
      <button
        type="button"
        className="ghost policy-action-secondary"
        data-testid="validate-draft-button"
        onClick={onValidate}
      >
        <span className="button-with-icon">
          <AppIcon name="check" className="app-icon-sm" />
          <span>Validate</span>
        </span>
      </button>
      <button
        type="button"
        className="ghost policy-action-secondary"
        data-testid="save-draft-button"
        onClick={onSave}
      >
        <span className="button-with-icon">
          <AppIcon name="save" className="app-icon-sm" />
          <span>Save draft</span>
        </span>
      </button>
      <button
        type="button"
        className="primary policy-action-prominent"
        data-testid="apply-draft-button"
        onClick={onApply}
      >
        <span className="button-with-icon">
          <AppIcon name="upload" className="app-icon-sm" />
          <span>Review &amp; apply</span>
        </span>
      </button>
    </div>
  );
});
