import { memo } from "react";

import type { PolicyVersion } from "../../dashboardTypes";
import { fmt } from "../../dashboardUi";
import type { PolicyDiffSummary } from "../../policyDiff";
import { AppIcon } from "./AppIcon";

type ApplyDialogProps = {
  mode: "apply";
  diff: PolicyDiffSummary;
  note: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  onNoteChange: (value: string) => void;
};

type RollbackDialogProps = {
  mode: "rollback";
  version: PolicyVersion;
  note: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  onNoteChange: (value: string) => void;
};

type PolicyChangeDialogProps = ApplyDialogProps | RollbackDialogProps;

function DiffSection({
  title,
  tone,
  items
}: {
  title: string;
  tone: "added" | "removed" | "changed";
  items: PolicyDiffSummary[keyof PolicyDiffSummary];
}) {
  if (!items.length) {
    return null;
  }

  return (
    <section className={`policy-diff-section policy-diff-section-${tone}`}>
      <h4>
        {title} ({items.length})
      </h4>
      <ul className="policy-diff-list">
        {items.map((item) => (
          <li key={item.key}>
            <strong>{item.label}</strong>
            {item.before && item.after ? (
              <span className="meta">
                {item.before}
                {" -> "}
                {item.after}
              </span>
            ) : (
              <span className="meta">{item.after ?? item.before}</span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export const PolicyChangeDialog = memo(function PolicyChangeDialog(props: PolicyChangeDialogProps) {
  const title = props.mode === "apply" ? "Review and Apply Policy Draft" : "Confirm Rollback";
  const confirmLabel = props.mode === "apply" ? "Apply and save policy" : "Rollback";
  const titleIcon = props.mode === "apply" ? "upload" : "undo";

  return (
    <div
      className="modal-overlay"
      data-testid={props.mode === "apply" ? "apply-confirm-modal" : "rollback-confirm-modal"}
    >
      <div className="modal-card policy-change-dialog">
        <div className="modal-header">
          <h3 className="heading-with-icon">
            <AppIcon name={titleIcon} className="app-icon-lg" />
            <span>{title}</span>
          </h3>
          <button
            className="ghost icon-only-button"
            onClick={props.onCancel}
            aria-label="Close"
            title="Close"
            disabled={props.busy}
          >
            <AppIcon name="close" className="app-icon-sm" />
            <span className="sr-only">Close</span>
          </button>
        </div>
        <div className="modal-body">
          {props.mode === "apply" ? (
            <>
              <p className="meta">
                Review the generated draft against the active policy. The policy is only applied and
                saved after you confirm below.
              </p>
              {!props.diff.added.length &&
              !props.diff.removed.length &&
              !props.diff.changed.length ? (
                <p className="info validation-state">
                  <AppIcon name="info" className="app-icon-sm" />
                  <span>No effective policy changes detected.</span>
                </p>
              ) : null}
              <DiffSection title="Added" tone="added" items={props.diff.added} />
              <DiffSection title="Removed" tone="removed" items={props.diff.removed} />
              <DiffSection title="Changed" tone="changed" items={props.diff.changed} />
            </>
          ) : (
            <div className="rollback-summary">
              <p>
                <strong>Version:</strong> <span className="mono">{props.version.id}</span>
              </p>
              <p>
                <strong>Created:</strong> {fmt(props.version.created_at)}
              </p>
              <p>
                <strong>Summary:</strong> {props.version.summary}
              </p>
            </div>
          )}
          <div className="form-group">
            <label htmlFor="policy-note-input">Add note (optional)</label>
            <textarea
              id="policy-note-input"
              className="policy-note-input"
              value={props.note}
              onChange={(event) => props.onNoteChange(event.target.value)}
              placeholder="Why are you applying or rolling back this policy?"
              rows={3}
              data-testid={props.mode === "apply" ? "apply-note-input" : "rollback-note-input"}
            />
          </div>
        </div>
        <div className="modal-footer">
          <button className="ghost" onClick={props.onCancel} disabled={props.busy}>
            Cancel
          </button>
          <button
            className="danger"
            onClick={props.onConfirm}
            disabled={props.busy}
            data-testid={
              props.mode === "apply" ? "apply-confirm-button" : "rollback-confirm-button"
            }
          >
            <span className="button-with-icon">
              <AppIcon name={props.mode === "apply" ? "upload" : "undo"} className="app-icon-sm" />
              <span>{props.busy ? "Working..." : confirmLabel}</span>
            </span>
          </button>
        </div>
      </div>
    </div>
  );
});
