import { memo } from "react";

import type { AuditLevel, DecisionMode, EnforcementMode, FailMode } from "../../policyHelpers";
import { AppIcon } from "./AppIcon";

type PolicyDefaultsPanelProps = {
  version: string;
  decision: DecisionMode;
  failMode: FailMode;
  auditLevel: AuditLevel;
  fileEnforcement: EnforcementMode;
  processEnforcement: EnforcementMode;
  networkEnforcement: EnforcementMode;
  onVersionChange: (value: string) => void;
  onDecisionChange: (value: DecisionMode) => void;
  onFailModeChange: (value: FailMode) => void;
  onAuditLevelChange: (value: AuditLevel) => void;
  onFileEnforcementChange: (value: EnforcementMode) => void;
  onProcessEnforcementChange: (value: EnforcementMode) => void;
  onNetworkEnforcementChange: (value: EnforcementMode) => void;
};

function policyModeCopy(value: DecisionMode): string {
  if (value === "allow") {
    return "Allow by default. Add deny rules for exceptions.";
  }
  return "Deny by default. Add allow rules for approved access.";
}

export const PolicyDefaultsPanel = memo(function PolicyDefaultsPanel({
  version,
  decision,
  failMode,
  auditLevel,
  fileEnforcement,
  processEnforcement,
  networkEnforcement,
  onVersionChange,
  onDecisionChange,
  onFailModeChange,
  onAuditLevelChange,
  onFileEnforcementChange,
  onProcessEnforcementChange,
  onNetworkEnforcementChange
}: PolicyDefaultsPanelProps) {
  return (
    <section className="policy-surface policy-defaults-panel" data-testid="policy-defaults-panel">
      <div className="policy-section-header">
        <div className="policy-section-copy">
          <p className="policy-kicker">Applies to all profiles</p>
          <h3 className="heading-with-icon">
            <AppIcon name="shield" className="app-icon-lg" />
            <span>Global defaults</span>
          </h3>
          <p>Baseline every profile inherits when no rule matches.</p>
        </div>
        <span className="policy-section-chip">All profiles</span>
      </div>

      <div className="policy-inline-note">
        <AppIcon name="info" className="app-icon-sm" />
        <span>{policyModeCopy(decision)}</span>
      </div>

      <div className="policy-defaults-grid">
        <div className="field">
          <label htmlFor="policy-version-input">Version</label>
          <input
            id="policy-version-input"
            data-testid="policy-version-input"
            value={version}
            onChange={(event) => onVersionChange(event.target.value || "v1")}
          />
        </div>
        <div className="field">
          <label htmlFor="policy-mode-select">Policy Mode</label>
          <select
            id="policy-mode-select"
            data-testid="policy-mode-select"
            value={decision}
            onChange={(event) => onDecisionChange(event.target.value as DecisionMode)}
          >
            <option value="allow">allow-unless-denied</option>
            <option value="deny">deny-unless-allowed</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-fail-mode-select">Fail Mode</label>
          <select
            id="policy-fail-mode-select"
            data-testid="policy-fail-mode-select"
            value={failMode}
            onChange={(event) => onFailModeChange(event.target.value as FailMode)}
          >
            <option value="fail_closed">fail_closed</option>
            <option value="fail_open">fail_open</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-audit-level-select">Audit Level</label>
          <select
            id="policy-audit-level-select"
            data-testid="policy-audit-level-select"
            value={auditLevel}
            onChange={(event) => onAuditLevelChange(event.target.value as AuditLevel)}
          >
            <option value="all">all</option>
            <option value="denies">denies</option>
            <option value="errors">errors</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-file-enforcement-select">File Enforcement</label>
          <select
            id="policy-file-enforcement-select"
            data-testid="policy-file-enforcement-select"
            value={fileEnforcement}
            onChange={(event) => onFileEnforcementChange(event.target.value as EnforcementMode)}
          >
            <option value="enforce">enforce</option>
            <option value="observe">observe</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-process-enforcement-select">Process Enforcement</label>
          <select
            id="policy-process-enforcement-select"
            data-testid="policy-process-enforcement-select"
            value={processEnforcement}
            onChange={(event) => onProcessEnforcementChange(event.target.value as EnforcementMode)}
          >
            <option value="enforce">enforce</option>
            <option value="observe">observe</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="policy-network-enforcement-select">Network Enforcement</label>
          <select
            id="policy-network-enforcement-select"
            data-testid="policy-network-enforcement-select"
            value={networkEnforcement}
            onChange={(event) => onNetworkEnforcementChange(event.target.value as EnforcementMode)}
          >
            <option value="enforce">enforce</option>
            <option value="observe">observe</option>
          </select>
        </div>
      </div>
    </section>
  );
});
