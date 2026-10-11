import { AppIcon } from "./AppIcon";
import { TabRail, type DashboardTabKey } from "./TabRail";

type SidebarProps = {
  activeTab: DashboardTabKey;
  onSelect: (tab: DashboardTabKey) => void;
  pendingApprovals: number;
  daemonUp: boolean | null;
  daemonDetail: string;
  username: string;
  showPasswordPanel: boolean;
  onTogglePasswordPanel: () => void;
  onLogout: () => void;
};

export function Sidebar({
  activeTab,
  onSelect,
  pendingApprovals,
  daemonUp,
  daemonDetail,
  username,
  showPasswordPanel,
  onTogglePasswordPanel,
  onLogout
}: SidebarProps) {
  const daemonLabel =
    daemonUp == null ? "Connecting…" : daemonUp ? "Daemon online" : "Daemon offline";
  const daemonTone = daemonUp == null ? "neutral" : daemonUp ? "success" : "danger";

  return (
    <aside className="sidebar" data-testid="sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark" aria-hidden="true">
          <AppIcon name="mercury" />
        </span>
        <div className="sidebar-brand-copy">
          <p className="sidebar-brand-name">Mercury</p>
          <p className="sidebar-brand-host">Linux runtime guard</p>
        </div>
      </div>

      <TabRail activeTab={activeTab} onSelect={onSelect} counts={{ approvals: pendingApprovals }} />

      <div className="sidebar-footer">
        <div className="sidebar-status" data-testid="sidebar-daemon-status">
          <p className="sidebar-status-row">
            <span className={`status-dot status-dot-${daemonTone}`} aria-hidden="true" />
            <span>{daemonLabel}</span>
          </p>
          <p className="sidebar-status-detail">{daemonDetail}</p>
        </div>
        <div className="sidebar-user">
          <span className="avatar" aria-hidden="true">
            {(username.trim()[0] ?? "?").toUpperCase()}
          </span>
          <div className="sidebar-user-copy">
            <p className="sidebar-user-name">{username || "operator"}</p>
            <p className="sidebar-user-role">Dashboard admin</p>
          </div>
          <button
            type="button"
            className="ghost icon-only-button"
            data-testid="toggle-password-panel-button"
            onClick={onTogglePasswordPanel}
            aria-label={showPasswordPanel ? "Close password dialog" : "Change password"}
            title={showPasswordPanel ? "Close password dialog" : "Change password"}
          >
            <AppIcon name="password" className="app-icon-sm" />
          </button>
          <button
            type="button"
            className="ghost icon-only-button"
            data-testid="logout-button"
            onClick={onLogout}
            aria-label="Log out"
            title="Log out"
          >
            <AppIcon name="logout" className="app-icon-sm" />
          </button>
        </div>
      </div>
    </aside>
  );
}
