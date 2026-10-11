import { AppIcon, type AppIconName } from "./AppIcon";

const tabs = [
  { key: "overview", label: "Overview", icon: "overview", group: "Monitor" },
  { key: "events", label: "Live events", icon: "activity", group: "Monitor" },
  { key: "approvals", label: "Approvals", icon: "approvals", group: "Monitor" },
  { key: "policy", label: "Policy studio", icon: "shield", group: "Configure" },
  { key: "enrollment", label: "Enrollments", icon: "enrollment", group: "Configure" },
  { key: "agents", label: "Agents", icon: "cpu", group: "Configure" },
  { key: "settings", label: "Settings", icon: "settings", group: "System" },
  { key: "help", label: "Help", icon: "help", group: "System" }
] as const;

export type DashboardTabKey = (typeof tabs)[number]["key"];

const GROUPS = ["Monitor", "Configure", "System"] as const;

type TabRailProps = {
  activeTab: DashboardTabKey;
  onSelect: (tab: DashboardTabKey) => void;
  /** Optional pill counts per tab (e.g. pending approvals). Zero hides the pill. */
  counts?: Partial<Record<DashboardTabKey, number>>;
};

export function TabRail({ activeTab, onSelect, counts }: TabRailProps) {
  return (
    <nav className="tab-rail" aria-label="Dashboard sections" data-testid="tab-rail">
      {GROUPS.map((group) => (
        <div className="nav-group" key={group}>
          <p className="nav-group-label">{group}</p>
          {tabs
            .filter((tab) => tab.group === group)
            .map((tab) => {
              const count = counts?.[tab.key] ?? 0;
              return (
                <button
                  key={tab.key}
                  type="button"
                  className={activeTab === tab.key ? "nav-item active" : "nav-item"}
                  aria-current={activeTab === tab.key ? "page" : undefined}
                  data-testid={`tab-${tab.key}`}
                  onClick={() => onSelect(tab.key)}
                >
                  <AppIcon name={tab.icon as AppIconName} className="nav-item-icon" />
                  <span className="nav-item-label">{tab.label}</span>
                  {count > 0 ? <span className="nav-item-count">{count}</span> : null}
                </button>
              );
            })}
        </div>
      ))}
    </nav>
  );
}
