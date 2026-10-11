/* eslint-disable react-refresh/only-export-components */
import { memo } from "react";
import type { DashboardTabKey } from "./TabRail";
import { AppIcon, type AppIconName } from "./AppIcon";
import { PanelCard } from "./PanelCard";

export type TourFocusRect = {
  top: number;
  left: number;
  width: number;
  height: number;
};

export type HelpTopic = {
  tab: DashboardTabKey;
  eyebrow: string;
  title: string;
  summary: string;
  highlights: string[];
};

export type TourStep = {
  tab: DashboardTabKey;
  selector: string;
  eyebrow: string;
  title: string;
  description: string;
  actions: string[];
};

const TAB_LABELS: Record<DashboardTabKey, string> = {
  overview: "Overview",
  events: "Live Events",
  approvals: "Approvals",
  policy: "Policy Studio",
  enrollment: "Enrollments",
  agents: "Agents",
  settings: "Settings",
  help: "Help Hub"
};

export const HELP_TOPICS: HelpTopic[] = [
  {
    tab: "overview",
    eyebrow: "Mission Control",
    title: "Overview",
    summary:
      "Use the overview to verify Mercury health, ingest pressure, and what is getting blocked before you drill into details.",
    highlights: [
      "The top metric row answers whether mercuryd, the kernel backend, the dashboard, and the URL gateway are healthy.",
      "Decision Throughput shows recent allow, deny, and observe volume so you can spot spikes quickly.",
      "Top Blocked Resources helps you identify the paths and endpoints driving the most denials."
    ]
  },
  {
    tab: "events",
    eyebrow: "Investigation",
    title: "Live Events",
    summary:
      "This stream is your live audit feed. It is the fastest path for answering what Mercury just allowed, denied, or observed.",
    highlights: [
      "The stream badge shows whether the SSE pipeline is healthy or reconnecting.",
      "Each row keeps the exact profile, resource, and reason code that produced the decision.",
      "Rows tagged with a model badge open the captured prompt, output and token usage for that model API call.",
      "Retry refreshes the current event query without leaving the page."
    ]
  },
  {
    tab: "approvals",
    eyebrow: "Human Approval",
    title: "Approvals",
    summary:
      "Pending MCP tool calls and resource reads land here when policy requires an operator decision before the local MCP server is allowed to continue.",
    highlights: [
      "Each request shows the server, requested action, profile, and payload preview before you decide.",
      "Approve lets the waiting MCP client continue; deny blocks the requested tool call or read before execution.",
      "The panel refreshes continuously so operators can work live without reopening the page."
    ]
  },
  {
    tab: "policy",
    eyebrow: "Change Control",
    title: "Policy Studio",
    summary:
      "Policy Studio is the safe editing surface for defaults, profile-specific rules, validation, preview, and rollback.",
    highlights: [
      "Defaults let you choose allow-unless-denied versus deny-unless-allowed, fail mode, audit level, and enforcement mode.",
      "Profiles isolate different workloads so you can give agents different file, exec, network, and URL permissions.",
      "Draft controls let you save, validate, apply, compare, and roll back policies without editing YAML by hand."
    ]
  },
  {
    tab: "enrollment",
    eyebrow: "Coverage",
    title: "Enrollments",
    summary:
      "Enrollments show which processes are currently under Mercury control, how they were enrolled, and which profile they carry.",
    highlights: [
      "Source distinguishes explicit mercury-run registrations from auto-enroll coverage.",
      "Mode shows whether the process is enforcing or only observing.",
      "Group IDs let you map a running process back to the Mercury control group that owns it (its cgroup)."
    ]
  },
  {
    tab: "agents",
    eyebrow: "Launch Control",
    title: "Agents",
    summary:
      "Use the Agents tab to start and stop server-style agents and background workers under a named Mercury profile.",
    highlights: [
      "If the launched process exposes its own web UI or API, interact with that service directly after launch.",
      "Interactive terminal or chat programs are a poor fit for the dashboard launcher because it does not provide an interactive console.",
      "Dashboard launches now run through mercury-run, so Mercury agent metadata and URL-proxy environment are injected consistently."
    ]
  },
  {
    tab: "settings",
    eyebrow: "TLS Operations",
    title: "Settings",
    summary:
      "Use Settings for dashboard certificate operations and deployment-time TLS guidance without leaving the UI.",
    highlights: [
      "Hot-swap Certificate lets operators reload a new cert and key path into the running dashboard.",
      "The panel also shows the currently loaded certificate details so you can verify what is active.",
      "The trusted-certificate guidance keeps ACME and manual certificate workflows visible during rollout and renewal work."
    ]
  },
  {
    tab: "help",
    eyebrow: "Operator Enablement",
    title: "Help Hub",
    summary:
      "The help hub is the operator onboarding surface: start the full guided tour, jump directly to a section, or reopen contextual help later.",
    highlights: [
      "Start the full tour to be guided through every major screen in sequence.",
      "Use section cards to jump to the exact workflow you want to learn next.",
      "The floating help bar stays available on demand from anywhere in the dashboard."
    ]
  }
];

export const TOUR_STEPS: TourStep[] = [
  {
    tab: "overview",
    selector: '[data-testid="shell-header"]',
    eyebrow: "Step 1",
    title: "The top bar anchors every workflow",
    description:
      "Refresh re-pulls the dashboard APIs, the moon/sun button switches light and dark themes, and Help returns you here later. Change password and log out live at the bottom of the sidebar.",
    actions: [
      "Use Refresh when runtime health looks stale or after applying policy.",
      "Use the key icon in the sidebar to rotate your password inside the UI.",
      "Use Help whenever you want this guide again without leaving the dashboard."
    ]
  },
  {
    tab: "overview",
    selector: '[data-testid="tab-rail"]',
    eyebrow: "Step 2",
    title: "The sidebar is the operational map",
    description:
      "Screens are grouped by job — Monitor, Configure and System — and each answers a different question. Pending approvals show a count so you never miss one.",
    actions: [
      "Overview answers whether the platform is healthy.",
      "Live Events answers what just happened.",
      "Policy Studio answers how to change behavior safely."
    ]
  },
  {
    tab: "overview",
    selector: '[data-testid="overview-grid"]',
    eyebrow: "Step 3",
    title: "Read the runtime snapshot first",
    description:
      "The KPI strip, Needs attention queue and System health list compress the main runtime signals into one scan: daemon state, kernel backend readiness, dashboard health, URL gateway, and queue pressure.",
    actions: [
      "Check Kernel backend before trusting enforcement results.",
      "Needs attention lists anything that requires an operator, with a shortcut to fix it.",
      "Use URL gateway health before debugging URL policy behavior."
    ]
  },
  {
    tab: "overview",
    selector: '[data-testid="decision-throughput-panel"]',
    eyebrow: "Step 4",
    title: "Decision Throughput shows system tempo",
    description:
      "Allow, deny and observe are plotted separately per minute, so you can see whether decision volume is stable or an agent suddenly changed behavior. Hover the chart for exact counts.",
    actions: [
      "Look for sharp deny spikes after policy changes.",
      "Compare allow, deny, and observe totals to understand enforcement mix.",
      "Use it as your first signal before opening the raw event stream."
    ]
  },
  {
    tab: "overview",
    selector: '[data-testid="top-blocked-panel"]',
    eyebrow: "Step 5",
    title: "Top Blocked Resources highlights hotspots",
    description:
      "This list surfaces the most frequently denied paths or endpoints so you can decide whether to loosen policy or investigate suspicious behavior.",
    actions: [
      "Repeated denies on expected resources usually point to missing allow rules.",
      "Unexpected blocked resources often indicate tool drift or suspicious access.",
      "Use this panel to prioritize policy edits instead of scanning every event row."
    ]
  },
  {
    tab: "events",
    selector: '[data-testid="events-panel"]',
    eyebrow: "Step 6",
    title: "Live Events is the real-time audit console",
    description:
      "The stream badge shows whether Mercury is actively feeding live decision events into the UI.",
    actions: [
      "Connected means live SSE updates are flowing.",
      "Reconnecting means the UI is trying to restore the stream.",
      "Retry re-runs the query if the stream history looks stale."
    ]
  },
  {
    tab: "events",
    selector: '[data-testid="events-table"]',
    eyebrow: "Step 7",
    title: "Each event row explains a decision",
    description:
      "Use Time, Decision, Profile, Resource, and Reason together to understand exactly why Mercury allowed, denied, or observed an action.",
    actions: [
      "Reason codes distinguish rule matches from observe-mode and default decisions.",
      "Resource tells you what file, executable, or network target was involved.",
      "Profile and PID help you map the event back to the responsible workload."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="policy-editor-panel"]',
    eyebrow: "Step 8",
    title: "Policy defaults shape global behavior",
    description:
      "Start here before adding rules. Default decision, fail mode, audit level, and enforcement modes define how every profile behaves when nothing matches.",
    actions: [
      "allow-unless-denied is permissive and good for incremental tightening.",
      "deny-unless-allowed is strict and best when you know the safe paths.",
      "Observe mode lets you study impact before enforcing a class."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="profile-toolbar"]',
    eyebrow: "Step 9",
    title: "Profiles carve policy by workload",
    description:
      "Profiles let you give different agents different workspaces and rule sets instead of collapsing everything into one global policy.",
    actions: [
      "Add a profile when a workload needs a separate trust boundary.",
      "Switch profiles before editing rules so changes land in the right place.",
      "Remove unused profiles to keep policy readable."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="network-allow-section"]',
    eyebrow: "Step 10",
    title: "Rule sections cover every major action class",
    description:
      "Workspace, file, exec, network, and URL sections let you build policy using structured forms instead of handwritten YAML.",
    actions: [
      "File and exec sections constrain filesystem access and allowed binaries.",
      "Network rules cover CIDR, host glob, port, and protocol.",
      "URL rules add scheme, host, path, method, and query controls above raw network access."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="policy-actions"]',
    eyebrow: "Step 11",
    title: "Use the draft actions as your safety rail",
    description:
      "Save captures the working copy, Validate checks it, Apply ships it, and Discard resets the editor back to the active policy.",
    actions: [
      "Validate before Apply whenever you add or broaden rules.",
      "Apply reloads the daemon and should be followed by a quick status check.",
      "Discard is the fastest way back to the live policy if an experiment goes sideways."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="policy-preview-panel"]',
    eyebrow: "Step 12",
    title: "Preview keeps forms honest",
    description:
      "The preview panel shows the active YAML next to the generated draft so you can see exactly what the form builder will change.",
    actions: [
      "Compare active and generated output before Apply.",
      "Use this to review rule IDs and patterns without leaving the UI.",
      "If the diff looks wrong, fix the form fields before saving again."
    ]
  },
  {
    tab: "policy",
    selector: '[data-testid="policy-versions-panel"]',
    eyebrow: "Step 13",
    title: "Versioned rollback is your escape hatch",
    description:
      "Every stored policy version can be rolled back from here, which keeps policy iteration safer during incidents.",
    actions: [
      "Use rollback when a new policy causes unexpected denials.",
      "The summary helps you identify the change set you want to restore.",
      "After rollback, re-check Overview and Live Events to confirm stability."
    ]
  },
  {
    tab: "enrollment",
    selector: '[data-testid="enrollments-panel"]',
    eyebrow: "Step 14",
    title: "Enrollments tell you who is actually covered",
    description:
      "This table confirms whether the processes you care about are enrolled, what profile they have, and whether Mercury is enforcing them.",
    actions: [
      "If a workload is missing here, Mercury is not currently controlling it.",
      "Use source to separate explicit mercury-run launches from auto-enroll rules.",
      "Use group IDs when correlating process coverage with host runtime state."
    ]
  },
  {
    tab: "settings",
    selector: '[data-testid="settings-panel"]',
    eyebrow: "Step 15",
    title: "Settings handles dashboard TLS operations",
    description:
      "Use Settings to inspect the active dashboard certificate, hot-swap a new cert/key pair, and keep the trusted-certificate workflow close to operators.",
    actions: [
      "Use hot-swap when renewing or replacing dashboard TLS material without editing the full config by hand.",
      "Verify the loaded certificate details before exposing the dashboard externally.",
      "Keep the trusted-cert guidance nearby when moving from self-signed testing to public deployment."
    ]
  },
  {
    tab: "help",
    selector: '[data-testid="help-screen-panel"]',
    eyebrow: "Step 16",
    title: "The help hub and help bar stay available on demand",
    description:
      "You can relaunch this tour, jump straight to any tab, or keep the floating help bar nearby for quick reminders while you work.",
    actions: [
      "Open Help Hub when a new operator needs a full walkthrough.",
      "Use section cards to jump directly to the screen you need.",
      "Use the floating help bar for quick actions without losing context."
    ]
  }
];

export function helpTabLabel(tab: DashboardTabKey): string {
  return TAB_LABELS[tab];
}

export function helpTopicForTab(tab: DashboardTabKey): HelpTopic {
  return HELP_TOPICS.find((topic) => topic.tab === tab) ?? HELP_TOPICS[0];
}

export function firstTourStepIndexForTab(tab: DashboardTabKey): number {
  const index = TOUR_STEPS.findIndex((step) => step.tab === tab);
  return index === -1 ? 0 : index;
}

const TOPIC_ICONS: Record<DashboardTabKey, AppIconName> = {
  overview: "overview",
  events: "activity",
  approvals: "approvals",
  policy: "shield",
  enrollment: "enrollment",
  agents: "cpu",
  settings: "lock",
  help: "help"
};

export const HelpTab = memo(function HelpTab({
  currentTab,
  onOpenTab,
  onStartTour,
  onStartTabTour
}: {
  currentTab: DashboardTabKey;
  onOpenTab: (tab: DashboardTabKey) => void;
  onStartTour: () => void;
  onStartTabTour: (tab: DashboardTabKey) => void;
}) {
  const activeTopic = helpTopicForTab(currentTab);

  return (
    <section className="help-grid" data-testid="help-screen-grid">
      <article className="card help-hero-panel" data-testid="help-screen-panel">
        <div className="help-hero-copy">
          <p className="eyebrow">Operator guide</p>
          <h2>Learn Mercury in a few minutes</h2>
          <p className="help-lead">
            The guided tour walks through every screen in order — what each panel answers and what
            to do when something looks wrong. You can leave and resume at any time.
          </p>
          <div className="actions">
            <button className="primary" data-testid="help-start-tour-button" onClick={onStartTour}>
              <span className="button-with-icon">
                <AppIcon name="play" className="app-icon-sm" />
                <span>Start full tour</span>
              </span>
            </button>
            <button
              className="ghost"
              data-testid="help-start-current-tour-button"
              onClick={() => onStartTabTour(currentTab)}
            >
              Tour {activeTopic.title}
            </button>
          </div>
        </div>
        <div className="help-current-card">
          <div className="help-current-heading">
            <span className="icon-tile icon-tile-accent" aria-hidden="true">
              <AppIcon name={TOPIC_ICONS[activeTopic.tab]} className="app-icon-sm" />
            </span>
            <div>
              <p className="eyebrow">{activeTopic.eyebrow}</p>
              <h4>{activeTopic.title}</h4>
            </div>
          </div>
          <p className="subtle">{activeTopic.summary}</p>
          <ul className="help-list">
            {activeTopic.highlights.map((highlight) => (
              <li key={highlight}>{highlight}</li>
            ))}
          </ul>
        </div>
      </article>

      <h3 className="section-heading">Guides by screen</h3>
      <div className="help-topic-grid">
        {HELP_TOPICS.map((topic) => (
          <article className="card help-topic-card" key={topic.tab}>
            <span className="icon-tile icon-tile-accent" aria-hidden="true">
              <AppIcon name={TOPIC_ICONS[topic.tab]} className="app-icon-sm" />
            </span>
            <div className="help-topic-copy">
              <p className="eyebrow">{topic.eyebrow}</p>
              <h3>{topic.title}</h3>
              <p className="subtle">{topic.summary}</p>
            </div>
            <div className="actions">
              <button className="ghost btn-sm" onClick={() => onOpenTab(topic.tab)}>
                Open {topic.title}
              </button>
              <button className="ghost borderless btn-sm" onClick={() => onStartTabTour(topic.tab)}>
                Tour this area
              </button>
            </div>
          </article>
        ))}
      </div>

      <PanelCard
        title="Tour outline"
        subtitle="Every step in the guided walkthrough."
        className="help-tour-outline"
        testId="help-tour-outline"
      >
        <ol className="tour-outline-list">
          {TOUR_STEPS.map((step, index) => (
            <li key={`${step.tab}-${step.selector}`}>
              <span className="tour-outline-number">{index + 1}</span>
              <div className="tour-outline-copy">
                <p className="label">{helpTabLabel(step.tab)}</p>
                <strong>{step.title}</strong>
                <p className="meta">{step.description}</p>
              </div>
              <button className="ghost btn-sm" onClick={() => onStartTabTour(step.tab)}>
                Go to section
              </button>
            </li>
          ))}
        </ol>
      </PanelCard>
    </section>
  );
});

export const HelpBar = memo(function HelpBar({
  currentTab,
  open,
  onToggle,
  onOpenHelp,
  onStartTour,
  onStartTabTour
}: {
  currentTab: DashboardTabKey;
  open: boolean;
  onToggle: () => void;
  onOpenHelp: () => void;
  onStartTour: () => void;
  onStartTabTour: (tab: DashboardTabKey) => void;
}) {
  const topic = helpTopicForTab(currentTab);

  return (
    <div className={`help-bar ${open ? "open" : ""}`} data-testid="help-bar">
      {open ? (
        <aside className="help-bar-panel" data-testid="help-bar-panel">
          <p className="eyebrow">Quick help</p>
          <h3>{topic.title}</h3>
          <p className="subtle">{topic.summary}</p>
          <ul className="help-list compact">
            {topic.highlights.slice(0, 2).map((highlight) => (
              <li key={highlight}>{highlight}</li>
            ))}
          </ul>
          <div className="help-bar-actions">
            <button className="primary" onClick={() => onStartTabTour(currentTab)}>
              Tour This Tab
            </button>
            <button className="ghost" onClick={onStartTour}>
              Start Full Tour
            </button>
            <button className="ghost borderless" onClick={onOpenHelp}>
              Open Help Hub
            </button>
          </div>
        </aside>
      ) : null}
      <button
        className="help-bar-toggle"
        data-testid="help-bar-toggle"
        onClick={onToggle}
        aria-expanded={open}
        aria-label={open ? "Hide quick help" : "Show quick help"}
        title={open ? "Hide quick help" : "Need help?"}
      >
        <AppIcon name={open ? "close" : "help"} />
      </button>
    </div>
  );
});

export const GuidedTourOverlay = memo(function GuidedTourOverlay({
  step,
  stepIndex,
  totalSteps,
  focusRect,
  onNext,
  onPrevious,
  onClose,
  onOpenHelp
}: {
  step: TourStep;
  stepIndex: number;
  totalSteps: number;
  focusRect: TourFocusRect | null;
  onNext: () => void;
  onPrevious: () => void;
  onClose: () => void;
  onOpenHelp: () => void;
}) {
  const progress = ((stepIndex + 1) / totalSteps) * 100;

  return (
    <div className="tour-overlay" role="dialog" aria-modal="true" aria-labelledby="tour-title">
      <button className="tour-scrim" aria-label="Close guided tour" onClick={onClose} />
      {focusRect ? (
        <div
          className="tour-focus-ring"
          style={{
            top: focusRect.top - 10,
            left: focusRect.left - 10,
            width: focusRect.width + 20,
            height: focusRect.height + 20
          }}
        />
      ) : null}
      <aside className="tour-panel" data-testid="guided-tour-panel">
        <div className="tour-progress">
          <p className="eyebrow">{step.eyebrow}</p>
          <span>
            {stepIndex + 1} / {totalSteps}
          </span>
        </div>
        <div className="tour-progress-bar">
          <span style={{ width: `${progress}%` }} />
        </div>
        <h2 id="tour-title">{step.title}</h2>
        <p className="subtle">{step.description}</p>
        <p className="tour-target-tag">Showing {helpTabLabel(step.tab)}</p>
        <ul className="help-list tour-list">
          {step.actions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
        <div className="tour-actions">
          <button className="ghost borderless" onClick={onOpenHelp}>
            Open Help Hub
          </button>
          <span className="tour-actions-spacer" />
          <button className="ghost" onClick={onPrevious} disabled={stepIndex === 0}>
            Previous
          </button>
          <button className="primary" onClick={onNext}>
            {stepIndex === totalSteps - 1 ? "Finish Tour" : "Next"}
          </button>
        </div>
      </aside>
    </div>
  );
});
