import {
  FormEvent,
  type ButtonHTMLAttributes,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import yaml from "js-yaml";
import { createPortal } from "react-dom";
import { api, AuthRequiredError, setUnauthorizedHandler } from "./apiClient";
import { ActionsLog } from "./components/dashboard/ActionsLog";
import { AgentLaunchPanel } from "./components/dashboard/AgentLaunchPanel";
import { ApprovalsPanel } from "./components/dashboard/ApprovalsPanel";
import { AppIcon } from "./components/dashboard/AppIcon";
import { EnrollmentsPanel } from "./components/dashboard/EnrollmentsPanel";
import { EventsPanel } from "./components/dashboard/EventsPanel";
import { PolicyActionBar } from "./components/dashboard/PolicyActionBar";
import { PolicyChangeDialog } from "./components/dashboard/PolicyChangeDialog";
import { PolicyDefaultsPanel } from "./components/dashboard/PolicyDefaultsPanel";
import { PolicyReviewRail } from "./components/dashboard/PolicyReviewRail";
import { PolicyRuleSection } from "./components/dashboard/PolicyRuleSection";
import { PolicyStudioShell, type PolicyStatusTone } from "./components/dashboard/PolicyStudioShell";
import { RuleCard } from "./components/dashboard/RuleCard";
import { ValidationIssueList } from "./components/dashboard/ValidationIssueList";
import {
  GuidedTourOverlay,
  HelpBar,
  HelpTab,
  TOUR_STEPS,
  firstTourStepIndexForTab,
  type TourFocusRect
} from "./components/dashboard/HelpExperience";
import { OverviewTab } from "./components/dashboard/OverviewTab";
import { ShellHeader } from "./components/dashboard/ShellHeader";
import { Sidebar } from "./components/dashboard/Sidebar";
import type { DashboardTabKey } from "./components/dashboard/TabRail";
import { SettingsPanel } from "./components/dashboard/SettingsPanel";
import { ErrorBoundary } from "./components/dashboard/ErrorBoundary";
import type {
  ApplyPolicyResponse,
  AuthMeResponse,
  DashboardActionItem,
  LoginResponse,
  PolicyDraft,
  PolicyVersion,
  StatsResponse,
  StatusSummary,
  TlsCertInfo,
  ValidationResult
} from "./dashboardTypes";
import { fmt } from "./dashboardUi";
import {
  emptyPolicyDocument,
  emptyProfilePolicy,
  nextRuleId,
  normalizePolicyDocument,
  type McpToolAction,
  type NetworkProtocol,
  type PolicyDocument,
  type ProfilePolicy
} from "./policyHelpers";
import { diffPolicyDocuments } from "./policyDiff";
import { isStaticDemoMode, resetStaticDemoState } from "./demo/demoBackend";
import {
  applyTheme,
  readThemePreference,
  resolveTheme,
  writeThemePreference,
  type ThemePreference
} from "./theme";

/** Operator actions fetched per page of the audit trail. */
const ACTIONS_PAGE_SIZE = 200;

type PortRuleCollectionKey = "network_allow" | "network_deny" | "url_allow" | "url_deny";
type PolicyPreviewMode = "active" | "generated";

function pluralize(count: number, singular: string, plural: string): string {
  return count === 1 ? singular : plural;
}

function summarizeFirstValue(values: string[], emptyLabel: string): string {
  if (!values.length) {
    return emptyLabel;
  }
  return values.length === 1 ? values[0] : `${values[0]} +${values.length - 1} more`;
}

function summarizeConfigured(
  count: number,
  singular: string,
  plural: string,
  emptyLabel: string
): string {
  if (!count) {
    return emptyLabel;
  }
  return `${count} ${pluralize(count, singular, plural)} configured`;
}

function PolicyIconButton({
  label,
  iconName,
  className,
  type = "button",
  ...props
}: {
  label: string;
  iconName: "add" | "remove";
  className?: string;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const classes = className
    ? `ghost icon-only-button policy-icon-button ${className}`
    : "ghost icon-only-button policy-icon-button";

  return (
    <button {...props} type={type} className={classes} aria-label={label} title={label}>
      <AppIcon name={iconName} className="app-icon-sm" />
      <span className="sr-only">{label}</span>
    </button>
  );
}

function PolicyTableHeader({ className, children }: { className: string; children: ReactNode }) {
  return <div className={`rule-table-head ${className}`}>{children}</div>;
}

const TAB_META: Record<DashboardTabKey, { title: string; description: string }> = {
  overview: {
    title: "Overview",
    description: "Health, decision throughput and hotspots across enrolled agents"
  },
  events: {
    title: "Live events",
    description: "Every allow, deny and observe decision, newest first"
  },
  approvals: {
    title: "Approvals",
    description: "MCP tool calls and resource reads waiting for an operator decision"
  },
  policy: {
    title: "Policy studio",
    description: "Edit, validate and roll out the enforcement policy"
  },
  enrollment: {
    title: "Enrollments",
    description: "Processes under Mercury control and the profile each one carries"
  },
  agents: {
    title: "Agents",
    description: "Launch and stop server-style agents under a Mercury profile"
  },
  settings: { title: "Settings", description: "Dashboard TLS certificate operations" },
  help: { title: "Help", description: "Guided tour, topic guides and quick reference" }
};

export function App() {
  const staticDemoMode = isStaticDemoMode();
  const [authUsername, setAuthUsername] = useState("admin");
  const [authPassword, setAuthPassword] = useState("");
  const [authPasswordConfirm, setAuthPasswordConfirm] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [setupRequired, setSetupRequired] = useState(false);
  const [showAuthHelp, setShowAuthHelp] = useState(false);

  const [showPasswordPanel, setShowPasswordPanel] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordConfirm, setNewPasswordConfirm] = useState("");
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);

  const [status, setStatus] = useState<StatusSummary | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [actions, setActions] = useState<DashboardActionItem[]>([]);
  const [actionsError, setActionsError] = useState<string | null>(null);
  const [actionsHasMore, setActionsHasMore] = useState(false);
  const [actionsLoadingMore, setActionsLoadingMore] = useState(false);
  const [panelRefreshNonce, setPanelRefreshNonce] = useState(0);

  const [policyDoc, setPolicyDoc] = useState<PolicyDocument>(emptyPolicyDocument());
  const [activePolicyDoc, setActivePolicyDoc] = useState<PolicyDocument>(emptyPolicyDocument());
  const [policyDirty, setPolicyDirty] = useState(false);
  const [activePolicyYaml, setActivePolicyYaml] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("default");
  const [draftId, setDraftId] = useState<string | null>(null);
  const [pendingApplyDraftId, setPendingApplyDraftId] = useState<string | null>(null);
  const [draftEtag, setDraftEtag] = useState<string | null>(null);
  const [savedDraftYaml, setSavedDraftYaml] = useState<string | null>(null);
  const [validatedDraftYaml, setValidatedDraftYaml] = useState<string | null>(null);
  const [validateResult, setValidateResult] = useState<ValidationResult | null>(null);
  const [policyMessage, setPolicyMessage] = useState<string | null>(null);
  const [portDrafts, setPortDrafts] = useState<Record<string, string>>({});
  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const [applyNote, setApplyNote] = useState("");
  const [pendingRollbackVersion, setPendingRollbackVersion] = useState<PolicyVersion | null>(null);
  const [rollbackNote, setRollbackNote] = useState("");
  const [policyActionBusy, setPolicyActionBusy] = useState(false);
  const [versionsCollapsed, setVersionsCollapsed] = useState(true);
  const [actionsCollapsed, setActionsCollapsed] = useState(true);
  const [policyPreviewMode, setPolicyPreviewMode] = useState<PolicyPreviewMode>("generated");
  const [collapsedRuleSections, setCollapsedRuleSections] = useState<Record<string, boolean>>({});

  const [activeTab, setActiveTab] = useState<DashboardTabKey>("overview");
  const [lastContentTab, setLastContentTab] = useState<DashboardTabKey>("overview");
  const [helpBarOpen, setHelpBarOpen] = useState(() => staticDemoMode);
  const [themePreference, setThemePreference] = useState<ThemePreference>(readThemePreference);
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() =>
    resolveTheme(readThemePreference())
  );
  const [tourStepIndex, setTourStepIndex] = useState<number | null>(null);
  const [tourFocusRect, setTourFocusRect] = useState<TourFocusRect | null>(null);
  const authHelpRef = useRef<HTMLDivElement | null>(null);
  const lastTourTargetRef = useRef<string | null>(null);

  const profileNames = useMemo(() => Object.keys(policyDoc.profiles), [policyDoc]);
  const currentProfileName = profileNames.includes(selectedProfile)
    ? selectedProfile
    : (profileNames[0] ?? "default");
  const currentProfile = policyDoc.profiles[currentProfileName] ?? emptyProfilePolicy();

  const generatedPolicyYaml = useMemo(
    () => yaml.dump(policyDoc, { lineWidth: 120, noRefs: true, sortKeys: false }),
    [policyDoc]
  );
  const activeTourStep = tourStepIndex == null ? null : TOUR_STEPS[tourStepIndex];
  const contextualHelpTab = activeTab === "help" ? lastContentTab : activeTab;
  const policyDiff = useMemo(
    () => diffPolicyDocuments(activePolicyDoc, policyDoc),
    [activePolicyDoc, policyDoc]
  );
  const hasPolicyChanges =
    policyDiff.added.length > 0 || policyDiff.removed.length > 0 || policyDiff.changed.length > 0;
  const policyStatus = useMemo<{ label: string; tone: PolicyStatusTone }>(() => {
    if (!hasPolicyChanges) {
      return { label: "Synced", tone: "synced" };
    }
    if (validateResult?.valid && validatedDraftYaml === generatedPolicyYaml) {
      return { label: "Validated", tone: "validated" };
    }
    return { label: "Unsaved edits", tone: "dirty" };
  }, [generatedPolicyYaml, hasPolicyChanges, validateResult, validatedDraftYaml]);
  const currentProfileRuleCount = useMemo(
    () =>
      currentProfile.file_allow.length +
      currentProfile.file_deny.length +
      currentProfile.exec_allow.length +
      currentProfile.exec_deny.length +
      currentProfile.network_allow.length +
      currentProfile.network_deny.length +
      currentProfile.url_allow.length +
      currentProfile.url_deny.length +
      (currentProfile.mcp?.servers.length ?? 0),
    [currentProfile]
  );
  const currentProfileRootCount = currentProfile.workspace_roots.length;
  const policySectionDetails = useMemo(
    () => [
      {
        id: "workspace-roots-section",
        count: currentProfile.workspace_roots.length,
        summary: summarizeFirstValue(
          currentProfile.workspace_roots,
          "No workspace roots configured"
        )
      },
      {
        id: "file-allow-section",
        count: currentProfile.file_allow.length,
        summary: summarizeConfigured(
          currentProfile.file_allow.length,
          "allow pattern",
          "allow patterns",
          "No file allow rules configured"
        )
      },
      {
        id: "file-deny-section",
        count: currentProfile.file_deny.length,
        summary: summarizeConfigured(
          currentProfile.file_deny.length,
          "deny pattern",
          "deny patterns",
          "No file deny rules configured"
        )
      },
      {
        id: "exec-allow-section",
        count: currentProfile.exec_allow.length,
        summary: summarizeConfigured(
          currentProfile.exec_allow.length,
          "exec allow rule",
          "exec allow rules",
          "No exec allow rules configured"
        )
      },
      {
        id: "exec-deny-section",
        count: currentProfile.exec_deny.length,
        summary: summarizeConfigured(
          currentProfile.exec_deny.length,
          "exec deny rule",
          "exec deny rules",
          "No exec deny rules configured"
        )
      },
      {
        id: "network-allow-section",
        count: currentProfile.network_allow.length,
        summary: summarizeConfigured(
          currentProfile.network_allow.length,
          "network allow rule",
          "network allow rules",
          "No network allow rules configured"
        )
      },
      {
        id: "network-deny-section",
        count: currentProfile.network_deny.length,
        summary: summarizeConfigured(
          currentProfile.network_deny.length,
          "network deny rule",
          "network deny rules",
          "No network deny rules configured"
        )
      },
      {
        id: "url-allow-section",
        count: currentProfile.url_allow.length,
        summary: summarizeConfigured(
          currentProfile.url_allow.length,
          "URL allow rule",
          "URL allow rules",
          "No URL allow rules configured"
        )
      },
      {
        id: "url-deny-section",
        count: currentProfile.url_deny.length,
        summary: summarizeConfigured(
          currentProfile.url_deny.length,
          "URL deny rule",
          "URL deny rules",
          "No URL deny rules configured"
        )
      },
      {
        id: "mcp-section",
        count: currentProfile.mcp?.servers.length ?? 0,
        summary: summarizeConfigured(
          currentProfile.mcp?.servers.length ?? 0,
          "MCP server",
          "MCP servers",
          "No MCP servers configured"
        )
      }
    ],
    [currentProfile]
  );
  const policySectionSummaryById = useMemo(
    () =>
      Object.fromEntries(
        policySectionDetails.map((section) => [section.id, section.summary] as const)
      ),
    [policySectionDetails]
  );
  const defaultExpandedRuleSection =
    policySectionDetails.find((section) => section.count > 0)?.id ?? "workspace-roots-section";

  function resetDashboardState(message: string | null) {
    setAuthenticated(false);
    setCsrfToken("");
    setAuthError(message);
    setAuthPassword("");
    setAuthPasswordConfirm("");
    setShowAuthHelp(false);
    setShowPasswordPanel(false);
    setCurrentPassword("");
    setNewPassword("");
    setNewPasswordConfirm("");
    setPasswordMessage(null);
    setStatus(null);
    setStatusError(null);
    setStats(null);
    setVersions([]);
    setActions([]);
    setActionsHasMore(false);
    setActionsError(null);
    setPanelRefreshNonce(0);
    setPolicyDoc(emptyPolicyDocument());
    setActivePolicyDoc(emptyPolicyDocument());
    setPolicyDirty(false);
    setActivePolicyYaml("");
    setSelectedProfile("default");
    setDraftId(null);
    setPendingApplyDraftId(null);
    setDraftEtag(null);
    setSavedDraftYaml(null);
    setValidatedDraftYaml(null);
    setValidateResult(null);
    setPolicyMessage(null);
    setPortDrafts({});
    setShowApplyConfirm(false);
    setApplyNote("");
    setPendingRollbackVersion(null);
    setRollbackNote("");
    setPolicyActionBusy(false);
    setVersionsCollapsed(true);
    setActionsCollapsed(true);
    setPolicyPreviewMode("generated");
    setCollapsedRuleSections({});
    setActiveTab("overview");
    setLastContentTab("overview");
    setHelpBarOpen(false);
    closeTour();
  }

  async function probeAuthState() {
    try {
      const me = await api<AuthMeResponse>("/auth/me");
      setSetupRequired(me.setup_required);
      if (me.username) {
        setAuthUsername(me.username);
      }
      if (me.authenticated) {
        setAuthenticated(true);
        setCsrfToken(me.csrf_token ?? "");
      } else {
        resetDashboardState(null);
      }
    } catch (err) {
      resetDashboardState((err as Error).message);
    }
  }

  function handleAuthExpiry(err: unknown): boolean {
    return err instanceof AuthRequiredError;
  }

  useEffect(() => {
    let cancelled = false;
    setUnauthorizedHandler(() => {
      void (async () => {
        try {
          const me = await api<AuthMeResponse>("/auth/me", { suppressAuthRedirect: true });
          if (cancelled) {
            return;
          }
          if (me.authenticated) {
            setAuthenticated(true);
            setCsrfToken(me.csrf_token ?? "");
            return;
          }
        } catch {
          // Fall through and reset state below.
        }

        if (!cancelled) {
          resetDashboardState("Session expired, please log in again.");
        }
      })();
    });
    return () => {
      cancelled = true;
      setUnauthorizedHandler(null);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function refreshStatus() {
    try {
      const next = await api<StatusSummary>("/status/summary");
      setStatus(next);
      setStatusError(null);
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setStatusError((err as Error).message);
    }
  }

  async function refreshStats() {
    try {
      const response = await api<StatsResponse>("/events/stats");
      setStats(response);
    } catch (err) {
      if (handleAuthExpiry(err)) return;
    }
  }

  async function refreshPolicy(force = false): Promise<boolean> {
    if (policyDirty && !force) {
      return false;
    }

    try {
      const response = await api<{ yaml: string; version: string }>("/policy/active");
      setActivePolicyYaml(response.yaml);

      const parsed = normalizePolicyDocument(yaml.load(response.yaml));
      setActivePolicyDoc(parsed);
      setPolicyDoc(parsed);
      setPolicyDirty(false);
      setPortDrafts({});
      setDraftId(null);
      setPendingApplyDraftId(null);
      setDraftEtag(null);
      setSavedDraftYaml(null);
      setValidatedDraftYaml(null);
      setValidateResult(null);

      const nextProfile = Object.keys(parsed.profiles)[0] ?? "default";
      setSelectedProfile((previous) => (parsed.profiles[previous] ? previous : nextProfile));
      return true;
    } catch (err) {
      if (handleAuthExpiry(err)) return false;
      setPolicyMessage(`Policy refresh failed: ${(err as Error).message}`);
      return false;
    }
  }

  async function refreshVersions() {
    try {
      const response = await api<PolicyVersion[]>("/policy/versions");
      setVersions(response);
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setPolicyMessage(`Version history refresh failed: ${(err as Error).message}`);
    }
  }

  async function refreshActions() {
    try {
      const response = await api<DashboardActionItem[]>(`/actions?limit=${ACTIONS_PAGE_SIZE}`);
      setActions(response);
      setActionsHasMore(response.length >= ACTIONS_PAGE_SIZE);
      setActionsError(null);
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      // UX-2: surface the failure so operators can distinguish "no actions" from
      // "action history failed to load" — critical for security audit workflows.
      setActionsError((err as Error).message);
    }
  }

  async function loadMoreActions() {
    const oldest = actions.length ? actions[actions.length - 1].id : null;
    if (oldest == null) {
      return;
    }
    setActionsLoadingMore(true);
    try {
      const page = await api<DashboardActionItem[]>(
        `/actions?limit=${ACTIONS_PAGE_SIZE}&before_id=${oldest}`
      );
      setActions((previous) => {
        const seen = new Set(previous.map((item) => item.id));
        return [...previous, ...page.filter((item) => !seen.has(item.id))];
      });
      setActionsHasMore(page.length >= ACTIONS_PAGE_SIZE);
      setActionsError(null);
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setActionsError((err as Error).message);
    } finally {
      setActionsLoadingMore(false);
    }
  }

  async function refreshAll() {
    setPanelRefreshNonce((value) => value + 1);
    await Promise.allSettled([
      refreshStatus(),
      refreshStats(),
      refreshPolicy(),
      refreshVersions(),
      refreshActions()
    ]);
  }

  function openHelpHub() {
    setHelpBarOpen(false);
    setActiveTab("help");
  }

  function startTour(stepIndex = 0) {
    setHelpBarOpen(false);
    setTourStepIndex(stepIndex);
  }

  function startTourForTab(tab: DashboardTabKey) {
    startTour(firstTourStepIndexForTab(tab));
  }

  function closeTour() {
    setTourStepIndex(null);
    setTourFocusRect(null);
    lastTourTargetRef.current = null;
  }

  function previousTourStep() {
    if (tourStepIndex == null) {
      return;
    }
    setTourStepIndex(Math.max(tourStepIndex - 1, 0));
  }

  function nextTourStep() {
    if (tourStepIndex == null) {
      setTourStepIndex(0);
      return;
    }
    if (tourStepIndex >= TOUR_STEPS.length - 1) {
      closeTour();
      return;
    }
    setTourStepIndex(tourStepIndex + 1);
  }

  function markPolicyEdited() {
    setPolicyDirty(true);
    setValidateResult(null);
  }

  function mutateCurrentProfile(mutator: (profile: ProfilePolicy) => ProfilePolicy) {
    markPolicyEdited();
    setPolicyDoc((previous) => {
      const existingNames = Object.keys(previous.profiles);
      const targetName = previous.profiles[currentProfileName]
        ? currentProfileName
        : (existingNames[0] ?? "default");
      const original = previous.profiles[targetName] ?? emptyProfilePolicy();
      const updated = mutator({
        ...original,
        workspace_roots: [...original.workspace_roots],
        file_allow: original.file_allow.map((rule) => ({ ...rule })),
        file_deny: original.file_deny.map((rule) => ({ ...rule })),
        exec_allow: original.exec_allow.map((rule) => ({ ...rule })),
        exec_deny: original.exec_deny.map((rule) => ({ ...rule })),
        network_allow: original.network_allow.map((rule) => ({ ...rule })),
        network_deny: original.network_deny.map((rule) => ({ ...rule })),
        url_allow: original.url_allow.map((rule) => ({ ...rule })),
        url_deny: original.url_deny.map((rule) => ({ ...rule })),
        mcp: original.mcp
          ? {
              ...original.mcp,
              servers: original.mcp.servers.map((server) => ({
                ...server,
                tools: {
                  allow: [...server.tools.allow],
                  deny: [...server.tools.deny],
                  require_approval: [...server.tools.require_approval]
                }
              }))
            }
          : undefined,
        enforcement: original.enforcement ? { ...original.enforcement } : undefined
      });
      return {
        ...previous,
        profiles: {
          ...previous.profiles,
          [targetName]: updated
        }
      };
    });
  }

  function mutatePolicyDocument(mutator: (policy: PolicyDocument) => PolicyDocument) {
    markPolicyEdited();
    setPolicyDoc((previous) => mutator(previous));
  }

  function rowToken(section: string, index: number): string {
    return `${section}:${index}`;
  }

  function rowKey(section: string, index: number): string {
    return `${currentProfileName}:${rowToken(section, index)}`;
  }

  function portDraftKey(list: PortRuleCollectionKey, ruleId: string): string {
    return `${currentProfileName}:${list}:${ruleId}`;
  }

  function getPortInputValue(list: PortRuleCollectionKey, ruleId: string, port?: number): string {
    const key = portDraftKey(list, ruleId);
    if (Object.prototype.hasOwnProperty.call(portDrafts, key)) {
      return portDrafts[key];
    }
    return port == null ? "" : String(port);
  }

  function setPortInputDraft(list: PortRuleCollectionKey, ruleId: string, value: string) {
    markPolicyEdited();
    const key = portDraftKey(list, ruleId);
    setPortDrafts((previous) => ({
      ...previous,
      [key]: value
    }));
  }

  function commitPortInput(list: PortRuleCollectionKey, index: number, ruleId: string) {
    const key = portDraftKey(list, ruleId);
    const raw = portDrafts[key] ?? "";
    const trimmed = raw.trim();
    const parsed = Number(trimmed);
    mutateCurrentProfile((profile) => {
      const next = [...profile[list]];
      next[index] = {
        ...next[index],
        port: trimmed.length > 0 && Number.isFinite(parsed) ? parsed : undefined
      };
      return {
        ...profile,
        [list]: next
      };
    });
    setPortDrafts((previous) => {
      if (!Object.prototype.hasOwnProperty.call(previous, key)) {
        return previous;
      }
      const updated = { ...previous };
      delete updated[key];
      return updated;
    });
  }

  async function handleLogin(event: FormEvent) {
    event.preventDefault();
    setAuthError(null);
    setShowAuthHelp(false);

    try {
      const response = await api<LoginResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: authUsername.trim(), password: authPassword })
      });
      setCsrfToken(response.csrf_token);
      setSetupRequired(false);
      setAuthenticated(true);
      await refreshAll();
    } catch (err) {
      resetDashboardState((err as Error).message);
    }
  }

  async function handleSignup(event: FormEvent) {
    event.preventDefault();
    setAuthError(null);
    setShowAuthHelp(false);

    if (authPassword !== authPasswordConfirm) {
      setAuthError("Password confirmation does not match.");
      return;
    }

    try {
      const response = await api<LoginResponse>("/auth/signup", {
        method: "POST",
        body: JSON.stringify({
          username: authUsername.trim(),
          password: authPassword,
          confirm_password: authPasswordConfirm
        })
      });
      setCsrfToken(response.csrf_token);
      setSetupRequired(false);
      setAuthenticated(true);
      await refreshAll();
    } catch (err) {
      resetDashboardState((err as Error).message);
    }
  }

  async function handleLogout() {
    try {
      // SG-1: send CSRF token on logout so the server can enforce CSRF protection.
      await api<{ ok: boolean }>("/auth/logout", {
        method: "POST",
        headers: csrfToken ? { "x-csrf-token": csrfToken } : {}
      });
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setAuthError((err as Error).message);
      }
    } finally {
      resetDashboardState(null);
    }
  }

  async function handleResetHostedDemo() {
    if (!staticDemoMode) {
      return;
    }

    resetStaticDemoState();
    setAuthError(null);
    setPasswordMessage(null);
    setShowPasswordPanel(false);
    setShowAuthHelp(false);
    setHelpBarOpen(true);
    setActiveTab("overview");
    setLastContentTab("overview");
    closeTour();
    await probeAuthState();
    await refreshAll();
  }

  async function handlePasswordChange(event: FormEvent) {
    event.preventDefault();
    setPasswordMessage(null);

    if (newPassword !== newPasswordConfirm) {
      setPasswordMessage("New password confirmation does not match.");
      return;
    }

    try {
      const response = await api<LoginResponse>("/auth/password/change", {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
          confirm_password: newPasswordConfirm
        })
      });

      setCsrfToken(response.csrf_token);
      setCurrentPassword("");
      setNewPassword("");
      setNewPasswordConfirm("");
      setShowPasswordPanel(false);
      setPasswordMessage("Password updated.");
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setPasswordMessage(`Password update failed: ${(err as Error).message}`);
    }
  }

  async function saveDraft(options?: {
    suppressSuccessMessage?: boolean;
  }): Promise<PolicyDraft | null> {
    try {
      const payload = {
        id: draftId ?? undefined,
        etag: draftEtag ?? undefined,
        document: policyDoc
      };

      const draft = await api<PolicyDraft>("/policy/drafts", {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken
        },
        body: JSON.stringify(payload)
      });

      setDraftId(draft.id);
      setDraftEtag(draft.etag);
      setSavedDraftYaml(generatedPolicyYaml);
      setValidatedDraftYaml(null);
      setValidateResult(null);
      if (!options?.suppressSuccessMessage) {
        setPolicyMessage(`Draft saved (${draft.id.slice(0, 8)})`);
      }
      return draft;
    } catch (err) {
      if (handleAuthExpiry(err)) {
        return null;
      }
      setPolicyMessage(`Draft save failed: ${(err as Error).message}`);
      return null;
    }
  }

  async function ensureDraftSaved(): Promise<string | null> {
    if (draftId && savedDraftYaml != null && savedDraftYaml === generatedPolicyYaml) {
      return draftId;
    }

    const draft = await saveDraft({ suppressSuccessMessage: true });
    return draft?.id ?? null;
  }

  async function validateDraft() {
    const draftToValidate = await ensureDraftSaved();
    if (!draftToValidate) {
      return;
    }

    try {
      const result = await api<ValidationResult>(`/policy/drafts/${draftToValidate}/validate`, {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken
        }
      });
      setValidateResult(result);
      setValidatedDraftYaml(generatedPolicyYaml);
      setPolicyMessage(result.valid ? "Validation passed" : "Validation failed");
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setPolicyMessage(`Validation failed: ${(err as Error).message}`);
    }
  }

  async function requestApplyConfirmation() {
    const draftToApply = await ensureDraftSaved();
    if (!draftToApply) {
      return;
    }
    setPendingApplyDraftId(draftToApply);
    setApplyNote("");
    setShowApplyConfirm(true);
  }

  async function applyDraft(note?: string, targetDraftId?: string | null) {
    const draftToApply = targetDraftId ?? pendingApplyDraftId ?? draftId;
    if (!draftToApply) {
      setPolicyMessage("Save a draft first.");
      return;
    }

    try {
      setPolicyActionBusy(true);
      const result = await api<ApplyPolicyResponse>(`/policy/drafts/${draftToApply}/apply`, {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken
        },
        body: JSON.stringify({
          note: note?.trim() || undefined
        })
      });
      if (!result.success) {
        setPolicyMessage(`Apply rejected: ${result.errors.join(" | ")}`);
        return;
      }
      const warningNote = result.warnings?.length
        ? ` (warning: ${result.warnings.join("; ")})`
        : "";
      const shortId = result.version_id?.slice(0, 8) ?? "unknown";
      setPolicyMessage(`Policy applied (version ${shortId})${warningNote}`);
      setPolicyDirty(false);
      setVersionsCollapsed(false);
      await refreshPolicy(true);
      await refreshStatus();
      await refreshStats();
      await refreshVersions();
      await refreshActions();
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setPolicyMessage(`Apply failed: ${(err as Error).message}`);
    } finally {
      setPolicyActionBusy(false);
      setShowApplyConfirm(false);
      setPendingApplyDraftId(null);
      setApplyNote("");
    }
  }

  function requestRollbackConfirmation(version: PolicyVersion) {
    setRollbackNote("");
    setPendingRollbackVersion(version);
  }

  async function rollback(versionId: string, note?: string) {
    try {
      setPolicyActionBusy(true);
      const result = await api<ApplyPolicyResponse>(`/policy/versions/${versionId}/rollback`, {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken
        },
        body: JSON.stringify({
          note: note?.trim() || undefined
        })
      });
      if (!result.success) {
        setPolicyMessage(`Rollback rejected: ${result.errors.join(" | ")}`);
        return;
      }
      setPolicyMessage(
        `Rolled back to ${versionId.slice(0, 8)} → new version ${result.version_id?.slice(0, 8) ?? "unknown"}`
      );
      setPolicyDirty(false);
      setVersionsCollapsed(false);
      await refreshPolicy(true);
      await refreshStatus();
      await refreshStats();
      await refreshVersions();
      await refreshActions();
    } catch (err) {
      if (handleAuthExpiry(err)) return;
      setPolicyMessage(`Rollback failed: ${(err as Error).message}`);
    } finally {
      setPolicyActionBusy(false);
      setPendingRollbackVersion(null);
      setRollbackNote("");
    }
  }

  async function discardLocalPolicyEdits() {
    setPolicyDirty(false);
    setPortDrafts({});
    setSavedDraftYaml(null);
    setValidatedDraftYaml(null);
    setValidateResult(null);
    const refreshed = await refreshPolicy(true);
    if (refreshed) {
      setPolicyMessage("Local edits discarded. Reloaded active policy.");
    }
  }

  function isRuleSectionCollapsed(id: string): boolean {
    return collapsedRuleSections[id] ?? id !== defaultExpandedRuleSection;
  }

  function toggleRuleSection(id: string) {
    setCollapsedRuleSections((previous) => ({
      ...previous,
      [id]: !(previous[id] ?? id !== defaultExpandedRuleSection)
    }));
  }

  useEffect(() => {
    void probeAuthState();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (activeTab !== "help") {
      setLastContentTab(activeTab);
    }
  }, [activeTab]);

  useEffect(() => {
    if (!authenticated) {
      return;
    }

    void refreshAll();

    const poll = window.setInterval(() => {
      void refreshStatus();
      void refreshStats();
    }, 5000);

    return () => {
      window.clearInterval(poll);
    };
  }, [authenticated]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!showAuthHelp) {
      return undefined;
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (authHelpRef.current && !authHelpRef.current.contains(event.target as Node)) {
        setShowAuthHelp(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowAuthHelp(false);
      }
    };

    window.addEventListener("pointerdown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [showAuthHelp]);

  useEffect(() => {
    if (!showPasswordPanel) {
      return undefined;
    }

    const previousOverflow = document.body.style.overflow;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowPasswordPanel(false);
      }
    };

    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [showPasswordPanel]);

  useEffect(() => {
    if (policyDirty) {
      return;
    }

    setCollapsedRuleSections(
      Object.fromEntries(
        policySectionDetails.map((section) => [
          section.id,
          section.id !== defaultExpandedRuleSection
        ])
      )
    );
  }, [
    activePolicyYaml,
    currentProfileName,
    defaultExpandedRuleSection,
    policyDirty,
    policySectionDetails
  ]);

  useEffect(() => {
    if (!activeTourStep) {
      lastTourTargetRef.current = null;
      return;
    }

    if (activeTab !== activeTourStep.tab) {
      setActiveTab(activeTourStep.tab);
      return;
    }

    const target = document.querySelector<HTMLElement>(activeTourStep.selector);
    if (!target) {
      return;
    }

    const targetKey = `${activeTourStep.tab}:${activeTourStep.selector}`;
    if (lastTourTargetRef.current !== targetKey) {
      target.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
      lastTourTargetRef.current = targetKey;
    }
  }, [activeTourStep, activeTab]);

  useEffect(() => {
    if (!activeTourStep) {
      setTourFocusRect(null);
      return;
    }

    const updateFocusRect = () => {
      const target = document.querySelector<HTMLElement>(activeTourStep.selector);
      if (!target) {
        setTourFocusRect(null);
        return;
      }
      const rect = target.getBoundingClientRect();
      setTourFocusRect({
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height
      });
    };

    const frame = window.requestAnimationFrame(updateFocusRect);
    window.addEventListener("resize", updateFocusRect);
    window.addEventListener("scroll", updateFocusRect, true);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", updateFocusRect);
      window.removeEventListener("scroll", updateFocusRect, true);
    };
  }, [
    activeTourStep,
    activeTab,
    versions.length,
    showPasswordPanel,
    policyDirty,
    generatedPolicyYaml
  ]);

  useEffect(() => {
    applyTheme(themePreference);
    setResolvedTheme(resolveTheme(themePreference));
    if (themePreference !== "system" || !window.matchMedia) {
      return undefined;
    }
    // Follow OS-level changes until the operator picks a theme explicitly.
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      applyTheme("system");
      setResolvedTheme(resolveTheme("system"));
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [themePreference]);

  function toggleTheme() {
    const next = resolvedTheme === "dark" ? "light" : "dark";
    writeThemePreference(next);
    setThemePreference(next);
  }

  if (!authenticated) {
    return (
      <main className="login-shell" data-testid="login-shell">
        <div className="login-glow" aria-hidden="true" />
        <form
          className="login-card"
          data-testid={setupRequired ? "signup-form" : "login-form"}
          onSubmit={setupRequired ? handleSignup : handleLogin}
        >
          <div className="login-brand">
            <span className="brand-mark brand-mark-lg" aria-hidden="true">
              <AppIcon name="mercury" />
            </span>
            <h1>{setupRequired ? "Create the admin account" : "Sign in to Mercury"}</h1>
            <p className="subtle">
              {setupRequired
                ? "No dashboard password is set yet. Choose one for the configured admin user."
                : staticDemoMode
                  ? "Static guided demo with seeded data. Explore the dashboard without installing Mercury."
                  : "Policy observability, decision telemetry and safe allow/deny management."}
            </p>
            {staticDemoMode && !setupRequired ? (
              <p className="meta">Use any non-empty password to enter the hosted demo.</p>
            ) : null}
          </div>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              data-testid="auth-username-input"
              value={authUsername}
              onChange={(event) => setAuthUsername(event.target.value)}
              placeholder="admin"
              autoComplete="username"
              disabled={setupRequired}
            />
          </div>
          <div className="field auth-password-field" ref={authHelpRef}>
            <div className="auth-label-row">
              <label htmlFor="password">Password</label>
              {!setupRequired && !staticDemoMode ? (
                <button
                  className="link-button auth-help-trigger"
                  type="button"
                  data-testid="auth-help-toggle"
                  aria-label="Show password help"
                  aria-controls="auth-help-popover"
                  aria-expanded={showAuthHelp}
                  aria-haspopup="dialog"
                  title="Show password help"
                  onClick={() => setShowAuthHelp((value) => !value)}
                >
                  Forgot password?
                </button>
              ) : null}
            </div>
            <label className="input-with-icon">
              <AppIcon name="lock" className="app-icon-sm" />
              <input
                id="password"
                type="password"
                data-testid="auth-password-input"
                value={authPassword}
                onChange={(event) => setAuthPassword(event.target.value)}
                placeholder={setupRequired ? "At least 12 characters" : "Dashboard password"}
                autoComplete={setupRequired ? "new-password" : "current-password"}
              />
            </label>
            {!setupRequired && !staticDemoMode && showAuthHelp ? (
              <div
                id="auth-help-popover"
                className="auth-help-popover"
                data-testid="auth-help-popover"
                role="dialog"
                aria-modal="false"
                aria-labelledby="auth-help-title"
              >
                <p id="auth-help-title" className="auth-help-title">
                  Locked out? Rotate the password on the host:
                </p>
                <code className="auth-help-command">
                  sudo mercury-policy dashboard-password rotate --file
                  /etc/mercury/dashboard.password --username admin
                </code>
              </div>
            ) : null}
          </div>
          {setupRequired ? (
            <div className="field">
              <label htmlFor="password-confirm">Confirm password</label>
              <label className="input-with-icon">
                <AppIcon name="lock" className="app-icon-sm" />
                <input
                  id="password-confirm"
                  type="password"
                  data-testid="auth-password-confirm-input"
                  value={authPasswordConfirm}
                  onChange={(event) => setAuthPasswordConfirm(event.target.value)}
                  placeholder="Repeat the password"
                  autoComplete="new-password"
                />
              </label>
            </div>
          ) : null}
          {authError ? (
            <p className="callout callout-danger" role="alert">
              <AppIcon name="alert" className="app-icon-sm" />
              <span>{authError}</span>
            </p>
          ) : null}
          <button
            type="submit"
            className="btn-block"
            data-testid={setupRequired ? "signup-submit" : "login-submit"}
          >
            {setupRequired ? "Create account & sign in" : "Sign in"}
          </button>
          {setupRequired ? (
            <p className="meta login-footnote">
              Stored as an Argon2 hash in the configured password file. You can rotate it later.
            </p>
          ) : null}
        </form>
        <p className="login-footer">
          <AppIcon name="lock" className="app-icon-sm" />
          <span>Mercury runtime security dashboard</span>
        </p>
      </main>
    );
  }

  return (
    <ErrorBoundary label="Dashboard">
      <main className="app-shell">
        <Sidebar
          activeTab={activeTab}
          onSelect={setActiveTab}
          pendingApprovals={status?.pending_mcp_approvals ?? 0}
          daemonUp={status ? status.daemon_up : null}
          daemonDetail={
            status
              ? `${status.backend_mode} · policy ${status.policy_version}`
              : "Waiting for status…"
          }
          username={authUsername}
          showPasswordPanel={showPasswordPanel}
          onTogglePasswordPanel={() => setShowPasswordPanel((value) => !value)}
          onLogout={() => void handleLogout()}
        />
        <div className="app-main">
          <ShellHeader
            title={TAB_META[activeTab].title}
            description={TAB_META[activeTab].description}
            onRefresh={() => void refreshAll()}
            onOpenHelp={openHelpHub}
            onToggleTheme={toggleTheme}
            theme={resolvedTheme}
            onResetDemo={() => void handleResetHostedDemo()}
            staticDemoMode={staticDemoMode}
          />
          <div className="app-layout" data-testid="app-layout">
            {activeTab === "overview" ? (
              <OverviewTab
                status={status}
                statusError={statusError}
                stats={stats}
                onNavigate={setActiveTab}
              />
            ) : null}

            <div hidden={activeTab !== "events"}>
              <EventsPanel
                csrfToken={csrfToken}
                policyDoc={activePolicyDoc}
                refreshNonce={panelRefreshNonce}
                onPolicyChanged={() => {
                  void refreshPolicy();
                  void refreshStatus();
                  void refreshStats();
                  void refreshVersions();
                  void refreshActions();
                }}
              />
            </div>

            <div hidden={activeTab !== "approvals"}>
              <ApprovalsPanel
                csrfToken={csrfToken}
                refreshNonce={panelRefreshNonce}
                onResolved={() => {
                  void refreshActions();
                  void refreshStats();
                }}
              />
            </div>

            {activeTab === "policy" ? (
              <PolicyStudioShell
                statusLabel={policyStatus.label}
                statusTone={policyStatus.tone}
                subtitle="Edit the draft with structured forms."
                statusMeta={
                  <span className="policy-status-note" data-testid="policy-dirty-state">
                    {hasPolicyChanges
                      ? "Draft differs from the active policy."
                      : "Active policy and editor are aligned."}
                  </span>
                }
                actionBar={
                  <PolicyActionBar
                    onSave={() => void saveDraft()}
                    onValidate={() => void validateDraft()}
                    onApply={() => requestApplyConfirmation()}
                    onDiscard={() => void discardLocalPolicyEdits()}
                    discardDisabled={!policyDirty}
                  />
                }
                feedback={
                  policyMessage ? (
                    <p className="meta policy-feedback-message" data-testid="policy-message">
                      {policyMessage}
                    </p>
                  ) : undefined
                }
                validation={
                  validateResult ? (
                    <div className="validation-box" data-testid="policy-validation-box">
                      <p
                        className={
                          validateResult.valid ? "ok validation-state" : "error validation-state"
                        }
                      >
                        <AppIcon
                          name={validateResult.valid ? "check" : "warning"}
                          className="app-icon-sm"
                        />
                        <span>
                          {validateResult.valid ? "Validation passed" : "Validation failed"}
                        </span>
                      </p>
                      <ValidationIssueList
                        issues={validateResult.warnings}
                        tone="warn"
                        title="Warnings"
                      />
                      <ValidationIssueList
                        issues={validateResult.errors}
                        tone="error"
                        title="Errors"
                      />
                    </div>
                  ) : undefined
                }
                defaultsPanel={
                  <PolicyDefaultsPanel
                    version={policyDoc.version}
                    decision={policyDoc.defaults.decision}
                    failMode={policyDoc.defaults.fail_mode}
                    auditLevel={policyDoc.defaults.audit_level}
                    fileEnforcement={policyDoc.defaults.enforcement.file}
                    processEnforcement={policyDoc.defaults.enforcement.process}
                    networkEnforcement={policyDoc.defaults.enforcement.network}
                    onVersionChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        version: value
                      }))
                    }
                    onDecisionChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          decision: value
                        }
                      }))
                    }
                    onFailModeChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          fail_mode: value
                        }
                      }))
                    }
                    onAuditLevelChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          audit_level: value
                        }
                      }))
                    }
                    onFileEnforcementChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          enforcement: {
                            ...previous.defaults.enforcement,
                            file: value
                          }
                        }
                      }))
                    }
                    onProcessEnforcementChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          enforcement: {
                            ...previous.defaults.enforcement,
                            process: value
                          }
                        }
                      }))
                    }
                    onNetworkEnforcementChange={(value) =>
                      mutatePolicyDocument((previous) => ({
                        ...previous,
                        defaults: {
                          ...previous.defaults,
                          enforcement: {
                            ...previous.defaults.enforcement,
                            network: value
                          }
                        }
                      }))
                    }
                  />
                }
                profileToolbar={
                  <section
                    className="policy-surface policy-profile-surface"
                    data-testid="profile-toolbar"
                  >
                    <div className="policy-profile-copy">
                      <p className="policy-kicker">Editing profile</p>
                      <div className="policy-profile-meta">
                        <p className="policy-profile-name" data-testid="policy-profile-name">
                          {currentProfileName}
                        </p>
                        <div className="policy-profile-stats" aria-label="Profile stats">
                          <span className="pill pill-neutral">
                            {currentProfileRootCount}{" "}
                            {pluralize(currentProfileRootCount, "root", "roots")}
                          </span>
                          <span className="pill pill-accent">
                            {currentProfileRuleCount}{" "}
                            {pluralize(currentProfileRuleCount, "rule", "rules")}
                          </span>
                        </div>
                      </div>
                    </div>
                    <label className="field policy-profile-picker">
                      <span>Choose profile</span>
                      <select
                        data-testid="profile-select"
                        value={currentProfileName}
                        onChange={(event) => setSelectedProfile(event.target.value)}
                      >
                        {profileNames.map((name) => (
                          <option key={name} value={name}>
                            {name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <div className="policy-profile-actions">
                      <PolicyIconButton
                        data-testid="remove-profile-button"
                        label="Remove profile"
                        iconName="remove"
                        onClick={() => {
                          if (profileNames.length <= 1) {
                            return;
                          }
                          mutatePolicyDocument((previous) => {
                            const nextProfiles = { ...previous.profiles };
                            delete nextProfiles[currentProfileName];
                            return {
                              ...previous,
                              profiles: nextProfiles
                            };
                          });
                          const fallback =
                            profileNames.find((name) => name !== currentProfileName) ?? "default";
                          setSelectedProfile(fallback);
                        }}
                        disabled={profileNames.length <= 1}
                      />
                      <PolicyIconButton
                        data-testid="add-profile-button"
                        label="Add profile"
                        iconName="add"
                        onClick={() => {
                          const nextName = window.prompt("New profile name", "new-profile");
                          if (!nextName) {
                            return;
                          }
                          const trimmed = nextName.trim();
                          if (!trimmed) {
                            setPolicyMessage("Profile name cannot be empty");
                            return;
                          }
                          mutatePolicyDocument((previous) => {
                            if (previous.profiles[trimmed]) {
                              setPolicyMessage(`Profile '${trimmed}' already exists`);
                              return previous;
                            }
                            return {
                              ...previous,
                              profiles: {
                                ...previous.profiles,
                                [trimmed]: emptyProfilePolicy()
                              }
                            };
                          });
                          setSelectedProfile(trimmed);
                        }}
                      />
                    </div>
                  </section>
                }
                reviewRail={
                  <PolicyReviewRail
                    previewMode={policyPreviewMode}
                    onPreviewModeChange={setPolicyPreviewMode}
                    activePolicyYaml={activePolicyYaml}
                    generatedPolicyYaml={generatedPolicyYaml}
                    versionsSection={
                      <article
                        className="card panel policy-versions-panel versions"
                        data-testid="policy-versions-panel"
                      >
                        <div className="card-header card-header-actions">
                          <div className="card-header-copy">
                            <h3 className="heading-with-icon">
                              <AppIcon name="history" className="app-icon-lg" />
                              <span>Versioned Rollback</span>
                            </h3>
                            <p>Re-apply any historical policy version</p>
                          </div>
                          <div className="card-header-controls">
                            <button
                              className="ghost icon-only-button"
                              type="button"
                              onClick={() => setVersionsCollapsed((value) => !value)}
                              aria-expanded={!versionsCollapsed}
                              aria-controls="policy-versions-content"
                              aria-label={
                                versionsCollapsed
                                  ? "Expand version history"
                                  : "Collapse version history"
                              }
                              title={
                                versionsCollapsed
                                  ? "Expand version history"
                                  : "Collapse version history"
                              }
                              data-testid="versions-collapse-button"
                            >
                              <AppIcon name="chevron" className="app-icon-chevron" />
                              <span className="sr-only">
                                {versionsCollapsed
                                  ? "Expand version history"
                                  : "Collapse version history"}
                              </span>
                            </button>
                          </div>
                        </div>
                        <div id="policy-versions-content" hidden={versionsCollapsed}>
                          <ul data-testid="policy-versions-list">
                            {versions.map((version) => (
                              <li key={version.id} data-testid={`policy-version-${version.id}`}>
                                <div>
                                  <p>
                                    <strong title={version.id}>{version.id.slice(0, 12)}</strong>
                                    {version.active ? (
                                      <span className="pill pill-allow">active</span>
                                    ) : null}
                                  </p>
                                  <p className="meta">
                                    {fmt(version.created_at)} · {version.created_by} ·{" "}
                                    {version.summary}
                                  </p>
                                </div>
                                <button
                                  className="ghost"
                                  data-testid={`rollback-${version.id}`}
                                  onClick={() => requestRollbackConfirmation(version)}
                                >
                                  <span className="button-with-icon">
                                    <AppIcon name="undo" className="app-icon-sm" />
                                    <span>Rollback</span>
                                  </span>
                                </button>
                              </li>
                            ))}
                          </ul>
                        </div>
                        {versionsCollapsed ? (
                          <p
                            className="meta collapsible-summary"
                            data-testid="versions-collapsed-summary"
                          >
                            {versions.length
                              ? `${versions.length} versions hidden.`
                              : "Section collapsed."}
                          </p>
                        ) : null}
                      </article>
                    }
                    actionsSection={
                      <ActionsLog
                        actions={actions}
                        collapsed={actionsCollapsed}
                        onToggleCollapsed={() => setActionsCollapsed((value) => !value)}
                        error={actionsError}
                        onRetry={() => void refreshActions()}
                        hasMore={actionsHasMore}
                        loadingMore={actionsLoadingMore}
                        onLoadMore={() => void loadMoreActions()}
                      />
                    }
                  />
                }
              >
                <PolicyRuleSection
                  title="Workspace Roots"
                  iconName="file"
                  count={currentProfile.workspace_roots.length}
                  summary={policySectionSummaryById["workspace-roots-section"]}
                  collapsed={isRuleSectionCollapsed("workspace-roots-section")}
                  onToggleCollapsed={() => toggleRuleSection("workspace-roots-section")}
                  addLabel="Add Root"
                  testId="workspace-roots-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      workspace_roots: [...profile.workspace_roots, "/workspace"]
                    }))
                  }
                >
                  {currentProfile.workspace_roots.length ? (
                    <PolicyTableHeader className="list-row">
                      <span>Path</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.workspace_roots.map((root, index) => (
                    <RuleCard
                      className="rule-card-row"
                      key={rowKey("workspace_roots", index)}
                      testId={`workspace-root-row-${index}`}
                    >
                      <div className="list-row">
                        <input
                          data-testid={`workspace-root-input-${index}`}
                          value={root}
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.workspace_roots];
                              next[index] = event.target.value;
                              return { ...profile, workspace_roots: next };
                            })
                          }
                        />
                        <PolicyIconButton
                          data-testid={`workspace-root-remove-${index}`}
                          label={`Remove workspace root ${index + 1}`}
                          iconName="remove"
                          onClick={() =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              workspace_roots: profile.workspace_roots.filter(
                                (_, itemIndex) => itemIndex !== index
                              )
                            }))
                          }
                        />
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="File Allow Rules"
                  iconName="file"
                  count={currentProfile.file_allow.length}
                  summary={policySectionSummaryById["file-allow-section"]}
                  collapsed={isRuleSectionCollapsed("file-allow-section")}
                  onToggleCollapsed={() => toggleRuleSection("file-allow-section")}
                  addLabel="Add Rule"
                  testId="file-allow-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      file_allow: [
                        ...profile.file_allow,
                        {
                          id: nextRuleId(
                            profile.file_allow.map((rule) => rule.id),
                            "file_allow"
                          ),
                          pattern: "/workspace/**"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.file_allow.length ? (
                    <PolicyTableHeader className="rule-grid">
                      <span>Rule ID</span>
                      <span>Pattern</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.file_allow.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      key={rowKey("file_allow", index)}
                      testId={`file-allow-row-${index}`}
                    >
                      <div className="rule-grid">
                        <input
                          data-testid={`file-allow-id-${index}`}
                          value={rule.id}
                          placeholder="rule id"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.file_allow];
                              next[index] = { ...next[index], id: event.target.value };
                              return { ...profile, file_allow: next };
                            })
                          }
                        />
                        <input
                          data-testid={`file-allow-pattern-${index}`}
                          value={rule.pattern}
                          placeholder="glob pattern"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.file_allow];
                              next[index] = { ...next[index], pattern: event.target.value };
                              return { ...profile, file_allow: next };
                            })
                          }
                        />
                        <PolicyIconButton
                          data-testid={`file-allow-remove-${index}`}
                          label={`Remove file allow rule ${index + 1}`}
                          iconName="remove"
                          onClick={() =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              file_allow: profile.file_allow.filter(
                                (_, itemIndex) => itemIndex !== index
                              )
                            }))
                          }
                        />
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="File Deny Rules"
                  iconName="file"
                  count={currentProfile.file_deny.length}
                  summary={policySectionSummaryById["file-deny-section"]}
                  collapsed={isRuleSectionCollapsed("file-deny-section")}
                  onToggleCollapsed={() => toggleRuleSection("file-deny-section")}
                  addLabel="Add Rule"
                  testId="file-deny-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      file_deny: [
                        ...profile.file_deny,
                        {
                          id: nextRuleId(
                            profile.file_deny.map((rule) => rule.id),
                            "file_deny"
                          ),
                          pattern: "/etc/**"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.file_deny.length ? (
                    <PolicyTableHeader className="rule-grid">
                      <span>Rule ID</span>
                      <span>Pattern</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.file_deny.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      key={rowKey("file_deny", index)}
                      testId={`file-deny-row-${index}`}
                    >
                      <div className="rule-grid">
                        <input
                          data-testid={`file-deny-id-${index}`}
                          value={rule.id}
                          placeholder="rule id"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.file_deny];
                              next[index] = { ...next[index], id: event.target.value };
                              return { ...profile, file_deny: next };
                            })
                          }
                        />
                        <input
                          data-testid={`file-deny-pattern-${index}`}
                          value={rule.pattern}
                          placeholder="glob pattern"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.file_deny];
                              next[index] = { ...next[index], pattern: event.target.value };
                              return { ...profile, file_deny: next };
                            })
                          }
                        />
                        <PolicyIconButton
                          data-testid={`file-deny-remove-${index}`}
                          label={`Remove file deny rule ${index + 1}`}
                          iconName="remove"
                          onClick={() =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              file_deny: profile.file_deny.filter(
                                (_, itemIndex) => itemIndex !== index
                              )
                            }))
                          }
                        />
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="Exec Allow Rules"
                  iconName="terminal"
                  count={currentProfile.exec_allow.length}
                  summary={policySectionSummaryById["exec-allow-section"]}
                  collapsed={isRuleSectionCollapsed("exec-allow-section")}
                  onToggleCollapsed={() => toggleRuleSection("exec-allow-section")}
                  addLabel="Add Rule"
                  testId="exec-allow-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      exec_allow: [
                        ...profile.exec_allow,
                        {
                          id: nextRuleId(
                            profile.exec_allow.map((rule) => rule.id),
                            "exec_allow"
                          ),
                          path: "/usr/bin/*"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.exec_allow.length ? (
                    <PolicyTableHeader className="rule-grid">
                      <span>Rule ID</span>
                      <span>Path</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.exec_allow.map((rule, index) => (
                    <RuleCard className="rule-card-row" key={rowKey("exec_allow", index)}>
                      <div className="rule-grid">
                        <input
                          value={rule.id}
                          placeholder="rule id"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.exec_allow];
                              next[index] = { ...next[index], id: event.target.value };
                              return { ...profile, exec_allow: next };
                            })
                          }
                        />
                        <input
                          value={rule.path}
                          placeholder="path glob"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.exec_allow];
                              next[index] = { ...next[index], path: event.target.value };
                              return { ...profile, exec_allow: next };
                            })
                          }
                        />
                        <PolicyIconButton
                          label={`Remove exec allow rule ${index + 1}`}
                          iconName="remove"
                          onClick={() =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              exec_allow: profile.exec_allow.filter(
                                (_, itemIndex) => itemIndex !== index
                              )
                            }))
                          }
                        />
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="Exec Deny Rules"
                  iconName="terminal"
                  count={currentProfile.exec_deny.length}
                  summary={policySectionSummaryById["exec-deny-section"]}
                  collapsed={isRuleSectionCollapsed("exec-deny-section")}
                  onToggleCollapsed={() => toggleRuleSection("exec-deny-section")}
                  addLabel="Add Rule"
                  testId="exec-deny-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      exec_deny: [
                        ...profile.exec_deny,
                        {
                          id: nextRuleId(
                            profile.exec_deny.map((rule) => rule.id),
                            "exec_deny"
                          ),
                          path: "/bin/rm"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.exec_deny.length ? (
                    <PolicyTableHeader className="rule-grid">
                      <span>Rule ID</span>
                      <span>Path</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.exec_deny.map((rule, index) => (
                    <RuleCard className="rule-card-row" key={rowKey("exec_deny", index)}>
                      <div className="rule-grid">
                        <input
                          data-testid={`exec-deny-id-${index}`}
                          value={rule.id}
                          placeholder="rule id"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.exec_deny];
                              next[index] = { ...next[index], id: event.target.value };
                              return { ...profile, exec_deny: next };
                            })
                          }
                        />
                        <input
                          data-testid={`exec-deny-path-${index}`}
                          value={rule.path}
                          placeholder="path glob"
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => {
                              const next = [...profile.exec_deny];
                              next[index] = { ...next[index], path: event.target.value };
                              return { ...profile, exec_deny: next };
                            })
                          }
                        />
                        <PolicyIconButton
                          label={`Remove exec deny rule ${index + 1}`}
                          iconName="remove"
                          data-testid={`exec-deny-remove-${index}`}
                          onClick={() =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              exec_deny: profile.exec_deny.filter(
                                (_, itemIndex) => itemIndex !== index
                              )
                            }))
                          }
                        />
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="Network Allow Rules"
                  iconName="network"
                  count={currentProfile.network_allow.length}
                  summary={policySectionSummaryById["network-allow-section"]}
                  collapsed={isRuleSectionCollapsed("network-allow-section")}
                  onToggleCollapsed={() => toggleRuleSection("network-allow-section")}
                  addLabel="Add Rule"
                  testId="network-allow-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      network_allow: [
                        ...profile.network_allow,
                        {
                          id: nextRuleId(
                            profile.network_allow.map((rule) => rule.id),
                            "network_allow"
                          ),
                          protocol: "TCP"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.network_allow.length ? (
                    <PolicyTableHeader className="rule-card-grid">
                      <span className="span-3">ID</span>
                      <span className="span-5">Host</span>
                      <span className="span-4">CIDR</span>
                      <span className="span-3">Port</span>
                      <span className="span-3">Protocol</span>
                      <span className="span-2 rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.network_allow.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      variant="network"
                      key={rowKey("network_allow", index)}
                    >
                      <div className="rule-card-grid rule-card-grid-compact">
                        <label className="rule-field span-3">
                          <span>ID</span>
                          <input
                            value={rule.id}
                            placeholder="rule id"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_allow];
                                next[index] = { ...next[index], id: event.target.value };
                                return { ...profile, network_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-5">
                          <span>Host Glob</span>
                          <input
                            value={rule.host_glob ?? ""}
                            placeholder="host_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_allow];
                                next[index] = {
                                  ...next[index],
                                  host_glob: event.target.value || undefined
                                };
                                return { ...profile, network_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-4">
                          <span>CIDR</span>
                          <input
                            value={rule.cidr ?? ""}
                            placeholder="cidr"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_allow];
                                next[index] = {
                                  ...next[index],
                                  cidr: event.target.value || undefined
                                };
                                return { ...profile, network_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-3">
                          <span>Port</span>
                          <input
                            value={getPortInputValue(
                              "network_allow",
                              rowToken("network_allow", index),
                              rule.port
                            )}
                            placeholder="port"
                            onChange={(event) =>
                              setPortInputDraft(
                                "network_allow",
                                rowToken("network_allow", index),
                                event.target.value
                              )
                            }
                            onBlur={() =>
                              commitPortInput(
                                "network_allow",
                                index,
                                rowToken("network_allow", index)
                              )
                            }
                          />
                        </label>
                        <label className="rule-field span-3">
                          <span>Protocol</span>
                          <select
                            value={rule.protocol ?? ""}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_allow];
                                next[index] = {
                                  ...next[index],
                                  protocol: event.target.value
                                    ? (event.target.value as NetworkProtocol)
                                    : undefined
                                };
                                return { ...profile, network_allow: next };
                              })
                            }
                          >
                            <option value="">protocol</option>
                            <option value="TCP">TCP</option>
                            <option value="UDP">UDP</option>
                          </select>
                        </label>
                        <div className="rule-field rule-field-actions rule-field-actions-compact span-2">
                          <PolicyIconButton
                            label={`Remove network allow rule ${index + 1}`}
                            iconName="remove"
                            onClick={() =>
                              mutateCurrentProfile((profile) => ({
                                ...profile,
                                network_allow: profile.network_allow.filter(
                                  (_, itemIndex) => itemIndex !== index
                                )
                              }))
                            }
                          />
                        </div>
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="Network Deny Rules"
                  iconName="network"
                  count={currentProfile.network_deny.length}
                  summary={policySectionSummaryById["network-deny-section"]}
                  collapsed={isRuleSectionCollapsed("network-deny-section")}
                  onToggleCollapsed={() => toggleRuleSection("network-deny-section")}
                  addLabel="Add Rule"
                  testId="network-deny-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      network_deny: [
                        ...profile.network_deny,
                        {
                          id: nextRuleId(
                            profile.network_deny.map((rule) => rule.id),
                            "network_deny"
                          ),
                          protocol: "TCP"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.network_deny.length ? (
                    <PolicyTableHeader className="rule-card-grid">
                      <span className="span-3">ID</span>
                      <span className="span-5">Host</span>
                      <span className="span-4">CIDR</span>
                      <span className="span-3">Port</span>
                      <span className="span-3">Protocol</span>
                      <span className="span-2 rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.network_deny.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      variant="network"
                      key={rowKey("network_deny", index)}
                    >
                      <div className="rule-card-grid rule-card-grid-compact">
                        <label className="rule-field span-3">
                          <span>ID</span>
                          <input
                            data-testid={`network-deny-id-${index}`}
                            value={rule.id}
                            placeholder="rule id"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_deny];
                                next[index] = { ...next[index], id: event.target.value };
                                return { ...profile, network_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-5">
                          <span>Host Glob</span>
                          <input
                            data-testid={`network-deny-host-${index}`}
                            value={rule.host_glob ?? ""}
                            placeholder="host_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_deny];
                                next[index] = {
                                  ...next[index],
                                  host_glob: event.target.value || undefined
                                };
                                return { ...profile, network_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-4">
                          <span>CIDR</span>
                          <input
                            data-testid={`network-deny-cidr-${index}`}
                            value={rule.cidr ?? ""}
                            placeholder="cidr"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_deny];
                                next[index] = {
                                  ...next[index],
                                  cidr: event.target.value || undefined
                                };
                                return { ...profile, network_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-3">
                          <span>Port</span>
                          <input
                            value={getPortInputValue(
                              "network_deny",
                              rowToken("network_deny", index),
                              rule.port
                            )}
                            placeholder="port"
                            onChange={(event) =>
                              setPortInputDraft(
                                "network_deny",
                                rowToken("network_deny", index),
                                event.target.value
                              )
                            }
                            onBlur={() =>
                              commitPortInput(
                                "network_deny",
                                index,
                                rowToken("network_deny", index)
                              )
                            }
                          />
                        </label>
                        <label className="rule-field span-3">
                          <span>Protocol</span>
                          <select
                            value={rule.protocol ?? ""}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.network_deny];
                                next[index] = {
                                  ...next[index],
                                  protocol: event.target.value
                                    ? (event.target.value as NetworkProtocol)
                                    : undefined
                                };
                                return { ...profile, network_deny: next };
                              })
                            }
                          >
                            <option value="">protocol</option>
                            <option value="TCP">TCP</option>
                            <option value="UDP">UDP</option>
                          </select>
                        </label>
                        <div className="rule-field rule-field-actions rule-field-actions-compact span-2">
                          <PolicyIconButton
                            label={`Remove network deny rule ${index + 1}`}
                            iconName="remove"
                            onClick={() =>
                              mutateCurrentProfile((profile) => ({
                                ...profile,
                                network_deny: profile.network_deny.filter(
                                  (_, itemIndex) => itemIndex !== index
                                )
                              }))
                            }
                          />
                        </div>
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="URL Allow Rules"
                  iconName="network"
                  count={currentProfile.url_allow.length}
                  summary={policySectionSummaryById["url-allow-section"]}
                  collapsed={isRuleSectionCollapsed("url-allow-section")}
                  onToggleCollapsed={() => toggleRuleSection("url-allow-section")}
                  addLabel="Add Rule"
                  testId="url-allow-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      url_allow: [
                        ...profile.url_allow,
                        {
                          id: nextRuleId(
                            profile.url_allow.map((rule) => rule.id),
                            "url_allow"
                          ),
                          scheme: "https",
                          host_glob: "*",
                          path_glob: "/**"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.url_allow.length ? (
                    <PolicyTableHeader className="rule-card-grid rule-card-grid-url">
                      <span>ID</span>
                      <span>Scheme</span>
                      <span>Host</span>
                      <span>Path</span>
                      <span>Query</span>
                      <span>Method</span>
                      <span>Port</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.url_allow.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      variant="url"
                      key={rowKey("url_allow", index)}
                      testId={`url-allow-row-${index}`}
                    >
                      <div className="rule-card-grid rule-card-grid-url rule-card-grid-compact">
                        <label className="rule-field">
                          <span>ID</span>
                          <input
                            data-testid={`url-allow-id-${index}`}
                            value={rule.id}
                            placeholder="rule id"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = { ...next[index], id: event.target.value };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Scheme</span>
                          <input
                            data-testid={`url-allow-scheme-${index}`}
                            value={rule.scheme ?? ""}
                            placeholder="http / https / *"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = {
                                  ...next[index],
                                  scheme: event.target.value || undefined
                                };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Host Glob</span>
                          <input
                            data-testid={`url-allow-host-${index}`}
                            value={rule.host_glob}
                            placeholder="host_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = { ...next[index], host_glob: event.target.value };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Path Glob</span>
                          <input
                            data-testid={`url-allow-path-${index}`}
                            value={rule.path_glob}
                            placeholder="path_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = { ...next[index], path_glob: event.target.value };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Query Glob</span>
                          <input
                            data-testid={`url-allow-query-${index}`}
                            value={rule.query_glob ?? ""}
                            placeholder="query_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = {
                                  ...next[index],
                                  query_glob: event.target.value || undefined
                                };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Method</span>
                          <input
                            data-testid={`url-allow-method-${index}`}
                            value={rule.method ?? ""}
                            placeholder="method"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_allow];
                                next[index] = {
                                  ...next[index],
                                  method: event.target.value || undefined
                                };
                                return { ...profile, url_allow: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Port</span>
                          <input
                            data-testid={`url-allow-port-${index}`}
                            value={getPortInputValue(
                              "url_allow",
                              rowToken("url_allow", index),
                              rule.port
                            )}
                            placeholder="port"
                            onChange={(event) =>
                              setPortInputDraft(
                                "url_allow",
                                rowToken("url_allow", index),
                                event.target.value
                              )
                            }
                            onBlur={() =>
                              commitPortInput("url_allow", index, rowToken("url_allow", index))
                            }
                          />
                        </label>
                        <div className="rule-field rule-field-actions rule-field-actions-compact">
                          <PolicyIconButton
                            data-testid={`url-allow-remove-${index}`}
                            label={`Remove URL allow rule ${index + 1}`}
                            iconName="remove"
                            onClick={() =>
                              mutateCurrentProfile((profile) => ({
                                ...profile,
                                url_allow: profile.url_allow.filter(
                                  (_, itemIndex) => itemIndex !== index
                                )
                              }))
                            }
                          />
                        </div>
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="URL Deny Rules"
                  iconName="network"
                  count={currentProfile.url_deny.length}
                  summary={policySectionSummaryById["url-deny-section"]}
                  collapsed={isRuleSectionCollapsed("url-deny-section")}
                  onToggleCollapsed={() => toggleRuleSection("url-deny-section")}
                  addLabel="Add Rule"
                  testId="url-deny-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      url_deny: [
                        ...profile.url_deny,
                        {
                          id: nextRuleId(
                            profile.url_deny.map((rule) => rule.id),
                            "url_deny"
                          ),
                          scheme: "https",
                          host_glob: "*",
                          path_glob: "/**"
                        }
                      ]
                    }))
                  }
                >
                  {currentProfile.url_deny.length ? (
                    <PolicyTableHeader className="rule-card-grid rule-card-grid-url">
                      <span>ID</span>
                      <span>Scheme</span>
                      <span>Host</span>
                      <span>Path</span>
                      <span>Query</span>
                      <span>Method</span>
                      <span>Port</span>
                      <span className="rule-table-head-action">Action</span>
                    </PolicyTableHeader>
                  ) : null}
                  {currentProfile.url_deny.map((rule, index) => (
                    <RuleCard
                      className="rule-card-row"
                      variant="url"
                      key={rowKey("url_deny", index)}
                      testId={`url-deny-row-${index}`}
                    >
                      <div className="rule-card-grid rule-card-grid-url rule-card-grid-compact">
                        <label className="rule-field">
                          <span>ID</span>
                          <input
                            data-testid={`url-deny-id-${index}`}
                            value={rule.id}
                            placeholder="rule id"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = { ...next[index], id: event.target.value };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Scheme</span>
                          <input
                            data-testid={`url-deny-scheme-${index}`}
                            value={rule.scheme ?? ""}
                            placeholder="http / https / *"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = {
                                  ...next[index],
                                  scheme: event.target.value || undefined
                                };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Host Glob</span>
                          <input
                            data-testid={`url-deny-host-${index}`}
                            value={rule.host_glob}
                            placeholder="host_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = { ...next[index], host_glob: event.target.value };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Path Glob</span>
                          <input
                            data-testid={`url-deny-path-${index}`}
                            value={rule.path_glob}
                            placeholder="path_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = { ...next[index], path_glob: event.target.value };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Query Glob</span>
                          <input
                            data-testid={`url-deny-query-${index}`}
                            value={rule.query_glob ?? ""}
                            placeholder="query_glob"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = {
                                  ...next[index],
                                  query_glob: event.target.value || undefined
                                };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Method</span>
                          <input
                            data-testid={`url-deny-method-${index}`}
                            value={rule.method ?? ""}
                            placeholder="method"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...profile.url_deny];
                                next[index] = {
                                  ...next[index],
                                  method: event.target.value || undefined
                                };
                                return { ...profile, url_deny: next };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field">
                          <span>Port</span>
                          <input
                            data-testid={`url-deny-port-${index}`}
                            value={getPortInputValue(
                              "url_deny",
                              rowToken("url_deny", index),
                              rule.port
                            )}
                            placeholder="port"
                            onChange={(event) =>
                              setPortInputDraft(
                                "url_deny",
                                rowToken("url_deny", index),
                                event.target.value
                              )
                            }
                            onBlur={() =>
                              commitPortInput("url_deny", index, rowToken("url_deny", index))
                            }
                          />
                        </label>
                        <div className="rule-field rule-field-actions rule-field-actions-compact">
                          <PolicyIconButton
                            data-testid={`url-deny-remove-${index}`}
                            label={`Remove URL deny rule ${index + 1}`}
                            iconName="remove"
                            onClick={() =>
                              mutateCurrentProfile((profile) => ({
                                ...profile,
                                url_deny: profile.url_deny.filter(
                                  (_, itemIndex) => itemIndex !== index
                                )
                              }))
                            }
                          />
                        </div>
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>

                <PolicyRuleSection
                  title="MCP Servers"
                  iconName="shield"
                  count={currentProfile.mcp?.servers.length ?? 0}
                  summary={policySectionSummaryById["mcp-section"]}
                  collapsed={isRuleSectionCollapsed("mcp-section")}
                  onToggleCollapsed={() => toggleRuleSection("mcp-section")}
                  addLabel="Add Server"
                  testId="mcp-section"
                  onAdd={() =>
                    mutateCurrentProfile((profile) => ({
                      ...profile,
                      mcp: {
                        default_tool_action: profile.mcp?.default_tool_action,
                        default_resource_action: profile.mcp?.default_resource_action,
                        servers: [
                          ...(profile.mcp?.servers ?? []),
                          {
                            id: nextRuleId(
                              (profile.mcp?.servers ?? []).map((s) => s.id),
                              "mcp_server"
                            ),
                            transport: "stdio" as const,
                            exec_path_glob: "",
                            base_url: undefined,
                            default_tool_action: undefined,
                            default_resource_action: undefined,
                            tools: { allow: [], deny: [], require_approval: [] },
                            resources: { allow: [], deny: [], require_approval: [] }
                          }
                        ]
                      }
                    }))
                  }
                >
                  <RuleCard className="mcp-defaults-card" testId="mcp-defaults-card">
                    <div className="mcp-card-header">
                      <div className="mcp-card-copy">
                        <p className="policy-kicker">Shared fallback</p>
                        <h4>Default MCP actions for all servers</h4>
                        <p>Used only when a server does not set its own default action.</p>
                      </div>
                    </div>
                    <div className="rule-card-grid mcp-server-grid">
                      <label className="rule-field span-6">
                        <span>Default Tool Action (all servers)</span>
                        <select
                          data-testid="mcp-default-action"
                          value={currentProfile.mcp?.default_tool_action ?? ""}
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              mcp: {
                                servers: profile.mcp?.servers ?? [],
                                default_resource_action: profile.mcp?.default_resource_action,
                                default_tool_action:
                                  (event.target.value as McpToolAction) || undefined
                              }
                            }))
                          }
                        >
                          <option value="">inherit (deny by default)</option>
                          <option value="allow">allow</option>
                          <option value="deny">deny</option>
                          <option value="require_approval">require_approval</option>
                        </select>
                      </label>
                      <label className="rule-field span-6">
                        <span>Default Resource Action (all servers)</span>
                        <select
                          data-testid="mcp-default-resource-action"
                          value={currentProfile.mcp?.default_resource_action ?? ""}
                          onChange={(event) =>
                            mutateCurrentProfile((profile) => ({
                              ...profile,
                              mcp: {
                                servers: profile.mcp?.servers ?? [],
                                default_tool_action: profile.mcp?.default_tool_action,
                                default_resource_action:
                                  (event.target.value as McpToolAction) || undefined
                              }
                            }))
                          }
                        >
                          <option value="">inherit (deny by default)</option>
                          <option value="allow">allow</option>
                          <option value="deny">deny</option>
                          <option value="require_approval">require_approval</option>
                        </select>
                      </label>
                    </div>
                  </RuleCard>

                  {(currentProfile.mcp?.servers ?? []).map((server, index) => (
                    <RuleCard
                      className="mcp-server-card"
                      key={rowKey("mcp_server", index)}
                      testId={`mcp-server-row-${index}`}
                    >
                      <div className="mcp-card-header">
                        <div className="mcp-card-copy">
                          <p className="policy-kicker">Server {index + 1}</p>
                          <h4>{server.id || `New MCP server ${index + 1}`}</h4>
                          <p>
                            Match the executable or base URL, then list the tools and resources
                            below.
                          </p>
                        </div>
                        <PolicyIconButton
                          data-testid={`mcp-server-remove-${index}`}
                          label={`Remove MCP server ${index + 1}`}
                          iconName="remove"
                          onClick={() =>
                            mutateCurrentProfile((profile) => {
                              const next = (profile.mcp?.servers ?? []).filter(
                                (_, serverIndex) => serverIndex !== index
                              );
                              return {
                                ...profile,
                                mcp:
                                  next.length === 0 &&
                                  !profile.mcp?.default_tool_action &&
                                  !profile.mcp?.default_resource_action
                                    ? undefined
                                    : { ...profile.mcp!, servers: next }
                              };
                            })
                          }
                        />
                      </div>
                      <div className="rule-card-grid mcp-server-grid">
                        <label className="rule-field span-4">
                          <span>Transport</span>
                          <select
                            data-testid={`mcp-server-transport-${index}`}
                            value={server.transport}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  transport: event.target.value === "http" ? "http" : "stdio",
                                  exec_path_glob:
                                    event.target.value === "http"
                                      ? undefined
                                      : (next[index].exec_path_glob ?? ""),
                                  base_url:
                                    event.target.value === "http"
                                      ? (next[index].base_url ?? "http://127.0.0.1:8080/mcp")
                                      : undefined
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          >
                            <option value="stdio">stdio</option>
                            <option value="http">http</option>
                          </select>
                        </label>
                        <label className="rule-field span-4">
                          <span>Server ID</span>
                          <input
                            data-testid={`mcp-server-id-${index}`}
                            value={server.id}
                            placeholder="github-mcp"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = { ...next[index], id: event.target.value };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-4">
                          <span>{server.transport === "http" ? "Base URL" : "Exec Path Glob"}</span>
                          <input
                            data-testid={`mcp-server-exec-${index}`}
                            value={
                              server.transport === "http"
                                ? (server.base_url ?? "")
                                : (server.exec_path_glob ?? "")
                            }
                            placeholder={
                              server.transport === "http"
                                ? "https://mcp.example.com"
                                : "/usr/local/bin/github-mcp*"
                            }
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] =
                                  server.transport === "http"
                                    ? { ...next[index], base_url: event.target.value || undefined }
                                    : {
                                        ...next[index],
                                        exec_path_glob: event.target.value || undefined
                                      };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field span-4">
                          <span>Default Tool Action</span>
                          <select
                            data-testid={`mcp-server-default-action-${index}`}
                            value={server.default_tool_action ?? ""}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  default_tool_action:
                                    (event.target.value as McpToolAction) || undefined
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          >
                            <option value="">inherit from MCP default</option>
                            <option value="allow">allow</option>
                            <option value="deny">deny</option>
                            <option value="require_approval">require_approval</option>
                          </select>
                        </label>
                        <label className="rule-field span-4">
                          <span>Default Resource Action</span>
                          <select
                            data-testid={`mcp-server-default-resource-action-${index}`}
                            value={server.default_resource_action ?? ""}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  default_resource_action:
                                    (event.target.value as McpToolAction) || undefined
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          >
                            <option value="">inherit from MCP default</option>
                            <option value="allow">allow</option>
                            <option value="deny">deny</option>
                            <option value="require_approval">require_approval</option>
                          </select>
                        </label>
                      </div>
                      <div className="mcp-tools-grid">
                        <label className="rule-field mcp-tool-field">
                          <span>Allow tools</span>
                          <small>One tool name per line that should always be allowed.</small>
                          <textarea
                            data-testid={`mcp-server-allow-tools-${index}`}
                            rows={5}
                            value={server.tools.allow.join("\n")}
                            placeholder={"list_repos\nget_issue"}
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  tools: {
                                    ...next[index].tools,
                                    allow: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field mcp-tool-field">
                          <span>Deny tools</span>
                          <small>One tool name per line that should always be blocked.</small>
                          <textarea
                            data-testid={`mcp-server-deny-tools-${index}`}
                            rows={5}
                            value={server.tools.deny.join("\n")}
                            placeholder="delete_repo"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  tools: {
                                    ...next[index].tools,
                                    deny: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field mcp-tool-field">
                          <span>Require approval</span>
                          <small>One tool name per line that should prompt for approval.</small>
                          <textarea
                            data-testid={`mcp-server-approval-tools-${index}`}
                            rows={5}
                            value={server.tools.require_approval.join("\n")}
                            placeholder="create_pull_request"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  tools: {
                                    ...next[index].tools,
                                    require_approval: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field mcp-tool-field">
                          <span>Allow resources</span>
                          <small>One URI glob per line that should always be allowed.</small>
                          <textarea
                            data-testid={`mcp-server-allow-resources-${index}`}
                            rows={5}
                            value={server.resources.allow.join("\n")}
                            placeholder="repo://docs/**"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  resources: {
                                    ...next[index].resources,
                                    allow: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field mcp-tool-field">
                          <span>Deny resources</span>
                          <small>One URI glob per line that should always be blocked.</small>
                          <textarea
                            data-testid={`mcp-server-deny-resources-${index}`}
                            rows={5}
                            value={server.resources.deny.join("\n")}
                            placeholder="repo://secret/**"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  resources: {
                                    ...next[index].resources,
                                    deny: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                        <label className="rule-field mcp-tool-field">
                          <span>Require resource approval</span>
                          <small>One URI glob per line that should prompt for approval.</small>
                          <textarea
                            data-testid={`mcp-server-approval-resources-${index}`}
                            rows={5}
                            value={server.resources.require_approval.join("\n")}
                            placeholder="repo://pull-request/**"
                            onChange={(event) =>
                              mutateCurrentProfile((profile) => {
                                const next = [...(profile.mcp?.servers ?? [])];
                                next[index] = {
                                  ...next[index],
                                  resources: {
                                    ...next[index].resources,
                                    require_approval: event.target.value
                                      .split("\n")
                                      .map((s) => s.trim())
                                      .filter(Boolean)
                                  }
                                };
                                return { ...profile, mcp: { ...profile.mcp!, servers: next } };
                              })
                            }
                          />
                        </label>
                      </div>
                    </RuleCard>
                  ))}
                </PolicyRuleSection>
              </PolicyStudioShell>
            ) : null}

            {activeTab === "enrollment" ? (
              <EnrollmentsPanel refreshNonce={panelRefreshNonce} />
            ) : null}

            {activeTab === "agents" ? (
              <AgentLaunchPanel csrfToken={csrfToken} profileNames={profileNames} />
            ) : null}

            {activeTab === "settings" ? (
              <SettingsPanel
                certInfo={status?.tls_cert_info}
                csrfToken={csrfToken}
                onCertInfoUpdate={(info: TlsCertInfo) => {
                  setStatus((prev) => (prev ? { ...prev, tls_cert_info: info } : prev));
                }}
              />
            ) : null}

            {activeTab === "help" ? (
              <HelpTab
                currentTab={contextualHelpTab}
                onOpenTab={(tab) => setActiveTab(tab)}
                onStartTour={() => startTour()}
                onStartTabTour={startTourForTab}
              />
            ) : null}
          </div>
        </div>

        <HelpBar
          currentTab={contextualHelpTab}
          open={helpBarOpen}
          onToggle={() => setHelpBarOpen((value) => !value)}
          onOpenHelp={openHelpHub}
          onStartTour={() => startTour()}
          onStartTabTour={startTourForTab}
        />

        {showApplyConfirm ? (
          <PolicyChangeDialog
            mode="apply"
            diff={policyDiff}
            note={applyNote}
            busy={policyActionBusy}
            onCancel={() => {
              if (!policyActionBusy) {
                setShowApplyConfirm(false);
                setPendingApplyDraftId(null);
                setApplyNote("");
              }
            }}
            onConfirm={() => void applyDraft(applyNote, pendingApplyDraftId)}
            onNoteChange={setApplyNote}
          />
        ) : null}

        {pendingRollbackVersion ? (
          <PolicyChangeDialog
            mode="rollback"
            version={pendingRollbackVersion}
            note={rollbackNote}
            busy={policyActionBusy}
            onCancel={() => {
              if (!policyActionBusy) {
                setPendingRollbackVersion(null);
                setRollbackNote("");
              }
            }}
            onConfirm={() => void rollback(pendingRollbackVersion.id, rollbackNote)}
            onNoteChange={setRollbackNote}
          />
        ) : null}

        {showPasswordPanel
          ? createPortal(
              <div
                className="modal-overlay"
                data-testid="password-panel"
                onMouseDown={(event) => {
                  if (event.target === event.currentTarget) {
                    setShowPasswordPanel(false);
                  }
                }}
              >
                <div
                  className="modal-card password-change-dialog"
                  role="dialog"
                  aria-modal="true"
                  aria-labelledby="password-dialog-title"
                >
                  <div className="modal-header">
                    <h3 id="password-dialog-title" className="heading-with-icon">
                      <AppIcon name="password" className="app-icon-lg" />
                      <span>Change Password</span>
                    </h3>
                    <button
                      className="ghost icon-only-button"
                      type="button"
                      onClick={() => setShowPasswordPanel(false)}
                      aria-label="Close password dialog"
                      title="Close password dialog"
                    >
                      <AppIcon name="close" className="app-icon-sm" />
                      <span className="sr-only">Close password dialog</span>
                    </button>
                  </div>
                  <form
                    className="modal-body auth-form"
                    data-testid="password-change-form"
                    onSubmit={handlePasswordChange}
                  >
                    <p className="meta">Update dashboard credentials without leaving the UI.</p>
                    <div className="field">
                      <label htmlFor="current-password">Current Password</label>
                      <input
                        id="current-password"
                        type="password"
                        data-testid="current-password-input"
                        value={currentPassword}
                        onChange={(event) => setCurrentPassword(event.target.value)}
                        autoComplete="current-password"
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="new-password">New Password</label>
                      <input
                        id="new-password"
                        type="password"
                        data-testid="new-password-input"
                        value={newPassword}
                        onChange={(event) => setNewPassword(event.target.value)}
                        autoComplete="new-password"
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="new-password-confirm">Confirm New Password</label>
                      <input
                        id="new-password-confirm"
                        type="password"
                        data-testid="new-password-confirm-input"
                        value={newPasswordConfirm}
                        onChange={(event) => setNewPasswordConfirm(event.target.value)}
                        autoComplete="new-password"
                      />
                    </div>
                    {passwordMessage ? (
                      <p className="meta" data-testid="password-message">
                        {passwordMessage}
                      </p>
                    ) : null}
                    <div className="modal-footer password-dialog-actions">
                      <button
                        className="ghost"
                        type="button"
                        onClick={() => setShowPasswordPanel(false)}
                      >
                        Cancel
                      </button>
                      <button type="submit" data-testid="password-update-submit">
                        Update Password
                      </button>
                    </div>
                  </form>
                </div>
              </div>,
              document.body
            )
          : null}

        {activeTourStep ? (
          <GuidedTourOverlay
            step={activeTourStep}
            stepIndex={tourStepIndex ?? 0}
            totalSteps={TOUR_STEPS.length}
            focusRect={tourFocusRect}
            onPrevious={previousTourStep}
            onNext={nextTourStep}
            onClose={closeTour}
            onOpenHelp={() => {
              closeTour();
              openHelpHub();
            }}
          />
        ) : null}
      </main>
    </ErrorBoundary>
  );
}
