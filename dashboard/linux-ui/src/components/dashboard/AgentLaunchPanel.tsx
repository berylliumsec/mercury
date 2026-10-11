import { memo, useCallback, useEffect, useRef, useState } from "react";

import {
  AuthRequiredError,
  launchAgent,
  listAgentLaunchHistory,
  listAgents,
  stopAgent
} from "../../apiClient";
import type { RecentAgentLaunch, RunningAgent } from "../../dashboardTypes";
import { parseShellArgs } from "./parseShellArgs";
import { AppIcon } from "./AppIcon";
import { PanelCard } from "./PanelCard";

type AgentLaunchPanelProps = {
  csrfToken: string;
  profileNames: string[];
};

function launchStatusClass(status: string): string {
  switch (status) {
    case "exited":
    case "completed":
      return "pill pill-success";
    case "failed":
    case "error":
      return "pill pill-danger";
    case "running":
      return "pill pill-info";
    default:
      return "pill pill-neutral";
  }
}

export const AgentLaunchPanel = memo(function AgentLaunchPanel({
  csrfToken,
  profileNames
}: AgentLaunchPanelProps) {
  // --- Running agents list ---
  const [agents, setAgents] = useState<RunningAgent[]>([]);
  const [launchHistory, setLaunchHistory] = useState<RecentAgentLaunch[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [stopping, setStopping] = useState<Set<string>>(new Set());

  // --- Launch form ---
  const [profile, setProfile] = useState(() => profileNames[0] ?? "");
  const [executable, setExecutable] = useState("");
  const [argumentsText, setArgumentsText] = useState("");
  const [cwd, setCwd] = useState("");
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [launchSuccess, setLaunchSuccess] = useState<string | null>(null);

  const pollRef = useRef<number | null>(null);

  const fetchAgents = useCallback(async () => {
    try {
      const [running, history] = await Promise.all([listAgents(), listAgentLaunchHistory()]);
      setAgents(running);
      setLaunchHistory(history);
      setListError(null);
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setListError((err as Error).message);
      }
    }
  }, []);

  useEffect(() => {
    void fetchAgents();
    pollRef.current = window.setInterval(() => {
      void fetchAgents();
    }, 5000);
    return () => {
      if (pollRef.current !== null) {
        window.clearInterval(pollRef.current);
      }
    };
  }, [fetchAgents]);

  // Keep profile select in sync when policy changes
  useEffect(() => {
    setProfile((prev) => (profileNames.includes(prev) ? prev : (profileNames[0] ?? "")));
  }, [profileNames]);

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault();
    setLaunchError(null);
    setLaunchSuccess(null);

    const trimmedExecutable = executable.trim();
    if (!trimmedExecutable.startsWith("/")) {
      setLaunchError("Executable path must be absolute (starting with /).");
      return;
    }

    let args: string[];
    try {
      args = parseShellArgs(argumentsText.trim());
    } catch (err) {
      setLaunchError((err as Error).message);
      return;
    }

    const request = {
      profile,
      executable: trimmedExecutable,
      args,
      cwd: cwd.trim() || undefined
    };

    setLaunching(true);
    try {
      const result = await launchAgent(request, csrfToken);
      setLaunchSuccess(`Launched PID ${result.pid} (agent ${result.agent_id.slice(0, 8)}…)`);
      setExecutable("");
      setArgumentsText("");
      setCwd("");
      await fetchAgents();
    } catch (err) {
      setLaunchError((err as Error).message);
    } finally {
      setLaunching(false);
    }
  }

  async function handleStop(agentId: string) {
    setStopping((prev) => new Set(prev).add(agentId));
    try {
      await stopAgent(agentId, csrfToken);
      await fetchAgents();
    } catch (err) {
      if (!(err instanceof AuthRequiredError)) {
        setListError((err as Error).message);
      }
    } finally {
      setStopping((prev) => {
        const next = new Set(prev);
        next.delete(agentId);
        return next;
      });
    }
  }

  return (
    <div className="panel-stack">
      {/* Launch form */}
      <PanelCard
        title="Launch Agent"
        subtitle="Runs mercury-run as the configured non-root Linux user. Best for server-style agents and background workers. If the launched process exposes its own web UI or API, interact with that service directly."
        testId="agents-launch-panel"
      >
        <form
          onSubmit={(e) => {
            void handleLaunch(e);
          }}
          className="agent-launch-form"
        >
          <div className="form-row">
            <label htmlFor="agent-profile">Profile</label>
            <select
              id="agent-profile"
              data-testid="agent-profile-select"
              value={profile}
              onChange={(e) => {
                setProfile(e.target.value);
              }}
              disabled={profileNames.length === 0}
            >
              {profileNames.length === 0 ? (
                <option value="">— no profiles —</option>
              ) : (
                profileNames.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))
              )}
            </select>
          </div>

          <div className="form-row">
            <label htmlFor="agent-executable">Executable Path</label>
            <input
              id="agent-executable"
              data-testid="agent-command-input"
              type="text"
              placeholder="/usr/bin/python3"
              value={executable}
              onChange={(e) => {
                setExecutable(e.target.value);
              }}
              required
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          <div className="form-row">
            <label htmlFor="agent-args">
              Arguments <span className="label-optional">(optional)</span>
            </label>
            <input
              id="agent-args"
              data-testid="agent-args-input"
              type="text"
              placeholder="-m my_agent.server --port 8080"
              value={argumentsText}
              onChange={(e) => {
                setArgumentsText(e.target.value);
              }}
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          <div className="form-row">
            <label htmlFor="agent-cwd">
              Working Dir <span className="label-optional">(optional)</span>
            </label>
            <input
              id="agent-cwd"
              data-testid="agent-cwd-input"
              type="text"
              placeholder="/opt/my-agent"
              value={cwd}
              onChange={(e) => {
                setCwd(e.target.value);
              }}
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          {launchError && <p className="form-error">{launchError}</p>}
          {launchSuccess && <p className="form-success">{launchSuccess}</p>}

          <div className="form-actions">
            <button
              type="submit"
              className="btn-primary"
              data-testid="agent-launch-button"
              disabled={launching || profileNames.length === 0}
            >
              {launching ? (
                "Launching…"
              ) : (
                <>
                  <AppIcon name="event" className="app-icon-sm" />
                  Launch
                </>
              )}
            </button>
          </div>
        </form>
      </PanelCard>

      {/* Running agents table */}
      <PanelCard title="Running Agents">
        {listError && <p className="panel-error">{listError}</p>}
        {agents.length === 0 && !listError ? (
          <p className="panel-empty">No agents running. Use the form above to launch one.</p>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>PID</th>
                  <th>Profile</th>
                  <th>Command</th>
                  <th>Working Dir</th>
                  <th>UID</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr key={agent.agent_id}>
                    <td className="monospace" title={agent.agent_id}>
                      {agent.agent_id.slice(0, 8)}…
                    </td>
                    <td>{agent.pid}</td>
                    <td>{agent.profile}</td>
                    <td className="monospace cell-truncate" title={agent.cmdline.join(" ")}>
                      {agent.cmdline.join(" ")}
                    </td>
                    <td className="monospace cell-truncate" title={agent.cwd}>
                      {agent.cwd}
                    </td>
                    <td>{agent.uid}</td>
                    <td>
                      <button
                        data-testid={`agent-stop-${agent.agent_id}`}
                        className="btn-danger btn-sm"
                        disabled={stopping.has(agent.agent_id)}
                        onClick={() => {
                          void handleStop(agent.agent_id);
                        }}
                        title="Send SIGTERM"
                      >
                        {stopping.has(agent.agent_id) ? "Stopping…" : "Stop"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelCard>

      <PanelCard title="Recent Launches" testId="agents-history-panel">
        {launchHistory.length === 0 ? (
          <p className="panel-empty">No completed or failed launches yet.</p>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Profile</th>
                  <th>Run As</th>
                  <th>Started</th>
                  <th>Command</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {launchHistory.map((launch) => (
                  <tr key={launch.launch_id}>
                    <td>
                      <span className={launchStatusClass(launch.status)}>{launch.status}</span>
                    </td>
                    <td>{launch.profile}</td>
                    <td>{launch.launch_user}</td>
                    <td>{new Date(launch.started_at).toLocaleString()}</td>
                    <td className="monospace cell-truncate" title={launch.cmdline.join(" ")}>
                      {launch.cmdline.join(" ")}
                    </td>
                    <td
                      className="monospace cell-truncate"
                      title={launch.error ?? launch.stderr_tail ?? ""}
                    >
                      {launch.error ??
                        (launch.exit_code != null
                          ? `exit ${launch.exit_code}`
                          : launch.signal != null
                            ? `signal ${launch.signal}`
                            : (launch.stderr_tail ?? ""))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelCard>
    </div>
  );
});
