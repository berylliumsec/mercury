# Mercury observability

What Mercury records, where it goes, how loss is detected, and how the records
of one agent run join up across layers.

| Page | Covers |
| --- | --- |
| [kernel.md](kernel.md) | eBPF LSM records (process context, lifecycle, rule attribution), loss accounting, kernel enforcement changes, daemon-restart recovery |
| [apparmor.md](apparmor.md) | AppArmor audit sources, record mapping, loss/gap events, profile lifecycle |
| [gateway-mcp.md](gateway-mcp.md) | URL gateway decision/outcome records, MCP traffic, approvals, model capture, redaction |
| [audit.md](audit.md) | JSONL writer, HMAC integrity chain, rotation, fsync, journald mirror, `mercury-audit verify` |
| [control-plane.md](control-plane.md) | dashboard operator audit trail, health/degraded state, `/metrics`, webhook alerts, exports |

## Record schema (v2)

Every line of `audit.jsonl` is one `AuditEvent`. Schema v2 adds optional,
top-level fields that are omitted when unset, so v1 consumers keep working:

* identity: `event_id`, `schema_version`, `host`, `source`, `actor`
* process: `tid`, `gid`, `comm`, `cgroup_id`, `root_pid`, `parent_agent_id`,
  `target_pid`, `signal`, `capability`, `exit_code`, `exit_signal`
* decision: `policy_epoch`, `simulated`, `truncated`
* joins: `correlation_id`, `outcome` (`status`, `bytes_sent`, `bytes_received`,
  `duration_ms`, `error`)
* resources: `FILE.source_path`, `EXEC.argv`/`argv_truncated`,
  `NETWORK.socket_path`/`family`, and the new `SYSTEM` resource
  (`event`, `detail`, `attributes`)

New action types: `PROC_START`, `PROC_EXIT`, `PROC_BPF`, `PROC_MODULE_LOAD`,
`PROC_MOUNT`, `PROC_USERNS`, `MCP_REQUEST`, `SYSTEM_EVENT`. New reason:
`INFORMATIONAL` (records that carry no policy decision).

## Following one agent run

* `agent_id` is the run id assigned at registration. Kernel records of every
  descendant resolve to it; `root_pid` is the registered process.
* `SYSTEM_EVENT agent_enrolled` records the launch (profile, cgroup, cmdline,
  cwd, caller uid); `PROC_START` records carry the argv actually executed;
  `PROC_EXIT` and `agent_unenrolled` close it.
* MCP server agents carry `parent_agent_id`; gateway and MCP records share a
  `correlation_id` between decision and outcome, and approval requests with
  their resolution.
* `event_id` is identical in the JSONL line, the journald entry
  (`MERCURY_EVENT_ID`), the dashboard copy and webhook alerts.

## Mercury's own lifecycle

`SYSTEM_EVENT` records with `source: daemon`:

| `resource.event` | When |
| --- | --- |
| `daemon_start` / `daemon_stop` | start-up after the initial policy load; SIGTERM (the audit log is synced) |
| `policy_reload` | every apply, with `result` applied/failed (failed = DENY record) |
| `agent_enrolled` / `agent_unenrolled` | registration of an agent or MCP server / its root exited (notes surviving descendants) |
| `enrollment_restored` / `enrollment_restore_failed` | restart recovery (see [kernel.md](kernel.md#daemon-restarts)) |
| `telemetry_loss` | kernel ring buffer, deny drops, rate limiting or ingest queue drops since the last report; `cause: daemon_downtime` after a restart |

Dry runs over the control socket (`mercury-policy test`) are written with
`simulated: true`, `source: control-api` and `actor: uid:<caller>`.

## Configuration added by this work

| Key | Default | Page |
| --- | --- | --- |
| `enrollment_state_path` | `/var/lib/mercury/enrollments.json` | [kernel.md](kernel.md) |
| `alerts.*` | disabled | [control-plane.md](control-plane.md) |
| `audit_integrity`, `audit_fsync`, `audit_max_file_bytes`, `audit_max_files`, `journald_mirror_mode` | see page | [audit.md](audit.md) |
| `apparmor.audit_source`, `apparmor.audit_log_path` | `auto`, `/var/log/audit/audit.log` | [apparmor.md](apparmor.md) |
| `url_gateway.model_traffic.extra_hosts` | `[]` | [gateway-mcp.md](gateway-mcp.md) |
| `dashboard.launch.stop_grace_seconds`, `dashboard.health_telemetry_loss_window_minutes` | `5`, `10` | [control-plane.md](control-plane.md) |

`mercury-status` exits `2` when the daemon is degraded (pass
`--ignore-degraded` in scripts that only need liveness).
