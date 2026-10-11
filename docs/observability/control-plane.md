# Control plane observability

This page covers what the dashboard, the control socket health response,
`mercury-status` and the optional webhook alerts record and report about
Mercury itself: operator actions, rejected sign-ins, telemetry loss and the
degraded state.

## Operator actions in the audit stream

Every action recorded in the dashboard's action trail (SQLite
`dashboard_actions`) is also emitted as an audit record through the daemon's
normal userspace audit path, so it lands in `audit.jsonl` (and its integrity
chain and mirrors) and in the live event view, not only in SQLite.

The record is a `SYSTEM_EVENT` with `source: "dashboard"`,
`reason: INFORMATIONAL` and `actor` set to the dashboard user:

```json
{
  "action_type": "SYSTEM_EVENT",
  "agent_id": "mercuryd",
  "profile": "system",
  "source": "dashboard",
  "actor": "admin",
  "resource": {
    "kind": "SYSTEM",
    "event": "dashboard_action",
    "detail": "policy_apply",
    "attributes": {
      "action": "policy_apply",
      "outcome": "success",
      "details": "draft_id=... version=... version_id=... note=...",
      "source_ip": "192.0.2.50",
      "user_agent": "Mozilla/5.0 ...",
      "session_id_hash": "3f1c9a0b7d2e4f61",
      "action_id": 1234
    }
  }
}
```

`session_id_hash` is the first 16 hex characters of SHA-256 of the session
id; the id itself is never recorded. `action_id` is the SQLite row id and is
omitted when the trail write failed. Trail write failures are logged and
counted (`dashboard_action_record_failures_total`); the audit record is still
emitted.

Recorded actions (`outcome` is `success` or `failure`):

| action | when |
| --- | --- |
| `login_success`, `signup_success`, `logout` | session lifecycle |
| `password_changed`, `password_change` (failure) | admin password rotation; all other sessions are revoked |
| `policy_draft_save`, `policy_draft_validate` | draft created/updated/validated (details carry draft id, etag, validity) |
| `policy_apply`, `policy_apply_failed` | draft applied, or rejected at validation/apply (errors included) |
| `policy_rollback`, `policy_rollback_failed` | rollback to a stored version |
| `quick_rule`, `quick_rule_failed` | rule created from an event |
| `mcp_approval_approve`, `mcp_approval_deny` | MCP approval decisions |
| `tls_update` | dashboard TLS certificate/key replacement, success or failure, with cert SHA-256 (DER), issuer and expiry |
| `agent_launch`, `agent_launch_failed` | dashboard launches, including rejected requests (stage `validate`, `profile`, `launch_user`, `launcher`, `spawn`, `register`) |
| `agent_stop` | agent stop with the real outcome (see below) |
| `events_export`, `actions_export` | who exported what |

The SQLite trail gained `outcome`, `source_ip`, `user_agent` and
`session_id_hash` columns (dashboard schema version 4; older databases are
migrated in place).

### Rejected sign-ins and requests

Rejected authentication is recorded as a `SYSTEM_EVENT` with
`resource.event: "auth_failure"`, `decision: DENY`,
`reason: DENY_BY_DEFAULT`, and `attributes.kind` one of:

| kind | when |
| --- | --- |
| `login_failed` | wrong username or password |
| `login_lockout_started` | 5 failures in 10 minutes locked the source out for 15 minutes |
| `login_locked_out`, `signup_locked_out`, `password_change_locked_out` | request from a locked-out source |
| `signup_failed`, `signup_after_setup` | bootstrap signup rejected, or attempted after an admin exists |
| `password_change_failed` | wrong current password |
| `session_missing`, `session_unknown`, `session_expired` | state-changing request without a live session |
| `csrf_missing`, `csrf_mismatch` | state-changing request (or logout) with a missing/wrong CSRF token |

Before authentication the actor is `anonymous`; the typed username is only
kept as `attributes.attempted_user` (trimmed to 64 printable characters).
Read-only requests without a live session are routine (page loads after a
timeout) and are not recorded.

At most 10 `auth_failure` records are written per source IP per minute. The
rest are counted in `auth_failures_total` and reported in the next record as
`suppressed_since_last`.

### Agent stop

`DELETE /api/v1/agents/{id}` stops every process in the agent's cgroup
(`<cgroup_base>/ai-<uuid>`), not only the launcher pid:

1. When `<cgroup>/cgroup.kill` exists, write `1` (SIGKILL to the whole
   cgroup, race-free against forks).
2. Otherwise SIGTERM every pid in `cgroup.procs` plus the launcher, wait
   `dashboard.launch.stop_grace_seconds`, then SIGKILL the survivors.
3. Re-read `cgroup.procs` and check the launcher to find survivors.

The `agent_stop` action records `method` (`cgroup.kill`, `signal`, `none`),
`pids_signalled` and `survivors`. The request fails with
`500 AGENT_STOP_INCOMPLETE` when anything survived.

## Dashboard API additions

| endpoint | change |
| --- | --- |
| `GET /api/v1/actions` | `before_id` (next page), `limit` (default 200, max 1000), `start`, `end` |
| `GET /api/v1/actions/export` | CSV of every action in `[start, end]`, oldest first, max 100 000 rows |
| `GET /api/v1/events` | new filters `agent_id`, `action_type`; `before_id` pages older events (`total` still counts every match) |
| `GET /api/v1/events/export` | the `/events` filters plus `format=jsonl` (original audit records, default) or `csv`, `limit` (default 50 000, max 200 000); streamed, oldest first |
| `GET /api/v1/events/stream` | `event: gap` frames, see below |

### Live stream gaps

The SSE stream no longer skips events silently. It sends

```
event: gap
data: {"skipped": 37, "reason": "lagged"}
```

when the client fell behind the broadcast buffer (`lagged`) or when a
reconnect needed more than the 500-event replay backlog (`backlog_limit`).
The events are still stored; the UI shows "N events were skipped by the live
stream" with a reload button. The stream now subscribes before it reads the
backlog, so events ingested during a reconnect are no longer lost.

## Degraded state

One definition, `control_api::degraded_reasons`, is used by `mercury-status`,
the dashboard overview and `/api/v1/health`. Mercury is degraded when:

- `backend_mode` is `kernel_strict` and the kernel program is not ready;
- the URL gateway is enabled but not ready;
- any audit write failed since start;
- enrollment sync reports an error;
- `telemetry_degraded_reasons` is non-empty (filled by the telemetry sources).

The dashboard health endpoint and overview additionally report telemetry
loss within the last `dashboard.health_telemetry_loss_window_minutes`: an
ingested `SYSTEM_EVENT telemetry_loss`, a record with `events_dropped`, or
growth of any loss counter (ring buffer, ingest queue, kernel rate limit,
dropped deny events, AppArmor records) since the previous check.

### `GET /api/v1/health`

Unauthenticated. Returns

```json
{"ok": false, "daemon_up": true, "degraded_reasons": ["kernel enforcement is not ready"],
 "uptime_seconds": 120, "policy_version": "v7", "kernel_ready": false,
 "url_gateway_enabled": false, "url_gateway_ready": false, "audit_write_failures_total": 0}
```

with HTTP 200. Add `?strict=true` to get HTTP 503 while degraded, for
monitors that only look at the status code.

### Status fields

`/api/v1/status/summary` and the control-socket `Health` response carry
(Health fields are `serde(default)`, so old clients and daemons interoperate):

`events_dropped_ringbuf_total`, `kernel_events_rate_limited_total`,
`kernel_deny_events_dropped_total`, `audit_write_failures_total`,
`audit_mirror_failures_total`, `apparmor_records_lost_total`,
`policy_reload_failures_total`, `policy_sync_last_error`,
`telemetry_degraded_reasons`.

The dashboard status also has `backpressure_active`,
`backpressure_activations_total`, `auth_failures_total`,
`dashboard_action_record_failures_total`, `sse_events_skipped_total` and
`degraded_reasons`.

### `/metrics`

New series:

| metric | type |
| --- | --- |
| `mercury_events_dropped_ringbuf_total` | counter |
| `mercury_kernel_events_rate_limited_total` | counter |
| `mercury_kernel_deny_events_dropped_total` | counter |
| `mercury_audit_write_failures_total` | counter |
| `mercury_audit_mirror_failures_total` | counter |
| `mercury_apparmor_records_lost_total` | counter |
| `mercury_policy_reload_failures_total` | counter |
| `mercury_denies_total{class="file\|process\|network\|mcp\|system"}` | counter, DENY records ingested by the dashboard |
| `mercury_auth_failures_total` | counter |
| `mercury_dashboard_action_record_failures_total` | counter |
| `mercury_sse_events_skipped_total` | counter |
| `mercury_health_degraded` | gauge, 1 while `/api/v1/health` is degraded |

## mercury-status

The first output line is unchanged. A second line reports
`events_dropped_ringbuf_total`, `kernel_events_rate_limited_total`,
`kernel_deny_events_dropped_total`, `events_dropped_queue_total`,
`backpressure_active`, `backpressure_activations_total`,
`audit_write_failures_total`, `audit_mirror_failures_total`,
`apparmor_records_lost_total`, `policy_reload_failures_total`,
`policy_sync_enabled`, `policy_sync_last_error` and `enrollment_sync_error`.
Then `degraded=<bool>` and one `degraded_reason=...` line per reason.

Exit status: `0` healthy, `2` degraded, `1` the daemon could not be queried.
`--ignore-degraded` exits 0 while degraded (for scripts that only need the
daemon to be up).

## Webhook alerts

Optional. Disabled unless `alerts.webhook_url` is set.

```yaml
alerts:
  webhook_url: https://hooks.example.com/mercury   # http(s); unset = disabled
  min_severity: deny          # deny | system | all
  rate_limit_per_minute: 60   # 0 = unlimited
  include_resource: true      # include the full resource object
```

Every audit record is offered to the sink; matching records are POSTed one
per request as compact JSON:

```json
{"source": "mercury", "severity": "critical", "timestamp": "...", "event_id": "...",
 "host": "...", "action_type": "PROC_MODULE_LOAD", "decision": "DENY",
 "reason": "DENY_BY_RULE", "rule_id": "...", "agent_id": "...", "profile": "...",
 "pid": 4242, "actor": null, "system_event": null, "message": "...",
 "policy_version": "...", "resource": {...}, "suppressed_since_last": 3}
```

(`null` fields are omitted.)

| `min_severity` | forwards |
| --- | --- |
| `deny` (default) | every DENY (including `auth_failure`), `telemetry_loss` / `audit_file_expired` / `apparmor_cursor_reset`, policy changes (`policy_reload`, `policy_sync`, dashboard policy actions) |
| `system` | the above plus every other `SYSTEM_EVENT` and allowed (observe-mode) `PROC_BPF` / `PROC_MODULE_LOAD` / `PROC_MOUNT` |
| `all` | every record |

`severity` is `critical` for denied tamper-relevant operations
(`PROC_BPF`, `PROC_MODULE_LOAD`, `PROC_MOUNT`) and telemetry loss, `high` for
other denies, policy changes and allowed tamper operations, `medium` for
other system events and `low` otherwise.

The sink never blocks the audit path: alerts over the per-minute limit are
dropped and counted, and reported in the next alert as
`suppressed_since_last`; when the 256-entry send queue is full the alert is
dropped and counted. Delivery failures (non-2xx or network errors, 5 s
timeout) are counted and logged with exponential back-off of the log lines.
`AlertSink::stats()` exposes `matched_total`, `queued_total`, `sent_total`,
`send_failures_total`, `rate_limited_total` and `dropped_queue_full_total`.

## Configuration keys

| key | default |
| --- | --- |
| `dashboard.launch.stop_grace_seconds` | `5` |
| `dashboard.health_telemetry_loss_window_minutes` | `10` |
| `alerts.webhook_url` | unset (alerts disabled) |
| `alerts.min_severity` | `deny` |
| `alerts.rate_limit_per_minute` | `60` |
| `alerts.include_resource` | `true` |
