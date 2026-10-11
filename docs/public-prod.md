# Public Production Guide

Mercury is ready for public production on supported Linux hosts, but the support contract is
deliberately narrow.

## Support Contract

`mercury-status preflight` now reports both a hard prerequisite result and a support tier.

- `support_level=fully_tested`
  Mercury is running on the tested release target: `ubuntu-24.04-x86_64`.
- `support_level=compatible`
  The host satisfies Mercury's prerequisites, but it is outside the primary tested release target.
- `support_level=unsupported`
  The host is missing required prerequisites and Mercury should not be installed without an
  explicit operator override.

Current public target:

| Target | Status |
| --- | --- |
| Ubuntu 24.04 `x86_64` with systemd | fully tested |
| Other Linux `x86_64` hosts with systemd that pass preflight | compatible |
| Non-Linux or non-`x86_64` hosts | unsupported |

Backend tiers:

| Backend mode | When to use it | Guarantees |
| --- | --- | --- |
| `kernel_strict` | Preferred on hosts with Linux 6.1+, bpffs, BPF LSM, and cgroup v2 | Full kernel-backed file, exec, raw-network, URL, and MCP enforcement |
| `linux_compat` | Opt-in fallback when AppArmor is available but full eBPF-LSM prerequisites are not | File, exec, raw-network, and `capable` mediation via AppArmor, plus URL policy through Mercury's gateway and MCP semantic policy |

## Install And Upgrade

Run preflight before every install or upgrade:

```bash
./install-mercury-linux.sh --preflight-only
./target/release/mercury-status preflight --json
```

Repo-local installs now mirror the release installer:

```bash
sudo ./scripts/install_mercury_system.sh --preflight-only
sudo ./scripts/install_mercury_system.sh
sudo ./scripts/install_mercury_system.sh --force
```

Behavior:

- fresh installs write the host-recommended `backend_mode`
- upgrades preserve existing `/etc/mercury/config.yaml` and `/etc/mercury/policy.yaml`
- repo-local and release installers both stop on failed preflight unless `--force` is used

## Backup And Restore

Before upgrading, capture both configuration and dashboard state:

```bash
sudo install -d -m 0700 /var/backups/mercury
sudo cp -a /etc/mercury /var/backups/mercury/etc-$(date +%Y%m%d-%H%M%S)
sudo sqlite3 /var/lib/mercury/dashboard.db ".backup '/var/backups/mercury/dashboard-$(date +%Y%m%d-%H%M%S).db'"
```

To restore:

1. Stop the service: `sudo systemctl stop mercuryd`
2. Restore `/etc/mercury`
3. Restore `dashboard.db`
4. Start the service: `sudo systemctl start mercuryd`

## Rollback

There are two rollback paths:

1. Policy rollback:
   use the dashboard Policy Versions view or `POST /api/v1/policy/versions/{id}/rollback`
2. Release rollback:
   reinstall the previous Mercury release without `--purge`, then restart `mercuryd`

Because `/etc/mercury` and `/var/lib/mercury` are preserved by default, release rollback does not
require rebuilding policy or dashboard state from scratch.

## Operational Checks

Use the unauthenticated liveness probe for load balancers:

- `GET /api/v1/health`

Use `mercury-status --dashboard` or the dashboard Overview tab for richer operational state:

- `dashboard_schema_version`
- `policy_versions_total`
- `pending_mcp_approvals`
- `active_dashboard_sessions`
- `active_sse_clients`
- `active_mcp_sessions`
- `dashboard_sqlite_bytes`
- per-surface `coverage`

Recommended alerts:

- `dashboard_ready=false`
- `url_gateway_ready=false`
- `kernel_ready=false` on `kernel_strict` hosts
- `pending_mcp_approvals` growing unexpectedly
- `ingest_backlog_len` growing steadily
- `events_dropped_queue_total` non-zero
- `kernel_deny_events_dropped_total` non-zero (denies were enforced but not logged)
- `events_dropped_ringbuf_total` or `apparmor_records_lost_total` increasing
- `audit_write_failures_total` / `audit_mirror_failures_total` non-zero
- `telemetry_degraded_reasons` non-empty (`mercury-status` exits `2`)
- any `SYSTEM_EVENT` with `resource.event` = `telemetry_loss` (including
  `cause: daemon_downtime` after a restart) in the audit stream

Alternatively configure `alerts.webhook_url` so the daemon pushes denies,
telemetry loss and tamper-relevant records itself (see
`docs/observability/control-plane.md`). With the AppArmor filesystem backend,
enable `systemd-journald-audit.socket` or auditd: the kernel's printk path is
rate limited and loses records (see `docs/observability/apparmor.md`).

## MCP HTTP Gateway

For HTTP MCP, clients should connect to the Mercury-hosted loopback gateway returned at server
registration time and authenticate with either:

- `Authorization: Bearer <token>`
- `x-mercury-mcp-gateway-token: <token>`

Query-parameter tokens are not supported.
