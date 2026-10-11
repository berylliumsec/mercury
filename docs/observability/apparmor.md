# AppArmor audit ingestion and profile lifecycle

With `filesystem_backend: apparmor` (the default, also under
`backend_mode: kernel_strict`) the eBPF file and exec hooks are not attached.
File and exec visibility and enforcement come from the per-agent AppArmor
profile `mercury-agent-<agent uuid>`, and Mercury reads the kernel's AppArmor
audit records back to produce audit events. Everything here is inert with
`filesystem_backend: ebpf_lsm`.

## Configuration

```yaml
apparmor:
  parser_path: /usr/sbin/apparmor_parser
  generated_policy_dir: /var/lib/mercury/apparmor   # profiles and cursors
  audit_source: auto                   # auto | journald_audit | journald_kernel | audit_log
  audit_log_path: /var/log/audit/audit.log
```

| `audit_source` | Reads |
| --- | --- |
| `auto` (default; `journald` is an accepted alias) | journald `_TRANSPORT=audit` (AVC and USER_AVC) and `_TRANSPORT=kernel` in one query, plus `audit_log_path` when that file exists and is readable. |
| `journald_audit` | journald `_TRANSPORT=audit` only. |
| `journald_kernel` | journald `_TRANSPORT=kernel` only (the behaviour before this change). |
| `audit_log` | `audit_log_path` only. A missing file is reported as a source error. |

`audit_log_path` defaults to `/var/log/audit/audit.log`.

### Choosing a transport

The kernel sends every audit record to three places:

- **printk**, when no auditd is connected. journald stores these as
  `_TRANSPORT=kernel`. They are rate-limited to about 10 records per 5 seconds;
  the kernel reports what it dropped as `kauditd_printk_skb: N callbacks
  suppressed`.
- **auditd**, when it is running. printk then stops.
- **the audit multicast group**. journald receives it as `_TRANSPORT=audit`
  when `systemd-journald-audit.socket` is enabled, whether or not auditd is
  running. This path is not rate-limited.

Profiles are generated with the `audit` flag, so every allowed access is
logged as well as every denial. On a busy agent that far exceeds the printk
limit. For complete telemetry, enable `systemd-journald-audit.socket` or run
auditd. Ubuntu ships the socket but leaves it disabled. With neither, `auto`
falls back to the rate-limited kernel transport and reports the gap as
`telemetry_loss` events (see below).

`auto` reads every available path. When the same record arrives on more than
one, it is emitted once. The deduplication key is the record's audit stamp
`audit(<secs>.<ms>:<serial>)` plus the record body. The key includes the body
because one syscall can emit several records under the same serial, for
example `rename_src` and `rename_dest`.

### Cursors

Each source resumes from a cursor kept in `generated_policy_dir`:

- `journal.cursor` holds the journald cursor.
- `auditlog.cursor` holds `<inode> <offset>` for the audit log. After a
  rotation, Mercury finishes reading `<audit_log_path>.1` (matched by inode)
  before it moves on to the new file.

On first start there is no cursor, so each source starts at its current end.
A cursor is committed only for records that were actually processed, so a
drain cut short by its event limit resumes where it stopped.

## Record mapping

Records whose subject is not a Mercury profile are ignored. For `STATUS` and
`change_*` records the subject is the Mercury profile named in `name=`.

The `apparmor=` value of a record sets its decision:

| Value | Decision / reason |
| --- | --- |
| `AUDIT` | Allowed in enforce mode. `ALLOW` with the Mercury policy's reason (`ALLOW_BY_RULE` plus the rule id). If the policy itself would deny the access, the kernel allowed it through the profile's fixed baseline (`abstractions/base`, library paths, runtime prefixes). The event is then `ALLOW_BY_RULE` with `rule_id: apparmor-baseline`, is counted in `verdict_mismatches`, and is not treated as an enforcement error. |
| `ALLOWED` | A would-deny in complain (observe) mode: `ALLOW` / `ALLOW_BY_OBSERVE_MODE`. |
| `DENIED`, `KILLED` | `DENY` with the policy's reason. A disagreement with the Mercury policy is still reported as `ERROR_ENFORCEMENT_UNAVAILABLE`, as before. |
| `STATUS` | `SYSTEM_EVENT apparmor_profile_<op>` (`load`, `replace`, `remove`). |
| anything else (`HINT`, `ERROR`, ...) | `SYSTEM_EVENT apparmor_unmapped_operation`. |

Operations map to actions as follows:

| AppArmor operation | Action |
| --- | --- |
| `open`, `file_perm`, `file_inherit`, `file_receive`, `file_lock`, `sysctl` | `FILE_*`, chosen from `requested_mask`: `m` gives MMAP, `c` CREATE, `d` DELETE, `w`/`a`/`k` WRITE, `l` LINK, anything else READ. |
| `getattr` / `setattr` | `FILE_READ` / `FILE_CHMOD` |
| `mknod`, `create` (file) | `FILE_CREATE` |
| `unlink`, `rename*`, `link`, `symlink*`, `mkdir`, `rmdir`, `chmod`, `chown`, `truncate`, `file_mmap`, `file_mprotect` | the matching `FILE_*` action |
| `exec` | `PROC_EXEC` |
| `mount`, `umount`, `remount`, `pivotroot`, `move_mount` | `PROC_MOUNT`, with the mount details in `argv_hash` |
| `userns_create` | `PROC_USERNS` |
| `signal` | `PROC_KILL`: `context.signal` is the signal number, `context.target_pid` comes from `peer_pid` when logged |
| `ptrace` | `PROC_PTRACE` (`context.target_pid`) |
| `capable` | `PROC_CAPABLE` (`context.capability`) |
| `connect`, `sendmsg`, `bind`, `listen`, `accept`, `create` (socket) | `NET_*`. AF_UNIX records set `resource.family: unix` and `resource.socket_path` (the path, or `@abstract`). inet records set `family` too. |
| anything else (`recvmsg`, `getsockopt`, `change_profile`, `dbus_*`, ...) | `SYSTEM_EVENT apparmor_unmapped_operation` |

An `apparmor_unmapped_operation` event keeps the record's decision, and the
raw fields (`operation`, `apparmor`, `class`, masks, `peer`, addresses) are
copied into its attributes. Mercury never drops such a record.

Other fields on every event:

- **Timestamp**: the record's own audit stamp, not the time journald received
  it.
- **`context.correlation_id`**: `audit(<secs>.<ms>:<serial>)`.
- **`context.source`**: `apparmor`.
- **`context.comm`**: the task's command name.
- **`context.root_pid`**: the enrollment root, when known.
- **Paths and `comm`**: the kernel hex-encodes values that contain spaces,
  quotes or non-ASCII bytes. Mercury decodes them.
- **`info`, `error`, `requested_mask`, `denied_mask`, `peer` and the full
  label**: appended to `message`.
- **`ppid`**: read from `/proc/<pid>/stat`, but only when that pid is still
  alive and still under the same label. Otherwise it is left empty. It is
  never guessed from the enrollment root.
- **`PROC_EXEC` `cwd`**: read from `/proc/<pid>/cwd` under the same condition,
  otherwise left empty.

### Attribution

Each record is attributed to an agent from the first of these that is
available:

1. the registered subject (in memory)
2. a cache of every Mercury label seen during this run
3. the label itself (`mercury-agent-<uuid>` gives the agent id) together with
   the `# mercury_profile=` header of the generated profile file

The label fallback keeps records attributable after a daemon restart, for
agents that are still confined. When the Mercury profile cannot be recovered,
the event has `profile: unknown` and is not checked against the policy. If
even the agent id cannot be recovered, the event is still emitted, with
`agent_id` set to the raw label, and counted in `records_unattributed`.

### Bootstrap suppression

For 3 s after a pre-exec launch, records from the enrollment root that are
not denials are hidden, but only if they come from the launcher itself: the
comm or executable is `mercury-run`, or the operation is `file_inherit`. The
agent's own records, including observe-mode would-denies, are never hidden.
Hidden records are counted in `records_suppressed_bootstrap`.

## Telemetry loss and gaps

| Event | When |
| --- | --- |
| `SYSTEM_EVENT telemetry_loss` | The kernel log says audit records were lost. The `source` attribute is `kernel_printk` (from `kauditd_printk_skb: N callbacks suppressed`), `kernel_audit_lost` (from `audit_lost=N`, reporting the increase and carrying `audit_lost_total`), `kernel_audit_backlog`, `kernel_audit_hold_queue` or `kernel_audit_rate_limit`. The event also carries `count`, `origin` and `audit_transport_active`. `audit_transport_active: true` means records also arrive over journald's audit transport, so printk suppression lost nothing. |
| `SYSTEM_EVENT apparmor_cursor_reset` | A source lost its position, which marks a telemetry gap. The `reason` attribute is `corrupt_cursor_file`, `journal_rejected_cursor` (with `gap_start`), `audit_log_truncated` or `audit_log_rotated`. |
| `SYSTEM_EVENT apparmor_source_error` | journalctl or the audit log could not be read (`stage: read`), or a cursor could not be saved (`stage: cursor_persist`). The same error is announced at most once a minute. |

A source error never discards records that were already read. The drain
returns what it has, and the in-memory cursor still advances past it. A
failed cursor save only means those records may be read again after a
restart.

The adapter no longer truncates a drain. Events beyond the caller's limit are
carried into the next drain and counted in `overflow_carried`. Sources are
only asked for what fits next to the carried events, so the carry never
exceeds one batch.

## Profile lifecycle

When an agent's enrollment root exits, its profile is no longer removed
straight away, because removing it would leave double-forked or daemonized
children unconfined and unobserved. Instead:

1. The label is marked as retiring.
2. Each prune cycle (`LinuxAdapter::prune_stale_enrollments`, every 30 s in
   the daemon, or `LinuxAdapter::prune_apparmor_profiles`) counts the live,
   non-zombie tasks in `/proc/*/attr/apparmor/current` (falling back to
   `attr/current`) whose label is the retiring one.
3. While any such task exists, the profile stays loaded and is refreshed on
   every policy reload.
4. Once none is left, Mercury runs `apparmor_parser --remove`, deletes the
   profile file and emits `SYSTEM_EVENT agent_exited`. That event carries
   `root_pid`, `profile`, `confined_after_root_exit` (the most tasks seen after
   the root exited), `deferred_checks`, `retired_secs`, `profile_removed` and
   `error` when removal failed.

On start, profile files left in `generated_policy_dir` by an earlier daemon
run are adopted: their records are attributed, and they go through the same
retire-then-remove path.

The `linux_compat` backend now prunes dead enrollments as well. Before this
change, they were never removed.

## Counters

`LinuxAdapter::apparmor_telemetry_stats()` returns `AppArmorTelemetryStats`,
a serde-serializable struct with these fields:

- `records_parsed`
- `records_emitted`
- `records_unmapped`
- `records_unattributed`
- `records_deduplicated`
- `records_suppressed_bootstrap`
- `verdict_mismatches`
- `parse_errors`
- `source_errors`
- `cursor_persist_errors`
- `cursor_resets`
- `kernel_suppressed_callbacks`
- `kernel_audit_lost`
- `overflow_carried`
- `profiles_pending_removal` (a gauge, not a counter)
- `profiles_removed`
