# Kernel telemetry and enforcement (eBPF LSM)

This page covers what the eBPF programs in `crates/kernel-ebpf/src/mercury_kern.c`
record and enforce, and how `crates/kernel-runtime` turns ring buffer records into
audit events. See [README.md](README.md) for the other layers.

> **Verification status.** The eBPF object is compiled with `-Werror` for both
> backends, but local BPF-LSM startup on Linux 6.8 fails verifier loading for
> `mercury_socket_connect` (instruction limit). The kernel suites have not passed.
> Use [local-kernel-testing.md](../local-kernel-testing.md) to reproduce and
> verify the fix before relying on these programs in production.

## What every kernel record carries

| Field | Source |
| --- | --- |
| `pid` / `context.tid` | `tgid` / thread id of the acting task |
| `ppid` | `real_parent->tgid` |
| `uid`, `context.gid`, `context.comm`, `context.cgroup_id` | current credentials, task name, cgroup v2 id |
| `agent_id` | the launching agent run (resolved from the enrollment id every descendant inherits); `kernel-pid-<pid>` only if unknown |
| `context.root_pid` | pid that was registered by `mercury-run` (the enrollment root) |
| `context.parent_agent_id` | client agent, for processes of an MCP server agent |
| `rule_id` | the policy rule that decided (kernel rule attribution), or a `builtin:*` id |
| `policy_version`, `context.policy_epoch` | the policy epoch that made the decision, not the one active when the event was drained |
| `kernel_seq` | `(cpu << 48) | per-cpu counter` |
| `context.truncated` | the path could not be resolved (e.g. longer than 255 bytes) |

Built-in rule ids:

| `rule_id` | Meaning |
| --- | --- |
| `builtin:url-enforcement-direct-egress` | URL-enforced profile tried to reach the network without the gateway |
| `builtin:ptrace-outside-enrollment` | ptrace ATTACH (or `/proc/<pid>/mem`, `process_vm_writev`) of a task outside the agent's enrollment |
| `builtin:signal-to-mercury` | signal from an agent to a Mercury-owned task |
| `builtin:bpf-requires-explicit-allow` | `bpf(2)` without an `exec_allow` rule for `<bpf>` |
| `builtin:kernel-module-requires-explicit-allow` | module / kexec load without an `exec_allow` rule for `<kernel-module>` |

## Record types

| `action_type` | Hook | Notes |
| --- | --- | --- |
| `PROC_START` | `sched_process_exec` | after a successful exec: `resource.path` = filename, `resource.argv` (first 511 bytes, `argv_truncated`) |
| `PROC_EXIT` | `sched_process_exit` | once per thread group: `context.exit_code` or `context.exit_signal` |
| `PROC_EXEC` | `bprm_check_security` | the allow/deny decision for an exec |
| `FILE_RENAME` | `path_rename` | `resource.source_path` is the old path |
| `FILE_LINK` | `path_link` | `resource.source_path` is the source *name* only (see limitations) |
| `FILE_CREATE` | `path_mknod` | full destination path; previously only the bare name was seen |
| `NET_CONNECT` / `NET_SENDMSG` | `socket_connect` / `socket_sendmsg` | `resource.family`, `resource.protocol`; AF_UNIX adds `resource.socket_path` (`@name` for abstract sockets) |
| `PROC_PTRACE` | `ptrace_access_check` | `context.target_pid`; READ-mode checks marked NOAUDIT are not recorded |
| `PROC_KILL` | `task_kill` | `context.target_pid`, `context.signal` |
| `PROC_CAPABLE` | `capable` | `context.capability` (a request; the grant is decided elsewhere) |
| `PROC_BPF` | `bpf` | new |
| `PROC_MODULE_LOAD` | `kernel_read_file`, `kernel_load_data` | modules and kexec images |
| `PROC_MOUNT` | `sb_mount`, `move_mount` | `resource.argv[0]` is the mount source when known |
| `PROC_USERNS` | `userns_create` | new |
| `SYSTEM_EVENT telemetry_loss` | kernel rate limiter | per-pid summary: `attributes.suppressed` |

The `bpf`, module, mount and userns hooks are optional: on kernels without them
the daemon starts, `mercury-status` lists them under `telemetry_degraded_reasons`,
and coverage is reduced.

## Loss accounting

* The per-process rate limit (`kernel.rate_limit_per_sec`, default 1000) applies
  only to ALLOW/observe records. **DENY, lifecycle and tamper-relevant records are
  never rate limited**, so a burst of allowed activity cannot hide a blocked
  action. When a window suppressed records, the kernel emits a per-pid
  `telemetry_loss` summary.
* Kernel counters are monotonic and split by cause: ring buffer full
  (`events_dropped_ringbuf_total`), deny records lost to a full ring buffer
  (`kernel_deny_events_dropped_total`, the enforced-but-unlogged case) and rate
  limited (`kernel_events_rate_limited_total`). They are in `mercury-status`,
  `/metrics` and the control-socket health response.
* Every 5 s the daemon compares the counters and writes a
  `SYSTEM_EVENT telemetry_loss` record (`source: daemon`) with the deltas; it is
  a DENY record when deny records were lost.

## Enforcement changes

* **Enrollment integrity.** Enrollment is keyed by thread group. It is no longer
  dropped when the leader thread exits before the others (`pthread_exit` in
  `main`) or when a non-leader thread execs; previously both silently
  un-enrolled a running process. Fork inheritance looks the parent up by tgid,
  so children of threads that existed before enrollment are covered.
* **Launch bypass.** The `mercury-run` handoff bypass is armed only at
  registration. Policy reloads used to re-arm it for every running agent,
  giving file access without enforcement until the agent's next exec.
* **Profile remapping.** Descendant entries are re-resolved to their profile on
  every policy load; a reload that added or removed a profile used to leave
  descendants enforcing a different profile.
* **Explicit enrollment wins over "ignored".** Processes forked by `mercuryd`
  (dashboard launches) inherit the daemon's ignored marker; registration now
  clears it and the kernel checks enrollment first.
* **rename** is also checked against `file_deny` on the *source*, so a denied
  file cannot be moved into an allowed location and read there.
* **File creation** is evaluated on the full path before the inode exists.
* **AF_UNIX sockets.** `file_deny` rules apply to the socket path on connect and
  sendmsg, e.g. `file_deny: [{id: no-docker, pattern: /var/run/docker.sock}]`.
* **ptrace** ATTACH access across the enrollment boundary is refused.
* **Signals** from an agent to Mercury-owned tasks are refused (killing
  `mercuryd` detaches every hook).
* **bpf(2)** and **kernel module / kexec loads** require an explicit
  `exec_allow` entry regardless of the default decision:

  ```yaml
  exec_allow:
    - id: allow-bpf-tools
      path: "<bpf>"
    - id: allow-module-load
      path: "<kernel-module>"
  ```
* **mount / move_mount** and **user namespace creation** are evaluated as
  `"<mount>"` / `"<userns>"` under normal policy semantics. Bind mounts can
  re-expose a denied tree under an allowed path; deny `"<mount>"` for agents
  that do not need their own mount namespace. Sandboxes such as bubblewrap
  need both allowed. With `filesystem_backend: apparmor` (the default), the
  generated AppArmor profiles additionally deny mount operations.

## Daemon restarts

The eBPF programs are not pinned, so while `mercuryd` is down nothing is
enforced or recorded by the eBPF layer (AppArmor profiles stay loaded). The
daemon now persists live registrations and a heartbeat to
`enrollment_state_path` (default `/var/lib/mercury/enrollments.json`, 0600). On
start it re-enrolls every live process of each surviving agent's cgroup under
one enrollment id (`SYSTEM_EVENT enrollment_restored`) and writes a
`telemetry_loss` record with `cause: daemon_downtime`, `gap_start` (last
heartbeat) and `gap_end`. Proxy tokens are not persisted: proxied traffic of a
surviving agent is refused until it is relaunched.

## Known limitations

* Hard-link sources are bare dentries; the kernel cannot resolve their path, so
  `file_deny` is not applied to the source of `link(2)` (the destination is).
* Paths of 256 bytes or more are recorded as `<unknown>` with
  `context.truncated: true` and evaluated as such.
* `PROC_CAPABLE` reports the request, not whether it was granted.
* DNS names, TLS SNI and payload sizes are not visible at this layer; see the
  URL gateway ([gateway-mcp.md](gateway-mcp.md)).
