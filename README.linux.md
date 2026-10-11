# Mercury Linux Runtime Guide

This document is the implementation-level guide for the Linux-only Mercury runtime.

## Quick Install (GitHub Releases)

Linux `x86_64` installs are published as GitHub Release assets.

1. Download `install-mercury-linux.sh` from the release you want.
2. Inspect it, then optionally verify it against the signed `SHA256SUMS` / `SHA256SUMS.sig`
   assets from the same release.
3. Run the built-in preflight check.
4. Run the installer as root.

```bash
chmod +x ./install-mercury-linux.sh
./install-mercury-linux.sh --preflight-only
sudo ./install-mercury-linux.sh
```

`mercury-status preflight` also reports `support_level=fully_tested|compatible|unsupported`. The
current tested release target is `ubuntu-24.04-x86_64`.

The release installer keeps the dashboard on `127.0.0.1:7480` by default. To expose it
intentionally, pass `--dashboard-expose` or `--dashboard-bind-addr <addr>`.

Non-loopback dashboard binds require a trusted TLS certificate. Use `--acme-domain` /
`--acme-email` or `--tls-cert-file` / `--tls-key-file`, or keep Mercury on localhost behind a
reverse proxy.

If you explicitly want Mercury's self-signed certificate on a non-loopback bind, pass
`--dashboard-allow-self-signed` together with `--dashboard-expose` or `--dashboard-bind-addr`.

The installer downloads `mercury-linux-x86_64.tar.gz` from the matching release tag, verifies the
signed checksum file before trusting the payload, and preserves existing
`/etc/mercury/config.yaml` and `/etc/mercury/policy.yaml` files by writing updated defaults
as `.new` files during upgrades.

Fresh installs also generate `/etc/mercury/dashboard.password`, `/etc/mercury/policy-signing-key`,
and re-sign `/etc/mercury/policy.yaml` so required policy signatures are enabled without exposing
first-login bootstrap signup.

Uninstall while preserving config and runtime data:

```bash
sudo ./install-mercury-linux.sh --uninstall
```

Purge `/etc/mercury`, `/var/lib/mercury`, and `/var/log/mercury` too:

```bash
sudo ./install-mercury-linux.sh --uninstall --purge
```

## 1) Scope and Current State

Mercury on Linux currently provides:

- A production control plane (`mercuryd`, `mercury-run`, `mercury-policy`, `mercury-status`)
- Policy parsing/validation/evaluation in Rust
- eBPF program loading and attachment through Aya
- Kernel event capture via ring buffer and daemon audit ingestion
- Process enrollment (`mercury-run`) + optional auto-enrollment via cgroup pattern scan

### Implementation status

- Implemented: kernel hook attach + event ingestion + audit pipeline
- Implemented: userspace policy decisions (`mercury-policy test`, daemon test path)
- Implemented: kernel policy IR compilation and epoch swap bookkeeping
- Implemented: in-kernel allow/deny for file/exec/network hooks (with observe-mode downgrade behavior)
- Implemented: full-URL policy layer (`url_allow` / `url_deny`) through local HTTP(S) gateway
- Implemented: kernel anti-bypass guardrails for URL-enforced profiles (direct outbound denied unless exempted)

## 2) Architecture Overview

### 2.1 Control/Data Plane Topology

```text
Clients
-------
  mercury-run --profile <p> -- <cmd>     mercury-policy reload/test     mercury-status/dashboard
                 \                         |                          /
                  \                        |                         /
                   +-----------------------+------------------------+
                                           |
                                           v
                         Unix socket: /run/mercury/mercuryd.sock
                                           |
                                           v
  +----------------------------------------------------------------------------------+
  | mercuryd (root, systemd unit)                                                   |
  |----------------------------------------------------------------------------------|
  | Control API server  | PolicyEngine | URL Gateway | LinuxAdapter | KernelRuntime |
  | Enrollment state    | Policy epoch swap + map sync | Audit logger | Dashboard   |
  +---------------------+-------------------------------+------------------------------+
             |                          |                               |
             | auto-enroll scan         | load/attach + map updates      | event ingest
             v                          v                               v
  /sys/fs/cgroup/**/cgroup.procs   +-----------------------------------------------+
                                    | Linux kernel (BPF LSM + tracepoints)         |
                                    |-----------------------------------------------|
                                    | LSM hooks:                                    |
                                    |   file_open | path_unlink | bprm_check_security |
                                    |   socket_connect                                |
                                    | Tracepoints:                                   |
                                    |   sched_process_fork | sched_process_exec      |
                                    |   sched_process_exit                           |
                                    | BPF maps:                                      |
                                    |   mercury_enrolled_pids  mercury_profiles    |
                                    |   mercury_file_rules     mercury_exec_rules  |
                                    |   mercury_net_rules      mercury_offsets     |
                                    |   mercury_ignored_pids   mercury_stats       |
                                    |   mercury_events (ring buffer)                |
                                    +---------------------------+---------------------+
                                                                |
                                                                | periodic drain (~200ms)
                                                                v
                                        +------------------------------------------+
                                        | Audit pipeline                            |
                                        | - /var/log/mercury/audit.jsonl          |
                                        | - journald mirror                         |
                                        | - dashboard event stream                  |
                                        +------------------------------------------+

                 URL Gateway (full URL policy)
                 ------------------------------
                 enrolled workload
                   -> HTTP_PROXY / HTTPS_PROXY (mercury-run injected)
                   -> 127.0.0.1:<gateway-port>
                   -> HTTP request parse OR HTTPS CONNECT interception
                   -> evaluate `url_deny` then `url_allow` (deny > allow > default)
                   -> emit URL-rich network audit event (full_url/scheme/method/path/query)
                   -> forward upstream on allow, return 403 on deny

                 Kernel anti-bypass for URL profiles
                 ------------------------------------
                 when profile has URL rules:
                   allow loopback TCP egress only to configured gateway port
                   allow explicit `network_allow` exceptions
                   deny all other direct outbound connect attempts
```

### 2.2 Enrollment and Decision Flow

```text
mercury-run --profile default -- <cmd>
  -> RegisterAgent(pid, uid, gid, profile, cmdline, cwd)
  -> daemon assigns agent_id/cgroup_id and records enrollment metadata
  -> daemon writes pid to /sys/fs/cgroup/mercury/agents/ai-<id>/cgroup.procs
  -> runtime syncs mercury_enrolled_pids map
  -> <cmd> executes; descendants inherit enrollment via sched_process_fork

On each hooked operation (file/exec/net/delete):
  -> lookup mercury_enrolled_pids[pid]
  -> lookup mercury_profiles[profile_index]
  -> evaluate against class rule maps (file/exec/net + workspace roots)
  -> apply enforcement mode for class (enforce vs observe)
  -> produce decision/reason/action/resource record
  -> emit RawKernelEvent to mercury_events ring buffer
  -> daemon drains ring buffer, converts to AuditEvent, persists/logs/serves
```

## 3) Runtime Flows

### 3.1 Daemon startup flow

```text
mercuryd
  -> load config YAML
  -> initialize Linux adapter
  -> kernel runtime start:
       - check Linux >= 6.1
       - check bpffs path exists
       - check BPF LSM enabled
       - check cgroup v2
       - load embedded eBPF object
       - attach LSM + tracepoint programs
  -> load initial policy via policy-engine
  -> serve Unix socket + periodic kernel event drain
```

### 3.2 Process enrollment flow (`mercury-run`)

```text
mercury-run --profile default -- <cmd>
  -> connect /run/mercury/mercuryd.sock
  -> send RegisterAgent(pid, uid, gid, profile, cmdline, cwd)
  -> daemon assigns agent_id + cgroup_id
  -> daemon writes pid into /sys/fs/cgroup/mercury/agents/ai-<id>/cgroup.procs
  -> daemon stores enrollment metadata
  -> mercury-run execs target command with:
       MERCURY_AGENT_ID
       MERCURY_PROFILE
       MERCURY_CGROUP_ID
       HTTP_PROXY / http_proxy
       HTTPS_PROXY / https_proxy
       NO_PROXY / no_proxy
       SSL_CERT_FILE
       REQUESTS_CA_BUNDLE
       NODE_EXTRA_CA_CERTS
       CURL_CA_BUNDLE
       GIT_SSL_CAINFO
```

### 3.3 Auto-enrollment flow (optional)

```text
config.kernel.auto_enroll_rules[*]
  -> every scan, daemon walks cgroup_root/**/cgroup.procs
  -> glob-match path against cgroup_pattern
  -> read pids from matching cgroup.procs
  -> create enrollment entries with source=auto_enroll
```

### 3.4 Policy reload flow

```text
mercury-policy --socket ... reload --file policy.yaml
  -> daemon validates+compiles policy (policy-engine)
  -> compile_kernel_ir(policy)
  -> create new epoch (inactive->active swap)
  -> retain active+previous epoch (bounded rollback window)
  -> update userspace evaluator policy
```

### 3.5 Kernel event to audit flow

```text
Kernel hook hit
  -> eBPF program emits RawKernelEvent to mercury_events ringbuf
  -> daemon tick (50ms) drains ringbuf; loss counters reported as telemetry_loss records
  -> decode RawKernelEvent -> AuditEvent
  -> write JSONL (+ journald mirror if enabled)
```

## 4) Components and Responsibilities

| Component | Path | Responsibility |
|---|---|---|
| Core schema | `crates/core-types` | Canonical action/resource/decision/audit models |
| Policy engine | `crates/policy-engine` | YAML validation + deterministic matching + kernel IR compile |
| Control API | `crates/control-api` | Unix socket request/response framing |
| Kernel matcher | `crates/kernel-matcher` | Kernel matcher constants + deterministic glob behavior primitives |
| Kernel object | `crates/kernel-ebpf` | Embedded eBPF C object build + program/map symbols |
| Kernel runtime | `crates/kernel-runtime` | Aya load/attach, enrollment, epoch tracking, ringbuf drain |
| Linux adapter | `crates/linux-adapter` | Adapter boundary for daemon, capability/status mapping |
| Daemon | `crates/daemon` | Policy authority, control server, audit sink |
| Launcher | `crates/launcher` (`mercury-run`) | Agent registration then command exec |
| CLI tools | `crates/cli` | `mercury-policy` and `mercury-status` |
| Audit crate | `crates/audit` | JSONL write/rotation and journald mirror |

## 5) Linux Prerequisites

## 5.1 Kernel/runtime requirements

- Linux kernel `>= 6.1`
- BPF LSM enabled in kernel LSM list (`/sys/kernel/security/lsm` contains `bpf`)
- bpffs mounted (default `/sys/fs/bpf`)
- cgroup v2 mounted (`/sys/fs/cgroup/cgroup.controllers` exists)

## 5.2 Build requirements

- Rust toolchain (`cargo`)
- `clang` with BPF target support

Check quickly:

```bash
uname -r
test -d /sys/fs/bpf && echo "bpffs ok"
test -f /sys/fs/cgroup/cgroup.controllers && echo "cgroup v2 ok"
grep -q '\bbpf\b' /sys/kernel/security/lsm && echo "bpf lsm ok"
clang --version
llc --version | rg bpf
```

## 6) Build and Test

Build all:

```bash
cargo build --workspace
```

Run all tests:

```bash
cargo test --workspace
```

Repo-wide quality entrypoints from the repository root:

```bash
make format-check
make lint
make test
```

### Repo-local install from a checked-out source tree

If you are building from source instead of GitHub Releases:

```bash
cargo build --release --workspace
npm --prefix dashboard/linux-ui ci
npm --prefix dashboard/linux-ui run build
sudo ./scripts/install_mercury_system.sh --preflight-only
sudo ./scripts/install_mercury_system.sh
```

The repo-local installer uses the same install helpers as the release installer, preserves
existing `/etc/mercury` files by writing `.new` siblings instead of overwriting them, and stops on
failed preflight unless you explicitly pass `--force`.

Remove a repo-local install while preserving config and runtime data:

```bash
sudo ./scripts/uninstall_mercury_system.sh
```

### Dashboard UI build (React + Vite)

Build the Linux dashboard bundle:

```bash
npm --prefix dashboard/linux-ui ci
npm --prefix dashboard/linux-ui run build
```

Then point daemon config `dashboard.static_dir` to the build output:

```yaml
dashboard:
  static_dir: /path/to/repo/dashboard/linux-ui/dist
```

Build a static guided dashboard demo, no daemon required:

```bash
npm --prefix dashboard/linux-ui ci
npm --prefix dashboard/linux-ui run build:demo
```

This writes a fixture-backed click-through demo to `docs/demo/`. The hosted build auto-signs into
seeded dashboard data and keeps edits in browser memory so people can explore the UI without
installing Mercury.

Hosted live demo:

<https://upgraded-adventure-r3gn15y.pages.github.io/>

Preview the generated bundle locally:

```bash
npm --prefix dashboard/linux-ui run preview:demo
```

The repo includes a GitHub Pages workflow at
[`github-pages-demo.yml`](./.github/workflows/github-pages-demo.yml). Once Pages is configured to
use GitHub Actions in repository settings, pushes to `main` publish the static demo automatically.

Bootstrap auth options:

1) First-run signup (default if `/etc/mercury/dashboard.password` is missing):
- Open the dashboard and create username/password in the signup form.

2) CLI rotate (for forgotten password or pre-provisioning):

```bash
mercury-policy dashboard-password rotate --file /etc/mercury/dashboard.password --username admin
```

The CLI command prints one-time credentials (`dashboard_username` + `dashboard_password`) and overwrites the stored hash.

Linux harness scripts:

```bash
./samples/oss-agents/run_smolagents_policy_test.sh
TIMEOUT_SECS=900 ./samples/oss-agents/run_major_agents_policy_test.sh
./samples/oss-agents/benchmark_kernel_overhead.sh
```

## 7) Configuration Reference (`/etc/mercury/config.yaml`)

Example:

```yaml
socket_path: /run/mercury/mercuryd.sock
policy_path: /etc/mercury/policy.yaml
audit_jsonl_path: /var/log/mercury/audit.jsonl
log_level: info
mirror_to_journald: true
signature_verification: require_valid
signature_key_path: /etc/mercury/policy-signing-key
policy_unavailable_mode: fail_closed
backend_mode: kernel_strict
cgroup_base: /sys/fs/cgroup/mercury/agents
kernel:
  bpffs_path: /sys/fs/bpf
  cgroup_root: /sys/fs/cgroup
  event_buffer_pages: 256
  auto_enroll_rules:
    - id: ide-agent
      cgroup_pattern: "**/user.slice/**/code-*.scope/cgroup.procs"
      profile: default
      mode: enforce
  unmatched_host_mode: observe
```

### Field details

| Field | Meaning |
|---|---|
| `socket_path` | Unix socket for local control API |
| `policy_path` | Startup policy file path |
| `audit_jsonl_path` | Audit log path (HMAC-chained, rotated; see `docs/observability/audit.md`) |
| `log_level` | Tracing level (`info`, `debug`, etc.) |
| `mirror_to_journald` | Mirror each audit entry to journald (native protocol; `journald_mirror_mode: syslog` for the old syslog-socket behavior) |
| `signature_verification` | `disabled`, `warn_on_invalid`, `require_valid` |
| `policy_unavailable_mode` | Fail behavior if policy missing (`fail_open` / `fail_closed`) |
| `backend_mode` | Linux backend mode (`kernel_strict`) |
| `cgroup_base` | Root for per-agent cgroup placement |
| `kernel.bpffs_path` | bpffs mount location used by kernel runtime checks |
| `kernel.cgroup_root` | cgroup root used for auto-enroll scanning |
| `kernel.event_buffer_pages` | ring/event buffer sizing knob (reserved) |
| `kernel.auto_enroll_rules[]` | cgroup path pattern -> profile mapping |
| `kernel.unmatched_host_mode` | behavior for unmatched host processes (`observe`) |

## 8) Policy Model (`/etc/mercury/policy.yaml`)

High-level policy semantics from `policy-engine`:

- Deny rules checked before allow rules
- Class-specific enforcement mode (`observe` vs `enforce`)
- Default decision fallback (`allow` or `deny`)
- Profile-scoped rule sets for file/exec/network

Rule classes:

- `file_allow` / `file_deny` with glob path patterns
- `exec_allow` / `exec_deny` with glob executable path patterns
- `network_allow` / `network_deny` with `cidr`, `protocol`, optional `port`, optional host glob
- `url_allow` / `url_deny` with `scheme`, `host_glob`, optional `port`, optional `method`,
  `path_glob`, optional `query_glob`
- `mcp` with `stdio` / `http` server transport, tool actions, and resource URI actions; HTTP
  registrations receive a Mercury gateway URL plus per-session bearer token for proxied
  `tools/call`, `resources/read`, `prompts/list`, and `prompts/get`

Backend coverage:

| Surface | `kernel_strict` | `linux_compat` |
| --- | --- | --- |
| File + exec | enforced | enforced via AppArmor |
| Raw network connect/sendmsg/bind/create | enforced | enforced via AppArmor |
| Raw network `listen` / `accept` | observe-only | enforced via AppArmor |
| `capable` | observe-only | enforced via AppArmor |
| `bpf(2)`, kernel module / kexec load | enforced (explicit `exec_allow` for `<bpf>` / `<kernel-module>` required) | not mediated |
| `mount` / `move_mount`, user namespace creation | enforced as `<mount>` / `<userns>` (hook optional per kernel) | mount denied by AppArmor profiles |
| ptrace attach outside the enrollment, signals to Mercury | refused | per AppArmor profile |
| AF_UNIX connect to a `file_deny` path | enforced | per AppArmor profile |
| URL gateway policy | enforced when gateway is ready | enforced when gateway is ready |
| MCP `tools/call` / `resources/read` / `prompts/list` / `prompts/get` | enforced | enforced |

### 8.1 Model traffic visibility (`url_gateway.model_traffic`)

The URL gateway streams every response to the client as it arrives. It does not buffer bodies,
and `request_timeout_ms` only limits the wait for response headers. Model hosts get a longer
header deadline (`model_traffic.request_timeout_ms`) because non-streaming completions only
send headers once generation is finished. `body_idle_timeout_ms` limits the pause between
chunks, not the total transfer time. WebSocket upgrades are relayed for plain HTTP proxy
requests and inside intercepted HTTPS tunnels.

With `model_traffic.capture` set to `metadata` or `content`, each model API exchange with a
recognised host and path produces a second audit event with a `model` object. This covers
OpenAI chat completions and responses, Anthropic messages, Gemini and Vertex
`generateContent` and `rawPredict`, Bedrock `converse` and `invoke`, and Responses API calls
sent over WebSocket.

| Mode | Recorded |
| --- | --- |
| `off` (default) | URL-level network events only |
| `metadata` | provider, API, model, stream/transport, status, duration, request/response bytes, request SHA-256, message count, tools offered, tool call names, finish reason, token usage, errors |
| `content` | metadata plus system prompt, the last `max_messages` messages, output text, reasoning text, and tool call arguments |

Captured text is truncated to `max_text_chars` per field. Strings that look like credentials
(`sk-…`, `AKIA…`, `AIza…`, `ghp_…`, `Bearer …`, and similar) are replaced with `[REDACTED]`.
Request headers are never recorded, so API keys sent in `Authorization`, `x-api-key`, or
`x-goog-api-key` headers stay out of the log. To keep captured traffic readable, the gateway
asks model APIs for uncompressed responses (`Accept-Encoding: identity`) and removes
`Sec-WebSocket-Extensions` from WebSocket handshakes it observes. Bodies that still arrive
compressed, and Bedrock's binary event streams, are recorded as metadata with a
`capture_note`.

`content` mode writes prompts and model output to `/var/log/mercury/audit.jsonl`, to the
journald mirror, and to the dashboard database. Treat those as sensitive before you enable it.

In the dashboard, a model call shows up on the Live Events tab with a provider/model badge on
its row and a **Transcript** action (**Model call** when only metadata was captured). The
dialog lists the API, transport, status, duration, token usage, finish reason, byte counts and
tools offered, then the captured system prompt, messages, model output, reasoning and tool call
arguments. It reports what the gateway left out — clipped fields, messages dropped by
`max_messages`, and any `capture_note` — because the stored text is redacted and truncated
rather than a verbatim copy of the exchange. **Copy JSON** yields the raw `model` object.

Example model event (abridged):

```json
{"action_type":"NET_CONNECT","decision":"ALLOW","agent_id":"...","resource":{"kind":"NETWORK","full_url":"https://api.anthropic.com/v1/messages", "...":"..."},
 "message":"model call provider=anthropic model=claude-opus-5 status=200 duration_ms=8123",
 "model":{"provider":"anthropic","api":"anthropic.messages","transport":"sse","model":"claude-opus-5","stream":true,
          "status":200,"message_count":14,"tools_offered":["Bash","Read"],"tool_calls":[{"name":"Bash","id":"toolu_..."}],
          "finish_reason":"tool_use","usage":{"input_tokens":5120,"output_tokens":210,"cache_read_tokens":4800},"truncated":false}}
```

## 9) CLI Reference

## 9.1 `mercury-policy`

Validate:

```bash
./target/release/mercury-policy validate --file samples/policy.yaml
```

Reload daemon policy:

```bash
./target/release/mercury-policy --socket /run/mercury/mercuryd.sock reload --file /etc/mercury/policy.yaml
```

Test decision through daemon evaluator:

```bash
./target/release/mercury-policy --socket /run/mercury/mercuryd.sock test \
  --profile default \
  --action file-read \
  --path /etc/hosts
```

## 9.2 `mercury-run`

```bash
./target/release/mercury-run --profile default -- /usr/bin/env
```

## 9.3 `mercury-status`

```bash
./target/release/mercury-status --socket /run/mercury/mercuryd.sock
```

Typical fields:

- `backend_mode=kernel_strict`
- `kernel_ready=true|false`
- `kernel_program_version=...`
- `auto_enroll_active_rules=<n>`
- `unmatched_mode=observe`
- `dashboard_schema_version=<n>`
- `pending_mcp_approvals=<n>`
- `active_mcp_sessions=<n>`
- `exec_hook/network_hook/filesystem_hook`

## 10) Systemd Deployment

Service file: `deploy/systemd/mercuryd.service`

Key hardening/capability choices:

- `NoNewPrivileges=true`
- strict filesystem protections
- explicit writable paths for runtime/audit/cgroup/bpffs
- capability set includes:
  - `CAP_BPF`
  - `CAP_PERFMON`
  - `CAP_SYS_ADMIN`
  - `CAP_DAC_READ_SEARCH`

Install:

```bash
sudo ./install-mercury-linux.sh
```

For local source builds, `sudo ./scripts/install_mercury_system.sh` installs the same service and
runtime files from repo-built artifacts. It supports `--preflight-only` and `--force`, just like
the signed release installer.

After adding your user to `mercury`, start a new login session so group membership applies before
running `mercury-run` without `sudo`.

## 11) Observability and Logs

Default audit file:

- `/var/log/mercury/audit.jsonl`

Each event contains:

- timestamp
- agent_id
- action_type
- decision
- reason
- rule_id
- resource payload
- profile
- policy_version
- message

Quick inspection:

```bash
tail -f /var/log/mercury/audit.jsonl
rg '"decision":"DENY"|"decision":"ALLOW"' /var/log/mercury/audit.jsonl
```

## 12) Troubleshooting

## 12.1 Daemon fails at startup

Check:

```bash
journalctl -u mercuryd -n 200 --no-pager
```

Common causes:

- kernel < 6.1
- bpffs not mounted
- BPF LSM not enabled
- cgroup v2 unavailable
- missing privileges/capabilities under service manager

## 12.2 `kernel_ready=false`

- run `mercury-status`
- verify all prerequisite checks in section 5.1
- verify service is running as root with expected capability set

## 12.3 No audit events from kernel hooks

- ensure daemon is running and draining (ticker every 200ms)
- confirm eBPF object includes expected programs/maps
- validate ring buffer map name is `mercury_events`

## 13) Security Notes

- Keep `/etc/mercury` root-owned and write-restricted
- Treat policy files as privileged configuration
- Prefer `policy_unavailable_mode: fail_closed` in production
- Forward JSONL/journald outputs to centralized logging/SIEM
- Follow the support matrix, backup, and rollback guidance in [`docs/public-prod.md`](docs/public-prod.md)

## 14) Current Limitations

- `linux_compat` is intentionally narrower than `kernel_strict`; raw non-URL network mediation
  still follows AppArmor semantics there rather than the eBPF LSM path
- MCP v1 covers `stdio` and `http` transports plus `tools/call`, `resources/read`,
  `prompts/list`, and `prompts/get`, but not sampling or elicitation
- `stdio` MCP still relies on client-side control-socket authorization integration; HTTP MCP
  approvals are enforced directly through the Mercury gateway
- Model traffic capture only sees clients that use the gateway. Loopback model servers (Ollama,
  vLLM, and similar) are in `no_proxy`, so they show up only as kernel connect events. Request
  bodies compressed by the client (for example `zstd`) are recorded as metadata only.

## 15) Repository Pointers

- Linux architecture notes: `docs/architecture.md`
- Linux install hardening notes: `docs/install.md`
- Public production guide: [`docs/public-prod.md`](docs/public-prod.md)
- Repository overview: `README.md`
