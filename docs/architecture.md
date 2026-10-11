# Linux-First Security Runtime Architecture

## Runtime chain

LLM -> Agent Runtime -> Tool Execution -> mercury-run -> mercuryd -> Linux kernel hook backend -> OS side effects.

## Components

- `mercury-run` (unprivileged): registers launch process/profile and executes command.
- `mercuryd` (privileged): policy authority, audit sink, control API host.
- `policy-engine`: deterministic deny-overrides-allow evaluation with default deny.
- `linux-adapter`: process tagging and hook backend capability management.

## Policy semantics

- Explicit profile selection by launcher.
- Deny overrides allow.
- Unmatched actions follow global default decision (default deny).
- Per-class enforcement mode (observe/enforce).
- Failure mode (fail-open/fail-closed) configurable.

## Linux enforcement backends

- Active Linux v1 backend: eBPF kernel enforcement in `kernel_strict` mode.
- Exec enforcement: `bprm_check_security`.
- Filesystem enforcement: `file_open`, `inode_unlink`.
- Network enforcement: `socket_connect`.
- Audit path: kernel ring buffer -> daemon periodic drain -> JSONL/journald.
- Auto-enrollment: optional systemd/cgroup scanners seed policy profiles; unmatched processes stay observe-only.

## Audit model

Each action decision can produce a structured event containing:

- timestamp
- agent_id
- action type
- resource payload
- decision
- reason code
- rule_id
- policy_version

Audit output targets:

- append-only JSONL local file
- journald syslog mirror
