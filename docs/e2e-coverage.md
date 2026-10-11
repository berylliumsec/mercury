# End-to-End Coverage Audit

This document tracks what Mercury exercises with end-to-end coverage today, what is only partially covered, and which runtime action surfaces still lack explicit end-to-end assertions.

The Linux kernel suites are run locally; see [local-kernel-testing.md](local-kernel-testing.md).
"Covered" below means an assertion exists, not that it passed on the current
commit and host.

## Product Workflow Matrix

| Area | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Dashboard auth bootstrap, login, logout, password rotation | Covered | `dashboard/linux-ui/e2e/specs/admin-flows.spec.ts`, `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | Covers first-run signup, login reuse, logout, and password change. |
| Overview health and status surface | Covered | `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | Verifies daemon and URL-gateway health cards after login. |
| Live events stream, filters, and quick actions | Covered | `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts`, `dashboard/linux-ui/e2e/specs/admin-flows.spec.ts`, `dashboard/linux-ui/e2e/specs/mcp-policy.spec.ts` | Covers SSE connectivity, deny filtering, URL/file events, and quick allow from an event. |
| Policy Studio draft, validate, apply, rollback, and regression handling | Covered | `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts`, `dashboard/linux-ui/e2e/specs/policy-regressions.spec.ts`, `dashboard/linux-ui/e2e/specs/mcp-policy.spec.ts` | Includes rollback and diff-modal assertions. |
| Multi-profile editing | Covered | `dashboard/linux-ui/e2e/specs/policy-advanced.spec.ts` | Covers profile creation, profile switch, and profile-specific rules. |
| MCP policy editing and MCP approval flows | Covered | `dashboard/linux-ui/e2e/specs/mcp-policy.spec.ts`, `dashboard/linux-ui/e2e/specs/policy-advanced.spec.ts` | Covers MCP server config, tool-call deny, and operator approval/deny loops. |
| Enrollments surface | Covered | `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | Verifies enrollment listing and filtering. |
| Settings TLS panel | Covered | `dashboard/linux-ui/e2e/specs/settings-and-agents.spec.ts` | Covers the TLS form save path when env-backed cert settings are present. |
| Agents launch and stop workflow | Covered | `dashboard/linux-ui/e2e/specs/settings-and-agents.spec.ts` | Covers launch, running-state visibility, stop, and launch history. |
| Help Hub, help bar, and guided tours | Covered | `dashboard/linux-ui/e2e/specs/help-experience.spec.ts` | Covers header entry, help bar entry, full-tour launch, tab tour launch, and returning to Help Hub from the overlay. |
| Runtime enforcement smoke harness | Covered | `scripts/run_linux_e2e_smoke.sh`, `scripts/run_linux_e2e_runtime_smoke.sh` | Covers daemon startup, dashboard UI, URL gateway, and selected kernel enforcement hooks. |
| Packaged install, reinstall, uninstall, and purge | Covered | `scripts/run_linux_release_smoke.sh` | Covers bundle build, installer preflight, install, uninstall, reinstall, and purge. |
| Static demo capture flows | Partial | `dashboard/linux-ui/e2e/demo/00-ui-overview.spec.ts`, `dashboard/linux-ui/e2e/demo/10-enforcement-clips.spec.ts` | Demo fixtures validate guided demo behavior, not live daemon/runtime behavior. |
| Public deployment permutations such as ACME, reverse proxy, and non-loopback dashboard exposure | Missing | No dedicated E2E harness | Current release smoke validates local install lifecycle, not public-network deployment variants. |

## Runtime Action Coverage Matrix

The canonical action list lives in `crates/core-types/src/lib.rs`.

| Action | Status | Evidence | Notes |
| --- | --- | --- | --- |
| `FILE_READ` | Covered | `scripts/run_linux_e2e_runtime_smoke.sh`, `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | Denied file reads and workspace-root allow/deny are both asserted. |
| `FILE_WRITE` | Missing | No explicit E2E assertion | No current smoke or Playwright test asserts write allow/deny behavior directly. |
| `FILE_DELETE` | Missing | No explicit E2E assertion | No direct unlink/remove-file enforcement check. |
| `FILE_MMAP` | Partial | `scripts/run_linux_e2e_mmap_regression.sh` | The inherited-descriptor regression runs separately from common runtime smoke. In a local Linux 6.8 run, the AppArmor backend allowed writable `MAP_SHARED` mapping of a denied file through a descriptor opened before enrollment. That backend needs a separate fix and passing regression. |
| `FILE_RENAME` | Missing | No explicit E2E assertion | Hook exists, but there is no rename-path smoke. |
| `FILE_LINK` | Missing | No explicit E2E assertion | Hard-link enforcement is not asserted. |
| `FILE_SYMLINK` | Missing | No explicit E2E assertion | Symlink creation enforcement is not asserted. |
| `FILE_MKDIR` | Missing | No explicit E2E assertion | No mkdir allow/deny smoke. |
| `FILE_RMDIR` | Missing | No explicit E2E assertion | No rmdir allow/deny smoke. |
| `FILE_CREATE` | Missing | No explicit E2E assertion | No create-path smoke. |
| `FILE_CHMOD` | Missing | No explicit E2E assertion | No chmod enforcement smoke. |
| `FILE_CHOWN` | Missing | No explicit E2E assertion | No chown enforcement smoke. |
| `FILE_TRUNCATE` | Missing | No explicit E2E assertion | No truncate enforcement smoke. |
| `PROC_EXEC` | Partial | `scripts/run_linux_e2e_runtime_smoke.sh`, `scripts/run_linux_e2e_exec_regression.sh`, `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | Runtime smoke checks denied child exec. The separate regression checks initial exec and audit delivery; a local AppArmor run allowed a denied initial binary and kernel audit suppression hid a denied child exec event. |
| `PROC_PTRACE` | Missing | No explicit E2E assertion | Quick-rule support exists, but there is no ptrace smoke. |
| `PROC_KILL` | Missing | No explicit E2E assertion | No signal-delivery enforcement smoke. |
| `PROC_CAPABLE` | Missing | No explicit E2E assertion | It appears in observed audit logs, but the suite does not assert it as a contract. |
| `NET_CONNECT` | Partial | `scripts/run_linux_e2e_runtime_smoke.sh` | The suite asserts policy-test and URL-path outcomes, but not a raw CIDR-gated connect hook end to end. |
| `NET_SENDMSG` | Covered | `scripts/run_linux_e2e_runtime_smoke.sh` | Explicit UDP `sendto()` regression probe exists. |
| `NET_BIND` | Missing | No explicit E2E assertion | No server bind enforcement smoke. |
| `NET_LISTEN` | Missing | No explicit E2E assertion | Coverage matrix may report it, but no test asserts it. |
| `NET_ACCEPT` | Missing | No explicit E2E assertion | Coverage matrix may report it, but no test asserts it. |
| `NET_CREATE` | Missing | No explicit E2E assertion | Agent helper notes mention it indirectly, but no smoke/test treats it as a checked outcome. |
| `URL_REQUEST` | Covered | `scripts/run_linux_e2e_runtime_smoke.sh`, `dashboard/linux-ui/e2e/specs/dashboard-smoke.spec.ts` | HTTP and HTTPS allow/deny flows are explicitly asserted. |
| `MCP_TOOL_CALL` | Covered | `dashboard/linux-ui/e2e/specs/mcp-policy.spec.ts`, `dashboard/linux-ui/e2e/specs/policy-advanced.spec.ts` | Deny and pending-approval tool call paths are both covered. |
| `MCP_RESOURCE_READ` | Missing | No explicit E2E assertion | No test currently sends `AuthorizeMcpResourceRead` through the control socket or UI. |

## Next Steps (priority order)

1. **Block denied initial executables on the AppArmor backend.** Check the requested executable before `mercury-run` performs its on-exec profile transition. The initial command and a later child command must both be denied by `exec_deny`. Recheck with `MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=exec_regression make e2e-smoke`; its audit assertion may still fail until step 3 is resolved.
2. **Block writable mappings through pre-enrollment descriptors.** Investigate whether AppArmor can mediate writable `MAP_SHARED` for an inherited descriptor; add a supplemental control if it cannot. The pass condition is a denied mapping and a `FILE_MMAP` audit event from `MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=mmap_regression make e2e-smoke`.
3. **Make AppArmor denial telemetry reliable under load.** Trace the missing child-exec record from kernel audit emission through Mercury's reader, account for suppressed records, and reduce or handle audit volume as needed. The `exec_regression` suite must then pass both enforcement and audit assertions without unreported loss.
4. **Run the complete local AppArmor plus eBPF suite and expand direct coverage.** Once the focused regressions pass, run `MERCURY_E2E_FILESYSTEM_BACKEND=apparmor make e2e-smoke` on a target Linux host. Add raw allow/deny probes for `FILE_WRITE`, `FILE_DELETE`, and `NET_CONNECT`, followed by `PROC_PTRACE`, `PROC_KILL`, and `MCP_RESOURCE_READ`. Decide which server-side network hooks need blocking release checks.
5. **Validate the separate full eBPF LSM backend.** Reduce the `mercury_socket_connect` verifier instruction count and resolve the `bpf_d_path` hook restriction exposed by the attempted fix. Load every required hook and pass the local `ebpf_lsm` E2E suites before claiming that backend enforces policy on the target kernel.

Record the commit, kernel, backend, and result for each local run. A passing
source-tree test does not establish that a published release or installed daemon
contains the same behavior.
