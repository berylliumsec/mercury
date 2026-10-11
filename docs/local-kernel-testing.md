# Local Linux validation

The kernel-dependent suites run locally. GitHub Actions runs formatting,
linting, unit tests, the dashboard build, and installer preflight; it does not
run these suites. Use a Linux host with BPF LSM in `/sys/kernel/security/lsm`,
bpffs at `/sys/fs/bpf`, cgroup v2, passwordless `sudo`, Rust, Node, and the
dependencies installed by `scripts/setup_ci_linux_build_deps.sh`.

```sh
grep -qw bpf /sys/kernel/security/lsm
test -d /sys/fs/bpf && test -f /sys/fs/cgroup/cgroup.controllers
make e2e-smoke                  # all runtime and dashboard smoke suites
make e2e-full                   # smoke, MCP, agent frameworks, overhead gate
make test-kernel                # agent frameworks and overhead gate only
# Verify the AppArmor plus eBPF object loads on the current kernel:
MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=backend_load make e2e-smoke
# Run the common AppArmor plus eBPF runtime checks:
MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=backend_load,runtime_smoke make e2e-smoke
# Recheck initial exec denial and its audit event (currently fails on AppArmor):
MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=exec_regression make e2e-smoke
# Recheck the inherited-descriptor mmap gap separately (currently fails on AppArmor):
MERCURY_E2E_FILESYSTEM_BACKEND=apparmor MERCURY_E2E_SUITES=mmap_regression make e2e-smoke
```

`backend_load` checks daemon readiness and the reported file, exec, and network
hook backends. `runtime_smoke` checks file reads, URL policy, UDP sendmsg, child
exec denial, workspace roots, and policy signing on either backend. On AppArmor,
the child exec starts inside the profile; `exec_regression` checks the initial
on-exec transition and its audit record separately. A local run allowed the
denied initial binary and lost the child-exec audit event under kernel audit
suppression. The inherited-descriptor `FILE_MMAP` check is in
`mmap_regression`; it remains a failing regression on AppArmor until that
enforcement gap is fixed.

The ordered remediation plan and pass conditions are in
[e2e-coverage.md](e2e-coverage.md#next-steps-priority-order).

The framework harnesses require `.venv-agent-test/bin/python` with
`smolagents`, `interpreter`, `langchain_classic`, `autogen_agentchat`, and
`autogen_ext` installed. Set `AGENT_PYTHON` to another prepared interpreter if
needed. `MERCURY_E2E_SUITES=runtime_smoke,extended_hooks make e2e-smoke` runs
selected suites. `python3 scripts/ci/select_e2e.py --base <base> --head HEAD`
reports the suites relevant to a diff.

The packaged release smoke installs, uninstalls, reinstalls, and purges Mercury.
Run `make e2e-release-local` **only on a disposable host or VM**. The script
refuses a host with an existing Mercury installation before changing it.

These tests load BPF programs and create temporary agent cgroups. Use a
dedicated test host when possible. Preserve the command output and the printed
work directory if a suite fails; a clean pass should be recorded alongside the
commit and kernel version tested.
