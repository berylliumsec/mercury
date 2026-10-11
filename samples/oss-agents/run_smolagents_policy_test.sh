#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -x "${REPO_ROOT}/target/release/mercuryd" ]]; then
  BIN_DIR="${REPO_ROOT}/target/release"
elif [[ -x "${REPO_ROOT}/target/debug/mercuryd" ]]; then
  BIN_DIR="${REPO_ROOT}/target/debug"
else
  echo "error: could not find mercuryd binary in target/release or target/debug" >&2
  echo "hint: run 'cargo build --workspace'" >&2
  exit 1
fi

AGENT_PYTHON="${AGENT_PYTHON:-${REPO_ROOT}/.venv-agent-test/bin/python}"
if [[ ! -x "${AGENT_PYTHON}" ]]; then
  echo "error: AGENT_PYTHON is not executable: ${AGENT_PYTHON}" >&2
  exit 1
fi

"${AGENT_PYTHON}" -c "import smolagents" >/dev/null 2>&1 || {
  echo "error: smolagents is not installed in ${AGENT_PYTHON}" >&2
  exit 1
}

TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
STARTUP_TIMEOUT_SECS="${STARTUP_TIMEOUT_SECS:-60}"
WORKDIR="$(mktemp -d)"

if [[ ! -d /sys/fs/bpf ]] || [[ ! -f /sys/fs/cgroup/cgroup.controllers ]] || ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
  echo "error: kernel_strict backend requires bpffs, cgroup v2, and bpf LSM support" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "${DAEMON_PID}" >/dev/null 2>&1 || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_WORKDIR:-0}" != "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

cat > "${WORKDIR}/policy.yaml" <<'YAML'
version: v1
defaults:
  decision: deny
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default:
    file_allow:
      - id: allow_abs
        pattern: /**
    file_deny:
      - id: deny_hosts
        pattern: /etc/hosts
    exec_allow:
      - id: allow_exec_abs
        path: /**
    network_allow:
      - id: allow_localhost_v4
        cidr: 127.0.0.1/32
        protocol: TCP
      - id: allow_localhost_v6
        cidr: ::1/128
        protocol: TCP
YAML

cat > "${WORKDIR}/config.yaml" <<YAML
socket_path: ${WORKDIR}/mercuryd.sock
policy_path: ${WORKDIR}/policy.yaml
audit_jsonl_path: ${WORKDIR}/audit.jsonl
log_level: info
mirror_to_journald: false
signature_verification: warn_on_invalid
policy_unavailable_mode: fail_closed
backend_mode: kernel_strict
filesystem_backend: ebpf_lsm
cgroup_base: ${WORKDIR}/cgroup
kernel:
  bpffs_path: /sys/fs/bpf
  cgroup_root: /sys/fs/cgroup
  event_buffer_pages: 256
  unmatched_host_mode: observe
YAML

"${BIN_DIR}/mercuryd" --config "${WORKDIR}/config.yaml" >"${WORKDIR}/daemon.out" 2>"${WORKDIR}/daemon.err" &
DAEMON_PID=$!

startup_polls=$((STARTUP_TIMEOUT_SECS * 5))
for _ in $(seq 1 "${startup_polls}"); do
  [[ -S "${WORKDIR}/mercuryd.sock" ]] && break
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo "error: daemon exited before socket was ready" >&2
    cat "${WORKDIR}/daemon.err" >&2 || true
    exit 1
  fi
  sleep 0.2
done
if [[ ! -S "${WORKDIR}/mercuryd.sock" ]]; then
  echo "error: daemon socket did not come up within ${STARTUP_TIMEOUT_SECS}s" >&2
  cat "${WORKDIR}/daemon.err" >&2 || true
  exit 1
fi

set +e
/usr/bin/time -f 'file_elapsed=%E file_cmd_rc=%x' \
  timeout "${TIMEOUT_SECS}" "${BIN_DIR}/mercury-run" \
  --socket "${WORKDIR}/mercuryd.sock" \
  --profile default \
  -- "${AGENT_PYTHON}" "${SCRIPT_DIR}/smolagents_file_deny.py" \
  >"${WORKDIR}/file.out" 2>"${WORKDIR}/file.err"
FILE_RC=$?

/usr/bin/time -f 'net_elapsed=%E net_cmd_rc=%x' \
  timeout "${TIMEOUT_SECS}" "${BIN_DIR}/mercury-run" \
  --socket "${WORKDIR}/mercuryd.sock" \
  --profile default \
  -- "${AGENT_PYTHON}" "${SCRIPT_DIR}/smolagents_net_deny.py" \
  >"${WORKDIR}/net.out" 2>"${WORKDIR}/net.err"
NET_RC=$?
set -e

DENY_TOTAL="$(rg -c '"decision":"DENY"' "${WORKDIR}/audit.jsonl" || true)"
DENY_HOSTS="$(rg -c 'deny_hosts|/etc/hosts' "${WORKDIR}/audit.jsonl" || true)"
DENY_NET="$(rg -c '"action_type":"NET_(CREATE|CONNECT)".*"decision":"DENY"' "${WORKDIR}/audit.jsonl" || true)"

echo "WORKDIR=${WORKDIR}"
echo "FILE_RC=${FILE_RC}"
echo "NET_RC=${NET_RC}"
echo "DENY_TOTAL=${DENY_TOTAL}"
echo "DENY_HOSTS=${DENY_HOSTS}"
echo "DENY_NET=${DENY_NET}"
echo "--- FILE OUT (tail) ---"
tail -n 60 "${WORKDIR}/file.out" || true
echo "--- FILE ERR ---"
cat "${WORKDIR}/file.err" || true
echo "--- NET OUT (tail) ---"
tail -n 60 "${WORKDIR}/net.out" || true
echo "--- NET ERR ---"
cat "${WORKDIR}/net.err" || true
echo "--- DENY AUDIT LINES (tail) ---"
rg -n '"decision":"DENY"' "${WORKDIR}/audit.jsonl" | tail -n 20 || true

if [[ "${FILE_RC}" -ne 0 ]]; then
  echo "error: file deny test failed" >&2
  exit 1
fi
if [[ "${NET_RC}" -ne 0 ]]; then
  echo "error: network deny test failed" >&2
  exit 1
fi
if [[ "${DENY_HOSTS}" -lt 1 || "${DENY_NET}" -lt 1 ]]; then
  echo "error: expected deny evidence missing in audit log" >&2
  exit 1
fi

echo "smolagents policy test passed"
