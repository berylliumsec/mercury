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

"${AGENT_PYTHON}" - <<'PY'
import importlib
required = [
    "smolagents",
    "interpreter",
    "langchain_classic",
    "autogen_agentchat",
    "autogen_ext",
]
missing = []
for mod in required:
    try:
        importlib.import_module(mod)
    except Exception:
        missing.append(mod)
if missing:
    raise SystemExit("missing modules: " + ", ".join(missing))
PY

TIMEOUT_SECS="${TIMEOUT_SECS:-900}"
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
      - id: allow_all_ipv4
        cidr: 0.0.0.0/0
        protocol: TCP
      - id: allow_all_ipv6
        cidr: ::/0
        protocol: TCP
    network_deny:
      - id: deny_test_target_ipv4
        cidr: 1.1.1.1/32
        protocol: TCP
    url_allow:
      - id: allow_unused_local_http
        scheme: http
        host_glob: 127.0.0.1
        method: GET
        path_glob: /__unused__/**
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

declare -a NAMES=(
  "smolagents"
  "open_interpreter"
  "langchain"
  "autogen"
)
declare -a SCRIPTS=(
  "${SCRIPT_DIR}/smolagents_major_matrix.py"
  "${SCRIPT_DIR}/open_interpreter_major_matrix.py"
  "${SCRIPT_DIR}/langchain_major_matrix.py"
  "${SCRIPT_DIR}/autogen_major_matrix.py"
)

declare -A RC_BY_NAME

set +e
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  script="${SCRIPTS[$i]}"
  out_file="${WORKDIR}/${name}.out"
  err_file="${WORKDIR}/${name}.err"

  /usr/bin/time -f "${name}_elapsed=%E ${name}_cmd_rc=%x" \
    timeout "${TIMEOUT_SECS}" "${BIN_DIR}/mercury-run" \
    --socket "${WORKDIR}/mercuryd.sock" \
    --profile default \
    -- "${AGENT_PYTHON}" "${script}" \
    >"${out_file}" 2>"${err_file}"

  RC_BY_NAME["${name}"]=$?
done
set -e

DENY_TOTAL="$(rg -c '"decision":"DENY"' "${WORKDIR}/audit.jsonl" || true)"
DENY_HOSTS="$(rg -c 'deny_hosts|/etc/hosts' "${WORKDIR}/audit.jsonl" || true)"
DENY_NET="$(rg -c '"action_type":"NET_(CREATE|CONNECT)".*"decision":"DENY"' "${WORKDIR}/audit.jsonl" || true)"

echo "WORKDIR=${WORKDIR}"
for name in "${NAMES[@]}"; do
  echo "${name}_rc=${RC_BY_NAME[$name]:-999}"
done
echo "DENY_TOTAL=${DENY_TOTAL}"
echo "DENY_HOSTS=${DENY_HOSTS}"
echo "DENY_NET=${DENY_NET}"

for name in "${NAMES[@]}"; do
  echo "--- ${name}.out (tail) ---"
  tail -n 80 "${WORKDIR}/${name}.out" || true
  echo "--- ${name}.err ---"
  cat "${WORKDIR}/${name}.err" || true
done

echo "--- DENY AUDIT LINES (tail) ---"
rg -n '"decision":"DENY"' "${WORKDIR}/audit.jsonl" | tail -n 40 || true

for name in "${NAMES[@]}"; do
  if [[ "${RC_BY_NAME[$name]:-1}" -ne 0 ]]; then
    echo "error: ${name} test failed" >&2
    exit 1
  fi
done

if [[ "${DENY_HOSTS}" -lt 4 ]]; then
  echo "error: expected at least 4 /etc/hosts deny events (one per framework)" >&2
  exit 1
fi
if [[ "${DENY_NET}" -lt 4 ]]; then
  echo "error: expected at least 4 net-connect deny events to denied target (one per framework)" >&2
  exit 1
fi

echo "major-agent policy test passed"
