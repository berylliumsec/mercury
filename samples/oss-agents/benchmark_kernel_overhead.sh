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
  exit 1
fi

MAX_OVERHEAD_PERCENT="${MAX_OVERHEAD_PERCENT:-5}"
STARTUP_TIMEOUT_SECS="${STARTUP_TIMEOUT_SECS:-60}"
HASH_COUNT_MB="${HASH_COUNT_MB:-256}"
WORKDIR="$(mktemp -d)"

cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "${DAEMON_PID}" >/dev/null 2>&1 || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

cat > "${WORKDIR}/policy.yaml" <<'YAML'
version: v1
defaults:
  decision: allow
  fail_mode: fail_closed
  audit_level: denies
profiles:
  default:
    file_allow:
      - id: allow_abs
        pattern: /**
    exec_allow:
      - id: allow_abs_exec
        path: /**
    network_allow:
      - id: allow_all_v4
        cidr: 0.0.0.0/0
        protocol: TCP
YAML

cat > "${WORKDIR}/config.yaml" <<YAML
socket_path: ${WORKDIR}/mercuryd.sock
policy_path: ${WORKDIR}/policy.yaml
audit_jsonl_path: ${WORKDIR}/audit.jsonl
log_level: warn
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

startup_polls=$((STARTUP_TIMEOUT_SECS * 10))
for _ in $(seq 1 "${startup_polls}"); do
  [[ -S "${WORKDIR}/mercuryd.sock" ]] && break
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo "error: daemon exited before socket was ready" >&2
    cat "${WORKDIR}/daemon.err" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "${WORKDIR}/mercuryd.sock" ]]; then
  echo "error: daemon socket did not come up within ${STARTUP_TIMEOUT_SECS}s" >&2
  cat "${WORKDIR}/daemon.err" >&2 || true
  exit 1
fi

run_ns() {
  local start end
  start="$(date +%s%N)"
  "$@"
  end="$(date +%s%N)"
  echo $((end - start))
}

BENCH_CMD=(bash -lc "dd if=/dev/zero bs=1M count=${HASH_COUNT_MB} status=none | sha256sum >/dev/null")

DIRECT_NS="$(run_ns "${BENCH_CMD[@]}")"
GUARD_NS="$(run_ns "${BIN_DIR}/mercury-run" --socket "${WORKDIR}/mercuryd.sock" --profile default -- "${BENCH_CMD[@]}")"

OVERHEAD="$(awk -v d="${DIRECT_NS}" -v g="${GUARD_NS}" 'BEGIN { if (d == 0) { print 0 } else { printf "%.3f", ((g-d)/d)*100 } }')"

echo "direct_ns=${DIRECT_NS}"
echo "guard_ns=${GUARD_NS}"
echo "overhead_percent=${OVERHEAD}"
echo "max_overhead_percent=${MAX_OVERHEAD_PERCENT}"
echo "hash_count_mb=${HASH_COUNT_MB}"

awk -v o="${OVERHEAD}" -v m="${MAX_OVERHEAD_PERCENT}" 'BEGIN { exit !(o <= m) }' || {
  echo "error: overhead gate failed (${OVERHEAD}% > ${MAX_OVERHEAD_PERCENT}%)" >&2
  exit 1
}

echo "kernel overhead gate passed"
