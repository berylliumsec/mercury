#!/usr/bin/env bash
# Lightweight wrapper that exercises only the runtime enforcement smoke tests
# (run_linux_e2e_runtime_smoke.sh) without the full npm/playwright build.
# Must be run as root: sudo -E bash scripts/run_linux_e2e_runtime_only.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${MERCURY_E2E_BIN_DIR:-${REPO_ROOT}/target/release}"
WORKDIR="${MERCURY_E2E_WORKDIR:-$(mktemp -d)}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
DAEMON_PID=""
HTTP_PID=""
HTTPS_PID=""
LAUNCH_USER="${MERCURY_E2E_LAUNCH_USER:-${SUDO_USER:-$(id -un)}}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: must run as root (sudo -E bash $0)" >&2
  exit 1
fi

if ! getent group mercury >/dev/null 2>&1; then
  groupadd --system mercury
fi
if id -u "${LAUNCH_USER}" >/dev/null 2>&1; then
  if ! id -nG "${LAUNCH_USER}" | tr ' ' '\n' | grep -qx mercury; then
    usermod -aG mercury "${LAUNCH_USER}"
  fi
else
  echo "error: dashboard launch user does not exist: ${LAUNCH_USER}" >&2
  exit 1
fi

cleanup() {
  [[ -n "${DAEMON_PID}" ]] && kill "${DAEMON_PID}" 2>/dev/null && wait "${DAEMON_PID}" 2>/dev/null || true
  [[ -n "${HTTP_PID}"   ]] && kill "${HTTP_PID}"   2>/dev/null && wait "${HTTP_PID}"   2>/dev/null || true
  [[ -n "${HTTPS_PID}"  ]] && kill "${HTTPS_PID}"  2>/dev/null && wait "${HTTPS_PID}"  2>/dev/null || true
  [[ "${KEEP_WORKDIR}" != "1" ]] && rm -rf "${WORKDIR}" || true
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

curl_direct() {
  env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy \
    /usr/bin/curl --noproxy '*' "$@"
}

wait_for_url() {
  local label="$1"
  shift

  for _ in $(seq 1 80); do
    if curl_direct --fail --silent --show-error --max-time 2 "$@" >/dev/null; then
      return 0
    fi
    sleep 0.25
  done

  echo "error: ${label} did not become ready" >&2
  [[ -f "${WORKDIR}/http-server.err" ]] && tail -20 "${WORKDIR}/http-server.err" >&2 || true
  [[ -f "${WORKDIR}/http-server.out" ]] && tail -20 "${WORKDIR}/http-server.out" >&2 || true
  [[ -f "${WORKDIR}/https-server.err" ]] && tail -20 "${WORKDIR}/https-server.err" >&2 || true
  [[ -f "${WORKDIR}/https-server.out" ]] && tail -20 "${WORKDIR}/https-server.out" >&2 || true
  exit 1
}

wait_for_daemon_ready() {
  local status_out="${WORKDIR}/daemon-status.out"
  local status_err="${WORKDIR}/daemon-status.err"

  for _ in $(seq 1 240); do
    if [[ -S "${WORKDIR}/mercuryd.sock" ]] \
      && "${BIN_DIR}/mercury-status" --socket "${WORKDIR}/mercuryd.sock" --ignore-degraded --dashboard \
        >"${status_out}" 2>"${status_err}"
    then
      if rg -q 'daemon_up=true' "${status_out}" && rg -q 'url_gateway_ready=true' "${status_out}"; then
        return 0
      fi
    fi
    sleep 0.25
  done

  echo "error: daemon did not become ready" >&2
  [[ -f "${WORKDIR}/daemon.err" ]] && tail -20 "${WORKDIR}/daemon.err" >&2 || true
  [[ -f "${WORKDIR}/daemon.out" ]] && tail -20 "${WORKDIR}/daemon.out" >&2 || true
  [[ -f "${status_err}" ]] && tail -20 "${status_err}" >&2 || true
  [[ -f "${status_out}" ]] && tail -20 "${status_out}" >&2 || true
  exit 1
}

mkdir -p "${WORKDIR}/www/allowed" "${WORKDIR}/www/blocked" "${WORKDIR}/certs"
printf 'allowed\n'     > "${WORKDIR}/www/allowed/index.html"
printf 'blocked\n'     > "${WORKDIR}/www/blocked/index.html"
printf 'top-secret\n'  > "${WORKDIR}/blocked.txt"

# ── TLS cert for the HTTPS test server ──────────────────────────────────────
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${WORKDIR}/certs/upstream-ca.key" \
  -out    "${WORKDIR}/certs/upstream-ca.crt" \
  -subj "/CN=Mercury E2E Upstream CA" -days 2 >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
  -keyout "${WORKDIR}/certs/upstream.key" \
  -out    "${WORKDIR}/certs/upstream.csr" \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1

cat > "${WORKDIR}/certs/upstream.ext" <<'EOF'
subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl x509 -req \
  -in    "${WORKDIR}/certs/upstream.csr" \
  -CA    "${WORKDIR}/certs/upstream-ca.crt" \
  -CAkey "${WORKDIR}/certs/upstream-ca.key" \
  -CAcreateserial \
  -out   "${WORKDIR}/certs/upstream.crt" \
  -days 2 -extfile "${WORKDIR}/certs/upstream.ext" >/dev/null 2>&1

# ── Static HTTP / HTTPS servers ──────────────────────────────────────────────
HTTP_PORT="${MERCURY_E2E_HTTP_PORT:-$(free_port)}"
HTTPS_PORT="${MERCURY_E2E_HTTPS_PORT:-$(free_port)}"
PROXY_PORT="$(free_port)"
DASHBOARD_PORT="$(free_port)"
PASSWORD="MercurySmoke123!"

python3 "${SCRIPT_DIR}/linux_e2e_static_server.py" \
  --bind 127.0.0.1 --port "${HTTP_PORT}" --root "${WORKDIR}/www" \
  > "${WORKDIR}/http-server.out" 2>&1 &
HTTP_PID=$!

python3 "${SCRIPT_DIR}/linux_e2e_static_server.py" \
  --bind 127.0.0.1 --port "${HTTPS_PORT}" --root "${WORKDIR}/www" \
  --certfile "${WORKDIR}/certs/upstream.crt" \
  --keyfile  "${WORKDIR}/certs/upstream.key" \
  > "${WORKDIR}/https-server.out" 2>&1 &
HTTPS_PID=$!

wait_for_url "local HTTP test server" "http://127.0.0.1:${HTTP_PORT}/allowed/index.html"
wait_for_url \
  "local HTTPS test server" \
  --cacert "${WORKDIR}/certs/upstream-ca.crt" \
  "https://127.0.0.1:${HTTPS_PORT}/allowed/index.html"

# ── Dashboard password ───────────────────────────────────────────────────────
"${BIN_DIR}/mercury-policy" dashboard-password rotate \
  --file "${WORKDIR}/dashboard.password" \
  --username admin >/dev/null

# ── Daemon config ────────────────────────────────────────────────────────────
cat > "${WORKDIR}/policy.yaml" <<YAML
version: v1
defaults:
  decision: allow
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default:
    workspace_roots: []
    file_allow: []
    file_deny: []
    exec_allow: []
    exec_deny: []
    network_allow: []
    network_deny: []
    url_allow: []
    url_deny: []
YAML

# Per-run audit integrity key so the chain can be verified (and nothing is
# written to /var/lib/mercury on the host running the tests).
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "${WORKDIR}/audit-integrity.key"
chmod 600 "${WORKDIR}/audit-integrity.key"

cat > "${WORKDIR}/config.yaml" <<YAML
socket_path: ${WORKDIR}/mercuryd.sock
policy_path: ${WORKDIR}/policy.yaml
audit_jsonl_path: ${WORKDIR}/audit.jsonl
audit_integrity_key_path: ${WORKDIR}/audit-integrity.key
enrollment_state_path: ${WORKDIR}/enrollments.json
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
dashboard:
  enabled: true
  required: false
  bind_addr: 127.0.0.1:${DASHBOARD_PORT}
  static_dir: /usr/share/mercury/dashboard
  sqlite_path: ${WORKDIR}/dashboard.db
  retention_days: 2
  sse_clients_max: 32
  request_rate_limit_rps: 200
  auth:
    username: admin
    password_file: ${WORKDIR}/dashboard.password
    session_ttl_minutes: 30
  launch:
    user: ${LAUNCH_USER}
    launcher_path: ${BIN_DIR}/mercury-run
    history_limit: 16
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    auto_generate_self_signed: false
url_gateway:
  enabled: true
  required: true
  bind_addr: 127.0.0.1:${PROXY_PORT}
  tls_intercept_enabled: true
  ca_cert_file: ${WORKDIR}/url-gateway-ca.crt
  ca_key_file: ${WORKDIR}/url-gateway-ca.key
  auto_generate_ca: true
  upstream_ca_cert_file: ${WORKDIR}/certs/upstream-ca.crt
  no_proxy: ""
YAML

# ── Start daemon ─────────────────────────────────────────────────────────────
"${BIN_DIR}/mercuryd" --config "${WORKDIR}/config.yaml" \
  > "${WORKDIR}/daemon.out" 2> "${WORKDIR}/daemon.err" &
DAEMON_PID=$!

echo "waiting for daemon socket..."
wait_for_daemon_ready

# ── Export env vars and call the runtime smoke script ────────────────────────
export MERCURY_E2E_WORKDIR="${WORKDIR}"
export MERCURY_E2E_SOCKET="${WORKDIR}/mercuryd.sock"
export MERCURY_E2E_FILE_DENY_PATH="${WORKDIR}/blocked.txt"
export MERCURY_E2E_HTTP_ALLOWED_URL="http://127.0.0.1:${HTTP_PORT}/allowed/index.html"
export MERCURY_E2E_HTTP_BLOCKED_URL="http://127.0.0.1:${HTTP_PORT}/blocked/index.html"
export MERCURY_E2E_HTTPS_ALLOWED_URL="https://127.0.0.1:${HTTPS_PORT}/allowed/index.html"
export MERCURY_E2E_HTTPS_BLOCKED_URL="https://127.0.0.1:${HTTPS_PORT}/blocked/index.html"
export MERCURY_E2E_HTTP_PORT="${HTTP_PORT}"
export MERCURY_E2E_HTTPS_PORT="${HTTPS_PORT}"
export MERCURY_E2E_BIN_DIR="${BIN_DIR}"

bash "${SCRIPT_DIR}/run_linux_e2e_runtime_smoke.sh"

# Extended E2E tests
for script in \
  run_linux_e2e_extended_hooks.sh \
  run_linux_e2e_observe_and_lifecycle.sh \
  run_linux_e2e_rate_limit.sh \
  run_linux_e2e_mcp_and_audit.sh \
  run_linux_e2e_policy_features.sh \
  run_linux_e2e_gateway_advanced.sh \
  run_linux_e2e_dashboard_and_errors.sh \
; do
  if [[ -x "${SCRIPT_DIR}/${script}" ]]; then
    bash "${SCRIPT_DIR}/${script}"
  fi
done

echo "linux runtime e2e (extended) passed"
