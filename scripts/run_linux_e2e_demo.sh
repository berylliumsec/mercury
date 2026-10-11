#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DASHBOARD_DIR="${REPO_ROOT}/dashboard/linux-ui"
BIN_DIR="${REPO_ROOT}/target/release"
PASSWORD="${MERCURY_E2E_PASSWORD:-MercuryDemo123!}"
WORKDIR="${MERCURY_E2E_WORKDIR:-$(mktemp -d)}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"

mkdir -p "${WORKDIR}"
python3 -m venv "${WORKDIR}/venv"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command '$1'" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd npm
require_cmd openssl
require_cmd python3
require_cmd rg
require_cmd curl

LAUNCH_USER="${MERCURY_E2E_LAUNCH_USER:-${SUDO_USER:-$(id -un)}}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run_linux_e2e_demo.sh must run as root (use sudo -E)" >&2
  exit 1
fi

if [[ ! -d /sys/fs/bpf ]] || [[ ! -f /sys/fs/cgroup/cgroup.controllers ]] || ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
  echo "error: kernel_strict backend requires bpffs, cgroup v2, and bpf LSM support" >&2
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

install -d -m 0775 -o "${LAUNCH_USER}" -g mercury "${WORKDIR}/launch-artifacts"

cleanup() {
  for pid_var in DAEMON_PID HTTP_PID HTTPS_PID TCP_PID; do
    if [[ -n "${!pid_var:-}" ]]; then
      kill "${!pid_var}" >/dev/null 2>&1 || true
      wait "${!pid_var}" 2>/dev/null || true
    fi
  done

  if [[ "${KEEP_WORKDIR}" != "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
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
  exit 1
}

wait_for_daemon_ready() {
  local status_out="${WORKDIR}/daemon-status.out"
  local status_err="${WORKDIR}/daemon-status.err"

  for _ in $(seq 1 120); do
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

cargo build --release -p daemon -p cli -p launcher

if [[ ! -d "${DASHBOARD_DIR}/node_modules" ]] \
  || [[ ! -d "${DASHBOARD_DIR}/node_modules/remotion" ]] \
  || [[ ! -d "${DASHBOARD_DIR}/node_modules/@remotion/cli" ]]
then
  npm --prefix "${DASHBOARD_DIR}" ci
fi

npm --prefix "${DASHBOARD_DIR}" run build
npm --prefix "${DASHBOARD_DIR}" exec playwright install chromium
npm --prefix "${DASHBOARD_DIR}" exec remotion browser ensure

HTTP_PORT="${MERCURY_E2E_HTTP_PORT:-$(free_port)}"
HTTPS_PORT="${MERCURY_E2E_HTTPS_PORT:-$(free_port)}"
DASHBOARD_PORT="${MERCURY_E2E_DASHBOARD_PORT:-$(free_port)}"
PROXY_PORT="${MERCURY_E2E_PROXY_PORT:-$(free_port)}"
TCP_PORT="${MERCURY_E2E_BLOCKED_TCP_PORT:-$(free_port)}"
DEMO_ARTIFACT_DIR="${MERCURY_E2E_DEMO_ARTIFACT_DIR:-${WORKDIR}/demo-artifacts}"
BLOCKED_DIR="${MERCURY_E2E_BLOCKED_DIR:-${WORKDIR}/demo-secrets}"
BLOCKED_FILE="${MERCURY_E2E_BLOCKED_FILE:-${BLOCKED_DIR}/secret.txt}"

mkdir -p \
  "${WORKDIR}/www/allowed" \
  "${WORKDIR}/www/blocked" \
  "${WORKDIR}/certs" \
  "${WORKDIR}/tcp-service" \
  "${BLOCKED_DIR}" \
  "${DEMO_ARTIFACT_DIR}"

printf 'allowed\n' > "${WORKDIR}/www/allowed/index.html"
printf 'blocked\n' > "${WORKDIR}/www/blocked/index.html"
printf 'demo tcp service\n' > "${WORKDIR}/tcp-service/index.html"
printf 'top-secret\n' > "${BLOCKED_FILE}"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${WORKDIR}/certs/upstream-ca.key" \
  -out "${WORKDIR}/certs/upstream-ca.crt" \
  -subj "/CN=Mercury E2E Upstream CA" \
  -days 2 >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
  -keyout "${WORKDIR}/certs/upstream.key" \
  -out "${WORKDIR}/certs/upstream.csr" \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1

cat > "${WORKDIR}/certs/upstream.ext" <<EOF
subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl x509 -req \
  -in "${WORKDIR}/certs/upstream.csr" \
  -CA "${WORKDIR}/certs/upstream-ca.crt" \
  -CAkey "${WORKDIR}/certs/upstream-ca.key" \
  -CAcreateserial \
  -out "${WORKDIR}/certs/upstream.crt" \
  -days 2 \
  -extfile "${WORKDIR}/certs/upstream.ext" >/dev/null 2>&1

python3 "${SCRIPT_DIR}/linux_e2e_static_server.py" \
  --bind 127.0.0.1 \
  --port "${HTTP_PORT}" \
  --root "${WORKDIR}/www" \
  > "${WORKDIR}/http-server.out" 2> "${WORKDIR}/http-server.err" &
HTTP_PID=$!

python3 "${SCRIPT_DIR}/linux_e2e_static_server.py" \
  --bind 127.0.0.1 \
  --port "${HTTPS_PORT}" \
  --root "${WORKDIR}/www" \
  --certfile "${WORKDIR}/certs/upstream.crt" \
  --keyfile "${WORKDIR}/certs/upstream.key" \
  > "${WORKDIR}/https-server.out" 2> "${WORKDIR}/https-server.err" &
HTTPS_PID=$!

python3 -m http.server "${TCP_PORT}" --bind 127.0.0.1 --directory "${WORKDIR}/tcp-service" \
  > "${WORKDIR}/tcp-server.out" 2> "${WORKDIR}/tcp-server.err" &
TCP_PID=$!

wait_for_url "local HTTP test server" "http://127.0.0.1:${HTTP_PORT}/allowed/index.html"
wait_for_url \
  "local HTTPS test server" \
  --cacert "${WORKDIR}/certs/upstream-ca.crt" \
  "https://127.0.0.1:${HTTPS_PORT}/allowed/index.html"
wait_for_url "local TCP demo service" "http://127.0.0.1:${TCP_PORT}/"

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
signature:
  key_id: local-dev
  alg: ed25519
  sig: ''
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
  required: true
  bind_addr: 127.0.0.1:${DASHBOARD_PORT}
  static_dir: ${DASHBOARD_DIR}/dist
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
    cert_file: ${WORKDIR}/dashboard.crt
    key_file: ${WORKDIR}/dashboard.key
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

"${BIN_DIR}/mercuryd" --config "${WORKDIR}/config.yaml" \
  > "${WORKDIR}/daemon.out" 2> "${WORKDIR}/daemon.err" &
DAEMON_PID=$!

for _ in $(seq 1 120); do
  [[ -S "${WORKDIR}/mercuryd.sock" ]] && break
  sleep 0.25
done

wait_for_daemon_ready

export MERCURY_E2E_WORKDIR="${WORKDIR}"
export MERCURY_E2E_SOCKET="${WORKDIR}/mercuryd.sock"
export MERCURY_E2E_BASE_URL="http://127.0.0.1:${DASHBOARD_PORT}"
export MERCURY_E2E_USERNAME="admin"
export MERCURY_E2E_PASSWORD="${PASSWORD}"
export MERCURY_E2E_LAUNCH_USER="${LAUNCH_USER}"
export MERCURY_E2E_LAUNCH_UID="$(id -u "${LAUNCH_USER}")"
export MERCURY_E2E_LAUNCH_MARKER="${WORKDIR}/launch-artifacts/agent-launch-marker.json"
export MERCURY_E2E_SYSTEM_PYTHON="/usr/bin/python3"
export MERCURY_E2E_VENV_PYTHON="${WORKDIR}/venv/bin/python"
export MERCURY_E2E_FILE_DENY_PATH="${BLOCKED_FILE}"
export MERCURY_E2E_HTTP_ALLOWED_URL="http://127.0.0.1:${HTTP_PORT}/allowed/index.html"
export MERCURY_E2E_HTTP_BLOCKED_URL="http://127.0.0.1:${HTTP_PORT}/blocked/index.html"
export MERCURY_E2E_HTTPS_ALLOWED_URL="https://127.0.0.1:${HTTPS_PORT}/allowed/index.html"
export MERCURY_E2E_HTTPS_BLOCKED_URL="https://127.0.0.1:${HTTPS_PORT}/blocked/index.html"
export MERCURY_E2E_HTTP_PORT="${HTTP_PORT}"
export MERCURY_E2E_HTTPS_PORT="${HTTPS_PORT}"
export MERCURY_E2E_BIN_DIR="${BIN_DIR}"
export MERCURY_E2E_BLOCKED_DIR="${BLOCKED_DIR}"
export MERCURY_E2E_BLOCKED_FILE="${BLOCKED_FILE}"
export MERCURY_E2E_BLOCKED_TCP_PORT="${TCP_PORT}"
export MERCURY_E2E_DEMO_ARTIFACT_DIR="${DEMO_ARTIFACT_DIR}"
export MERCURY_E2E_OUTPUT_DIR="${DEMO_ARTIFACT_DIR}/playwright-output"
export PLAYWRIGHT_HTML_REPORT="${DEMO_ARTIFACT_DIR}/playwright-report"

npm --prefix "${DASHBOARD_DIR}" run demo:capture
npm --prefix "${DASHBOARD_DIR}" run demo:render
npm --prefix "${DASHBOARD_DIR}" run demo:readme-assets

echo "WORKDIR=${WORKDIR}"
echo "DEMO_ARTIFACT_DIR=${DEMO_ARTIFACT_DIR}"
echo "README_SNIPPET=${DEMO_ARTIFACT_DIR}/readme/README.demo.generated.md"
echo "linux e2e demo pipeline passed"
