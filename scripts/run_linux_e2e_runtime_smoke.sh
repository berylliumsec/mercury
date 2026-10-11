#!/usr/bin/env bash
set -euo pipefail
set -x

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: missing required environment variable ${name}" >&2
    exit 1
  fi
}

require_var MERCURY_E2E_WORKDIR
require_var MERCURY_E2E_SOCKET
require_var MERCURY_E2E_FILE_DENY_PATH
require_var MERCURY_E2E_HTTP_ALLOWED_URL
require_var MERCURY_E2E_HTTP_BLOCKED_URL
require_var MERCURY_E2E_HTTPS_ALLOWED_URL
require_var MERCURY_E2E_HTTPS_BLOCKED_URL
require_var MERCURY_E2E_HTTP_PORT
require_var MERCURY_E2E_HTTPS_PORT

WORKDIR="${MERCURY_E2E_WORKDIR}"
SOCKET="${MERCURY_E2E_SOCKET}"
BIN_DIR="${MERCURY_E2E_BIN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release}"
POLICY_FILE="${WORKDIR}/runtime-smoke-policy.yaml"
STATUS_OUT="${WORKDIR}/runtime-status.out"
RELOAD_OUT="${WORKDIR}/runtime-reload.out"

wait_for_audit_match() {
  local pattern="$1"
  local attempts="${2:-100}"

  for _ in $(seq 1 "${attempts}"); do
    if rg -q "${pattern}" "${WORKDIR}/audit.jsonl"; then
      return 0
    fi
    sleep 0.05
  done

  echo "FAIL: timed out waiting for audit pattern: ${pattern}" >&2
  tail -20 "${WORKDIR}/audit.jsonl" >&2 || true
  return 1
}

curl_via_mercury_http_proxy() {
  local url="$1"
  "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
    /bin/sh -ceu 'test -n "${http_proxy:-}"; exec /usr/bin/curl --noproxy "" --proxy "${http_proxy}" -sS -o /dev/null -w "%{http_code}" "$1"' sh "${url}"
}

curl_via_mercury_https_proxy() {
  local url="$1"
  "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
    /bin/sh -ceu 'test -n "${https_proxy:-}"; exec /usr/bin/curl --noproxy "" --proxy "${https_proxy}" -sS -o /dev/null -w "%{http_code}" "$1"' sh "${url}"
}

cat > "${POLICY_FILE}" <<YAML
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
      - id: deny_secret_file
        pattern: ${MERCURY_E2E_FILE_DENY_PATH}
    exec_allow:
      - id: allow_exec_abs
        path: /**
    url_allow:
      - id: allow_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /allowed/**
      - id: allow_https_local
        scheme: https
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTPS_PORT}
        path_glob: /allowed/**
    url_deny:
      - id: deny_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /blocked/**
      - id: deny_https_local
        scheme: https
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTPS_PORT}
        path_glob: /blocked/**
YAML

"${BIN_DIR}/mercury-status" --socket "${SOCKET}" --ignore-degraded --dashboard > "${STATUS_OUT}"
rg -q 'daemon_up=true' "${STATUS_OUT}"
rg -q 'url_gateway_ready=true' "${STATUS_OUT}"

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${POLICY_FILE}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

ALLOW_HTTP_TEST="$("${BIN_DIR}/mercury-policy" test --socket "${SOCKET}" --profile default --action net-connect --url "${MERCURY_E2E_HTTP_ALLOWED_URL}" --method GET)"
BLOCK_HTTP_TEST="$("${BIN_DIR}/mercury-policy" test --socket "${SOCKET}" --profile default --action net-connect --url "${MERCURY_E2E_HTTP_BLOCKED_URL}" --method GET)"
ALLOW_HTTPS_TEST="$("${BIN_DIR}/mercury-policy" test --socket "${SOCKET}" --profile default --action net-connect --url "${MERCURY_E2E_HTTPS_ALLOWED_URL}" --method GET)"
BLOCK_HTTPS_TEST="$("${BIN_DIR}/mercury-policy" test --socket "${SOCKET}" --profile default --action net-connect --url "${MERCURY_E2E_HTTPS_BLOCKED_URL}" --method GET)"

[[ "${ALLOW_HTTP_TEST}" == *"decision=Allow"* ]]
[[ "${BLOCK_HTTP_TEST}" == *"decision=Deny"* ]]
[[ "${ALLOW_HTTPS_TEST}" == *"decision=Allow"* ]]
[[ "${BLOCK_HTTPS_TEST}" == *"decision=Deny"* ]]

CHILD_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- /bin/sh -c "cat '${MERCURY_E2E_FILE_DENY_PATH}' >/dev/null 2>&1; parent=\$?; /bin/sh -c \"cat '${MERCURY_E2E_FILE_DENY_PATH}' >/dev/null 2>&1\"; child=\$?; echo parent:\$parent child:\$child; test \$parent -ne 0 -a \$child -ne 0")"
[[ "${CHILD_OUT}" == *"parent:"*"child:"* ]]

HTTP_ALLOW_STATUS="$(curl_via_mercury_http_proxy "${MERCURY_E2E_HTTP_ALLOWED_URL}")"
HTTP_BLOCK_STATUS="$(curl_via_mercury_http_proxy "${MERCURY_E2E_HTTP_BLOCKED_URL}")"
HTTPS_ALLOW_STATUS="$(curl_via_mercury_https_proxy "${MERCURY_E2E_HTTPS_ALLOWED_URL}")"
HTTPS_BLOCK_STATUS="$(curl_via_mercury_https_proxy "${MERCURY_E2E_HTTPS_BLOCKED_URL}")"

[[ "${HTTP_ALLOW_STATUS}" == "200" ]]
[[ "${HTTP_BLOCK_STATUS}" == "403" ]]
[[ "${HTTPS_ALLOW_STATUS}" == "200" ]]
[[ "${HTTPS_BLOCK_STATUS}" == "403" ]]

rg -qF "${MERCURY_E2E_FILE_DENY_PATH}" "${WORKDIR}/audit.jsonl"
rg -q 'deny_http_local' "${WORKDIR}/audit.jsonl"
rg -q 'deny_https_local' "${WORKDIR}/audit.jsonl"

# ── socket_sendmsg hook ───────────────────────────────────────────────────────
# Verify that lsm/socket_sendmsg blocks a UDP sendto() that supplies an explicit
# destination address (without a prior connect()) to a denied network range.
# This exercises the bypass path that socket_connect does not cover.

echo "testing socket_sendmsg hook..."

SENDMSG_POLICY_FILE="${WORKDIR}/sendmsg-hook-policy.yaml"
# 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — documentation range, not routable.
DENIED_UDP_IP="192.0.2.99"
DENIED_UDP_PORT="12345"

cat > "${SENDMSG_POLICY_FILE}" <<YAML
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
      - id: deny_secret_file
        pattern: ${MERCURY_E2E_FILE_DENY_PATH}
    exec_allow:
      - id: allow_exec_abs
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    network_deny:
      - id: deny_udp_test_net
        cidr: 192.0.2.0/24
    url_allow:
      - id: allow_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /allowed/**
      - id: allow_https_local
        scheme: https
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTPS_PORT}
        path_glob: /allowed/**
    url_deny:
      - id: deny_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /blocked/**
      - id: deny_https_local
        scheme: https
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTPS_PORT}
        path_glob: /blocked/**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${SENDMSG_POLICY_FILE}" > /dev/null

SENDMSG_PY="${WORKDIR}/test_sendmsg_hook.py"
cat > "${SENDMSG_PY}" <<PYEOF
import socket, sys

# Create a UDP socket — do NOT call connect() first.
# sendto() with an explicit destination triggers lsm/socket_sendmsg, not
# lsm/socket_connect, because the socket has no bound remote address.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(b'probe', ('${DENIED_UDP_IP}', ${DENIED_UDP_PORT}))
    print('allowed')
    sys.exit(0)
except PermissionError:
    print('denied')
    sys.exit(1)
finally:
    sock.close()
PYEOF

SENDMSG_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  "${MERCURY_E2E_SYSTEM_PYTHON:-/usr/bin/python3}" "${SENDMSG_PY}" 2>&1)" || true

if [[ "${SENDMSG_OUT}" != *"denied"* ]]; then
  echo "FAIL: socket_sendmsg hook did not block UDP sendto to denied network" >&2
  echo "     got: ${SENDMSG_OUT}" >&2
  cat "${WORKDIR}/daemon.err" | tail -20 >&2
  exit 1
fi

# Wait for audit drain (50ms interval) before checking log.
wait_for_audit_match 'NET_SENDMSG' 100

echo "socket_sendmsg hook: ok"

# ---------------------------------------------------------------------------
# exec_deny: verify a denied child exec from within the active profile.
# AppArmor's on-exec transition enters the profile as the initial command starts;
# the target profile cannot deny that same transition by its own exec rules.
# ---------------------------------------------------------------------------
EXEC_DENY_POLICY="${WORKDIR}/exec-deny-policy.yaml"
cat > "${EXEC_DENY_POLICY}" <<YAML
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
    exec_allow:
      - id: allow_exec_abs
        path: /**
    exec_deny:
      - id: deny_curl_exec
        path: /usr/bin/curl
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${EXEC_DENY_POLICY}" > /dev/null

if [[ "${MERCURY_E2E_FILESYSTEM_BACKEND:-ebpf_lsm}" == "apparmor" ]]; then
  EXEC_DENY_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
    /bin/sh -c '/usr/bin/curl --version' 2>&1)" && EXEC_DENY_CODE=0 || EXEC_DENY_CODE=$?
else
  EXEC_DENY_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
    /usr/bin/curl --version 2>&1)" && EXEC_DENY_CODE=0 || EXEC_DENY_CODE=$?
fi

if [[ "${EXEC_DENY_CODE}" -eq 0 ]]; then
  echo "FAIL: exec_deny did not block /usr/bin/curl" >&2
  echo "     got exit code 0, output: ${EXEC_DENY_OUT}" >&2
  exit 1
fi

echo "exec_deny hook: ok"

# ---------------------------------------------------------------------------
# workspace_roots: files inside the workspace root are allowed; outside denied
# ---------------------------------------------------------------------------
WORKSPACE_DIR="${WORKDIR}/ws_root_test"
mkdir -p "${WORKSPACE_DIR}"
INSIDE_FILE="${WORKSPACE_DIR}/inside.txt"
OUTSIDE_FILE="${WORKDIR}/outside.txt"
echo "inside" > "${INSIDE_FILE}"
echo "outside" > "${OUTSIDE_FILE}"

WORKSPACE_POLICY="${WORKDIR}/workspace-roots-policy.yaml"
cat > "${WORKSPACE_POLICY}" <<YAML
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
      - id: allow_ld_cache
        pattern: /etc/ld.so.cache
      - id: allow_locale_alias
        pattern: /etc/locale.alias
      - id: allow_usr_lib
        pattern: /usr/lib/**
      - id: allow_lib
        pattern: /lib/**
    workspace_roots:
      - ${WORKSPACE_DIR}
    exec_allow:
      - id: allow_exec_abs
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${WORKSPACE_POLICY}" > /dev/null

# Reading a file inside the workspace root should succeed (workspace_root allow).
INSIDE_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/cat "${INSIDE_FILE}" 2>&1)" && INSIDE_CODE=0 || INSIDE_CODE=$?

if [[ "${INSIDE_CODE}" -ne 0 ]]; then
  echo "FAIL: workspace_roots blocked read inside workspace (expected allow)" >&2
  echo "     got exit code ${INSIDE_CODE}, output: ${INSIDE_OUT}" >&2
  exit 1
fi

# Reading a file outside the workspace root should be denied (default deny).
OUTSIDE_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/cat "${OUTSIDE_FILE}" 2>&1)" && OUTSIDE_CODE=0 || OUTSIDE_CODE=$?

if [[ "${OUTSIDE_CODE}" -eq 0 ]]; then
  echo "FAIL: workspace_roots allowed read outside workspace (expected deny)" >&2
  echo "     got exit code 0, output: ${OUTSIDE_OUT}" >&2
  exit 1
fi

echo "workspace_roots enforcement: ok"

# ---------------------------------------------------------------------------
# Policy signing: generate key, sign policy, validate with require mode;
# also verify that validating an unsigned policy in require mode fails.
# ---------------------------------------------------------------------------
SIGNING_KEY_FILE="${WORKDIR}/signing.key"
UNSIGNED_POLICY="${WORKDIR}/unsigned-policy.yaml"
SIGNED_POLICY="${WORKDIR}/signed-policy.yaml"

# Write a minimal valid policy to sign.
cat > "${UNSIGNED_POLICY}" <<YAML
version: v1
defaults:
  decision: allow
  fail_mode: fail_open
  audit_level: all
  enforcement:
    file: observe
    process: observe
    network: observe
profiles:
  default: {}
YAML

# Generate a fresh signing key.
"${BIN_DIR}/mercury-policy" generate-signing-key --key-file "${SIGNING_KEY_FILE}"

# Sign the policy (writes signature block in-place to SIGNED_POLICY).
cp "${UNSIGNED_POLICY}" "${SIGNED_POLICY}"
"${BIN_DIR}/mercury-policy" sign \
  --file "${SIGNED_POLICY}" \
  --key-file "${SIGNING_KEY_FILE}" \
  --key-id "smoke-test-key"

# Validate signed policy with --signature=require → must succeed (exit 0).
"${BIN_DIR}/mercury-policy" validate \
  --file "${SIGNED_POLICY}" \
  --signature require \
  --key-file "${SIGNING_KEY_FILE}"

# Validate unsigned policy with --signature=require → must fail (non-zero exit).
"${BIN_DIR}/mercury-policy" validate \
  --file "${UNSIGNED_POLICY}" \
  --signature require \
  --key-file "${SIGNING_KEY_FILE}" \
  && { echo "FAIL: unsigned policy passed --signature=require validation" >&2; exit 1; } \
  || true

echo "policy signing: ok"

echo "linux runtime smoke passed"
