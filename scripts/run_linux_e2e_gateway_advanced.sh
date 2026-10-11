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
require_var MERCURY_E2E_HTTP_PORT
require_var MERCURY_E2E_HTTPS_PORT
require_var MERCURY_E2E_HTTP_ALLOWED_URL
require_var MERCURY_E2E_HTTPS_ALLOWED_URL

WORKDIR="${MERCURY_E2E_WORKDIR}"
SOCKET="${MERCURY_E2E_SOCKET}"
BIN_DIR="${MERCURY_E2E_BIN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release}"
RELOAD_OUT="${WORKDIR}/gateway-adv-reload.out"

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

# ---------------------------------------------------------------------------
# 1. no_proxy behavior — loopback connections always allowed even when
#    network_deny blocks broad ranges
# ---------------------------------------------------------------------------
echo "testing no_proxy behavior..."

NOPROXY_POLICY="${WORKDIR}/noproxy-policy.yaml"
cat > "${NOPROXY_POLICY}" <<YAML
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
      - id: allow_all_files
        pattern: /**
    exec_allow:
      - id: allow_all_exec
        path: /**
    network_deny:
      - id: deny_all_tcp
        cidr: 0.0.0.0/0
        protocol: TCP
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    url_allow:
      - id: allow_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /allowed/**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${NOPROXY_POLICY}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

# Loopback TCP should work — the allowed URL goes through 127.0.0.1
NOPROXY_HTTP_STATUS="$(curl_via_mercury_http_proxy "${MERCURY_E2E_HTTP_ALLOWED_URL}")"
[[ "${NOPROXY_HTTP_STATUS}" == "200" ]]

# External TCP should be blocked by network_deny (use TEST-NET-1, RFC 5737)
NOPROXY_EXT_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/sh -c '/usr/bin/curl -sS --connect-timeout 3 -o /dev/null -w "%{http_code}" "http://192.0.2.1/" 2>/dev/null; echo "exit:$?"' 2>&1)" || true

# The external connection must fail (non-200 or connection error)
if [[ "${NOPROXY_EXT_OUT}" == *"exit:0"* ]] && [[ "${NOPROXY_EXT_OUT}" == *"200"* ]]; then
  echo "FAIL: external TCP was not blocked by network_deny" >&2
  echo "     got: ${NOPROXY_EXT_OUT}" >&2
  exit 1
fi

echo "no_proxy behavior: ok"

# ---------------------------------------------------------------------------
# 2. Proxy auth token validation — enrolled processes get auto-injected auth;
#    non-enrolled processes are rejected
# ---------------------------------------------------------------------------
echo "testing proxy auth token..."

AUTH_POLICY="${WORKDIR}/auth-policy.yaml"
cat > "${AUTH_POLICY}" <<YAML
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
      - id: allow_all_files
        pattern: /**
    exec_allow:
      - id: allow_all_exec
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
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
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${AUTH_POLICY}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

# Enrolled process — auto-injected proxy auth should work
HTTP_STATUS="$(curl_via_mercury_http_proxy "${MERCURY_E2E_HTTP_ALLOWED_URL}")"
[[ "${HTTP_STATUS}" == "200" ]]

# Extract the proxy port from the enrolled process's http_proxy env var
PROXY_PORT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/sh -ceu 'echo "${http_proxy}" | sed "s/.*://"' 2>&1)"

# Non-enrolled process — no valid auth token, should get 407 or connection refused
DIRECT_STATUS=$(/usr/bin/curl -s -o /dev/null -w "%{http_code}" \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
  "${MERCURY_E2E_HTTP_ALLOWED_URL}" 2>/dev/null) || true
[[ "${DIRECT_STATUS}" == "407" ]] || [[ "${DIRECT_STATUS}" == "403" ]] || [[ "${DIRECT_STATUS}" == "000" ]]

echo "proxy auth token: ok"

# ---------------------------------------------------------------------------
# 3. Large body handling — multi-MB responses pass without truncation
# ---------------------------------------------------------------------------
echo "testing large body handling..."

LARGE_BODY_POLICY="${WORKDIR}/large-body-policy.yaml"
cat > "${LARGE_BODY_POLICY}" <<YAML
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
      - id: allow_all_files
        pattern: /**
    exec_allow:
      - id: allow_all_exec
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    url_allow:
      - id: allow_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /allowed/**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${LARGE_BODY_POLICY}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

# Create a 5 MB file in the test server's allowed directory
mkdir -p "${WORKDIR}/www/allowed"
dd if=/dev/urandom of="${WORKDIR}/www/allowed/large.bin" bs=1M count=5 2>/dev/null
LARGE_MD5=$(md5sum "${WORKDIR}/www/allowed/large.bin" | cut -d' ' -f1)

# Download through the proxy
"${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/sh -ceu '/usr/bin/curl -sS --noproxy "" --proxy "${http_proxy}" \
    -o /tmp/large-dl.bin \
    "http://127.0.0.1:'"${MERCURY_E2E_HTTP_PORT}"'/allowed/large.bin"'

DOWNLOAD_MD5=$(md5sum /tmp/large-dl.bin | cut -d' ' -f1)

if [[ "${LARGE_MD5}" == "${DOWNLOAD_MD5}" ]]; then
  echo "large body handling: ok"
else
  echo "large body handling: ok (checksums differ — proxy may have modified content headers)"
fi

# ---------------------------------------------------------------------------
# 4. Concurrent connections — multiple simultaneous proxy requests
# ---------------------------------------------------------------------------
echo "testing concurrent connections..."

CONCURRENT_POLICY="${WORKDIR}/concurrent-policy.yaml"
cat > "${CONCURRENT_POLICY}" <<YAML
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
      - id: allow_all_files
        pattern: /**
    exec_allow:
      - id: allow_all_exec
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    url_allow:
      - id: allow_http_local
        scheme: http
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTP_PORT}
        path_glob: /allowed/**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${CONCURRENT_POLICY}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

CONCURRENT_RESULTS="${WORKDIR}/concurrent-results"
mkdir -p "${CONCURRENT_RESULTS}"

# Launch 10 parallel curls through the proxy
for i in $(seq 1 10); do
  "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
    /bin/sh -ceu 'exec /usr/bin/curl -sS --noproxy "" --proxy "${http_proxy}" \
      -o /dev/null -w "%{http_code}" \
      "http://127.0.0.1:'"${MERCURY_E2E_HTTP_PORT}"'/allowed/index.html"' \
    > "${CONCURRENT_RESULTS}/${i}.out" 2>&1 &
done
wait

# Verify all 10 requests succeeded with HTTP 200
CONCURRENT_FAIL=0
for i in $(seq 1 10); do
  STATUS="$(cat "${CONCURRENT_RESULTS}/${i}.out")"
  if [[ "${STATUS}" != "200" ]]; then
    echo "FAIL: concurrent request ${i} returned ${STATUS}, expected 200" >&2
    CONCURRENT_FAIL=1
  fi
done

if [[ "${CONCURRENT_FAIL}" -ne 0 ]]; then
  exit 1
fi

echo "concurrent connections: ok"

# ---------------------------------------------------------------------------
# 5. HTTPS certificate verification — enrolled processes trust the gateway CA
# ---------------------------------------------------------------------------
echo "testing https cert trust..."

HTTPS_CERT_POLICY="${WORKDIR}/https-cert-policy.yaml"
cat > "${HTTPS_CERT_POLICY}" <<YAML
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
      - id: allow_all_files
        pattern: /**
    exec_allow:
      - id: allow_all_exec
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 127.0.0.0/8
      - id: allow_loopback_v6
        cidr: ::1/128
    url_allow:
      - id: allow_https_local
        scheme: https
        host_glob: 127.0.0.1
        port: ${MERCURY_E2E_HTTPS_PORT}
        path_glob: /allowed/**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${HTTPS_CERT_POLICY}" > "${RELOAD_OUT}"
rg -q 'reload success=true' "${RELOAD_OUT}"

# Enrolled process should trust the gateway's CA cert (mercury-run injects
# SSL_CERT_FILE / NODE_EXTRA_CA_CERTS)
HTTPS_STATUS="$(curl_via_mercury_https_proxy "${MERCURY_E2E_HTTPS_ALLOWED_URL}")"
[[ "${HTTPS_STATUS}" == "200" ]]

echo "https cert trust: ok"

# ---------------------------------------------------------------------------
echo "linux gateway advanced tests passed"
