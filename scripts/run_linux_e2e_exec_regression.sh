#!/usr/bin/env bash
set -euo pipefail

: "${MERCURY_E2E_WORKDIR:?}"
: "${MERCURY_E2E_SOCKET:?}"
: "${MERCURY_E2E_BIN_DIR:?}"

WORKDIR="${MERCURY_E2E_WORKDIR}"
SOCKET="${MERCURY_E2E_SOCKET}"
BIN_DIR="${MERCURY_E2E_BIN_DIR}"
POLICY_FILE="${WORKDIR}/exec-regression-policy.yaml"

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
    exec_allow:
      - id: allow_exec_abs
        path: /**
    exec_deny:
      - id: deny_curl_exec
        path: /usr/bin/curl
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${POLICY_FILE}" > /dev/null
AUDIT_BYTES="$(wc -c < "${WORKDIR}/audit.jsonl")"

result=0
if "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /usr/bin/curl --version > "${WORKDIR}/initial-exec.out" 2>&1; then
  echo "FAIL: denied initial executable ran successfully" >&2
  result=1
fi

if "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/sh -c '/usr/bin/curl --version' > "${WORKDIR}/child-exec.out" 2>&1; then
  echo "FAIL: denied child executable ran successfully" >&2
  result=1
fi

audit_found=0
for _ in $(seq 1 100); do
  if tail -c "+$((AUDIT_BYTES + 1))" "${WORKDIR}/audit.jsonl" \
      | rg -q 'deny_curl_exec|"action_type":"PROC_EXEC".*"decision":"DENY"'; then
    audit_found=1
    break
  fi
  sleep 0.05
done
if [[ "${audit_found}" -ne 1 ]]; then
  echo "FAIL: denied exec produced no Mercury audit event" >&2
  result=1
fi

if [[ "${result}" -eq 0 ]]; then
  echo "initial and child exec denial with audit: ok"
fi
exit "${result}"
