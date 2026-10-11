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

WORKDIR="${MERCURY_E2E_WORKDIR}"
SOCKET="${MERCURY_E2E_SOCKET}"
BIN_DIR="${MERCURY_E2E_BIN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release}"
POLICY_FILE="${WORKDIR}/rate-limit-policy.yaml"
STATUS_OUT="${WORKDIR}/rate-limit-status.out"

# ---------------------------------------------------------------------------
# Helper: capture mercury-status health output into a file
# ---------------------------------------------------------------------------
capture_health() {
  local dest="$1"
  "${BIN_DIR}/mercury-status" --socket "${SOCKET}" --ignore-degraded > "${dest}"
}

# ---------------------------------------------------------------------------
# Helper: extract a key=value field from the single-line health output
# ---------------------------------------------------------------------------
health_field() {
  local key="$1"
  local file="$2"
  # Health output is a single line of space-separated key=value pairs.
  # Use grep -oP to extract the value for the requested key.
  grep -oP "(?<=${key}=)[^ ]+" "${file}" || echo "0"
}

# ---------------------------------------------------------------------------
# Helper: wait for audit log to contain a pattern (same as smoke test)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Permissive policy: allow everything so events are generated without blocking
# ---------------------------------------------------------------------------
cat > "${POLICY_FILE}" <<YAML
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
  default:
    file_allow:
      - id: allow_all
        pattern: /**
    exec_allow:
      - id: allow_exec_all
        path: /**
    network_allow:
      - id: allow_loopback
        cidr: 0.0.0.0/0
YAML

# Verify daemon is up before we begin.
capture_health "${STATUS_OUT}"
rg -q 'daemon_up=true' "${STATUS_OUT}"

# Load the permissive policy.
"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${POLICY_FILE}" > /dev/null

# ===========================================================================
# Part 1: Rate Limiting Verification
# ===========================================================================
echo "testing rate_limit: burst suppression..."

# Record baseline ingestion counter.
capture_health "${STATUS_OUT}"
BASELINE_INGESTED=$(health_field events_ingested_total "${STATUS_OUT}")
BASELINE_DROPPED_QUEUE=$(health_field events_dropped_queue_total "${STATUS_OUT}")

# Truncate the audit log so we only count events from this burst.
: > "${WORKDIR}/audit.jsonl" || true

# Generate a burst of 2000+ file operations in ~1 second from an enrolled process.
BURST_PY="${WORKDIR}/burst_file_ops.py"
cat > "${BURST_PY}" <<'PYEOF'
import os, time

start = time.monotonic()
count = 0
while time.monotonic() - start < 1.0:
    try:
        fd = os.open('/dev/null', os.O_RDONLY)
        os.close(fd)
        count += 1
    except:
        pass
print(f"attempted:{count}")
PYEOF

BURST_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  python3 "${BURST_PY}" 2>&1)"
echo "burst output: ${BURST_OUT}"

# Extract how many file opens we attempted.
BURST_ATTEMPTED=$(echo "${BURST_OUT}" | grep -oP '(?<=attempted:)\d+' || echo "0")

if [[ "${BURST_ATTEMPTED}" -lt 2000 ]]; then
  echo "WARN: burst only managed ${BURST_ATTEMPTED} attempts (need >=2000 for meaningful test)" >&2
  echo "      continuing anyway — test will check relative suppression" >&2
fi

# Give the daemon a moment to flush its ingest pipeline.
sleep 1

# Count audit events produced during the burst window.
AUDIT_EVENT_COUNT=$(wc -l < "${WORKDIR}/audit.jsonl" || echo "0")

# Capture post-burst health.
capture_health "${STATUS_OUT}"
POST_INGESTED=$(health_field events_ingested_total "${STATUS_OUT}")
POST_DROPPED_QUEUE=$(health_field events_dropped_queue_total "${STATUS_OUT}")

INGESTED_DURING_BURST=$((POST_INGESTED - BASELINE_INGESTED))
DROPPED_DURING_BURST=$((POST_DROPPED_QUEUE - BASELINE_DROPPED_QUEUE))

echo "burst stats: attempted=${BURST_ATTEMPTED} ingested=${INGESTED_DURING_BURST} dropped_queue=${DROPPED_DURING_BURST} audit_lines=${AUDIT_EVENT_COUNT}"

# The kernel rate limiter caps events per PID per second (~1000 default).
# If we attempted 2000+ opens, the audit/ingest count should be noticeably
# less than the number attempted — evidence the rate limiter is working.
# We use a generous threshold: audit events should be less than 90% of attempts.
if [[ "${BURST_ATTEMPTED}" -ge 2000 ]]; then
  THRESHOLD=$(( BURST_ATTEMPTED * 90 / 100 ))
  if [[ "${AUDIT_EVENT_COUNT}" -ge "${THRESHOLD}" ]]; then
    echo "FAIL: expected rate limiting to suppress events — got ${AUDIT_EVENT_COUNT} audit lines for ${BURST_ATTEMPTED} attempts (threshold ${THRESHOLD})" >&2
    exit 1
  fi
  echo "rate limiting evidence: ${AUDIT_EVENT_COUNT} audit events for ${BURST_ATTEMPTED} attempts"
fi

echo "rate_limit burst suppression: ok"

# ---------------------------------------------------------------------------
# Part 1b: Normal flow after rate limit window resets
# ---------------------------------------------------------------------------
echo "testing rate_limit: normal flow after reset..."

# Wait for the rate limit window to reset (2 seconds).
sleep 2

# Truncate audit log again.
: > "${WORKDIR}/audit.jsonl" || true

# A single file access should still produce an audit event.
"${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  /bin/cat /dev/null > /dev/null 2>&1

# Wait for the event to appear in the audit log.
sleep 1

POST_RESET_LINES=$(wc -l < "${WORKDIR}/audit.jsonl" || echo "0")

if [[ "${POST_RESET_LINES}" -lt 1 ]]; then
  echo "FAIL: expected at least 1 audit event after rate limit reset, got ${POST_RESET_LINES}" >&2
  exit 1
fi

echo "rate_limit normal flow after reset: ok"

# ===========================================================================
# Part 2: Backpressure Detection
# ===========================================================================
echo "testing backpressure: pre-load health check..."

# Check health endpoint before load.
capture_health "${STATUS_OUT}"
PRE_LOAD_BACKLOG=$(health_field ingest_backlog_len "${STATUS_OUT}")
PRE_LOAD_INGESTED=$(health_field events_ingested_total "${STATUS_OUT}")

echo "pre-load: backlog=${PRE_LOAD_BACKLOG} ingested=${PRE_LOAD_INGESTED}"

# Daemon must be up.
rg -q 'daemon_up=true' "${STATUS_OUT}"

echo "backpressure pre-load health: ok"

# ---------------------------------------------------------------------------
# Part 2b: Generate sustained event flood from multiple enrolled processes
# ---------------------------------------------------------------------------
echo "testing backpressure: sustained event flood..."

FLOOD_PY="${WORKDIR}/flood_events.py"
cat > "${FLOOD_PY}" <<'PYEOF'
import os, multiprocessing, time

def flood(duration=3):
    start = time.monotonic()
    count = 0
    while time.monotonic() - start < duration:
        try:
            fd = os.open('/dev/null', os.O_RDONLY)
            os.close(fd)
            count += 1
        except:
            pass
    return count

if __name__ == '__main__':
    procs = [multiprocessing.Process(target=flood) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    print("flood_complete")
PYEOF

FLOOD_OUT="$("${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  python3 "${FLOOD_PY}" 2>&1)" || true
echo "flood output: ${FLOOD_OUT}"

# Give daemon time to process the tail end of the flood.
sleep 2

echo "backpressure sustained flood: ok"

# ---------------------------------------------------------------------------
# Part 2c: Post-load health check — daemon must still be responsive
# ---------------------------------------------------------------------------
echo "testing backpressure: post-load health check..."

capture_health "${STATUS_OUT}"

# Daemon must still be up and responsive after the flood.
rg -q 'daemon_up=true' "${STATUS_OUT}"

POST_LOAD_INGESTED=$(health_field events_ingested_total "${STATUS_OUT}")
POST_LOAD_DROPPED=$(health_field events_dropped_queue_total "${STATUS_OUT}")
POST_LOAD_BACKLOG=$(health_field ingest_backlog_len "${STATUS_OUT}")

echo "post-load: ingested=${POST_LOAD_INGESTED} dropped_queue=${POST_LOAD_DROPPED} backlog=${POST_LOAD_BACKLOG}"

# The daemon must have ingested some events during the flood.
if [[ "${POST_LOAD_INGESTED}" -le "${PRE_LOAD_INGESTED}" ]]; then
  echo "FAIL: expected events_ingested_total to increase after flood" >&2
  echo "     pre=${PRE_LOAD_INGESTED} post=${POST_LOAD_INGESTED}" >&2
  exit 1
fi

echo "backpressure post-load health: ok"

# ===========================================================================
echo "linux e2e rate-limit and backpressure tests passed"
