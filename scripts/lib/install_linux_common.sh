#!/usr/bin/env bash

set -euo pipefail

readonly MERCURY_BINARIES=(mercuryd mercury-run mercury-policy mercury-status mercury-audit)
readonly MERCURY_INSTALL_HELPER_DIR="/usr/local/lib/mercury"
readonly MERCURY_INSTALL_HELPER_PATH="${MERCURY_INSTALL_HELPER_DIR}/install_linux_common.sh"

mercury_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "error: run as root" >&2
    exit 1
  fi
}

mercury_need_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "error: missing required file: $path" >&2
    exit 1
  fi
}

mercury_assert_payload_root() {
  local payload_root="$1"
  local binary=""

  for binary in "${MERCURY_BINARIES[@]}"; do
    mercury_need_file "$payload_root/bin/$binary"
  done

  mercury_need_file "$payload_root/share/dashboard/index.html"
  mercury_need_file "$payload_root/share/examples/config.yaml"
  mercury_need_file "$payload_root/share/examples/policy.yaml"
  mercury_need_file "$payload_root/systemd/mercuryd.service"
  mercury_need_file "$payload_root/systemd/mercuryd.tmpfiles.conf"
}

mercury_stage_repo_payload() {
  local repo_root="$1"
  local payload_root="$2"
  local binary=""

  for binary in "${MERCURY_BINARIES[@]}"; do
    mercury_need_file "$repo_root/target/release/$binary"
  done

  mercury_need_file "$repo_root/dashboard/linux-ui/dist/index.html"
  mercury_need_file "$repo_root/samples/config.yaml"
  mercury_need_file "$repo_root/samples/policy.yaml"
  mercury_need_file "$repo_root/deploy/systemd/mercuryd.service"
  mercury_need_file "$repo_root/deploy/systemd/mercuryd.tmpfiles.conf"
  mercury_need_file "$repo_root/scripts/lib/install_linux_common.sh"

  rm -rf "$payload_root"
  mkdir -p "$payload_root/bin" "$payload_root/share/dashboard" "$payload_root/share/examples" \
    "$payload_root/systemd" "$payload_root/lib"

  for binary in "${MERCURY_BINARIES[@]}"; do
    install -m 0755 "$repo_root/target/release/$binary" "$payload_root/bin/$binary"
  done

  cp -a "$repo_root/dashboard/linux-ui/dist/." "$payload_root/share/dashboard/"
  install -m 0644 "$repo_root/samples/config.yaml" "$payload_root/share/examples/config.yaml"
  install -m 0644 "$repo_root/samples/policy.yaml" "$payload_root/share/examples/policy.yaml"
  install -m 0644 "$repo_root/deploy/systemd/mercuryd.service" \
    "$payload_root/systemd/mercuryd.service"
  install -m 0644 "$repo_root/deploy/systemd/mercuryd.tmpfiles.conf" \
    "$payload_root/systemd/mercuryd.tmpfiles.conf"
  install -m 0644 "$repo_root/scripts/lib/install_linux_common.sh" \
    "$payload_root/lib/install_linux_common.sh"
}

mercury_install_example_file() {
  local source_path="$1"
  local target_path="$2"
  local installed_var="${3:-}"
  local new_path="${target_path}.new"

  if [[ ! -f "$target_path" ]]; then
    install -m 0644 "$source_path" "$target_path"
    if [[ -n "$installed_var" ]]; then
      printf -v "$installed_var" '%s' "1"
    fi
    echo "installed new $target_path"
    return
  fi

  install -m 0644 "$source_path" "$new_path"
  if [[ -n "$installed_var" ]]; then
    printf -v "$installed_var" '%s' "0"
  fi
  echo "left existing $target_path unchanged; wrote $new_path"
}

mercury_ensure_filesystem_backend_config() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local result=""

  if [[ ! -f "$config_path" ]]; then
    return 0
  fi

  result=$(python3 - "$config_path" <<'PYEOF'
import re
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    sys.exit(0)

path = Path(sys.argv[1])

try:
    text = path.read_text()
except Exception:
    sys.exit(0)

try:
    document = yaml.safe_load(text) or {}
except Exception:
    sys.stdout.write(
        f"warning: {path} could not be parsed to auto-set filesystem_backend; "
        "add 'filesystem_backend: apparmor' manually and clear "
        "'kernel.auto_enroll_rules'."
    )
    sys.exit(0)

if not isinstance(document, dict):
    sys.exit(0)

kernel = document.get("kernel")
if kernel is None:
    kernel = {}
    document["kernel"] = kernel
if not isinstance(kernel, dict):
    sys.stdout.write(
        f"warning: {path} has a non-mapping kernel section; add "
        "'filesystem_backend: apparmor' manually and clear "
        "'kernel.auto_enroll_rules'."
    )
    sys.exit(0)

backend = document.get("filesystem_backend")
auto_enroll_rules = kernel.get("auto_enroll_rules") or []
has_auto_enroll = isinstance(auto_enroll_rules, list) and len(auto_enroll_rules) > 0

changed = False
messages = []

if backend in (None, "", "app_armor"):
    document["filesystem_backend"] = "apparmor"
    changed = True
    messages.append("set filesystem_backend: apparmor")

if document.get("filesystem_backend") == "apparmor" and has_auto_enroll:
    kernel["auto_enroll_rules"] = []
    changed = True
    messages.append("cleared kernel.auto_enroll_rules")

if not changed:
    sys.exit(0)

path.write_text(yaml.safe_dump(document, sort_keys=False))

if messages:
    sys.stdout.write(f"updated {path}: " + "; ".join(messages))
else:
    sys.exit(0)
PYEOF
)

  if [[ -n "$result" ]]; then
    echo "$result" >&2
  fi
}

mercury_apply_installer_security_defaults() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local installed_new_config="${2:-0}"
  local dashboard_bind_addr="${MERCURY_DASHBOARD_BIND_ADDR:-}"
  local result=""

  if [[ ! -f "$config_path" ]]; then
    return 0
  fi

  result=$(python3 - "$config_path" "$installed_new_config" "$dashboard_bind_addr" <<'PYEOF'
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    sys.exit(0)

path = Path(sys.argv[1])
installed_new_config = sys.argv[2] == "1"
dashboard_bind_addr = sys.argv[3].strip()

try:
    document = yaml.safe_load(path.read_text()) or {}
except Exception:
    sys.stdout.write(
        f"warning: {path} could not be parsed to apply installer security defaults"
    )
    sys.exit(0)

if not isinstance(document, dict):
    sys.exit(0)

changed = False
messages = []

dashboard = document.get("dashboard")
if dashboard is None:
    dashboard = {}
    document["dashboard"] = dashboard
if isinstance(dashboard, dict) and dashboard_bind_addr:
    if str(dashboard.get("bind_addr", "")).strip() != dashboard_bind_addr:
        dashboard["bind_addr"] = dashboard_bind_addr
        changed = True
        messages.append(f"set dashboard.bind_addr={dashboard_bind_addr}")

if installed_new_config:
    if document.get("signature_verification") != "require_valid":
        document["signature_verification"] = "require_valid"
        changed = True
        messages.append("set signature_verification=require_valid")

    if not str(document.get("signature_key_path", "")).strip():
        document["signature_key_path"] = "/etc/mercury/policy-signing-key"
        changed = True
        messages.append("set signature_key_path=/etc/mercury/policy-signing-key")

    if not str(document.get("signature_key_id", "")).strip():
        document["signature_key_id"] = "default"
        changed = True
        messages.append("set signature_key_id=default")

if not changed:
    sys.exit(0)

path.write_text(yaml.safe_dump(document, sort_keys=False))
sys.stdout.write(f"updated {path}: " + "; ".join(messages))
PYEOF
)

  if [[ -n "$result" ]]; then
    echo "$result" >&2
  fi
}

mercury_run_payload_preflight() {
  local payload_root="$1"
  "$payload_root/bin/mercury-status" preflight
}

mercury_sync_backend_mode_from_preflight() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local mercury_status_bin="${2:-/usr/local/bin/mercury-status}"
  local installed_new_config="${3:-0}"
  local preflight_json=""
  local result=""

  if [[ ! -f "$config_path" || ! -x "$mercury_status_bin" ]]; then
    return 0
  fi

  preflight_json="$("$mercury_status_bin" preflight --json 2>/dev/null || true)"
  if [[ -z "$preflight_json" ]]; then
    echo "warning: failed to read Mercury preflight report; backend_mode was not adjusted" >&2
    return 0
  fi

  result=$(python3 - "$config_path" "$installed_new_config" "$preflight_json" <<'PYEOF'
import json
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    sys.exit(0)

path = Path(sys.argv[1])
installed_new_config = sys.argv[2] == "1"

try:
    report = json.loads(sys.argv[3])
except Exception:
    sys.stdout.write("warning: invalid preflight JSON; backend_mode was not adjusted")
    sys.exit(0)

recommended = str(report.get("recommended_backend_mode", "")).strip()
support_level = str(report.get("support_level", "")).strip() or "unknown"
if recommended not in {"kernel_strict", "linux_compat"}:
    sys.stdout.write(
        f"warning: preflight recommended backend '{recommended or 'unsupported'}'; backend_mode was left unchanged"
    )
    sys.exit(0)

try:
    document = yaml.safe_load(path.read_text()) or {}
except Exception:
    sys.stdout.write(
        f"warning: {path} could not be parsed to align backend_mode with host preflight"
    )
    sys.exit(0)

if not isinstance(document, dict):
    sys.exit(0)

configured = str(document.get("backend_mode", "")).strip()
messages = []
changed = False

if installed_new_config or not configured:
    if configured != recommended:
        document["backend_mode"] = recommended
        changed = True
    messages.append(
        f"set backend_mode={recommended} from host preflight (support_level={support_level})"
    )
elif configured != recommended:
    messages.append(
        f"warning: {path} keeps backend_mode={configured} even though host preflight recommends {recommended}"
    )
else:
    sys.exit(0)

if changed:
    path.write_text(yaml.safe_dump(document, sort_keys=False))

sys.stdout.write("; ".join(messages))
PYEOF
)

  if [[ -n "$result" ]]; then
    echo "$result" >&2
  fi
}

mercury_ensure_dashboard_password_file() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local mercury_policy_bin="${2:-/usr/local/bin/mercury-policy}"
  local password_file=""
  local username=""

  if [[ ! -f "$config_path" || ! -x "$mercury_policy_bin" ]]; then
    return 0
  fi

  readarray -t dashboard_auth < <(python3 - "$config_path" <<'PYEOF'
import sys

try:
    import yaml
except Exception:
    sys.exit(0)

cfg = yaml.safe_load(open(sys.argv[1])) or {}
dashboard = (cfg.get("dashboard") or {}) if isinstance(cfg, dict) else {}
auth = (dashboard.get("auth") or {}) if isinstance(dashboard, dict) else {}

enabled = dashboard.get("enabled", True)
password_file = auth.get("password_file", "/etc/mercury/dashboard.password")
username = auth.get("username", "admin")

print("1" if enabled else "0")
print(password_file)
print(username)
PYEOF
)

  if [[ "${#dashboard_auth[@]}" -lt 3 || "${dashboard_auth[0]}" != "1" ]]; then
    return 0
  fi

  password_file="${dashboard_auth[1]}"
  username="${dashboard_auth[2]}"

  if [[ -f "$password_file" ]]; then
    chmod 0600 "$password_file"
    chown root:root "$password_file"
    echo "preserved existing dashboard password file: $password_file"
    return 0
  fi

  echo "generating dashboard admin password file: $password_file"
  "$mercury_policy_bin" dashboard-password rotate --file "$password_file" --username "$username"
  chmod 0600 "$password_file"
  chown root:root "$password_file"
}

mercury_ensure_signed_policy() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local policy_path="${2:-/etc/mercury/policy.yaml}"
  local mercury_policy_bin="${3:-/usr/local/bin/mercury-policy}"
  local signature_mode=""
  local key_path=""
  local key_id=""

  if [[ ! -f "$config_path" || ! -f "$policy_path" || ! -x "$mercury_policy_bin" ]]; then
    return 0
  fi

  readarray -t signature_cfg < <(python3 - "$config_path" <<'PYEOF'
import sys

try:
    import yaml
except Exception:
    sys.exit(0)

cfg = yaml.safe_load(open(sys.argv[1])) or {}
if not isinstance(cfg, dict):
    sys.exit(0)

print(cfg.get("signature_verification", "warn_on_invalid"))
print(cfg.get("signature_key_path", "/etc/mercury/policy-signing-key"))
print(cfg.get("signature_key_id", "default"))
PYEOF
)

  if [[ "${#signature_cfg[@]}" -lt 3 ]]; then
    return 0
  fi

  signature_mode="${signature_cfg[0]}"
  key_path="${signature_cfg[1]}"
  key_id="${signature_cfg[2]}"

  if [[ "$signature_mode" != "require_valid" ]]; then
    return 0
  fi

  if [[ ! -f "$key_path" ]]; then
    echo "generating policy signing key: $key_path"
    "$mercury_policy_bin" generate-signing-key --key-file "$key_path"
    chown root:root "$key_path"
    chmod 0600 "$key_path"
  fi

  echo "signing policy file: $policy_path"
  "$mercury_policy_bin" sign --file "$policy_path" --key-file "$key_path" --key-id "$key_id"
}

mercury_validate_dashboard_exposure() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local allow_self_signed="${MERCURY_ALLOW_SELF_SIGNED_DASHBOARD_EXPOSURE:-0}"
  local validation_output=""

  if [[ ! -f "$config_path" ]]; then
    return 0
  fi

  set +e
  validation_output=$(python3 - "$config_path" "$allow_self_signed" <<'PYEOF'
import sys

try:
    import yaml
except Exception:
    sys.exit(0)

cfg = yaml.safe_load(open(sys.argv[1])) or {}
allow_self_signed = sys.argv[2] == "1"
dashboard = (cfg.get("dashboard") or {}) if isinstance(cfg, dict) else {}
if not isinstance(dashboard, dict) or not dashboard.get("enabled", True):
    sys.exit(0)

bind_addr = str(dashboard.get("bind_addr", "127.0.0.1:7480")).strip()
host = bind_addr
if bind_addr.startswith("[") and "]" in bind_addr:
    host = bind_addr[1:].split("]", 1)[0]
elif bind_addr.count(":") == 1:
    host = bind_addr.rsplit(":", 1)[0]

if host in {"127.0.0.1", "localhost", "::1"}:
    sys.exit(0)

tls = dashboard.get("tls") or {}
if not isinstance(tls, dict) or not tls.get("enabled", True):
    print(
        f"dashboard.bind_addr={bind_addr} exposes the dashboard beyond loopback; enable TLS or keep the dashboard on localhost behind a reverse proxy"
    )
    sys.exit(2)

if tls.get("auto_generate_self_signed", False):
    if allow_self_signed:
        print(
            f"warning: allowing self-signed TLS for exposed dashboard bind {bind_addr}; browsers will warn unless the Mercury certificate is trusted explicitly"
        )
        sys.exit(3)
    print(
        f"dashboard.bind_addr={bind_addr} exposes the dashboard beyond loopback; provide a trusted TLS certificate with --acme-domain/--acme-email or --tls-cert-file/--tls-key-file, or pass --dashboard-allow-self-signed to opt in explicitly"
    )
    sys.exit(2)
PYEOF
)
  local status=$?
  set -e

  if [[ "$status" -eq 2 ]]; then
    echo "error: ${validation_output}" >&2
    exit 1
  fi

  if [[ "$status" -eq 3 ]]; then
    echo "${validation_output}" >&2
  fi
}

mercury_ensure_dashboard_launch_config() {
  local config_path="${1:-/etc/mercury/config.yaml}"
  local launch_user="${2:-${SUDO_USER:-}}"
  local launcher_path="${3:-/usr/local/bin/mercury-run}"
  local result=""

  if [[ ! -f "$config_path" ]]; then
    return 0
  fi

  result=$(python3 - "$config_path" "$launch_user" "$launcher_path" <<'PYEOF'
import sys
from pathlib import Path

try:
    import yaml
except Exception:
    sys.exit(0)

path = Path(sys.argv[1])
launch_user = sys.argv[2].strip()
launcher_path = sys.argv[3].strip()

try:
    document = yaml.safe_load(path.read_text()) or {}
except Exception:
    sys.stdout.write(
        f"warning: {path} could not be parsed to auto-set dashboard.launch config; "
        "set dashboard.launch.user manually before using the Agents tab."
    )
    sys.exit(0)

if not isinstance(document, dict):
    sys.exit(0)

dashboard = document.get("dashboard")
if dashboard is None:
    dashboard = {}
    document["dashboard"] = dashboard
if not isinstance(dashboard, dict):
    sys.stdout.write(
        f"warning: {path} has a non-mapping dashboard section; set dashboard.launch.user manually."
    )
    sys.exit(0)

launch = dashboard.get("launch")
if launch is None:
    launch = {}
    dashboard["launch"] = launch
if not isinstance(launch, dict):
    sys.stdout.write(
        f"warning: {path} has a non-mapping dashboard.launch section; set dashboard.launch.user manually."
    )
    sys.exit(0)

changed = False
messages = []

if launch_user and not str(launch.get("user", "")).strip():
    launch["user"] = launch_user
    changed = True
    messages.append(f"set dashboard.launch.user={launch_user}")

if launcher_path and not str(launch.get("launcher_path", "")).strip():
    launch["launcher_path"] = launcher_path
    changed = True
    messages.append(f"set dashboard.launch.launcher_path={launcher_path}")

if not launch.get("history_limit"):
    launch["history_limit"] = 25
    changed = True
    messages.append("set dashboard.launch.history_limit=25")

if not changed:
    sys.exit(0)

path.write_text(yaml.safe_dump(document, sort_keys=False))
sys.stdout.write(f"updated {path}: " + "; ".join(messages))
PYEOF
)

  if [[ -n "$result" ]]; then
    echo "$result" >&2
  fi
}

mercury_prepare_group() {
  if ! getent group mercury >/dev/null; then
    groupadd --system mercury
    echo "created system group: mercury"
  fi

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    if ! id -nG "${SUDO_USER}" | tr ' ' '\n' | grep -qx "mercury"; then
      usermod -aG mercury "${SUDO_USER}"
      echo "added user '${SUDO_USER}' to mercury group (log out/in to refresh session groups)"
    fi
  fi
}

# ── TLS certificate setup ─────────────────────────────────────────────────────
# Called from mercury_install_payload_root before the daemon starts.
# Reads env vars set by the installer (or flags passed by the user):
#   MERCURY_ACME_DOMAIN, MERCURY_ACME_EMAIL  – Let's Encrypt via certbot
#   MERCURY_TLS_CERT_FILE, MERCURY_TLS_KEY_FILE – bring-your-own cert
#   MERCURY_NO_TLS=1                           – skip; use self-signed
# Sets MERCURY_TLS_CERT_OUT, MERCURY_TLS_KEY_OUT, MERCURY_TLS_AUTO_GENERATE
# so mercury_install_payload_root can patch config.yaml before daemon start.
#
# Reinstall / upgrade: if certs already exist from a previous run the function
# detects them and skips re-acquiring, making the operation idempotent.
mercury_setup_tls() {
  # Inherit from env if not already set
  local acme_domain="${MERCURY_ACME_DOMAIN:-}"
  local acme_email="${MERCURY_ACME_EMAIL:-}"
  local byoc_cert="${MERCURY_TLS_CERT_FILE:-}"
  local byoc_key="${MERCURY_TLS_KEY_FILE:-}"
  local no_tls="${MERCURY_NO_TLS:-0}"

  # Default outputs (self-signed path)
  MERCURY_TLS_CERT_OUT="/etc/mercury/dashboard.crt"
  MERCURY_TLS_KEY_OUT="/etc/mercury/dashboard.key"
  MERCURY_TLS_AUTO_GENERATE="true"

  if [[ "${no_tls}" == "1" ]]; then
    echo "TLS: using self-signed certificate (auto-generated on first daemon start)"
    return 0
  fi

  # ── BYOC path ──────────────────────────────────────────────────────────────
  if [[ -n "${byoc_cert}" || -n "${byoc_key}" ]]; then
    if [[ -z "${byoc_cert}" || -z "${byoc_key}" ]]; then
      echo "error: --tls-cert-file and --tls-key-file must both be provided together" >&2
      exit 1
    fi
    if [[ ! -f "${byoc_cert}" ]]; then
      echo "error: TLS cert file not found: ${byoc_cert}" >&2
      exit 1
    fi
    if [[ ! -f "${byoc_key}" ]]; then
      echo "error: TLS key file not found: ${byoc_key}" >&2
      exit 1
    fi
    MERCURY_TLS_CERT_OUT="${byoc_cert}"
    MERCURY_TLS_KEY_OUT="${byoc_key}"
    MERCURY_TLS_AUTO_GENERATE="false"
    echo "TLS: using provided certificate: ${byoc_cert}"
    return 0
  fi

  # ── Detect existing TLS configuration (reinstall / upgrade) ────────────────
  # If the config already points at real cert files, default to keeping them.
  # CI-1 FIX: use a YAML-aware parser instead of a regex grep so that keys in
  # sibling sections (e.g. url_gateway.ca_cert_file) are never matched.
  local existing_cert="" existing_key=""
  if [[ -f /etc/mercury/config.yaml ]]; then
    existing_cert=$(python3 -c "
import sys
try:
    import yaml
    cfg = yaml.safe_load(open('/etc/mercury/config.yaml'))
    tls = ((cfg or {}).get('dashboard') or {}).get('tls') or {}
    print(tls.get('cert_file', ''), end='')
except Exception:
    pass
" 2>/dev/null || true)
    existing_key=$(python3 -c "
import sys
try:
    import yaml
    cfg = yaml.safe_load(open('/etc/mercury/config.yaml'))
    tls = ((cfg or {}).get('dashboard') or {}).get('tls') or {}
    print(tls.get('key_file', ''), end='')
except Exception:
    pass
" 2>/dev/null || true)
  fi
  # If the existing paths differ from the self-signed defaults and both files exist, reuse them.
  local self_signed_cert="/etc/mercury/dashboard.crt"
  if [[ -n "${existing_cert}" && "${existing_cert}" != "${self_signed_cert}" \
        && -f "${existing_cert}" && -f "${existing_key:-}" ]]; then
    MERCURY_TLS_CERT_OUT="${existing_cert}"
    MERCURY_TLS_KEY_OUT="${existing_key}"
    MERCURY_TLS_AUTO_GENERATE="false"
    echo "TLS: keeping existing certificate: ${existing_cert}"
    return 0
  fi

  # ── Interactive prompt (if not already set by env/flags) ──────────────────
  # Skip the prompt on reinstall/upgrade when the self-signed cert already exists.
  local self_signed_exists=0
  if [[ -f "/etc/mercury/dashboard.crt" && -f "/etc/mercury/dashboard.key" ]]; then
    self_signed_exists=1
  fi

  if [[ -z "${acme_domain}" && -t 0 && "${self_signed_exists}" -eq 0 ]]; then
    echo
    echo "Certificate setup"
    echo "-----------------"
    echo "Mercury's dashboard runs over HTTPS. Options:"
    echo "  1) Let's Encrypt – obtain a free, trusted certificate (requires a public domain and port 80)"
    echo "  2) Skip           – use a self-signed certificate (browser will show a warning)"
    read -r -p "Choice [1/2, default 2]: " tls_choice </dev/tty
    if [[ "${tls_choice}" == "1" ]]; then
      read -r -p "Domain name (e.g. guard.example.com): " acme_domain </dev/tty
      read -r -p "Email address for Let's Encrypt notifications: " acme_email </dev/tty
    else
      echo "TLS: using self-signed certificate (auto-generated on first daemon start)"
      return 0
    fi
  fi

  # ── Let's Encrypt / certbot path ───────────────────────────────────────────
  if [[ -n "${acme_domain}" ]]; then
    if [[ -z "${acme_email}" ]]; then
      echo "error: --acme-email is required with --acme-domain" >&2
      exit 1
    fi

    # If the cert already exists from a previous run, skip acquisition.
    local le_cert="/etc/letsencrypt/live/${acme_domain}/fullchain.pem"
    local le_key="/etc/letsencrypt/live/${acme_domain}/privkey.pem"
    if [[ -f "${le_cert}" && -f "${le_key}" ]]; then
      echo "TLS: Let's Encrypt certificate already present for ${acme_domain}; skipping certbot"
      _mercury_install_le_hook "${acme_domain}"
      MERCURY_TLS_CERT_OUT="${le_cert}"
      MERCURY_TLS_KEY_OUT="${le_key}"
      MERCURY_TLS_AUTO_GENERATE="false"
      return 0
    fi

    # Ensure certbot is available
    if ! command -v certbot >/dev/null 2>&1; then
      echo "certbot not found; attempting to install..."
      if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y certbot >/dev/null
      elif command -v snap >/dev/null 2>&1; then
        snap install --classic certbot >/dev/null
        ln -sf /snap/bin/certbot /usr/local/bin/certbot || true
      else
        echo "error: could not install certbot; install it manually and re-run with --acme-domain" >&2
        exit 1
      fi
    fi

    # Run certbot; detect port-80 conflicts and offer to resolve them.
    _mercury_certbot_with_port80_retry "${acme_domain}" "${acme_email}" || {
      echo "warning: certbot failed; falling back to self-signed certificate." >&2
      echo "TLS: using self-signed certificate (auto-generated on first daemon start)"
      return 0
    }

    # Install the deploy hook so renewals signal the daemon
    _mercury_install_le_hook "${acme_domain}"

    MERCURY_TLS_CERT_OUT="${le_cert}"
    MERCURY_TLS_KEY_OUT="${le_key}"
    MERCURY_TLS_AUTO_GENERATE="false"
    echo "TLS: Let's Encrypt certificate obtained for ${acme_domain}"
  fi
}

# Install (or refresh) the certbot deploy hook that reloads the daemon's TLS cert.
_mercury_install_le_hook() {
  local domain="$1"
  local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
  mkdir -p "${hook_dir}"
  cat > "${hook_dir}/mercuryd.sh" <<'HOOK'
#!/bin/bash
# Reload Mercury dashboard TLS certificate after Let's Encrypt renewal.
if systemctl is-active --quiet mercuryd; then
  kill -HUP "$(systemctl show -p MainPID --value mercuryd)" 2>/dev/null || \
    systemctl restart mercuryd
fi
HOOK
  chmod 0755 "${hook_dir}/mercuryd.sh"
  echo "     Renewal deploy-hook installed at ${hook_dir}/mercuryd.sh"
}

# Run certbot. If port 80 is blocked, identify the owner, offer to stop it,
# and retry. Any services stopped are restarted afterwards regardless of outcome.
_mercury_certbot_with_port80_retry() {
  local domain="$1"
  local email="$2"
  local stopped_services=()

  _run_certbot() {
    certbot certonly \
      --standalone \
      --non-interactive \
      --agree-tos \
      -m "$2" \
      -d "$1" 2>&1
  }

  echo "Requesting Let's Encrypt certificate for ${domain}..."
  local output exit_code
  output=$(_run_certbot "${domain}" "${email}") && echo "${output}" && return 0
  exit_code=$?
  echo "${output}"

  # Check whether the failure was a port-80 conflict
  if ! echo "${output}" | grep -qiE 'port 80|address already in use|bind.*80'; then
    return "${exit_code}"
  fi

  echo
  echo "Port 80 is in use. Checking which process is holding it..."

  # Identify the process on port 80
  local port80_info port80_proc
  port80_info=$(ss -tlnp 'sport = :80' 2>/dev/null | grep ':80' || true)
  port80_proc=$(echo "${port80_info}" | grep -oP '(?<=users:\(\(")[^"]+' | head -1 || true)
  if [[ -z "${port80_proc}" ]]; then
    # fuser fallback
    port80_proc=$(fuser 80/tcp 2>/dev/null | xargs -I{} ps -p {} -o comm= 2>/dev/null | head -1 || true)
  fi

  if [[ -n "${port80_proc}" ]]; then
    echo "Port 80 is held by: ${port80_proc}"
  else
    echo "Could not identify the process on port 80 (may need root or lsof)."
  fi

  # If non-interactive, do nothing further
  if [[ ! -t 0 ]]; then
    echo "Non-interactive mode: cannot prompt. Pass --no-tls or free port 80 first." >&2
    return 1
  fi

  # Offer known web-server services to stop
  local candidate_services=()
  for svc in nginx apache2 apache lighttpd caddy haproxy httpd; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      candidate_services+=("${svc}")
    fi
  done

  if [[ "${#candidate_services[@]}" -eq 0 && -n "${port80_proc}" ]]; then
    # No recognised systemd service found but we know the process name — add it as a hint
    echo "No recognised web server service found. Stop '${port80_proc}' manually and re-run."
    return 1
  elif [[ "${#candidate_services[@]}" -eq 0 ]]; then
    echo "No recognised web server service is running. Free port 80 manually and re-run."
    return 1
  fi

  echo
  echo "The following services are active and could be temporarily stopped:"
  for svc in "${candidate_services[@]}"; do
    echo "  - ${svc}"
  done
  echo
  read -r -p "Stop them now to allow certbot through, then restart after? [y/N]: " confirm </dev/tty
  if [[ "${confirm,,}" != "y" ]]; then
    echo "Skipping. Free port 80 manually and re-run the installer."
    return 1
  fi

  # Stop the services
  for svc in "${candidate_services[@]}"; do
    echo "Stopping ${svc}..."
    systemctl stop "${svc}" && stopped_services+=("${svc}")
  done

  # Retry certbot
  echo "Retrying certbot..."
  local retry_output ok=0
  if retry_output=$(_run_certbot "${domain}" "${email}"); then
    echo "${retry_output}"
    ok=1
  else
    echo "${retry_output}"
  fi

  # Always restart services we stopped
  for svc in "${stopped_services[@]}"; do
    echo "Restarting ${svc}..."
    systemctl start "${svc}" 2>/dev/null || true
  done

  [[ "${ok:-0}" -eq 1 ]] && return 0 || return 1
}

mercury_install_payload_root() {
  local payload_root="$1"
  local binary=""
  local installed_new_config="0"
  local installed_new_policy="0"

  mercury_assert_payload_root "$payload_root"
  mercury_prepare_group

  install -d -m 0755 /usr/local/bin
  for binary in "${MERCURY_BINARIES[@]}"; do
    install -m 0755 "$payload_root/bin/$binary" "/usr/local/bin/$binary"
  done
  # CI-4: install ai-* alias binaries when present in the payload bundle.
  # These give users shorter names (ai-run, ai-policy, ai-status, ai-guardd)
  # alongside the canonical mercury-* commands. Presence is optional so that
  # release bundles that only include the mercury-* variants still install cleanly.
  local ai_alias=""
  for ai_alias in ai-run ai-policy ai-status ai-guardd; do
    if [[ -f "$payload_root/bin/$ai_alias" ]]; then
      install -m 0755 "$payload_root/bin/$ai_alias" "/usr/local/bin/$ai_alias"
    fi
  done
  echo "installed binaries into /usr/local/bin"

  rm -rf /usr/share/mercury/dashboard
  install -d -m 0755 /usr/share/mercury
  install -d -m 0755 /usr/share/mercury/dashboard
  cp -a "$payload_root/share/dashboard/." /usr/share/mercury/dashboard/
  echo "installed dashboard assets into /usr/share/mercury/dashboard"

  install -d -m 0750 -o root -g mercury /etc/mercury
  mercury_install_example_file "$payload_root/share/examples/config.yaml" /etc/mercury/config.yaml installed_new_config
  mercury_install_example_file "$payload_root/share/examples/policy.yaml" /etc/mercury/policy.yaml installed_new_policy

  chown root:mercury /etc/mercury
  chmod 0750 /etc/mercury

  # TLS cert setup — runs before daemon starts so port 80 is free for certbot
  mercury_setup_tls
  # Patch dashboard.tls block in config.yaml with chosen cert paths.
  # Idempotent: removes any existing tls sub-block(s) under dashboard: before
  # inserting exactly one, so reinstalls/upgrades can't accumulate duplicates.
  if [[ -f /etc/mercury/config.yaml ]]; then
    python3 - <<PYEOF
import re

path = '/etc/mercury/config.yaml'
with open(path) as f:
    txt = f.read()

# Build the replacement tls block (2-space indent matching typical Mercury YAML)
tls_block = """\
  tls:
    enabled: true
    cert_file: ${MERCURY_TLS_CERT_OUT}
    key_file: ${MERCURY_TLS_KEY_OUT}
    auto_generate_self_signed: ${MERCURY_TLS_AUTO_GENERATE}
"""

# 1. Strip ALL existing "  tls:" sub-blocks (handles reinstall duplicates).
#    Match any block of lines that start with "  tls:" followed by lines
#    that are indented deeper (4+ spaces).
txt = re.sub(r'(  tls:\n(?:    [^\n]*\n)*)', '', txt)

# 2. Insert exactly one tls block: right before the end of the dashboard: section.
#    The dashboard section ends at the first top-level key after it.
#    Strategy: find the last line inside the dashboard: block and append after it.
#    A "dashboard-level" line is one indented exactly 2 spaces.
#    The section ends when we hit a line with 0-space indent (top-level key).
dashboard_m = re.search(r'\ndashboard:.*?(?=\n\S|\Z)', txt, re.DOTALL)
if dashboard_m:
    insert_pos = dashboard_m.end()
    # Trim trailing newline from the section to avoid blank lines
    section = txt[dashboard_m.start():insert_pos].rstrip('\n')
    txt = txt[:dashboard_m.start()] + section + '\n' + tls_block + txt[insert_pos:]
else:
    # No dashboard section found — append
    txt = txt.rstrip('\n') + '\ndashboard:\n' + tls_block

with open(path, 'w') as f:
    f.write(txt)

print('config.yaml dashboard.tls updated')
PYEOF
  fi

  mercury_ensure_filesystem_backend_config /etc/mercury/config.yaml
  mercury_sync_backend_mode_from_preflight /etc/mercury/config.yaml /usr/local/bin/mercury-status "$installed_new_config"
  mercury_apply_installer_security_defaults /etc/mercury/config.yaml "$installed_new_config"
  mercury_ensure_dashboard_launch_config /etc/mercury/config.yaml "${SUDO_USER:-}" "/usr/local/bin/mercury-run"
  mercury_validate_dashboard_exposure /etc/mercury/config.yaml
  mercury_ensure_signed_policy /etc/mercury/config.yaml /etc/mercury/policy.yaml /usr/local/bin/mercury-policy
  mercury_ensure_dashboard_password_file /etc/mercury/config.yaml /usr/local/bin/mercury-policy

  install -d -m 0755 /var/lib/mercury
  install -d -m 0755 /var/log/mercury

  mkdir -p /sys/fs/cgroup/mercury/agents

  if [[ -f /etc/mercury/dashboard.password ]]; then
    chmod 0600 /etc/mercury/dashboard.password
    chown root:root /etc/mercury/dashboard.password
  fi

  install -d -m 0755 "$MERCURY_INSTALL_HELPER_DIR"
  install -m 0644 "$payload_root/lib/install_linux_common.sh" "$MERCURY_INSTALL_HELPER_PATH"

  install -m 0644 "$payload_root/systemd/mercuryd.service" /etc/systemd/system/mercuryd.service
  install -m 0644 "$payload_root/systemd/mercuryd.tmpfiles.conf" \
    /etc/tmpfiles.d/mercuryd.tmpfiles.conf
  # Install logrotate config so external log rotation sends SIGHUP to reopen the audit log fd.
  if [[ -f "$payload_root/linux/logrotate.mercury-audit" ]]; then
    install -m 0644 "$payload_root/linux/logrotate.mercury-audit" /etc/logrotate.d/mercury-audit
  fi
  systemd-tmpfiles --create /etc/tmpfiles.d/mercuryd.tmpfiles.conf
  systemctl daemon-reload
  systemctl enable mercuryd >/dev/null
  if systemctl is-active --quiet mercuryd; then
    systemctl restart mercuryd
  else
    systemctl start mercuryd
  fi

  echo "system install complete"
  local _=""
  local ready=0
  for _ in $(seq 1 180); do
    if systemctl is-active --quiet mercuryd \
      && [[ -S /run/mercury/mercuryd.sock ]] \
      && /usr/local/bin/mercury-status --dashboard --ignore-degraded >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.5
  done

  if [[ "$ready" -eq 1 ]]; then
    /usr/local/bin/mercury-status --dashboard --ignore-degraded
  else
    /usr/local/bin/mercury-status --dashboard || true
  fi
}

mercury_remove_installed_binaries() {
  local binary=""

  for binary in "${MERCURY_BINARIES[@]}"; do
    rm -f "/usr/local/bin/${binary}"
  done
  # CI-4: remove ai-* alias binaries if they were installed.
  local ai_alias=""
  for ai_alias in ai-run ai-policy ai-status ai-guardd; do
    rm -f "/usr/local/bin/${ai_alias}"
  done
}

mercury_remove_empty_dir() {
  local path="$1"

  if [[ -d "$path" ]]; then
    rmdir "$path" 2>/dev/null || true
  fi
}

mercury_remove_cgroup_dirs() {
  local path=""

  for path in /sys/fs/cgroup/mercury/agents/*; do
    if [[ -d "$path" ]]; then
      rmdir "$path" 2>/dev/null || true
    fi
  done

  mercury_remove_empty_dir /sys/fs/cgroup/mercury/agents
  mercury_remove_empty_dir /sys/fs/cgroup/mercury
}

mercury_uninstall_system() {
  local purge="${1:-0}"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now mercuryd >/dev/null 2>&1 || true
    systemctl reset-failed mercuryd >/dev/null 2>&1 || true
  fi

  rm -f /etc/systemd/system/mercuryd.service
  rm -f /etc/tmpfiles.d/mercuryd.tmpfiles.conf

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  mercury_remove_installed_binaries

  rm -rf /usr/share/mercury/dashboard
  rm -rf /run/mercury
  rm -f "$MERCURY_INSTALL_HELPER_PATH"

  mercury_remove_empty_dir /usr/share/mercury
  mercury_remove_empty_dir "$MERCURY_INSTALL_HELPER_DIR"
  mercury_remove_cgroup_dirs

  if [[ "$purge" -eq 1 ]]; then
    rm -rf /etc/mercury /var/lib/mercury /var/log/mercury
    echo "purged Mercury config and runtime data"
  else
    echo "preserved /etc/mercury, /var/lib/mercury, and /var/log/mercury"
  fi

  echo "Mercury uninstall complete"
  echo "note: the 'mercury' group was left in place"
}
