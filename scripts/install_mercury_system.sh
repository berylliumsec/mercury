#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib/install_linux_common.sh"

usage() {
	cat <<'EOF'
usage: install_mercury_system.sh [--preflight-only] [--force]
                                 [--acme-domain <domain>] [--acme-email <email>]
																 [--tls-cert-file <path> --tls-key-file <path>] [--no-tls]
										 [--dashboard-bind-addr <addr>] [--dashboard-expose]
										 [--dashboard-allow-self-signed]

Builds an install payload from the local repository and installs Mercury on this host.

Dashboard bind options:
	--dashboard-bind-addr <addr>  Set dashboard.bind_addr explicitly, e.g. 127.0.0.1:7480
	--dashboard-expose            Convenience flag for --dashboard-bind-addr 0.0.0.0:7480
	--dashboard-allow-self-signed Allow exposed dashboard binds to use Mercury-managed self-signed TLS
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

PREFLIGHT_ONLY=0
FORCE_INSTALL=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--preflight-only)
			PREFLIGHT_ONLY=1
			shift
			;;
		--force)
			FORCE_INSTALL=1
			shift
			;;
		--acme-domain)
			export MERCURY_ACME_DOMAIN="$2"
			shift 2
			;;
		--acme-domain=*)
			export MERCURY_ACME_DOMAIN="${1#*=}"
			shift
			;;
		--acme-email)
			export MERCURY_ACME_EMAIL="$2"
			shift 2
			;;
		--acme-email=*)
			export MERCURY_ACME_EMAIL="${1#*=}"
			shift
			;;
		--tls-cert-file)
			export MERCURY_TLS_CERT_FILE="$2"
			shift 2
			;;
		--tls-cert-file=*)
			export MERCURY_TLS_CERT_FILE="${1#*=}"
			shift
			;;
		--tls-key-file)
			export MERCURY_TLS_KEY_FILE="$2"
			shift 2
			;;
		--tls-key-file=*)
			export MERCURY_TLS_KEY_FILE="${1#*=}"
			shift
			;;
		--no-tls)
			export MERCURY_NO_TLS=1
			shift
			;;
		--dashboard-bind-addr)
			export MERCURY_DASHBOARD_BIND_ADDR="$2"
			shift 2
			;;
		--dashboard-bind-addr=*)
			export MERCURY_DASHBOARD_BIND_ADDR="${1#*=}"
			shift
			;;
		--dashboard-expose)
			export MERCURY_DASHBOARD_BIND_ADDR="0.0.0.0:7480"
			shift
			;;
		--dashboard-allow-self-signed)
			export MERCURY_ALLOW_SELF_SIGNED_DASHBOARD_EXPOSURE=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "error: unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PAYLOAD_ROOT="$WORK_DIR/mercury-linux-x86_64"
mercury_stage_repo_payload "$REPO_ROOT" "$PAYLOAD_ROOT"

if ! mercury_run_payload_preflight "$PAYLOAD_ROOT"; then
	if [[ "$PREFLIGHT_ONLY" -eq 1 ]]; then
		exit 1
	fi

	if [[ "$FORCE_INSTALL" -ne 1 ]]; then
		die "preflight failed; rerun with --force to continue anyway"
	fi

	echo "preflight failed; continuing because --force was provided" >&2
fi

if [[ "$PREFLIGHT_ONLY" -eq 1 ]]; then
	exit 0
fi

mercury_require_root
mercury_install_payload_root "$PAYLOAD_ROOT"
