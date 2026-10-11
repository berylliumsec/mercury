#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_PATH="$REPO_ROOT/deploy/linux/install-mercury-linux.sh.template"

OUTPUT_PATH=""
RELEASE_TAG=""
REPOSITORY=""
PUBLIC_KEY_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --release-tag)
      RELEASE_TAG="$2"
      shift 2
      ;;
    --repository)
      REPOSITORY="$2"
      shift 2
      ;;
    --public-key-file)
      PUBLIC_KEY_FILE="$2"
      shift 2
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$OUTPUT_PATH" || -z "$RELEASE_TAG" || -z "$REPOSITORY" || -z "$PUBLIC_KEY_FILE" ]]; then
  echo "usage: $0 --output <path> --release-tag <tag> --repository <owner/repo> --public-key-file <path>" >&2
  exit 1
fi

if [[ ! -f "$PUBLIC_KEY_FILE" ]]; then
  echo "error: missing public key file: $PUBLIC_KEY_FILE" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

PUBLIC_KEY_B64="$(base64 < "$PUBLIC_KEY_FILE" | tr -d '\n')"

sed \
  -e "s|__RELEASE_TAG__|$RELEASE_TAG|g" \
  -e "s|__RELEASE_REPOSITORY__|$REPOSITORY|g" \
  -e "s|__SIGNING_PUBLIC_KEY_B64__|$PUBLIC_KEY_B64|g" \
  "$TEMPLATE_PATH" > "$OUTPUT_PATH"

chmod 0755 "$OUTPUT_PATH"
echo "rendered $OUTPUT_PATH"
