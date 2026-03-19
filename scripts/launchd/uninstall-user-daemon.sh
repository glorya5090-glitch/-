#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uninstall AgentPay SDK root LaunchDaemon.

Usage:
  uninstall-user-daemon.sh [options]

Options:
  --label <label>                LaunchDaemon label (default: com.agentpay.daemon)
  --keychain-service <name>      Keychain service (default: agentpay-daemon-password)
  --keychain-account <name>      Keychain account (default: current username)
  --delete-keychain-password     Remove stored Keychain password item
  --help                         Show this help
EOF
}

require_non_empty_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" ]]; then
    echo "missing value for $flag" >&2
    exit 1
  fi
}

validate_label() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid --label '$value': allowed characters are [A-Za-z0-9._-]" >&2
    exit 1
  fi
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "uninstall-user-daemon.sh must be run as root" >&2
  exit 1
fi

label="com.agentpay.daemon"
keychain_service="agentpay-daemon-password"
keychain_account="$(id -un)"
delete_keychain_password=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      require_non_empty_value "$1" "${2:-}"
      label="$2"
      shift 2
      ;;
    --keychain-service)
      require_non_empty_value "$1" "${2:-}"
      keychain_service="$2"
      shift 2
      ;;
    --keychain-account)
      require_non_empty_value "$1" "${2:-}"
      keychain_account="$2"
      shift 2
      ;;
    --delete-keychain-password)
      delete_keychain_password=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_label "$label"

plist_path="/Library/LaunchDaemons/${label}.plist"

launchctl bootout "system/${label}" >/dev/null 2>&1 || true
launchctl disable "system/${label}" >/dev/null 2>&1 || true

if [[ -f "$plist_path" ]]; then
  rm -f "$plist_path"
fi

if [[ "$delete_keychain_password" == true ]]; then
  security delete-generic-password \
    -s "$keychain_service" \
    -a "$keychain_account" \
    /Library/Keychains/System.keychain >/dev/null 2>&1 || true
fi

cat <<EOF
uninstalled launch daemon:
  label: ${label}
  plist removed: ${plist_path}
  keychain password removed: ${delete_keychain_password}
EOF
