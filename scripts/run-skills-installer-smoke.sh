#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WORK_DIR_DEFAULT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentpay-skills-installer-smoke"
KEEP_WORK_DIR_DEFAULT="${AGENTPAY_SKILLS_INSTALLER_SMOKE_KEEP_WORK_DIR:-1}"
BUNDLE_ARCHIVE_DEFAULT="${AGENTPAY_SKILLS_INSTALLER_SMOKE_BUNDLE_ARCHIVE:-}"

WORK_DIR="$WORK_DIR_DEFAULT"
KEEP_WORK_DIR="$KEEP_WORK_DIR_DEFAULT"
BUNDLE_ARCHIVE="$BUNDLE_ARCHIVE_DEFAULT"

say() {
  printf '[agentpay-skills-installer-smoke] %s\n' "$*"
}

die() {
  printf '[agentpay-skills-installer-smoke] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF_USAGE'
Run a smoke test for the AgentPay skills-only installer mode.

Usage:
  scripts/run-skills-installer-smoke.sh [options]

Options:
  --work-dir <dir>           Scratch directory for the bundle, fake HOME, workspace, and logs
  --bundle-archive <path>    Prebuilt AgentPay installer bundle archive to install
  --keep-work-dir <0|1>      Keep the work directory after success/failure (default: 1)
  --help                     Show this message

Behavior:
  - runs scripts/installer.sh --skills-only twice
  - uses a fake HOME and fake workspace so skill installs do not touch the host machine
  - forces installation of the full preset target catalog
  - reuses the standard AgentPay installer bundle instead of a separate skills-only archive
  - verifies the installed skill packs, workspace adapters, and Cursor files after install
EOF_USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --work-dir)
        WORK_DIR="$2"
        shift 2
        ;;
      --bundle-archive)
        BUNDLE_ARCHIVE="$2"
        shift 2
        ;;
      --keep-work-dir)
        KEEP_WORK_DIR="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

normalize_keep_work_dir() {
  case "$KEEP_WORK_DIR" in
    0|1)
      ;;
    *)
      die "--keep-work-dir must be 0 or 1"
      ;;
  esac
}

require_host() {
  command -v tar >/dev/null 2>&1 || die "tar is required."
  command -v bash >/dev/null 2>&1 || die "bash is required."
  [[ -n "$BUNDLE_ARCHIVE" ]] || die "--bundle-archive is required."
  [[ -f "$BUNDLE_ARCHIVE" ]] || die "Bundle archive does not exist: $BUNDLE_ARCHIVE"
}

prepare_dirs() {
  local abs=""
  mkdir -p "$(dirname "$WORK_DIR")"
  mkdir -p "$WORK_DIR"
  abs="$(cd "$WORK_DIR" && pwd)"
  WORK_DIR="$abs"
  LOG_DIR="$WORK_DIR/logs"
  HOME_DIR="$WORK_DIR/home"
  PROJECT_WORKSPACE="$WORK_DIR/project-workspace"
  CURSOR_WORKSPACE="$WORK_DIR/cursor-workspace"
  ABS_BUNDLE_ARCHIVE="$(cd "$(dirname "$BUNDLE_ARCHIVE")" && pwd)/$(basename "$BUNDLE_ARCHIVE")"

  rm -rf "$LOG_DIR" "$HOME_DIR" "$PROJECT_WORKSPACE" "$CURSOR_WORKSPACE"
  mkdir -p "$LOG_DIR" "$HOME_DIR" "$PROJECT_WORKSPACE" "$CURSOR_WORKSPACE"
}

cleanup_on_success() {
  if [[ "$KEEP_WORK_DIR" == "1" ]]; then
    return
  fi
  rm -rf "$WORK_DIR"
}

run_and_capture() {
  local logfile="$1"
  shift
  (
    set -o pipefail
    "$@" 2>&1 | tee "$logfile"
  )
}

run_installer_pass() {
  local pass_name="$1"
  local logfile="$LOG_DIR/${pass_name}.log"

  say "Running skills installer pass: $pass_name"
  run_and_capture "$logfile" env \
    HOME="$HOME_DIR" \
    PATH="${PATH}" \
    SHELL="/bin/bash" \
    AGENTPAY_SDK_BUNDLE_URL="file://${ABS_BUNDLE_ARCHIVE}" \
    AGENTPAY_SETUP_INSTALL_SKILLS="yes" \
    AGENTPAY_SETUP_WORKSPACE="$PROJECT_WORKSPACE" \
    AGENTPAY_SETUP_CURSOR_WORKSPACE="$CURSOR_WORKSPACE" \
    AGENTPAY_SETUP_ASSUME_DEFAULTS="1" \
    AGENTPAY_SETUP_USE_STDIN="1" \
    bash "$REPO_ROOT/scripts/installer.sh" --skills-only
}

verify_install() {
  local verify_log="$LOG_DIR/verify.log"

  run_and_capture "$verify_log" env \
    HOME="$HOME_DIR" \
    PROJECT_WORKSPACE="$PROJECT_WORKSPACE" \
    CURSOR_WORKSPACE="$CURSOR_WORKSPACE" \
    bash -c '
      set -euo pipefail
      test -f "$HOME/.codex/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.config/agents/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.agents/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.cline/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.openclaw/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.claude/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.config/goose/skills/agentpay-sdk/SKILL.md"
      test -f "$HOME/.codeium/windsurf/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/.agents/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/.claude/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/.cline/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/.goose/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/.windsurf/skills/agentpay-sdk/SKILL.md"
      test -f "$PROJECT_WORKSPACE/AGENTS.md"
      test -f "$PROJECT_WORKSPACE/CLAUDE.md"
      test -f "$PROJECT_WORKSPACE/GEMINI.md"
      test -f "$PROJECT_WORKSPACE/.github/copilot-instructions.md"
      test -f "$PROJECT_WORKSPACE/.clinerules/agentpay-sdk.md"
      test -f "$CURSOR_WORKSPACE/.cursor/rules/agentpay-sdk.mdc"
      test -f "$CURSOR_WORKSPACE/AGENTS.md"
    '

  {
    printf 'WORK_DIR=%s\n' "$WORK_DIR"
    printf 'HOME_DIR=%s\n' "$HOME_DIR"
    printf 'PROJECT_WORKSPACE=%s\n' "$PROJECT_WORKSPACE"
    printf 'CURSOR_WORKSPACE=%s\n' "$CURSOR_WORKSPACE"
    printf 'BUNDLE_ARCHIVE=%s\n' "$ABS_BUNDLE_ARCHIVE"
  } >"$LOG_DIR/paths.env"

  find "$HOME_DIR" -maxdepth 5 -print | sort >"$LOG_DIR/home-tree.txt"
  find "$PROJECT_WORKSPACE" -maxdepth 5 -print | sort >"$LOG_DIR/project-tree.txt"
  find "$CURSOR_WORKSPACE" -maxdepth 5 -print | sort >"$LOG_DIR/cursor-tree.txt"
}

main() {
  parse_args "$@"
  normalize_keep_work_dir
  require_host
  prepare_dirs

  run_installer_pass installer-pass-1
  run_installer_pass installer-pass-2
  verify_install

  say "Skills installer smoke succeeded. Logs: $LOG_DIR"
  cleanup_on_success
}

main "$@"
