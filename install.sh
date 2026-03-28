#!/usr/bin/env bash
# wlfi.sh — dev environment bootstrap
# Usage:
#   curl -fsSL https://wlfi.sh         | bash   # latest
#   curl -fsSL https://wlfi.sh/latest  | bash   # latest (explicit)
#   curl -fsSL https://wlfi.sh/0.1.0   | bash   # specific version
set -euo pipefail

VERSION="0.1.0"

# ── colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { printf "${CYAN}  →${RESET} %s\n" "$*"; }
success() { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}  !${RESET} %s\n" "$*"; }
error()   { printf "${RED}  ✗${RESET} %s\n" "$*" >&2; exit 1; }
header()  { printf "\n${BOLD}%s${RESET}\n" "$*"; }

detect_os() {
  case "$(uname -s)" in
    Darwin) OS="macos" ;;
    Linux)
      if   [ -f /etc/debian_version ]; then OS="debian"
      elif [ -f /etc/redhat-release ]; then OS="redhat"
      elif [ -f /etc/arch-release ];   then OS="arch"
      else                                  OS="linux"
      fi ;;
    *) error "Unsupported OS: $(uname -s)" ;;
  esac
}

pkg_install() {
  case "$OS" in
    macos)  brew install "$@" ;;
    debian) sudo apt-get install -y "$@" ;;
    redhat) sudo dnf install -y "$@" ;;
    arch)   sudo pacman -S --noconfirm "$@" ;;
    *)      warn "Unknown package manager — skipping: $*" ;;
  esac
}

cmd_exists() { command -v "$1" &>/dev/null; }

install_homebrew() {
  if cmd_exists brew; then success "Homebrew already installed"; return; fi
  info "Installing Homebrew…"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  [ -f /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
  success "Homebrew installed"
}

update_pkg_cache() {
  case "$OS" in
    debian) sudo apt-get update -qq ;;
    redhat) sudo dnf check-update -q || true ;;
    arch)   sudo pacman -Sy --noconfirm ;;
  esac
}

install_core_tools() {
  header "Core tools"
  local tools=()
  cmd_exists git   || tools+=(git)
  cmd_exists curl  || tools+=(curl)
  cmd_exists wget  || tools+=(wget)
  cmd_exists jq    || tools+=(jq)
  cmd_exists unzip || tools+=(unzip)
  if [ ${#tools[@]} -eq 0 ]; then success "All core tools already present"; return; fi
  info "Installing: ${tools[*]}"
  pkg_install "${tools[@]}"
  success "Core tools ready"
}

install_node() {
  header "Node.js (fnm)"
  if cmd_exists fnm; then
    success "fnm already installed"
  else
    info "Installing fnm…"
    if [ "$OS" = "macos" ]; then brew install fnm
    else
      curl -fsSL https://fnm.vercel.app/install | bash
      export PATH="$HOME/.local/share/fnm:$PATH"
      eval "$(fnm env 2>/dev/null)" || true
    fi
    success "fnm installed"
  fi
  if cmd_exists fnm; then
    eval "$(fnm env 2>/dev/null)" || true
    if fnm list 2>/dev/null | grep -q "lts-latest"; then
      success "Node.js LTS already installed"
    else
      info "Installing Node.js LTS…"
      fnm install --lts && fnm use lts-latest
      success "Node.js $(node --version) ready"
    fi
  fi
}

install_python() {
  header "Python (pyenv)"
  if cmd_exists pyenv; then
    success "pyenv already installed"
  else
    info "Installing pyenv…"
    if [ "$OS" = "macos" ]; then brew install pyenv
    else
      case "$OS" in
        debian) pkg_install build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncursesw5-dev xz-utils libffi-dev liblzma-dev ;;
        redhat) pkg_install gcc make openssl-devel bzip2-devel libffi-devel zlib-devel readline-devel sqlite-devel xz-devel ;;
        arch)   pkg_install base-devel openssl zlib xz ;;
      esac
      curl -fsSL https://pyenv.run | bash
    fi
    success "pyenv installed"
  fi
  export PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
  export PATH="$PYENV_ROOT/bin:$PATH"
  eval "$(pyenv init - 2>/dev/null)" || true
  if cmd_exists pyenv; then
    local latest
    latest="$(pyenv install --list 2>/dev/null | grep -E '^\s+3\.[0-9]+\.[0-9]+$' | tail -1 | tr -d ' ')"
    if pyenv versions 2>/dev/null | grep -q "$latest"; then
      success "Python $latest already installed"
    else
      info "Installing Python $latest…"
      pyenv install "$latest" && pyenv global "$latest"
      success "Python $(python3 --version) ready"
    fi
  fi
}

configure_shell() {
  header "Shell configuration"
  local shell_rc
  case "${SHELL:-}" in
    */zsh)  shell_rc="$HOME/.zshrc" ;;
    */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
    *)      shell_rc="$HOME/.bashrc" ;;
  esac
  grep -q 'fnm env' "$shell_rc" 2>/dev/null || printf '\n# fnm (Node.js)\neval "$(fnm env --use-on-cd 2>/dev/null)"\n' >> "$shell_rc"
  grep -q 'pyenv init' "$shell_rc" 2>/dev/null || printf '\n# pyenv (Python)\nexport PYENV_ROOT="$HOME/.pyenv"\nexport PATH="$PYENV_ROOT/bin:$PATH"\neval "$(pyenv init -)"\n' >> "$shell_rc"
  if [ "$OS" != "macos" ]; then
    grep -q 'agentpay' "$shell_rc" 2>/dev/null || printf '\n# agentpay\nexport PATH="$HOME/.agentpay/bin:$PATH"\n' >> "$shell_rc"
    info "agentpay PATH added to $shell_rc"
    # Also add to ~/.profile for login shells that don't source .bashrc/.zshrc
    local profile="$HOME/.profile"
    grep -q 'agentpay' "$profile" 2>/dev/null || printf '\n# agentpay\nexport PATH="$HOME/.agentpay/bin:$PATH"\n' >> "$profile"
  fi
  success "Shell config updated ($shell_rc)"
}

install_rust() {
  if cmd_exists cargo; then success "Rust already installed"; return; fi
  header "Rust"
  info "Installing Rust via rustup…"
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
  success "Rust $(rustc --version) ready"
}

install_agentpay_linux() {
  header "agentpay (Linux)"

  local bin_dir="$HOME/.agentpay/bin"
  if [ -x "$bin_dir/agentpay" ] && [ -x "$bin_dir/agentpay-daemon" ]; then
    success "agentpay already installed"; return
  fi

  # Ensure Rust is available
  install_rust
  source "$HOME/.cargo/env" 2>/dev/null || true

  # Build deps
  case "$OS" in
    debian) pkg_install build-essential pkg-config libssl-dev ;;
    redhat) pkg_install gcc pkg-config openssl-devel ;;
    arch)   pkg_install base-devel pkg-config openssl ;;
  esac

  # Clone into Linux FS to avoid Windows-FS binary corruption
  local src_dir="$HOME/.agentpay-sdk-src"
  if [ -d "$src_dir/.git" ]; then
    info "Updating agentpay-sdk source…"
    git -C "$src_dir" pull --ff-only
  else
    info "Cloning agentpay-sdk into Linux filesystem…"
    git clone --depth=1 https://github.com/worldliberty/agentpay-sdk.git "$src_dir"
  fi

  # Install Node deps and build JS bundle
  info "Building JS bundle…"
  (cd "$src_dir" && pnpm install --frozen-lockfile && pnpm run build)

  # Install CLI launcher and Rust binaries (writes to ~/.agentpay/bin)
  info "Installing CLI launcher and Rust binaries…"
  (cd "$src_dir" && pnpm run install:cli-launcher && pnpm run install:rust-binaries)

  # Fix any CRLF line endings in shell scripts
  for f in "$bin_dir"/*.sh; do
    [ -f "$f" ] && sed -i 's/\r//' "$f"
  done

  success "agentpay installed to $bin_dir"
}

setup_linux_daemon() {
  header "Linux daemon (systemd)"

  # systemd user services require a real login session; skip in containers/CI
  if ! cmd_exists systemctl; then
    warn "systemctl not available — skipping daemon setup"
    warn "Run 'agentpay admin setup' manually after starting a systemd session"
    return
  fi

  local unit_dir="$HOME/.config/systemd/user"
  local unit_file="$unit_dir/agentpay-daemon.service"
  local bin_dir="$HOME/.agentpay/bin"

  mkdir -p "$unit_dir"
  cat > "$unit_file" <<EOF
[Unit]
Description=AgentPay daemon
After=network.target

[Service]
Type=simple
ExecStart=${bin_dir}/agentpay-daemon
Restart=on-failure
RestartSec=5
Environment=AGENTPAY_DAEMON_BIN=${bin_dir}/agentpay-daemon
Environment=AGENTPAY_SIGNER_BACKEND=software

[Install]
WantedBy=default.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable --now agentpay-daemon.service \
    && success "agentpay-daemon systemd user service started" \
    || warn "Could not start systemd user service — run manually: systemctl --user start agentpay-daemon"
}

setup_wallet() {
  header "Wallet setup"
  local wallet_dir="$HOME/.agentpay"
  local wallet_file="$wallet_dir/wallet.json"
  mkdir -p "$wallet_dir/bin"
  if [ -f "$wallet_file" ]; then
    success "Wallet already configured ($wallet_file)"
    return
  fi
  info "Initialising wallet…"
  if cmd_exists agentpay; then
    agentpay admin setup && success "Wallet initialised"
  else
    # Stub wallet file so the PATH entry is meaningful even before agentpay binary is present
    printf '{"version":1,"created":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$wallet_file"
    warn "agentpay binary not found — stub wallet created at $wallet_file"
    warn "Re-run this script or install agentpay manually once it is available"
  fi
}

main() {
  printf "\n${BOLD}${CYAN}wlfi.sh${RESET} ${BOLD}v${VERSION}${RESET} — dev environment bootstrap\n"
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
  detect_os
  info "Detected OS: $OS"
  [ "$OS" = "macos" ] && install_homebrew
  [ "$OS" != "macos" ] && update_pkg_cache
  install_core_tools
  install_node
  install_python
  configure_shell
  if [ "$OS" != "macos" ]; then
    install_agentpay_linux
    setup_linux_daemon
    setup_wallet
  fi
  local shell_rc
  case "${SHELL:-}" in
    */zsh) shell_rc=".zshrc" ;;
    */fish) shell_rc=".config/fish/config.fish" ;;
    *) shell_rc=".bashrc" ;;
  esac
  printf "\n${GREEN}${BOLD}All done!${RESET} Restart your shell or run:  ${CYAN}source ~/%s${RESET}\n\n" "$shell_rc"
}

main "$@"
