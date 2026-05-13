#    █████████  ███████████ █████ █████ ██████████     █████████  ███████████ █████ ███████████
#   ███░░░░░███░░███░░░░░███░░███░░███ ░░███░░░░░███  ███░░░░░███░░███░░░░░███░░███ ░░███░░░░░███
#   ███     ░░░  ░███    ░███ ░███ ░███  ░███    ░███ ███     ░░░  ░███    ░███ ░███  ░███    ░███
#  ░███          ░██████████  ░███ ░███  ░███    ░███░███████████  ░██████████  ░███  ░███    ░███
#  ░███    █████ ░███░░░░░███ ░███ ░███  ░███    ░███░███░░░░░███  ░███░░░░░███ ░███  ░███    ░███
#  ░░███  ░░███  ░███    ░███ ░███ ░███  ░███    ███ ░███    ░███  ░███    ░███ ░███  ░███    ░███
#   ░░█████████  █████   █████░░████████ ██████████  ░░█████████   █████   ██████████ █████   █████
#    ░░░░░░░░░  ░░░░░   ░░░░░  ░░░░░░░░ ░░░░░░░░░     ░░░░░░░░░   ░░░░░   ░░░░░░░░░ ░░░░░   ░░░░░ 
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
#
# ================================================================

set -euo pipefail

GRUDARIN_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER_SRC="$GRUDARIN_DIR/scanner"
NETPROBE_SRC="$GRUDARIN_DIR/netprobe"
BIN_DIR="$GRUDARIN_DIR/bin"
LUA_RULES="$GRUDARIN_DIR/lua_rules"
VENV_DIR="$GRUDARIN_DIR/gruenv"
LEGACY_VENV_DIR="$GRUDARIN_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "  ${GREEN}[ok]${NC}    $1"; }
warn()  { echo -e "  ${YELLOW}[warn]${NC}  $1"; }
fail()  { echo -e "  ${RED}[fail]${NC}  $1"; }
step()  { echo ""; echo -e "  ${CYAN}${BOLD}>> $1${NC}"; }

echo ""
echo -e "${CYAN}${BOLD}"
echo "    ================================================================"
echo "                          G R U D A R I N"
echo "                        Installer v2.0.0"
echo "    ================================================================"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. Some steps may fail."
    warn "Re-run with: sudo ./install.sh"
    echo ""
    read -p "  Continue anyway? [y/N]: " confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && exit 1
fi

# Detect OS
step "Detecting system"
OS="unknown"; PKG="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release; OS="$ID"
elif [ "$(uname)" = "Darwin" ]; then
    OS="macos"
fi

case "$OS" in
    ubuntu|debian|kali|parrot|pop|linuxmint|raspbian) PKG="apt" ;;
    fedora|rhel|centos|rocky|alma) PKG="dnf" ;;
    arch|manjaro|endeavouros) PKG="pacman" ;;
    opensuse*|sles) PKG="zypper" ;;
    alpine) PKG="apk" ;;
    macos) PKG="brew" ;;
esac
info "OS: $OS (pkg: $PKG)"

# Install system deps
step "Installing system dependencies"
case "$PKG" in
    apt)
        apt-get update -qq 2>/dev/null
        apt-get install -y -qq \
            python3 python3-pip python3-venv python3-dev \
            g++ make cmake libpcap-dev \
            lua5.4 liblua5.4-dev \
            net-tools wireless-tools iw \
            libsdl2-dev tcpdump golang-go 2>/dev/null || true
        info "APT packages installed" ;;
    dnf)
        dnf install -y -q \
            python3 python3-pip python3-devel \
            gcc-c++ make cmake libpcap-devel \
            lua lua-devel net-tools wireless-tools iw \
            SDL2-devel tcpdump golang 2>/dev/null || true
        info "DNF packages installed" ;;
    pacman)
        pacman -Sy --noconfirm --needed \
            python python-pip gcc make cmake libpcap lua \
            net-tools iw sdl2 tcpdump go 2>/dev/null || true
        info "Pacman packages installed" ;;
    brew)
        brew install python3 libpcap lua sdl2 cmake go 2>/dev/null || true
        info "Homebrew packages installed" ;;
    apk)
        apk add --no-cache \
            python3 py3-pip python3-dev g++ make cmake \
            libpcap-dev lua5.4 lua5.4-dev \
            sdl2-dev tcpdump go 2>/dev/null || true
        info "APK packages installed" ;;
    *)
        warn "Unknown package manager. Install dependencies manually." ;;
esac

# Compile C++ scanner
step "Compiling C++ port scanner"
mkdir -p "$BIN_DIR"
if command -v g++ &>/dev/null; then
    g++ -std=c++17 -O2 -Wall -Wextra -pthread \
        -o "$BIN_DIR/grudarin_scanner" \
        "$SCANNER_SRC/scanner.cpp" \
        -lpthread 2>&1 && \
        info "Scanner compiled: $BIN_DIR/grudarin_scanner" || \
        fail "Scanner compilation failed"
else
    warn "g++ not found. Install with: apt install g++"
fi

# Build Go netprobe
step "Building Go network probe"
if command -v go &>/dev/null; then
    cd "$NETPROBE_SRC"
    go build -o "$BIN_DIR/grudarin_netprobe" netprobe.go 2>&1 && \
        info "Netprobe compiled: $BIN_DIR/grudarin_netprobe" || \
        warn "Go build failed"
    cd "$GRUDARIN_DIR"
else
    warn "Go not found. Netprobe will use Python fallback."
fi

# Build Rust probe helper
step "Building Rust site probe helper"
if command -v cargo &>/dev/null; then
    cargo build --release --manifest-path "$GRUDARIN_DIR/rust_tools/grudarin_probe/Cargo.toml" 2>&1 && \
        cp "$GRUDARIN_DIR/rust_tools/grudarin_probe/target/release/grudarin_probe" "$BIN_DIR/grudarin_probe" && \
        info "Rust probe compiled: $BIN_DIR/grudarin_probe" || \
        warn "Rust build failed"
else
    warn "Cargo not found. Rust probe helper will be skipped."
fi

# Python env
step "Setting up Python environment"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR" 2>/dev/null || { warn "Failed to create gruenv, using system Python"; VENV_DIR=""; }
fi

if [ -n "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/pip" ]; then
    PIP="$VENV_DIR/bin/pip"
elif [ -f "$LEGACY_VENV_DIR/bin/pip" ]; then
    warn "Using legacy .venv (gruenv not available)"
    VENV_DIR="$LEGACY_VENV_DIR"
    PIP="$LEGACY_VENV_DIR/bin/pip"
else
    PIP="pip3"
fi

if ! $PIP install --upgrade pip --quiet; then
    fail "Failed to upgrade pip"
    exit 1
fi
if ! $PIP install -r "$GRUDARIN_DIR/requirements.txt" --quiet; then
    fail "Failed to install Python requirements"
    exit 1
fi
if ! $PIP install -e "$GRUDARIN_DIR" --quiet; then
    warn "Editable install failed, continuing with direct module execution"
fi
info "Python dependencies installed"

# Lua check
step "Checking Lua rules engine"
if command -v lua5.4 &>/dev/null; then
    info "Lua 5.4 available"
elif command -v lua &>/dev/null; then
    info "Lua available"
else
    warn "Lua not found. Rules engine will use Python fallback."
fi

# Launcher
step "Creating launcher"
cat > "$GRUDARIN_DIR/grudarin.sh" << 'LAUNCHER'
#!/usr/bin/env bash
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    TARGET="$(readlink "$SOURCE")"
    if [ "${TARGET#/}" = "$TARGET" ]; then
        SOURCE="$DIR/$TARGET"
    else
        SOURCE="$TARGET"
    fi
done
DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

if [ -f "$DIR/gruenv/bin/python" ]; then
    GRUENV="$DIR/gruenv"
elif [ -f "$DIR/.venv/bin/python" ]; then
    GRUENV="$DIR/.venv"
else
    GRUENV=""
fi

if [ -n "$GRUENV" ]; then
    # Process-scoped activation: environment exists only while grudarin runs.
    export VIRTUAL_ENV="$GRUENV"
    export PATH="$GRUENV/bin:$PATH"
    export PYTHONNOUSERSITE=1
    PY="$GRUENV/bin/python"
else
    PY="python3"
fi

RUN_CODE="import runpy, sys; sys.path.insert(0, '$DIR'); sys.argv[0] = 'grudarin'; runpy.run_module('grudarin', run_name='__main__')"

if [ "$EUID" -ne 0 ]; then
    exec sudo "$PY" -c "$RUN_CODE" "$@"
else
    exec "$PY" -c "$RUN_CODE" "$@"
fi
LAUNCHER
chmod +x "$GRUDARIN_DIR/grudarin.sh"
info "Launcher: $GRUDARIN_DIR/grudarin.sh"

if [ "$EUID" -eq 0 ]; then
    ln -sf "$GRUDARIN_DIR/grudarin.sh" /usr/local/bin/grudarin 2>/dev/null || true
    info "Symlink: /usr/local/bin/grudarin"
fi

# Verify
step "Verifying installation"
errs=0
command -v python3 &>/dev/null && info "Python3: $(python3 --version)" || { fail "Python3 missing"; errs=$((errs+1)); }
[ -x "$BIN_DIR/grudarin_scanner" ] && info "C++ Scanner: ready" || warn "C++ Scanner: not available"
[ -x "$BIN_DIR/grudarin_netprobe" ] && info "Go Netprobe: ready" || warn "Go Netprobe: not available"
(command -v lua5.4 || command -v lua) &>/dev/null && info "Lua: ready" || warn "Lua: not available"
[ -x "$GRUDARIN_DIR/check.sh" ] && info "Health Check: ready (./check.sh)" || warn "Health Check: missing"

echo ""
if [ $errs -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}Installation complete.${NC}"
else
    echo -e "  ${YELLOW}${BOLD}Installed with $errs issue(s).${NC}"
fi
echo ""
echo "  Usage:"
echo "    sudo grudarin --list"
echo "    sudo grudarin --scan wlan0"
echo "    sudo grudarin --scan eth0 -o ~/reports --name home_scan"
echo "    ./check.sh"
echo "    grudarin --help"
echo ""
