#!/usr/bin/env bash
# ================================================================
#                    G R U D A R I N
#                    Updater Script
# ================================================================
#
# Pulls latest changes from the git repository and rebuilds
# all compiled components.
#
# Usage:
#   sudo ./update.sh
#
# ================================================================

set -euo pipefail

GRUDARIN_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER_SRC="$GRUDARIN_DIR/scanner"
NETPROBE_SRC="$GRUDARIN_DIR/netprobe"
SCANNER_BIN="$GRUDARIN_DIR/bin"
VENV_DIR="$GRUDARIN_DIR/gruenv"
LEGACY_VENV_DIR="$GRUDARIN_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}"
echo "    ================================================================"
echo "                          G R U D A R I N"
echo "                        Updater v1.1.8"
echo "    ================================================================"
echo -e "${NC}"
echo -e "  ${CYAN}>> Installed version:${NC} 1.1.8"

# ----------------------------------------------------------------
# Step 1: Check git
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Checking repository${NC}"

if ! command -v git &>/dev/null; then
    echo -e "  ${RED}[fail]${NC}  git not found. Install git first."
    exit 1
fi

cd "$GRUDARIN_DIR"

if [ ! -d ".git" ]; then
    echo -e "  ${YELLOW}[warn]${NC}  Not a git repository."
    echo -e "  ${YELLOW}[warn]${NC}  Manual update: download latest from the repository"
    echo -e "  ${YELLOW}[warn]${NC}  and replace the files, then run install.sh again."
    exit 1
fi

# ----------------------------------------------------------------
# Step 2: Stash local changes
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Saving local changes${NC}"

LOCAL_CHANGES=false
if ! git diff --quiet 2>/dev/null; then
    LOCAL_CHANGES=true
    git stash push -m "grudarin-update-$(date +%Y%m%d_%H%M%S)" 2>/dev/null
    echo -e "  ${GREEN}[ok]${NC}    Local changes stashed"
else
    echo -e "  ${GREEN}[ok]${NC}    No local changes"
fi

# ----------------------------------------------------------------
# Step 3: Pull latest
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Pulling latest changes${NC}"

BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
BEFORE=$(git rev-parse HEAD 2>/dev/null)

git pull origin "$BRANCH" 2>&1 | while IFS= read -r line; do
    echo "          $line"
done

AFTER=$(git rev-parse HEAD 2>/dev/null)

if [ "$BEFORE" = "$AFTER" ]; then
    echo -e "  ${GREEN}[ok]${NC}    Already up to date"
else
    echo -e "  ${GREEN}[ok]${NC}    Updated: ${BEFORE:0:8} -> ${AFTER:0:8}"
    echo ""
    echo -e "  ${CYAN}>> Recent changes:${NC}"
    git log --oneline "$BEFORE..$AFTER" 2>/dev/null | head -10 | while IFS= read -r line; do
        echo "          $line"
    done
    echo ""
    echo -e "  ${CYAN}>> Files changed:${NC}"
    git diff --name-only "$BEFORE" "$AFTER" 2>/dev/null | head -20 | while IFS= read -r line; do
        echo "          $line"
    done
fi

# ----------------------------------------------------------------
# Step 4: Restore local changes
# ----------------------------------------------------------------
if [ "$LOCAL_CHANGES" = true ]; then
    echo -e "  ${CYAN}>> Restoring local changes${NC}"
    git stash pop 2>/dev/null && \
        echo -e "  ${GREEN}[ok]${NC}    Local changes restored" || \
        echo -e "  ${YELLOW}[warn]${NC}  Merge conflict. Check git stash list."
fi

# ----------------------------------------------------------------
# Step 5: Recompile C++ scanner
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Rebuilding C++ scanner${NC}"

mkdir -p "$SCANNER_BIN"

if command -v g++ &>/dev/null; then
    g++ -std=c++17 -O2 -Wall -Wextra -pthread \
        -o "$SCANNER_BIN/grudarin_scanner" \
        "$SCANNER_SRC/scanner.cpp" \
        -lpthread 2>&1 && \
        echo -e "  ${GREEN}[ok]${NC}    Scanner compiled" || \
        echo -e "  ${YELLOW}[warn]${NC}  Scanner compilation failed"
else
    echo -e "  ${YELLOW}[skip]${NC}  g++ not found"
fi

# ----------------------------------------------------------------
# Step 6: Rebuild Go netprobe
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Rebuilding Go netprobe${NC}"

if command -v go &>/dev/null; then
    cd "$NETPROBE_SRC"
    go build -o "$SCANNER_BIN/grudarin_netprobe" netprobe.go 2>&1 && \
        echo -e "  ${GREEN}[ok]${NC}    Netprobe compiled" || \
        echo -e "  ${YELLOW}[warn]${NC}  Netprobe build failed"
    cd "$GRUDARIN_DIR"
else
    echo -e "  ${YELLOW}[skip]${NC}  Go not found"
fi

# ----------------------------------------------------------------
# Step 7: Rebuild Rust probe helper
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Rebuilding Rust probe helper${NC}"

if command -v cargo &>/dev/null; then
    cargo build --release --manifest-path "$GRUDARIN_DIR/rust_tools/grudarin_probe/Cargo.toml" 2>&1 && \
        cp "$GRUDARIN_DIR/rust_tools/grudarin_probe/target/release/grudarin_probe" "$SCANNER_BIN/grudarin_probe" && \
        echo -e "  ${GREEN}[ok]${NC}    Rust probe compiled" || \
        echo -e "  ${YELLOW}[warn]${NC}  Rust probe build failed"
else
    echo -e "  ${YELLOW}[skip]${NC}  Cargo not found"
fi

# ----------------------------------------------------------------
# Step 8: Update Python dependencies
# ----------------------------------------------------------------
echo -e "  ${CYAN}>> Updating Python dependencies${NC}"

if [ -n "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/pip" ]; then
    PIP="$VENV_DIR/bin/pip"
elif [ -f "$LEGACY_VENV_DIR/bin/pip" ]; then
    PIP="$LEGACY_VENV_DIR/bin/pip"
else
    PIP="pip3"
fi

if ! $PIP install --upgrade pip --quiet; then
    echo -e "  ${YELLOW}[warn]${NC}  pip upgrade failed"
fi
if ! $PIP install -r "$GRUDARIN_DIR/requirements.txt" --quiet --upgrade; then
    echo -e "  ${YELLOW}[warn]${NC}  requirements update failed"
fi
if ! $PIP install -e "$GRUDARIN_DIR" --quiet; then
    echo -e "  ${YELLOW}[warn]${NC}  editable install failed"
fi
echo -e "  ${GREEN}[ok]${NC}    Python dependencies updated"

# ----------------------------------------------------------------
# Done
# ----------------------------------------------------------------
echo ""
echo -e "  ${CYAN}>> Upgrade summary${NC}"
echo -e "  ${GREEN}[ok]${NC}    Core version: 1.1.8"
echo -e "  ${GREEN}[ok]${NC}    CLI refreshed"
echo -e "  ${GREEN}[ok]${NC}    Native helpers rebuilt when toolchains were available"
echo ""
echo -e "  ${GREEN}${BOLD}Update complete.${NC}"
echo ""
echo "  Run grudarin to verify:"
echo "    sudo grudarin --list"
echo ""
