#    █████████  ███████████ █████ █████ ██████████     █████████  ███████████ █████ ███████████
#   ███░░░░░███░░███░░░░░███░░███░░███ ░░███░░░░░███  ███░░░░░███░░███░░░░░███░░███ ░░███░░░░░███
#   ███     ░░░  ░███    ░███ ░███ ░███  ░███    ░███ ███     ░░░  ░███    ░███ ░███  ░███    ░███
#  ░███          ░██████████  ░███ ░███  ░███    ░███░███████████  ░██████████  ░███  ░███    ░███
#  ░███    █████ ░███░░░░░███ ░███ ░███  ░███    ░███░███░░░░░███  ░███░░░░░███ ░███  ░███    ░███
#  ░░███  ░░███  ░███    ░███ ░███ ░███  ░███    ███ ░███    ░███  ░███    ░███ ░███  ░███    ░███
#   ░░█████████  █████   █████░░████████ ██████████  ░░█████████   █████   ██████████ █████   █████
#    ░░░░░░░░░  ░░░░░   ░░░░░  ░░░░░░░░ ░░░░░░░░░     ░░░░░░░░░   ░░░░░   ░░░░░░░░░ ░░░░░   ░░░░░ 
#
set -euo pipefail

GRUDARIN_DIR="$(cd "$(dirname "$0")" && pwd)"

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
echo "                       Uninstaller v2.0.0"
echo "    ================================================================"
echo -e "${NC}"

echo -e "  ${YELLOW}This will remove Grudarin from your system.${NC}"
echo ""
echo "  The following will be removed:"
echo "    - Compiled binaries (bin/)"
echo "    - Python virtual environment (gruenv/, .venv/)"
echo "    - System symlink (/usr/local/bin/grudarin)"
echo "    - Launcher script (grudarin.sh)"
echo "    - Python package registration"
echo ""
echo "  The following will NOT be removed:"
echo "    - Your scan reports and notes (grudarin_output/)"
echo "    - Source code files"
echo "    - System packages (python3, g++, lua, etc.)"
echo ""
read -p "  Continue with uninstall? [y/N]: " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "  Aborted."
    exit 0
fi

echo ""

# Remove compiled binaries
if [ -d "$GRUDARIN_DIR/bin" ]; then
    rm -rf "$GRUDARIN_DIR/bin"
    echo -e "  ${GREEN}[ok]${NC}    Removed bin/"
fi

# Remove venvs
if [ -d "$GRUDARIN_DIR/gruenv" ]; then
    rm -rf "$GRUDARIN_DIR/gruenv"
    echo -e "  ${GREEN}[ok]${NC}    Removed gruenv/"
fi
if [ -d "$GRUDARIN_DIR/.venv" ]; then
    rm -rf "$GRUDARIN_DIR/.venv"
    echo -e "  ${GREEN}[ok]${NC}    Removed .venv/"
fi

# Remove symlink
if [ -L "/usr/local/bin/grudarin" ]; then
    rm -f "/usr/local/bin/grudarin" 2>/dev/null || true
    echo -e "  ${GREEN}[ok]${NC}    Removed /usr/local/bin/grudarin"
fi

# Remove launcher
if [ -f "$GRUDARIN_DIR/grudarin.sh" ]; then
    rm -f "$GRUDARIN_DIR/grudarin.sh"
    echo -e "  ${GREEN}[ok]${NC}    Removed grudarin.sh"
fi

# Uninstall pip package
pip3 uninstall grudarin -y 2>/dev/null && \
    echo -e "  ${GREEN}[ok]${NC}    Uninstalled pip package" || \
    echo -e "  ${YELLOW}[skip]${NC}  pip package not found"

# Remove pycache
find "$GRUDARIN_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find "$GRUDARIN_DIR" -name "*.pyc" -delete 2>/dev/null
find "$GRUDARIN_DIR" -name "*.egg-info" -exec rm -rf {} + 2>/dev/null
echo -e "  ${GREEN}[ok]${NC}    Cleaned cache files"

echo ""
echo -e "  ${GREEN}${BOLD}Grudarin has been uninstalled.${NC}"
echo ""
echo "  Your scan reports in grudarin_output/ have been preserved."
echo "  To fully remove, delete the grudarin directory:"
echo "    rm -rf $GRUDARIN_DIR"
echo ""
