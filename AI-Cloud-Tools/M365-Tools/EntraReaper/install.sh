#!/usr/bin/env bash
#
# EntraReaper Installer
# Checks prerequisites, installs Python dependencies, and optionally
# registers the MCP server in Claude Code.
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  EntraReaper v2.1 Installer${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

ERRORS=0

# ---------------------------------------------------------------
# 1. Check Python 3.11+
# ---------------------------------------------------------------
echo -e "${CYAN}[1/5] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        echo -e "  ${GREEN}OK${NC} Python $PY_VERSION"
    else
        echo -e "  ${RED}FAIL${NC} Python $PY_VERSION found, but 3.11+ required"
        echo "       Install: brew install python@3.12"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC} Python 3 not found"
    echo "       Install: brew install python@3.12"
    ERRORS=$((ERRORS + 1))
fi

# ---------------------------------------------------------------
# 2. Check uv
# ---------------------------------------------------------------
echo -e "${CYAN}[2/5] Checking uv...${NC}"
if command -v uv &>/dev/null; then
    UV_VERSION=$(uv --version 2>&1 | head -1)
    echo -e "  ${GREEN}OK${NC} $UV_VERSION"
else
    echo -e "  ${YELLOW}WARN${NC} uv not found -- installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source the updated PATH
    export PATH="$HOME/.cargo/bin:$PATH"
    if command -v uv &>/dev/null; then
        echo -e "  ${GREEN}OK${NC} uv installed successfully"
    else
        echo -e "  ${RED}FAIL${NC} uv installation failed"
        echo "       Manual install: curl -LsSf https://astral.sh/uv/install.sh | sh"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ---------------------------------------------------------------
# 3. Check PowerShell 7
# ---------------------------------------------------------------
echo -e "${CYAN}[3/5] Checking PowerShell 7...${NC}"
if command -v pwsh &>/dev/null; then
    PWSH_VERSION=$(pwsh -c '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)
    echo -e "  ${GREEN}OK${NC} PowerShell $PWSH_VERSION"
else
    echo -e "  ${RED}FAIL${NC} PowerShell 7 (pwsh) not found"
    echo "       Install: brew install powershell"
    ERRORS=$((ERRORS + 1))
fi

# ---------------------------------------------------------------
# 4. Check AADInternals module
# ---------------------------------------------------------------
echo -e "${CYAN}[4/5] Checking AADInternals module...${NC}"
if command -v pwsh &>/dev/null; then
    AAD_VERSION=$(pwsh -c '
        $ErrorActionPreference = "SilentlyContinue"
        $m = Get-Module -ListAvailable AADInternals 2>$null | Select-Object -First 1
        if ($m) { $m.Version.ToString() } else { "NOT_FOUND" }
    ' 2>/dev/null)
    if [ "$AAD_VERSION" = "NOT_FOUND" ] || [ -z "$AAD_VERSION" ]; then
        echo -e "  ${YELLOW}WARN${NC} AADInternals module not found -- installing..."
        pwsh -c 'Install-Module AADInternals -Scope CurrentUser -Force -AllowClobber' 2>/dev/null
        AAD_VERSION=$(pwsh -c '(Get-Module -ListAvailable AADInternals | Select-Object -First 1).Version.ToString()' 2>/dev/null)
        if [ -n "$AAD_VERSION" ] && [ "$AAD_VERSION" != "NOT_FOUND" ]; then
            echo -e "  ${GREEN}OK${NC} AADInternals $AAD_VERSION installed"
        else
            echo -e "  ${RED}FAIL${NC} AADInternals installation failed"
            echo "       Manual install: pwsh -c 'Install-Module AADInternals -Scope CurrentUser -Force'"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "  ${GREEN}OK${NC} AADInternals $AAD_VERSION"
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} Cannot check AADInternals without PowerShell"
fi

# ---------------------------------------------------------------
# 5. Install Python dependencies
# ---------------------------------------------------------------
echo -e "${CYAN}[5/5] Installing Python dependencies...${NC}"
if command -v uv &>/dev/null; then
    cd "$SCRIPT_DIR"
    uv sync 2>&1 | tail -3
    echo -e "  ${GREEN}OK${NC} Python dependencies installed"
else
    echo -e "  ${RED}FAIL${NC} Cannot install dependencies without uv"
    ERRORS=$((ERRORS + 1))
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}========================================${NC}"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}  All checks passed${NC}"
else
    echo -e "${RED}  $ERRORS check(s) failed${NC}"
    echo -e "  Fix the issues above and re-run install.sh"
    echo ""
    exit 1
fi
echo -e "${CYAN}========================================${NC}"
echo ""

# ---------------------------------------------------------------
# Optional: Register MCP server in Claude Code
# ---------------------------------------------------------------
echo -e "${YELLOW}Register EntraReaper as an MCP server in Claude Code?${NC}"
echo "This runs: claude mcp add entrareaper -- uv run --directory $SCRIPT_DIR python server.py"
echo ""
read -p "Register now? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v claude &>/dev/null; then
        claude mcp add entrareaper -- uv run --directory "$SCRIPT_DIR" python server.py
        echo -e "${GREEN}Registered.${NC} EntraReaper is now available as an MCP server in Claude Code."
    else
        echo -e "${YELLOW}Claude Code CLI not found.${NC} Add manually:"
        echo ""
        echo "  claude mcp add entrareaper -- uv run --directory $SCRIPT_DIR python server.py"
    fi
else
    echo "Skipped. To register later:"
    echo ""
    echo "  claude mcp add entrareaper -- uv run --directory $SCRIPT_DIR python server.py"
fi

# ---------------------------------------------------------------
# Verification
# ---------------------------------------------------------------
echo ""
echo -e "${CYAN}Verification:${NC}"
echo "  Run the server:  cd $SCRIPT_DIR && uv run python server.py"
echo "  Setup check:     pwsh $SCRIPT_DIR/scripts/setup.ps1"
echo ""
echo -e "${GREEN}EntraReaper v2.1 is ready.${NC}"
echo ""
