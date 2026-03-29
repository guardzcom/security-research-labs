# AADInternals MCP Server — Environment Setup
# Run this script in PowerShell 7 (pwsh) on macOS

Write-Host "=== AADInternals MCP Server Setup ===" -ForegroundColor Cyan

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "ERROR: PowerShell 7+ required. Install: brew install powershell" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Green

# Install AADInternals if not present
$module = Get-Module -ListAvailable AADInternals
if (-not $module) {
    Write-Host "Installing AADInternals module..." -ForegroundColor Yellow
    Install-Module AADInternals -Scope CurrentUser -Force -AllowClobber
    $module = Get-Module -ListAvailable AADInternals
}
Write-Host "[OK] AADInternals v$($module.Version)" -ForegroundColor Green

# Verify module loads
try {
    Import-Module AADInternals -ErrorAction Stop
    Write-Host "[OK] Module imports successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to import AADInternals: $_" -ForegroundColor Red
    exit 1
}

# Test basic functionality
try {
    $tid = Get-AADIntTenantId -Domain "microsoft.com"
    Write-Host "[OK] API connectivity verified (microsoft.com tenant: $tid)" -ForegroundColor Green
} catch {
    Write-Host "WARN: API test failed (may be network issue): $_" -ForegroundColor Yellow
}

# List available commands
$commands = Get-Command -Module AADInternals | Measure-Object
Write-Host "[OK] $($commands.Count) cmdlets available" -ForegroundColor Green

Write-Host ""
Write-Host "Setup complete. Add this MCP server to Claude Code:" -ForegroundColor Cyan
Write-Host '  claude mcp add aadinternals -- uv run --directory /path/to/aadinternalsMCP python server.py' -ForegroundColor White
Write-Host ""
