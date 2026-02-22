<#
.SYNOPSIS
    Scan skill files and URLs for malicious patterns.

.DESCRIPTION
    PowerShell wrapper for skillscan.py. Detects prompt injection, malware
    delivery, code execution, suspicious URLs, encoded content, and suspicious
    skill metadata in skill definition files.

.EXAMPLE
    skillscan scan file skill.md
    skillscan scan url https://playbooks.com/skills/openclaw/skills/reddit-trends --strip-html
    skillscan scan dir .\skills\ --pattern "*.md"
    skillscan rules
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PythonScript = Join-Path $ScriptDir "skillscan.py"

if (-not (Test-Path $PythonScript)) {
    Write-Error "skillscan.py not found at $PythonScript"
    exit 1
}

# Find python - try python3 first, then python
$Python = $null
foreach ($cmd in @("python3", "python")) {
    $Python = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($Python) { break }
}

if (-not $Python) {
    Write-Error "Python not found. Install Python 3 and ensure it is on your PATH."
    exit 1
}

& $Python.Source $PythonScript @args
exit $LASTEXITCODE
