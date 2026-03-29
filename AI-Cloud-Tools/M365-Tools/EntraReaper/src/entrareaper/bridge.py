"""
PowerShell bridge for AADInternals.
Executes cmdlets via pwsh subprocess with JSON output parsing.
Uses asyncio.create_subprocess_exec (not shell) to avoid injection.
"""

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("entrareaper.bridge")

# Path to the macOS/.NET Core compatibility layer
COMPAT_SCRIPT = Path(__file__).parent / "compat.ps1"

# PowerShell preamble: load compat shims, import module, suppress progress bars
# Key: compat.ps1 must load FIRST (defines polyfill types for macOS/.NET Core),
# then AADInternals imports with SilentlyContinue (its own Add-Type -AssemblyName
# calls will fail on macOS but the polyfill types are already in memory).
# After import, we verify the module loaded and reset ErrorAction to Stop.
PS_PREAMBLE = f"""
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
. '{COMPAT_SCRIPT}'
$ErrorActionPreference = 'SilentlyContinue'
Import-Module AADInternals 2>$null 3>$null 4>$null 5>$null 6>$null | Out-Null
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'
if (-not (Get-Module AADInternals)) {{ throw 'AADInternals module failed to load' }}
"""

# Timeout for PowerShell commands (seconds)
DEFAULT_TIMEOUT = 120
LONG_TIMEOUT = 600  # For enumeration/spray operations


@dataclass
class PSResult:
    """Result from a PowerShell command execution."""
    success: bool
    data: dict | list | str | None = None
    error: str | None = None
    raw_output: str = ""
    raw_error: str = ""
    command: str = ""
    duration_ms: int = 0


def build_cmdlet_string(cmdlet: str, params: dict | None = None, json_output: bool = True, raw_suffix: str = "") -> str:
    """
    Build a PowerShell command string from cmdlet name and parameters.
    Parameters are sanitized to prevent injection.
    """
    # Validate cmdlet name - must match AADInt cmdlet pattern
    import re
    if not re.match(r'^[A-Za-z]+-AADInt[A-Za-z]+$', cmdlet) and cmdlet not in ("Get-Module", "Get-Command"):
        raise ValueError(f"Invalid cmdlet name: {cmdlet}")

    cmd_parts = [cmdlet]

    if params:
        for key, value in params.items():
            # Validate parameter name
            if not re.match(r'^[A-Za-z][A-Za-z0-9_]*$', key):
                raise ValueError(f"Invalid parameter name: {key}")

            if value is None:
                continue
            if isinstance(value, bool):
                if value:
                    cmd_parts.append(f"-{key}")
            elif isinstance(value, (list, tuple)):
                items = ",".join(f"'{_sanitize_ps_string(str(v))}'" for v in value)
                cmd_parts.append(f"-{key} @({items})")
            elif isinstance(value, (int, float)):
                cmd_parts.append(f"-{key} {value}")
            elif isinstance(value, str):
                cmd_parts.append(f"-{key} '{_sanitize_ps_string(value)}'")
            else:
                cmd_parts.append(f"-{key} '{_sanitize_ps_string(str(value))}'")

    if raw_suffix:
        cmd_parts.append(raw_suffix)

    if json_output:
        cmd_parts.append("| ConvertTo-Json -Depth 10 -Compress")

    return " ".join(cmd_parts)


def _sanitize_ps_string(value: str) -> str:
    """Escape single quotes for PowerShell single-quoted strings."""
    return value.replace("'", "''")


@dataclass
class PSBridge:
    """Manages PowerShell subprocess execution for AADInternals."""

    pwsh_path: str = field(default_factory=lambda: shutil.which("pwsh") or "/usr/local/bin/pwsh")
    module_verified: bool = False

    async def verify_environment(self) -> PSResult:
        """Verify pwsh and AADInternals are available."""
        if not shutil.which(self.pwsh_path):
            return PSResult(
                success=False,
                error=f"PowerShell 7 (pwsh) not found at {self.pwsh_path}. Install: brew install powershell",
            )

        result = await self._run_ps(
            "Get-Module -ListAvailable AADInternals | Select-Object Name, Version | ConvertTo-Json"
        )
        if not result.success:
            return PSResult(
                success=False,
                error="AADInternals module not found. Install: pwsh -c 'Install-Module AADInternals -Scope CurrentUser -Force'",
                raw_error=result.raw_error,
            )

        self.module_verified = True
        return PSResult(success=True, data=result.data, raw_output=result.raw_output)

    async def execute(
        self,
        cmdlet: str,
        params: dict | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        json_output: bool = True,
        raw_suffix: str = "",
    ) -> PSResult:
        """
        Execute an AADInternals cmdlet with parameters.
        All parameters are sanitized before execution.
        Uses create_subprocess_exec (no shell) for safety.
        """
        cmd_str = build_cmdlet_string(cmdlet, params, json_output, raw_suffix)
        full_command = PS_PREAMBLE + "\n" + cmd_str
        logger.debug(f"Executing: {cmdlet} with params {params}")
        return await self._run_ps(full_command, timeout=timeout, label=cmdlet)

    async def execute_script(self, script: str, timeout: int = DEFAULT_TIMEOUT) -> PSResult:
        """Execute a multi-line PowerShell script with AADInternals imported."""
        full_script = PS_PREAMBLE + "\n" + script
        return await self._run_ps(full_script, timeout=timeout, label="script")

    async def _run_ps(self, command: str, timeout: int = DEFAULT_TIMEOUT, label: str = "") -> PSResult:
        """
        Execute PowerShell via create_subprocess_exec (no shell injection).
        The command is passed as a single -Command argument to pwsh.
        """
        import time
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                self.pwsh_path,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration_ms = int((time.monotonic() - start) * 1000)

            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                return PSResult(
                    success=False,
                    error=stderr_str or f"pwsh exited with code {proc.returncode}",
                    raw_output=stdout_str,
                    raw_error=stderr_str,
                    command=label,
                    duration_ms=duration_ms,
                )

            data = _try_parse_json(stdout_str)

            return PSResult(
                success=True,
                data=data,
                raw_output=stdout_str,
                raw_error=stderr_str,
                command=label,
                duration_ms=duration_ms,
            )

        except asyncio.TimeoutError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return PSResult(
                success=False,
                error=f"Command timed out after {timeout}s",
                command=label,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            return PSResult(
                success=False,
                error=f"Execution error: {str(e)}",
                command=label,
                duration_ms=duration_ms,
            )


def _try_parse_json(text: str) -> dict | list | str | None:
    """Attempt to parse JSON from PowerShell output."""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for start_char in ("{", "["):
            idx = text.find(start_char)
            if idx >= 0:
                try:
                    return json.loads(text[idx:])
                except json.JSONDecodeError:
                    continue
        return text
