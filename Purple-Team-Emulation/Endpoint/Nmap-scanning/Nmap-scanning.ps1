# Nmap Detection Rule Validation 
# Simulates nmap process creation patterns to test detection logic


$testDir = "$env:TEMP\s1-validation"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

# Create a benign dummy executable disguised as nmap
# Using a simple .NET console app compiled on the fly
$nmapSimSource = @"
using System;
namespace NmapSim {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("S1 Detection Validation - Not real nmap");
            Console.WriteLine("Args: " + String.Join(" ", args));
            System.Threading.Thread.Sleep(2000);
        }
    }
}
"@

$nmapExePath = "$testDir\nmap.exe"
Add-Type -TypeDefinition $nmapSimSource -OutputAssembly $nmapExePath -OutputType ConsoleApplication -ErrorAction Stop

# Define test cases matching the DV query logic
$testCases = @(
    @{
        Name = "SYN Scan Simulation"
        Args = "-sS -p 80,443 192.168.1.0/24"
        ShouldTrigger = $true
    },
    @{
        Name = "OS Detection Simulation"
        Args = "-sV -O -p 1-1000 10.0.0.1"
        ShouldTrigger = $true
    },
    @{
        Name = "Output to File Simulation"
        Args = "-sT -oN scan_results.txt -p 22,80,443 172.16.0.0/16"
        ShouldTrigger = $true
    },
    @{
        Name = "Aggressive Scan Simulation"
        Args = "-sS -sV -n -p- -iL targets.txt"
        ShouldTrigger = $true
    },
    @{
        Name = "UDP Scan Simulation"
        Args = "-sU -p 53,161,500 10.10.10.0/24"
        ShouldTrigger = $true
    },
    @{
        Name = "No Matching Flags - Should Not Trigger"
        Args = "--help"
        ShouldTrigger = $false
    }
)

Write-Host "`n=== S1 Nmap Detection Rule Validation ===" -ForegroundColor Cyan
Write-Host "Executing as: $env:USERDOMAIN\$env:USERNAME"
Write-Host "Target rule: Process Creation where nmap.exe with scan flags, non-SYSTEM context`n"

# Validate we are NOT running as SYSTEM (matches the exclusion in the rule)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$excludedUsers = @('SYSTEM', 'AUTORITE NT', 'SISTEMA')
$isExcluded = $excludedUsers | Where-Object { $currentUser -match $_ }

if ($isExcluded) {
    Write-Warning "Running as $currentUser - this context is EXCLUDED by the detection rule"
    Write-Warning "Run as a standard user to properly validate detection"
    exit 1
}

$results = @()

foreach ($test in $testCases) {
    Write-Host "[$($test.Name)]" -ForegroundColor Yellow
    Write-Host "  Command: nmap.exe $($test.Args)"
    Write-Host "  Expected trigger: $($test.ShouldTrigger)"

    try {
        $proc = Start-Process -FilePath $nmapExePath `
                              -ArgumentList $test.Args `
                              -PassThru `
                              -NoNewWindow `
                              -Wait

        Write-Host "  PID: $($proc.Id) | Exit: $($proc.ExitCode)" -ForegroundColor Green

        $results += [PSCustomObject]@{
            TestCase       = $test.Name
            CommandLine    = "nmap.exe $($test.Args)"
            PID            = $proc.Id
            User           = $currentUser
            ShouldTrigger  = $test.ShouldTrigger
            Executed       = $true
        }
    } catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
        $results += [PSCustomObject]@{
            TestCase       = $test.Name
            CommandLine    = "nmap.exe $($test.Args)"
            PID            = "N/A"
            User           = $currentUser
            ShouldTrigger  = $test.ShouldTrigger
            Executed       = $false
        }
    }

    Write-Host ""
    Start-Sleep -Seconds 1
}

# Summary
Write-Host "=== Validation Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# DV Query to verify detections
Write-Host "=== S1 Deep Visibility Verification Query ===" -ForegroundColor Cyan
Write-Host @"

dataSource.name = 'SentinelOne'
AND event.type = 'Process Creation'
AND tgt.process.name = 'nmap.exe'
AND tgt.process.cmdline containsAny ('-s', '-o', '-n', '-p', '-i')
AND tgt.process.user NOT IN ('NT AUTHORITY\SYSTEM', 'AUTORITE NT\SISTEMA')
AND event.time > 'now-1h'

"@ -ForegroundColor Gray

# Cleanup
Write-Host "Cleaning up test artifacts..." -ForegroundColor DarkGray
Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Done. Check S1 console for triggered alerts.`n" -ForegroundColor Green
