param([string]$Path)
$logs = Get-Content $Path | ConvertFrom-Json
$failed = $logs | Where-Object { $_.status.errorCode -ne 0 }
Write-Host "Total events: $($logs.Count)"
Write-Host "Failed logins: $($failed.Count)"
# Add more threat hunting logic here
