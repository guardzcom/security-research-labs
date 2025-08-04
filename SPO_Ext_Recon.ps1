# SharePoint Online Recon v1.1
# 
# Description:
#   1. Automates reconnaissance of SharePoint Online and OneDrive for Business sites to identify exposed or misconfigured resources.
#   2. Enumerates common business, engineering, collaboration, and admin site paths, including potential test, public, and partner/client exposures.
#   3. Checks for anonymous access, metadata API exposure, and shared document visibility.
#   4. Designed for red team, blue team, and DFIR use in hybrid and cloud environments.
#
# WARNING:
#   - Legal Notice: Use this script only on assets you own or have explicit permission to test. Unauthorized use may violate laws and organizational policies.
#   - Operational Risk: Recon modules may trigger alerts or rate limits. Always coordinate with stakeholders and follow change management protocols.
#   - Data Sensitivity: Output may contain sensitive information. Handle results per your organization’s data classification and retention policies.
#
# Usage:
#   1. Edit $domain and $onedriveDomain to match your target tenant.
#   2. Optionally, add usernames to $usernames for OneDrive checks.
#   3. Run in PowerShell 5.1+ (Windows, macOS, or Linux with PowerShell Core).
#   4. Results are saved to Exposed_SharePoint_Sites.txt.
#
# ----------------------------------------------------------------------

$domain = "demo.sharepoint.com"
$onedriveDomain = "demo-my.sharepoint.com"

$paths = @(
    # Business units
   "sites/hr", "sites/finance", "sites/legal", "sites/sales", "sites/marketing", "sites/operations", "sites/security", "sites/support",


   # Engineering and dev
   "sites/engineering", "sites/dev", "sites/devops", "sites/qa", "sites/test", "sites/rd", "sites/research", "sites/code",


   # Collaboration and projects
   "sites/projects", "sites/collaboration", "sites/innovation", "sites/internal", "sites/teamspace", "sites/initiatives",


   # IT & Infrastructure
   "sites/it", "sites/infrastructure", "sites/tools", "sites/automation", "sites/scripts", "sites/platforms",


   # M365 / Teams defaults
   "teams/marketing", "teams/hr", "teams/finance", "teams/engineering", "teams/product", "teams/devops", "teams/sales", "teams/security", "teams/rd",


   # Public/external
   "sites/public", "sites/guest", "sites/community", "sites/press", "sites/media", "sites/events",


   # Misconfig or leftover test
   "sites/demo", "sites/DemoSite", "sites/temp", "sites/migration", "sites/poc", "sites/old", "sites/archive", "sites/backup", "sites/beta", "sites/junk", "sites/testsite1", "sites/testsite2",


   # Admin or sensitive by role
   "sites/compliance", "sites/ciso", "sites/legalhold", "sites/investigation", "sites/audit", "sites/legalarchive",


   # Partner or client exposure
   "sites/partners", "sites/vendors", "sites/external", "sites/customer", "sites/resellers", "sites/clients"


)


# Optional personal OneDrive users
$usernames = @("elli", "moshe", "ron")


foreach ($user in $usernames) {
   $encoded = $user -replace "\.", "_"
   $paths += "personal/${encoded}_demospo_com"
}


$headers = @{
   "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShellRecon/2.0"
}


$outputFile = "Exposed_SharePoint_Sites.txt"
if (Test-Path $outputFile) { Remove-Item $outputFile }


function Test-Url {
   param (
       [string]$url,
       [string]$type
   )


   try {
       $res = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers $headers -TimeoutSec 5
       if ($res.StatusCode -eq 200) {
           Write-Host "[+] $type{}: $url" -ForegroundColor Green
           Add-Content -Path $outputFile -Value "$type{}: $url"


           if ($res.Content -match "SharePoint" -or $res.RawContent -match "SPClient") {
               # Check metadata API
               $metaEndpoints = @("_api/site", "_api/web", "_api/web/title", "_api/web/lists")
               foreach ($api in $metaEndpoints) {
                   try {
                       $metaUrl = "$url/$api"
                       $meta = Invoke-WebRequest -Uri $metaUrl -Headers $headers -UseBasicParsing -TimeoutSec 5
                       if ($meta.StatusCode -eq 200) {
                           Write-Host "    [i] Metadata exposed: $api" -ForegroundColor Yellow
                       }
                   } catch {}
               }


               # Shared Documents test
               $sharedUrl = "$url/_layouts/15/start.aspx#/Shared%20Documents/Forms/AllItems.aspx"
               try {
                   $docRes = Invoke-WebRequest -Uri $sharedUrl -Headers $headers -UseBasicParsing -TimeoutSec 5
                   if ($docRes.StatusCode -eq 200) {
                       Write-Host "    [!] Shared Docs are anonymously visible" -ForegroundColor Magenta
                   }
               } catch {}
           }
       } elseif ($res.StatusCode -in 301, 302) {
           Write-Host "[>] Redirected: $url -> $($res.Headers.Location)" -ForegroundColor Cyan
       }
   } catch {
       Write-Host "[-] Not accessible: $url" -ForegroundColor DarkGray
   }
}


# Scan each path
foreach ($path in $paths) {
   if ($path.StartsWith("personal/")) {
       $url = "https://$onedriveDomain/$path"
       Test-Url -url $url -type "OneDrive"
   } else {
       $url = "https://$domain/$path"
       Test-Url -url $url -type "SharePoint"
   }
}


Write-Host "`n[+] Scan completed. Results saved to: $outputFile" -ForegroundColor Cyan


