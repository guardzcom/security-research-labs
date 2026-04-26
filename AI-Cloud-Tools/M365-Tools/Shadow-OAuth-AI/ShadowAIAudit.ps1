<#
.SYNOPSIS
    Shadow AI - 10-check audit of AI agents and OAuth AI tools in M365.

.DESCRIPTION
    Runs ten independent risk checks against every AI-named service principal in
    a Microsoft 365 tenant via Microsoft Graph (read-only). Aggregates findings
    per app into a composite risk score, builds a self-contained HTML dashboard
    with charts, severity tiles, and per-check breakdowns, and auto-opens it.

    The 10 checks:
      1. AI Vendor App Inventory                  (baseline)
      2. Critical Graph Scopes                    (Mail/Files/Sites/Directory)
      3. Application (App-Only) Permissions       (no user-in-the-loop)
      4. Tenant-Wide Admin Consent                (consentType=AllPrincipals)
      5. Unverified Publisher                     (no MPN attestation)
      6. Recently Added (<RecentDays)             (supply-chain window)
      7. Multi-Tenant App Reach                   (cross-tenant pivot risk)
      8. Directory Role Assignments to App        (Entra privesc)
      9. Risky Redirect URIs                      (http/localhost/dangling)
     10. Multiple App Credentials                 (persistence pattern)

.PARAMETER TenantId
    UPN suffix or GUID. Omit for interactive default-tenant sign-in.

.PARAMETER OutputFolder
    Parent folder under which a timestamped audit folder is created.
    Defaults to the script's own folder ($PSScriptRoot), falling back to the
    current location if the script is dot-sourced from a pipeline.

.PARAMETER RecentDays
    Window for check #6 (default: 30).

.PARAMETER NoOpen
    Suppress auto-open of the HTML report.

.EXAMPLE
    .\Scan-ShadowAI-Comprehensive.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Scan-ShadowAI-Comprehensive.ps1 -OutputFolder C:\Audits\Contoso
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }),
    [int]$RecentDays = 30,
    [switch]$NoOpen
)

# Build a single timestamped audit folder; HTML + every CSV land inside it
$timestamp   = Get-Date -Format yyyyMMdd-HHmm
$auditFolder = Join-Path $OutputFolder "shadow-ai-audit-$timestamp"
if (-not (Test-Path $auditFolder)) { New-Item -ItemType Directory -Path $auditFolder -Force | Out-Null }
$auditFolder = (Resolve-Path $auditFolder).Path
$OutFile     = Join-Path $auditFolder "shadow-ai.html"

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ─── 1. Module bootstrap ─────────────────────────────────────────────────────
$NeedMods = 'Microsoft.Graph.Authentication','Microsoft.Graph.Applications','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.DirectoryManagement'
foreach ($m in $NeedMods) {
    if (-not (Get-Module -ListAvailable $m)) {
        Write-Host "[*] Installing $m..." -ForegroundColor Yellow
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $m -ErrorAction Stop
}

# ─── 2. AI vendor regex + risk catalogs ──────────────────────────────────────
$AiPatterns = 'claude|anthropic|openai|gpt|chatgpt|copilot|gemini|bard|' +
              'perplexity|mistral|cohere|huggingface|replicate|mcp|rogueai|' +
              'cursor|aider|opencode|codeium|tabnine|cody|sourcegraph|' +
              'langchain|llamaindex|devin|crewai|autogen|autogpt|babyagi|' +
              'metagpt|granola|notion ai|elevenlabs|deepseek|qwen|tongyi|' +
              'glean|writer\.com|jasper|character\.ai|inflection|pi\.ai|' +
              'grok|xai|stability|midjourney|runway|synthesia|otter|' +
              'fireflies|read\.ai|tldv|fathom|krisp|mem\.ai|reflect|' +
              'agent|llm|\bai\b|\bml\b'

$CriticalScopes = @(
    'Mail.Read','Mail.ReadWrite','Mail.Send','Mail.Read.Shared',
    'Files.Read.All','Files.ReadWrite.All',
    'Calendars.Read','Calendars.ReadWrite',
    'Sites.Read.All','Sites.FullControl.All','Sites.Manage.All',
    'User.Read.All','User.ReadWrite.All',
    'Directory.Read.All','Directory.ReadWrite.All',
    'Group.Read.All','Group.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All','RoleManagement.ReadWrite.Directory',
    'ChannelMessage.Read.All','Chat.Read.All','OnlineMeetings.Read.All',
    'AuditLog.Read.All','SecurityEvents.Read.All'
)

$SeverityWeight = @{ 'CRITICAL' = 40; 'HIGH' = 20; 'MEDIUM' = 8; 'LOW' = 2 }

# ─── 3. Connect ──────────────────────────────────────────────────────────────
$Scopes = 'Application.Read.All','Directory.Read.All','DelegatedPermissionGrant.Read.All','RoleManagement.Read.Directory'
if ($TenantId) { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome }
else           { Connect-MgGraph                      -Scopes $Scopes -NoWelcome }
$ctx = Get-MgContext
Write-Host "[*] Connected: tenant=$($ctx.TenantId) account=$($ctx.Account)" -ForegroundColor Cyan

# ─── 4. Pull data ONCE into in-memory caches ─────────────────────────────────
Write-Host "[*] Pulling service principals (30-90s on large tenants)..." -ForegroundColor Cyan
$AllSps = Get-MgServicePrincipal -All -Property `
    Id,AppId,DisplayName,PublisherName,VerifiedPublisher,AppRoles,Tags,CreatedDateTime,`
    SignInAudience,ServicePrincipalType,ReplyUrls,KeyCredentials,PasswordCredentials,AppOwnerOrganizationId

$AiSps = $AllSps | Where-Object { $_.DisplayName -match $AiPatterns }
Write-Host "[+] $($AiSps.Count) AI-named service principals matched (out of $($AllSps.Count) total)" -ForegroundColor Green

Write-Host "[*] Pulling OAuth2 permission grants..." -ForegroundColor Cyan
$AllGrants = Get-MgOauth2PermissionGrant -All

Write-Host "[*] Pulling app role assignments per AI app..." -ForegroundColor Cyan
$RoleAssignmentsByApp = @{}
$ResourceSpCache = @{}
foreach ($sp in $AiSps) {
    $RoleAssignmentsByApp[$sp.Id] = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
}

Write-Host "[*] Pulling directory role memberships..." -ForegroundColor Cyan
$DirRoles    = Get-MgDirectoryRole -All
$DirRoleMembersByApp = @{}
foreach ($r in $DirRoles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All -ErrorAction SilentlyContinue
    foreach ($m in $members) {
        if ($m.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.servicePrincipal') {
            if (-not $DirRoleMembersByApp.ContainsKey($m.Id)) { $DirRoleMembersByApp[$m.Id] = @() }
            $DirRoleMembersByApp[$m.Id] += $r.DisplayName
        }
    }
}

# ─── 5. Helper: scope resolution ─────────────────────────────────────────────
function Resolve-AppRoleValue {
    param([string]$ResourceId,[string]$AppRoleId)
    if (-not $ResourceSpCache.ContainsKey($ResourceId)) {
        $ResourceSpCache[$ResourceId] = Get-MgServicePrincipal -ServicePrincipalId $ResourceId -ErrorAction SilentlyContinue
    }
    $rsp = $ResourceSpCache[$ResourceId]
    if ($rsp) { ($rsp.AppRoles | Where-Object Id -eq $AppRoleId).Value }
}

# ─── 6. Run the 10 checks ────────────────────────────────────────────────────
$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param($CheckId,$CheckName,$Severity,$Sp,$Detail,$Evidence)
    $Findings.Add([pscustomobject]@{
        CheckId     = $CheckId
        CheckName   = $CheckName
        Severity    = $Severity
        AppId       = $Sp.AppId
        DisplayName = $Sp.DisplayName
        Publisher   = $Sp.PublisherName
        Detail      = $Detail
        Evidence    = $Evidence
        Score       = $SeverityWeight[$Severity]
    })
}

$now = Get-Date
$recentCutoff = $now.AddDays(-$RecentDays)

foreach ($sp in $AiSps) {

    # CHECK 1 - Inventory baseline (every AI app counts as LOW)
    Add-Finding 'C01' 'AI Vendor App Inventory' 'LOW' $sp `
        "Detected AI-named service principal" "DisplayName=$($sp.DisplayName)"

    # Build unified scope set (delegated + app-only)
    $delegated = $AllGrants | Where-Object { $_.ClientId -eq $sp.Id }
    $appRoles  = $RoleAssignmentsByApp[$sp.Id]

    $delegatedScopes = @(); $appRoleScopes = @()
    $delegated | ForEach-Object { $delegatedScopes += ($_.Scope -split '\s+') }
    $appRoles  | ForEach-Object {
        $v = Resolve-AppRoleValue -ResourceId $_.ResourceId -AppRoleId $_.AppRoleId
        if ($v) { $appRoleScopes += $v }
    }
    $delegatedScopes = $delegatedScopes | Where-Object { $_ } | Sort-Object -Unique
    $appRoleScopes   = $appRoleScopes   | Where-Object { $_ } | Sort-Object -Unique
    $allScopes       = ($delegatedScopes + $appRoleScopes) | Sort-Object -Unique

    # CHECK 2 - Critical Graph scopes
    $crit = $allScopes | Where-Object { $_ -in $CriticalScopes }
    if ($crit) {
        $sev = if ($crit.Count -ge 3) { 'CRITICAL' } elseif ($crit.Count -ge 1) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C02' 'Critical Graph Scopes' $sev $sp `
            "$($crit.Count) critical scope(s) granted" "Scopes: $($crit -join ', ')"
    }

    # CHECK 3 - Application (app-only) permissions
    if ($appRoleScopes.Count -gt 0) {
        $appCrit = $appRoleScopes | Where-Object { $_ -in $CriticalScopes }
        $sev = if ($appCrit.Count -ge 1) { 'CRITICAL' } else { 'HIGH' }
        Add-Finding 'C03' 'Application (App-Only) Permissions' $sev $sp `
            "$($appRoleScopes.Count) app-role permission(s) - runs without user" "AppRoles: $($appRoleScopes -join ', ')"
    }

    # CHECK 4 - Tenant-wide admin consent
    $tenantWide = $delegated | Where-Object { $_.ConsentType -eq 'AllPrincipals' }
    if ($tenantWide) {
        $tenantWideScopes = ($tenantWide.Scope -split '\s+') | Sort-Object -Unique
        $hasCrit = $tenantWideScopes | Where-Object { $_ -in $CriticalScopes }
        $sev = if ($hasCrit) { 'CRITICAL' } else { 'HIGH' }
        Add-Finding 'C04' 'Tenant-Wide Admin Consent' $sev $sp `
            "Admin-consented for ALL users in tenant" "Scopes: $($tenantWideScopes -join ', ')"
    }

    # CHECK 5 - Unverified publisher
    $verified = [bool]$sp.VerifiedPublisher.VerifiedPublisherId
    if (-not $verified) {
        $sev = if ($crit) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C05' 'Unverified Publisher' $sev $sp `
            "Publisher not MPN-verified" "Publisher='$($sp.PublisherName)' AppOwnerOrgId=$($sp.AppOwnerOrganizationId)"
    }

    # CHECK 6 - Recently added
    if ($sp.CreatedDateTime -and $sp.CreatedDateTime -gt $recentCutoff) {
        $age = [int]($now - $sp.CreatedDateTime).TotalDays
        $sev = if ($crit -or $appRoleScopes.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C06' "Recently Added (<$RecentDays days)" $sev $sp `
            "Service principal created $age day(s) ago" "Created=$($sp.CreatedDateTime.ToString('yyyy-MM-dd HH:mm UTC'))"
    }

    # CHECK 7 - Multi-tenant reach
    if ($sp.SignInAudience -in 'AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount') {
        $sev = if ($crit) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C07' 'Multi-Tenant App Reach' $sev $sp `
            "App accepts cross-tenant authentication" "SignInAudience=$($sp.SignInAudience)"
    }

    # CHECK 8 - Directory role assignments to the app
    if ($DirRoleMembersByApp.ContainsKey($sp.Id)) {
        $roles = $DirRoleMembersByApp[$sp.Id]
        Add-Finding 'C08' 'Directory Role Assignments' 'CRITICAL' $sp `
            "Service principal holds $($roles.Count) Entra directory role(s)" "Roles: $($roles -join ', ')"
    }

    # CHECK 9 - Risky redirect URIs
    $risky = @()
    foreach ($url in $sp.ReplyUrls) {
        if ($url -match '^http://(?!localhost)' -or
            $url -match 'localhost|127\.0\.0\.1|0\.0\.0\.0' -or
            $url -match '\.ngrok\.|\.serveo\.|\.loca\.lt|\.tunnelmole\.|trycloudflare') {
            $risky += $url
        }
    }
    if ($risky) {
        $sev = if ($risky -match '^http://(?!localhost)') { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C09' 'Risky Redirect URIs' $sev $sp `
            "$($risky.Count) redirect URI(s) flagged" "URIs: $($risky -join ' | ')"
    }

    # CHECK 10 - Multiple credentials (persistence pattern)
    $secretCount = ($sp.PasswordCredentials | Measure-Object).Count
    $certCount   = ($sp.KeyCredentials      | Measure-Object).Count
    $totalCreds  = $secretCount + $certCount
    if ($totalCreds -ge 2) {
        $sev = if ($totalCreds -ge 4) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding 'C10' 'Multiple App Credentials' $sev $sp `
            "$totalCreds credential(s) attached - possible persistence" "Secrets=$secretCount Certs=$certCount"
    }
}

# ─── 7. Per-app composite risk roll-up ───────────────────────────────────────
$AppRollup = $Findings | Group-Object AppId | ForEach-Object {
    $a = $_.Group[0]
    $score = ($_.Group | Measure-Object Score -Sum).Sum
    $maxSev = ($_.Group | Sort-Object @{e={$SeverityWeight[$_.Severity]};desc=$true} | Select-Object -First 1).Severity
    $checks = ($_.Group.CheckId | Sort-Object -Unique)
    [pscustomobject]@{
        AppId        = $a.AppId
        DisplayName  = $a.DisplayName
        Publisher    = $a.Publisher
        Score        = $score
        MaxSeverity  = $maxSev
        ChecksHit    = $checks.Count
        CheckIds     = ($checks -join ',')
    }
} | Sort-Object Score -Descending

# ─── 7b. Build per-check summary (used by CSV + HTML) ────────────────────────
$checkSummary = 1..10 | ForEach-Object {
    $id = "C{0:D2}" -f $_
    $hits = $Findings | Where-Object CheckId -eq $id
    $name = if ($hits) { $hits[0].CheckName } else {
        switch ($id) {
            'C01' {'AI Vendor App Inventory'}     'C02' {'Critical Graph Scopes'}
            'C03' {'Application (App-Only) Permissions'} 'C04' {'Tenant-Wide Admin Consent'}
            'C05' {'Unverified Publisher'}        'C06' {"Recently Added (<$RecentDays days)"}
            'C07' {'Multi-Tenant App Reach'}      'C08' {'Directory Role Assignments'}
            'C09' {'Risky Redirect URIs'}         'C10' {'Multiple App Credentials'}
        }
    }
    [pscustomobject]@{ Id=$id; Name=$name; Hits=$hits.Count; Findings=$hits }
}

# ─── 7c. CSV exports - one file per "sheet" (check) + summary + rollup ───────
# CSVs land flat inside the same audit folder as the HTML
$csvFolder = $auditFolder

# Sheet 1: Summary (one row per check)
$summaryRows = $checkSummary | ForEach-Object {
    [pscustomobject]@{
        CheckId    = $_.Id
        CheckName  = $_.Name
        Findings   = $_.Hits
        Critical   = (@($_.Findings | Where-Object Severity -eq 'CRITICAL')).Count
        High       = (@($_.Findings | Where-Object Severity -eq 'HIGH')).Count
        Medium     = (@($_.Findings | Where-Object Severity -eq 'MEDIUM')).Count
        Low        = (@($_.Findings | Where-Object Severity -eq 'LOW')).Count
    }
}
$summaryRows | Export-Csv (Join-Path $csvFolder '01_Summary.csv') -NoTypeInformation -Encoding UTF8

# Sheet 2: Apps rollup (composite risk per app)
$AppRollup | Export-Csv (Join-Path $csvFolder '02_Apps-Rollup.csv') -NoTypeInformation -Encoding UTF8

# Sheet 3: All findings (every row)
$Findings | Export-Csv (Join-Path $csvFolder '03_All-Findings.csv') -NoTypeInformation -Encoding UTF8

# Sheets 4-13: One CSV per check
foreach ($cs in $checkSummary) {
    $safeName = ($cs.Name -replace '[^A-Za-z0-9]+','-').Trim('-')
    $path = Join-Path $csvFolder "$($cs.Id)_$safeName.csv"
    if ($cs.Findings) {
        $cs.Findings | Export-Csv $path -NoTypeInformation -Encoding UTF8
    } else {
        '"CheckId","CheckName","Severity","AppId","DisplayName","Publisher","Detail","Evidence","Score"' | Out-File $path -Encoding utf8
    }
}
$csvFiles = Get-ChildItem -Path $csvFolder -Filter '*.csv' -File
$csvCount = $csvFiles.Count
Write-Host "[+] Audit folder: $auditFolder ($csvCount CSV file$(if ($csvCount -ne 1) {'s'}))" -ForegroundColor Green

# Bundle all CSVs into a single zip so the HTML can offer a one-click download
$zipName = 'shadow-ai-csvs.zip'
$zipPath = Join-Path $auditFolder $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $csvFiles.FullName -DestinationPath $zipPath -Force
Write-Host "[+] CSV bundle: $zipPath" -ForegroundColor Green

# ─── 8. Build self-contained HTML dashboard ──────────────────────────────────
# HTML excludes Unverified Publisher (C05) and the per-check detail section
$HtmlFindings = $Findings | Where-Object CheckId -ne 'C05'
$totalFindings = $HtmlFindings.Count
$sevCount = @{ CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0 }
$HtmlFindings | Group-Object Severity | ForEach-Object { $sevCount[$_.Name] = $_.Count }

# Recompute apps rollup excluding C05 contribution
$HtmlAppRollup = $HtmlFindings | Group-Object AppId | ForEach-Object {
    $a = $_.Group[0]
    $score = ($_.Group | Measure-Object Score -Sum).Sum
    $maxSev = ($_.Group | Sort-Object @{e={$SeverityWeight[$_.Severity]};desc=$true} | Select-Object -First 1).Severity
    $checks = ($_.Group.CheckId | Sort-Object -Unique)
    [pscustomobject]@{
        AppId        = $a.AppId
        DisplayName  = $a.DisplayName
        Publisher    = $a.Publisher
        Score        = $score
        MaxSeverity  = $maxSev
        ChecksHit    = $checks.Count
        CheckIds     = ($checks -join ',')
    }
} | Sort-Object Score -Descending

# Check chart excludes C05
$HtmlCheckSummary = $checkSummary | Where-Object Id -ne 'C05'

function Esc { param($s) if ($null -eq $s) {''} else { [System.Web.HttpUtility]::HtmlEncode([string]$s) } }
Add-Type -AssemblyName System.Web

$rowsApps = ($HtmlAppRollup | ForEach-Object {
    $sevClass = $_.MaxSeverity.ToLower()
    "<tr class='sev-$sevClass'><td><span class='pill $sevClass'>$($_.MaxSeverity)</span></td><td><b>$(Esc $_.DisplayName)</b><div class='mono small'>$($_.AppId)</div></td><td>$(Esc $_.Publisher)</td><td class='num'>$($_.Score)</td><td class='num'>$($_.ChecksHit)/9</td><td class='mono small'>$($_.CheckIds)</td></tr>"
}) -join "`n"

# CSV download links for the header dropdown - relative paths (HTML + CSVs in same folder)
$csvAggregateLinks = @(
    "<a class='csv-link' href='01_Summary.csv' download><span class='label'>Summary (per-check counts)</span><span class='count'>10 checks</span></a>"
    "<a class='csv-link' href='02_Apps-Rollup.csv' download><span class='label'>Apps Rollup (composite risk)</span><span class='count'>$($AppRollup.Count) apps</span></a>"
    "<a class='csv-link' href='03_All-Findings.csv' download><span class='label'>All Findings (every row)</span><span class='count'>$($Findings.Count) rows</span></a>"
) -join "`n"

$csvCheckLinks = ($checkSummary | ForEach-Object {
    $safeName = ($_.Name -replace '[^A-Za-z0-9]+','-').Trim('-')
    $href = "$($_.Id)_$safeName.csv"
    "<a class='csv-link' href='$href' download><span class='label'>$($_.Id) - $(Esc $_.Name)</span><span class='count'>$($_.Hits) finding$(if ($_.Hits -ne 1){'s'})</span></a>"
}) -join "`n"

$scanTime = $now.ToString('yyyy-MM-dd HH:mm:ss UTC')

$html = @"
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>Shadow AI - $($ctx.TenantId)</title>
<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'></script>
<style>
:root {
  --bg:#0b0e14; --panel:#141923; --panel2:#1a2030; --text:#e6e9ef;
  --muted:#8b95a8; --line:#262d3d; --accent:#8B5CF6;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#3b82f6;
}
* { box-sizing: border-box }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
.wrap { max-width: 1400px; margin: 0 auto; padding: 24px; }
header.top { display:flex; justify-content:space-between; align-items:flex-start; padding-bottom:16px; border-bottom:1px solid var(--line); margin-bottom:24px; }
header.top h1 { margin:0 0 6px 0; font-size:24px; }
header.top h1 .pulse { color:var(--accent); }
.meta { color:var(--muted); font-size:13px; }
.tiles { display:grid; grid-template-columns: repeat(6,1fr); gap:12px; margin-bottom:24px; }
.tile { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }
.tile .label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.tile .val   { font-size:28px; font-weight:700; margin-top:6px; }
.tile.crit .val { color:var(--critical); }
.tile.high .val { color:var(--high); }
.tile.med  .val { color:var(--medium); }
.tile.low  .val { color:var(--low); }
.grid2 { display:grid; grid-template-columns: 380px 1fr; gap:16px; margin-bottom:24px; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }
.panel h2 { margin:0 0 12px 0; font-size:15px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
canvas { max-height: 300px; }
table { width:100%; border-collapse: collapse; font-size:13px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
td.num { text-align:right; font-variant-numeric: tabular-nums; }
.pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.5px; }
.pill.critical { background:rgba(239,68,68,.15); color:var(--critical); border:1px solid rgba(239,68,68,.4); }
.pill.high     { background:rgba(249,115,22,.15); color:var(--high); border:1px solid rgba(249,115,22,.4); }
.pill.medium   { background:rgba(234,179,8,.15); color:var(--medium); border:1px solid rgba(234,179,8,.4); }
.pill.low      { background:rgba(59,130,246,.15); color:var(--low); border:1px solid rgba(59,130,246,.4); }
.mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
.small { font-size:11px; color:var(--muted); }
.ok { color:#4ade80; text-align:center; padding:18px; }
.check-card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:0; margin-bottom:14px; overflow:hidden; }
.check-card header { display:flex; align-items:center; gap:12px; padding:12px 16px; background:var(--panel2); border-bottom:1px solid var(--line); }
.check-card header h3 { margin:0; font-size:15px; flex:1; }
.check-id { font-family:ui-monospace,monospace; background:var(--accent); color:#fff; padding:3px 8px; border-radius:6px; font-size:12px; font-weight:700; }
.hits-pill { color:var(--muted); font-size:12px; }
.check-card table { font-size:12.5px; }
.check-card th, .check-card td { padding:8px 16px; }
footer { text-align:center; color:var(--muted); margin-top:32px; font-size:12px; }
.csv-dropdown { position: relative; }
.csv-dropdown summary { list-style: none; cursor: pointer; user-select: none; }
.csv-dropdown summary::-webkit-details-marker { display: none; }
.btn-csv {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--accent); color: #fff; font-weight: 600; font-size: 13px;
  padding: 9px 16px; border-radius: 8px; border: 0;
  transition: filter .15s ease;
}
.btn-csv:hover { filter: brightness(1.1); }
.btn-csv .chev { transition: transform .15s ease; font-size: 11px; }
.csv-dropdown[open] .btn-csv .chev { transform: rotate(180deg); }
.csv-panel {
  position: absolute; right: 0; top: calc(100% + 8px); z-index: 50;
  background: var(--panel2); border: 1px solid var(--line); border-radius: 10px;
  padding: 8px; width: 380px; max-height: 520px; overflow-y: auto;
  box-shadow: 0 12px 32px rgba(0,0,0,.45);
}
.csv-panel-section { padding: 6px 10px 4px 10px; font-size: 10px; text-transform: uppercase;
  letter-spacing: .6px; color: var(--muted); }
.csv-link {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 9px 12px; border-radius: 6px; text-decoration: none; color: var(--text);
  font-size: 13px; transition: background .12s ease;
}
.csv-link:hover { background: var(--panel); }
.csv-link .label { flex: 1; }
.csv-link .count { color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.csv-link.primary {
  background: linear-gradient(180deg, rgba(139,92,246,.18) 0%, rgba(139,92,246,.08) 100%);
  border: 1px solid rgba(139,92,246,.4); margin-bottom: 6px; font-weight: 600;
}
.csv-link.primary:hover { background: rgba(139,92,246,.28); }
.csv-link.primary .count { color: var(--accent); }
</style>
</head>
<body>
<div class='wrap'>

<header class='top'>
  <div>
    <h1><span class='pulse'>Shadow AI</span></h1>
    <div class='meta'>Tenant <b>$($ctx.TenantId)</b> &middot; Account <b>$($ctx.Account)</b> &middot; Scanned <b>$scanTime</b></div>
  </div>
  <div style='display:flex; flex-direction:column; align-items:flex-end; gap:10px;'>
    <div class='meta'>$($AiSps.Count) AI apps inspected</div>
    <details class='csv-dropdown'>
      <summary class='btn-csv'>Download CSVs <span class='chev'>&#9662;</span></summary>
      <div class='csv-panel'>
        <a class='csv-link primary' href='$zipName' download>
          <span class='label'>All CSVs (zip)</span>
          <span class='count'>$csvCount files</span>
        </a>
        <div class='csv-panel-section'>Aggregate Sheets</div>
        $csvAggregateLinks
        <div class='csv-panel-section'>Per-Check Sheets</div>
        $csvCheckLinks
      </div>
    </details>
  </div>
</header>

<div class='tiles'>
  <div class='tile'><div class='label'>AI Apps Detected</div><div class='val'>$($AiSps.Count)</div></div>
  <div class='tile'><div class='label'>Total Findings</div><div class='val'>$totalFindings</div></div>
  <div class='tile crit'><div class='label'>Critical</div><div class='val'>$($sevCount.CRITICAL)</div></div>
  <div class='tile high'><div class='label'>High</div><div class='val'>$($sevCount.HIGH)</div></div>
  <div class='tile med'><div class='label'>Medium</div><div class='val'>$($sevCount.MEDIUM)</div></div>
  <div class='tile low'><div class='label'>Low / Info</div><div class='val'>$($sevCount.LOW)</div></div>
</div>

<div class='grid2'>
  <div class='panel'>
    <h2>Severity Distribution</h2>
    <canvas id='sevChart'></canvas>
  </div>
  <div class='panel'>
    <h2>Findings per Check</h2>
    <canvas id='checkChart'></canvas>
  </div>
</div>

<div class='panel' style='margin-bottom:24px'>
  <h2>Top Risk Apps (composite score across all 10 checks)</h2>
  <table>
    <thead><tr><th>Max Sev</th><th>App</th><th>Publisher</th><th class='num'>Score</th><th class='num'>Checks</th><th>Check IDs</th></tr></thead>
    <tbody>
      $rowsApps
    </tbody>
  </table>
</div>

<footer>Generated by Scan-ShadowAI-Comprehensive.ps1 &middot; $scanTime</footer>
</div>

<script>
const sevColors = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#3b82f6' };
new Chart(document.getElementById('sevChart'), {
  type: 'doughnut',
  data: {
    labels: ['Critical','High','Medium','Low'],
    datasets: [{
      data: [$($sevCount.CRITICAL),$($sevCount.HIGH),$($sevCount.MEDIUM),$($sevCount.LOW)],
      backgroundColor: [sevColors.CRITICAL,sevColors.HIGH,sevColors.MEDIUM,sevColors.LOW],
      borderColor: '#0b0e14', borderWidth: 2
    }]
  },
  options: { plugins: { legend: { position: 'bottom', labels: { color: '#e6e9ef' } } } }
});
new Chart(document.getElementById('checkChart'), {
  type: 'bar',
  data: {
    labels: [$(($HtmlCheckSummary | ForEach-Object { "'$($_.Id)'" }) -join ',')],
    datasets: [{
      label: 'Findings',
      data: [$(($HtmlCheckSummary | ForEach-Object { $_.Hits }) -join ',')],
      backgroundColor: '#8B5CF6', borderRadius: 4
    }]
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8b95a8' }, grid: { color: '#262d3d' } },
      y: { ticks: { color: '#8b95a8' }, grid: { color: '#262d3d' }, beginAtZero: true }
    }
  }
});
</script>
</body>
</html>
"@

# ─── 9. Write + auto-open ────────────────────────────────────────────────────
$html | Out-File -FilePath $OutFile -Encoding utf8
$resolved = (Resolve-Path $OutFile).Path
Write-Host "`n[+] HTML report: $resolved" -ForegroundColor Green

Write-Host "`nShadow AI audit summary (tenant=$($ctx.TenantId)):" -ForegroundColor Cyan
Write-Host ("  AI apps inspected : {0}" -f $AiSps.Count)
Write-Host ("  Total findings    : {0}" -f $totalFindings)
foreach ($s in 'CRITICAL','HIGH','MEDIUM','LOW') {
    $c = switch ($s) { 'CRITICAL' {'Red'} 'HIGH' {'Yellow'} 'MEDIUM' {'White'} default {'Gray'} }
    Write-Host ("  {0,-9} : {1}" -f $s, $sevCount[$s]) -ForegroundColor $c
}

if (-not $NoOpen) {
    Write-Host "`n[*] Opening report..." -ForegroundColor Cyan
    if ($IsMacOS)        { & open  $resolved }
    elseif ($IsLinux)    { & xdg-open $resolved }
    else                 { Start-Process $resolved }
}

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
