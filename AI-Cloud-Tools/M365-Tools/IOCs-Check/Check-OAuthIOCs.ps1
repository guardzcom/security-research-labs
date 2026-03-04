<#
.SYNOPSIS
    Guardz Office 365 OAuth IOC Scanner — detects malicious OAuth abuse patterns in your Entra ID tenant.

.DESCRIPTION
    Developed by Guardz Security Research Labs.

    Connects to Microsoft Graph via interactive (delegated) auth and scans your tenant for
    indicators of compromise (IOCs) associated with known OAuth abuse campaigns.

    Scan phases (works on ALL license tiers):
    - Phase 1: Check if malicious OAuth apps exist as Service Principals in the tenant
    - Phase 2: Check OAuth2 permission grants for malicious apps
    - Phase 3: Check app role assignments for malicious apps

    Premium-only phases (requires Entra ID P1/P2 — skipped gracefully if unavailable):
    - Phase 4: Sign-in logs for malicious client IDs and OAuth URL pattern abuse
    - Phase 5: Audit logs for consent grants and service principal creation

    For each malicious Client ID, the scanner reports whether it EXISTS in the tenant
    (critical finding) or does not exist (safe).

    IOC source: https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md

.NOTES
    Author  : Guardz Security Research Labs
    Version : 1.1
    License : MIT

.PARAMETER DaysBack
    Number of days to look back in logs (premium phases only). Default: 30.

.PARAMETER OutputPath
    Directory for CSV/HTML output. Default: current directory.

.PARAMETER SkipHtmlReport
    Skip generating the HTML report.

.EXAMPLE
    .\Check-OAuthIOCs.ps1
    .\Check-OAuthIOCs.ps1 -DaysBack 90 -OutputPath C:\Reports
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 30,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$SkipHtmlReport
)

$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# IOC DEFINITIONS
# Source: Guardz Security Research Labs — Microsoft OAuth Abuse Intel
# ─────────────────────────────────────────────────────────────────────────────

$MaliciousClientIds = @(
    '9a36eaa2-cf9d-4e50-ad3e-58c9b5c04255'
    '89430f84-6c29-43f8-9b23-62871a314417'
    '440f4886-2c3a-4269-a78c-088b3b521e02'
    'c752e1ef-e475-43c0-9b97-9c9832dd3755'
    '6755c710-194d-464f-9365-7d89d773b443'
    '3cc07cb4-dba8-4051-82cd-93250a43b53b'
    '8c659c19-8a90-49b0-a9f1-15aeba3bb449'
    'bc618bf4-c6d1-4653-8c4d-c6036001b226'
    '6efe57d9-b00a-4091-b861-a16b7368ab11'
    'f73c6332-4618-4b9d-bcd4-c77726581acd'
    '6fae87b3-3a0f-4519-8b56-006ba50f62c4'
    '1b6f59dd-45da-4ff7-9b70-36fb780f855b'
    '00afba72-9008-454f-bbe6-d24e743fbe73'
    'a68c61ee-6185-4b36-bc59-1dca946d95cb'
)

$MaliciousRedirectUrls = @(
    'https://dynamic-entry.powerappsportals.com/dynamics/'
    'https://login-web-auth.github.io/red-auth/'
    'https://westsecure.powerappsportals.com/security/'
    'https://gbm234.powerappsportals.com/auth/'
    'https://email-services.powerappsportals.com/divisor/'
    'https://memointernals.powerappsportals.com/auth/'
    'https://calltask.im/cpcounting/via-secureplatform/quick/'
    'https://ouviraparelhosauditivos.com.br/auth/entry.php'
    'https://abv-abc3.top/abv2/css/red.html'
    'https://weds101.siriusmarine-sg.com/minerwebmailsecure101/'
    'https://mweb-ssm.surge.sh'
    'https://ssmapp.github.io/web'
    'https://ssmview-group.gitlab.io/ssmview'
)

# Extract domains from URLs for substring matching
$MaliciousRedirectDomains = $MaliciousRedirectUrls | ForEach-Object {
    if ($_ -match 'https?://([^/]+)') { $Matches[1] }
}

$ConsentOperations = @(
    'Consent to application'
    'Add OAuth2PermissionGrant'
    'Add app role assignment to service principal'
    'Add delegated permission grant'
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Message,
        [string]$Detail
    )
    $color = switch ($Severity) {
        'CRITICAL' { 'Red' }
        'HIGH'     { 'DarkRed' }
        'MEDIUM'   { 'Yellow' }
        'INFO'     { 'Cyan' }
        default    { 'White' }
    }
    Write-Host "[$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$Category - " -ForegroundColor White -NoNewline
    Write-Host $Message -ForegroundColor Gray
    if ($Detail) {
        Write-Host "         $Detail" -ForegroundColor DarkGray
    }
}

function Test-EncodedEmail {
    param([string]$Value)
    if (-not $Value) { return $false }
    if ($Value -match '[A-Za-z0-9._%+-]+%40[A-Za-z0-9.-]+\.[A-Za-z]{2,}') { return $true }
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))
        if ($decoded -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}') { return $true }
    } catch { }
    return $false
}

function Test-MaliciousRedirect {
    param([string]$Url)
    if (-not $Url) { return $false }
    foreach ($domain in $MaliciousRedirectDomains) {
        if ($Url -like "*$domain*") { return $true }
    }
    return $false
}

function Extract-OAuthUrlParams {
    param([string]$Text)
    $results = @{
        HasPromptNone    = $false
        HasScopeInvalid  = $false
        HasEncodedEmail  = $false
        HasMaliciousRedir = $false
    }
    if (-not $Text) { return $results }
    if ($Text -match '[?&]prompt=none' -or $Text -match 'prompt%3Dnone' -or $Text -match 'prompt=none') {
        $results.HasPromptNone = $true
    }
    if ($Text -match '[?&]scope=invalid' -or $Text -match 'scope%3Dinvalid' -or $Text -match 'scope=invalid') {
        $results.HasScopeInvalid = $true
    }
    if ($Text -match '[?&]state=([^&]+)') {
        $stateValue = $Matches[1]
        if (Test-EncodedEmail -Value $stateValue) { $results.HasEncodedEmail = $true }
    }
    if (Test-MaliciousRedirect -Url $Text) { $results.HasMaliciousRedir = $true }
    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

$findings = [System.Collections.Generic.List[PSObject]]::new()
$startDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$scanTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "         Office 365 OAuth IOC Scanner v1.1                      " -ForegroundColor Cyan
Write-Host "         Guardz Security Research Labs                          " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scan window : Last $DaysBack days (since $startDate)" -ForegroundColor White
Write-Host "IOCs loaded  : $($MaliciousClientIds.Count) client IDs, $($MaliciousRedirectUrls.Count) redirect URLs" -ForegroundColor White
Write-Host ""

# -- Step 1: Check prerequisites & install if needed --

Write-Host "[*] Checking prerequisites..." -ForegroundColor Cyan

$requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Reports')
$missingModules = @()

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        $missingModules += $mod
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "[*] Missing modules: $($missingModules -join ', ')" -ForegroundColor Yellow
    Write-Host "    Installing now (one-time setup)..." -ForegroundColor DarkGray
    try {
        foreach ($mod in $missingModules) {
            Write-Host "    Installing $mod ..." -ForegroundColor DarkGray -NoNewline
            Install-Module $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host " done" -ForegroundColor Green
        }
    } catch {
        Write-Host ""
        Write-Host "[!] Auto-install failed: $_" -ForegroundColor Red
        Write-Host "    Run manually: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "[+] Required Graph modules already installed." -ForegroundColor Green
}

# -- Step 2: Connect to Microsoft Graph --

Write-Host "[*] Connecting to Microsoft Graph (interactive login)..." -ForegroundColor Cyan

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
    Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
    Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($context) {
        Write-Host "    Already connected as: $($context.Account)" -ForegroundColor Green
    } else {
        Connect-MgGraph -Scopes 'Application.Read.All','Directory.Read.All','AuditLog.Read.All' -NoWelcome
        $context = Get-MgContext
        Write-Host "    Connected as: $($context.Account)" -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

Write-Host "    Tenant ID: $($context.TenantId)" -ForegroundColor DarkGray
Write-Host ""

# -- Step 3: Detect Entra ID license tier --

Write-Host "[*] Detecting Entra ID license tier..." -ForegroundColor Cyan

$licenseTier = 'Free'
$hasPremium = $false

try {
    $subscribedSkus = Invoke-MgGraphRequest -Method GET -Uri '/v1.0/subscribedSkus' -ErrorAction Stop
    $skuNames = $subscribedSkus.value | ForEach-Object { $_.skuPartNumber }

    # Check for P2 first (highest), then P1
    $p2Skus = @('AAD_PREMIUM_P2', 'IDENTITY_THREAT_PROTECTION', 'EMSPREMIUM', 'SPE_E5', 'ENTERPRISEPREMIUM', 'Microsoft_365_E5', 'MICROSOFT_365_E5_SUITE')
    $p1Skus = @('AAD_PREMIUM', 'AAD_PREMIUM_P1', 'EMSPREMIUM_P1', 'SPE_E3', 'ENTERPRISEPACK', 'Microsoft_365_E3', 'MICROSOFT_365_BUSINESS_PREMIUM', 'M365_BUSINESS_PREMIUM')

    foreach ($sku in $skuNames) {
        if ($p2Skus -contains $sku) {
            $licenseTier = 'P2'
            $hasPremium = $true
            break
        }
    }
    if ($licenseTier -eq 'Free') {
        foreach ($sku in $skuNames) {
            if ($p1Skus -contains $sku) {
                $licenseTier = 'P1'
                $hasPremium = $true
                break
            }
        }
    }

    $tierColor = switch ($licenseTier) {
        'P2'   { 'Green' }
        'P1'   { 'Green' }
        'Free' { 'Yellow' }
    }
    Write-Host "    Entra ID License: " -ForegroundColor White -NoNewline
    Write-Host "$licenseTier" -ForegroundColor $tierColor

    if ($hasPremium) {
        Write-Host "    Sign-in & audit log scanning: ENABLED" -ForegroundColor Green
    } else {
        Write-Host "    Sign-in & audit log scanning: UNAVAILABLE (requires P1/P2)" -ForegroundColor Yellow
        Write-Host "    Phases 1-3 will still check for malicious apps, grants, and URL patterns." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    [!] Could not detect license tier: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Will attempt all phases and skip on error." -ForegroundColor DarkGray
    # Try anyway — the sign-in log probe will catch it
    $hasPremium = $true
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Check Enterprise Applications (Service Principals)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 1: Checking Enterprise Applications (Service Principals)" -ForegroundColor White
Write-Host "           (All license tiers - Free, P1, P2)" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$spHits = 0
foreach ($clientId in $MaliciousClientIds) {
    Write-Host "  $clientId ... " -ForegroundColor DarkGray -NoNewline

    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -ErrorAction Stop

        if ($sp) {
            Write-Host "EXIST" -ForegroundColor Red
            $spHits++

            $finding = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString('o')
                Severity    = 'CRITICAL'
                Category    = 'Malicious App Exists in Tenant'
                User        = ''
                IPAddress   = ''
                AppId       = $clientId
                AppName     = $sp.DisplayName
                Resource    = "SP ObjectId: $($sp.Id)"
                Status      = "Enabled: $($sp.AccountEnabled)"
                Location    = ''
                Detail      = "Malicious OAuth app registered as service principal. Created: $($sp.CreatedDateTime)"
                RawId       = $sp.Id
            }
            $findings.Add($finding)

            Write-Finding -Severity 'CRITICAL' -Category 'Malicious App EXISTS' `
                -Message "App: $($sp.DisplayName) ($clientId)" `
                -Detail "Created: $($sp.CreatedDateTime) | Enabled: $($sp.AccountEnabled) | SP ID: $($sp.Id)"

            # Check reply URLs for malicious redirects
            if ($sp.ReplyUrls) {
                foreach ($url in $sp.ReplyUrls) {
                    if (Test-MaliciousRedirect -Url $url) {
                        $finding = [PSCustomObject]@{
                            Timestamp   = (Get-Date).ToString('o')
                            Severity    = 'CRITICAL'
                            Category    = 'Malicious Redirect URL on SP'
                            User        = ''
                            IPAddress   = ''
                            AppId       = $clientId
                            AppName     = $sp.DisplayName
                            Resource    = $url
                            Status      = ''
                            Location    = ''
                            Detail      = "Service principal has known malicious redirect URL configured"
                            RawId       = $sp.Id
                        }
                        $findings.Add($finding)

                        Write-Finding -Severity 'CRITICAL' -Category 'Malicious Redirect URL' `
                            -Message $url `
                            -Detail "On app: $($sp.DisplayName)"
                    }
                }
            }
        } else {
            Write-Host "not exist in tenant" -ForegroundColor Green
        }
    } catch {
        Write-Host "error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1b: Check App Registrations (owned apps in the tenant)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 1b: Checking App Registrations (owned apps)" -ForegroundColor White
Write-Host "            (All license tiers - Free, P1, P2)" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$appRegHits = 0
foreach ($clientId in $MaliciousClientIds) {
    Write-Host "  $clientId ... " -ForegroundColor DarkGray -NoNewline

    try {
        $app = Get-MgApplication -Filter "appId eq '$clientId'" -ErrorAction Stop

        if ($app) {
            Write-Host "EXIST (App Registration)" -ForegroundColor Red
            $appRegHits++

            $finding = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString('o')
                Severity    = 'CRITICAL'
                Category    = 'Malicious App Registration in Tenant'
                User        = ''
                IPAddress   = ''
                AppId       = $clientId
                AppName     = $app.DisplayName
                Resource    = "App ObjectId: $($app.Id)"
                Status      = "SignInAudience: $($app.SignInAudience)"
                Location    = ''
                Detail      = "Malicious OAuth app registered as App Registration. Created: $($app.CreatedDateTime)"
                RawId       = $app.Id
            }
            $findings.Add($finding)

            Write-Finding -Severity 'CRITICAL' -Category 'Malicious App Registration EXISTS' `
                -Message "App: $($app.DisplayName) ($clientId)" `
                -Detail "Created: $($app.CreatedDateTime) | Audience: $($app.SignInAudience) | Object ID: $($app.Id)"

            # Check redirect URIs on the app registration
            $appRedirectUris = @()
            if ($app.Web -and $app.Web.RedirectUris) { $appRedirectUris += $app.Web.RedirectUris }
            if ($app.Spa -and $app.Spa.RedirectUris) { $appRedirectUris += $app.Spa.RedirectUris }
            if ($app.PublicClient -and $app.PublicClient.RedirectUris) { $appRedirectUris += $app.PublicClient.RedirectUris }

            foreach ($url in $appRedirectUris) {
                $analysis = Extract-OAuthUrlParams -Text $url
                $maliciousRedir = Test-MaliciousRedirect -Url $url

                if ($maliciousRedir -or $analysis.HasPromptNone -or $analysis.HasScopeInvalid -or $analysis.HasEncodedEmail) {
                    $detail = @()
                    if ($maliciousRedir) { $detail += "Known malicious redirect" }
                    if ($analysis.HasPromptNone) { $detail += "prompt=none" }
                    if ($analysis.HasScopeInvalid) { $detail += "scope=invalid" }
                    if ($analysis.HasEncodedEmail) { $detail += "encoded email in state" }

                    $finding = [PSCustomObject]@{
                        Timestamp   = (Get-Date).ToString('o')
                        Severity    = 'CRITICAL'
                        Category    = 'Suspicious Redirect URI on App Registration'
                        User        = ''
                        IPAddress   = ''
                        AppId       = $clientId
                        AppName     = $app.DisplayName
                        Resource    = $url
                        Status      = ''
                        Location    = ''
                        Detail      = "App Registration redirect URI: $($detail -join ', ')"
                        RawId       = $app.Id
                    }
                    $findings.Add($finding)

                    Write-Finding -Severity 'CRITICAL' -Category 'Suspicious Redirect on App Reg' `
                        -Message $url -Detail "Patterns: $($detail -join ', ')"
                }
            }

            # Check required resource access (API permissions requested)
            if ($app.RequiredResourceAccess) {
                $permCount = ($app.RequiredResourceAccess | ForEach-Object { $_.ResourceAccess.Count } | Measure-Object -Sum).Sum
                Write-Host "         Requested API permissions: $permCount" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "not exist in tenant" -ForegroundColor Green
        }
    } catch {
        Write-Host "error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Check OAuth2 Permission Grants (works on ALL license tiers)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 2: Checking OAuth2 permission grants for malicious apps" -ForegroundColor White
Write-Host "           (All license tiers - Free, P1, P2)" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$grantHits = 0
try {
    $allGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
    Write-Host "  Retrieved $($allGrants.Count) OAuth2 permission grants. Analyzing..." -ForegroundColor DarkGray

    foreach ($grant in $allGrants) {
        # Check if the grant's client service principal matches a malicious app
        $grantClientSp = $null
        try {
            $grantClientSp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
        } catch { }

        if ($grantClientSp -and $MaliciousClientIds -contains $grantClientSp.AppId) {
            $grantHits++
            $finding = [PSCustomObject]@{
                Timestamp   = (Get-Date).ToString('o')
                Severity    = 'CRITICAL'
                Category    = 'OAuth2 Permission Grant to Malicious App'
                User        = if ($grant.PrincipalId) { $grant.PrincipalId } else { 'All Users (admin consent)' }
                IPAddress   = ''
                AppId       = $grantClientSp.AppId
                AppName     = $grantClientSp.DisplayName
                Resource    = "Scopes: $($grant.Scope)"
                Status      = "ConsentType: $($grant.ConsentType)"
                Location    = ''
                Detail      = "Active permission grant to known malicious OAuth app"
                RawId       = $grant.Id
            }
            $findings.Add($finding)

            Write-Finding -Severity 'CRITICAL' -Category 'Permission Grant to Malicious App' `
                -Message "App: $($grantClientSp.DisplayName) ($($grantClientSp.AppId))" `
                -Detail "Scopes: $($grant.Scope) | ConsentType: $($grant.ConsentType)"
        }
    }

    if ($grantHits -eq 0) {
        Write-Host "  [+] No permission grants found for any malicious app IDs." -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] Error checking grants: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Check App Role Assignments (works on ALL license tiers)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 3: Checking app role assignments for malicious apps" -ForegroundColor White
Write-Host "           (All license tiers - Free, P1, P2)" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$roleHits = 0
# Only check role assignments for apps that actually exist in the tenant
$existingSps = $findings | Where-Object { $_.Category -eq 'Malicious App Exists in Tenant' }
if ($existingSps.Count -gt 0) {
    foreach ($spFinding in $existingSps) {
        $spId = $spFinding.RawId
        try {
            $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -All -ErrorAction Stop
            if ($roleAssignments -and $roleAssignments.Count -gt 0) {
                foreach ($role in $roleAssignments) {
                    $roleHits++
                    $finding = [PSCustomObject]@{
                        Timestamp   = $role.CreatedDateTime
                        Severity    = 'CRITICAL'
                        Category    = 'App Role Assignment to Malicious App'
                        User        = $role.PrincipalDisplayName
                        IPAddress   = ''
                        AppId       = $spFinding.AppId
                        AppName     = $spFinding.AppName
                        Resource    = "RoleId: $($role.AppRoleId) -> $($role.ResourceDisplayName)"
                        Status      = ''
                        Location    = ''
                        Detail      = "Malicious app has application permission role assignment"
                        RawId       = $role.Id
                    }
                    $findings.Add($finding)

                    Write-Finding -Severity 'CRITICAL' -Category 'App Role on Malicious App' `
                        -Message "$($spFinding.AppName) -> $($role.ResourceDisplayName)" `
                        -Detail "Role: $($role.AppRoleId) | Created: $($role.CreatedDateTime)"
                }
            } else {
                Write-Host "  $($spFinding.AppName): no app role assignments" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  [!] Error checking roles for $($spFinding.AppName): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  [+] No malicious apps found in tenant - skipping role check." -ForegroundColor Green
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3b: Check OAuth URL patterns on all service principals
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 3b: Scanning OAuth URL patterns on app registrations" -ForegroundColor White
Write-Host "            (All license tiers - Free, P1, P2)" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$oauthPatternHits = 0
Write-Host "  Fetching all service principals with reply URLs..." -ForegroundColor DarkGray

try {
    $allSps = Get-MgServicePrincipal -All -Property 'AppId,DisplayName,ReplyUrls,Web' -ErrorAction Stop
    $spsWithUrls = $allSps | Where-Object { $_.ReplyUrls.Count -gt 0 -or $_.Web.RedirectUris.Count -gt 0 }
    Write-Host "  Found $($spsWithUrls.Count) service principals with redirect URIs. Scanning..." -ForegroundColor DarkGray

    foreach ($sp in $spsWithUrls) {
        $urlsToCheck = @()
        if ($sp.ReplyUrls) { $urlsToCheck += $sp.ReplyUrls }
        if ($sp.Web -and $sp.Web.RedirectUris) { $urlsToCheck += $sp.Web.RedirectUris }

        foreach ($url in $urlsToCheck) {
            $analysis = Extract-OAuthUrlParams -Text $url
            $maliciousRedir = Test-MaliciousRedirect -Url $url

            if ($analysis.HasPromptNone) {
                $oauthPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString('o'); Severity = 'HIGH'
                    Category = 'App with prompt=none in Redirect URI'; User = ''
                    IPAddress = ''; AppId = $sp.AppId; AppName = $sp.DisplayName
                    Resource = $url; Status = ''; Location = ''
                    Detail = "Redirect URI contains prompt=none - consent bypass pattern"
                    RawId = $sp.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'prompt=none in Redirect URI' `
                    -Message "$($sp.DisplayName) ($($sp.AppId))" -Detail "URL: $url"
            }

            if ($analysis.HasScopeInvalid) {
                $oauthPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString('o'); Severity = 'HIGH'
                    Category = 'App with scope=invalid in Redirect URI'; User = ''
                    IPAddress = ''; AppId = $sp.AppId; AppName = $sp.DisplayName
                    Resource = $url; Status = ''; Location = ''
                    Detail = "Redirect URI contains scope=invalid - error redirect abuse pattern"
                    RawId = $sp.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'scope=invalid in Redirect URI' `
                    -Message "$($sp.DisplayName) ($($sp.AppId))" -Detail "URL: $url"
            }

            if ($analysis.HasEncodedEmail) {
                $oauthPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString('o'); Severity = 'HIGH'
                    Category = 'App with Encoded Email in Redirect URI'; User = ''
                    IPAddress = ''; AppId = $sp.AppId; AppName = $sp.DisplayName
                    Resource = $url; Status = ''; Location = ''
                    Detail = "Redirect URI contains encoded email in state - phishing tracking pattern"
                    RawId = $sp.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'Encoded Email in Redirect URI' `
                    -Message "$($sp.DisplayName) ($($sp.AppId))" -Detail "URL: $url"
            }

            if ($maliciousRedir) {
                $oauthPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString('o'); Severity = 'CRITICAL'
                    Category = 'App with Malicious Redirect URL'; User = ''
                    IPAddress = ''; AppId = $sp.AppId; AppName = $sp.DisplayName
                    Resource = $url; Status = ''; Location = ''
                    Detail = "Redirect URI matches known malicious phishing landing page"
                    RawId = $sp.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'CRITICAL' -Category 'Malicious Redirect on App' `
                    -Message "$($sp.DisplayName) ($($sp.AppId))" -Detail "URL: $url"
            }
        }
    }

    if ($oauthPatternHits -eq 0) {
        Write-Host "  [+] No suspicious OAuth URL patterns found on any app registrations." -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] Error scanning app redirect URIs: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Sign-in Logs (Premium only — graceful skip)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 4: Scanning sign-in logs (requires Entra ID P1/P2)" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$clientIdHits = 0
$urlPatternHits = 0

if (-not $hasPremium) {
    Write-Host "  [i] Entra ID $licenseTier - sign-in logs require P1/P2. Skipping." -ForegroundColor Yellow
    Write-Host "      (Phases 1-3 already checked for malicious apps without premium)" -ForegroundColor DarkGray
}

if ($hasPremium) {
    # Phase 4a: Check sign-in logs for malicious client IDs
    Write-Host ""
    Write-Host "  --- 4a: Checking sign-ins from malicious client IDs ---" -ForegroundColor DarkGray

    foreach ($clientId in $MaliciousClientIds) {
        Write-Host "  $clientId ... " -ForegroundColor DarkGray -NoNewline
        try {
            $filter = "appId eq '$clientId' and createdDateTime ge $startDate"
            $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop

            if ($signIns -and $signIns.Count -gt 0) {
                Write-Host "EXIST ($($signIns.Count) sign-ins)" -ForegroundColor Red
                $clientIdHits += $signIns.Count

                foreach ($event in $signIns) {
                    $finding = [PSCustomObject]@{
                        Timestamp   = $event.CreatedDateTime
                        Severity    = 'CRITICAL'
                        Category    = 'Sign-in from Malicious OAuth App'
                        User        = $event.UserPrincipalName
                        IPAddress   = $event.IpAddress
                        AppId       = $event.AppId
                        AppName     = $event.AppDisplayName
                        Resource    = $event.ResourceDisplayName
                        Status      = "$($event.Status.ErrorCode) - $($event.Status.FailureReason)"
                        Location    = "$($event.Location.City), $($event.Location.CountryOrRegion)"
                        Detail      = "User authenticated via known malicious OAuth client"
                        RawId       = $event.Id
                    }
                    $findings.Add($finding)

                    Write-Finding -Severity 'CRITICAL' -Category 'Malicious Sign-in' `
                        -Message "$($event.UserPrincipalName) - App: $($event.AppDisplayName)" `
                        -Detail "IP: $($event.IpAddress) | Time: $($event.CreatedDateTime) | Status: $($event.Status.ErrorCode)"
                }
            } else {
                Write-Host "not exist in tenant" -ForegroundColor Green
            }
        } catch {
            Write-Host "error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Phase 4b: Scan for OAuth URL pattern abuse
    Write-Host ""
    Write-Host "  --- 4b: Scanning for OAuth URL pattern abuse ---" -ForegroundColor DarkGray
    Write-Host "  Fetching recent sign-in events..." -ForegroundColor DarkGray

    try {
        $filter = "createdDateTime ge $startDate"
        $recentSignIns = Get-MgAuditLogSignIn -Filter $filter -Top 5000 -ErrorAction Stop
        Write-Host "  Retrieved $($recentSignIns.Count) sign-in events. Analyzing..." -ForegroundColor DarkGray

        foreach ($event in $recentSignIns) {
            $eventJson = $event | ConvertTo-Json -Depth 10 -Compress -ErrorAction SilentlyContinue
            if (-not $eventJson) { continue }

            $analysis = Extract-OAuthUrlParams -Text $eventJson

            if ($analysis.HasPromptNone) {
                $urlPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = $event.CreatedDateTime; Severity = 'HIGH'; Category = 'OAuth prompt=none Abuse'
                    User = $event.UserPrincipalName; IPAddress = $event.IpAddress; AppId = $event.AppId
                    AppName = $event.AppDisplayName; Resource = $event.ResourceDisplayName
                    Status = "$($event.Status.ErrorCode)"; Location = "$($event.Location.City), $($event.Location.CountryOrRegion)"
                    Detail = "OAuth URL contains prompt=none - bypasses consent screen"; RawId = $event.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'prompt=none' `
                    -Message "$($event.UserPrincipalName) - App: $($event.AppDisplayName)" `
                    -Detail "IP: $($event.IpAddress) | Bypasses user consent prompt"
            }

            if ($analysis.HasScopeInvalid) {
                $urlPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = $event.CreatedDateTime; Severity = 'HIGH'; Category = 'OAuth scope=invalid Abuse'
                    User = $event.UserPrincipalName; IPAddress = $event.IpAddress; AppId = $event.AppId
                    AppName = $event.AppDisplayName; Resource = $event.ResourceDisplayName
                    Status = "$($event.Status.ErrorCode)"; Location = "$($event.Location.City), $($event.Location.CountryOrRegion)"
                    Detail = "OAuth URL contains scope=invalid - error redirect to phishing page"; RawId = $event.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'scope=invalid' `
                    -Message "$($event.UserPrincipalName) - App: $($event.AppDisplayName)" `
                    -Detail "IP: $($event.IpAddress) | Malformed scope triggers error-based redirect"
            }

            if ($analysis.HasEncodedEmail) {
                $urlPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = $event.CreatedDateTime; Severity = 'HIGH'; Category = 'Encoded Email in OAuth State'
                    User = $event.UserPrincipalName; IPAddress = $event.IpAddress; AppId = $event.AppId
                    AppName = $event.AppDisplayName; Resource = $event.ResourceDisplayName
                    Status = "$($event.Status.ErrorCode)"; Location = "$($event.Location.City), $($event.Location.CountryOrRegion)"
                    Detail = "OAuth state parameter contains encoded email - phishing tracking"; RawId = $event.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'HIGH' -Category 'Encoded Email in State' `
                    -Message "$($event.UserPrincipalName) - App: $($event.AppDisplayName)" `
                    -Detail "IP: $($event.IpAddress) | Victim email encoded in OAuth state param"
            }

            if ($analysis.HasMaliciousRedir) {
                $urlPatternHits++
                $finding = [PSCustomObject]@{
                    Timestamp = $event.CreatedDateTime; Severity = 'CRITICAL'; Category = 'Malicious Redirect URL'
                    User = $event.UserPrincipalName; IPAddress = $event.IpAddress; AppId = $event.AppId
                    AppName = $event.AppDisplayName; Resource = $event.ResourceDisplayName
                    Status = "$($event.Status.ErrorCode)"; Location = "$($event.Location.City), $($event.Location.CountryOrRegion)"
                    Detail = "Redirect to known malicious phishing landing page"; RawId = $event.Id
                }
                $findings.Add($finding)
                Write-Finding -Severity 'CRITICAL' -Category 'Malicious Redirect' `
                    -Message "$($event.UserPrincipalName) - App: $($event.AppDisplayName)" `
                    -Detail "IP: $($event.IpAddress) | Redirected to known phishing page"
            }
        }
    } catch {
        Write-Host "  [!] Error scanning sign-in logs: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Audit Logs (Premium only — graceful skip)
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host "  PHASE 5: Scanning audit logs (requires Entra ID P1/P2)" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

$consentHits = 0
$auditSpHits = 0

if (-not $hasPremium) {
    Write-Host "  [i] Entra ID $licenseTier - audit logs require P1/P2. Skipping." -ForegroundColor Yellow
} else {
    # Phase 5a: Consent grants
    Write-Host "  --- 5a: Checking consent grant operations ---" -ForegroundColor DarkGray

    foreach ($operation in $ConsentOperations) {
        Write-Host "  Checking: $operation ... " -ForegroundColor DarkGray -NoNewline
        try {
            $filter = "activityDisplayName eq '$operation' and activityDateTime ge $startDate"
            $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop

            if (-not $auditLogs -or $auditLogs.Count -eq 0) {
                Write-Host "not exist in tenant" -ForegroundColor Green
                continue
            }

            Write-Host "$($auditLogs.Count) events, analyzing..." -ForegroundColor DarkGray

            foreach ($event in $auditLogs) {
                $isMalicious = $false
                $matchedClientId = $null

                foreach ($target in $event.TargetResources) {
                    $targetId = $target.Id
                    $targetAppId = $null
                    foreach ($prop in $target.ModifiedProperties) {
                        if ($prop.DisplayName -eq 'AppId' -or $prop.DisplayName -eq 'ServicePrincipal.AppId') {
                            $targetAppId = $prop.NewValue -replace '"', ''
                        }
                    }
                    foreach ($badId in $MaliciousClientIds) {
                        if ($targetId -eq $badId -or $targetAppId -eq $badId) {
                            $isMalicious = $true; $matchedClientId = $badId; break
                        }
                    }
                    if ($isMalicious) { break }

                    $targetJson = $target | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue
                    if ($targetJson -and (Test-MaliciousRedirect -Url $targetJson)) {
                        $isMalicious = $true; $matchedClientId = 'redirect-url-match'
                    }
                }

                if ($isMalicious) {
                    $consentHits++
                    $initiator = if ($event.InitiatedBy.User) { $event.InitiatedBy.User.UserPrincipalName }
                                 elseif ($event.InitiatedBy.App) { $event.InitiatedBy.App.DisplayName }
                                 else { 'Unknown' }
                    $finding = [PSCustomObject]@{
                        Timestamp = $event.ActivityDateTime; Severity = 'CRITICAL'
                        Category = "Malicious OAuth Consent ($operation)"; User = $initiator
                        IPAddress = $event.InitiatedBy.User.IpAddress; AppId = $matchedClientId
                        AppName = ($event.TargetResources | Select-Object -First 1).DisplayName
                        Resource = $operation; Status = $event.Result; Location = ''
                        Detail = "User consented to known malicious OAuth application"; RawId = $event.Id
                    }
                    $findings.Add($finding)
                    Write-Finding -Severity 'CRITICAL' -Category "Malicious Consent" `
                        -Message "$initiator consented to malicious app ($matchedClientId)" `
                        -Detail "Operation: $operation | Result: $($event.Result)"
                }
            }
        } catch {
            Write-Host "error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  --- 5b: Checking service principal creation ---" -ForegroundColor DarkGray

    try {
        $filter = "activityDisplayName eq 'Add service principal' and activityDateTime ge $startDate"
        $spEvents = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop
        Write-Host "  Found $($spEvents.Count) SP additions to analyze..." -ForegroundColor DarkGray

        foreach ($event in $spEvents) {
            foreach ($target in $event.TargetResources) {
                $spAppId = $null
                foreach ($prop in $target.ModifiedProperties) {
                    if ($prop.DisplayName -eq 'AppId') { $spAppId = $prop.NewValue -replace '"', '' }
                }
                if ($spAppId -and $MaliciousClientIds -contains $spAppId) {
                    $auditSpHits++
                    $initiator = if ($event.InitiatedBy.User) { $event.InitiatedBy.User.UserPrincipalName } else { 'System/App' }
                    $finding = [PSCustomObject]@{
                        Timestamp = $event.ActivityDateTime; Severity = 'CRITICAL'
                        Category = 'Malicious SP Created (Audit)'; User = $initiator
                        IPAddress = $event.InitiatedBy.User.IpAddress; AppId = $spAppId
                        AppName = $target.DisplayName; Resource = 'Service Principal'
                        Status = $event.Result; Location = ''
                        Detail = "Service principal created for known malicious OAuth app"; RawId = $event.Id
                    }
                    $findings.Add($finding)
                    Write-Finding -Severity 'CRITICAL' -Category 'Malicious SP Created' `
                        -Message "$initiator - App: $($target.DisplayName) ($spAppId)" `
                        -Detail "Malicious service principal registered in tenant"
                }
            }
        }
    } catch {
        Write-Host "  [!] Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY & OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                      SCAN RESULTS                              " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tenant  : $($context.TenantId)" -ForegroundColor DarkGray
Write-Host "  License : Entra ID $licenseTier" -ForegroundColor $(if ($hasPremium) { 'Green' } else { 'Yellow' })
Write-Host ""

$totalFindings = $findings.Count
$criticalCount = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
$highCount = ($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count

if ($totalFindings -eq 0) {
    Write-Host "  [+] NO IOC MATCHES FOUND" -ForegroundColor Green
    Write-Host "      Checked $($MaliciousClientIds.Count) malicious client IDs against tenant." -ForegroundColor Gray
    Write-Host "      No malicious OAuth apps, permission grants, or role assignments found." -ForegroundColor Gray
    if (-not $hasPremium) {
        Write-Host "      (Sign-in & audit log scan skipped - Entra ID $licenseTier, requires P1/P2)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [!] $totalFindings IOC MATCHES FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host "      CRITICAL : $criticalCount" -ForegroundColor Red
    Write-Host "      HIGH     : $highCount" -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  Breakdown:" -ForegroundColor White
    Write-Host "      Enterprise Apps (SPs)     : $spHits" -ForegroundColor $(if ($spHits -gt 0) { 'Red' } else { 'Green' })
    Write-Host "      App Registrations         : $appRegHits" -ForegroundColor $(if ($appRegHits -gt 0) { 'Red' } else { 'Green' })
    Write-Host "      OAuth2 Permission Grants  : $grantHits" -ForegroundColor $(if ($grantHits -gt 0) { 'Red' } else { 'Green' })
    Write-Host "      App Role Assignments      : $roleHits" -ForegroundColor $(if ($roleHits -gt 0) { 'Red' } else { 'Green' })
    Write-Host "      OAuth URL Pattern Matches : $oauthPatternHits" -ForegroundColor $(if ($oauthPatternHits -gt 0) { 'Red' } else { 'Green' })
    if ($hasPremium) {
        Write-Host "      Sign-in Log Hits          : $clientIdHits" -ForegroundColor $(if ($clientIdHits -gt 0) { 'Red' } else { 'Green' })
        Write-Host "      OAuth URL Patterns        : $urlPatternHits" -ForegroundColor $(if ($urlPatternHits -gt 0) { 'Red' } else { 'Green' })
        Write-Host "      Consent Grants (Audit)    : $consentHits" -ForegroundColor $(if ($consentHits -gt 0) { 'Red' } else { 'Green' })
        Write-Host "      SP Creation (Audit)       : $auditSpHits" -ForegroundColor $(if ($auditSpHits -gt 0) { 'Red' } else { 'Green' })
    } else {
        Write-Host "      Sign-in/Audit Logs        : skipped (Entra ID $licenseTier)" -ForegroundColor DarkGray
    }

    $affectedUsers = $findings | Select-Object -ExpandProperty User -Unique | Where-Object { $_ -and $_ -ne '' }
    if ($affectedUsers) {
        Write-Host ""
        Write-Host "  Affected Users:" -ForegroundColor White
        foreach ($user in $affectedUsers) {
            $userFindings = ($findings | Where-Object { $_.User -eq $user }).Count
            Write-Host "      - $user ($userFindings findings)" -ForegroundColor Yellow
        }
    }
}

Write-Host ""

# -- Export CSV --

if ($findings.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "OAuth-IOC-Scan_$scanTimestamp.csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  [>] CSV exported: $csvPath" -ForegroundColor Green
}

# -- Export HTML Report --

if (-not $SkipHtmlReport) {
    $htmlPath = Join-Path $OutputPath "OAuth-IOC-Scan_$scanTimestamp.html"

    $findingsRows = ""
    foreach ($f in ($findings | Sort-Object Timestamp -Descending)) {
        $rowClass = "sev-$($f.Severity)"
        $findingsRows += "<tr class=`"$rowClass`"><td>$($f.Timestamp)</td><td>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.User)</td><td>$($f.IPAddress)</td><td style=`"font-family:monospace;font-size:0.8rem`">$($f.AppId)</td><td>$($f.Detail)</td></tr>`n"
    }

    $clientIdList = ""
    foreach ($id in $MaliciousClientIds) { $clientIdList += "<li>$id</li>`n" }
    $urlList = ""
    foreach ($u in $MaliciousRedirectUrls) { $urlList += "<li>$u</li>`n" }

    $resultSection = ""
    if ($findings.Count -gt 0) {
        $resultSection = @"
<h2>Findings ($totalFindings)</h2>
<table>
<tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>User</th><th>IP Address</th><th>App ID</th><th>Detail</th></tr>
$findingsRows
</table>
"@
    } else {
        $resultSection = @"
<h2>Results</h2>
<div class="summary" style="text-align:center">
    <div class="stat-value clean">All Clear</div>
    <p>No malicious OAuth IOCs detected in the tenant.</p>
</div>
"@
    }

    $statusClass = if ($totalFindings -gt 0) { 'critical' } else { 'clean' }
    $premiumNote = if (-not $hasPremium) { "<p style=`"color:#d29922`">Note: Tenant license is Entra ID $licenseTier. Sign-in and audit log scans require P1/P2 and were skipped. Phases 1-3 completed successfully.</p>" } else { "<p style=`"color:#3fb950`">Tenant license: Entra ID $licenseTier - all scan phases completed.</p>" }

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OAuth IOC Scan Report - $scanTimestamp</title>
<style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }
    h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 0.5rem; }
    h2 { color: #79c0ff; margin-top: 2rem; }
    h3 { color: #8b949e; }
    .summary { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin: 1rem 0; }
    .stat { display: inline-block; margin: 0.5rem 1rem; text-align: center; }
    .stat-value { font-size: 2rem; font-weight: bold; }
    .stat-label { font-size: 0.85rem; color: #8b949e; }
    .critical { color: #f85149; }
    .high { color: #d29922; }
    .clean { color: #3fb950; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th { background: #21262d; color: #58a6ff; text-align: left; padding: 0.75rem; border: 1px solid #30363d; }
    td { padding: 0.75rem; border: 1px solid #30363d; font-size: 0.9rem; }
    tr:hover { background: #161b22; }
    .sev-CRITICAL { background: #3d1214; }
    .sev-HIGH { background: #3d2e00; }
    .ioc-list { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; font-family: monospace; font-size: 0.85rem; }
    .ioc-list li { margin: 0.3rem 0; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85rem; }
    a { color: #58a6ff; }
</style>
</head>
<body>
<h1>Office 365 OAuth IOC Scan Report</h1>
<div class="summary">
    <div class="stat"><div class="stat-value $statusClass">$totalFindings</div><div class="stat-label">Total Findings</div></div>
    <div class="stat"><div class="stat-value critical">$criticalCount</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-value high">$highCount</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-value">$($MaliciousClientIds.Count)</div><div class="stat-label">IOCs Checked</div></div>
</div>
<p>Scan time: $scanTimestamp | Tenant: $($context.TenantId)</p>
$premiumNote

<h2>IOCs Checked</h2>
<h3>Malicious OAuth Client IDs ($($MaliciousClientIds.Count))</h3>
<ul class="ioc-list">$clientIdList</ul>

<h3>Malicious Redirect URLs ($($MaliciousRedirectUrls.Count))</h3>
<ul class="ioc-list">$urlList</ul>

<h3>OAuth URL Patterns</h3>
<ul class="ioc-list">
<li>prompt=none (consent bypass)</li>
<li>scope=invalid (error redirect abuse)</li>
<li>Encoded email in state parameter (phishing tracking)</li>
</ul>

$resultSection

<div class="footer">
    <p>Generated by <strong>Guardz Office 365 OAuth IOC Scanner v1.1</strong></p>
    <p>IOC source: <a href="https://github.com/guardzcom/security-research-labs/blob/main/Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md">Microsoft-Intel-OAuth.md</a></p>
</div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "  [>] HTML report: $htmlPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Scan complete." -ForegroundColor Cyan
Write-Host ""
