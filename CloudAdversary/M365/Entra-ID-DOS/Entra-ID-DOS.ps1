<#
.SYNOPSIS
    Validates Microsoft Entra ID Smart Lockout policy in cloud-only and hybrid
    (PHS / PTA) environments.

.DESCRIPTION
    Entra-ID-DOS uses the modern browser login flow (OAuth2 authorize + form
    POST) to send controlled authentication requests with random incorrect
    passwords. Unlike ROPC (grant_type=password), this approach:

      - Bypasses ROPC blocks (Conditional Access, Security Defaults)
      - Works with tenants that have disabled legacy auth
      - Goes through the same authentication pipeline as a real browser
      - Detects MFA challenges (password correct, stopped at MFA wall)

    The script monitors for AADSTS50053 (account locked) responses to confirm
    that Smart Lockout activates at or below the configured threshold.

    Flow per attempt:
      1. GET /authorize - obtain login context (flow token + sCtx)
      2. POST /login    - submit credentials via form POST
      3. Parse response - 50126 (bad pwd), 50053 (locked), MFA (pwd correct)

    If modern auth initialization fails, falls back to ROPC automatically.

    HYBRID SUPPORT
    The script validates the Microsoft-recommended hybrid configuration:

    Password Hash Sync (PHS):
      - Smart Lockout hash tracking: same bad password should NOT increment
        the lockout counter (last 3 hashes tracked in the cloud).
      - Lockout threshold and duration validated against Entra config.

    Pass-through Authentication (PTA):
      - Hash tracking is NOT available (auth happens on-premises).
      - Entra lockout threshold MUST be less than AD DS threshold.
      - AD DS threshold should be at least 2-3x the Entra threshold.
      - Entra lockout duration MUST be longer than AD DS duration.
      - The script validates these relationships and warns on misconfiguration.

    Reference:
    https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout

.PARAMETER TenantId
    The Entra ID tenant ID (GUID) or domain of the target tenant.

.PARAMETER UserEmail
    The UPN of the test user account to validate lockout against.

.PARAMETER DeploymentType
    The authentication deployment type. Determines which validations run.
      Auto      - Default. Auto-detects via User Realm Discovery, OpenID
                  config, and probe authentication (hash tracking test).
      CloudOnly - Standard Entra ID Smart Lockout tests only.
      PHS       - Password Hash Sync. Adds hash-tracking replay test.
      PTA       - Pass-through Authentication. Adds AD DS threshold/duration
                  compliance checks. Requires -ADLockoutThreshold and
                  -ADLockoutDurationMin.
      Federated - AD FS. Tests cloud-side lockout; advises on AD FS Extranet
                  Smart Lockout for on-premises coverage.

    Auto-detection uses three signals:
      1. User Realm Discovery → Managed vs Federated namespace
      2. OpenID Configuration → Tenant reachability
      3. Probe auth + hash tracking test → PTA (no tracking) vs PHS (tracking)

.PARAMETER LockoutThreshold
    The expected Entra ID Smart Lockout threshold. Default: 10.
    (Azure Public default: 10, Azure US Gov default: 3)

.PARAMETER LockoutDurationSec
    The expected Entra ID Smart Lockout duration in seconds. Default: 60.
    Used for PTA compliance validation against AD DS duration.

.PARAMETER ADLockoutThreshold
    On-premises AD DS account lockout threshold. Required for PTA.
    Must be at least 2x the Entra LockoutThreshold per Microsoft guidance.

.PARAMETER ADLockoutDurationMin
    On-premises AD DS "Reset account lockout counter after" value in minutes.
    Required for PTA. Entra LockoutDurationSec must exceed this (converted).

.PARAMETER MaxAttempts
    Maximum number of authentication attempts before stopping. Default: 150.

.PARAMETER DelaySec
    Fixed delay in seconds between authentication attempts. Default: 2.

.PARAMETER ClientId
    The OAuth2 public client application ID used for ROPC authentication.
    Default: Azure AD PowerShell well-known client ID.

.PARAMETER OutputPath
    Directory for log and CSV output files. Default: current directory.

.EXAMPLE
    .\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com"

    Auto-detects deployment type (PHS/PTA/Federated/CloudOnly) and runs the
    appropriate validation suite. Default: threshold=10, max=150 attempts.

.EXAMPLE
    .\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType PHS

    Forces PHS mode. Includes hash-tracking replay test (same password sent
    multiple times should not increment lockout counter).

.EXAMPLE
    .\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType PTA -ADLockoutThreshold 20 -ADLockoutDurationMin 1 -LockoutDurationSec 120

    Forces PTA mode. Validates Entra threshold (10) < AD threshold (20)
    and Entra duration (120s) > AD duration (60s).

.EXAMPLE
    .\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType Auto -ADLockoutThreshold 20 -ADLockoutDurationMin 1

    Auto-detects and if PTA is detected, uses the provided AD DS values for
    compliance validation. If non-PTA, AD params are ignored gracefully.

.NOTES
    Author:      Security Engineering
    Version:     2.0.0
    Requires:    PowerShell 5.1+
    License:     MIT

    AUTHORIZATION REQUIRED: This script must only be executed against tenants
    where you have explicit written authorization for security testing.

    HYBRID CONFIGURATION REQUIREMENTS (per Microsoft):
      PTA: Entra threshold < AD DS threshold (AD should be 2-3x Entra)
      PTA: Entra duration (seconds) > AD DS duration (minutes)
      PHS: Hash tracking active (last 3 bad hashes, same password = no increment)

    ENTRA ID ERROR CODES:
        AADSTS50126 - Invalid credentials (expected during testing)
        AADSTS50053 - Account locked by Smart Lockout (target signal)
        AADSTS50057 - Account disabled
        AADSTS50076 - MFA required (Conditional Access)

.LINK
    https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Object[]. Returns an array of PSCustomObjects with per-attempt results.
    Also writes a .log file and .csv file to the OutputPath directory.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "Entra ID tenant ID or domain")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory, Position = 1, HelpMessage = "Target user UPN")]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$UserEmail,

    [Parameter(HelpMessage = "Deployment type: Auto (detect), CloudOnly, PHS, PTA, or Federated")]
    [ValidateSet('Auto', 'CloudOnly', 'PHS', 'PTA', 'Federated')]
    [string]$DeploymentType = 'Auto',

    [Parameter(HelpMessage = "Expected Entra ID Smart Lockout threshold")]
    [ValidateRange(1, 50)]
    [int]$LockoutThreshold = 10,

    [Parameter(HelpMessage = "Expected Entra ID Smart Lockout duration in seconds")]
    [ValidateRange(1, 3600)]
    [int]$LockoutDurationSec = 60,

    [Parameter(HelpMessage = "On-premises AD DS account lockout threshold (required for PTA)")]
    [ValidateRange(1, 999)]
    [int]$ADLockoutThreshold,

    [Parameter(HelpMessage = "On-premises AD DS lockout counter reset in minutes (required for PTA)")]
    [ValidateRange(1, 99999)]
    [int]$ADLockoutDurationMin,

    [Parameter(HelpMessage = "Maximum authentication attempts")]
    [ValidateRange(1, 150)]
    [int]$MaxAttempts = 150,

    [Parameter(HelpMessage = "Delay between attempts (seconds)")]
    [ValidateRange(1, 60)]
    [int]$DelaySec = 2,

    [Parameter(HelpMessage = "OAuth2 public client application ID")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894",

    [Parameter(HelpMessage = "Output directory for log and CSV files")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$OutputPath = (Get-Location).Path
)

#region Auto-Detection & Parameter Validation

function Detect-DeploymentType {
    <#
    .SYNOPSIS
        Auto-detects the tenant's authentication deployment type using
        unauthenticated discovery endpoints.
    .DESCRIPTION
        Uses three signals:
        1. User Realm Discovery (login.microsoftonline.com/common/UserRealmExtended)
           → Returns NameSpaceType (Managed vs Federated) and cloud_instance_name
        2. OpenID Configuration (login.microsoftonline.com/{tenant}/.well-known/openid-configuration)
           → Confirms tenant exists and is reachable
        3. Probe authentication attempt error response
           → PTA returns specific sub-errors and x-ms-clitelem patterns

        Detection logic:
          Federated (ADFS)    → NameSpaceType = "Federated", has AuthURL
          Managed + PTA       → NameSpaceType = "Managed", has_password_auth = true,
                                and probe error lacks hash tracking behavior
          Managed + PHS       → NameSpaceType = "Managed", cloud-authenticated
          Cloud-Only          → NameSpaceType = "Managed", no on-prem indicators
    #>

    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host "  DEPLOYMENT AUTO-DETECTION" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor White

    $detected = 'CloudOnly'
    $realmInfo = $null
    $isFederated = $false
    $isManaged = $false
    $federationUrl = $null
    $hasPTA = $false

    # ── Step 1: User Realm Discovery ──
    Write-Host "  [1/3] Querying User Realm Discovery..." -ForegroundColor Gray
    try {
        $realmUrl = "https://login.microsoftonline.com/common/UserRealmExtended?user=$([Uri]::EscapeDataString($UserEmail))&api-version=2.0"
        $realmInfo = Invoke-RestMethod -Uri $realmUrl -Method Get -ErrorAction Stop

        $nsType = $realmInfo.NameSpaceType
        Write-Host "        NameSpaceType:       " -NoNewline -ForegroundColor DarkGray
        if ($nsType -eq 'Federated') {
            Write-Host "$nsType" -ForegroundColor Yellow
            $isFederated = $true
            $federationUrl = $realmInfo.AuthURL
            Write-Host "        Federation URL:      $federationUrl" -ForegroundColor DarkGray
        }
        elseif ($nsType -eq 'Managed') {
            Write-Host "$nsType" -ForegroundColor Green
            $isManaged = $true
        }
        else {
            Write-Host "$nsType (unexpected)" -ForegroundColor Red
        }

        # Check for on-prem indicators
        $cloudName = $realmInfo.cloud_instance_name
        $domainName = $realmInfo.DomainName
        $hasPassword = $realmInfo.is_signup_allowed  # Managed domains have this

        Write-Host "        Cloud Instance:      $cloudName" -ForegroundColor DarkGray
        Write-Host "        Domain:              $domainName" -ForegroundColor DarkGray

        if ($realmInfo.PSObject.Properties['EstsProperties']) {
            $estsProps = $realmInfo.EstsProperties
            if ($estsProps.PSObject.Properties['DesktopSsoEnabled']) {
                $ssoEnabled = $estsProps.DesktopSsoEnabled
                Write-Host "        Desktop SSO:         $ssoEnabled" -ForegroundColor DarkGray
                if ($ssoEnabled) {
                    Write-Host "        " -NoNewline
                    Write-Host "Seamless SSO detected - indicates hybrid (PHS or PTA)" -ForegroundColor Cyan
                }
            }
            if ($estsProps.PSObject.Properties['UserTenantBranding']) {
                Write-Host "        Tenant Branding:     Present" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Host "        Failed to query realm: $_" -ForegroundColor Red
        Write-Log "Realm discovery failed: $_" 'WARN'
    }

    # ── Step 2: OpenID Configuration ──
    Write-Host "  [2/3] Querying OpenID Configuration..." -ForegroundColor Gray
    try {
        $oidcUrl = "https://login.microsoftonline.com/$TenantId/.well-known/openid-configuration"
        $oidcInfo = Invoke-RestMethod -Uri $oidcUrl -Method Get -ErrorAction Stop
        Write-Host "        Issuer:              $($oidcInfo.issuer)" -ForegroundColor DarkGray
        Write-Host "        Token Endpoint:      Reachable" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "        OpenID discovery failed: $_" -ForegroundColor Red
    }

    # ── Step 3: Probe Authentication (detect PTA vs PHS) ──
    Write-Host "  [3/3] Probe authentication to detect PTA/PHS..." -ForegroundColor Gray
    if ($isManaged) {
        # Use modern auth flow for probe (same as main test)
        $probePassword = New-RandomPassword -Length 16
        $probeInit = Initialize-LoginFlow
        if ($probeInit) {
            $probeResult = Send-AuthAttempt -Password $probePassword -Phase 'probe'
            Write-Host "        Probe Error:         $($probeResult.ErrorCode)" -ForegroundColor DarkGray
            Write-Host "        Probe Method:        $($probeResult.AuthMethod)" -ForegroundColor DarkGray

            # Send the SAME password again to test hash tracking behavior
            Write-Host "        Sending same password again (hash tracking probe)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 1

            $probeResult2 = Send-AuthAttempt -Password $probePassword -Phase 'probe-repeat'
            Write-Host "        Repeat Error:        $($probeResult2.ErrorCode)" -ForegroundColor DarkGray

            # If the second attempt with same password returns 50053 (locked),
            # hash tracking is NOT working → likely PTA
            if ($probeResult2.ErrorCode -eq '50053' -and $probeResult.ErrorCode -eq '50126') {
                $hasPTA = $true
                Write-Host "        " -NoNewline
                Write-Host "Same password incremented counter -> PTA detected (no hash tracking)" -ForegroundColor Yellow
            }
            elseif ($probeResult2.ErrorCode -eq '50126') {
                Write-Host "        " -NoNewline
                Write-Host "Same password did NOT increment counter -> PHS likely (hash tracking active)" -ForegroundColor Cyan
            }
        }
        else {
            Write-Host "        Could not initialize modern auth flow for probe" -ForegroundColor DarkGray
        }
    }

    # ── Determine deployment type ──
    Write-Host ""
    if ($isFederated) {
        $detected = 'Federated'
        Write-Host "  Detected: " -NoNewline
        Write-Host "FEDERATED (AD FS)" -ForegroundColor Yellow
        Write-Host "  Federation URL: $federationUrl" -ForegroundColor DarkGray
        Write-Check 'INFO' "Federated auth detected. Smart Lockout applies to cloud-side. Consider AD FS Extranet Smart Lockout for on-prem."
    }
    elseif ($hasPTA) {
        $detected = 'PTA'
        Write-Host "  Detected: " -NoNewline
        Write-Host "PASS-THROUGH AUTHENTICATION (PTA)" -ForegroundColor Yellow
        Write-Check 'INFO' "PTA detected: passwords validated on-premises, no hash tracking in cloud"
        Write-Check 'WARN' "PTA requires AD DS lockout threshold > Entra threshold (2-3x recommended)"
    }
    elseif ($isManaged -and $realmInfo -and (
        ($realmInfo.PSObject.Properties['EstsProperties'] -and
         $realmInfo.EstsProperties.PSObject.Properties['DesktopSsoEnabled'] -and
         $realmInfo.EstsProperties.DesktopSsoEnabled)
    )) {
        $detected = 'PHS'
        Write-Host "  Detected: " -NoNewline
        Write-Host "PASSWORD HASH SYNC (PHS)" -ForegroundColor Cyan
        Write-Check 'INFO' "PHS detected: Seamless SSO enabled, hash tracking active in cloud"
    }
    else {
        $detected = 'CloudOnly'
        Write-Host "  Detected: " -NoNewline
        Write-Host "CLOUD-ONLY" -ForegroundColor Green
        Write-Check 'INFO' "No on-premises hybrid indicators detected"
    }

    Write-Host "  ==========================================" -ForegroundColor White
    Write-Log "Auto-detected deployment type: $detected"

    return $detected
}

# Auto-detect if needed
if ($DeploymentType -eq 'Auto') {
    $DeploymentType = Detect-DeploymentType
}

# PTA parameter validation
if ($DeploymentType -eq 'PTA') {
    if (-not $PSBoundParameters.ContainsKey('ADLockoutThreshold')) {
        Write-Host ""
        Write-Host "  PTA detected but -ADLockoutThreshold not provided." -ForegroundColor Yellow
        Write-Host "  To verify on-prem AD DS policy:" -ForegroundColor Yellow
        Write-Host "    Group Policy > Computer Configuration > Policies > Windows Settings" -ForegroundColor DarkGray
        Write-Host "    > Security Settings > Account Policies > Account Lockout Policy" -ForegroundColor DarkGray
        Write-Host ""
        $adThresholdInput = Read-Host "  Enter your AD DS Account Lockout Threshold (or press Enter to skip PTA checks)"
        if ($adThresholdInput -and $adThresholdInput -match '^\d+$') {
            $script:ADLockoutThreshold = [int]$adThresholdInput
            $ADLockoutThreshold = $script:ADLockoutThreshold
        }
        else {
            Write-Host "  Skipping PTA compliance checks (no AD DS threshold provided)." -ForegroundColor DarkGray
            $DeploymentType = 'CloudOnly'
        }
    }
    if ($DeploymentType -eq 'PTA' -and -not $PSBoundParameters.ContainsKey('ADLockoutDurationMin')) {
        $adDurationInput = Read-Host "  Enter your AD DS Reset Lockout Counter After (minutes, or press Enter to skip)"
        if ($adDurationInput -and $adDurationInput -match '^\d+$') {
            $script:ADLockoutDurationMin = [int]$adDurationInput
            $ADLockoutDurationMin = $script:ADLockoutDurationMin
        }
        else {
            Write-Host "  Skipping PTA duration compliance (no AD DS duration provided)." -ForegroundColor DarkGray
            $DeploymentType = 'CloudOnly'
        }
    }
}

# Federated notice
if ($DeploymentType -eq 'Federated') {
    Write-Host ""
    Write-Host "  NOTE: Federated environments use AD FS Extranet Smart Lockout." -ForegroundColor Yellow
    Write-Host "  This script tests the Entra ID cloud-side lockout only." -ForegroundColor Yellow
    Write-Host "  For full coverage, also test AD FS Extranet Lockout separately." -ForegroundColor Yellow
    Write-Host ""
}

#endregion

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

#region Configuration

$script:LogFile = Join-Path $OutputPath "Entra-ID-DOS_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:CsvFile = $script:LogFile -replace '\.log$', '.csv'
$script:TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

# Modern auth endpoints (browser login flow)
$script:AuthorizeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
$script:LoginPostUrl = "https://login.microsoftonline.com/$TenantId/login"
$script:RedirectUri  = "https://login.microsoftonline.com/common/oauth2/nativeclient"

# Session state for modern auth flow
$script:FlowToken = $null
$script:FlowContext = $null
$script:SessionCookies = $null

#endregion

#region Helper Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'ALERT', 'PASS', 'FAIL')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $entry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'ALERT' { Write-Warning $Message }
        'ERROR' { Write-Warning $Message }
        'FAIL'  { Write-Warning $Message }
        'PASS'  { Write-Information $entry -InformationAction Continue }
        default { Write-Verbose $entry }
    }

    $entry | Out-File -Append -FilePath $script:LogFile -Encoding UTF8
}

function Write-Section {
    param([string]$Title, [string]$Color = 'White')
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "  $('-' * 50)"
}

function Write-Check {
    param([string]$Status, [string]$Message, [string]$LogLevel = 'INFO')
    switch ($Status) {
        'PASS' {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
            Write-Host $Message
            Write-Log "PASS: $Message" 'PASS'
        }
        'FAIL' {
            Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
            Write-Host $Message
            Write-Log "FAIL: $Message" 'FAIL'
        }
        'WARN' {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
            Write-Host $Message
            Write-Log "WARN: $Message" 'WARN'
        }
        'INFO' {
            Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
            Write-Host $Message
            Write-Log "INFO: $Message"
        }
    }
}

function Get-ErrorDescription {
    [CmdletBinding()]
    param([string]$Code)

    $descriptions = @{
        '50053'  = 'Account locked (Smart Lockout)'
        '50126'  = 'Invalid password'
        '50057'  = 'Account disabled'
        '50076'  = 'MFA required (Conditional Access)'
        '50074'  = 'Password correct, MFA needed'
        '50079'  = 'MFA registration required'
        '50105'  = 'Admin consent required'
        '50158'  = 'External security challenge not satisfied'
        '53003'  = 'Blocked by Conditional Access'
        '530032' = 'Blocked by Security Defaults'
        '700016' = 'Application not found in tenant'
        '7000218'= 'ROPC not allowed for client'
        '65001'  = 'Application not consented'
        '90095'  = 'Admin consent required for permissions'
        'mfa_required' = 'Password correct - MFA challenge presented'
        'mfa_redirect' = 'Password correct - redirected to MFA'
        'unknown' = 'Unknown error'
    }

    if ($descriptions.ContainsKey($Code)) { return $descriptions[$Code] }
    return "AADSTS$Code"
}

function New-RandomPassword {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [ValidateRange(8, 128)]
        [int]$Length = 16
    )

    $charSets = @{
        Upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Lower   = 'abcdefghijklmnopqrstuvwxyz'
        Digit   = '0123456789'
        Special = '!@#$%^&*-_+=?'
    }

    $allChars = ($charSets.Values -join '')

    $mandatory = foreach ($set in $charSets.Values) {
        $set[(Get-Random -Maximum $set.Length)]
    }

    $remaining = 1..($Length - $mandatory.Count) | ForEach-Object {
        $allChars[(Get-Random -Maximum $allChars.Length)]
    }

    $plaintext = ($mandatory + $remaining | Get-Random -Count $Length) -join ''
    return $plaintext
}

function Get-ErrorDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $detail = [PSCustomObject]@{
        HttpStatus      = $null
        ErrorCode       = 'unknown'
        ErrorType       = $null
        Description     = $null
        SubError        = $null
        ErrorCodes      = $null
        Timestamp       = $null
        TraceId         = $null
        CorrelationId   = $null
        ErrorUri        = $null
        Datacenter      = $null
        RequestId       = $null
        ClientTelemetry = $null
        ClientRequestId = $null
        ServerDate      = $null
    }

    try {
        $response = $ErrorRecord.Exception.Response

        # ── HTTP Status ──
        if ($null -ne $response) {
            $detail.HttpStatus = [int]$response.StatusCode
        }

        # ── Response Body (5 fallback paths) ──
        $bodyText = $null

        # Path 1: PS7+ ErrorDetails.Message (most reliable for PS7)
        if (-not $bodyText -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $bodyText = $ErrorRecord.ErrorDetails.Message
            Write-Verbose "Body source: ErrorDetails.Message"
        }

        # Path 2: PS7+ HttpResponseMessage.Content.ReadAsStringAsync()
        if (-not $bodyText -and $null -ne $response -and $response.PSObject.Properties['Content'] -and $null -ne $response.Content) {
            try {
                $bodyText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                Write-Verbose "Body source: Response.Content.ReadAsStringAsync"
            } catch { }
        }

        # Path 3: PS5.1 GetResponseStream()
        if (-not $bodyText -and $null -ne $response -and $response.PSObject.Methods['GetResponseStream']) {
            try {
                $stream = $response.GetResponseStream()
                if ($null -ne $stream) {
                    if ($stream.CanSeek) { $stream.Position = 0 }
                    $reader = [System.IO.StreamReader]::new($stream)
                    $bodyText = $reader.ReadToEnd()
                    $reader.Dispose()
                    Write-Verbose "Body source: GetResponseStream"
                }
            } catch { }
        }

        # Path 4: Exception.Message often contains AADSTS error text
        if (-not $bodyText -and $ErrorRecord.Exception.Message) {
            $msg = $ErrorRecord.Exception.Message
            # Check if the message itself contains JSON or AADSTS code
            if ($msg -match '\{.*"error"') {
                $bodyText = $msg -replace '^[^{]*', ''
                Write-Verbose "Body source: Exception.Message (JSON extracted)"
            }
            elseif ($msg -match 'AADSTS\d+') {
                # Not JSON but contains error code - extract what we can
                if ($msg -match 'AADSTS(\d+)') {
                    $detail.ErrorCode = $Matches[1]
                }
                $detail.Description = $msg
                Write-Verbose "Body source: Exception.Message (AADSTS regex)"
            }
        }

        # Path 5: ToString() of the inner exception
        if (-not $bodyText -and $ErrorRecord.Exception.InnerException) {
            $inner = $ErrorRecord.Exception.InnerException.Message
            if ($inner -match 'AADSTS(\d+)') {
                $detail.ErrorCode = $Matches[1]
                $detail.Description = $inner
                Write-Verbose "Body source: InnerException.Message"
            }
        }

        # ── Parse JSON body ──
        if ($bodyText) {
            try {
                $body = $bodyText | ConvertFrom-Json

                $detail.ErrorType     = $body.error
                $detail.Description   = $body.error_description
                $detail.SubError      = $body.suberror
                $detail.ErrorCodes    = ($body.error_codes -join ',')
                $detail.Timestamp     = $body.timestamp
                $detail.TraceId       = $body.trace_id
                $detail.CorrelationId = $body.correlation_id
                $detail.ErrorUri      = $body.error_uri

                if ($body.error_description -match 'AADSTS(\d+)') {
                    $detail.ErrorCode = $Matches[1]
                }
                elseif ($body.error_codes -and $body.error_codes.Count -gt 0) {
                    $detail.ErrorCode = $body.error_codes[0].ToString()
                }
            }
            catch {
                Write-Verbose "JSON parse failed, trying regex on raw body"
                if ($bodyText -match 'AADSTS(\d+)') {
                    $detail.ErrorCode = $Matches[1]
                }
                if ($bodyText -match '"error_description"\s*:\s*"([^"]+)"') {
                    $detail.Description = $Matches[1]
                }
            }
        }

        # ── Response Headers (3 fallback paths) ──
        if ($null -ne $response) {
            $headerNames = @{
                'x-ms-ests-server'  = 'Datacenter'
                'x-ms-request-id'   = 'RequestId'
                'x-ms-clitelem'     = 'ClientTelemetry'
                'client-request-id' = 'ClientRequestId'
                'Date'              = 'ServerDate'
            }

            # Path A: PS7+ HttpResponseHeaders.TryGetValues
            if ($response.Headers -is [System.Net.Http.Headers.HttpResponseHeaders]) {
                foreach ($h in $headerNames.GetEnumerator()) {
                    $vals = $null
                    # Try response headers
                    if ($response.Headers.TryGetValues($h.Key, [ref]$vals)) {
                        $detail.($h.Value) = $vals[0]
                    }
                }
                # Some headers may be in Content.Headers (PS7)
                if ($null -ne $response.Content -and $null -ne $response.Content.Headers) {
                    foreach ($h in $headerNames.GetEnumerator()) {
                        if (-not $detail.($h.Value)) {
                            $vals = $null
                            try {
                                if ($response.Content.Headers.TryGetValues($h.Key, [ref]$vals)) {
                                    $detail.($h.Value) = $vals[0]
                                }
                            } catch { }
                        }
                    }
                }
            }
            # Path B: PS5.1 WebHeaderCollection indexer
            elseif ($response.Headers -is [System.Net.WebHeaderCollection]) {
                foreach ($h in $headerNames.GetEnumerator()) {
                    $val = $response.Headers[$h.Key]
                    if ($val) { $detail.($h.Value) = $val }
                }
            }
            # Path C: Generic fallback - try indexer
            elseif ($null -ne $response.Headers) {
                foreach ($h in $headerNames.GetEnumerator()) {
                    try {
                        $val = $response.Headers[$h.Key]
                        if ($val) { $detail.($h.Value) = $val }
                    } catch { }
                }
            }
        }
    }
    catch {
        Write-Verbose "Get-ErrorDetail failed: $_"
        # Last resort: scan the full error record for AADSTS code
        $fullErr = $ErrorRecord | Out-String
        if ($fullErr -match 'AADSTS(\d+)') {
            $detail.ErrorCode = $Matches[1]
        }
    }

    return $detail
}

function Initialize-LoginFlow {
    <#
    .SYNOPSIS
        Starts a new OAuth2 authorize flow and extracts the flow token (sFT),
        context (sCtx), and login POST URL from the HTML response.
        This mimics what a browser does when navigating to the login page.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Initializing modern auth login flow..."

    $script:SessionCookies = [System.Net.CookieContainer]::new()

    $authorizeParams = @{
        client_id     = $ClientId
        response_type = 'code'
        redirect_uri  = $script:RedirectUri
        scope         = 'openid profile'
        response_mode = 'query'
        sso_reload    = 'true'
    }

    $queryString = ($authorizeParams.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$([Uri]::EscapeDataString($_.Value))"
    }) -join '&'

    $fullUrl = "$($script:AuthorizeUrl)?$queryString"

    try {
        $webParams = @{
            Uri                  = $fullUrl
            Method               = 'GET'
            UseBasicParsing      = $true
            MaximumRedirection   = 10
            ErrorAction          = 'Stop'
        }

        # PS7+ and PS5.1 handle cookies differently
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $webParams['SessionVariable'] = 'loginSession'
        }

        $response = Invoke-WebRequest @webParams

        $html = $response.Content

        # Extract $Config JSON block from the login page HTML
        # Microsoft embeds config as: $Config={"sFT":"...","sCtx":"...","urlPost":"...",...};
        if ($html -match '\$Config=({[^;]+});') {
            $configJson = $Matches[1] | ConvertFrom-Json

            $script:FlowToken   = $configJson.sFT
            $script:FlowContext  = $configJson.sCtx

            # urlPost may be relative or absolute
            if ($configJson.urlPost -match '^https://') {
                $script:LoginPostUrl = $configJson.urlPost
            }
            elseif ($configJson.urlPost) {
                $script:LoginPostUrl = "https://login.microsoftonline.com$($configJson.urlPost)"
            }

            Write-Verbose "Flow token obtained (length: $($script:FlowToken.Length))"
            Write-Verbose "Context obtained (length: $($script:FlowContext.Length))"
            Write-Verbose "Post URL: $($script:LoginPostUrl)"

            # Store session cookies for PS7+
            if ($loginSession) {
                $script:SessionCookies = $loginSession.Cookies
            }

            return $true
        }
        else {
            Write-Verbose "Could not extract \$Config from login page"
            # Try alternative pattern: JSON embedded differently
            if ($html -match '"sFT"\s*:\s*"([^"]+)"') {
                $script:FlowToken = $Matches[1]
            }
            if ($html -match '"sCtx"\s*:\s*"([^"]+)"') {
                $script:FlowContext = $Matches[1]
            }
            if ($html -match '"urlPost"\s*:\s*"([^"]+)"') {
                $postUrl = $Matches[1]
                if ($postUrl -match '^https://') {
                    $script:LoginPostUrl = $postUrl
                }
                else {
                    $script:LoginPostUrl = "https://login.microsoftonline.com$postUrl"
                }
            }

            if ($script:FlowToken -and $script:FlowContext) {
                Write-Verbose "Flow token extracted via fallback regex"
                return $true
            }

            Write-Warning "Failed to extract login flow tokens from authorize page"
            return $false
        }
    }
    catch {
        Write-Warning "Failed to initialize login flow: $_"
        return $false
    }
}

function Send-AuthAttempt {
    <#
    .SYNOPSIS
        Submits credentials via the modern auth browser login flow.
        POSTs to the login endpoint with flow token and context,
        exactly like a browser submitting the login form.

        This bypasses ROPC blocks, CA policies that block legacy auth,
        and Security Defaults restrictions.

        Results:
          50126 = Invalid password (counts toward lockout)
          50053 = Account locked (Smart Lockout triggered)
          50076 = MFA required (password was CORRECT, stopped at MFA)
          redirect = Password correct, proceeding to next step
    #>
    [CmdletBinding()]
    param(
        [string]$Password,
        [string]$Phase = 'main'
    )

    $result = [PSCustomObject]@{
        Timestamp       = (Get-Date).ToUniversalTime().ToString("o")
        Phase           = $Phase
        Password        = $Password
        HttpStatus      = $null
        ErrorCode       = $null
        ErrorType       = $null
        Description     = $null
        SubError        = $null
        ErrorCodes      = $null
        ServerTimestamp  = $null
        TraceId         = $null
        CorrelationId   = $null
        ErrorUri        = $null
        Datacenter      = $null
        RequestId       = $null
        ClientTelemetry = $null
        ClientRequestId = $null
        ServerDate      = $null
        LockedOut       = $false
        AuthMethod      = 'modern'
    }

    # Refresh flow token if not set (first attempt or expired)
    if (-not $script:FlowToken -or -not $script:FlowContext) {
        $initialized = Initialize-LoginFlow
        if (-not $initialized) {
            # Fallback to ROPC if modern auth flow initialization fails
            Write-Verbose "Modern auth init failed, falling back to ROPC"
            $result.AuthMethod = 'ropc-fallback'
            return Send-AuthAttemptROPC -Password $Password -Phase $Phase -Result $result
        }
    }

    # Build the login form POST body (mimics browser form submission)
    $formBody = @{
        login          = $UserEmail
        loginFmt       = $UserEmail
        passwd         = $Password
        ctx            = $script:FlowContext
        flowtoken      = $script:FlowToken
        type           = '11'
        LoginOptions   = '3'
        lrt            = ''
        lrtPartition   = ''
        hisRegion      = ''
        hisScaleUnit   = ''
        canary         = ''
        i13            = '0'
        i17            = ''
        i18            = ''
        i19            = ([DateTimeOffset](Get-Date)).ToUnixTimeMilliseconds().ToString()
    }

    try {
        $webParams = @{
            Uri               = $script:LoginPostUrl
            Method            = 'POST'
            Body              = $formBody
            ContentType       = 'application/x-www-form-urlencoded'
            UseBasicParsing   = $true
            MaximumRedirection = 0
            ErrorAction       = 'Stop'
        }

        $response = Invoke-WebRequest @webParams
        $result.HttpStatus = [int]$response.StatusCode
        $responseBody = $response.Content

        # Extract headers
        Extract-ResponseHeaders -Response $response -Result $result

        # Parse the response HTML for error codes or success indicators
        Parse-LoginResponse -ResponseBody $responseBody -Result $result
    }
    catch {
        $ex = $_
        $statusCode = $null

        # HTTP 302 redirect = password correct, moving to MFA or consent
        if ($ex.Exception.Response) {
            $statusCode = [int]$ex.Exception.Response.StatusCode
        }

        # Invoke-WebRequest with MaximumRedirection=0 throws on 302
        if ($statusCode -eq 302) {
            $result.HttpStatus = 302
            $location = $null
            try {
                if ($ex.Exception.Response.Headers -is [System.Net.Http.Headers.HttpResponseHeaders]) {
                    $vals = $null
                    if ($ex.Exception.Response.Headers.TryGetValues('Location', [ref]$vals)) {
                        $location = $vals[0]
                    }
                }
                else {
                    $location = $ex.Exception.Response.Headers['Location']
                }
            } catch { }

            if ($location -match 'error=') {
                # Error in redirect URL
                if ($location -match 'error_description=([^&]+)') {
                    $desc = [Uri]::UnescapeDataString($Matches[1])
                    $result.Description = $desc
                    if ($desc -match 'AADSTS(\d+)') {
                        $result.ErrorCode = $Matches[1]
                    }
                }
            }
            else {
                # Redirect without error = password correct, MFA next
                $result.ErrorCode   = 'mfa_redirect'
                $result.ErrorType   = 'interaction_required'
                $result.Description = 'Password correct - redirected to MFA challenge'
            }

            Extract-ResponseHeaders -ErrorResponse $ex.Exception.Response -Result $result
        }
        else {
            # Non-302 error - try to parse the response body
            $result.HttpStatus = if ($statusCode) { $statusCode } else { 0 }

            # Try to get response body
            $errorBody = $null
            if ($ex.ErrorDetails -and $ex.ErrorDetails.Message) {
                $errorBody = $ex.ErrorDetails.Message
            }
            elseif ($ex.Exception.Response) {
                try {
                    if ($ex.Exception.Response.PSObject.Properties['Content'] -and $ex.Exception.Response.Content) {
                        $errorBody = $ex.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                } catch { }
            }

            if ($errorBody) {
                Parse-LoginResponse -ResponseBody $errorBody -Result $result
            }
            elseif ($ex.Exception.Message -match 'AADSTS(\d+)') {
                $result.ErrorCode   = $Matches[1]
                $result.Description = $ex.Exception.Message
            }

            Extract-ResponseHeaders -ErrorResponse $ex.Exception.Response -Result $result
        }
    }

    # Detect lockout
    if ($result.ErrorCode -eq '50053') {
        $result.LockedOut = $true
    }

    # Refresh flow token for next attempt.
    # Parse-LoginResponse already extracts new sFT/sCtx from the response HTML.
    # Only re-initialize if the tokens are missing (expired or not returned).
    if (-not $script:FlowToken -or -not $script:FlowContext) {
        Write-Verbose "Flow token missing after attempt, re-initializing login flow"
        $null = Initialize-LoginFlow
    }

    return $result
}

function Send-AuthAttemptROPC {
    <#
    .SYNOPSIS
        Fallback ROPC method if modern auth flow initialization fails.
    #>
    [CmdletBinding()]
    param(
        [string]$Password,
        [string]$Phase,
        [PSCustomObject]$Result
    )

    $body = @{
        grant_type = "password"
        scope      = "openid"
        client_id  = $ClientId
        username   = $UserEmail
        password   = $Password
    }

    try {
        $null = Invoke-RestMethod -Uri $script:TokenEndpoint -Method Post -Body $body -ErrorAction Stop
        $Result.HttpStatus = 200
        $Result.ErrorCode  = 'success'
    }
    catch {
        $detail = Get-ErrorDetail -ErrorRecord $_

        $Result.HttpStatus      = $detail.HttpStatus
        $Result.ErrorCode       = $detail.ErrorCode
        $Result.ErrorType       = $detail.ErrorType
        $Result.Description     = $detail.Description
        $Result.SubError        = $detail.SubError
        $Result.ErrorCodes      = $detail.ErrorCodes
        $Result.ServerTimestamp  = $detail.Timestamp
        $Result.TraceId         = $detail.TraceId
        $Result.CorrelationId   = $detail.CorrelationId
        $Result.ErrorUri        = $detail.ErrorUri
        $Result.Datacenter      = $detail.Datacenter
        $Result.RequestId       = $detail.RequestId
        $Result.ClientTelemetry = $detail.ClientTelemetry
        $Result.ClientRequestId = $detail.ClientRequestId
        $Result.ServerDate      = $detail.ServerDate

        if ($detail.ErrorCode -eq '50053') {
            $Result.LockedOut = $true
        }
    }

    return $Result
}

function Parse-LoginResponse {
    <#
    .SYNOPSIS
        Parses the HTML/JSON response from the login POST for error codes,
        MFA requirements, or success indicators.
    #>
    [CmdletBinding()]
    param(
        [string]$ResponseBody,
        [PSCustomObject]$Result
    )

    if (-not $ResponseBody) { return }

    # Check for $Config JSON in response (error pages return this)
    if ($ResponseBody -match '\$Config=({[^;]+});') {
        try {
            $config = $Matches[1] | ConvertFrom-Json

            # Error code in config
            if ($config.PSObject.Properties['strServiceExceptionMessage']) {
                $Result.Description = $config.strServiceExceptionMessage
                if ($config.strServiceExceptionMessage -match 'AADSTS(\d+)') {
                    $Result.ErrorCode = $Matches[1]
                }
            }

            # Error code in sErrTxt
            if ($config.PSObject.Properties['sErrTxt'] -and $config.sErrTxt) {
                if (-not $Result.Description) { $Result.Description = $config.sErrTxt }
                if ($config.sErrTxt -match 'AADSTS(\d+)') {
                    $Result.ErrorCode = $Matches[1]
                }
            }

            # Error code in pgid (page ID indicates error type)
            if ($config.PSObject.Properties['pgid']) {
                $pgid = $config.pgid
                # ConvergedLoginPaginatedError = login error page
                # ConvergedTFA = MFA page (password was correct!)
                if ($pgid -match 'TFA|SecondFactor|Mfa') {
                    $Result.ErrorCode   = 'mfa_required'
                    $Result.ErrorType   = 'interaction_required'
                    $Result.Description = "Password correct - MFA challenge presented (page: $pgid)"
                }
                elseif ($pgid -match 'Error|Lockout') {
                    # Error page - code should already be extracted above
                    if (-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') {
                        $Result.ErrorType = 'login_error'
                    }
                }
            }

            # Extract arrCodes if present
            if ($config.PSObject.Properties['arrCodes'] -and $config.arrCodes.Count -gt 0) {
                $Result.ErrorCodes = ($config.arrCodes -join ',')
                if (-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') {
                    $Result.ErrorCode = $config.arrCodes[0].ToString()
                }
            }

            # Update flow token for next attempt
            if ($config.PSObject.Properties['sFT'] -and $config.sFT) {
                $script:FlowToken = $config.sFT
            }
            if ($config.PSObject.Properties['sCtx'] -and $config.sCtx) {
                $script:FlowContext = $config.sCtx
            }

            # Correlation ID from config
            if ($config.PSObject.Properties['correlationId'] -and $config.correlationId) {
                $Result.CorrelationId = $config.correlationId
            }
            # Session ID / request ID
            if ($config.PSObject.Properties['sessionId'] -and $config.sessionId) {
                $Result.RequestId = $config.sessionId
            }
            # Timestamp from config
            if ($config.PSObject.Properties['serverDetails'] -and $config.serverDetails) {
                $sd = $config.serverDetails
                if ($sd.PSObject.Properties['slc'] -and $sd.slc) {
                    $Result.Datacenter = $sd.slc
                }
                if ($sd.PSObject.Properties['dc'] -and $sd.dc) {
                    $Result.Datacenter = $sd.dc
                }
            }
            # sFTTag often contains datacenter info (e.g., "cpim_sft:ESTSWUS2...")
            if (-not $Result.Datacenter -and $config.PSObject.Properties['sFTTag'] -and $config.sFTTag) {
                if ($config.sFTTag -match '(ESTS\w+)') {
                    $Result.Datacenter = $Matches[1]
                }
            }
            # Server timestamp
            if ($config.PSObject.Properties['sServerTime'] -and $config.sServerTime) {
                $Result.ServerTimestamp = $config.sServerTime
            }
            # Error type / sub-error
            if (-not $Result.ErrorType -and $config.PSObject.Properties['sErrorCode'] -and $config.sErrorCode) {
                $Result.ErrorType = "error_code:$($config.sErrorCode)"
                if (-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') {
                    $Result.ErrorCode = $config.sErrorCode.ToString()
                }
            }
            # Trace ID
            if (-not $Result.TraceId -and $config.PSObject.Properties['sRequestId'] -and $config.sRequestId) {
                $Result.TraceId = $config.sRequestId
            }
        }
        catch {
            Write-Verbose "Failed to parse \$Config from response: $_"
        }
    }

    # Fallback: scan raw HTML for AADSTS codes
    if ((-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') -and $ResponseBody -match 'AADSTS(\d+)') {
        $Result.ErrorCode = $Matches[1]
    }

    # Fallback: check for locked account text
    if ((-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') -and
        $ResponseBody -match 'temporarily locked|prevent unauthorized use') {
        $Result.ErrorCode   = '50053'
        $Result.Description = 'Account temporarily locked (detected from page text)'
    }

    # Fallback: check for invalid password text
    if ((-not $Result.ErrorCode -or $Result.ErrorCode -eq 'unknown') -and
        $ResponseBody -match "account or password is incorrect|password is incorrect") {
        $Result.ErrorCode   = '50126'
        $Result.Description = 'Invalid password (detected from page text)'
    }
}

function Extract-ResponseHeaders {
    <#
    .SYNOPSIS
        Extracts relevant headers from Invoke-WebRequest response or
        HttpResponseMessage (error path). Handles PS5.1 and PS7+ differences
        and case-sensitive header lookups.
    #>
    [CmdletBinding()]
    param(
        $Response,
        $ErrorResponse,
        [PSCustomObject]$Result
    )

    $headers = $null

    if ($Response -and $Response.Headers) {
        $headers = $Response.Headers
    }
    elseif ($ErrorResponse -and $ErrorResponse.Headers) {
        $headers = $ErrorResponse.Headers
    }

    if ($null -eq $headers) { return }

    # Target headers (lowercase keys for case-insensitive matching)
    $headerMap = @{
        'x-ms-ests-server'  = 'Datacenter'
        'x-ms-request-id'   = 'RequestId'
        'x-ms-clitelem'     = 'ClientTelemetry'
        'client-request-id' = 'ClientRequestId'
        'date'              = 'ServerDate'
    }

    # Strategy: try direct access first, then case-insensitive scan

    # PS7+ HttpResponseHeaders (from error responses)
    if ($headers -is [System.Net.Http.Headers.HttpResponseHeaders]) {
        foreach ($h in $headerMap.GetEnumerator()) {
            $vals = $null
            if ($headers.TryGetValues($h.Key, [ref]$vals)) {
                $Result.($h.Value) = $vals[0]
            }
        }
        # Also check Content.Headers for some headers
        if ($ErrorResponse -and $ErrorResponse.PSObject.Properties['Content'] -and
            $null -ne $ErrorResponse.Content -and $null -ne $ErrorResponse.Content.Headers) {
            foreach ($h in $headerMap.GetEnumerator()) {
                if (-not $Result.($h.Value)) {
                    $vals = $null
                    try {
                        if ($ErrorResponse.Content.Headers.TryGetValues($h.Key, [ref]$vals)) {
                            $Result.($h.Value) = $vals[0]
                        }
                    } catch { }
                }
            }
        }
        return
    }

    # PS5.1 WebHeaderCollection
    if ($headers -is [System.Net.WebHeaderCollection]) {
        foreach ($h in $headerMap.GetEnumerator()) {
            $val = $headers[$h.Key]
            if ($val) { $Result.($h.Value) = $val }
        }
        return
    }

    # PS7 Invoke-WebRequest returns Dictionary<string,IEnumerable<string>>
    # Keys may be case-sensitive, so we do case-insensitive matching
    if ($headers -is [System.Collections.IDictionary]) {
        # Build a lowercase lookup of actual header keys
        $lowerMap = @{}
        foreach ($key in $headers.Keys) {
            $lowerMap[$key.ToLower()] = $key
        }

        foreach ($h in $headerMap.GetEnumerator()) {
            $lookupKey = $h.Key.ToLower()
            if ($lowerMap.ContainsKey($lookupKey)) {
                $actualKey = $lowerMap[$lookupKey]
                $val = $headers[$actualKey]
                if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $Result.($h.Value) = ($val | Select-Object -First 1)
                }
                elseif ($val) {
                    $Result.($h.Value) = $val
                }
            }
        }
        return
    }

    # Generic fallback: try direct indexer and case-insensitive scan
    foreach ($h in $headerMap.GetEnumerator()) {
        try {
            $val = $headers[$h.Key]
            if ($val) {
                if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $Result.($h.Value) = ($val | Select-Object -First 1)
                }
                else {
                    $Result.($h.Value) = $val
                }
            }
        } catch { }
    }
}

function Write-AttemptLine {
    param(
        [int]$Index,
        [int]$Total,
        [PSCustomObject]$Result,
        [int]$FailedCount,
        [int]$LockoutCt,
        [bool]$IsFirstLockout
    )

    $ts       = Get-Date -Format "HH:mm:ss"
    $desc     = Get-ErrorDescription -Code $Result.ErrorCode
    $subErr   = if ($Result.SubError) { $Result.SubError } else { '-' }

    Write-Host "  [$ts] " -NoNewline
    Write-Host "[$Index/$Total]" -ForegroundColor Cyan -NoNewline

    switch ($Result.ErrorCode) {
        'success' {
            Write-Host " SUCCESS " -ForegroundColor Black -BackgroundColor Yellow -NoNewline
            Write-Host " Unexpected authentication success" -ForegroundColor Yellow
        }
        { $_ -eq 'mfa_required' -or $_ -eq 'mfa_redirect' } {
            Write-Host " MFA     " -ForegroundColor Black -BackgroundColor Green -NoNewline
            Write-Host " HTTP $($Result.HttpStatus) | Password CORRECT | MFA challenge presented" -ForegroundColor Green
        }
        '50053' {
            if ($IsFirstLockout) {
                Write-Host " LOCKED  " -ForegroundColor White -BackgroundColor Red -NoNewline
                Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc | First lockout at attempt $Index" -ForegroundColor Red
            }
            else {
                Write-Host " LOCKED  " -ForegroundColor White -BackgroundColor DarkRed -NoNewline
                Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc | Lockout $LockoutCt" -ForegroundColor DarkRed
            }
        }
        '50126' {
            Write-Host " FAILED  " -ForegroundColor White -BackgroundColor DarkGray -NoNewline
            Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc | Failed: $FailedCount/$LockoutThreshold" -ForegroundColor Gray
        }
        '50057' {
            Write-Host " DISABLED" -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
            Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc - stopping test" -ForegroundColor Magenta
        }
        '50076' {
            Write-Host " CA/MFA  " -ForegroundColor White -BackgroundColor DarkYellow -NoNewline
            Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc - stopping test" -ForegroundColor Yellow
        }
        default {
            Write-Host " ERROR   " -ForegroundColor White -BackgroundColor DarkGray -NoNewline
            Write-Host " HTTP $($Result.HttpStatus) | AADSTS$($Result.ErrorCode) | $desc" -ForegroundColor Gray
        }
    }

    # Helper: show '-' for null/empty fields
    $fType    = if ($Result.ErrorType)       { $Result.ErrorType }       else { '-' }
    $fDC      = if ($Result.Datacenter)      { $Result.Datacenter }      else { '-' }
    $fTrace   = if ($Result.TraceId)         { $Result.TraceId }         else { '-' }
    $fCorr    = if ($Result.CorrelationId)   { $Result.CorrelationId }   else { '-' }
    $fReqId   = if ($Result.RequestId)       { $Result.RequestId }       else { '-' }
    $fDate    = if ($Result.ServerDate)       { $Result.ServerDate }      else { '-' }
    $fTelem   = if ($Result.ClientTelemetry) { $Result.ClientTelemetry } else { '-' }

    # Line 2: Extended details
    Write-Host "             " -NoNewline
    Write-Host "Type: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fType" -ForegroundColor DarkCyan -NoNewline
    Write-Host " | SubError: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$subErr" -ForegroundColor DarkCyan -NoNewline
    Write-Host " | DC: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fDC" -ForegroundColor DarkCyan
    # Line 3: Trace & correlation
    Write-Host "             " -NoNewline
    Write-Host "TraceId: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fTrace" -ForegroundColor DarkCyan -NoNewline
    Write-Host " | CorrelationId: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fCorr" -ForegroundColor DarkCyan
    # Line 4: Request ID, server date, telemetry
    Write-Host "             " -NoNewline
    Write-Host "RequestId: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fReqId" -ForegroundColor DarkCyan -NoNewline
    Write-Host " | ServerDate: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fDate" -ForegroundColor DarkCyan -NoNewline
    Write-Host " | Telemetry: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$fTelem" -ForegroundColor DarkCyan
}

#endregion

#region Pre-flight: Hybrid Configuration Compliance

function Test-HybridCompliance {
    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host "  HYBRID CONFIGURATION COMPLIANCE ($DeploymentType)" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Log "=========================================="
    Write-Log "HYBRID CONFIGURATION COMPLIANCE ($DeploymentType)"
    Write-Log "=========================================="

    $compliancePass = $true

    if ($DeploymentType -eq 'PTA') {
        Write-Section "PTA: Threshold Compliance" "Yellow"
        Write-Host "  Entra Threshold:  $LockoutThreshold"
        Write-Host "  AD DS Threshold:  $ADLockoutThreshold"
        Write-Host "  Ratio:            1:$([math]::Round($ADLockoutThreshold / $LockoutThreshold, 1))"
        Write-Log "Entra Threshold: $LockoutThreshold | AD DS Threshold: $ADLockoutThreshold | Ratio: 1:$([math]::Round($ADLockoutThreshold / $LockoutThreshold, 1))"

        # Check: Entra threshold < AD DS threshold
        if ($LockoutThreshold -ge $ADLockoutThreshold) {
            Write-Check 'FAIL' "Entra threshold ($LockoutThreshold) must be LESS than AD DS threshold ($ADLockoutThreshold)"
            $compliancePass = $false
        }
        else {
            Write-Check 'PASS' "Entra threshold ($LockoutThreshold) < AD DS threshold ($ADLockoutThreshold)"
        }

        # Check: AD DS threshold >= 2x Entra threshold
        if ($ADLockoutThreshold -ge ($LockoutThreshold * 2)) {
            Write-Check 'PASS' "AD DS threshold is $([math]::Round($ADLockoutThreshold / $LockoutThreshold, 1))x Entra (recommended: 2-3x)"
        }
        else {
            Write-Check 'WARN' "AD DS threshold ($ADLockoutThreshold) is less than 2x Entra ($($LockoutThreshold * 2)). Microsoft recommends 2-3x."
            $compliancePass = $false
        }

        Write-Section "PTA: Duration Compliance" "Yellow"
        $adDurationSec = $ADLockoutDurationMin * 60
        Write-Host "  Entra Duration:   ${LockoutDurationSec}s"
        Write-Host "  AD DS Duration:   ${ADLockoutDurationMin}m (${adDurationSec}s)"
        Write-Log "Entra Duration: ${LockoutDurationSec}s | AD DS Duration: ${ADLockoutDurationMin}m (${adDurationSec}s)"

        # Check: Entra duration > AD DS duration
        if ($LockoutDurationSec -gt $adDurationSec) {
            Write-Check 'PASS' "Entra duration (${LockoutDurationSec}s) > AD DS duration (${adDurationSec}s)"
        }
        else {
            Write-Check 'FAIL' "Entra duration (${LockoutDurationSec}s) must be LONGER than AD DS duration (${adDurationSec}s)"
            $compliancePass = $false
        }

        Write-Section "PTA: On-Premises Protection" "Yellow"
        $marginAttempts = $ADLockoutThreshold - $LockoutThreshold
        Write-Check 'INFO' "Safety margin: $marginAttempts attempts before on-prem AD locks out"
        Write-Check 'INFO' "Hash tracking NOT available with PTA (auth happens on-premises)"
        Write-Check 'INFO' "Same bad password WILL increment lockout counter with PTA"
    }
    elseif ($DeploymentType -eq 'PHS') {
        Write-Section "PHS: Configuration" "Cyan"
        Write-Host "  Entra Threshold:  $LockoutThreshold"
        Write-Host "  Entra Duration:   ${LockoutDurationSec}s"
        Write-Log "Entra Threshold: $LockoutThreshold | Entra Duration: ${LockoutDurationSec}s"

        Write-Check 'INFO' "Hash tracking IS available with PHS (last 3 bad hashes tracked)"
        Write-Check 'INFO' "Same bad password should NOT increment lockout counter"
        Write-Check 'INFO' "Hash tracking test will run before main lockout test"

        if ($PSBoundParameters.ContainsKey('ADLockoutThreshold')) {
            Write-Section "PHS: Optional AD DS Cross-Check" "Cyan"
            Write-Host "  AD DS Threshold:  $ADLockoutThreshold"
            if ($LockoutThreshold -lt $ADLockoutThreshold) {
                Write-Check 'PASS' "Entra threshold ($LockoutThreshold) < AD DS threshold ($ADLockoutThreshold) - additional protection"
            }
            else {
                Write-Check 'INFO' "Entra threshold ($LockoutThreshold) >= AD DS threshold ($ADLockoutThreshold) - AD may lock first on hash-miss"
            }
        }
    }
    else {
        Write-Section "Cloud-Only: Configuration" "Cyan"
        Write-Host "  Entra Threshold:  $LockoutThreshold"
        Write-Host "  Entra Duration:   ${LockoutDurationSec}s"
        Write-Check 'INFO' "No on-premises AD DS to protect"
        Write-Check 'INFO' "Hash tracking active (last 3 bad password hashes)"
    }

    Write-Host ""
    if ($compliancePass) {
        Write-Host "  COMPLIANCE: " -NoNewline
        Write-Host "PASSED" -ForegroundColor Green
        Write-Log "Hybrid compliance check: PASSED" 'PASS'
    }
    else {
        Write-Host "  COMPLIANCE: " -NoNewline
        Write-Host "FAILED - Review settings above" -ForegroundColor Red
        Write-Log "Hybrid compliance check: FAILED" 'FAIL'
    }
    Write-Host "  ==========================================" -ForegroundColor White

    return $compliancePass
}

#endregion

#region Phase: PHS Hash Tracking Test

function Test-HashTracking {
    Write-Section "PHS HASH TRACKING TEST" "Magenta"
    Write-Host "  Sending the SAME bad password 5 times to verify hash tracking." -ForegroundColor Gray
    Write-Host "  Expected: counter should NOT increment (last 3 hashes tracked)." -ForegroundColor Gray
    Write-Host ""
    Write-Log "=========================================="
    Write-Log "PHS HASH TRACKING TEST"
    Write-Log "=========================================="

    $hashResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $staticPassword = New-RandomPassword -Length 16
    $lockoutSeen = $false

    for ($h = 1; $h -le 5; $h++) {
        Write-Progress -Activity "Hash Tracking Test" `
            -Status "Sending same password: attempt $h of 5" `
            -PercentComplete (($h / 5) * 100)

        $r = Send-AuthAttempt -Password $staticPassword -Phase 'hash-tracking'

        $ts = Get-Date -Format "HH:mm:ss"
        $desc = Get-ErrorDescription -Code $r.ErrorCode
        Write-Host "  [$ts] " -NoNewline
        Write-Host "[Hash $h/5]" -ForegroundColor Magenta -NoNewline

        if ($r.LockedOut) {
            Write-Host " LOCKED  " -ForegroundColor White -BackgroundColor Red -NoNewline
            Write-Host " $desc - hash tracking may not be working" -ForegroundColor Red
            $lockoutSeen = $true
        }
        else {
            Write-Host " HTTP $($r.HttpStatus) | AADSTS$($r.ErrorCode) | $desc" -ForegroundColor Gray
        }

        $hashResults.Add($r)

        if ($h -lt 5) { Start-Sleep -Seconds $DelaySec }
    }

    Write-Progress -Activity "Hash Tracking Test" -Completed

    # Then send a DIFFERENT password to confirm counter does increment
    Write-Host ""
    Write-Host "  Sending a DIFFERENT bad password to confirm counter increments..." -ForegroundColor Gray
    Start-Sleep -Seconds $DelaySec

    $diffPassword = New-RandomPassword -Length 16
    $diffResult = Send-AuthAttempt -Password $diffPassword -Phase 'hash-tracking-diff'
    $hashResults.Add($diffResult)

    $ts = Get-Date -Format "HH:mm:ss"
    $desc = Get-ErrorDescription -Code $diffResult.ErrorCode
    Write-Host "  [$ts] " -NoNewline
    Write-Host "[Diff Pwd]" -ForegroundColor Magenta -NoNewline
    Write-Host " HTTP $($diffResult.HttpStatus) | AADSTS$($diffResult.ErrorCode) | $desc" -ForegroundColor Gray

    # Analysis
    Write-Host ""
    $samePasswordLockouts = ($hashResults | Where-Object { $_.Phase -eq 'hash-tracking' -and $_.LockedOut }).Count

    if ($samePasswordLockouts -eq 0 -and -not $lockoutSeen) {
        Write-Check 'PASS' "Same password sent 5 times without triggering lockout - hash tracking confirmed"
    }
    else {
        Write-Check 'FAIL' "Same password triggered lockout ($samePasswordLockouts times) - hash tracking may be disabled or not working"
        Write-Check 'INFO' "This is expected if PTA is actually in use (hash tracking only works with PHS)"
    }

    Write-Host ""
    return $hashResults.ToArray()
}

#endregion

#region Phase: Main Lockout Test

function Invoke-EntraIDDOS {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param()

    if (-not $PSCmdlet.ShouldProcess($UserEmail, "Send $MaxAttempts authentication attempts to validate Smart Lockout")) {
        return
    }

    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host "  SMART LOCKOUT TEST ($DeploymentType)" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Log "=========================================="
    Write-Log "SMART LOCKOUT TEST ($DeploymentType)"
    Write-Log "=========================================="
    Write-Log "Tenant:           $TenantId"
    Write-Log "Target User:      $UserEmail"
    Write-Log "Deployment:       $DeploymentType"
    Write-Log "Lockout Threshold: $LockoutThreshold"
    Write-Log "Lockout Duration: ${LockoutDurationSec}s"
    Write-Log "Max Attempts:     $MaxAttempts"
    Write-Log "Delay:            ${DelaySec}s"
    Write-Log "Client ID:        $ClientId"
    Write-Log "Log File:         $($script:LogFile)"

    Write-Host "  Tenant:           $TenantId"
    Write-Host "  Target User:      $UserEmail"
    Write-Host "  Deployment:       " -NoNewline
    switch ($DeploymentType) {
        'PTA' { Write-Host "Pass-through Authentication" -ForegroundColor Yellow }
        'PHS' { Write-Host "Password Hash Sync" -ForegroundColor Cyan }
        default { Write-Host "Cloud-Only" -ForegroundColor Green }
    }
    Write-Host "  Threshold:        $LockoutThreshold"
    Write-Host "  Duration:         ${LockoutDurationSec}s"
    Write-Host "  Max Attempts:     $MaxAttempts"
    Write-Host "  Delay:            ${DelaySec}s"
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host ""

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $failedAttempts = 0
    $lockoutCount = 0
    $lockoutDetected = $false
    $firstLockoutAttempt = $null
    $datacenterMap = @{}

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    for ($i = 1; $i -le $MaxAttempts; $i++) {

        # Progress bar
        $pctComplete  = [math]::Round((($i - 1) / $MaxAttempts) * 100)
        $elapsed      = $stopwatch.Elapsed
        $avgPerAttempt = if ($i -gt 1) { $elapsed.TotalSeconds / ($i - 1) } else { 0 }
        $remaining    = [TimeSpan]::FromSeconds($avgPerAttempt * ($MaxAttempts - $i + 1))

        $lockoutStatus = if ($lockoutDetected) { " | LOCKED (x$lockoutCount)" } else { "" }
        $progressParams = @{
            Activity        = "Smart Lockout Test ($DeploymentType) - $UserEmail"
            Status          = "Attempt $i of $MaxAttempts | Failed: $failedAttempts/$LockoutThreshold$lockoutStatus | Elapsed: $($elapsed.ToString('mm\:ss')) | ETA: $($remaining.ToString('mm\:ss'))"
            PercentComplete = $pctComplete
            CurrentOperation = "Sending authentication request"
        }
        Write-Progress @progressParams

        $password = New-RandomPassword -Length 16
        $attemptResult = Send-AuthAttempt -Password $password -Phase 'lockout-test'
        $attemptResult | Add-Member -NotePropertyName 'Attempt' -NotePropertyValue $i

        # Track datacenter distribution
        if ($attemptResult.Datacenter) {
            $dc = $attemptResult.Datacenter -replace '\s.*', ''
            if ($datacenterMap.ContainsKey($dc)) { $datacenterMap[$dc]++ }
            else { $datacenterMap[$dc] = 1 }
        }

        if ($attemptResult.ErrorCode -eq '50053') {
            $lockoutCount++
            $attemptResult.LockedOut = $true

            $isFirst = $false
            if (-not $lockoutDetected) {
                $lockoutDetected = $true
                $firstLockoutAttempt = $i
                $isFirst = $true
            }

            Write-AttemptLine -Index $i -Total $MaxAttempts -Result $attemptResult `
                -FailedCount $failedAttempts -LockoutCt $lockoutCount -IsFirstLockout $isFirst

            if ($isFirst) {
                Write-Log "FIRST LOCKOUT at attempt $i after $failedAttempts failed attempts" 'ALERT'
            }
        }
        elseif ($attemptResult.ErrorCode -eq '50126') {
            $failedAttempts++
            Write-AttemptLine -Index $i -Total $MaxAttempts -Result $attemptResult `
                -FailedCount $failedAttempts -LockoutCt $lockoutCount -IsFirstLockout $false
        }
        elseif ($attemptResult.ErrorCode -eq '50057' -or $attemptResult.ErrorCode -eq '50076') {
            Write-AttemptLine -Index $i -Total $MaxAttempts -Result $attemptResult `
                -FailedCount $failedAttempts -LockoutCt $lockoutCount -IsFirstLockout $false
            Write-Log "Terminal error $($attemptResult.ErrorCode) - stopping" 'ERROR'
            $results.Add($attemptResult)
            break
        }
        else {
            $failedAttempts++
            Write-AttemptLine -Index $i -Total $MaxAttempts -Result $attemptResult `
                -FailedCount $failedAttempts -LockoutCt $lockoutCount -IsFirstLockout $false
        }

        Write-Log ("Attempt {0}/{1} | HTTP {2} | AADSTS{3} | DC: {4}" -f $i, $MaxAttempts, $attemptResult.HttpStatus, $attemptResult.ErrorCode, $attemptResult.Datacenter)

        $results.Add($attemptResult)

        if ($i -lt $MaxAttempts) {
            $lockoutStatus = if ($lockoutDetected) { " | LOCKED (x$lockoutCount)" } else { "" }
            Write-Progress -Activity "Smart Lockout Test ($DeploymentType) - $UserEmail" `
                -Status "Attempt $i of $MaxAttempts | Failed: $failedAttempts/$LockoutThreshold$lockoutStatus | Waiting ${DelaySec}s..." `
                -PercentComplete ([math]::Round(($i / $MaxAttempts) * 100)) `
                -CurrentOperation "Throttle delay before next attempt"

            Start-Sleep -Seconds $DelaySec
        }
    }

    $stopwatch.Stop()
    Write-Progress -Activity "Smart Lockout Test ($DeploymentType) - $UserEmail" -Completed

    return @{
        Results           = $results.ToArray()
        FailedAttempts    = $failedAttempts
        LockoutCount      = $lockoutCount
        LockoutDetected   = $lockoutDetected
        FirstLockout      = $firstLockoutAttempt
        DatacenterMap     = $datacenterMap
        ElapsedTime       = $stopwatch.Elapsed
    }
}

#endregion

#region Summary & Analysis

function Write-TestSummary {
    param(
        [hashtable]$TestData,
        [PSCustomObject[]]$HashTrackResults
    )

    $results         = $TestData.Results
    $failedAttempts  = $TestData.FailedAttempts
    $lockoutCount    = $TestData.LockoutCount
    $lockoutDetected = $TestData.LockoutDetected
    $firstLockout    = $TestData.FirstLockout
    $datacenterMap   = $TestData.DatacenterMap
    $elapsed         = $TestData.ElapsedTime

    $invalidPwdCount = ($results | Where-Object { $_.ErrorCode -eq '50126' }).Count
    $lockedResults   = $results | Where-Object { $_.LockedOut -eq $true }
    $lastLockout     = $lockedResults | Select-Object -Last 1

    # ── Results Summary ──
    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host "  RESULTS SUMMARY ($DeploymentType)" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Log "=========================================="
    Write-Log "RESULTS SUMMARY ($DeploymentType)"
    Write-Log "=========================================="

    Write-Host "  Total Attempts:     $($results.Count)"
    Write-Host "  Invalid Passwords:  $invalidPwdCount" -ForegroundColor Gray
    Write-Host "  Lockout Responses:  " -NoNewline
    if ($lockoutCount -gt 0) { Write-Host "$lockoutCount" -ForegroundColor Red }
    else { Write-Host "0" -ForegroundColor Green }
    Write-Host "  Elapsed Time:       $($elapsed.ToString('mm\:ss'))"

    Write-Log "Total Attempts: $($results.Count) | Invalid Passwords: $invalidPwdCount | Lockouts: $lockoutCount | Elapsed: $($elapsed.ToString('mm\:ss'))"

    # ── Datacenter Distribution ──
    if ($datacenterMap.Count -gt 0) {
        Write-Section "DATACENTER DISTRIBUTION" "DarkCyan"
        Write-Check 'INFO' "Requests routed across $($datacenterMap.Count) datacenter(s)"
        foreach ($dc in $datacenterMap.GetEnumerator() | Sort-Object Value -Descending) {
            $pct = [math]::Round(($dc.Value / $results.Count) * 100, 1)
            Write-Host "    $($dc.Key): $($dc.Value) requests ($pct%)" -ForegroundColor DarkCyan
        }
        if ($datacenterMap.Count -gt 1) {
            Write-Check 'INFO' "Multi-DC routing detected. Lockout state syncs across DCs with slight variance per Microsoft docs."
        }
        Write-Log "Datacenters: $($datacenterMap.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" } | Join-String -Separator ', ')"
    }

    # ── Lockout Analysis ──
    if ($lockoutDetected) {
        $lockoutPct = [math]::Round(($lockoutCount / $results.Count) * 100, 1)

        Write-Section "LOCKOUT ANALYSIS" "Yellow"
        Write-Host "  First Lockout:      Attempt $firstLockout"
        Write-Host "  Last Lockout:       Attempt $($lastLockout.Attempt)"
        Write-Host "  Lockout Rate:       $lockoutPct% of total attempts"
        Write-Host "  Threshold Config:   $LockoutThreshold"

        Write-Log "First Lockout: $firstLockout | Last Lockout: $($lastLockout.Attempt) | Rate: $lockoutPct%"

        Write-Host ""
        if ($firstLockout -le ($LockoutThreshold + 1)) {
            Write-Check 'PASS' "Smart Lockout activated at attempt $firstLockout (threshold: $LockoutThreshold)"
        }
        else {
            Write-Check 'WARN' "Lockout at attempt $firstLockout, above threshold ($LockoutThreshold) - review policy or DC variance"
        }

        # Unlock detection
        $postLockoutAttempts = $results | Where-Object { $_.Attempt -gt $firstLockout }
        $postLockoutUnlocked = $postLockoutAttempts | Where-Object { $_.ErrorCode -eq '50126' }

        if ($postLockoutUnlocked.Count -gt 0) {
            $unlockAttempt = ($postLockoutUnlocked | Select-Object -First 1).Attempt
            $lockoutDurationActual = ($unlockAttempt - $firstLockout) * $DelaySec
            Write-Check 'INFO' "Account unlocked at attempt $unlockAttempt (~${lockoutDurationActual}s after first lockout)"

            # Lockout escalation: check for re-lockout after unlock
            $postUnlockLockouts = $results | Where-Object { $_.Attempt -gt $unlockAttempt -and $_.LockedOut }
            if ($postUnlockLockouts.Count -gt 0) {
                $reLockAttempt = ($postUnlockLockouts | Select-Object -First 1).Attempt
                Write-Check 'INFO' "Re-locked at attempt $reLockAttempt (lockout escalation - duration increases per Microsoft docs)"
            }
        }
        elseif ($postLockoutAttempts.Count -gt 0) {
            Write-Check 'INFO' "Account remained locked for all $($postLockoutAttempts.Count) attempts after lockout"
        }
    }
    else {
        Write-Host ""
        Write-Check 'FAIL' "No lockout detected after $($results.Count) attempts (expected at $LockoutThreshold)"
    }

    # ── PTA-Specific Analysis ──
    if ($DeploymentType -eq 'PTA') {
        Write-Section "PTA: ON-PREMISES PROTECTION ANALYSIS" "Yellow"

        if ($lockoutDetected) {
            Write-Check 'PASS' "Entra Smart Lockout activated BEFORE on-prem AD threshold ($ADLockoutThreshold)"
            $adMargin = $ADLockoutThreshold - $firstLockout
            Write-Check 'INFO' "On-prem AD protected with $adMargin attempt margin"

            if ($firstLockout -le $LockoutThreshold) {
                Write-Check 'PASS' "Brute-force attacks will be filtered by Entra before reaching AD DS"
            }
        }
        else {
            Write-Check 'FAIL' "Entra did not lock out - on-prem AD may receive all $($results.Count) attempts"
            if ($results.Count -ge $ADLockoutThreshold) {
                Write-Check 'FAIL' "CRITICAL: On-prem AD DS account may be locked out ($($results.Count) >= $ADLockoutThreshold)"
            }
            else {
                Write-Check 'WARN' "On-prem AD not yet at threshold ($($results.Count) < $ADLockoutThreshold) but Entra should have locked first"
            }
        }

        Write-Check 'INFO' "PTA reminder: each unique bad password counts toward lockout (no hash tracking)"
    }

    # ── PHS Hash Tracking Summary ──
    if ($DeploymentType -eq 'PHS' -and $null -ne $HashTrackResults -and $HashTrackResults.Count -gt 0) {
        Write-Section "PHS: HASH TRACKING SUMMARY" "Magenta"
        $hashLockouts = ($HashTrackResults | Where-Object { $_.LockedOut }).Count
        $hashTotal    = ($HashTrackResults | Where-Object { $_.Phase -eq 'hash-tracking' }).Count

        if ($hashLockouts -eq 0) {
            Write-Check 'PASS' "Hash tracking confirmed: $hashTotal identical passwords sent, 0 lockouts"
            Write-Check 'INFO' "Smart Lockout tracks last 3 bad password hashes in the cloud"
        }
        else {
            Write-Check 'FAIL' "Hash tracking failed: $hashLockouts lockout(s) from $hashTotal identical passwords"
            Write-Check 'WARN' "Verify PHS is active (not PTA). Hash tracking only works with cloud-side validation."
        }
    }

    # ── Final Verdict ──
    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor White
    Write-Host "  FINAL VERDICT" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor White

    $allPass = $true

    if (-not $lockoutDetected) {
        Write-Check 'FAIL' "Smart Lockout did not activate"
        $allPass = $false
    }
    elseif ($firstLockout -gt ($LockoutThreshold + 2)) {
        Write-Check 'WARN' "Lockout activated late (attempt $firstLockout vs threshold $LockoutThreshold)"
        $allPass = $false
    }
    else {
        Write-Check 'PASS' "Smart Lockout threshold validated"
    }

    if ($DeploymentType -eq 'PTA') {
        if ($LockoutThreshold -ge $ADLockoutThreshold) {
            Write-Check 'FAIL' "PTA MISCONFIGURED: Entra threshold >= AD DS threshold"
            $allPass = $false
        }
        elseif ($ADLockoutThreshold -lt ($LockoutThreshold * 2)) {
            Write-Check 'WARN' "PTA: AD DS threshold below recommended 2x multiplier"
        }
        else {
            Write-Check 'PASS' "PTA threshold relationship validated"
        }

        $adDurSec = $ADLockoutDurationMin * 60
        if ($LockoutDurationSec -le $adDurSec) {
            Write-Check 'FAIL' "PTA MISCONFIGURED: Entra duration <= AD DS duration"
            $allPass = $false
        }
        else {
            Write-Check 'PASS' "PTA duration relationship validated"
        }
    }

    if ($DeploymentType -eq 'PHS' -and $null -ne $HashTrackResults) {
        $hashLockouts = ($HashTrackResults | Where-Object { $_.LockedOut }).Count
        if ($hashLockouts -eq 0) {
            Write-Check 'PASS' "PHS hash tracking validated"
        }
        else {
            Write-Check 'FAIL' "PHS hash tracking not working"
            $allPass = $false
        }
    }

    Write-Host ""
    if ($allPass) {
        Write-Host "  OVERALL: " -NoNewline
        Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
        Write-Log "OVERALL: ALL CHECKS PASSED" 'PASS'
    }
    else {
        Write-Host "  OVERALL: " -NoNewline
        Write-Host "ONE OR MORE CHECKS FAILED" -ForegroundColor Red
        Write-Log "OVERALL: ONE OR MORE CHECKS FAILED" 'FAIL'
    }
    Write-Host "  ==========================================" -ForegroundColor White
}

#endregion

#region Execution

# 1. Hybrid compliance pre-flight
$complianceResult = Test-HybridCompliance

# 2. PHS hash tracking test (before main lockout test)
$hashTrackResults = $null
if ($DeploymentType -eq 'PHS') {
    $hashTrackResults = Test-HashTracking
}

# 3. Main lockout test
$testData = Invoke-EntraIDDOS

if ($null -eq $testData) { return }

# 4. Summary & analysis
Write-TestSummary -TestData $testData -HashTrackResults $hashTrackResults

# 5. Export all results
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($null -ne $hashTrackResults) {
    $idx = 0
    foreach ($r in $hashTrackResults) {
        $idx++
        $r | Add-Member -NotePropertyName 'Attempt' -NotePropertyValue $idx -ErrorAction SilentlyContinue
        $allResults.Add($r)
    }
}

foreach ($r in $testData.Results) {
    $allResults.Add($r)
}

$allResults | Export-Csv -Path $script:CsvFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "  CSV exported: $($script:CsvFile)" -ForegroundColor DarkGray
Write-Host "  Log file:     $($script:LogFile)" -ForegroundColor DarkGray
Write-Log "CSV exported: $($script:CsvFile)"
Write-Log "Log file:     $($script:LogFile)"

# Return results to pipeline
$allResults.ToArray()

#endregion
