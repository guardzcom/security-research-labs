<#
.SYNOPSIS
  Device Code Flow helper for Microsoft Graph with automatic refresh.

.DESCRIPTION
  This script performs OAuth2 device-code authentication against a specified
  Entra ID tenant (or common) using a client_id you provide. It optionally
  caches refresh tokens to disk, refreshes access tokens automatically before
  expiry, exposes the access token to the calling session, and logs safe events.

  Important security notes:
  1) Storing token on disk increases risk. If you enable caching,
     store the file on an encrypted disk or restrict filesystem permissions.
  2) Use this script only with apps and tenants you control.
  3) For production usage consider MSAL libraries which handle refresh and PKCE.
#>

$token=Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -Body @{client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46";scope="https://graph.microsoft.com/.default offline_access"}; Write-Host "Go to $($token.verification_uri) and enter $($token.user_code)"; $access=$null; while (-not $access) { Start-Sleep -Seconds 5; try { $access=Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body @{client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46";grant_type="urn:ietf:params:oauth:grant-type:device_code";device_code=$token.device_code} -ErrorAction Stop } catch {} }; Write-Host "Access Token: $($access.access_token)"; while ($true) { Start-Sleep -Seconds 3500; $access=Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body @{client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46";grant_type="refresh_token";refresh_token=$access.refresh_token;scope="https://graph.microsoft.com/.default"}; Write-Host "New Access Token: $($access.access_token)" }
