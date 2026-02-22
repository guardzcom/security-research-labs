<#
.SYNOPSIS
    SkillScan web server for PowerShell (Windows 11).

.DESCRIPTION
    Serves the skillscan_web.html frontend and provides a /api/fetch endpoint
    for URL scanning. Uses System.Net.HttpListener (no dependencies).

.EXAMPLE
    .\skillscan_server.ps1
    .\skillscan_server.ps1 -Port 9090
    .\skillscan_server.ps1 -NoBrowser
#>

param(
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$HtmlFile  = Join-Path $ScriptDir "skillscan_web.html"

if (-not (Test-Path $HtmlFile)) {
    Write-Error "skillscan_web.html not found at $HtmlFile"
    exit 1
}

$HtmlContent = [System.IO.File]::ReadAllBytes($HtmlFile)

# Content type map
$MimeTypes = @{
    ".html" = "text/html; charset=utf-8"
    ".js"   = "application/javascript"
    ".css"  = "text/css"
    ".json" = "application/json"
    ".png"  = "image/png"
    ".ico"  = "image/x-icon"
}

$Prefix = "http://127.0.0.1:${Port}/"
$Listener = New-Object System.Net.HttpListener
$Listener.Prefixes.Add($Prefix)

try {
    $Listener.Start()
} catch {
    Write-Error "Failed to start listener on port $Port. Try running as Administrator or use a different port."
    exit 1
}

Write-Host "SkillScan server running at $Prefix"
Write-Host "Press Ctrl+C to stop`n"

if (-not $NoBrowser) {
    Start-Process $Prefix
}

try {
    while ($Listener.IsListening) {
        $Context  = $Listener.GetContext()
        $Request  = $Context.Request
        $Response = $Context.Response

        $Path   = $Request.Url.AbsolutePath
        $Method = $Request.HttpMethod

        Write-Host "[skillscan] $Method $Path"

        try {
            # --- API: Fetch URL ---
            if ($Method -eq "POST" -and $Path -eq "/api/fetch") {
                $Reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
                $Body   = $Reader.ReadToEnd()
                $Reader.Close()

                try {
                    $Data = $Body | ConvertFrom-Json
                    $Url  = $Data.url

                    if (-not $Url -or (-not $Url.StartsWith("http://") -and -not $Url.StartsWith("https://"))) {
                        $JsonBytes = [System.Text.Encoding]::UTF8.GetBytes(
                            '{"error":"URL must start with http:// or https://"}')
                        $Response.StatusCode = 400
                        $Response.ContentType = "application/json"
                        $Response.OutputStream.Write($JsonBytes, 0, $JsonBytes.Length)
                        $Response.Close()
                        continue
                    }

                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.Headers.Add("User-Agent", "skillscan/1.0")
                    $Content = $WebClient.DownloadString($Url)
                    $WebClient.Dispose()

                    $ResponseObj = @{ content = $Content; url = $Url } | ConvertTo-Json -Depth 2 -Compress
                    $JsonBytes = [System.Text.Encoding]::UTF8.GetBytes($ResponseObj)
                    $Response.StatusCode = 200
                    $Response.ContentType = "application/json"
                    $Response.OutputStream.Write($JsonBytes, 0, $JsonBytes.Length)

                } catch {
                    $ErrMsg = $_.Exception.Message -replace '"', '\"'
                    $JsonBytes = [System.Text.Encoding]::UTF8.GetBytes(
                        "{`"error`":`"$ErrMsg`"}")
                    $Response.StatusCode = 502
                    $Response.ContentType = "application/json"
                    $Response.OutputStream.Write($JsonBytes, 0, $JsonBytes.Length)
                }

                $Response.Close()
                continue
            }

            # --- Serve HTML front page ---
            if ($Method -eq "GET" -and ($Path -eq "/" -or $Path -eq "/skillscan_web.html")) {
                $Response.StatusCode  = 200
                $Response.ContentType = "text/html; charset=utf-8"
                $Response.OutputStream.Write($HtmlContent, 0, $HtmlContent.Length)
                $Response.Close()
                continue
            }

            # --- Serve static files from script directory ---
            if ($Method -eq "GET") {
                $FilePath = Join-Path $ScriptDir ($Path.TrimStart("/"))
                if ((Test-Path $FilePath) -and -not (Get-Item $FilePath).PSIsContainer) {
                    $Ext = [System.IO.Path]::GetExtension($FilePath)
                    $CT  = $MimeTypes[$Ext]
                    if (-not $CT) { $CT = "application/octet-stream" }

                    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                    $Response.StatusCode  = 200
                    $Response.ContentType = $CT
                    $Response.OutputStream.Write($FileBytes, 0, $FileBytes.Length)
                    $Response.Close()
                    continue
                }
            }

            # --- 404 ---
            $Response.StatusCode = 404
            $NotFound = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found")
            $Response.OutputStream.Write($NotFound, 0, $NotFound.Length)
            $Response.Close()

        } catch {
            Write-Host "[skillscan] Error: $_" -ForegroundColor Red
            try { $Response.Close() } catch {}
        }
    }
} finally {
    $Listener.Stop()
    $Listener.Close()
    Write-Host "Server stopped."
}
