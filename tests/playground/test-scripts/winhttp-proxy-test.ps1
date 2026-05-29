# MXC Proxy Test Script — uses native WinHTTP COM to test proxy routing
# This script creates a WinHTTP request and reports the response.
# It uses the WinHttp.WinHttpRequest.5.1 COM object which goes through
# the OS WinHTTP stack (not .NET HttpClient or curl).

param(
    [string]$Url = "https://www.example.com",
    [int]$TimeoutSeconds = 15
)

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

Write-Output "=== MXC WinHTTP Proxy Test ==="
Write-Output "URL: $Url"
Write-Output "Timeout: ${TimeoutSeconds}s"
Write-Output ""

try {
    $h = New-Object -ComObject WinHttp.WinHttpRequest.5.1

    # Set timeouts (resolve, connect, send, receive) in milliseconds
    $ms = $TimeoutSeconds * 1000
    $h.SetTimeouts($ms, $ms, $ms, $ms)

    # Use automatic proxy detection (picks up OS-configured proxy)
    $h.SetProxy(1) # HTTPREQUEST_PROXYSETTING_DEFAULT

    $h.Open('GET', $Url, $false)
    $h.Send()

    $status = $h.Status
    $statusText = $h.StatusText
    $body = $h.ResponseText

    Write-Output "Status: $status $statusText"
    Write-Output "Body length: $($body.Length) bytes"
    Write-Output ""

    if ($body.Length -gt 500) {
        Write-Output $body.Substring(0, 500)
        Write-Output "... (truncated)"
    } else {
        Write-Output $body
    }

    Write-Output ""
    Write-Output "WINHTTP_OK"
} catch {
    Write-Output "ERROR: $_"
    Write-Output ""
    Write-Output "WINHTTP_FAILED"
    exit 1
}
