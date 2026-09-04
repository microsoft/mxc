# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC cooperative HTTP/HTTPS proxy functional test.
#
# WSLC has no in-kernel iptables, so per-host network policy is enforced
# *cooperatively*: the runner translates `network.proxy` into HTTP(S)_PROXY
# env vars and cooperating clients (curl, wget, ...) route through the proxy.
# This script proves that path end-to-end:
#
#   1. Parser accepts the `wslc` backend with a `url`-form proxy.
#   2. The runner injects HTTP_PROXY/HTTPS_PROXY from network.proxy.url,
#      scrubs the attacker-supplied proxy env vars in the config's process.env,
#      and neutralizes NO_PROXY/no_proxy to empty (so a caller- or image-baked
#      exemption like NO_PROXY=* cannot defeat the cooperative proxy).
#   3. A cooperating client (busybox wget) routes through the proxy.
#
# The proxy is an in-container marker server on 127.0.0.1 (a WSLC container
# runs in its own network namespace / separate VM, so loopback is the only
# address reachable by both the client and a self-hosted proxy -- a
# host/distro-loopback proxy is NOT reachable). The marker answers every
# request with the body `PROXY_HIT`; example.com is never actually contacted,
# so `PROXY_HIT` in the client output is an unambiguous "the proxy was used"
# signal.
#
# Usage:
#   .\run_wslc_proxy_test.ps1                       # auto-discovers wxc-exec.exe
#   .\run_wslc_proxy_test.ps1 -WxcExecPath <path>   # explicit binary
#   .\run_wslc_proxy_test.ps1 -Debug                # debug build + --debug

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot "tests\configs\wslc_network_proxy.json"

# Resolve the binary: explicit path, then target-specific and default dirs.
$Target = "x86_64-pc-windows-msvc"
$Profile = if ($Debug) { "debug" } else { "release" }
if ($WxcExecPath) {
    $WxcExec = $WxcExecPath
} else {
    $Candidates = @(
        (Join-Path $RepoRoot "src\target\$Target\$Profile\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$Profile\wxc-exec.exe")
    )
    $WxcExec = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found. Build with: cd src; cargo build --features wslc --release --target $Target" -ForegroundColor Red
    exit 1
}

Write-Host "Running WSLC cooperative proxy functional test..."
Write-Host "Binary: $WxcExec" -ForegroundColor Gray

$wxcArgs = @()
if ($Debug) { $wxcArgs += "--debug" }
$wxcArgs += $ConfigPath

$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$output = & $WxcExec @wxcArgs 2>&1 | Out-String
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $prev
Write-Host $output

$pass = $true
$reason = ""

if ($exitCode -ne 0) {
    $pass = $false
    $reason = "wxc-exec returned non-zero exit $exitCode"
}

# Scope env assertions to the child's own `PROXY_ENV ...` line: the raw stream
# also holds executor diagnostics (diagnostic-console logging echoes the input
# JSON, which carries attacker.invalid), so matching $output would false-flag.
$childLine = ($output -split "`r?`n" | Where-Object { $_ -match '^PROXY_ENV ' } | Select-Object -First 1)
if ($pass -and (-not $childLine)) {
    $pass = $false
    $reason = "child did not emit the PROXY_ENV diagnostic line"
}

# The runner must have injected the configured proxy URL, replacing the
# attacker.invalid values supplied in the config's process.env.
if ($pass -and ($childLine -notmatch 'HTTP_PROXY=\[http://127\.0\.0\.1:8888\]')) {
    $pass = $false
    $reason = "runner did not inject/scrub HTTP_PROXY (expected http://127.0.0.1:8888)"
}
if ($pass -and ($childLine -match 'attacker\.invalid')) {
    $pass = $false
    $reason = "caller-supplied proxy env var leaked to the child (attacker.invalid not scrubbed)"
}

# The FTP family is set to the proxy as well, so an image-baked ftp_proxy
# cannot send FTP traffic somewhere the operator did not choose. Matched
# case-sensitively: -notmatch would let the upper-case entry satisfy both
# checks and leave the lower-case one untested.
if ($pass -and (($childLine -cnotmatch 'FTP_PROXY=\[http://127\.0\.0\.1:8888\]') -or ($childLine -cnotmatch 'ftp_proxy=\[http://127\.0\.0\.1:8888\]'))) {
    $pass = $false
    $reason = "runner did not inject/scrub the FTP proxy family (expected http://127.0.0.1:8888)"
}

# NO_PROXY / no_proxy must be neutralized to empty so an image-baked or
# caller-supplied exemption (e.g. NO_PROXY=*) cannot disable the proxy.
if ($pass -and (($childLine -notmatch 'NO_PROXY=\[\]') -or ($childLine -notmatch 'no_proxy=\[\]'))) {
    $pass = $false
    $reason = "runner did not neutralize NO_PROXY/no_proxy to empty"
}

# The cooperating client must have routed through the marker proxy.
if ($pass -and ($output -notmatch "WSLC_PROXY_FUNCTIONAL_OK")) {
    $pass = $false
    $reason = "client did not route through the proxy (marker 'PROXY_HIT' not observed)"
}

if ($pass) {
    Write-Host "PASS: WSLC cooperative proxy is functional (env injected, caller vars scrubbed, NO_PROXY neutralized, client routed)." -ForegroundColor Green
    exit 0
} else {
    Write-Host "FAIL: $reason" -ForegroundColor Red
    exit 1
}
