# Wraps wxc-exec.exe in an Azure AD authentication flow against the Lithium
# (W365A SandboxManagement) service and launches N agent workloads against the
# remote sandbox pool.
#
# Auth model: the Lithium runner reads two bearer tokens from env vars named
# in the config's experimental.lithium section:
#   - managementTokenEnvVar (default MXC_LITHIUM_MANAGEMENT_TOKEN) — checkout / terminate
#   - proxyTokenEnvVar (default MXC_LITHIUM_PROXY_TOKEN) — in-sandbox command-runner POST
# This script acquires both via `az account get-access-token` and exports them
# before invoking the binary.
#
# Service endpoints + AAD scopes are mirrored from
# D:/repos/W365A-Sandbox/src/Cli/Configuration/EnvironmentEndpoints.cs.

[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\examples\15_lithium_agent_fleet.json'),
    [int]    $Count = 10,
    [ValidateSet('test', 'int')]
    [string] $Environment = 'test',
    [string] $WxcExePath,
    [string] $TenantId,
    [int]    $MaxParallel = 5,
    # Forward --debug to wxc-exec so the runner streams its full trace on
    # stdout (URLs, request bodies, ports[]/proxyUri, response statuses).
    # Note: failures already surface a [debug] backend-trace block on stderr
    # without this — use this for visibility on the success path.
    [switch] $TraceRunner
)

$ErrorActionPreference = 'Stop'

$endpoints = @{
    test = @{
        ApiEndpoint = 'https://sandboxmanagement.us.test.w365lith.azure-test.net'
        MgmtScope   = 'api://w365a-svc-sandboxmanagement-test/.default'
        ProxyScope  = 'api://w365a-svc-nodeproxy-test/.default'
    }
    int  = @{
        ApiEndpoint = 'https://sandboxmanagement.us.int.w365lith.azure.com'
        MgmtScope   = 'api://7702b3c7-c33c-4ca7-8cf4-1a49063b77e2/.default'
        ProxyScope  = 'api://afc70dbb-531d-4d7f-8f76-def8215631c7/.default'
    }
}

$envInfo = $endpoints[$Environment]
$resolvedConfig = (Resolve-Path $ConfigPath).Path

if (-not $WxcExePath) {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $candidates = @(
        Join-Path $repoRoot 'sdk\bin\x64\wxc-exec.exe'
        Join-Path $repoRoot 'sdk\bin\arm64\wxc-exec.exe'
        Join-Path $repoRoot 'src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe'
        Join-Path $repoRoot 'src\target\x86_64-pc-windows-msvc\release\wxc-exec.exe'
        Join-Path $repoRoot 'src\target\debug\wxc-exec.exe'
        Join-Path $repoRoot 'src\target\release\wxc-exec.exe'
    )
    # Pick the most recently built binary so a fresh `cargo build` is preferred
    # over a stale sdk/bin copy. Override with -WxcExePath if you want a
    # specific one.
    $existing = $candidates | Where-Object { Test-Path $_ }
    $WxcExePath = $existing |
        Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending |
        Select-Object -First 1
    if (-not $WxcExePath) {
        throw "wxc-exec.exe not found. Build first (build.bat --debug) or pass -WxcExePath."
    }
}

if (-not (Test-Path $WxcExePath)) {
    throw "wxc-exec.exe not found at: $WxcExePath"
}

$binaryMTime = if (Test-Path $WxcExePath) {
    (Get-Item $WxcExePath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
} else { '<unknown>' }
Write-Host "Lithium environment : $Environment ($($envInfo.ApiEndpoint))" -ForegroundColor Cyan
Write-Host "Management scope    : $($envInfo.MgmtScope)" -ForegroundColor Cyan
Write-Host "Proxy scope         : $($envInfo.ProxyScope)" -ForegroundColor Cyan
Write-Host "Config              : $resolvedConfig" -ForegroundColor Cyan
Write-Host "Binary              : $WxcExePath (mtime $binaryMTime)" -ForegroundColor Cyan
Write-Host "Workload count      : $Count" -ForegroundColor Cyan
Write-Host "Max parallel        : $MaxParallel" -ForegroundColor Cyan
if ($TraceRunner) {
    Write-Host "Trace runner        : ON (--debug forwarded; full output printed for every workload)" -ForegroundColor Yellow
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI ('az') is required. Install from https://aka.ms/azcli, then run 'az login'."
}

Write-Host ""
Write-Host "Acquiring AAD bearer tokens via 'az account get-access-token'..." -ForegroundColor Cyan

function Get-AadToken {
    param(
        [Parameter(Mandatory)] [string] $Scope,
        [string] $TenantId
    )
    #$resource = ($Scope -replace '/\.default$', '')
    $tokenArgs = @('account', 'get-access-token', '--scope', $Scope, '--query', 'accessToken', '-o', 'tsv')
    if ($TenantId) { $tokenArgs += @('--tenant', $TenantId) }
    $tok = & az @tokenArgs
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tok)) {
        throw "Failed to acquire access token for scope '$Scope'. Run 'az login' (optionally with --tenant)."
    }
    return $tok.Trim()
}

$mgmtToken  = Get-AadToken -Scope $envInfo.MgmtScope  -TenantId $TenantId
$env:MXC_LITHIUM_MANAGEMENT_TOKEN = $mgmtToken
Write-Host "Management token acquired (length=$($mgmtToken.Length))." -ForegroundColor Green

# In 'int' the proxy and management share an AAD audience, so the second
# call returns essentially the same token. Acquire it anyway — keeps the
# logic uniform and lets the runner authenticate against the proxy with the
# right audience in 'test'.
$proxyToken = if ($envInfo.ProxyScope -eq $envInfo.MgmtScope) {
    $mgmtToken
} else {
    Get-AadToken -Scope $envInfo.ProxyScope -TenantId $TenantId
}
$env:MXC_LITHIUM_PROXY_TOKEN = $proxyToken
Write-Host "Proxy token acquired (length=$($proxyToken.Length))." -ForegroundColor Green

# Patch the config in-memory so each invocation hits the configured environment
# without needing the example file to hard-code an endpoint per env. We write a
# temporary copy per invocation so containerId stays unique.
$configJson = Get-Content -Raw -Path $resolvedConfig | ConvertFrom-Json
if (-not $configJson.experimental) { throw "Config missing experimental.lithium section." }
if (-not $configJson.experimental.lithium) { throw "Config missing experimental.lithium section." }
$configJson.experimental.lithium.apiEndpoint = $envInfo.ApiEndpoint

$tempDir = Join-Path $env:TEMP "mxc-lithium-fleet-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Write-Host "Per-invocation configs: $tempDir" -ForegroundColor Cyan

$jobs = @()
$results = @()
$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)

Write-Host ""
Write-Host "Launching $Count agent workload(s)..." -ForegroundColor Cyan

for ($i = 1; $i -le $Count; $i++) {
    $agentName = "agent-$runId-$('{0:D2}' -f $i)"
    $configJson | Add-Member -NotePropertyName containerId -NotePropertyValue $agentName -Force
    $perRunPath = Join-Path $tempDir "$agentName.json"
    $configJson | ConvertTo-Json -Depth 12 | Set-Content -Path $perRunPath -Encoding utf8

    while (@($jobs | Where-Object { $_.Job.State -eq 'Running' }).Count -ge $MaxParallel) {
        Start-Sleep -Milliseconds 250
    }

    Write-Host "  -> $agentName" -ForegroundColor DarkGray
    $job = Start-Job -ScriptBlock {
        param($Exe, $Cfg, $MgmtToken, $ProxyToken, $Trace)
        $env:MXC_LITHIUM_MANAGEMENT_TOKEN = $MgmtToken
        $env:MXC_LITHIUM_PROXY_TOKEN = $ProxyToken
        $extraArgs = @()
        if ($Trace) { $extraArgs += '--debug' }
        & $Exe --experimental @extraArgs --config $Cfg 2>&1
        return $LASTEXITCODE
    } -ArgumentList $WxcExePath, $perRunPath, $env:MXC_LITHIUM_MANAGEMENT_TOKEN, $env:MXC_LITHIUM_PROXY_TOKEN, $TraceRunner.IsPresent

    $jobs += [pscustomobject]@{ Name = $agentName; Job = $job; ConfigPath = $perRunPath }
}

Write-Host ""
Write-Host "Waiting for all workloads to complete..." -ForegroundColor Cyan
$jobs | ForEach-Object { Wait-Job -Job $_.Job | Out-Null }

foreach ($entry in $jobs) {
    $output = Receive-Job -Job $entry.Job -Keep
    $exitCode = ($output | Select-Object -Last 1)
    $stdout = ($output | Select-Object -SkipLast 1) -join "`n"
    Remove-Job -Job $entry.Job | Out-Null

    $results += [pscustomobject]@{
        Agent    = $entry.Name
        ExitCode = $exitCode
        Output   = $stdout
    }
}

Write-Host ""
Write-Host "Results:" -ForegroundColor Cyan
$results | ForEach-Object {
    $status = if ($_.ExitCode -eq 0) { 'OK' } else { "FAIL($($_.ExitCode))" }
    $color = if ($_.ExitCode -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-32} {1}" -f $_.Agent, $status) -ForegroundColor $color
}

# Always surface each workload's captured output. On success this is the
# command's stdout (proving each agent ran on its own sandbox); with
# -TraceRunner it also includes the runner's --debug trace.
Write-Host ""
$header = if ($TraceRunner) { 'Workload output (with --debug trace):' } else { 'Workload output:' }
Write-Host $header -ForegroundColor Yellow
foreach ($r in $results) {
    Write-Host "--- $($r.Agent) (exit $($r.ExitCode)) ---" -ForegroundColor Yellow
    Write-Host $r.Output
}

$failed = @($results | Where-Object { $_.ExitCode -ne 0 }).Count
$summaryColor = if ($failed -eq 0) { 'Green' } else { 'Yellow' }
Write-Host ""
Write-Host "Summary: $($results.Count - $failed)/$($results.Count) succeeded." -ForegroundColor $summaryColor

exit $failed
