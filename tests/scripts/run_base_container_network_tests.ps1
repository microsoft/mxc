# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 7.0

# Verifies native BaseContainer egress defaults, host loopback, and proxy
# endpoint isolation using published contracts. Requires native PSEC support;
# unavailable features fail rather than skip.
#
# Usage:
#   .\run_base_container_network_tests.ps1          # prefer debug, fall back to release
#   .\run_base_container_network_tests.ps1 -Release # prefer release, fall back to debug

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'lib\LoopbackAnchor.ps1')
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')

$WxcExec = if ($BinDir) {
    Join-Path $BinDir "wxc-exec.exe"
} else {
    $DebugWxcExec = Join-Path $RepoRoot "src\target\debug\wxc-exec.exe"
    $ReleaseWxcExec = Join-Path $RepoRoot "src\target\release\wxc-exec.exe"

    if ($Release) {
        $Candidates = @($ReleaseWxcExec, $DebugWxcExec)
    } else {
        $Candidates = @($DebugWxcExec, $ReleaseWxcExec)
    }

    $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

$TestConfigs = @(
    @{
        Name = "allow"
        Path = Join-Path $RepoRoot "tests\configs\base_container_network_allow.json"
        ExpectedAction = "allow"
        ExpectedMarker = "OK:network_allow"
    },
    @{
        Name = "deny"
        Path = Join-Path $RepoRoot "tests\configs\base_container_network_deny.json"
        ExpectedAction = "deny"
        ExpectedMarker = "OK:network_deny"
    }
)

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    if ($BinDir) {
        Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    } else {
        Write-Host "ERROR: wxc-exec.exe not found in src\target\debug or src\target\release" -ForegroundColor Red
    }
    Write-Host "Run 'cargo build' or 'cargo build --release' first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Using wxc-exec: $WxcExec" -ForegroundColor Gray
$ScratchRoot = Join-Path $env:TEMP ("mxc-native-network-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
Write-Host "Network test artifacts: $ScratchRoot"
$Passed = 0

foreach ($test in $TestConfigs) {
    if (-not (Test-Path $test.Path)) {
        Write-Host "ERROR: config not found at $($test.Path)" -ForegroundColor Red
        exit 1
    }
}

function Invoke-NetworkExecutor {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Invoke-NativeProcessContainer -WxcExec $WxcExec -ScratchRoot $ScratchRoot -Name $Name -Arguments $Arguments
}

function Assert-NativeNetworkPolicy {
    param($Result, [string]$Name, [ValidateSet('allow', 'deny')][string]$ExpectedAction)
    $events = [regex]::Matches($Result.Log,
        '(?m)^(?:\[\d+\]\s*)?(\{"event":"mxc.NetworkPolicyApplied"[^\r\n]*\})\r?$')
    if ($events.Count -ne 1) {
        throw "$Name did not report one applied native network policy. See $ScratchRoot."
    }
    $policy = $events[0].Groups[1].Value | ConvertFrom-Json
    $expectedDefault = if ($ExpectedAction -eq 'deny') { 'block' } else { 'allow' }
    if ($policy.backend -ne 'processcontainer' -or $policy.tier -ne 'base-container' -or
        $policy.status -ne 'success' -or $policy.default_policy -ne $expectedDefault) {
        throw "$Name applied an unexpected network policy: $($events[0].Value)"
    }
}

$probeResult = Invoke-NetworkExecutor -Name 'probe' -Arguments @('--probe', '--config', $TestConfigs[0].Path)
if ($probeResult.ExitCode -ne 0) {
    throw "BaseContainer capability probe failed: $($probeResult.Stderr)"
}

$probe = $probeResult.Stdout | ConvertFrom-Json
if ($probe.tier -ne "base-container") {
    throw "Native PSEC is required; selected tier: $($probe.tier)"
}

$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot 'run_processcontainer_network_loopback_test.ps1') `
    -BinDir (Split-Path -Parent $WxcExec)
if ($LASTEXITCODE -ne 0) { throw "Focused loopback suite exited $LASTEXITCODE." }

$destinations = @(
    @{ Url = 'https://dev.azure.com/'; Pattern = 'Object moved' },
    @{ Url = 'https://example.com/'; Pattern = 'Example Domain' }
)
foreach ($destination in $destinations) {
    $uri = [Uri]$destination.Url
    $addresses = @([Net.Dns]::GetHostAddresses($uri.Host) |
        Where-Object AddressFamily -eq InterNetwork)
    if (-not $addresses.Count) { throw "No IPv4 address for $($uri.Host)." }
    $destination.Addresses = @($addresses | ForEach-Object IPAddressToString)
    $destination.Address = $destination.Addresses[0]
    $body = & (Join-Path $env:SystemRoot 'System32\curl.exe') --silent --show-error `
        --noproxy '*' --max-time 15 --resolve "$($uri.Host):443:$($destination.Address)" $destination.Url
    if ($LASTEXITCODE -ne 0 -or ($body -join "`n") -notmatch $destination.Pattern) {
        throw "Host cannot reach the egress control $($destination.Url)."
    }
}
$target, $unlisted = $destinations
Write-Host 'PASSED: external-target-host-controls (before negative cases)'

foreach ($test in $TestConfigs) {
    Write-Host "Running BaseContainer network $($test.Name) test..." -ForegroundColor Cyan

    $result = Invoke-NetworkExecutor -Name $test.Name -Arguments @($test.Path)
    Assert-NativeNetworkPolicy -Result $result -Name $test.Name -ExpectedAction $test.ExpectedAction

    if ($result.ExitCode -ne 0) {
        throw "$($test.Name) exited with code $($result.ExitCode): $($result.Stderr)"
    }

    if ($result.Stdout -notmatch [regex]::Escape($test.ExpectedMarker)) {
        Write-Host "FAILED: expected marker '$($test.ExpectedMarker)'" -ForegroundColor Red
        exit 1
    }

    Write-Host "PASSED: BaseContainer network $($test.Name)" -ForegroundColor Green
    $Passed++
}

function Invoke-LoopbackCase {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Url,
        [string]$IngressDefault,
        [string]$HostLoopback,
        [string]$ProxyUrl,
        [string]$ExpectedBody,
        [string]$ExpectedBodyPattern,
        [hashtable]$Egress,
        [string]$ResolveAddress,
        [ValidateSet('normal', 'omitted', 'empty')][string]$NetworkForm = 'normal',
        [switch]$ProxyEnvironment,
        [switch]$Ping,
        [switch]$IPv4,
        [int[]]$BlockedExitCodes = @(7, 28),
        [string]$CommandLine,
        [string[]]$ReadonlyPaths = @(),
        [switch]$Blocked
    )
    $curlArguments = @()
    if ($ResolveAddress) {
        $uri = [Uri]$Url
        $curlArguments += @('--resolve', "$($uri.Host):$($uri.Port):$ResolveAddress")
    }
    if ($IPv4) { $curlArguments += '--ipv4' }
    $config = @{
        version = '1.0.0'
        containment = 'processcontainer'
        process = @{
            commandLine = (Get-LoopbackAnchorCommand -Url $Url -TimeoutSec 5 `
                -UseProxyEnvironment:([bool]$ProxyUrl -and -not $Blocked) -AdditionalArguments $curlArguments)
            cwd = $ScratchRoot
            timeout = 30000
        }
        filesystem = @{
            readwritePaths = @($ScratchRoot)
            readonlyPaths = @($env:SystemRoot)
        }
        network = @{ egress = @{ default = 'allow' } }
        ui = @{ disable = $false }
    }
    if ($Egress) { $config.network.egress = $Egress }
    if ($IngressDefault -or $HostLoopback) {
        $config.network.ingress = @{}
        if ($IngressDefault) { $config.network.ingress.default = $IngressDefault }
        if ($HostLoopback) { $config.network.ingress.hostLoopback = $HostLoopback }
    }
    if ($ProxyUrl) {
        $config.network.egress.default = 'deny'
        $config.runtimeConfig = @{ networkProxy = $ProxyUrl }
    }
    if ($NetworkForm -eq 'omitted') { $config.Remove('network') }
    if ($NetworkForm -eq 'empty') { $config.network = @{} }
    if ($ProxyEnvironment) {
        $config.process.commandLine = 'cmd.exe /d /s /c "set HTTP_PROXY & set HTTPS_PROXY & set NO_PROXY & exit /b 0"'
    }
    if ($Ping) {
        $config.process.commandLine = 'cmd.exe /d /s /c "echo NATIVE_PING_STARTED && ' +
            $env:SystemRoot + '\System32\ping.exe -n 1 -w 1000 127.0.0.1"'
    }
    if ($CommandLine) { $config.process.commandLine = $CommandLine }
    $config.filesystem.readonlyPaths += $ReadonlyPaths
    $configPath = Join-Path $ScratchRoot "$Name.json"
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath
    $result = Invoke-NetworkExecutor -Name $Name -Arguments @($configPath)
    $action = if ($NetworkForm -eq 'normal') { $config.network.egress.default } else { 'deny' }
    Assert-NativeNetworkPolicy -Result $result -Name $Name -ExpectedAction $action
    if ($ProxyEnvironment) {
        $environment = @{}
        foreach ($line in ($result.Stdout -split "`r?`n")) {
            if ($line -match '^([^=]+)=(.*)$') { $environment[$matches[1]] = $matches[2] }
        }
        $pass = $result.ExitCode -eq 0 -and $environment.HTTP_PROXY -ceq $ProxyUrl -and
            $environment.HTTPS_PROXY -ceq $ProxyUrl -and
            (-not $environment.ContainsKey('NO_PROXY') -or
                $environment.NO_PROXY -notmatch '(?i)\*|127\.0\.0\.1|localhost')
    } elseif ($Ping) {
        $pass = $result.ExitCode -ne 0 -and $result.Stdout -match '(?m)^NATIVE_PING_STARTED' -and
            "$($result.Stdout)$($result.Stderr)" -match '(?i)ICMP|pinging|socket|10013|general failure|access.*denied'
    } elseif ($Blocked) {
        # A launch/config failure is not evidence that networking was denied.
        $codes = $BlockedExitCodes -join '|'
        $pass = $result.ExitCode -in $BlockedExitCodes -and $result.Stderr -match "curl: \(($codes)\)"
    } else {
        $bodyMatches = if ($ExpectedBodyPattern) {
            $result.Stdout -match $ExpectedBodyPattern
        } else {
            $result.Stdout.Trim() -ceq $ExpectedBody
        }
        $pass = $result.ExitCode -eq 0 -and $bodyMatches
    }
    if (-not $pass) {
        throw "$Name failed: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr). See $ScratchRoot."
    }
    $script:Passed++
    Write-Host "PASSED: $Name" -ForegroundColor Green
}

$anchors = @()
try {
    foreach ($spec in @(
        @{ Address = '127.0.0.1'; Body = 'MXC-DIRECT-IPV4' },
        @{ Address = '::1'; Body = 'MXC-DIRECT-IPV6' },
        @{ Address = '127.0.0.1'; Body = 'MXC-PROXY-ENDPOINT' }
    )) {
        $anchor = Start-LoopbackAnchor -BindAddress ([Net.IPAddress]::Parse($spec.Address)) -Body $spec.Body
        if (-not $anchor) { throw "Cannot bind the $($spec.Address) loopback test listener." }
        $anchors += $anchor
        $response = Invoke-WebRequest -Uri $anchor.Url -NoProxy -TimeoutSec 5
        if ($response.Content -cne $anchor.Body) {
            throw "Host cannot reach its loopback listener at $($anchor.Url)."
        }
    }
    $ipv4, $ipv6, $proxy = $anchors
    foreach ($form in @('normal', 'omitted', 'empty')) {
        Invoke-LoopbackCase -Name "model3-deny-$form" -Url $target.Url -NetworkForm $form `
            -Egress @{ default = 'deny' } -IngressDefault 'deny' -HostLoopback 'deny' `
            -ResolveAddress $target.Address -Blocked
    }
    Write-Host 'PASSED: model3-spellings-agree (three launched, blocked workloads)'
    Invoke-LoopbackCase -Name 'capability-matrix-deny-allow' -Url $target.Url `
        -Egress @{ default = 'deny' } -IngressDefault 'allow' -HostLoopback 'deny' `
        -ResolveAddress $target.Address -Blocked
    Invoke-LoopbackCase -Name 'capability-matrix-allow-allow' -Url $target.Url `
        -IngressDefault 'allow' -HostLoopback 'deny' -ResolveAddress $target.Address -ExpectedBodyPattern $target.Pattern
    Invoke-LoopbackCase -Name 'proxy-endpoint-reachable' -Url 'http://mxc-proxy-probe.invalid/' `
        -IngressDefault 'allow' -HostLoopback 'allow' -ProxyUrl $proxy.Url -ExpectedBody $proxy.Body
    Invoke-LoopbackCase -Name 'proxy-child-environment' -Url $proxy.Url -ProxyEnvironment `
        -IngressDefault 'allow' -HostLoopback 'allow' -ProxyUrl $proxy.Url
    Invoke-LoopbackCase -Name 'proxy-blocks-direct-external' -Url $target.Url `
        -IngressDefault 'allow' -HostLoopback 'allow' -ProxyUrl $proxy.Url `
        -ResolveAddress $target.Address -Blocked -BlockedExitCodes @(6, 7, 28)
    foreach ($direct in @($ipv4, $ipv6)) {
        $family = if ($direct -eq $ipv4) { 'ipv4' } else { 'ipv6' }
        Invoke-LoopbackCase -Name "proxy-blocks-direct-$family" -Url $direct.Url `
            -IngressDefault 'allow' -HostLoopback 'allow' -ProxyUrl $proxy.Url -Blocked
    }
    $rule = @{
        to = @(@{ cidr = "$($target.Address)/32" })
        ports = @(@{ protocol = 'tcp'; port = 443 })
    }
    $allow = @{ default = 'deny'; allow = @($rule) }
    Invoke-LoopbackCase -Name 'egress-rule-allows-named-endpoint' -Url $target.Url `
        -Egress $allow -ResolveAddress $target.Address -ExpectedBodyPattern $target.Pattern
    Invoke-LoopbackCase -Name 'egress-rule-blocks-unlisted-endpoint' -Url $unlisted.Url `
        -Egress $allow -ResolveAddress $unlisted.Address -Blocked
    Invoke-LoopbackCase -Name 'egress-deny-overrides-allow' -Url $target.Url `
        -Egress @{ default = 'deny'; allow = @($rule); deny = @($rule) } `
        -ResolveAddress $target.Address -Blocked
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
        ForEach-Object ServerAddresses | Sort-Object -Unique)
    if (-not $dns.Count) { throw 'No IPv4 resolvers for the UDP/53 control.' }
    $tcpRules = @(@{
        to = @($target.Addresses | ForEach-Object { @{ cidr = "$_/32" } })
        ports = @(@{ protocol = 'tcp'; port = 443 })
    })
    $dnsRules = @(@{
        to = @($dns | ForEach-Object { @{ cidr = "$_/32" } })
        ports = @(@{ protocol = 'udp'; port = 53 })
    })
    Invoke-LoopbackCase -Name 'egress-udp53-and-tcp443' -Url $target.Url -IPv4 `
        -Egress @{ default = 'deny'; allow = @($tcpRules + $dnsRules) } `
        -IngressDefault 'allow' -HostLoopback 'deny' -ExpectedBodyPattern $target.Pattern
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) { throw 'Direct UDP/53 validation requires Windows PowerShell 5.1.' }
    $dnsProbe = Join-Path $PSScriptRoot 'lib\processcontainer_policy_probe.ps1'
    $resolver = $null
    foreach ($candidate in $dns) {
        $hostDns = & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $dnsProbe 'dns' $ScratchRoot $candidate ([Uri]$target.Url).Host '1' `
            2> (Join-Path $ScratchRoot "dns-host-$candidate.stderr.txt")
        if ($LASTEXITCODE -eq 0 -and ($hostDns -join "`n").Trim() -ceq 'NATIVE_POLICY_OK') {
            $resolver = $candidate
            break
        }
    }
    if ($resolver) {
        Write-Host 'PASSED: direct-udp53-host-positive-control'
        foreach ($allowed in @($true, $false)) {
            $command = @($windowsPowerShell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', $dnsProbe, 'dns', $ScratchRoot, $resolver, ([Uri]$target.Url).Host, "$([int]$allowed)")
            $egress = @{ default = 'deny'; allow = $tcpRules }
            if ($allowed) { $egress.allow = @($tcpRules + $dnsRules) }
            Invoke-LoopbackCase -Name "direct-udp53-allowed-$allowed" -Url $target.Url -Egress $egress `
                -CommandLine (($command | ForEach-Object { '"' + $_ + '"' }) -join ' ') `
                -ReadonlyPaths @((Split-Path $dnsProbe -Parent)) -ExpectedBody 'NATIVE_POLICY_OK'
        }
    } else {
        Write-Host 'SKIPPED (no host resolver answered a direct UDP/53 query): direct DNS packet controls'
    }
    $hostPing = & (Join-Path $env:SystemRoot 'System32\ping.exe') -n 1 -w 1000 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "Host ICMP control failed: $hostPing" }
    Invoke-LoopbackCase -Name 'default-deny-blocks-icmp' -Url $target.Url -Ping `
        -Egress @{ default = 'deny' } -IngressDefault 'deny' -HostLoopback 'deny'
} finally {
    foreach ($anchor in $anchors) { Stop-LoopbackAnchor -Anchor $anchor }
}

Write-Host "PASSED: all $Passed BaseContainer network tests" -ForegroundColor Green
