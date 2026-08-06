# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$target = if ($Release) { "release" } else { "debug" }
$targetTriple = "x86_64-pc-windows-msvc"
$wxcExe = Join-Path $repoRoot "src\target\$targetTriple\$target\wxc-exec.exe"
$proxyExe = Join-Path $repoRoot "src\target\$targetTriple\$target\wxc-test-proxy.exe"
$networkConfigRoot = Join-Path $repoRoot "tests\configs\processcontainer\networking"

if (-not (Test-Path $wxcExe)) {
    throw "Missing $wxcExe. Build it from src with: cargo build --target $targetTriple"
}
if (-not (Test-Path $proxyExe)) {
    throw "Missing $proxyExe. Build it from src with: cargo build -p wxc_test_proxy --target $targetTriple"
}

$results = [System.Collections.Generic.List[object]]::new()

function Invoke-NetworkConfig {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    $output = & $wxcExe --experimental --config $ConfigPath 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    $passed = $exitCode -eq 0
    $results.Add([pscustomobject]@{
        Name = $Name
        Status = if ($passed) { "Passed" } else { "Failed" }
        ExitCode = $exitCode
    })
}

function Invoke-RejectedNetworkConfig {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$ExpectedError
    )

    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    $output = & $wxcExe --experimental --config $ConfigPath 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    $output | ForEach-Object { Write-Host $_ }
    $passed = $exitCode -ne 0 -and $text.Contains($ExpectedError)
    $results.Add([pscustomobject]@{
        Name = $Name
        Status = if ($passed) { "Passed" } else { "Failed" }
        ExitCode = $exitCode
    })
}

$hostDnsOutput = (& nslookup.exe example.com 8.8.8.8 2>&1) -join [Environment]::NewLine
$hostCanReachPublicDns = $hostDnsOutput -match "Addresses?:" -and
    $hostDnsOutput -notmatch "timed out|No response from server"

$directConfigs = @(
    "base_container_network_allow.json",
    "base_container_network_deny.json",
    "base_container_network_v08_default_deny_tcp_blocked.json",
    "base_container_network_v08_allow_ip_tcp443.json",
    "base_container_network_v08_allow_cidr_except_blocked.json",
    "base_container_network_v08_allow_port_range_tcp443.json",
    "base_container_network_v08_multiple_rules.json",
    "base_container_network_v08_deny_overrides_allow.json",
    "base_container_network_v08_allow_any_protocol_tcp443.json",
    "base_container_network_v08_allow_udp53.json",
    "base_container_network_v08_deny_udp53.json"
)

foreach ($configName in $directConfigs) {
    if ($configName -eq "base_container_network_v08_allow_udp53.json" -and
        -not $hostCanReachPublicDns) {
        Write-Host "`n=== base_container_network_v08_allow_udp53 ===" -ForegroundColor Cyan
        Write-Host "SKIP: host network cannot reach public UDP/53 at 8.8.8.8."
        $results.Add([pscustomobject]@{
            Name = "base_container_network_v08_allow_udp53"
            Status = "Skipped"
            ExitCode = $null
        })
        continue
    }
    Invoke-NetworkConfig `
        -Name ([IO.Path]::GetFileNameWithoutExtension($configName)) `
        -ConfigPath (Join-Path $networkConfigRoot $configName)
}

Invoke-RejectedNetworkConfig `
    -Name "base_container_network_v08_proxy_with_egress_invalid" `
    -ConfigPath (Join-Path $networkConfigRoot "base_container_network_v08_proxy_with_egress_invalid.json") `
    -ExpectedError "requires deny-default egress with no direct allow/deny rules"

$packageSuffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$packageName = "Microsoft.Mxc.TestProxy.$packageSuffix"
$tempRoot = Join-Path $env:TEMP "mxc-network-proxy-$packageSuffix"
$packageRoot = Join-Path $tempRoot "package"
$proxyProcessId = $null
$package = $null
$shutdownFile = $null

try {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    Copy-Item `
        -Path (Join-Path $PSScriptRoot "AppContainerProxyPackage\*") `
        -Destination $packageRoot `
        -Recurse
    Copy-Item $proxyExe (Join-Path $packageRoot "wxc-test-proxy.exe")

    $manifestPath = Join-Path $packageRoot "AppxManifest.xml"
    $manifest = (Get-Content $manifestPath -Raw).Replace(
        "__PACKAGE_NAME__",
        $packageName)
    Set-Content -Path $manifestPath -Value $manifest -Encoding utf8
    Add-AppxPackage -Register $manifestPath -ForceApplicationShutdown
    $package = Get-AppxPackage -Name $packageName
    if (-not $package) {
        throw "The loose AppContainer proxy package did not register."
    }

    $packageLocalState = Join-Path `
        $env:LOCALAPPDATA `
        "Packages\$($package.PackageFamilyName)\LocalState"
    New-Item -ItemType Directory -Path $packageLocalState -Force | Out-Null
    $readyFile = Join-Path $packageLocalState "ready"
    $shutdownFile = Join-Path $packageLocalState "shutdown"
    $cleanupEvent = "Local\mxc-unused-$([Guid]::NewGuid().ToString('N'))"
    $proxyArguments = @(
        "--ready-file `"$readyFile`"",
        "--cleanup-event `"$cleanupEvent`"",
        "--parent-pid $PID",
        "--shutdown-file `"$shutdownFile`"",
        "--allow-host example.com"
    ) -join " "
    Add-Type -Path (Join-Path $PSScriptRoot "PackagedAppActivator.cs")
    $appUserModelId = "$($package.PackageFamilyName)!Proxy"
    $proxyProcessId = [PackagedAppActivator]::Activate(
        $appUserModelId,
        $proxyArguments)

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path $readyFile) -and [DateTime]::UtcNow -lt $deadline) {
        if (-not (Get-Process -Id $proxyProcessId -ErrorAction SilentlyContinue)) {
            throw "The AppContainer proxy exited before becoming ready."
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path $readyFile)) {
        throw "Timed out waiting for the AppContainer proxy to become ready."
    }

    $proxyPort = [int](Get-Content $readyFile -Raw)
    $blockedLoopbackPort = if ($proxyPort -lt 65535) { $proxyPort + 1 } else { $proxyPort - 1 }
    $allowedPeer = $package.PackageFamilyName
    Write-Host "`nProxy AppContainer: $allowedPeer, port $proxyPort" -ForegroundColor Cyan

    $proxyCases = @(
        @{
            Name = "B1_winhttp_allowed_domain_through_proxy"
            Command = "`$request = New-Object -ComObject WinHttp.WinHttpRequest.5.1; try { `$request.Open('GET', 'https://example.com/', `$false); `$request.Send(); if (`$request.Status -ge 200 -and `$request.Status -lt 400) { Write-Output 'OK:B1_winhttp_allowed'; exit 0 }; Write-Output ('WinHTTP status: {0}' -f `$request.Status) } catch { Write-Output ('WinHTTP error: {0}' -f `$_.Exception.Message) }; Write-Output 'FAIL:B1_winhttp_allowed'; exit 1"
        },
        @{
            Name = "B1_curl_allowed_domain_through_proxy"
            Command = "Write-Output ('HTTP_PROXY={0}; HTTPS_PROXY={1}' -f `$env:HTTP_PROXY, `$env:HTTPS_PROXY); & curl.exe -v --max-time 15 https://example.com/ 2>&1 | Write-Output; if (`$LASTEXITCODE -eq 0) { Write-Output 'OK:B1_curl_allowed'; exit 0 }; Write-Output 'FAIL:B1_curl_allowed'; exit 1"
        },
        @{
            Name = "B2_non_allowed_domain_blocked_at_proxy"
            Command = "`$request = New-Object -ComObject WinHttp.WinHttpRequest.5.1; try { `$request.Open('GET', 'https://www.microsoft.com/', `$false); `$request.Send(); if (`$request.Status -eq 403) { Write-Output 'OK:B2_domain_blocked'; exit 0 }; Write-Output ('B2 unexpected status: {0}' -f `$request.Status) } catch { Write-Output ('B2 proxy error: {0}' -f `$_.Exception.Message) }; Write-Output 'FAIL:B2_domain_policy_not_observed'; exit 1"
        },
        @{
            Name = "B3_raw_external_tcp_blocked"
            Command = "`$client = [Net.Sockets.TcpClient]::new(); try { `$connected = `$client.ConnectAsync('1.1.1.1', 443).Wait(5000) } catch { `$connected = `$false } finally { `$client.Dispose() }; if (-not `$connected) { Write-Output 'OK:B3_raw_tcp_blocked'; exit 0 }; Write-Output 'FAIL:B3_raw_tcp_connected'; exit 1"
        },
        @{
            Name = "B4_arbitrary_loopback_port_blocked"
            Command = "`$client = [Net.Sockets.TcpClient]::new(); try { `$connected = `$client.ConnectAsync('127.0.0.1', $blockedLoopbackPort).Wait(3000) } catch { `$connected = `$false } finally { `$client.Dispose() }; if (-not `$connected) { Write-Output 'OK:B4_loopback_blocked'; exit 0 }; Write-Output 'FAIL:B4_loopback_connected'; exit 1"
        },
        @{
            Name = "B5_proxy_loopback_port_reachable"
            Command = "`$client = [Net.Sockets.TcpClient]::new(); try { `$connected = `$client.ConnectAsync('127.0.0.1', $proxyPort).Wait(5000) } catch { Write-Output (`"B5 connect error: {0}`" -f `$_.Exception.Message); `$connected = `$false } finally { `$client.Dispose() }; if (`$connected) { Write-Output 'OK:B5_proxy_reachable'; exit 0 }; & whoami.exe /all | Write-Output; Write-Output 'FAIL:B5_proxy_blocked'; exit 1"
        },
        @{
            Name = "B6_direct_external_udp53_blocked"
            Command = "`$output = (& nslookup.exe example.com 8.8.8.8 2>&1) -join [Environment]::NewLine; if (`$output -match 'timed out|No response from server|UnKnown') { Write-Output 'OK:B6_udp53_blocked'; exit 0 }; Write-Output 'FAIL:B6_udp53_response'; Write-Output `$output; exit 1"
        }
    )

    foreach ($case in $proxyCases) {
        $configPath = Join-Path $tempRoot "$($case.Name).json"
        $config = [ordered]@{
            '$schema' = (Join-Path $repoRoot "schemas\dev\mxc-config.schema.0.8.0-dev.json")
            version = "0.8.0-dev"
            containerId = "CLI-$($case.Name)"
            containment = "processcontainer"
            process = [ordered]@{
                commandLine = "powershell.exe -NoProfile -NonInteractive -Command `"$($case.Command)`""
                timeout = 30000
            }
            filesystem = [ordered]@{
                readonlyPaths = @("C:\Windows")
            }
            ui = [ordered]@{
                disable = $false
            }
            network = [ordered]@{
                egress = [ordered]@{ default = "deny" }
                ingress = [ordered]@{ hostLoopback = "deny" }
            }
            runtimeConfig = [ordered]@{
                networkProxy = "http://127.0.0.1:$proxyPort"
            }
            processContainer = [ordered]@{
                network = [ordered]@{
                    allowedPeer = $allowedPeer
                }
            }
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding utf8
        Invoke-NetworkConfig -Name $case.Name -ConfigPath $configPath
    }
}
finally {
    if ($shutdownFile) {
        New-Item -ItemType File -Path $shutdownFile -Force | Out-Null
    }
    if ($proxyProcessId) {
        $proxyProcess = Get-Process -Id $proxyProcessId -ErrorAction SilentlyContinue
        if ($proxyProcess) {
            if (-not $proxyProcess.WaitForExit(3000)) {
                Stop-Process -Id $proxyProcessId -Force
            }
        }
    }
    if ($package) {
        Remove-AppxPackage -Package $package.PackageFullName
    }
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force
    }
}

Write-Host "`n=== BaseContainer network test summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$failed = @($results | Where-Object { $_.Status -eq "Failed" })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) BaseContainer network test(s) failed."
}

Write-Host "All BaseContainer network tests passed." -ForegroundColor Green
