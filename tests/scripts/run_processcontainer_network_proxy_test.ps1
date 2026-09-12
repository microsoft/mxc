# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_network_proxy_test.ps1
#
# runtimeConfig.networkProxy and proxy peer identity.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_network_proxy_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$CargoRoot,
    [string]$WxcDebug,
    [string]$WxcRelease,
    [string]$UiProbeDebug,
    [string]$UiProbeRelease,
    [string]$ScratchRoot,
    [string]$ResultsJson,
    [string]$CargoLog,
    [string]$CapsJson,
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 8e — schema 0.8 runtime proxy (model 2).
#
# docs/process-container/networking.md is explicit and testable here:
#   * MXC sets HTTP_PROXY / HTTPS_PROXY and their lowercase variants to the
#     loopback endpoint;
#   * NO_PROXY is a bypass list and must NOT carry the proxy endpoint;
#   * direct egress is blocked while the proxy is configured;
#   * "Direct egress allow and deny rules do not apply when
#     runtimeConfig.networkProxy is present";
#   * identity-scoped (allowedProxyPeer present) keeps hostLoopback deny;
#     identity-less REQUIRES hostLoopback allow;
#   * schema 0.8 proxy requests never fall back to SBOX or AppContainer.
#
# The env-var contract is asserted by having the workload print its own
# environment — a log line saying MXC configured a proxy does not prove the
# child received it.
# -----------------------------------------------------------------------
function Phase-NetworkProxy {
    Section 'Phase 8e: schema 0.8 runtime proxy (model 2)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8e' -Name 'runtime proxy' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible
    $port = Get-FreeTcpPort
    $proxyUrl = "http://127.0.0.1:$port"

    # Identity-less deployment: no allowedProxyPeer, so the doc requires
    # ingress.default=allow AND hostLoopback=allow. Workload dumps its env.
    $envDump = "$env:SystemRoot\System32\cmd.exe /c set"
    $cfgEnv = New-Config -Name 'net-proxy-envvars' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'allow' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $envRun = Invoke-NetRun -Name 'net-proxy-envvars' -ConfigPath $cfgEnv

    if ($psec) {
        $out = $envRun.Result.Stdout
        $ran = [bool]($out -match '(?im)^SystemRoot=')
        Record-Result -Phase 'P8e' -Name 'identity-less proxy config runs (ingress=allow + hostLoopback=allow)' `
            -Pass $ran -Detail "exit=$($envRun.Result.ExitCode); stderr=$(Format-Snippet $envRun.Result.Stderr)"
        if ($ran) {
            foreach ($v in @('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')) {
                # cmd.exe `set` upper-cases nothing, but Windows env lookup is
                # case-insensitive and duplicate-insensitive, so a variable set
                # twice in different cases collapses. Match case-insensitively
                # on the name and require the endpoint as the value.
                $hit = [bool]($out -match ("(?im)^" + [regex]::Escape($v) + "=.*" + [regex]::Escape("127.0.0.1:$port")))
                Record-Result -Phase 'P8e' -Name "child env carries $v = proxy endpoint" `
                    -Pass $hit -Detail "endpoint=127.0.0.1:$port"
            }
            # NO_PROXY is a bypass list. Carrying the endpoint there would tell
            # cooperating clients to bypass the very proxy they must use.
            $noProxyPoisoned = [bool]($out -match ("(?im)^no_proxy=.*" + [regex]::Escape("127.0.0.1:$port")))
            Record-Result -Phase 'P8e' -Name 'NO_PROXY does NOT carry the proxy endpoint' `
                -Pass (-not $noProxyPoisoned) -Detail 'NO_PROXY is a bypass list, not a proxy setting'
        }

        # Direct egress must be blocked while the proxy is configured. The
        # proxy is not actually listening, so a REACHED verdict here means the
        # workload went straight out — the exact bypass the model forbids.
        $cfgDirect = New-Config -Name 'net-proxy-direct-blocked' `
            -CommandLine (Get-AnchorFetchCommand) `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'allow' `
            -NetworkProxy $proxyUrl -TimeoutMs 25000
        $direct = Invoke-NetRun -Name 'net-proxy-direct-blocked' -ConfigPath $cfgDirect
        Record-Result -Phase 'P8e' -Name 'direct egress blocked while runtime proxy is configured' `
            -Pass ($direct.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($direct.Verdict); WFP scopes egress to the proxy endpoint only"
    } else {
        # "schema 0.8 runtime proxy requests do not fall back because neither
        # SBOX nor AppContainer can preserve their peer or host-loopback
        # requirements."
        $rejected = Test-WasRejected $envRun
        Record-Result -Phase 'P8e' -Name 'non-PSEC tier rejects schema 0.8 runtime proxy (no fallback)' `
            -Pass $rejected `
            -Detail "exit=$($envRun.Result.ExitCode); timedOut=$($envRun.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # --- Model-2 shape requirements, independent of tier. -----------------
    # Identity-scoped: allowedProxyPeer present, hostLoopback stays deny.
    $cfgPeer = New-Config -Name 'net-proxy-identity-scoped' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' `
        -NetworkProxy $proxyUrl -AllowedProxyPeer 'Contoso.Proxy_8wekyb3d8bbwe' -TimeoutMs 25000
    $peer = Invoke-NetRun -Name 'net-proxy-identity-scoped' -ConfigPath $cfgPeer
    if ($psec) {
        # The peer does not exist on this host, so a launch failure is
        # expected; what must NOT happen is the config being refused as an
        # invalid SHAPE. "No rejection message" alone is not evidence — an
        # empty stderr, a harness timeout, or a binary that never started all
        # look the same — so positive proof that the config cleared validation
        # is required too.
        $peerLog = Remove-ConfigEcho $peer.Log
        $shapeRejected = [bool]("$($peer.Result.Stderr)" -match '(?i)policy_validation|unsupported.*polic|invalid.*(polic|config|network)')
        $gotPastValidation = ($peer.Result.ExitCode -eq 0) -or ($peerLog -match '(?i)selected isolation tier')
        Record-Result -Phase 'P8e' -Name 'identity-scoped proxy shape (peer + hostLoopback=deny) is a valid policy' `
            -Pass ($gotPastValidation -and -not $shapeRejected) `
            -Detail ("exit=$($peer.Result.ExitCode); pastValidation=$gotPastValidation; " +
                     "stderr=$(Format-Snippet $peer.Result.Stderr)")
    } else {
        Record-Result -Phase 'P8e' -Name 'non-PSEC tier rejects allowedProxyPeer' `
            -Pass (Test-WasRejected $peer) `
            -Detail "exit=$($peer.Result.ExitCode); timedOut=$($peer.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # The two shape rules below are only meaningful on PSEC. On a non-PSEC
    # tier the phase has already asserted that EVERY schema 0.8 runtime-proxy
    # config is refused, so asserting "this particular one is refused" would be
    # green by construction and would test nothing about the rule it names.
    if (-not $psec) {
        Record-Result -Phase 'P8e' -Name 'model-2 shape rules (hostLoopback / ingress.default)' -Status 'skip' `
            -Detail "tier=$($Script:ExpectedTier) refuses all 0.8 runtime proxies, so a shape-specific rejection is not attributable"
        return
    }

    # Identity-less proxy WITHOUT hostLoopback=allow. The doc says this
    # deployment requires it, so the configuration is incomplete and must be
    # refused rather than run with a proxy the container cannot reach.
    $cfgNoLoopback = New-Config -Name 'net-proxy-identityless-no-loopback' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $noLoopback = Invoke-NetRun -Name 'net-proxy-identityless-no-loopback' -ConfigPath $cfgNoLoopback
    Record-Result -Phase 'P8e' -Name 'identity-less proxy without hostLoopback=allow is rejected' `
        -Pass (Test-WasRejected $noLoopback) `
        -Detail "exit=$($noLoopback.Result.ExitCode); timedOut=$($noLoopback.Result.TimedOut); doc requires hostLoopback=allow when allowedProxyPeer is omitted"

    # Model 2 requires ingress.default=allow. Without it the client container
    # never gets privateNetworkClientServer and cannot reach a loopback proxy.
    $cfgNoIngress = New-Config -Name 'net-proxy-no-ingress-allow' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'allow' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $noIngress = Invoke-NetRun -Name 'net-proxy-no-ingress-allow' -ConfigPath $cfgNoIngress
    Record-Result -Phase 'P8e' -Name 'runtime proxy without ingress.default=allow is rejected' `
        -Pass (Test-WasRejected $noIngress) `
        -Detail "exit=$($noIngress.Result.ExitCode); timedOut=$($noIngress.Result.TimedOut); model 2 requires egress deny + ingress allow"
}

Invoke-WpcPhase -Key 'NetworkProxy' -Body { Phase-NetworkProxy }
Complete-WpcChild

