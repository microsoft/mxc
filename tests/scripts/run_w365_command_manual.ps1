# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -Version 7.0
<#
.SYNOPSIS
    Run on a new or existing W365 session through wxc-exec; release explicitly.
.DESCRIPTION
    Manual-only. Run without SessionId checks out once. Run with the full opaque
    MXC ID never checks out. Sessions are retained even on failure. Authentication
    uses the existing protected Python MSAL helper, not a service implementation.
#>
[CmdletBinding()]
param(
    [ValidateSet('Run', 'Release')][string] $Operation = 'Run',
    [string] $SessionId,
    [string] $ConfigPath,
    [string] $PoolId,
    [string] $CommandLine,
    [string] $TenantId,
    [string] $ClientId,
    [string] $ControlPlaneHost,
    [string] $DataPlaneSuffix,
    [string] $WxcExePath,
    [string] $LoginHint,
    [string] $ExpectedUserObjectId,
    [string] $WorkingDirectory,
    [ValidateRange(0, 2147400000)][int] $TimeoutMs = 30000,
    [string] $ReceiptPath,
    [switch] $ForceSignIn
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\W365Common.ps1')
if (-not $IsWindows) { throw 'This manual runner requires Windows and current-user DPAPI.' }
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'w365-test.json' }
if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    $settings = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    if ($settings -isnot [System.Collections.IDictionary]) { throw 'Configuration must be a JSON object.' }
    foreach ($key in $settings.Keys) {
        if ($key -cnotin @('poolId', 'tenantId', 'clientId', 'controlPlaneHost', 'dataPlaneSuffix')) {
            throw 'Unknown configuration field. Configuration must not contain credentials.'
        }
        if ($settings[$key] -isnot [string]) { throw 'Configuration values must be strings.' }
    }
    foreach ($name in @('PoolId', 'TenantId', 'ClientId', 'ControlPlaneHost', 'DataPlaneSuffix')) {
        $key = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)
        if (-not $PSBoundParameters.ContainsKey($name) -and $settings.Contains($key)) {
            Set-Variable -Name $name -Value $settings[$key]
        }
    }
} elseif ($PSBoundParameters.ContainsKey('ConfigPath')) { throw 'ConfigPath does not exist.' }
if (-not $PSBoundParameters.ContainsKey('ControlPlaneHost') -and $env:W365A_CONTROLPLANE_URL) {
    $ControlPlaneHost = $env:W365A_CONTROLPLANE_URL
}
if (-not $PSBoundParameters.ContainsKey('DataPlaneSuffix') -and $env:W365A_DP_SUFFIX) {
    $DataPlaneSuffix = $env:W365A_DP_SUFFIX
}
$PoolId = Assert-W365Guid $PoolId 'PoolId'
$TenantId = Assert-W365Guid $TenantId 'TenantId'
$ClientId = Assert-W365Guid $ClientId 'ClientId'
if ($ExpectedUserObjectId) { $ExpectedUserObjectId = Assert-W365Guid $ExpectedUserObjectId 'ExpectedUserObjectId' }
Assert-W365Host $ControlPlaneHost 'ControlPlaneHost / W365A_CONTROLPLANE_URL'
if ($Operation -eq 'Run') {
    if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.Contains([char]0)) {
        throw 'CommandLine must be a nonblank Windows executable command line without NUL.'
    }
    if ($WorkingDirectory.Contains([char]0)) { throw 'WorkingDirectory must not contain NUL.' }
    Assert-W365Host $DataPlaneSuffix 'DataPlaneSuffix / W365A_DP_SUFFIX'
    if (("$PoolId.$DataPlaneSuffix").Length -gt 253) { throw 'Pool-prefixed data-plane hostname exceeds 253 characters.' }
} elseif (-not $SessionId -or $PSBoundParameters.ContainsKey('CommandLine')) {
    throw 'Release requires the full opaque SessionId and no CommandLine.'
}
$sandboxId = if ($SessionId) { Get-W365SandboxId $SessionId $PoolId } else { $null }
if (-not $ReceiptPath) {
    $ReceiptPath = Join-Path ([IO.Path]::GetTempPath()) "mxc-w365-manual-$([guid]::NewGuid().ToString('N')).json"
}
$ReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
Write-Host "Token-free receipt: $ReceiptPath"
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($ReceiptPath)) -PathType Container)) {
    throw 'ReceiptPath parent directory must already exist.'
}
$exe = Get-W365Executor $WxcExePath (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
if (-not ('Mxc.W365Manual.ChildProcess' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'lib\W365Process.cs') }
$lock = [IO.File]::Open("$ReceiptPath.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$journal = $null
$journalCreated = $false
$commandExit = $null
$auth = $null
try {
    $existing = Test-Path -LiteralPath $ReceiptPath
    if ($existing) {
        if (-not $sandboxId) { throw 'A receipt already exists. Never reuse a receipt for another checkout.' }
        $journal = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json -AsHashtable
        if ($journal.format -cne 'mxc-w365-manual-v2' -or $journal.sandboxId -cne $sandboxId -or
            $journal.poolId -ine $PoolId -or $journal.tenantId -ine $TenantId -or
            $journal.clientId -ine $ClientId -or $journal.controlPlaneHost -ine $ControlPlaneHost -or
            ($Operation -eq 'Run' -and $journal.dataPlaneSuffix -ine $DataPlaneSuffix) -or
            $journal.tokenPersisted -ne $false -or
            $journal.state -notin @('Completed', 'FailedOrUnknown', 'ReleaseAccepted', 'startSubmitted', 'execSubmitted', 'deprovisionSubmitted')) {
            throw 'Receipt identity, deployment, format, or state does not match; reconcile it before proceeding.'
        }
        if ($journal.releaseAccepted) { throw 'Release was already accepted; this session must not be reused.' }
        if ($journal.state -ceq 'deprovisionSubmitted') { throw 'Reconcile the submitted release before another attempt; never replay an uncertain release.' }
        if ($Operation -eq 'Run' -and $journal.state -cne 'Completed') {
            throw 'The prior outcome is uncertain; reconcile it before another command. Explicit release is still available.'
        }
        if ($ExpectedUserObjectId -and $journal.userObjectId -ine $ExpectedUserObjectId) { throw 'Receipt owner mismatch.' }
        $ExpectedUserObjectId = Assert-W365Guid $journal.userObjectId 'Receipt owner'
    }
    $base = @{ version = '1.1.0-alpha' }
    $provision = @{
        version = '1.1.0-alpha'; containment = 'w365_agents'
        w365Agents = @{ provision = @{ poolId = $PoolId; userType = 'Local'
            userObjectId = $(if ($ExpectedUserObjectId) { $ExpectedUserObjectId } else { '11111111-1111-1111-1111-111111111111' }) } }
    }
    $execRequest = @{ version = '1.1.0-alpha'; process = @{ commandLine = $CommandLine; timeout = $TimeoutMs } }
    if ($PSBoundParameters.ContainsKey('WorkingDirectory')) { $execRequest.process.cwd = $WorkingDirectory }
    $phases = if ($Operation -eq 'Release') { @('deprovision') }
        elseif ($sandboxId) { @('start', 'exec') } else { @('provision', 'start', 'exec') }
    foreach ($phase in $phases) {
        $request = if ($phase -eq 'provision') { $provision } elseif ($phase -eq 'exec') { $execRequest } else { $base }
        $id = if ($phase -eq 'provision') { $null } else { "w365:${PoolId}:11111111-1111-1111-1111-111111111111" }
        $native = Invoke-W365Native $exe $phase $request $id $ControlPlaneHost $DataPlaneSuffix 'synthetic-preflight-token' 15000 -DryRun
        $envelope = ConvertFrom-W365Envelope $native
        if ($native.ExitCode -ne 0 -or $envelope.Contains('error')) {
            throw "Executor development-contract/experimental $phase dry-run failed; no sign-in or service request performed."
        }
    }
    $auth = Get-W365Token $TenantId $ClientId $LoginHint $ExpectedUserObjectId -Force:$ForceSignIn
    $provision.w365Agents.provision.userObjectId = $auth.UserObjectId
    if (-not $existing) {
        $journal = @{
            format = 'mxc-w365-manual-v2'; runId = [guid]::NewGuid().ToString('D')
            poolId = $PoolId; tenantId = $TenantId; clientId = $ClientId; userObjectId = $auth.UserObjectId
            controlPlaneHost = $ControlPlaneHost; dataPlaneSuffix = $DataPlaneSuffix
            userType = 'Local'; apiVersion = '2.0'; contractVersion = '1.1.0-alpha'
            startedUtc = [DateTimeOffset]::UtcNow.ToString('o'); state = 'Prepared'
            allocationRequestCount = $(if ($sandboxId) { 0 } else { 1 }); tokenPersisted = $false
            remoteResetConfirmed = $false; releaseAccepted = $false; operations = @()
            sandboxId = $sandboxId; sessionId = $sandboxId
        }
        Save-W365Journal $ReceiptPath $journal -Create
    }
    $journalCreated = $true
    foreach ($phase in $phases) {
        $auth = Get-W365CleanupAuth $auth $TenantId $ClientId $LoginHint
        $journal.state = "${phase}Submitted"
        Save-W365Journal $ReceiptPath $journal
        $budget = switch ($phase) {
            'provision' { 60000 }
            'start' { 135000 }
            'exec' { $(if ($TimeoutMs -eq 0) { 300000 } else { $TimeoutMs }) + 45000 }
            'deprovision' { 45000 }
        }
        $request = if ($phase -eq 'provision') { $provision } elseif ($phase -eq 'exec') { $execRequest } else { $base }
        $native = Invoke-W365Native $exe $phase $request $sandboxId $ControlPlaneHost $DataPlaneSuffix $auth.Token $budget -Stream:($phase -eq 'exec')
        $record = @{ operation = $phase; nativeExitCode = $native.ExitCode; outcome = 'FailedOrUnknown' }
        $journal.operations += $record
        if ($phase -eq 'exec') {
            if ($native.Failure) { throw "Native $($native.Failure); remote command outcome unknown." }
            $commandExit = $native.ExitCode
            $journal.nativeExecExitCode = $commandExit
            $record.outcome = if ($commandExit -eq 0) { 'Completed' } else { 'FailedOrUnknown' }
            if ($commandExit -ne 0) { throw "Command/native exec exited $commandExit; remote outcome may be unknown. No replay." }
        } else {
            $envelope = ConvertFrom-W365Envelope $native
            if ($envelope.Contains('error')) {
                $record.error = Get-W365SafeError $envelope.error
                if ($phase -eq 'provision' -and
                    $envelope.error['details'] -is [System.Collections.IDictionary] -and $envelope.error.details['sandboxId']) {
                    $sandboxId = Get-W365SandboxId $envelope.error.details['sandboxId'] $PoolId
                }
                throw "Native $phase failed: $($record.error | ConvertTo-Json -Compress)."
            }
            if ($phase -eq 'provision') {
                $sandboxId = Get-W365SandboxId $envelope.result.sandboxId $PoolId
                $journal.sandboxId = $sandboxId
                $journal.sessionId = $sandboxId
                Save-W365Journal $ReceiptPath $journal
                Write-Host "MXC SessionId: $sandboxId"
                $parts = $sandboxId.Split(':')
                if ($envelope.result.metadata.poolId -ine $parts[1] -or
                    $envelope.result.metadata.sessionId -ine $parts[2] -or
                    $envelope.result.metadata.computerId -ine $parts[2]) {
                    throw 'Provision metadata does not match the saved cleanup identity.'
                }
            }
            if ($native.ExitCode -ne 0) { throw "Native $phase exited $($native.ExitCode) without a structured error." }
            if ($phase -eq 'start' -and $envelope.result.metadata.status -cne 'Ready') {
                throw 'Native start did not confirm Ready; no command submitted.'
            }
            if ($phase -eq 'deprovision') {
                if ($envelope.result.metadata.releaseRequested -ne $true -or $envelope.result.metadata.restartable -ne $false) {
                    throw 'Native deprovision did not confirm terminal release acceptance.'
                }
                $journal.releaseAccepted = $true
                $record.outcome = 'AcceptedNotResetConfirmed'
            } else { $record.outcome = 'Succeeded' }
        }
        Save-W365Journal $ReceiptPath $journal
    }
    $journal.state = if ($journal.releaseAccepted) { 'ReleaseAccepted' } else { 'Completed' }
    Save-W365Journal $ReceiptPath $journal
    if ($journal.releaseAccepted) { Write-Host 'Terminal release accepted; remote reset/sanitization is NOT confirmed.' }
    else { Write-Host "Session retained. Reuse or explicitly release MXC SessionId: $sandboxId" }
} catch {
    $failure = $_.Exception.Message
    if ($journalCreated) {
        $journal.state = if ($journal.releaseAccepted) { 'ReleaseAccepted' }
            elseif ($journal.state -ceq 'deprovisionSubmitted') { 'deprovisionSubmitted' }
            else { 'FailedOrUnknown' }
        $journal.sandboxId = $sandboxId
        $journal.sessionId = $sandboxId
        $journal.primaryFailure = $failure
        $journal.reconciliationRequired = $true
        try { Save-W365Journal $ReceiptPath $journal }
        catch { Write-Host 'Receipt update failed; preserve the earlier journal and reconcile the outcome.' }
    }
    Write-Host "Failure: $failure"
    if ($sandboxId) { Write-Host "Session NOT automatically released. MXC SessionId: $sandboxId" }
    elseif ($journalCreated) { Write-Host 'Checkout outcome unknown without a cleanup ID; reconcile before another checkout.' }
    if ($null -ne $commandExit -and $commandExit -ne 0) { exit $commandExit }
    exit 1
} finally {
    $auth = $null
    $lock.Dispose()
}
exit 0
