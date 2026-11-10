# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -Version 7.0
<#
.SYNOPSIS
    Manual-only W365 Local checkout, readiness, one command, and terminal release.
.DESCRIPTION
    Uses wxc-exec for every service operation. Not registered in CI or aggregate
    runners. Authentication uses Python MSAL system-browser sign-in and a
    current-user Windows DPAPI cache. See the W365 backend guide for prerequisites,
    the fixed ARI INT resource, and recovery after uncertain outcomes.
.EXAMPLE
    .\run_w365_command_manual.ps1 -PoolId <guid> -TenantId <guid> -ClientId <guid> `
        -CommandLine 'cmd.exe /c echo hello' -ControlPlaneHost <host> -DataPlaneSuffix <suffix>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $PoolId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $CommandLine,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $ClientId,
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

$PoolId = Assert-W365Guid $PoolId 'PoolId'
$TenantId = Assert-W365Guid $TenantId 'TenantId'
$ClientId = Assert-W365Guid $ClientId 'ClientId'
if ($ExpectedUserObjectId) { $ExpectedUserObjectId = Assert-W365Guid $ExpectedUserObjectId 'ExpectedUserObjectId' }
if ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.Contains([char]0)) {
    throw 'CommandLine must be a nonblank Windows executable command line without NUL.'
}
if ($WorkingDirectory.Contains([char]0)) { throw 'WorkingDirectory must not contain NUL.' }
if (-not $IsWindows) { throw 'This manual runner requires Windows and current-user DPAPI.' }
if (-not $PSBoundParameters.ContainsKey('ControlPlaneHost')) { $ControlPlaneHost = $env:W365A_CONTROLPLANE_URL }
if (-not $PSBoundParameters.ContainsKey('DataPlaneSuffix')) { $DataPlaneSuffix = $env:W365A_DP_SUFFIX }
Assert-W365Host $ControlPlaneHost 'ControlPlaneHost / W365A_CONTROLPLANE_URL'
Assert-W365Host $DataPlaneSuffix 'DataPlaneSuffix / W365A_DP_SUFFIX'
if (("$PoolId.$DataPlaneSuffix").Length -gt 253) { throw 'Pool-prefixed data-plane hostname exceeds 253 characters.' }
if (-not $ReceiptPath) {
    $ReceiptPath = Join-Path ([IO.Path]::GetTempPath()) "mxc-w365-manual-$([guid]::NewGuid().ToString('N')).json"
}
$ReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
Write-Host "Token-free receipt: $ReceiptPath"
if (Test-Path -LiteralPath $ReceiptPath) {
    throw 'A receipt already exists. Keep/reconcile it; this runner never overwrites or reuses a prior attempt.'
}
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($ReceiptPath)) -PathType Container)) {
    throw 'ReceiptPath parent directory must already exist.'
}
$exe = Get-W365Executor $WxcExePath (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
if (-not ('Mxc.W365Manual.ChildProcess' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'lib\W365Process.cs') }

$base = @{ version = '1.1.0-alpha' }
$provision = @{
    version = '1.1.0-alpha'; containment = 'w365_agents'
    w365Agents = @{ provision = @{ poolId = $PoolId; userType = 'Local'
        userObjectId = $(if ($ExpectedUserObjectId) { $ExpectedUserObjectId } else { '11111111-1111-1111-1111-111111111111' }) } }
}
$execRequest = @{ version = '1.1.0-alpha'; process = @{ commandLine = $CommandLine; timeout = $TimeoutMs } }
if ($PSBoundParameters.ContainsKey('WorkingDirectory')) { $execRequest.process.cwd = $WorkingDirectory }
$preflightId = "w365:${PoolId}:11111111-1111-1111-1111-111111111111"
foreach ($phase in @('provision', 'start', 'exec', 'deprovision')) {
    $request = if ($phase -eq 'provision') { $provision } elseif ($phase -eq 'exec') { $execRequest } else { $base }
    $id = if ($phase -eq 'provision') { $null } else { $preflightId }
    $native = Invoke-W365Native $exe $phase $request $id $ControlPlaneHost $DataPlaneSuffix `
        'synthetic-preflight-token' 15000 -DryRun
    $envelope = ConvertFrom-W365Envelope $native
    if ($native.ExitCode -ne 0 -or $envelope.Contains('error')) {
        throw "Executor development-contract/experimental $phase dry-run failed; no sign-in or service request performed."
    }
}
Write-Host 'Using the protected MSAL cache, or system-browser sign-in when required.'
Write-Host "Encrypted cache: $env:LOCALAPPDATA\Microsoft\MXC\w365-manual-auth\${TenantId}_${ClientId}.bin"
$auth = Get-W365Token $TenantId $ClientId $LoginHint $ExpectedUserObjectId -Force:$ForceSignIn
$provision.w365Agents.provision.userObjectId = $auth.UserObjectId
$journal = @{
    format = 'mxc-w365-manual-v1'; runId = [guid]::NewGuid().ToString('D')
    poolId = $PoolId; tenantId = $TenantId; clientId = $ClientId; userObjectId = $auth.UserObjectId
    controlPlaneHost = $ControlPlaneHost; dataPlaneSuffix = $DataPlaneSuffix
    userType = 'Local'; apiVersion = '2.0'; contractVersion = '1.1.0-alpha'
    startedUtc = [DateTimeOffset]::UtcNow.ToString('o'); state = 'CheckoutSubmitted'
    allocationRequestCount = 1; tokenPersisted = $false
    remoteResetConfirmed = $false; releaseAccepted = $false; operations = @()
}
$sandboxId = $null
$primaryFailure = $null
$cleanupFailure = $null
$commandExit = $null
$journalCreated = $false
try {
    Save-W365Journal $ReceiptPath $journal -Create
    $journalCreated = $true
    foreach ($phase in @('provision', 'start', 'exec')) {
        $journal.state = "${phase}Submitted"
        Save-W365Journal $ReceiptPath $journal
        $budget = switch ($phase) {
            'provision' { 60000 }
            'start' { 135000 }
            'exec' { $(if ($TimeoutMs -eq 0) { 300000 } else { $TimeoutMs }) + 45000 }
        }
        $request = if ($phase -eq 'provision') { $provision } elseif ($phase -eq 'exec') { $execRequest } else { $base }
        $native = Invoke-W365Native $exe $phase $request $sandboxId $ControlPlaneHost $DataPlaneSuffix `
            $auth.Token $budget -Stream:($phase -eq 'exec')
        $record = @{ operation = $phase; nativeExitCode = $native.ExitCode; outcome = 'Unknown' }
        $journal.operations += $record
        if ($phase -eq 'exec') {
            # Exec stdout/stderr belong to the guest/native adapter, never to
            # lifecycle JSON parsing or the journal.
            if ($native.Failure) { throw "Native $($native.Failure); remote command outcome unknown." }
            $commandExit = $native.ExitCode
            $record.outcome = if ($commandExit -eq 0) { 'Completed' } else { 'FailedOrUnknown' }
            $journal.nativeExecExitCode = $commandExit
            Save-W365Journal $ReceiptPath $journal
            if ($commandExit -ne 0) {
                throw "Command/native exec exited $commandExit; remote outcome may be unknown. See streamed stderr; no replay."
            }
            continue
        }
        $envelope = ConvertFrom-W365Envelope $native
        if ($envelope.Contains('error')) {
            $record.error = Get-W365SafeError $envelope.error
            if ($phase -eq 'provision' -and
                $envelope.error['details'] -is [System.Collections.IDictionary] -and $envelope.error.details['sandboxId']) {
                $sandboxId = Get-W365SandboxId $envelope.error.details['sandboxId'] $PoolId
            }
            $record.outcome = 'FailedOrUnknown'
            throw "Native $phase failed: $($record.error | ConvertTo-Json -Compress)."
        }
        if ($phase -eq 'provision') {
            # Retain a valid cleanup ID even when exit status or metadata is bad.
            $sandboxId = Get-W365SandboxId $envelope.result.sandboxId $PoolId
        }
        if ($native.ExitCode -ne 0) { throw "Native $phase exited $($native.ExitCode) without a structured error." }
        if ($phase -eq 'start' -and $envelope.result.metadata.status -cne 'Ready') {
            throw 'Native start did not confirm Ready; no command submitted.'
        }
        $record.outcome = 'Succeeded'
        if ($sandboxId) {
            $journal.sandboxId = $sandboxId
            $journal.sessionId = $sandboxId.Split(':')[2]
        }
        Save-W365Journal $ReceiptPath $journal
    }
} catch {
    $primaryFailure = $_.Exception.Message
    if ($journalCreated) {
        $journal.state = 'FailedOrUnknown'
        $journal.primaryFailure = $primaryFailure
    }
} finally {
    if ($journalCreated -and $sandboxId) {
        $journal.sandboxId = $sandboxId
        $journal.sessionId = $sandboxId.Split(':')[2]
        $journal.state = 'ReleaseSubmitted'
        try {
            try { Save-W365Journal $ReceiptPath $journal }
            catch {
                $cleanupFailure = 'Receipt update failed before release; terminal release will still be attempted.'
                $journal.journalFailure = $cleanupFailure
            }
            $auth = Get-W365CleanupAuth $auth $TenantId $ClientId $LoginHint
            $native = Invoke-W365Native $exe 'deprovision' $base $sandboxId $ControlPlaneHost $DataPlaneSuffix $auth.Token 45000
            $record = @{ operation = 'deprovision'; nativeExitCode = $native.ExitCode; outcome = 'FailedOrUnknown' }
            $journal.operations += $record
            $envelope = ConvertFrom-W365Envelope $native
            if ($envelope.Contains('error')) {
                $record.error = Get-W365SafeError $envelope.error
                throw "Native deprovision failed: $($record.error | ConvertTo-Json -Compress)."
            }
            if ($native.ExitCode -ne 0 -or $envelope.result.metadata.releaseRequested -ne $true -or
                $envelope.result.metadata.restartable -ne $false) {
                throw 'Native deprovision did not confirm terminal release acceptance.'
            }
            $journal.releaseAccepted = $true
            $record.outcome = 'AcceptedNotResetConfirmed'
            $journal.state = 'ReleaseAccepted'
        } catch {
            $cleanupFailure = @($cleanupFailure, $_.Exception.Message) | Where-Object { $_ } | Join-String -Separator ' '
            $journal.cleanupFailure = $cleanupFailure
            $journal.state = 'ReleaseFailedOrUnknown'
        }
    } elseif ($journalCreated) {
        $journal.state = 'CheckoutOutcomeUnknownNoCleanupId'
        $journal.reconciliationRequired = $true
    }
    $auth = $null
    if ($journalCreated) {
        try { Save-W365Journal $ReceiptPath $journal }
        catch {
            $cleanupFailure = @($cleanupFailure, 'Final receipt write failed; retain the earlier journal and reconcile.') |
                Where-Object { $_ } | Join-String -Separator ' '
        }
    }
}
if ($primaryFailure) { Write-Host "Primary failure: $primaryFailure" }
if ($cleanupFailure) { Write-Host "Cleanup failure (same saved ID): $cleanupFailure" }
if (-not $sandboxId -and $journalCreated) {
    Write-Host 'No valid cleanup ID. Keep the receipt and reconcile request IDs with the service operator; do not replay checkout.'
}
if ($journal.releaseAccepted) { Write-Host 'Terminal release accepted; remote reset/sanitization is NOT confirmed.' }
if ($primaryFailure -or $cleanupFailure) {
    if ($null -ne $commandExit -and $commandExit -ne 0 -and -not $cleanupFailure) { exit $commandExit }
    exit 1
}
exit 0
