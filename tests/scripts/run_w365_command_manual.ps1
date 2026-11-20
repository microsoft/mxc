# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -Version 7.0
<#
.SYNOPSIS
    Run on a new or existing W365 session through wxc-exec; release explicitly.
.DESCRIPTION
    Manual-only. Run without SessionId invokes provision once. Run with the full opaque
    MXC ID never checks out. Sessions are retained even on failure. Authentication
    uses separate Graph and service credentials through the Python MSAL helper.
    Provision performs checkout only, without readiness polling or execution.
.PARAMETER Operation
    Run executes on a new or existing session. Provision checks out one new
    session without readiness polling or execution. Release returns a session.
#>
[CmdletBinding()]
param(
    [ValidateSet('Run', 'Provision', 'Release')][string] $Operation = 'Run',
    [string] $SessionId,
    [string] $ConfigPath,
    [string] $PoolId,
    [string] $CommandLine,
    [string] $TenantId,
    [string] $ClientId,
    [ValidateSet('public', 'canary')][string] $GraphEnvironment = 'public',
    [string] $ControlPlaneResource,
    [string] $DataPlaneResource,
    [string] $WxcExePath,
    [string] $LoginHint,
    [string] $ExpectedUserObjectId,
    [string] $WorkingDirectory,
    [ValidateRange(0, 600000)][int] $TimeoutMs = 30000,
    [string] $ReceiptPath,
    [switch] $ForceSignIn
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\W365Common.ps1')
if (-not $IsWindows) { throw 'This manual runner requires Windows and current-user DPAPI.' }
if ($Operation -eq 'Provision' -and (
    $PSBoundParameters.ContainsKey('SessionId') -or $PSBoundParameters.ContainsKey('CommandLine') -or
    $PSBoundParameters.ContainsKey('WorkingDirectory') -or $PSBoundParameters.ContainsKey('TimeoutMs'))) {
    throw 'Provision requires no SessionId, CommandLine, WorkingDirectory or TimeoutMs.'
}
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'w365-test.json' }
$settings = @{}
if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    $settings = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    if ($settings -isnot [System.Collections.IDictionary]) { throw 'Configuration must be a JSON object.' }
    foreach ($key in $settings.Keys) {
        if ($key -cnotin @('poolId', 'tenantId', 'clientId',
                'graphEnvironment', 'controlPlaneResource', 'dataPlaneResource')) {
            throw 'Unknown configuration field. Configuration must not contain credentials.'
        }
        if ($settings[$key] -isnot [string]) { throw 'Configuration values must be strings.' }
    }
    foreach ($name in @('PoolId', 'TenantId', 'ClientId',
            'GraphEnvironment', 'ControlPlaneResource', 'DataPlaneResource')) {
        $key = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)
        if (-not $PSBoundParameters.ContainsKey($name) -and $settings.Contains($key)) {
            Set-Variable -Name $name -Value $settings[$key]
        }
    }
} elseif ($PSBoundParameters.ContainsKey('ConfigPath')) { throw 'ConfigPath does not exist.' }
if ($PSBoundParameters.ContainsKey('PoolId') -or $settings.Contains('poolId')) {
    $PoolId = Assert-W365Guid $PoolId 'PoolId'
}
$requestedPoolId = $PoolId
$TenantId = Assert-W365Guid $TenantId 'TenantId'
$ClientId = Assert-W365Guid $ClientId 'ClientId'
$GraphEnvironment = $GraphEnvironment.ToLowerInvariant()
$defaultResource = if ($GraphEnvironment -eq 'public') { '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5' }
    else { '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' }
if (-not $PSBoundParameters.ContainsKey('ControlPlaneResource') -and -not $settings.Contains('controlPlaneResource')) {
    $ControlPlaneResource = $defaultResource
}
if (-not $PSBoundParameters.ContainsKey('DataPlaneResource') -and -not $settings.Contains('dataPlaneResource')) {
    $DataPlaneResource = $defaultResource
}
$ControlPlaneResource = Assert-W365Guid $ControlPlaneResource 'ControlPlaneResource'
$DataPlaneResource = Assert-W365Guid $DataPlaneResource 'DataPlaneResource'
if ($ExpectedUserObjectId) { $ExpectedUserObjectId = Assert-W365Guid $ExpectedUserObjectId 'ExpectedUserObjectId' }
if ($Operation -in @('Run', 'Provision')) {
    if ($Operation -eq 'Run' -and ([string]::IsNullOrWhiteSpace($CommandLine) -or $CommandLine.Contains([char]0))) {
        throw 'CommandLine must be a nonblank Windows executable command line without NUL.'
    }
    if ($WorkingDirectory.Contains([char]0)) { throw 'WorkingDirectory must not contain NUL.' }
} elseif (-not $SessionId -or $PSBoundParameters.ContainsKey('CommandLine')) {
    throw 'Release requires the full opaque SessionId and no CommandLine.'
}
$sandboxId = if ($SessionId) { Get-W365SandboxId $SessionId } else { $null }
if ($sandboxId) { $PoolId = $sandboxId.Split(':')[1] }
$newProvision = -not $sandboxId
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
$graphAuth = $null
$dpAuth = $null
try {
    $existing = Test-Path -LiteralPath $ReceiptPath
    if ($existing) {
        if (-not $sandboxId) { throw 'A receipt already exists. Never reuse a receipt for another checkout.' }
        $journal = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json -AsHashtable
        if ($journal.format -cne 'mxc-w365-manual-v3' -or $journal.sandboxId -cne $sandboxId -or
            $journal.poolId -ine $PoolId -or $journal.tenantId -ine $TenantId -or
            $journal.clientId -ine $ClientId -or $journal.graphEnvironment -ine $GraphEnvironment -or
            $journal.controlPlaneResource -ine $ControlPlaneResource -or $journal.dataPlaneResource -ine $DataPlaneResource -or
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
    $provisionRequest = @{
        version = '1.1.0-alpha'; containment = 'w365_agents'
        w365Agents = @{ provision = @{ userType = 'Local'
            userObjectId = $(if ($ExpectedUserObjectId) { $ExpectedUserObjectId } else { '11111111-1111-1111-1111-111111111111' }) } }
    }
    if ($requestedPoolId) { $provisionRequest.w365Agents.provision.poolId = $requestedPoolId }
    $execRequest = @{ version = '1.1.0-alpha'; process = @{ commandLine = $CommandLine; timeout = $TimeoutMs } }
    if ($PSBoundParameters.ContainsKey('WorkingDirectory')) { $execRequest.process.cwd = $WorkingDirectory }
    $phases = if ($Operation -eq 'Release') { @('deprovision') }
        elseif ($Operation -eq 'Provision') { @('provision') }
        elseif ($sandboxId) { @('start', 'exec') } else { @('provision', 'start', 'exec') }
    # Later dry-runs require the routing record created by provision.
    $preflight = if ($newProvision) { @('provision') } else { $phases }
    foreach ($phase in $preflight) {
        $request = if ($phase -eq 'provision') { $provisionRequest } elseif ($phase -eq 'exec') { $execRequest } else { $base }
        $native = Invoke-W365Native $exe $phase $request $sandboxId $GraphEnvironment `
            'synthetic-preflight-token' 'synthetic-preflight-graph-token' 15000 -DryRun `
            -UseDataPlaneToken:($phase -in @('start', 'exec') -and $DataPlaneResource -ne $ControlPlaneResource)
        $envelope = ConvertFrom-W365Envelope $native
        if ($native.ExitCode -ne 0 -or $envelope.Contains('error')) {
            throw "Executor development-contract/experimental $phase dry-run failed; no sign-in or service request performed."
        }
    }
    $resource = if ($newProvision -or $Operation -eq 'Release') { $ControlPlaneResource } else { $DataPlaneResource }
    $auth = Get-W365Token $TenantId $ClientId $LoginHint $ExpectedUserObjectId -ResourceId $resource -Force:$ForceSignIn
    if ($newProvision) {
        $graphAuth = Get-W365Token $TenantId $ClientId $LoginHint $auth.UserObjectId -Graph -GraphEnvironment $GraphEnvironment -Force:$ForceSignIn
    } elseif ($Operation -eq 'Run') { $dpAuth = $auth }
    $provisionRequest.w365Agents.provision.userObjectId = $auth.UserObjectId
    if (-not $existing) {
        $journal = @{
            format = 'mxc-w365-manual-v3'; runId = [guid]::NewGuid().ToString('D')
            poolId = $(if ($sandboxId) { $PoolId } else { $null }); requestedPoolId = $(if ($requestedPoolId) { $requestedPoolId } else { $null })
            tenantId = $TenantId; clientId = $ClientId; userObjectId = $auth.UserObjectId
            graphEnvironment = $GraphEnvironment; controlPlaneResource = $ControlPlaneResource; dataPlaneResource = $DataPlaneResource
            routingOwner = 'native-backend'
            userType = 'Local'; apiVersion = '3.0'; releaseApiVersion = '2.0'; contractVersion = '1.1.0-alpha'
            startedUtc = [DateTimeOffset]::UtcNow.ToString('o'); state = 'Prepared'
            provisionInvocationCount = $(if ($sandboxId) { 0 } else { 1 }); tokenPersisted = $false
            remoteResetConfirmed = $false; releaseAccepted = $false; operations = @()
            sandboxId = $sandboxId; sessionId = $sandboxId
        }
        Save-W365Journal $ReceiptPath $journal -Create
    }
    $journalCreated = $true
    foreach ($phase in $phases) {
        if ($phase -in @('start', 'exec')) {
            if (-not $dpAuth) {
                $dpAuth = Get-W365Token $TenantId $ClientId $LoginHint $auth.UserObjectId -ResourceId $DataPlaneResource -Force:$ForceSignIn
            }
            $dpAuth = Get-W365CleanupAuth $dpAuth $TenantId $ClientId $LoginHint $DataPlaneResource
            $token = $dpAuth.Token
        } else {
            $auth = Get-W365CleanupAuth $auth $TenantId $ClientId $LoginHint $ControlPlaneResource
            $token = $auth.Token
        }
        $useDataPlaneToken = $phase -in @('start', 'exec') -and $DataPlaneResource -ne $ControlPlaneResource
        $request = if ($phase -eq 'provision') { $provisionRequest } elseif ($phase -eq 'exec') { $execRequest } else { $base }
        if ($newProvision -and $phase -ne 'provision') {
            $native = Invoke-W365Native $exe $phase $request $sandboxId $GraphEnvironment $token '' 15000 -DryRun -UseDataPlaneToken:$useDataPlaneToken
            $envelope = ConvertFrom-W365Envelope $native
            if ($native.ExitCode -ne 0 -or $envelope.Contains('error')) {
                throw "Executor $phase dry-run failed; no $phase service request performed."
            }
        }
        $journal.state = "${phase}Submitted"
        Save-W365Journal $ReceiptPath $journal
        $budget = switch ($phase) {
            'provision' { 0 }
            'start' { 135000 }
            'exec' { $(if ($TimeoutMs -eq 0) { 300000 } else { $TimeoutMs }) + 45000 }
            'deprovision' { 45000 }
        }
        $graphToken = if ($phase -eq 'provision') { $graphAuth.Token } else { '' }
        $native = Invoke-W365Native $exe $phase $request $sandboxId $GraphEnvironment $token $graphToken $budget -Stream:($phase -eq 'exec') -UseDataPlaneToken:$useDataPlaneToken
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
                if ($phase -eq 'provision' -and
                    $envelope.error['details'] -is [System.Collections.IDictionary] -and $envelope.error.details['sandboxId']) {
                    $sandboxId = Get-W365SandboxId $envelope.error.details['sandboxId']
                }
                $record.error = Get-W365SafeError $envelope.error
                throw "Native $phase failed: $($record.error | ConvertTo-Json -Compress)."
            }
            if ($phase -eq 'provision') {
                $sandboxId = Get-W365SandboxId $envelope.result.sandboxId
                $PoolId = $sandboxId.Split(':')[1]
                $journal.poolId = $PoolId
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
    if ($Operation -eq 'Provision') { Write-Host 'Provision succeeded; readiness polling and execution were not requested.' }
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
        if ($sandboxId) { $journal.poolId = $sandboxId.Split(':')[1] }
        $journal.primaryFailure = $failure
        $journal.reconciliationRequired = $true
        try { Save-W365Journal $ReceiptPath $journal }
        catch { Write-Host 'Receipt update failed; preserve the earlier journal and reconcile the outcome.' }
    }
    Write-Host "Failure: $failure"
    if ($sandboxId) { Write-Host "Session NOT automatically released. MXC SessionId: $sandboxId" }
    elseif ($journalCreated) { Write-Host 'Provision failed without a cleanup ID; reconcile before another checkout.' }
    if ($null -ne $commandExit -and $commandExit -ne 0) { exit $commandExit }
    exit 1
} finally {
    $auth = $null
    $graphAuth = $null
    $dpAuth = $null
    $token = $null
    $graphToken = $null
    $lock.Dispose()
}
exit 0
