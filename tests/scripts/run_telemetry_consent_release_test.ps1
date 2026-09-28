# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Exercises the telemetry consent path in a RELEASE wxc-exec, where the
    debug-only store and policy overrides are compiled out.

.DESCRIPTION
    The debug smoke test redirects the consent store with
    MXC_TEST_LOCALAPPDATA_OVERRIDE and the policy key with
    MXC_TEST_POLICY_KEY_OVERRIDE. Both are gated on
    `cfg(any(test, all(feature = "test-support", debug_assertions)))`, so a
    shipped binary resolves the store through SHGetKnownFolderPath and reads
    policy from HKLM. That release-only shape has no other coverage.

    Reaching it requires giving up isolation: this test writes the real
    per-user consent store and the real HKLM policy key. Run it only on a
    machine you are willing to mutate. Prior state is backed up and restored,
    but a crash mid-run can leave the store or the policy key modified.

.PARAMETER BinDir
    Directory holding a release wxc-exec.exe.

.PARAMETER AcceptRealMachineMutation
    Required acknowledgement. There is deliberately no CI auto-detection:
    self-hosted runners also set GITHUB_ACTIONS, and those machines persist.

.PARAMETER RequirePolicyCeiling
    Fails instead of skipping when the session is not elevated. CI passes this
    so a runner that stops being elevated surfaces as a failure rather than
    silently dropping the only coverage of the real HKLM policy key.
#>

[CmdletBinding()]
param(
    [string]$BinDir,
    [switch]$AcceptRealMachineMutation,
    [switch]$RequirePolicyCeiling
)

$ErrorActionPreference = 'Stop'

if (-not $AcceptRealMachineMutation) {
    throw 'This test mutates the real consent store and HKLM policy. Pass -AcceptRealMachineMutation on an ephemeral machine.'
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $BinDir) { $BinDir = Join-Path $repoRoot 'src\target\release' }
elseif (-not [IO.Path]::IsPathRooted($BinDir)) { $BinDir = Join-Path $repoRoot $BinDir }
$BinDir = [IO.Path]::GetFullPath($BinDir)
$exe = Join-Path $BinDir 'wxc-exec.exe'
if (-not (Test-Path $exe)) {
    throw "Release wxc-exec.exe not found at '$exe'. Run 'cargo build --release -p wxc'."
}
if ($exe -match '\\debug\\') {
    throw 'Debug binaries are refused: this test exists to exercise the release cfg shape.'
}

# GetFolderPath mirrors the SHGetKnownFolderPath call the executor makes;
# %LOCALAPPDATA% is a separate, spoofable source of truth.
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
if (-not $localAppData) { throw 'Could not resolve the LocalApplicationData known folder.' }
$mxcDir = Join-Path $localAppData 'mxc'
$consentFile = Join-Path $mxcDir 'telemetry-consent.json'
# The executor creates this alongside the store and leaves it behind once the
# lock is released, so cleanup has to account for it too.
$lockFile = Join-Path $mxcDir 'telemetry-consent.lock'
# A pending marker means an interrupted withdrawal, which reads fail-closed.
# Every consent write clears it, so it has to be backed up and restored.
$withdrawalFile = Join-Path $mxcDir 'telemetry-consent.withdrawal-pending'
$policySubKey = 'SOFTWARE\Policies\Mxc'
$policyKey = "HKLM:\$policySubKey"

$expectedBody = @'
Help improve MXC and other Microsoft product including Windows by sharing optional diagnostic data with Microsoft.

If enabled, MXC sends diagnostic information about product usage, performance, and reliability. MXC does not send your commands, file paths, credentials, or other customer content.
'@ -replace "`r`n", "`n"

function New-ConsentProcess {
    param([string]$Arguments, [hashtable]$Environment)

    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $exe
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    if ($Environment) {
        foreach ($name in $Environment.Keys) { $start.Environment[$name] = [string]$Environment[$name] }
    }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "Failed to start '$exe $Arguments'." }
    return $process
}

# Reads both pipes concurrently. Native stderr never reaches PowerShell's error
# stream this way, so the script behaves identically under 5.1 and 7.
function Invoke-Consent {
    param([string]$Arguments, [hashtable]$Environment)

    $process = New-ConsentProcess -Arguments $Arguments -Environment $Environment
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Close()
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut   = $stdout.Result
        StdErr   = $stderr.Result
    }
}

function Invoke-ConsentJson {
    param([string]$Arguments, [hashtable]$Environment)

    $result = Invoke-Consent -Arguments $Arguments -Environment $Environment
    if ($result.ExitCode -ne 0) {
        throw "'$Arguments' exited $($result.ExitCode): $($result.StdErr)"
    }
    return ($result.StdOut | ConvertFrom-Json)
}

function Invoke-ConsentRequest {
    param([string]$Decision, [hashtable]$Environment)

    $process = New-ConsentProcess `
        -Arguments '--telemetry-consent request --telemetry-consent-locale en-US' `
        -Environment $Environment
    $stderr = $process.StandardError.ReadToEndAsync()
    $firstLine = $process.StandardOutput.ReadLine()
    if (-not $firstLine) {
        $process.WaitForExit()
        throw "Consent request emitted no response: $($stderr.Result)"
    }
    $first = $firstLine | ConvertFrom-Json
    if ($first.result -ne 'presentationRequired') {
        $process.StandardInput.Close()
        $process.WaitForExit()
        return $first
    }
    if (-not $first.prompt -or -not $first.challenge) {
        throw "Unexpected consent presentation: $firstLine"
    }
    if ($first.prompt.resourceVersion -ne 3 -or
        $first.prompt.locale -ne 'en-US' -or
        $first.prompt.title.text -ne 'Help improve Microsoft Products' -or
        $first.prompt.body.text -ne $expectedBody -or
        $first.prompt.affirmativeLabel.text -ne 'Yes' -or
        $first.prompt.negativeLabel.text -ne 'No' -or
        $first.prompt.learnMoreLabel.text -ne 'Privacy Statement' -or
        $first.prompt.learnMoreUrl -ne 'https://go.microsoft.com/fwlink/?linkid=521839') {
        throw 'The canonical consent resource drifted in the release build.'
    }
    $response = [pscustomobject]@{
        challenge       = $first.challenge
        resourceVersion = $first.prompt.resourceVersion
        decision        = $Decision
    }
    $process.StandardInput.WriteLine(($response | ConvertTo-Json -Compress))
    $finalRead = $process.StandardOutput.ReadLineAsync()
    if (-not $finalRead.Wait(5000)) {
        $process.Kill()
        $process.WaitForExit()
        throw 'Consent process waited for stdin EOF instead of accepting the decision line.'
    }
    $process.StandardInput.Close()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Consent request failed: $($stderr.Result)" }
    return ($finalRead.Result | ConvertFrom-Json)
}

function Assert-Status {
    param(
        [object]$Value,
        [string]$Stored,
        [string]$Effective,
        [string]$Policy,
        [bool]$NeedsPrompt,
        [string]$Step
    )
    if ($Value.storedState -ne $Stored -or
        $Value.effectiveState -ne $Effective -or
        $Value.policy -ne $Policy -or
        $Value.needsPrompt -ne $NeedsPrompt) {
        throw "$Step returned an unexpected response: $($Value | ConvertTo-Json -Compress)"
    }
}

function Write-ConsentRecord {
    param([string]$Consent, [int]$PromptVersion = 3, [string]$Locale = 'en-US')

    $record = [pscustomobject]@{
        schemaVersion         = 2
        consent               = $Consent
        source                = 'release-path-test'
        promptedMxcVersion    = '0.0.0-release-test'
        promptResourceVersion = $PromptVersion
        promptLocale          = $Locale
        updatedAtEpoch        = 0
    }
    [IO.File]::WriteAllText(
        $consentFile,
        ($record | ConvertTo-Json -Compress),
        (New-Object Text.UTF8Encoding $false))
}

function Remove-RealConsentFile {
    if (Test-Path $consentFile) { Remove-Item $consentFile -Force }
}

# --- Test sections ---------------------------------------------------------

function Test-CliContract {
    $invalid = Invoke-Consent -Arguments '--telemetry-consent invalid'
    if ($invalid.ExitCode -ne 64) {
        throw "Invalid consent action returned $($invalid.ExitCode); expected 64."
    }
    $conflict = Invoke-Consent -Arguments '--telemetry-consent status --config missing.json'
    if ($conflict.ExitCode -ne 64) {
        throw "Consent/config conflict returned $($conflict.ExitCode); expected 64."
    }
    $afterSeparator = Invoke-Consent -Arguments '--unknown-flag -- --telemetry-consent=request'
    if ($afterSeparator.ExitCode -ne 2) {
        throw "Consent-like text after '--' returned $($afterSeparator.ExitCode); expected 2."
    }
    Write-Host '  ok: release CLI exit-code contract'
}

function Test-FreshStore {
    Remove-RealConsentFile
    $fresh = Invoke-ConsentJson -Arguments '--telemetry-consent status'
    Assert-Status $fresh 'undetermined' 'undetermined' 'unrestricted' $true 'fresh status'
    Write-Host '  ok: real store resolves and reports undetermined when absent'
}

function Test-PipedEofFailsClosed {
    Remove-RealConsentFile
    $piped = Invoke-Consent -Arguments '--telemetry-consent request --telemetry-consent-locale en-US'
    if ($piped.ExitCode -ne 1) {
        throw "Piped request exited $($piped.ExitCode); expected 1: $($piped.StdErr)"
    }
    $responses = @($piped.StdOut -split '\r?\n' | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    if ($responses.Count -ne 2 -or
        $responses[0].result -ne 'presentationRequired' -or
        $responses[1].result -ne 'presentationUnavailable') {
        throw "Piped request returned an unexpected response: $($piped.StdOut)"
    }
    if (Test-Path $consentFile) { throw 'Piped request EOF created a consent record.' }
    Write-Host '  ok: presenter EOF fails closed without creating the real store'
}

function Test-RealStoreLifecycle {
    $denied = Invoke-ConsentRequest -Decision 'no'
    if ($denied.result -ne 'denied') { throw 'Explicit No was not persisted as Denied.' }
    if (-not (Test-Path $consentFile)) {
        throw "Explicit No did not create the store at the known-folder path '$consentFile'."
    }
    $record = Get-Content $consentFile -Raw | ConvertFrom-Json
    if ($record.schemaVersion -ne 2 -or
        $record.consent -ne 'denied' -or
        $record.promptResourceVersion -ne 3 -or
        $record.promptLocale -ne 'en-US') {
        throw "The persisted record is malformed: $(Get-Content $consentFile -Raw)"
    }
    Assert-Status (Invoke-ConsentJson -Arguments '--telemetry-consent status') `
        'denied' 'denied' 'unrestricted' $false 'denied status'
    Write-Host "  ok: store written to the real known-folder path"
}

# The property the cfg gating exists for. Only provable against release.
function Test-OverridesAreCompiledOut {
    $probeDir = Join-Path ([IO.Path]::GetTempPath()) "mxc_release_probe_$([guid]::NewGuid().ToString('N'))"
    $probeStore = Join-Path $probeDir 'mxc'
    New-Item -ItemType Directory -Path $probeStore -Force | Out-Null
    $probeSubkey = "Software\MxcReleaseProbe\$([guid]::NewGuid().ToString('N'))"
    $probePath = "HKCU:\$probeSubkey"
    try {
        # A store override, if honored, would report granted instead of denied.
        $record = [pscustomobject]@{
            schemaVersion         = 2
            consent               = 'granted'
            source                = 'release-path-test-probe'
            promptedMxcVersion    = '0.0.0-release-test'
            promptResourceVersion = 3
            promptLocale          = 'en-US'
            updatedAtEpoch        = 0
        }
        [IO.File]::WriteAllText(
            (Join-Path $probeStore 'telemetry-consent.json'),
            ($record | ConvertTo-Json -Compress),
            (New-Object Text.UTF8Encoding $false))

        # A policy override, if honored, would report blocked instead of unrestricted.
        New-Item -Path $probePath -Force | Out-Null
        Set-ItemProperty -Path $probePath -Name AllowTelemetry -Value 0 -Type DWord

        $status = Invoke-ConsentJson -Arguments '--telemetry-consent status' -Environment @{
            MXC_TEST_LOCALAPPDATA_OVERRIDE           = $probeDir
            MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID = "$PID"
            MXC_TEST_POLICY_KEY_OVERRIDE             = $probeSubkey
            MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID   = "$PID"
        }
        if ($status.storedState -ne 'denied') {
            throw "MXC_TEST_LOCALAPPDATA_OVERRIDE redirected a release binary (storedState '$($status.storedState)'). The debug override is not compiled out."
        }
        if ($status.policy -ne 'unrestricted') {
            throw "MXC_TEST_POLICY_KEY_OVERRIDE redirected a release binary (policy '$($status.policy)'). The debug override is not compiled out."
        }
        Write-Host '  ok: debug store and policy overrides are compiled out'
    }
    finally {
        Remove-Item -Recurse -Force $probeDir -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $probePath -ErrorAction SilentlyContinue
    }
}

function Test-GrantAndCorruptionRecovery {
    $granted = Invoke-ConsentRequest -Decision 'yes'
    if ($granted.result -ne 'granted') { throw 'Explicit Yes was not persisted as Granted.' }
    Assert-Status (Invoke-ConsentJson -Arguments '--telemetry-consent status') `
        'granted' 'granted' 'unrestricted' $false 'granted status'

    [IO.File]::WriteAllText($consentFile, 'not json at all', (New-Object Text.UTF8Encoding $false))
    $corrupt = Invoke-ConsentJson -Arguments '--telemetry-consent status'
    if ($corrupt.effectiveState -eq 'granted') {
        throw 'A corrupted real store was treated as a grant.'
    }

    Write-ConsentRecord -Consent 'granted' -PromptVersion 999
    $stale = Invoke-ConsentJson -Arguments '--telemetry-consent status'
    if ($stale.storedState -ne 'granted' -or $stale.effectiveState -ne 'undetermined') {
        throw "A grant for an unsupported prompt version authorized collection: $($stale | ConvertTo-Json -Compress)"
    }
    Write-Host '  ok: corrupt and stale-prompt records fail closed at the real path'
}

function Test-PolicyCeiling {
    Write-ConsentRecord -Consent 'granted'
    Assert-Status (Invoke-ConsentJson -Arguments '--telemetry-consent status') `
        'granted' 'granted' 'unrestricted' $false 'policy absent'

    New-Item -Path $policyKey -Force | Out-Null
    Set-ItemProperty -Path $policyKey -Name AllowTelemetry -Value 0 -Type DWord
    $blocked = Invoke-ConsentRequest -Decision 'yes'
    if ($blocked.result -ne 'policyBlocked') {
        throw "Blocked HKLM policy did not suppress presentation: $($blocked | ConvertTo-Json -Compress)"
    }
    Assert-Status $blocked 'granted' 'granted' 'blocked' $false 'blocked status'

    Set-ItemProperty -Path $policyKey -Name AllowTelemetry -Value 3 -Type DWord
    Assert-Status (Invoke-ConsentJson -Arguments '--telemetry-consent status') `
        'granted' 'granted' 'allowed' $false 'allowed status'

    Set-ItemProperty -Path $policyKey -Name AllowTelemetry -Value 0 -Type DWord
    $withdrawn = Invoke-ConsentJson -Arguments '--telemetry-consent withdraw'
    if ($withdrawn.result -ne 'withdrawn') { throw 'Withdrawal while blocked did not report withdrawn.' }
    Assert-Status $withdrawn 'denied' 'denied' 'blocked' $false 'withdrawal while blocked'
    $again = Invoke-ConsentJson -Arguments '--telemetry-consent withdraw'
    if ($again.result -ne 'withdrawn') { throw 'Repeated withdrawal was not idempotent.' }
    Write-Host '  ok: real HKLM policy ceiling gates presentation and never grants'
}

# --- Run -------------------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($RequirePolicyCeiling -and -not $isAdmin) {
    throw 'HKLM policy ceiling coverage was required but this session is not elevated.'
}

$mxcDirPreexisted = Test-Path $mxcDir
$consentBackup = if (Test-Path $consentFile) { [IO.File]::ReadAllBytes($consentFile) } else { $null }
$lockFilePreexisted = Test-Path $lockFile
$withdrawalBackup = $null
$withdrawalBackupWritten = $null
if (Test-Path $withdrawalFile) {
    $withdrawalBackup = [IO.File]::ReadAllBytes($withdrawalFile)
    $withdrawalBackupWritten = [IO.File]::GetLastWriteTimeUtc($withdrawalFile)
}
$policyKeyPreexisted = Test-Path $policyKey
$policyValueBackup = $null
# The value kind is part of the state: policy.rs fail-closes on a non-DWORD
# AllowTelemetry, so restoring a REG_SZ as a DWORD would change the machine.
$policyValueKind = $null
if ($policyKeyPreexisted) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($policySubKey)
    if ($key) {
        try {
            $policyValueBackup = $key.GetValue(
                'AllowTelemetry', $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $policyValueBackup) {
                $policyValueKind = $key.GetValueKind('AllowTelemetry')
            }
        }
        finally { $key.Dispose() }
    }
}

Write-Host "Release executor : $exe"
Write-Host "Consent store    : $consentFile"
Write-Host "Policy key       : $policyKey"

try {
    if (-not $mxcDirPreexisted) { New-Item -ItemType Directory -Path $mxcDir -Force | Out-Null }

    Test-CliContract
    Test-FreshStore
    Test-PipedEofFailsClosed
    Test-RealStoreLifecycle
    Test-OverridesAreCompiledOut
    Test-GrantAndCorruptionRecovery

    if ($isAdmin) {
        Test-PolicyCeiling
    }
    else {
        Write-Host '  skipped: HKLM policy ceiling (requires Administrator)' -ForegroundColor Yellow
    }

    Write-Host 'PASSED: release-path telemetry consent test' -ForegroundColor Green
}
finally {
    if ($null -ne $consentBackup) {
        New-Item -ItemType Directory -Path $mxcDir -Force | Out-Null
        [IO.File]::WriteAllBytes($consentFile, $consentBackup)
    }
    elseif ($mxcDirPreexisted) {
        Remove-RealConsentFile
    }
    else {
        Remove-Item -Recurse -Force $mxcDir -ErrorAction SilentlyContinue
    }

    if ($mxcDirPreexisted -and -not $lockFilePreexisted) {
        Remove-Item -Force $lockFile -ErrorAction SilentlyContinue
    }

    if ($null -ne $withdrawalBackup) {
        New-Item -ItemType Directory -Path $mxcDir -Force | Out-Null
        [IO.File]::WriteAllBytes($withdrawalFile, $withdrawalBackup)
        # The marker goes stale on mtime, so let it keep aging from where it was.
        [IO.File]::SetLastWriteTimeUtc($withdrawalFile, $withdrawalBackupWritten)
    }
    elseif ($mxcDirPreexisted) {
        Remove-Item -Force $withdrawalFile -ErrorAction SilentlyContinue
    }

    if ($isAdmin) {
        if (-not $policyKeyPreexisted) {
            Remove-Item -Recurse -Force $policyKey -ErrorAction SilentlyContinue
        }
        elseif ($null -eq $policyValueKind) {
            Remove-ItemProperty -Path $policyKey -Name AllowTelemetry -ErrorAction SilentlyContinue
        }
        else {
            $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($policySubKey)
            try { $key.SetValue('AllowTelemetry', $policyValueBackup, $policyValueKind) }
            finally { $key.Dispose() }
        }
    }
}
