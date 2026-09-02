# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param([string]$BinDir)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $BinDir) { $BinDir = Join-Path $repoRoot 'src\target\debug' }
elseif (-not [IO.Path]::IsPathRooted($BinDir)) { $BinDir = Join-Path $repoRoot $BinDir }
$BinDir = [IO.Path]::GetFullPath($BinDir)
$wxcExec = Join-Path $BinDir 'wxc-exec.exe'
if (-not (Test-Path $wxcExec)) {
    throw "Debug wxc-exec.exe not found at '$wxcExec'. Run 'cargo build -p wxc --features test-support'."
}
if ($wxcExec -match '\\release\\') {
    throw 'Release binaries are refused because consent isolation uses debug-only overrides.'
}

function Assert-ConsentParseExitCodes {
    $executors = @($wxcExec)
    foreach ($name in @('lxc-exec.exe', 'mxc-exec-mac.exe')) {
        $candidate = Join-Path $BinDir $name
        if (Test-Path $candidate) { $executors += $candidate }
    }
    foreach ($executor in $executors) {
        & $executor --telemetry-consent invalid *> $null
        if ($LASTEXITCODE -ne 64) {
            throw "$executor returned $LASTEXITCODE for an invalid consent action; expected 64."
        }
        & $executor --telemetry-consent status --config missing.json *> $null
        if ($LASTEXITCODE -ne 64) {
            throw "$executor returned $LASTEXITCODE for a consent/config conflict; expected 64."
        }

        & $executor --unknown-flag -- --telemetry-consent=request *> $null
        if ($LASTEXITCODE -ne 2) {
            throw "$executor returned $LASTEXITCODE when consent-like text followed '--'; expected 2."
        }
    }
}

$expectedBody = @'
Help improve MXC by sharing optional diagnostic data with Microsoft.
If enabled, MXC sends diagnostic information about product usage, performance, and reliability. MXC does not send your commands, file paths, credentials, or other customer content.
You can change your choice at any time.
'@ -replace "`r`n", "`n"

function Invoke-Maintenance([string]$Action) {
    $output = & $wxcExec --telemetry-consent $Action
    if ($LASTEXITCODE -ne 0) { throw "$Action failed with exit code $LASTEXITCODE" }
    $output | ConvertFrom-Json
}

function Invoke-ConsentRequest([string]$Decision) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $wxcExec
    $start.Arguments = '--telemetry-consent request --telemetry-consent-locale en-US'
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $start.Environment['MXC_TEST_LOCALAPPDATA_OVERRIDE'] = $tempDir
    $start.Environment['MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID'] = "$PID"
    $start.Environment['MXC_TEST_POLICY_KEY_OVERRIDE'] = $policySubkey
    $start.Environment['MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID'] = "$PID"
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Failed to start consent process.' }
    $firstLine = $process.StandardOutput.ReadLine()
    $first = $firstLine | ConvertFrom-Json
    if ($first.result -ne 'presentationRequired') {
        $process.WaitForExit()
        return $first
    }
    if (-not $first.prompt -or -not $first.challenge) {
        throw "Unexpected consent presentation: $firstLine"
    }
    if ($first.prompt.resourceVersion -ne 1 -or
        $first.prompt.locale -ne 'en-US' -or
        $first.prompt.title.text -ne 'Help improve Microsoft eXecution Container (MXC)' -or
        $first.prompt.body.text -ne $expectedBody -or
        $first.prompt.affirmativeLabel.text -ne 'Yes' -or
        $first.prompt.negativeLabel.text -ne 'No' -or
        $first.prompt.learnMoreLabel.text -ne 'Privacy Statement' -or
        $first.prompt.learnMoreUrl -ne 'https://go.microsoft.com/fwlink/?linkid=521839') {
        throw 'The canonical consent resource drifted.'
    }
    $response = [pscustomobject]@{
        challenge = $first.challenge
        resourceVersion = $first.prompt.resourceVersion
        decision = $Decision
    }
    $process.StandardInput.WriteLine(($response | ConvertTo-Json -Compress))
    $finalRead = $process.StandardOutput.ReadLineAsync()
    if (-not $finalRead.Wait(5000)) {
        $process.Kill()
        throw 'Consent process waited for stdin EOF instead of accepting the decision line.'
    }
    $finalLine = $finalRead.Result
    $process.StandardInput.Close()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Consent process failed: $stderr" }
    $finalLine | ConvertFrom-Json
}

function Assert-PipedRequestEofFails {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $wxcExec
    $start.Arguments = '--telemetry-consent request --telemetry-consent-locale en-US'
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $start.Environment['MXC_TEST_LOCALAPPDATA_OVERRIDE'] = $tempDir
    $start.Environment['MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID'] = "$PID"
    $start.Environment['MXC_TEST_POLICY_KEY_OVERRIDE'] = $policySubkey
    $start.Environment['MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID'] = "$PID"
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Failed to start piped consent process.' }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 1) {
        throw "Piped request exited $($process.ExitCode), expected 1: $stderr"
    }
    $responses = @($stdout -split '\r?\n' |
        Where-Object { $_ } |
        ForEach-Object { $_ | ConvertFrom-Json })
    if ($responses.Count -ne 2 -or
        $responses[0].result -ne 'presentationRequired' -or
        $responses[1].result -ne 'presentationUnavailable') {
        throw "Piped request returned an unexpected response: $stdout"
    }
    if (Test-Path $consentFile) {
        throw 'Piped request EOF changed the consent store.'
    }
}

function Assert-Status(
    [object]$Value,
    [string]$Stored,
    [string]$Effective,
    [string]$Policy,
    [bool]$NeedsPrompt,
    [string]$Step
) {
    if ($Value.storedState -ne $Stored -or
        $Value.effectiveState -ne $Effective -or
        $Value.policy -ne $Policy -or
        $Value.needsPrompt -ne $NeedsPrompt) {
        throw "$Step returned an unexpected response: $($Value | ConvertTo-Json -Compress)"
    }
}

$overrideName = 'MXC_TEST_LOCALAPPDATA_OVERRIDE'
$policyOverrideName = 'MXC_TEST_POLICY_KEY_OVERRIDE'
$policyOverrideOwnerName = 'MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID'
$originalOverride = [Environment]::GetEnvironmentVariable($overrideName)
$originalPolicyOverride = [Environment]::GetEnvironmentVariable($policyOverrideName)
$originalPolicyOverrideOwner = [Environment]::GetEnvironmentVariable($policyOverrideOwnerName)
$runId = [guid]::NewGuid().ToString('N')
$tempDir = Join-Path ([IO.Path]::GetTempPath()) "mxc_consent_smoke_$runId"
$consentFile = Join-Path $tempDir 'mxc\telemetry-consent.json'
$policySubkey = "Software\MxcTelemetryConsentSmoke\$runId"
$policyPath = "HKCU:\$policySubkey"

try {
    Assert-ConsentParseExitCodes

    New-Item -ItemType Directory -Path (Split-Path -Parent $consentFile) -Force | Out-Null
    New-Item -Path $policyPath -Force | Out-Null
    Set-Item "Env:$overrideName" $tempDir
    Set-Item "Env:$policyOverrideName" $policySubkey
    Set-Item "Env:$policyOverrideOwnerName" $PID

    foreach ($seed in @('granted', 'denied')) {
        $record = [pscustomobject]@{
            schemaVersion = 2
            consent = $seed
            source = 'smoke-proof'
            promptedMxcVersion = '0.0.0-smoke'
            promptResourceVersion = 1
            promptLocale = 'en-US'
            updatedAtEpoch = 0
        }
        [IO.File]::WriteAllText(
            $consentFile,
            ($record | ConvertTo-Json -Compress),
            (New-Object Text.UTF8Encoding $false))
        $probe = Invoke-Maintenance 'status'
        if ($probe.effectiveState -ne $seed) {
            throw "Consent override proof failed for '$seed'; refusing all MXC writes."
        }
    }
    Remove-Item $consentFile -Force

    Assert-PipedRequestEofFails

    $fresh = Invoke-Maintenance 'status'
    Assert-Status $fresh 'undetermined' 'undetermined' 'unrestricted' $true 'fresh status'

    $denied = Invoke-ConsentRequest 'no'
    if ($denied.result -ne 'denied') { throw 'Explicit No was not persisted as Denied.' }
    if (-not (Test-Path $consentFile)) {
        throw "Explicit No did not create the isolated consent record at '$consentFile'."
    }
    Assert-Status (Invoke-Maintenance 'status') 'denied' 'denied' 'unrestricted' $false 'denied status'

    $granted = Invoke-ConsentRequest 'yes'
    if ($granted.result -ne 'granted') { throw 'Explicit Yes was not persisted as Granted.' }
    Assert-Status (Invoke-Maintenance 'status') 'granted' 'granted' 'unrestricted' $false 'granted status'

    Set-ItemProperty $policyPath -Name AllowTelemetry -Value 0 -Type DWord
    $blocked = Invoke-ConsentRequest 'yes'
    if ($blocked.result -ne 'policyBlocked') { throw 'Blocked policy did not suppress presentation.' }
    Assert-Status $blocked 'granted' 'granted' 'blocked' $false 'blocked status'

    $withdrawn = Invoke-Maintenance 'withdraw'
    if ($withdrawn.result -ne 'withdrawn') { throw 'Withdrawal did not report withdrawn.' }
    Assert-Status $withdrawn 'denied' 'denied' 'blocked' $false 'withdrawal while blocked'
    $withdrawnAgain = Invoke-Maintenance 'withdraw'
    if ($withdrawnAgain.result -ne 'withdrawn') { throw 'Repeated withdrawal was not idempotent.' }

    Write-Host 'PASSED: isolated telemetry consent smoke test' -ForegroundColor Green
} finally {
    if ($null -eq $originalOverride) { Remove-Item "Env:$overrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$overrideName" $originalOverride }
    if ($null -eq $originalPolicyOverride) { Remove-Item "Env:$policyOverrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$policyOverrideName" $originalPolicyOverride }
    if ($null -eq $originalPolicyOverrideOwner) { Remove-Item "Env:$policyOverrideOwnerName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$policyOverrideOwnerName" $originalPolicyOverrideOwner }
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $policyPath -ErrorAction SilentlyContinue
}
