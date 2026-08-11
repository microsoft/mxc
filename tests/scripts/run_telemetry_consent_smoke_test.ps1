# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param([string]$BinDir)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $BinDir) { $BinDir = Join-Path $repoRoot 'src\target\debug' }
$wxcExec = Join-Path $BinDir 'wxc-exec.exe'
if (-not (Test-Path $wxcExec)) {
    throw "Debug wxc-exec.exe not found at '$wxcExec'. Run 'cargo build -p wxc'."
}
if ($wxcExec -match '\\release\\') {
    throw 'Release binaries are refused because consent isolation uses debug-only overrides.'
}
$expectedBody = @'
Help improve MXC by sharing optional diagnostic data with Microsoft.
If enabled, MXC sends diagnostic information about product usage, performance, and reliability. MXC does not send your commands, file paths, credentials, or other customer content.
You can change your choice at any time.
'@ -replace "`r`n", "`n"

function ConvertTo-Base64Json([object]$Value) {
    $json = $Value | ConvertTo-Json -Compress -Depth 10
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}

function Invoke-Maintenance([string]$Action) {
    $request = [pscustomobject]@{ command = 'telemetryConsent'; action = $Action }
    $output = & $wxcExec --config-base64 (ConvertTo-Base64Json $request)
    if ($LASTEXITCODE -ne 0) { throw "$Action failed with exit code $LASTEXITCODE" }
    $output | ConvertFrom-Json
}

function Invoke-ConsentRequest([string]$Decision) {
    $request = [pscustomobject]@{ command = 'telemetryConsent'; action = 'request'; locale = 'en-US' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $wxcExec
    $start.Arguments = "--config-base64 $(ConvertTo-Base64Json $request)"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $start.Environment['MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL'] = '1'
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
    $process.StandardInput.Close()
    $finalLine = $process.StandardOutput.ReadLine()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Consent process failed: $stderr" }
    $finalLine | ConvertFrom-Json
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
$originalOverride = [Environment]::GetEnvironmentVariable($overrideName)
$originalPolicyOverride = [Environment]::GetEnvironmentVariable($policyOverrideName)
$runId = [guid]::NewGuid().ToString('N')
$tempDir = Join-Path ([IO.Path]::GetTempPath()) "mxc_consent_smoke_$runId"
$consentFile = Join-Path $tempDir 'mxc\telemetry-consent.json'
$policySubkey = "Software\MxcTelemetryConsentSmoke\$runId"
$policyPath = "HKCU:\$policySubkey"

try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $consentFile) -Force | Out-Null
    New-Item -Path $policyPath -Force | Out-Null
    Set-Item "Env:$overrideName" $tempDir
    Set-Item "Env:$policyOverrideName" $policySubkey

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

    $fresh = Invoke-Maintenance 'status'
    Assert-Status $fresh 'undetermined' 'undetermined' 'unrestricted' $true 'fresh status'

    $denied = Invoke-ConsentRequest 'no'
    if ($denied.result -ne 'denied') { throw 'Explicit No was not persisted as Denied.' }
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
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $policyPath -ErrorAction SilentlyContinue
}
