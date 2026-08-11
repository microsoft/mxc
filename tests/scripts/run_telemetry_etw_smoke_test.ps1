<#
.SYNOPSIS
    Isolated ETW capture smoke test for MXC telemetry.

.DESCRIPTION
    Uses a debug wxc-exec only, proves the debug-only consent and policy
    redirects before any MXC write, grants consent through the canonical
    session-bound presenter protocol, captures the public MXC ETW provider,
    and restores all process/machine state in finally.
#>

[CmdletBinding()]
param(
    [string]$BinDir,
    [switch]$SkipClean
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$srcDir = Join-Path $repoRoot 'src'
if (-not $BinDir) {
    $BinDir = Join-Path $srcDir 'target\debug'
}
$wxcExe = Join-Path $BinDir 'wxc-exec.exe'
if (-not (Test-Path $wxcExe)) {
    throw "Debug wxc-exec.exe not found at '$wxcExe'. Run 'cargo build -p wxc' (without --release)."
}
if ($wxcExe -match '\\release\\') {
    throw 'Release binaries are refused: telemetry smoke isolation depends on debug-only test overrides.'
}
$expectedBody = @'
Would you like to send optional diagnostic data to Microsoft to help us understand how MXC is used, diagnose problems, and improve the product?

If you choose Yes, MXC will send the MXC version and channel, containment backend, run outcome and exit code, run duration, bounded failure category, lifecycle phase, and random identifiers used to correlate events from the same app session or sandbox lifecycle.

MXC does not send your command text, file paths, environment variables, standard input or output, usernames, credentials, or free-form error messages.

Choosing No, closing this prompt, or not responding will keep telemetry off. If this consent request is never shown, telemetry also remains off. You can change or withdraw your choice later using MXC telemetry consent controls.
'@ -replace "`r`n", "`n"

$configFile = Join-Path $repoRoot 'tests\examples\28_telemetry_enabled.json'
if (-not (Test-Path $configFile)) {
    throw "Config not found: $configFile"
}

$providerName = 'Microsoft.MXC'
function Get-TraceLoggingProviderGuid {
    param([Parameter(Mandatory)][string]$Name)
    $seed = [byte[]]@(0x48,0x2C,0x2D,0xB2,0xC3,0x90,0x47,0xC8,0x87,0xF8,0x1A,0x15,0xBF,0xC1,0x30,0xFB)
    $nameBytes = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Name.ToUpperInvariant())
    $buffer = New-Object byte[] ($seed.Length + $nameBytes.Length)
    [Array]::Copy($seed, 0, $buffer, 0, $seed.Length)
    [Array]::Copy($nameBytes, 0, $buffer, $seed.Length, $nameBytes.Length)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha1.ComputeHash($buffer) } finally { $sha1.Dispose() }
    $guidBytes = New-Object byte[] 16
    [Array]::Copy($hash, 0, $guidBytes, 0, 16)
    $guidBytes[7] = ($guidBytes[7] -band 0x0F) -bor 0x50
    return '{' + ([guid]::new($guidBytes)).ToString() + '}'
}

function ConvertTo-Base64Json {
    param([Parameter(Mandatory)][object]$Value)
    $json = $Value | ConvertTo-Json -Compress -Depth 10
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}

function Invoke-Status {
    $output = & $wxcExe --telemetry-consent-status
    if ($LASTEXITCODE -ne 0) { throw "Consent status failed with exit code $LASTEXITCODE" }
    return ($output | ConvertFrom-Json)
}

function Invoke-CanonicalGrant {
    $request = [pscustomobject]@{ command = 'telemetryConsent'; action = 'request'; locale = 'en-US' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $wxcExe
    $start.Arguments = "--config-base64 $(ConvertTo-Base64Json $request)"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $start.Environment['MXC_TELEMETRY_CONSENT_PRESENTER_PROTOCOL'] = '1'
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Failed to start consent maintenance process.' }

    $presentationLine = $process.StandardOutput.ReadLine()
    if (-not $presentationLine) { throw "Consent process emitted no presentation: $($process.StandardError.ReadToEnd())" }
    $presentation = $presentationLine | ConvertFrom-Json
    if ($presentation.result -eq 'alreadyGranted') {
        $process.WaitForExit()
        return $presentation
    }
    if ($presentation.result -ne 'presentationRequired' -or -not $presentation.challenge -or -not $presentation.prompt) {
        throw "Unexpected consent presentation: $presentationLine"
    }
    if ($presentation.prompt.resourceVersion -ne 1 -or
        $presentation.prompt.locale -ne 'en-US' -or
        $presentation.prompt.title.text -ne 'Help improve Microsoft eXecution Container (MXC)' -or
        $presentation.prompt.body.text -ne $expectedBody -or
        $presentation.prompt.affirmativeLabel.text -ne 'Yes, send optional diagnostic data' -or
        $presentation.prompt.negativeLabel.text -ne 'No, do not send' -or
        $presentation.prompt.learnMoreUrl -ne 'https://privacy.microsoft.com/privacystatement') {
        throw 'The executor did not present the canonical telemetry consent resource.'
    }

    $response = [pscustomobject]@{
        challenge = $presentation.challenge
        resourceVersion = $presentation.prompt.resourceVersion
        decision = 'yes'
    }
    $process.StandardInput.WriteLine(($response | ConvertTo-Json -Compress))
    $process.StandardInput.Close()
    $finalLine = $process.StandardOutput.ReadLine()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Consent request failed: $stderr" }
    if (-not $finalLine) { throw 'Consent process emitted no final response.' }
    $final = $finalLine | ConvertFrom-Json
    if ($final.result -ne 'granted' -or $final.effectiveState -ne 'granted') {
        throw "Consent was not granted: $finalLine"
    }
    return $final
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'SKIPPED: Administrator privileges are required for ETW session creation.' -ForegroundColor Yellow
    exit 0
}

$overrideName = 'MXC_TEST_LOCALAPPDATA_OVERRIDE'
$policyOverrideName = 'MXC_TEST_POLICY_KEY_OVERRIDE'
$originalOverride = [Environment]::GetEnvironmentVariable($overrideName)
$originalPolicyOverride = [Environment]::GetEnvironmentVariable($policyOverrideName)
$runId = [guid]::NewGuid().ToString('N')
$tempDir = Join-Path ([IO.Path]::GetTempPath()) "mxc_etw_test_$runId"
$consentFile = Join-Path $tempDir 'mxc\telemetry-consent.json'
$policySubkey = "Software\MxcTelemetryEtwSmoke\$runId"
$policyPath = "HKCU:\$policySubkey"
$etlDir = Join-Path $tempDir 'etl'
$etlFile = Join-Path $etlDir 'mxc_trace.etl'
$xmlFile = Join-Path $etlDir 'mxc_trace.xml'
$sessionName = "MxcTelemetryTest_$runId"
$traceStarted = $false

try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $consentFile) -Force | Out-Null
    New-Item -ItemType Directory -Path $etlDir -Force | Out-Null
    New-Item -Path $policyPath -Force | Out-Null
    Set-Item -Path "Env:$overrideName" -Value $tempDir
    Set-Item -Path "Env:$policyOverrideName" -Value $policySubkey

    foreach ($seed in @('granted', 'denied')) {
        $record = [pscustomobject]@{
            schemaVersion = 2
            consent = $seed
            source = 'etw-smoke-proof'
            promptedMxcVersion = '0.0.0-smoke'
            promptResourceVersion = 1
            promptLocale = 'en-US'
            updatedAtEpoch = 0
        }
        [IO.File]::WriteAllText(
            $consentFile,
            ($record | ConvertTo-Json -Compress),
            (New-Object Text.UTF8Encoding $false))
        $status = Invoke-Status
        if ($status.effectiveState -ne $seed) {
            throw "Consent override proof failed for '$seed'; refusing all MXC writes."
        }
    }
    Remove-Item $consentFile -Force

    $grant = Invoke-CanonicalGrant
    Set-ItemProperty -Path $policyPath -Name AllowTelemetry -Value 3 -Type DWord
    $authorized = Invoke-Status
    if ($authorized.effectiveState -ne 'granted' -or $authorized.policy -ne 'allowed') {
        throw 'Consent/policy authorization was not effective before ETW capture.'
    }

    $providerGuid = Get-TraceLoggingProviderGuid -Name $providerName
    logman stop $sessionName -ets 2>$null | Out-Null
    logman delete $sessionName -ets 2>$null | Out-Null
    logman create trace $sessionName -ets -o "$etlFile" -p $providerGuid 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create ETW trace session.' }
    $traceStarted = $true

    $proc = Start-Process -FilePath $wxcExe -ArgumentList '--debug', $configFile -PassThru -NoNewWindow -Wait
    Write-Host "wxc-exec exited with code $($proc.ExitCode)"
    Start-Sleep -Seconds 2

    logman stop $sessionName -ets 2>&1 | Out-Host
    $traceStarted = $false
    if (-not (Test-Path $etlFile) -or (Get-Item $etlFile).Length -eq 0) {
        throw 'ETL output was absent or empty.'
    }
    tracerpt "$etlFile" -o "$xmlFile" -of XML -y 2>&1 | Out-Host
    if (-not (Test-Path $xmlFile)) { throw 'tracerpt did not produce XML.' }
    $xml = Get-Content $xmlFile -Raw
    if (([regex]::Matches($xml, '<Event ')).Count -eq 0) {
        throw 'No parseable MXC events were captured.'
    }
    if ($xml -notmatch 'MXC\.Execution|MXC\.Error') {
        throw 'Captured events did not preserve the MXC.Execution/MXC.Error identities.'
    }
    Write-Host 'PASSED: isolated MXC ETW capture smoke test' -ForegroundColor Green
} finally {
    if ($traceStarted) { logman stop $sessionName -ets 2>$null | Out-Null }
    logman delete $sessionName -ets 2>$null | Out-Null
    if ($null -eq $originalOverride) { Remove-Item "Env:$overrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$overrideName" $originalOverride }
    if ($null -eq $originalPolicyOverride) { Remove-Item "Env:$policyOverrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$policyOverrideName" $originalPolicyOverride }
    Remove-Item -Recurse -Force $policyPath -ErrorAction SilentlyContinue
    if (-not $SkipClean) { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue }
}
