<#
.SYNOPSIS
    Isolated ETW capture smoke test for MXC telemetry.

.DESCRIPTION
    Uses a debug wxc-exec only, proves the debug-only consent and policy
    redirects before any MXC write, grants consent through the canonical
    session-bound presenter protocol, captures the public MXC ETW provider,
    and restores all process/machine state in finally.

.PARAMETER IsolationSessionLifecycle
    Captures two real IsolationSession lifecycles through the existing lifecycle
    suite instead of the create-and-run smoke request. Requires an available
    IsolationSession backend and Administrator; missing prerequisites fail.
    The executor must be a local-only debug build with test-support and
    isolation_session features.
#>

[CmdletBinding()]
param(
    [string]$BinDir,
    [switch]$SkipClean,
    [switch]$IsolationSessionLifecycle
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\TelemetryEtwAssertions.ps1')
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$srcDir = Join-Path $repoRoot 'src'
if (-not $BinDir) {
    $BinDir = Join-Path $srcDir 'target\debug'
}
elseif (-not [IO.Path]::IsPathRooted($BinDir)) {
    $BinDir = Join-Path $repoRoot $BinDir
}
$BinDir = [IO.Path]::GetFullPath($BinDir)
$wxcExe = Join-Path $BinDir 'wxc-exec.exe'
if (-not (Test-Path $wxcExe)) {
    throw "Debug wxc-exec.exe not found at '$wxcExe'. Run 'cargo build -p wxc --features test-support' (without --release)."
}
if ($wxcExe -match '\\release\\') {
    throw 'Release binaries are refused: telemetry smoke isolation depends on debug-only test overrides.'
}
$expectedBody = @'
Help improve MXC and other Microsoft product including Windows by sharing optional diagnostic data with Microsoft.

If enabled, MXC sends diagnostic information about product usage, performance, and reliability, including a random session ID that links events from the same container lifecycle. MXC does not send your commands, full file paths, credentials, or other customer content.
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

function Invoke-Status {
    $output = & $wxcExe --telemetry-consent status
    if ($LASTEXITCODE -ne 0) { throw "Consent status failed with exit code $LASTEXITCODE" }
    return ($output | ConvertFrom-Json)
}

function Invoke-CanonicalGrant {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $wxcExe
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
    if ($presentation.prompt.resourceVersion -ne 4 -or
        $presentation.prompt.locale -ne 'en-US' -or
        $presentation.prompt.title.text -ne 'Help improve Microsoft Products' -or
        $presentation.prompt.body.text -ne $expectedBody -or
        $presentation.prompt.affirmativeLabel.text -ne 'Yes' -or
        $presentation.prompt.negativeLabel.text -ne 'No' -or
        $presentation.prompt.learnMoreLabel.text -ne 'Privacy Statement' -or
        $presentation.prompt.learnMoreUrl -ne 'https://go.microsoft.com/fwlink/?linkid=521839') {
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
    if ($IsolationSessionLifecycle) { throw 'Administrator privileges are required for lifecycle ETW capture.' }
    Write-Host 'SKIPPED: Administrator privileges are required for ETW session creation.' -ForegroundColor Yellow
    exit 0
}

$overrideName = 'MXC_TEST_LOCALAPPDATA_OVERRIDE'
$overrideOwnerName = 'MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID'
$policyOverrideName = 'MXC_TEST_POLICY_KEY_OVERRIDE'
$policyOverrideOwnerName = 'MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID'
$originalOverride = [Environment]::GetEnvironmentVariable($overrideName)
$originalOverrideOwner = [Environment]::GetEnvironmentVariable($overrideOwnerName)
$originalPolicyOverride = [Environment]::GetEnvironmentVariable($policyOverrideName)
$originalPolicyOverrideOwner = [Environment]::GetEnvironmentVariable($policyOverrideOwnerName)
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
    Set-Item -Path "Env:$overrideOwnerName" -Value $PID
    Set-Item -Path "Env:$policyOverrideName" -Value $policySubkey
    Set-Item -Path "Env:$policyOverrideOwnerName" -Value $PID

    foreach ($seed in @('granted', 'denied')) {
        $record = [pscustomobject]@{
            schemaVersion = 2
            consent = $seed
            source = 'etw-smoke-proof'
            promptedMxcVersion = '0.0.0-smoke'
            promptResourceVersion = 4
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
    logman create trace $sessionName -ets -o "$etlFile" -p $providerGuid 0xFFFFFFFFFFFFFFFF 5 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create ETW trace session.' }
    $traceStarted = $true

    if ($IsolationSessionLifecycle) {
        $manifestFile = Join-Path $tempDir 'lifecycle-invocations.json'
        $global:LASTEXITCODE = 0
        & (Join-Path $PSScriptRoot 'run_isolation_session_state_aware_tests.ps1') `
            -WxcExePath $wxcExe -TelemetryResultsPath $manifestFile
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $manifestFile)) {
            throw 'IsolationSession lifecycle telemetry scenario did not complete.'
        }
        $invocations = @(Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json)
        $remainingRecords = @(Get-ChildItem -LiteralPath (Join-Path $tempDir 'mxc\correlation') -Filter '*.cv' -ErrorAction Stop)
        if ($remainingRecords.Count -ne 0) { throw 'Deprovision left lifecycle correlation records behind.' }
    } else {
        $executionTimeoutSeconds = 60
        $proc = Start-Process -FilePath $wxcExe -ArgumentList '--debug', $configFile -PassThru -NoNewWindow
        # Caching the handle keeps ExitCode readable after the process exits.
        $null = $proc.Handle
        if (-not $proc.WaitForExit($executionTimeoutSeconds * 1000)) {
            Stop-Process -Id $proc.Id -Force
            $proc.WaitForExit()
            throw "wxc-exec timed out after $executionTimeoutSeconds seconds"
        }
        Write-Host "wxc-exec exited with code $($proc.ExitCode)"
        $invocations = @([pscustomobject]@{ ProcessId = $proc.Id })
    }
    Start-Sleep -Seconds 2

    logman stop $sessionName -ets 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Failed to stop ETW trace session.' }
    $traceStarted = $false
    if (-not (Test-Path $etlFile) -or (Get-Item $etlFile).Length -eq 0) {
        throw 'ETL output was absent or empty.'
    }
    tracerpt "$etlFile" -o "$xmlFile" -of XML -lr -y 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Failed to decode ETW trace.' }
    if (-not (Test-Path $xmlFile)) { throw 'tracerpt did not produce XML.' }
    $xml = Get-Content $xmlFile -Raw
    Assert-TelemetryExecutionTrace -XmlText $xml -ProviderGuid $providerGuid `
        -Invocations $invocations -RequireLifecycles:$IsolationSessionLifecycle
    Write-Host 'PASSED: isolated MXC ETW capture smoke test' -ForegroundColor Green
} finally {
    if ($traceStarted) { logman stop $sessionName -ets 2>$null | Out-Null }
    if ($null -eq $originalOverride) { Remove-Item "Env:$overrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$overrideName" $originalOverride }
    if ($null -eq $originalOverrideOwner) { Remove-Item "Env:$overrideOwnerName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$overrideOwnerName" $originalOverrideOwner }
    if ($null -eq $originalPolicyOverride) { Remove-Item "Env:$policyOverrideName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$policyOverrideName" $originalPolicyOverride }
    if ($null -eq $originalPolicyOverrideOwner) { Remove-Item "Env:$policyOverrideOwnerName" -ErrorAction SilentlyContinue }
    else { Set-Item "Env:$policyOverrideOwnerName" $originalPolicyOverrideOwner }
    Remove-Item -Recurse -Force $policyPath -ErrorAction SilentlyContinue
    if (-not $SkipClean) { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue }
}

# Native cleanup commands may legitimately report "session not found." Do not
# leak their `$LASTEXITCODE` after the test has completed successfully.
exit 0
