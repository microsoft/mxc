# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$ContextJson,
    [string]$ResultsJson,
    [string]$RequireTier,
    [switch]$SkipNetwork,
    [switch]$KeepArtifacts,
    [switch]$RequirePolicyResults,
    [string]$CaseManifest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')
$contextArguments = @{}
foreach ($name in @('ContextJson', 'ResultsJson', 'RequireTier', 'SkipNetwork', 'KeepArtifacts')) {
    if ($PSBoundParameters.ContainsKey($name)) { $contextArguments[$name] = $PSBoundParameters[$name] }
}
Initialize-WpcContext @contextArguments

function Read-PolicyReport {
    param([string]$Stderr)
    $report = $null
    foreach ($line in ($Stderr -split '\r?\n')) {
        if (-not $line.StartsWith('{') -or
            ($line -notmatch '^\{"error"\s*:' -and
                $line -notmatch '"type"\s*:\s*"policyEnforcement"')) { continue }
        $envelope = $line | ConvertFrom-Json -ErrorAction Stop
        if ($envelope.PSObject.Properties['type'] -and $envelope.type -eq 'policyEnforcement') {
            $report = $envelope.report
        } elseif ($envelope.PSObject.Properties['error'] -and
            $envelope.error.PSObject.Properties['details'] -and
            $envelope.error.details.PSObject.Properties['policyEnforcement']) {
            $report = $envelope.error.details.policyEnforcement
        }
    }
    if ($null -eq $report) { throw 'No structured creation-policy report was returned.' }
    if ($report.reportVersion -ne 1) { throw 'The executor returned an unsupported policy report version.' }
    return $report
}

function Get-WorkloadCreationCount([string]$Log) {
    # Logger timestamps can prefix individual formatted fragments, including the PID.
    $text = [regex]::Replace($Log, '\[[0-9]+\] ', '')
    return [regex]::Matches($text,
        '(?m)^(?:process created|Process created successfully) \(PID: [0-9]+\)\r?$').Count
}

function Test-IgnoredPolicyAttempts($Report) {
    if ($Report.modeApplied -or $Report.availability -notin @('unavailable', 'notApplicable')) {
        return $false
    }
    $attempts = @($Report.attempts)
    if ($attempts.Count -eq 0) { return $true }
    return $Report.availability -eq 'unavailable' -and $attempts.Count -eq 1 -and
        $attempts[0].hresult -eq '0x80004001' -and
        $attempts[0].result.outcome.code -eq 0 -and
        $attempts[0].result.detailsCount -eq 0 -and @($attempts[0].result.details).Count -eq 0 -and
        $attempts[0].result.resourceCharsWritten -eq 0 -and $attempts[0].result.resourceCharsRequired -eq 0
}

function Test-PolicyDeniedGuidance([string]$Text) {
    return $Text -cmatch '(?<![0-9A-Fa-f])0x800704EC(?![0-9A-Fa-f])' -and
        $Text.Contains('IT-managed policy rule') -and
        $Text.Contains('requested sandbox permissions') -and
        $Text.Contains('system administrator')
}

function Phase-PolicyEnforcement {
    Section 'Creation-policy reporting and bounded mutation'
    $policyDenied = '0x800704EC IT-managed policy rule requested sandbox permissions system administrator'
    if (-not (Test-PolicyDeniedGuidance $policyDenied) -or
        (Test-PolicyDeniedGuidance ($policyDenied.Replace('0x800704EC','0x80070005'))) -or
        (Test-PolicyDeniedGuidance 'failed to create the process security environment: 0x800704EC')) {
        throw 'The policy-denied guidance oracle accepted an unrelated or unexplained failure.'
    }
    $first = '[100] process created (PID: [100] 123[100] )'
    $second = '[101] Process created successfully (PID: 456)'
    if ((Get-WorkloadCreationCount '') -ne 0 -or
        (Get-WorkloadCreationCount $first) -ne 1 -or
        (Get-WorkloadCreationCount "$first`n$second") -ne 2) {
        throw 'The independent workload-creation counter failed its regression checks.'
    }
    $ignored = [pscustomobject]@{ availability = 'unavailable'; modeApplied = $false; attempts = @() }
    if (-not (Test-IgnoredPolicyAttempts $ignored)) { throw 'Zero-attempt compatibility oracle failed.' }
    $ignored.attempts = @([pscustomobject]@{
        hresult = '0x80004001'
        result = [pscustomobject]@{
            outcome = [pscustomobject]@{ code = 0 }; detailsCount = 0; details = @()
            resourceCharsWritten = 0; resourceCharsRequired = 0
        }
    })
    if (-not (Test-IgnoredPolicyAttempts $ignored)) { throw 'Decision-free compatibility oracle failed.' }
    $ignored.attempts[0].result.outcome.code = 3
    if (Test-IgnoredPolicyAttempts $ignored) { throw 'The compatibility oracle accepted a policy refusal.' }
    $probeConfig = New-Config -Name 'policy-results-probe' -CommandLine 'cmd /c exit 0' `
        -SchemaVersion '0.10.0-alpha' -EgressDefault deny -IngressDefault deny -HostLoopback deny
    $probeRequest = Get-Content -LiteralPath $probeConfig -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $probeRequest.PSObject.Properties['processContainer']) {
        $probeRequest | Add-Member -NotePropertyName processContainer -NotePropertyValue ([pscustomobject]@{})
    }
    $probeRequest.processContainer | Add-Member -NotePropertyName policyEnforcement `
        -NotePropertyValue ([pscustomobject]@{})
    $probeConfig = New-RawConfig -Name 'policy-results-probe' -Object $probeRequest
    $probe = Invoke-Probe -Wxc $WxcDebug -ConfigPath $probeConfig -Phase 'PolicyEnforcement' -Name 'policy-results'
    if ($null -eq $probe -or -not $probe.probes.PSObject.Properties['baseContainerPolicyResultsAvailable']) {
        throw 'The executor did not report detailed policy-result capability.'
    }
    $available = [bool]$probe.probes.baseContainerPolicyResultsAvailable
    if ($RequirePolicyResults -and (-not $available -or $probe.tier -ne 'base-container')) {
        throw 'This lane requires BaseContainer and the CPSE2 policy-result contract; fallback is not coverage.'
    }

    if (-not $available) {
        foreach ($mode in @('legacy', 'pass-through', 'mutate')) {
            $version = if ($mode -eq 'legacy') { '0.9.0-alpha' } else { '0.10.0-alpha' }
            $path = New-Config -Name "policy-ignored-$mode" -SchemaVersion $version `
                -CommandLine 'cmd /c echo MXC_POLICY_COMPAT' -ReadOnly @($env:SystemRoot) `
                -EgressDefault deny -IngressDefault deny -HostLoopback deny
            $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($mode -ne 'legacy') {
                if (-not $config.PSObject.Properties['processContainer']) {
                    $config | Add-Member -NotePropertyName processContainer -NotePropertyValue ([pscustomobject]@{})
                }
                $config.processContainer | Add-Member -NotePropertyName policyEnforcement `
                    -NotePropertyValue ([pscustomobject]@{ mode = $mode; maxAttempts = 1 })
            }
            $path = New-RawConfig -Name "policy-ignored-$mode" -Object $config
            $run = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $path `
                -LogPath (Join-Path $ScratchRoot "logs\policy-ignored-$mode.log") -Experimental $false
            if ($mode -eq 'legacy') {
                Record-Result -Phase 'PolicyEnforcement' -Name 'Omitted controls retain legacy output without CPSE2' `
                    -Pass (-not $run.TimedOut -and $run.ExitCode -eq 0 -and
                        $run.Stdout -match 'MXC_POLICY_COMPAT' -and $run.Stderr -notmatch '"policyEnforcement"')
                continue
            }
            $report = Read-PolicyReport $run.Stderr
            Record-Result -Phase 'PolicyEnforcement' -Name "$mode ignored without CPSE2 or experimental authorization" `
                -Pass (-not $run.TimedOut -and $run.ExitCode -eq 0 -and
                    $run.Stdout -match 'MXC_POLICY_COMPAT' -and -not $report.modeApplied -and
                    $report.availability -in @('unavailable', 'notApplicable') -and
                    (Test-IgnoredPolicyAttempts $report) -and
                    $report.termination -eq 'ignored')
        }
        return
    }

    if (-not $CaseManifest) {
        if ($RequirePolicyResults) { throw 'The enforcing lane requires a prepared policy-case manifest.' }
        Record-Result -Phase 'PolicyEnforcement' -Name 'Governed policy cases require an isolated prepared VM' `
            -Status skip -Detail 'CPSE2 is available, but no governed-caller policy fixture was supplied.'
        return
    }

    $manifestPath = (Resolve-Path -LiteralPath $CaseManifest).Path
    $parsedCases = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $cases = @($parsedCases)
    if ($cases.Count -eq 0) { throw 'The policy-case manifest is empty.' }
    $blocked = $false
    $multipleRepairs = $false
    $index = 0
    foreach ($case in $cases) {
        $expectReport = $true
        if ($case.PSObject.Properties['expectReport']) {
            if ($case.expectReport -isnot [bool]) { throw 'expectReport must be a JSON boolean.' }
            $expectReport = $case.expectReport
        }
        $requiredFields = @('name', 'config', 'experimental', 'expectedExitCode',
            'stdoutPattern', 'stdoutMatchCount', 'expectedProcessCreations')
        if ($expectReport) {
            $requiredFields += @('expectedTermination', 'expectedOutcomeCode', 'minAttempts', 'maxAttempts')
        }
        foreach ($field in $requiredFields) {
            if (-not $case.PSObject.Properties[$field]) { throw "Policy case is missing '$field'." }
        }
        if ($case.experimental -isnot [bool]) { throw 'The experimental case option must be a JSON boolean.' }
        if ($case.expectedProcessCreations -notin @(0, 1)) {
            throw 'A policy case must expect zero or one workload process creation.'
        }
        if ($expectReport) {
            $expectedAvailability = if ($case.PSObject.Properties['expectedAvailability']) {
                [string]$case.expectedAvailability
            } else { 'available' }
            if ($expectedAvailability -notin @('available', 'unavailable', 'notApplicable')) {
                throw 'Unsupported expected policy-result availability.'
            }
            $minimumAttempts = if ($expectedAvailability -eq 'available') { 1 } else { 0 }
            if ($case.minAttempts -lt $minimumAttempts -or $case.maxAttempts -gt 64 -or
                $case.minAttempts -gt $case.maxAttempts) {
                throw 'Attempt bounds must be ordered within 0-64, with at least one attempt for available policy results.'
            }
        }
        $configPath = if ([IO.Path]::IsPathRooted($case.config)) {
            [string]$case.config
        } else {
            Join-Path (Split-Path -Parent $manifestPath) $case.config
        }
        if ($case.PSObject.Properties['expectedTier']) {
            $requestProbe = Invoke-Probe -Wxc $WxcDebug -ConfigPath $configPath `
                -Phase 'PolicyEnforcement' -Name "case-$index-tier"
            if (-not $requestProbe -or -not $requestProbe.PSObject.Properties['tier'] -or
                $requestProbe.tier -ne $case.expectedTier) {
                throw "Case $($case.name) did not select its required tier."
            }
        }
        $run = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $configPath `
            -LogPath (Join-Path $ScratchRoot "logs\policy-case-$index.log") `
            -Experimental ([bool]$case.experimental)
        $parentLog = [IO.File]::ReadAllText((Join-Path $ScratchRoot "logs\policy-case-$index.log"))
        if ([string]::IsNullOrWhiteSpace($parentLog)) {
            throw 'A nonempty parent diagnostic log is required to count workload creations.'
        }
        $processCreations = Get-WorkloadCreationCount $parentLog
        foreach ($stream in @('Stdout', 'Stderr')) {
            [IO.File]::WriteAllText(
                (Join-Path $ScratchRoot "logs\policy-case-$index.$stream.txt"),
                $run.$stream, [Text.UTF8Encoding]::new($false))
        }
        if (-not $expectReport) {
            $pass = -not $run.TimedOut -and $run.ExitCode -eq $case.expectedExitCode -and
                $run.Stderr -notmatch '"policyEnforcement"' -and
                $processCreations -eq $case.expectedProcessCreations -and
                ([regex]::Matches($run.Stdout, $case.stdoutPattern).Count -eq $case.stdoutMatchCount)
            if ($case.PSObject.Properties['stderrPattern']) {
                $pass = $pass -and $run.Stderr -match $case.stderrPattern
            }
            if ($case.PSObject.Properties['expectedPolicyDeniedGuidance']) {
                if ($case.expectedPolicyDeniedGuidance -isnot [bool]) { throw 'expectedPolicyDeniedGuidance must be a boolean.' }
                if ($case.expectedPolicyDeniedGuidance) {
                    $pass = $pass -and (Test-PolicyDeniedGuidance $run.Stderr)
                }
            }
            Record-Result -Phase 'PolicyEnforcement' -Name $case.name -Pass $pass `
                -Detail "exit=$($run.ExitCode); report=absent; creations=$processCreations"
            $index++
            continue
        }
        $report = Read-PolicyReport $run.Stderr
        $attempts = @($report.attempts)
        $outcome = if ($attempts.Count -gt 0) { $attempts[-1].result.outcome.code } else { -1 }
        $pass = -not $run.TimedOut -and $run.ExitCode -eq $case.expectedExitCode -and
            $report.availability -eq $expectedAvailability -and
            $report.termination -eq $case.expectedTermination -and
            $outcome -eq $case.expectedOutcomeCode -and
            $attempts.Count -ge $case.minAttempts -and $attempts.Count -le $case.maxAttempts -and
            $processCreations -eq $case.expectedProcessCreations -and
            ([regex]::Matches($run.Stdout, $case.stdoutPattern).Count -eq $case.stdoutMatchCount)
        foreach ($attempt in $attempts) {
            if (@($attempt.result.details).Count -ne $attempt.result.detailsCount -or
                $attempt.result.detailsCount -gt 64) {
                throw 'A policy attempt has an inconsistent detail array.'
            }
        }
        if ($case.PSObject.Properties['expectedDetailCounts']) {
            $actualCounts = @($attempts | ForEach-Object { [int]$_.result.detailsCount })
            $pass = $pass -and
                (($actualCounts -join ',') -eq (@($case.expectedDetailCounts) -join ','))
        }
        if ($expectedAvailability -ne 'available') {
            $pass = $pass -and (Test-IgnoredPolicyAttempts $report)
        }
        Record-Result -Phase 'PolicyEnforcement' -Name $case.name -Pass $pass `
            -Detail "exit=$($run.ExitCode); attempts=$($attempts.Count); creations=$processCreations; termination=$($report.termination); outcome=$outcome"
        $blocked = $blocked -or ($pass -and $outcome -eq 3 -and -not $report.environmentCreated -and $processCreations -eq 0)
        $batchRepairs = @($attempts | Where-Object {
            $_.result.detailsCount -gt 1 -and $_.PSObject.Properties['changes'] -and @($_.changes).Count -gt 0
        }).Count -gt 0
        $multipleRepairs = $multipleRepairs -or ($pass -and $batchRepairs -and
            $outcome -eq 2 -and $report.termination -eq 'created' -and
            $report.environmentCreated -and $case.stdoutMatchCount -eq 1 -and $processCreations -eq 1)
        $index++
    }
    if ($RequirePolicyResults) {
        Record-Result -Phase 'PolicyEnforcement' -Name 'Governing policy actually refused a creation' -Pass $blocked
        Record-Result -Phase 'PolicyEnforcement' -Name 'Multiple repairs preceded one successful creation' -Pass $multipleRepairs
    }
}

Invoke-WpcPhase -Key 'PolicyEnforcement' -Body { Phase-PolicyEnforcement }
Complete-WpcChild
