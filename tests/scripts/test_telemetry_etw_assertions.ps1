# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [Parameter(Mandatory)][string]$WxcExePath
)

$ErrorActionPreference = 'Stop'
$WxcExec = (Resolve-Path -LiteralPath $WxcExePath).Path
. (Join-Path $PSScriptRoot 'lib\TelemetryEtwAssertions.ps1')

$providerGuid = [guid]'11111111-2222-4333-8444-555555555555'
$nextProcessId = 100
$invocations = @(
    foreach ($lifecycle in 1, 2) {
        foreach ($phase in @('provision', 'start', 'exec', 'exec', 'stop', 'deprovision')) {
            [pscustomobject]@{
                Lifecycle = $lifecycle; Phase = $phase; ProcessId = $nextProcessId; ExitCode = 0
                ContractVersion = $(if ($lifecycle -eq 2) { '1.1.0-alpha' } else { '1.0.0' })
                RequireProcessExit = $phase -eq 'exec'
                RequireError = $phase -eq 'provision'
            }
            $nextProcessId++
        }
    }
)
function New-TestTrace {
    $eventXml = foreach ($invocation in $invocations) {
        foreach ($task in @('MXC.ExecutionStart', 'MXC.ExecutionEnd')) {
            $fields = [ordered]@{
                'PartA_PrivacyProduct' = '11'
                'PartA_PrivacyDataCategory' = '1'
                'PartA_PrivTags' = $(if ($invocation.ContractVersion -eq '1.1.0-alpha') { '16777216' } else { '33554432' })
                'mxc.session_id' = "00000000-0000-4000-8000-00000000000$($invocation.Lifecycle)"
                'mxc.capture_denials' = 'not_applicable'
                'mxc.sandbox_kind' = 'isolation_session'
                'mxc.backend' = 'isolation_session'
                'mxc.exit_code' = '0'
                'mxc.outcome' = $(if ($task -eq 'MXC.ExecutionStart') { 'started' } else { 'success' })
                'mxc.duration_ms' = '0'
                'mxc.failure_reason' = ''
                'mxc.phase' = $invocation.Phase
                '__TlgCV__' = "lifecycle$($invocation.Lifecycle).$($invocation.ProcessId).0"
            }
            $eventData = foreach ($field in $fields.Keys) { "<Data Name='$field'>$($fields[$field])</Data>" }
            $keyword = if ($invocation.ContractVersion -eq '1.1.0-alpha') { '0x800000000000' } else { '0x400000000000' }
            "<Event><System><Provider Guid='{$providerGuid}'/><Task>0</Task><Keywords>$keyword</Keywords><Execution ProcessID='$($invocation.ProcessId)'/><TimeCreated SystemTime='2026-01-01T00:00:00Z'/></System><EventData>$($eventData -join '')</EventData><RenderingInfo Culture='en-US'><Task>$task</Task></RenderingInfo></Event>"
        }
    }
    $eventXml += @(
        foreach ($invocation in $invocations) {
            foreach ($task in @(
                'MXC.PolicyHash'
                if ($invocation.RequireProcessExit) { 'MXC.ProcessExited' }
                if ($invocation.RequireError) { 'MXC.Error' }
            )) {
                $keyword = if ($invocation.ContractVersion -eq '1.1.0-alpha' -and $task -ne 'MXC.PolicyHash') {
                    '0x800000000000'
                } else { '0x400000000000' }
                $privacyTag = if ($keyword -eq '0x800000000000') { '16777216' } else { '33554432' }
                "<Event><System><Provider Guid='{$providerGuid}'/><Keywords>$keyword</Keywords><Execution ProcessID='$($invocation.ProcessId)'/><TimeCreated SystemTime='2026-01-01T00:00:00Z'/></System><EventData><Data Name='PartA_PrivTags'>$privacyTag</Data></EventData><RenderingInfo><Task>$task</Task></RenderingInfo></Event>"
            }
        }
    )
    "<Events xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>$($eventXml -join '')</Events>"
}

function Set-TestField {
    param([xml]$Trace, [int]$EventIndex, [string]$Name, [string]$Value)
    $events = $Trace.SelectNodes("//*[local-name()='Event']")
    $field = $events[$EventIndex].SelectSingleNode("*[local-name()='EventData']/*[@Name='$Name']")
    $field.InnerText = $Value
}

$cases = @(
    @{ Name = 'two complete cross-process lifecycles'; Mutate = {}; Fails = $false },
    @{ Name = 'missing terminal event'; Mutate = { $null = $trace.DocumentElement.RemoveChild($trace.DocumentElement.ChildNodes[23]) }; Fails = $true },
    @{ Name = 'duplicate start'; Mutate = { $null = $trace.DocumentElement.AppendChild($trace.DocumentElement.FirstChild.CloneNode($true)) }; Fails = $true },
    @{ Name = 'wrong emitter'; Mutate = { $trace.DocumentElement.ChildNodes[23].System.Execution.SetAttribute('ProcessID', '9999') }; Fails = $true },
    @{ Name = 'wrong provider'; Mutate = { $trace.DocumentElement.ChildNodes[23].System.Provider.SetAttribute('Guid', '{99999999-2222-4333-8444-555555555555}') }; Fails = $true },
    @{ Name = 'missing rendered event name'; Mutate = {
        $event = $trace.DocumentElement.FirstChild
        $null = $event.RemoveChild($event.RenderingInfo)
        $event.System.Task = 'MXC.ExecutionStart'
    }; Fails = $true },
    @{ Name = 'retired rendered event name'; Mutate = {
        $trace.DocumentElement.FirstChild.RenderingInfo.Task = 'MXC.Execution'
    }; Fails = $true },
    @{ Name = 'unknown session ID'; Mutate = { Set-TestField $trace 0 'mxc.session_id' 'unknown' }; Fails = $true },
    @{ Name = 'Start End ID mismatch'; Mutate = { Set-TestField $trace 1 'mxc.session_id' '00000000-0000-4000-8000-000000000009' }; Fails = $true },
    @{ Name = 'lost ID between processes'; Mutate = {
        Set-TestField $trace 2 'mxc.session_id' '00000000-0000-4000-8000-000000000009'
        Set-TestField $trace 3 'mxc.session_id' '00000000-0000-4000-8000-000000000009'
    }; Fails = $true },
    @{ Name = 'lost CV between processes'; Mutate = {
        Set-TestField $trace 2 '__TlgCV__' 'changed.0'
        Set-TestField $trace 3 '__TlgCV__' 'changed.0'
    }; Fails = $true },
    @{ Name = 'reused session after cleanup'; Mutate = {
        for ($index = 12; $index -lt 24; $index++) {
            Set-TestField $trace $index 'mxc.session_id' '00000000-0000-4000-8000-000000000001'
        }
    }; Fails = $true },
    @{ Name = 'wrong phase'; Mutate = { Set-TestField $trace 0 'mxc.phase' 'exec'; Set-TestField $trace 1 'mxc.phase' 'exec' }; Fails = $true },
    @{ Name = 'wrong backend'; Mutate = { Set-TestField $trace 0 'mxc.backend' 'processcontainer'; Set-TestField $trace 1 'mxc.backend' 'processcontainer' }; Fails = $true },
    @{ Name = 'invalid capture mode'; Mutate = { Set-TestField $trace 0 'mxc.capture_denials' 'unbounded' }; Fails = $true },
    @{ Name = 'unsuccessful lifecycle'; Mutate = { Set-TestField $trace 1 'mxc.outcome' 'failure' }; Fails = $true },
    @{ Name = 'terminal before start'; Mutate = { $trace.DocumentElement.FirstChild.System.TimeCreated.SetAttribute('SystemTime', '2026-01-02T00:00:00Z') }; Fails = $true },
    @{ Name = 'missing field'; Mutate = {
        $field = $trace.DocumentElement.FirstChild.SelectSingleNode("*[local-name()='EventData']/*[@Name='mxc.session_id']")
        $null = $field.ParentNode.RemoveChild($field)
    }; Fails = $true },
    @{ Name = 'development event still Measures'; Mutate = { $trace.DocumentElement.ChildNodes[12].System.Keywords = '0x400000000000' }; Fails = $true },
    @{ Name = 'published event changed to Critical'; Mutate = { $trace.DocumentElement.FirstChild.System.Keywords = '0x800000000000' }; Fails = $true },
    @{ Name = 'combined telemetry categories'; Mutate = { $trace.DocumentElement.ChildNodes[12].System.Keywords = '0xC00000000000' }; Fails = $true },
    @{ Name = 'missing descriptor keywords'; Mutate = {
        $system = $trace.DocumentElement.FirstChild.System
        $null = $system.RemoveChild($system.SelectSingleNode("*[local-name()='Keywords']"))
    }; Fails = $true },
    @{ Name = 'Core start still tagged Usage'; Mutate = { Set-TestField $trace 12 'PartA_PrivTags' '33554432' }; Fails = $true },
    @{ Name = 'Core end still tagged Usage'; Mutate = { Set-TestField $trace 13 'PartA_PrivTags' '33554432' }; Fails = $true },
    @{ Name = 'published event changed to Performance'; Mutate = { Set-TestField $trace 0 'PartA_PrivTags' '16777216' }; Fails = $true },
    @{ Name = 'Core error still tagged Usage'; Mutate = {
        $event = $trace.SelectSingleNode("//*[local-name()='Event'][*[local-name()='System']/*[local-name()='Keywords']='0x800000000000'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.Error']")
        $event.EventData.Data.InnerText = '33554432'
    }; Fails = $true },
    @{ Name = 'Core exit still tagged Usage'; Mutate = {
        $event = $trace.SelectSingleNode("//*[local-name()='Event'][*[local-name()='System']/*[local-name()='Keywords']='0x800000000000'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.ProcessExited']")
        $event.EventData.Data.InnerText = '33554432'
    }; Fails = $true },
    @{ Name = 'other events retain Usage'; Mutate = {
        $event = $trace.SelectSingleNode("//*[local-name()='Event'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.PolicyHash']")
        $event.EventData.Data.InnerText = '16777216'
    }; Fails = $true },
    @{ Name = 'missing privacy tag'; Mutate = {
        $event = $trace.DocumentElement.FirstChild
        $field = $event.SelectSingleNode("*[local-name()='EventData']/*[@Name='PartA_PrivTags']")
        $null = $field.ParentNode.RemoveChild($field)
    }; Fails = $true },
    @{ Name = 'invalid privacy tag'; Mutate = { Set-TestField $trace 12 'PartA_PrivTags' 'invalid' }; Fails = $true },
    @{ Name = 'combined privacy categories'; Mutate = { Set-TestField $trace 12 'PartA_PrivTags' '50331648' }; Fails = $true },
    @{ Name = 'hexadecimal privacy tag'; Mutate = { Set-TestField $trace 12 'PartA_PrivTags' '0x01000000' }; Fails = $false },
    @{ Name = 'other events must retain Measures'; Mutate = {
        $event = $trace.SelectSingleNode("//*[local-name()='Event'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.PolicyHash']")
        $event.System.Keywords = '0x800000000000'
    }; Fails = $true },
    @{ Name = 'missing process exit'; Mutate = {
        foreach ($event in @($trace.SelectNodes("//*[local-name()='Event'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.ProcessExited']"))) {
            $null = $event.ParentNode.RemoveChild($event)
        }
    }; Fails = $true },
    @{ Name = 'missing categorized failure'; Mutate = {
        foreach ($event in @($trace.SelectNodes("//*[local-name()='Event'][*[local-name()='RenderingInfo']/*[local-name()='Task']='MXC.Error']"))) {
            $null = $event.ParentNode.RemoveChild($event)
        }
    }; Fails = $true }
)
foreach ($case in $cases) {
    [xml]$trace = New-TestTrace
    & $case.Mutate
    $failure = $null
    try {
        Assert-TelemetryExecutionTrace -XmlText $trace.OuterXml -ProviderGuid $providerGuid `
            -Invocations $invocations -RequireLifecycles -CheckKeywords
    } catch { $failure = $_.Exception.Message }
    if ([bool]$failure -ne $case.Fails) { throw "$($case.Name): unexpected assertion result '$failure'." }
    Write-Host "PASS: $($case.Name)"
}
Assert-TelemetryExecutionTrace -XmlText (New-TestTrace) -ProviderGuid $providerGuid `
    -Invocations @($invocations[0])
Write-Host 'PASS: basic smoke execution pair'
[xml]$failedExecutionTrace = New-TestTrace
Set-TestField $failedExecutionTrace 1 'mxc.outcome' 'failure'
Set-TestField $failedExecutionTrace 1 'mxc.exit_code' '1'
Assert-TelemetryExecutionTrace -XmlText $failedExecutionTrace.OuterXml -ProviderGuid $providerGuid `
    -Invocations @($invocations[0])
Write-Host 'PASS: basic smoke failure execution pair on an unavailable backend'
foreach ($manifestCase in @(
    @{ Name = 'empty selection'; Invocations = @() },
    @{ Name = 'only one lifecycle'; Invocations = @($invocations | Select-Object -First 6) },
    @{ Name = 'reused executor PID'; Invocations = @($invocations[0], $invocations[0]) }
)) {
    $rejected = $false
    try {
        Assert-TelemetryExecutionTrace -XmlText (New-TestTrace) -ProviderGuid $providerGuid `
            -Invocations $manifestCase.Invocations -RequireLifecycles
    } catch { $rejected = $true }
    if (-not $rejected) { throw "$($manifestCase.Name) should fail." }
    Write-Host "PASS: $($manifestCase.Name)"
}

# Exercise the same fixture writer as release CI without running its machine mutations.
$releaseTest = Join-Path $PSScriptRoot 'run_telemetry_consent_release_test.ps1'
$parseErrors = $null
$syntax = [Management.Automation.Language.Parser]::ParseFile($releaseTest, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors -join "`n") }
$writer = $syntax.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-ConsentRecord'
}, $true)
if (-not $writer) { throw 'Release consent fixture writer was not found.' }
. ([scriptblock]::Create($writer.Extent.Text))
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("mxc-release-consent-fixture-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $consentFile = Join-Path $scratch 'consent.json'
    Write-ConsentRecord -Consent 'granted'
    $record = Get-Content -LiteralPath $consentFile -Raw | ConvertFrom-Json
    $resourcePath = Join-Path $PSScriptRoot '..\..\src\mxc-sdk\resources\telemetry\consent\en-US.json'
    $resource = Get-Content -LiteralPath $resourcePath -Raw | ConvertFrom-Json
    if ($record.promptResourceVersion -ne $resource.resourceVersion) {
        throw 'Release consent default fixture does not match the current consent resource.'
    }
    Write-ConsentRecord -Consent 'granted' -PromptVersion 999
    if ((Get-Content -LiteralPath $consentFile -Raw | ConvertFrom-Json).promptResourceVersion -ne 999) {
        throw 'The explicit unsupported-version fixture was lost.'
    }
    Write-Host 'PASS: release consent fixture defaults and unsupported-version control'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}

# Validate the actual scenario's requests with --dry-run, without provisioning
# accounts or sessions. Synthetic results let the same orchestration continue.
$suitePath = Join-Path $PSScriptRoot 'run_isolation_session_state_aware_tests.ps1'
$suiteSyntax = [Management.Automation.Language.Parser]::ParseFile($suitePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors -join "`n") }
foreach ($functionName in @('ConvertTo-StateAwareInvocation', 'Invoke-StateAware')) {
    $definition = $suiteSyntax.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true)
    if (-not $definition) { throw "Lifecycle helper '$functionName' was not found." }
    $functionText = $definition.Extent.Text
    if ($functionName -eq 'Invoke-StateAware') {
        $functionText = $functionText.Replace('function Invoke-StateAware {', 'function Invoke-ValidatedStateAware {')
    }
    . ([scriptblock]::Create($functionText))
}
$scenario = $suiteSyntax.Find({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -eq '$TelemetryResultsPath' -and
        $node.Extent.Text.Contains('$telemetryInvocations =')
}, $true)
if (-not $scenario) { throw 'Lifecycle telemetry scenario was not found.' }
$statements = $scenario.Clauses[0].Item2.Statements
if ($statements[-1] -isnot [Management.Automation.Language.ExitStatementAst]) {
    throw 'Expected the lifecycle scenario to end with its exit gate.'
}
$runScenario = [scriptblock]::Create(
    ($statements[0..($statements.Count - 2)] | ForEach-Object { $_.Extent.Text }) -join "`n")
$script:validatedRequests = [Collections.Generic.List[object]]::new()
$syntheticPayload = '{"version":1,"agentUserName":"mxc-telemetry-dry-run"}'
$syntheticSandboxId = 'iso:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($syntheticPayload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

function Parse-Envelope {
    param([string]$Stdout)
    $Stdout | ConvertFrom-Json
}

function Invoke-StateAware {
    param([hashtable]$Request)
    $validationRequest = $Request.Clone()
    $validationRequest.telemetry = @{ enabled = $false }
    $validation = Invoke-ValidatedStateAware -Request $validationRequest -DryRun
    if ($validation.ExitCode -ne 0) {
        throw "Lifecycle '$($Request.phase)' failed real dry-run validation: $($validation.Stdout) $($validation.Stderr)"
    }
    $script:validatedRequests.Add($Request.Clone())
    $stdout = switch ($Request.phase) {
        'provision' { @{ result = @{ sandboxId = $syntheticSandboxId } } | ConvertTo-Json -Compress }
        'exec' { 'mxc-telemetry-lifecycle' }
        default { '{"result":{}}' }
    }
    @{ ProcessId = 100 + $script:validatedRequests.Count; ExitCode = 0; Stdout = $stdout; Stderr = '' }
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("mxc-lifecycle-requests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $TelemetryResultsPath = Join-Path $scratch 'invocations.json'
    $TelemetryKeywords = $true
    & $runScenario
    $manifest = @(Get-Content -LiteralPath $TelemetryResultsPath -Raw | ConvertFrom-Json)
    if ($manifest.Count -ne 12 -or $script:validatedRequests.Count -ne 12) {
        throw 'The lifecycle scenario did not validate all twelve executor requests.'
    }
    foreach ($request in $script:validatedRequests) {
        if ($request.telemetry.enabled -ne $true -or
            ($request.phase -ne 'provision' -and $request.ContainsKey('network'))) {
            throw 'Lifecycle opt-in or provision-only network placement was lost.'
        }
        if (@($manifest | Where-Object ContractVersion -CEQ '1.0.0').Count -ne 6 -or
            @($manifest | Where-Object ContractVersion -CEQ '1.1.0-alpha').Count -ne 6 -or
            @($script:validatedRequests | Where-Object version -CEQ '1.0.0').Count -ne 6 -or
            @($script:validatedRequests | Where-Object version -CEQ '1.1.0-alpha').Count -ne 6) {
            throw 'Lifecycle keyword validation must exercise both published and development contracts.'
        }
    }
    $missingNetwork = $script:validatedRequests[0].Clone()
    $null = $missingNetwork.Remove('network')
    $missingNetwork.telemetry = @{ enabled = $false }
    $rejected = Invoke-ValidatedStateAware -Request $missingNetwork -DryRun
    $rejectionText = "$($rejected.Stdout)`n$($rejected.Stderr)"
    if ($rejected.ExitCode -eq 0 -or $rejectionText -notmatch 'malformed_request' -or
        $rejectionText -notmatch 'missing field .network.') {
        throw 'The missing-network counterfactual must be rejected by the real contract parser.'
    }
    Write-Host 'PASS: actual lifecycle requests pass real CLI/backend dry-run validation; missing-network control fails'
    foreach ($version in @('1.0.0', '1.1.0-alpha')) {
        $failureRequest = @{
            version = $version
            containment = 'bubblewrap'
            process = @{ commandLine = 'true' }
            telemetry = @{ enabled = $false }
        }
        $failureFile = Join-Path $scratch 'unsupported-backend.json'
        $failureRequest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $failureFile
        $failureOutput = & $WxcExec --debug $failureFile 2>&1
        if ($LASTEXITCODE -eq 0 -or
            ($failureOutput -join "`n") -notmatch 'unsupported_containment|backend_unavailable') {
            throw "Keyword failure scenario for $version did not reach backend dispatch: $failureOutput"
        }
    }
    Write-Host 'PASS: paired keyword failure scenarios reach real CLI/backend rejection without enabling telemetry'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
