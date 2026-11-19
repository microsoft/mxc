# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -Version 7.0
<#
.SYNOPSIS
    Manual-only offline functional regression for the real W365 runner entrypoint.
.DESCRIPTION
    Stages the runner with a controlled auth replacement and compiled fake executor.
    Never authenticates, reads a user cache, or contacts a service. Requires Windows.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scratch = Join-Path ([IO.Path]::GetTempPath()) "mxc-w365-runner-test-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path (Join-Path $scratch 'lib')
$passed = 0
$pool = '11111111-1111-1111-1111-111111111111'
$client = '22222222-2222-2222-2222-222222222222'
$owner = '33333333-3333-3333-3333-333333333333'
$command = '"C:\Program Files\sample.exe" "quoted argument" & not-an-implicit-shell \ trailing\'
$runner = Join-Path $scratch 'run_w365_command_manual.ps1'
$exe = Join-Path $scratch 'wxc-exec.exe'
$log = Join-Path $scratch 'events.jsonl'

function Assert([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Scenario([string] $Scenario, [string[]] $Extra = @(), [switch] $MissingCommand,
        [switch] $ExistingReceipt, [switch] $DefaultReceipt,
        [switch] $Config, [switch] $NoPool, [hashtable] $ConfigOverrides = @{}) {
    $receipt = Join-Path $scratch "$Scenario.json"
    if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log }
    if ($ExistingReceipt) { [IO.File]::WriteAllText($receipt, '{"state":"ReleaseAccepted"}') }
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
    foreach ($arg in @('-NoProfile', '-NonInteractive', '-File', $runner)) { $start.ArgumentList.Add($arg) }
    $parameters = [ordered]@{
        PoolId = $pool; TenantId = $pool; ClientId = $client; WxcExePath = $exe; ReceiptPath = $receipt
    }
    if ($NoPool) { $parameters.Remove('PoolId') }
    if ($DefaultReceipt) { $parameters.Remove('ReceiptPath') }
    if (-not $MissingCommand) { $parameters.CommandLine = $command }
    $configuration = @{}
    if ($Config) {
        $configPath = Join-Path $scratch 'config.json'
        $configuration = @{ tenantId = $pool; clientId = $client }
        if (-not $NoPool) { $configuration.poolId = $pool }
        foreach ($key in $ConfigOverrides.Keys) { $configuration[$key] = $ConfigOverrides[$key] }
        [IO.File]::WriteAllText($configPath, ($configuration | ConvertTo-Json -Compress))
        foreach ($key in @('PoolId', 'TenantId', 'ClientId')) { $parameters.Remove($key) }
        $parameters.ConfigPath = $configPath
    }
    for ($i = 0; $i -lt $Extra.Count; $i++) {
        $key = $Extra[$i].TrimStart('-')
        $value = if ($key -in @('ForceSignIn', 'Provision')) { $null } else { $Extra[++$i] }
        $parameters[$key] = $value
    }
    if ($parameters.Contains('ReceiptPath')) { $receipt = $parameters.ReceiptPath }
    foreach ($key in $parameters.Keys) {
        $start.ArgumentList.Add("-$key")
        if ($null -ne $parameters[$key]) { $start.ArgumentList.Add($parameters[$key]) }
    }
    $start.Environment['W365_MANUAL_FIXTURE_SCENARIO'] = $Scenario
    $start.Environment['W365_MANUAL_FIXTURE_LOG'] = $log
    $start.Environment['W365_MANUAL_FIXTURE_RECEIPT'] = $receipt
    $start.Environment['W365_MANUAL_FIXTURE_COMMAND'] = $command
    $start.Environment['TEMP'] = $scratch
    $start.Environment['TMP'] = $scratch
    $start.Environment['W365_MANUAL_FIXTURE_OPTIONAL_POOL'] = if ($NoPool) { '1' } else { '0' }
    $requestedPool = if ($parameters.Contains('PoolId')) { $parameters.PoolId }
        elseif ($configuration.ContainsKey('poolId')) { $configuration.poolId } else { '' }
    $selectedPool = if ($requestedPool) { $requestedPool } else { '55555555-5555-5555-5555-555555555555' }
    if ($parameters.Contains('SessionId') -and $parameters.SessionId -match '^w365:([^:]+):') { $selectedPool = $Matches[1] }
    $start.Environment['W365_MANUAL_FIXTURE_SELECTED_POOL'] = $selectedPool
    $start.Environment['W365_MANUAL_FIXTURE_REQUESTED_POOL'] = $requestedPool
    $graphEnvironment = if ($parameters.Contains('GraphEnvironment')) { $parameters.GraphEnvironment.ToLowerInvariant() }
        elseif ($configuration.ContainsKey('graphEnvironment')) { $configuration.graphEnvironment.ToLowerInvariant() } else { 'public' }
    $defaultResource = if ($graphEnvironment -eq 'public') { '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5' }
        else { '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' }
    $start.Environment['W365_MANUAL_FIXTURE_GRAPH_ENVIRONMENT'] = $graphEnvironment
    foreach ($name in @('ControlPlaneResource', 'DataPlaneResource')) {
        $key = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)
        $resource = if ($parameters.Contains($name)) { $parameters[$name] }
            elseif ($configuration.ContainsKey($key)) { $configuration[$key] } else { $defaultResource }
        $role = if ($name -eq 'ControlPlaneResource') { 'CP' } else { 'DP' }
        $start.Environment["W365_MANUAL_FIXTURE_${role}_RESOURCE"] = $resource
    }
    $start.Environment['W365A_CP_TOKEN'] = 'SYNTHETIC_SECRET_PARENT_CP'
    $start.Environment['W365A_DP_TOKEN'] = 'SYNTHETIC_SECRET_PARENT_DP'
    $start.Environment['W365A_GRAPH_TOKEN'] = 'SYNTHETIC_SECRET_PARENT_GRAPH'
    $start.Environment['W365A_GRAPH_ENVIRONMENT'] = 'invalid-inherited-environment'
    $start.Environment['W365A_INHERITED_TEST'] = 'must-be-removed'
    $start.Environment['MXC_W365_TEST_PORT'] = '1'
    $start.Environment['W365A_DP_SUFFIX'] = 'invalid inherited suffix'
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $process.StandardInput.Close()
        $prefix = ''
        if ($Scenario -eq 'large_output') {
            do {
                $line = $process.StandardOutput.ReadLineAsync()
                Assert ($line.Wait(15000)) 'Streaming output was delayed.'
                Assert ($null -ne $line.Result) 'No live guest output.'
                $prefix += $line.Result + "`n"
            } until ($line.Result -eq 'guest-output-first')
            Assert (-not $process.HasExited) 'Guest output was buffered until process completion.'
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        Assert ($process.WaitForExit(90000)) "Scenario $Scenario hung."
        Assert ([Threading.Tasks.Task]::WaitAll(@($stdout, $stderr), 5000)) "Scenario $Scenario output hung."
        $output = $prefix + $stdout.Result + $stderr.Result
        Assert (-not $output.Contains('synthetic-private-') -and -not $output.Contains('SYNTHETIC_SECRET')) 'Credential/body leaked to console.'
        $events = @(if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log | ForEach-Object { ConvertFrom-Json -InputObject $_ -AsHashtable }
        })
        $journal = if (Test-Path -LiteralPath $receipt) {
            $text = [IO.File]::ReadAllText($receipt)
            Assert (-not $text.Contains('synthetic-private-') -and -not $text.Contains('SYNTHETIC_SECRET') -and
                -not $text.Contains('guest-output-first') -and -not $text.Contains('sample.exe')) 'Secret, guest output, or command leaked to receipt.'
            ConvertFrom-Json -InputObject $text -AsHashtable
        } else { $null }
        if ($DefaultReceipt -and $output -match '(?m)^Token-free receipt: ([^\r\n]+)') { $receipt = $Matches[1] }
        return @{ Code = $process.ExitCode; Journal = $journal; Events = $events; Output = $output; Path = $receipt }
    } finally {
        if (-not $process.HasExited) { $process.Kill($true); $null = $process.WaitForExit(5000) }
        $process.Dispose()
    }
}

try {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'run_w365_command_manual.ps1') -Destination $runner
    foreach ($name in @('W365Common.ps1', 'W365Process.cs')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "lib\$name") -Destination (Join-Path $scratch "lib\$name")
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'lib\w365_manual_auth_fixture.py') -Destination (Join-Path $scratch 'lib\w365_auth.py')
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe /r:System.Web.Extensions.dll "/out:$exe" (Join-Path $PSScriptRoot 'lib\w365_manual_executor_fixture.cs')
    Assert ($LASTEXITCODE -eq 0) 'Could not compile offline executor fixture.'

    foreach ($case in @(
        @{ Name = 'missing_command'; Missing = $true; Extra = @() },
        @{ Name = 'bad_pool'; Extra = @('-PoolId', 'invalid') },
        @{ Name = 'bad_tenant'; Extra = @('-TenantId', 'invalid') },
        @{ Name = 'bad_client'; Extra = @('-ClientId', 'invalid') },
        @{ Name = 'bad_cp_resource'; Extra = @('-ControlPlaneResource', 'invalid') },
        @{ Name = 'bad_dp_resource'; Extra = @('-DataPlaneResource', 'invalid') },
        @{ Name = 'empty_cp_resource'; Extra = @('-ControlPlaneResource', '') },
        @{ Name = 'empty_dp_resource'; Extra = @('-DataPlaneResource', '') },
        @{ Name = 'bad_graph_environment'; Extra = @('-GraphEnvironment', 'invalid') },
        @{ Name = 'empty_pool'; Extra = @('-PoolId', '') },
        @{ Name = 'empty_command'; Extra = @('-CommandLine', ' ') },
        @{ Name = 'excessive_exec_timeout'; Extra = @('-TimeoutMs', '600001') },
        @{ Name = 'url_endpoint'; Extra = @('-ControlPlaneHost', 'https://control.example.invalid') },
        @{ Name = 'retired_suffix'; Extra = @('-DataPlaneSuffix', 'data.example.invalid') },
        @{ Name = 'empty_endpoint'; Extra = @('-ControlPlaneHost', '') },
        @{ Name = 'provision_with_command'; Extra = @('-Operation', 'Provision') },
        @{ Name = 'provision_with_id'; Missing = $true; Extra = @('-Operation', 'Provision', '-SessionId', "w365:${pool}:44444444-4444-4444-4444-444444444444") },
        @{ Name = 'provision_with_directory'; Missing = $true; Extra = @('-Operation', 'Provision', '-WorkingDirectory', 'C:\Windows') },
        @{ Name = 'provision_with_timeout'; Missing = $true; Extra = @('-Operation', 'Provision', '-TimeoutMs', '1000') },
        @{ Name = 'retired_provision_switch'; Missing = $true; Extra = @('-Provision') }
    )) {
        $result = Invoke-Scenario $case.Name -Extra $case.Extra -MissingCommand:($case['Missing'] -eq $true)
        Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0 -and $null -eq $result.Journal) "$($case.Name) failed to refuse locally."
        $passed++
    }
    $result = Invoke-Scenario 'preflight_failure'
    Assert ($result.Code -ne 0 -and @($result.Events | Where-Object { $_.operation -eq 'auth' }).Count -eq 0) 'Preflight must precede auth.'
    $passed++
    $result = Invoke-Scenario 'missing_environment_endpoints'
    Assert ($result.Code -eq 0 -and $result.Journal.sessionId) 'Discovery required legacy endpoint variables.'
    $passed++
    $result = Invoke-Scenario 'auth_failure'
    Assert ($result.Code -ne 0 -and $null -eq $result.Journal) 'Auth failure allocated or created a receipt.'
    $passed++
    foreach ($scenario in @('graph_auth_failure', 'graph_wrong_owner')) {
        $result = Invoke-Scenario $scenario -NoPool
        Assert ($result.Code -ne 0 -and $null -eq $result.Journal -and
            @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry }).Count -eq 0) 'Graph auth failure or identity mismatch reached allocation.'
        $passed++
    }
    $result = Invoke-Scenario 'auth_wrong_owner' -Extra @('-ExpectedUserObjectId', '44444444-4444-4444-4444-444444444444')
    Assert ($result.Code -ne 0 -and $null -eq $result.Journal -and
        @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry }).Count -eq 0) 'Wrong actual identity reached allocation.'
    $passed++
    $first = Invoke-Scenario 'auth_failure' -DefaultReceipt
    $second = Invoke-Scenario 'auth_failure' -DefaultReceipt
    Assert ($first.Path -ne $second.Path -and $first.Path.StartsWith([IO.Path]::GetTempPath()) -and
        $first.Output.Contains('mxc-w365-manual-') -and -not (Test-Path -LiteralPath $first.Path) -and
        -not (Test-Path -LiteralPath $second.Path)) 'Default receipt path was not fresh/printed or allocated before auth.'
    $passed++
    $result = Invoke-Scenario 'existing' -ExistingReceipt
    Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0 -and $result.Journal.state -eq 'ReleaseAccepted') 'Existing receipt was reused.'
    $passed++

    foreach ($scenario in @('success', 'native_defaults', 'service_default_timeout',
            'exec_nonzero', 'exec_negative', 'exec_timeout', 'checkout_error_id',
            'checkout_nonzero', 'readiness_failure', 'readiness_live', 'readiness_invalid',
            'primary_and_cleanup_failure', 'large_output', 'long_readiness', 'journal_write_failure')) {
        $extra = if ($scenario -eq 'native_defaults') { @('-ForceSignIn') }
            else { @('-WorkingDirectory', 'C:\existing guest path', '-ExpectedUserObjectId', $owner, '-ForceSignIn') }
        if ($scenario -eq 'service_default_timeout') { $extra += @('-TimeoutMs', '0') }
        $result = Invoke-Scenario $scenario -Extra $extra
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        $expected = if ($scenario -in @('checkout_error_id', 'checkout_nonzero')) { 'provision' }
            elseif ($scenario -in @('readiness_failure', 'readiness_live', 'readiness_invalid', 'primary_and_cleanup_failure', 'journal_write_failure')) { 'provision,start' }
            else { 'provision,start,exec' }
        Assert (($operations.operation -join ',') -ceq $expected) "Incorrect lifecycle sequence for $scenario."
        Assert (@($operations.pid | Select-Object -Unique).Count -eq $operations.Count) 'Lifecycle operations did not use independent child processes.'
        Assert (@($operations | Where-Object { $_.id -and $_.id -ne "w365:${pool}:44444444-4444-4444-4444-444444444444" }).Count -eq 0) 'Cleanup or command targeted another reservation.'
        $succeeded = $scenario -in @('success', 'environment_endpoints', 'native_defaults', 'service_default_timeout', 'large_output', 'long_readiness')
        Assert (($result.Code -eq 0) -eq $succeeded) "Wrong exit for $scenario. $($result.Output)"
        Assert ($result.Journal.remoteResetConfirmed -eq $false) 'Claimed remote reset.'
        $expectedAuthCount = if ($operations.operation -contains 'start') { 3 } else { 2 }
        Assert (@($result.Events | Where-Object { $_.operation -eq 'auth' -and $_.force }).Count -eq $expectedAuthCount) 'ForceSignIn not forwarded to each required resource.'
        if ($scenario -eq 'exec_nonzero') { Assert ($result.Code -eq 23 -and $result.Journal.nativeExecExitCode -eq 23) 'Command exit was not preserved.' }
        if ($scenario -eq 'exec_negative') { Assert ($result.Code -eq -1 -and $result.Journal.nativeExecExitCode -eq -1) 'Negative command exit was not preserved.' }
        if ($scenario -in @('native_defaults', 'service_default_timeout')) {
            $processRequest = @($operations | Where-Object { $_.operation -eq 'exec' })[0].request.process
            $expectedTimeout = if ($scenario -eq 'service_default_timeout') { 0 } else { 30000 }
            Assert ($processRequest.timeout -eq $expectedTimeout -and -not $processRequest.ContainsKey('env')) 'Native timeout/environment defaults changed.'
            if ($scenario -eq 'native_defaults') { Assert (-not $processRequest.ContainsKey('cwd')) 'Omitted guest working directory was defaulted locally.' }
        }
        if ($scenario -eq 'journal_write_failure') {
            Assert ($result.Output.Contains('Session NOT automatically released') -and $result.Code -ne 0) 'Journal failure hid the retained session or was reported as success.'
            [IO.File]::SetAttributes($result.Path, [IO.FileAttributes]::Normal)
            $passed++
            continue
        }
        if ($scenario -eq 'large_output') {
            Assert ($result.Output.Contains(('O' * 524288)) -and $result.Output.Contains(('E' * 524288))) 'Large output was not drained.'
            Assert (-not ([IO.File]::ReadAllText($result.Path)).Contains('guest_not_native')) 'Guest JSON was parsed into receipt.'
        }
        Assert (-not $result.Journal.releaseAccepted -and $result.Journal.sessionId -ceq $result.Journal.sandboxId) 'Run released the session or returned a raw service GUID.'
        if ($scenario -eq 'primary_and_cleanup_failure') {
            Assert ([bool]$result.Journal.primaryFailure) 'Primary failure was lost.'
            Assert ($result.Journal.operations[1].error.httpStatus -eq 403 -and
                $result.Journal.operations[1].error.clientRequestId -eq '44444444-4444-4444-4444-444444444444') 'Structured diagnostics lost.'
        }
        $passed++
    }
    foreach ($scenario in @('checkout_no_id', 'checkout_invalid', 'checkout_bad_id')) {
        $result = Invoke-Scenario $scenario
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        Assert ($result.Code -ne 0 -and ($operations.operation -join ',') -eq 'provision') 'Unknown checkout was retried or a fake cleanup ID used.'
        Assert ($result.Journal.reconciliationRequired -and -not $result.Journal.sandboxId) 'Missing ID was not recorded as uncertain.'
        $passed++
    }

    $id = "w365:${pool}:44444444-4444-4444-4444-444444444444"
    $provisioned = Invoke-Scenario 'provision_only' -MissingCommand -Config -Extra @('-Operation', 'Provision')
    $native = @($provisioned.Events | Where-Object { $_.ContainsKey('dry') })
    Assert ($provisioned.Code -eq 0 -and $native.Count -eq 2 -and
        ($native.operation -join ',') -ceq 'provision,provision' -and $native[0].dry -and -not $native[1].dry) 'Provision-only invoked readiness, execution, or release in preflight or live flow.'
    Assert ($provisioned.Journal.state -eq 'Completed' -and $provisioned.Journal.provisionInvocationCount -eq 1 -and
        $provisioned.Journal.sessionId -ceq $id -and $provisioned.Journal.sandboxId -ceq $id -and
        -not $provisioned.Journal.releaseAccepted -and $provisioned.Journal.apiVersion -eq '3.0' -and
        $provisioned.Journal.releaseApiVersion -eq '2.0' -and
        $provisioned.Output.Contains('readiness polling and execution were not requested')) 'Provision-only lost identity, reported readiness, or released the session.'
    $passed++
    $replay = Invoke-Scenario 'provision_only_replay' -MissingCommand -Extra @('-Operation', 'Provision', '-ReceiptPath', $provisioned.Path)
    Assert ($replay.Code -ne 0 -and $replay.Events.Count -eq 0) 'Provision-only replayed a checkout using an existing receipt.'
    $passed++
    $again = Invoke-Scenario 'provision_only_reuse' -Extra @('-SessionId', $id, '-ReceiptPath', $provisioned.Path)
    $operations = @($again.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
    Assert ($again.Code -eq 0 -and ($operations.operation -join ',') -ceq 'start,exec') 'Execution after provision-only allocated or failed.'
    $passed++
    $release = Invoke-Scenario 'provision_only_release' -MissingCommand -Extra @('-Operation', 'Release', '-SessionId', $id, '-ReceiptPath', $provisioned.Path)
    $operations = @($release.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
    Assert ($release.Code -eq 0 -and ($operations.operation -join ',') -ceq 'deprovision' -and
        $release.Journal.releaseAccepted -and -not $release.Journal.remoteResetConfirmed) 'Explicit release after provision-only failed or claimed reset.'
    $passed++
    foreach ($scenario in @('checkout_error_id', 'checkout_no_id')) {
        $result = Invoke-Scenario $scenario -MissingCommand -Extra @('-Operation', 'Provision', '-ReceiptPath', (Join-Path $scratch "provision-only-$scenario.json"))
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        Assert ($result.Code -ne 0 -and ($operations.operation -join ',') -ceq 'provision' -and
            $result.Journal.state -eq 'FailedOrUnknown' -and -not $result.Journal.releaseAccepted) 'Failed provision-only retried, ran another phase, or released.'
        Assert (($scenario -eq 'checkout_error_id' -and $result.Journal.sandboxId -ceq $id) -or
            ($scenario -eq 'checkout_no_id' -and -not $result.Journal.sandboxId)) 'Failed provision-only lost or fabricated a cleanup identity.'
        $passed++
    }
    $configured = Invoke-Scenario 'minimal_config' -Config
    Assert ($configured.Code -eq 0 -and $configured.Journal.sessionId -ceq $id) 'Minimal shared deployment config was not used.'
    $passed++
    foreach ($scenario in @('explicit_discovery_pool', 'routing_write_failure')) {
        $requestedPool = '66666666-6666-6666-6666-666666666666'
        $requestedId = "w365:${requestedPool}:44444444-4444-4444-4444-444444444444"
        $result = Invoke-Scenario $scenario -MissingCommand -Extra @('-Operation', 'Provision', '-PoolId', $requestedPool)
        Assert ($result.Journal.requestedPoolId -ceq $requestedPool -and $result.Journal.poolId -ceq $requestedPool -and
            $result.Journal.sessionId -ceq $requestedId) "Provision replaced or lost the selected pool identity. $($result.Output)"
        Assert (($result.Code -eq 0) -eq ($scenario -eq 'explicit_discovery_pool')) 'Routing publication failure was hidden.'
        $passed++
        if ($scenario -eq 'explicit_discovery_pool') {
            $reuse = Invoke-Scenario 'explicit_discovery_pool_reuse' -Extra @(
                '-PoolId', $requestedPool, '-SessionId', $requestedId, '-ReceiptPath', $result.Path)
            Assert ($reuse.Code -eq 0 -and $reuse.Journal.sessionId -ceq $requestedId) "Selected pool blocked reuse of the returned ID. $($reuse.Output)"
            $passed++
        }
    }
    $retired = Invoke-Scenario 'retired_endpoint_config' -Config -ConfigOverrides @{ controlPlaneHost = 'control.example.invalid' }
    Assert ($retired.Code -ne 0 -and $retired.Events.Count -eq 0) 'Retired endpoint config was accepted.'
    $passed++
    $first = Invoke-Scenario 'reusable'
    Assert ($first.Code -eq 0 -and $first.Journal.sessionId -ceq $id) 'Initial run did not return opaque identity.'
    $serviceAuth = @($first.Events | Where-Object { $_.operation -eq 'auth' -and $_.resource -eq 'service' })
    Assert ($first.Journal.controlPlaneResource -ceq '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5' -and
        $first.Journal.dataPlaneResource -ceq '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5' -and $serviceAuth.Count -eq 2 -and
        @($serviceAuth | Where-Object { $_.resourceId -cne '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5' -or $_.clientId -cne $client }).Count -eq 0) 'Public CP/DP authentication used the INT resource or changed the sign-in client.'
    $again = Invoke-Scenario 'reuse' -Extra @('-SessionId', $id, '-ReceiptPath', $first.Path)
    $operations = @($again.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
    Assert ($again.Code -eq 0 -and ($operations.operation -join ',') -ceq 'start,exec') 'Reuse allocated or failed.'
    $release = Invoke-Scenario 'explicit_release' -MissingCommand -Extra @('-Operation', 'Release', '-SessionId', $id, '-ReceiptPath', $first.Path)
    $operations = @($release.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
    Assert ($release.Code -eq 0 -and ($operations.operation -join ',') -ceq 'deprovision' -and
        $release.Journal.releaseAccepted -and -not $release.Journal.remoteResetConfirmed) 'Explicit release targeted wrong phase or claimed reset.'
    $afterRelease = Invoke-Scenario 'reuse_released' -Extra @('-SessionId', $id, '-ReceiptPath', $first.Path)
    Assert ($afterRelease.Code -ne 0 -and $afterRelease.Events.Count -eq 0) 'Released session was reused.'
    $passed += 4
    foreach ($scenario in @('receiptless_reuse', 'readiness_failure', 'exec_timeout')) {
        $result = Invoke-Scenario "reuse_$scenario" -Extra @('-SessionId', $id)
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        Assert (@($operations | Where-Object { $_.operation -in @('provision', 'deprovision') }).Count -eq 0) 'Reuse allocated or automatically released.'
        $passed++
    }
    foreach ($scenario in @('release_failure', 'release_invalid', 'receiptless_release')) {
        $result = Invoke-Scenario $scenario -MissingCommand -Extra @('-Operation', 'Release', '-SessionId', $id)
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        Assert (($operations.operation -join ',') -ceq 'deprovision') 'Receiptless release performed another operation.'
        Assert (($result.Code -eq 0) -eq ($scenario -eq 'receiptless_release')) 'Explicit release error was lost.'
        Assert ($result.Journal.sessionId -ceq $id) 'Release lost opaque ID.'
        if ($scenario -ne 'receiptless_release') {
            $retry = Invoke-Scenario "${scenario}_retry" -MissingCommand -Extra @('-Operation', 'Release', '-SessionId', $id, '-ReceiptPath', $result.Path)
            Assert ($retry.Code -ne 0 -and $retry.Events.Count -eq 0) 'Uncertain release was replayed.'
            $passed++
        }
        $passed++
    }
    foreach ($bad in @('44444444-4444-4444-4444-444444444444', 'w365:not-a-pool:44444444-4444-4444-4444-444444444444')) {
        $result = Invoke-Scenario ('bad_id_' + $passed) -Extra @('-SessionId', $bad)
        Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0) 'Invalid identity reached auth or native calls.'
        $passed++
    }

    $canary = Invoke-Scenario 'canary_resource_defaults' -Config -NoPool -ConfigOverrides @{ graphEnvironment = 'CaNaRy' }
    $serviceAuth = @($canary.Events | Where-Object { $_.operation -eq 'auth' -and $_.resource -eq 'service' })
    Assert ($canary.Code -eq 0 -and $canary.Journal.controlPlaneResource -ceq '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' -and
        $canary.Journal.dataPlaneResource -ceq '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' -and $serviceAuth.Count -eq 2 -and
        @($serviceAuth | Where-Object { $_.resourceId -cne '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' -or $_.clientId -cne $client }).Count -eq 0) "Canary config changed the working INT resource. $($canary.Output)"
    $passed++
    $overridden = Invoke-Scenario 'resource_overrides' -Config -NoPool -ConfigOverrides @{
        controlPlaneResource = '274133f7-12bb-4bfb-ae3b-bd446b7e8a75'
        dataPlaneResource = '66666666-6666-6666-6666-666666666666'
    } -Extra @('-DataPlaneResource', '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5')
    Assert ($overridden.Code -eq 0 -and $overridden.Journal.controlPlaneResource -ceq '274133f7-12bb-4bfb-ae3b-bd446b7e8a75' -and
        $overridden.Journal.dataPlaneResource -ceq '90ecec28-f5a6-42b3-9bde-dae1ca98f8b5') "Resource defaults overrode configuration or explicit parameters. $($overridden.Output)"
    $passed++
    $deployment = @('-GraphEnvironment', 'Canary', '-DataPlaneResource', '66666666-6666-6666-6666-666666666666')
    $automatic = Invoke-Scenario 'automatic_success' -NoPool -Extra $deployment
    $selectedPool = '55555555-5555-5555-5555-555555555555'
    $selectedId = "w365:${selectedPool}:44444444-4444-4444-4444-444444444444"
    Assert ($automatic.Code -eq 0 -and $automatic.Journal.poolId -ceq $selectedPool -and
        $null -eq $automatic.Journal.requestedPoolId -and $automatic.Journal.sessionId -ceq $selectedId -and
        $automatic.Journal.provisionInvocationCount -eq 1 -and -not $automatic.Journal.ContainsKey('allocationRequestCount')) "Automatic selection lost the actual pool or misreported allocation attempts. $($automatic.Output)"
    $graph = @($automatic.Events | Where-Object { $_.operation -eq 'auth' -and $_.resource -eq 'graph' })
    Assert ($graph.Count -eq 1 -and $graph[0].graphEnvironment -ceq 'canary') 'Provision did not acquire the selected Graph resource separately.'
    $passed++
    $reuse = Invoke-Scenario 'automatic_reuse' -NoPool -Extra ($deployment + @('-SessionId', $selectedId, '-ReceiptPath', $automatic.Path))
    $authEvents = @($reuse.Events | Where-Object { $_.operation -eq 'auth' })
    Assert ($reuse.Code -eq 0 -and $authEvents.Count -eq 1 -and $authEvents[0].resource -ceq 'service' -and
        $authEvents[0].resourceId -ceq '66666666-6666-6666-6666-666666666666') "Existing-ID execution required Graph/CP auth or another checkout. $($reuse.Output)"
    $passed++
    $release = Invoke-Scenario 'automatic_release' -NoPool -MissingCommand -Extra ($deployment + @(
        '-Operation', 'Release', '-SessionId', $selectedId, '-ReceiptPath', $automatic.Path))
    $authEvents = @($release.Events | Where-Object { $_.operation -eq 'auth' })
    Assert ($release.Code -eq 0 -and $release.Journal.releaseAccepted -and $authEvents.Count -eq 1 -and
        $authEvents[0].resource -ceq 'service' -and $authEvents[0].resourceId -ceq '274133f7-12bb-4bfb-ae3b-bd446b7e8a75') 'Release did not use only CP authentication and the returned opaque identity.'
    $passed++
    $configured = Invoke-Scenario 'automatic_config' -Config -NoPool -MissingCommand -Extra @('-Operation', 'Provision')
    Assert ($configured.Code -eq 0 -and $configured.Journal.poolId -ceq $selectedPool) "Minimal config still required pool/endpoints. $($configured.Output)"
    $passed++
    foreach ($scenario in @('automatic_routing_write_failure', 'automatic_checkout_no_id', 'automatic_checkout_invalid')) {
        $result = Invoke-Scenario $scenario -NoPool
        $operations = @($result.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
        Assert ($result.Code -ne 0 -and ($operations.operation -join ',') -ceq 'provision' -and
            $result.Journal.reconciliationRequired) 'Automatic selection replayed or hid an uncertain native provision.'
        if ($scenario -eq 'automatic_routing_write_failure') {
            Assert ($result.Journal.sessionId -ceq $selectedId -and $result.Journal.poolId -ceq $selectedPool -and
                $result.Journal.operations[0].error.controlPlaneHost -ceq 'recovery.example.invalid') 'Routing-write failure lost selected identity or recovery destination.'
        } else { Assert (-not $result.Journal.sessionId) 'Unknown checkout fabricated a selected identity.' }
        $passed++
    }
    $wrongOwner = Invoke-Scenario 'dp_wrong_owner' -NoPool -Extra $deployment
    $operations = @($wrongOwner.Events | Where-Object { $_.ContainsKey('dry') -and -not $_.dry })
    Assert ($wrongOwner.Code -ne 0 -and ($operations.operation -join ',') -ceq 'provision' -and
        $wrongOwner.Journal.sessionId -ceq $selectedId) 'DP identity mismatch submitted execution or lost the allocated ID.'
    $passed++

    Add-Type -Path (Join-Path $PSScriptRoot 'lib\W365Process.cs')
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.ArgumentList.Add('hang')
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $result = [Mxc.W365Manual.ChildProcess]::Run($start, 150, $false)
    Assert ($result.Failure -eq 'client_deadline_outcome_unknown' -and $clock.ElapsedMilliseconds -lt 7000) 'Local deadline/worker cleanup was unbounded or called remote termination.'
    $passed++
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.ArgumentList.Add('short')
    $result = [Mxc.W365Manual.ChildProcess]::Run($start, 0, $false)
    Assert ($null -eq $result.Failure -and $result.ExitCode -eq 0) 'Provision-style zero outer deadline immediately terminated the child.'
    $passed++
    . (Join-Path $scratch 'lib\W365Common.ps1')
    $savedEnvironment = @{}
    foreach ($key in @('W365_MANUAL_FIXTURE_SCENARIO', 'W365_MANUAL_FIXTURE_LOG')) {
        $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    }
    try {
        $env:W365_MANUAL_FIXTURE_SCENARIO = 'cleanup_refresh'
        $env:W365_MANUAL_FIXTURE_LOG = $log
        if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log }
        $fresh = Get-W365CleanupAuth @{ ExpiresOn = 0; Token = 'expired-synthetic'; UserObjectId = $owner } $pool $client ''
        Assert ($fresh.UserObjectId -eq $owner -and $fresh.Token -eq 'synthetic-private-computer-token') 'Cleanup did not renew the same identity.'
        $event = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($log)) -AsHashtable
        Assert ($event.silent -eq $true -and $event.force -eq $false) 'Cleanup renewal requested a browser or force sign-in.'
        $passed++
    } finally {
        foreach ($key in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], 'Process')
        }
    }
    Write-Host "$passed offline runner scenarios passed; no browser, user cache, or service calls."
} finally {
    Get-ChildItem -LiteralPath $scratch -File | ForEach-Object { [IO.File]::SetAttributes($_.FullName, [IO.FileAttributes]::Normal) }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
