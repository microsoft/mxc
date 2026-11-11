# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#requires -Version 7.0
<#
.SYNOPSIS
    Manual-only offline functional regression for the real W365 runner entrypoint.
.DESCRIPTION
    Stages the runner with a controlled auth replacement and compiled fake executor.
    Never authenticates, reads a user cache, or contacts a service. Not wired in CI.
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
        [switch] $ExistingReceipt, [switch] $EnvironmentEndpoints, [switch] $DefaultReceipt,
        [switch] $Config) {
    $receipt = Join-Path $scratch "$Scenario.json"
    if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log }
    if ($ExistingReceipt) { [IO.File]::WriteAllText($receipt, '{"state":"ReleaseAccepted"}') }
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
    foreach ($arg in @('-NoProfile', '-NonInteractive', '-File', $runner)) { $start.ArgumentList.Add($arg) }
    $parameters = [ordered]@{
        PoolId = $pool; TenantId = $pool; ClientId = $client; WxcExePath = $exe; ReceiptPath = $receipt
    }
    if ($DefaultReceipt) { $parameters.Remove('ReceiptPath') }
    if (-not $MissingCommand) { $parameters.CommandLine = $command }
    if (-not $EnvironmentEndpoints) {
        $parameters.ControlPlaneHost = 'control.example.invalid'
        $parameters.DataPlaneSuffix = 'data.example.invalid'
    }
    if ($Config) {
        $configPath = Join-Path $scratch 'config.json'
        [IO.File]::WriteAllText($configPath, (@{
            poolId = $pool; tenantId = $pool; clientId = $client
            controlPlaneHost = 'control.example.invalid'; dataPlaneSuffix = 'data.example.invalid'
        } | ConvertTo-Json -Compress))
        foreach ($key in @('PoolId', 'TenantId', 'ClientId', 'ControlPlaneHost', 'DataPlaneSuffix')) { $parameters.Remove($key) }
        $parameters.ConfigPath = $configPath
    }
    for ($i = 0; $i -lt $Extra.Count; $i++) {
        $key = $Extra[$i].TrimStart('-')
        $value = if ($key -eq 'ForceSignIn') { $null } else { $Extra[++$i] }
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
    $start.Environment['W365A_CP_TOKEN'] = 'SYNTHETIC_SECRET_PARENT_CP'
    $start.Environment['W365A_DP_TOKEN'] = 'SYNTHETIC_SECRET_PARENT_DP'
    $start.Environment['W365A_INHERITED_TEST'] = 'must-be-removed'
    $start.Environment['MXC_W365_TEST_PORT'] = '1'
    $start.Environment['W365A_CONTROLPLANE_URL'] = if ($EnvironmentEndpoints) { 'control.example.invalid' } else { 'invalid inherited URL' }
    $start.Environment['W365A_DP_SUFFIX'] = if ($EnvironmentEndpoints) { 'data.example.invalid' } else { 'invalid inherited suffix' }
    if ($Scenario -eq 'missing_environment_endpoints' -or $Config) {
        $null = $start.Environment.Remove('W365A_CONTROLPLANE_URL')
        $null = $start.Environment.Remove('W365A_DP_SUFFIX')
    }
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
        Assert (-not $output.Contains('synthetic-private-computer-token') -and -not $output.Contains('SYNTHETIC_SECRET')) 'Credential/body leaked to console.'
        $events = @(if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log | ForEach-Object { ConvertFrom-Json -InputObject $_ -AsHashtable }
        })
        $journal = if (Test-Path -LiteralPath $receipt) {
            $text = [IO.File]::ReadAllText($receipt)
            Assert (-not $text.Contains('synthetic-private-computer-token') -and -not $text.Contains('SYNTHETIC_SECRET') -and
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
        @{ Name = 'empty_command'; Extra = @('-CommandLine', ' ') },
        @{ Name = 'url_endpoint'; Extra = @('-ControlPlaneHost', 'https://control.example.invalid') },
        @{ Name = 'port_endpoint'; Extra = @('-DataPlaneSuffix', 'data.example.invalid:443') },
        @{ Name = 'empty_endpoint'; Extra = @('-ControlPlaneHost', '') },
        @{ Name = 'path_endpoint'; Extra = @('-DataPlaneSuffix', 'data.example.invalid/path') }
    )) {
        $result = Invoke-Scenario $case.Name -Extra $case.Extra -MissingCommand:($case['Missing'] -eq $true)
        Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0 -and $null -eq $result.Journal) "$($case.Name) failed to refuse locally."
        $passed++
    }
    $result = Invoke-Scenario 'preflight_failure'
    Assert ($result.Code -ne 0 -and @($result.Events | Where-Object { $_.operation -eq 'auth' }).Count -eq 0) 'Preflight must precede auth.'
    $passed++
    $result = Invoke-Scenario 'missing_environment_endpoints' -EnvironmentEndpoints
    Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0 -and $null -eq $result.Journal) 'Missing effective environment endpoints reached auth/executor.'
    $passed++
    $result = Invoke-Scenario 'auth_failure'
    Assert ($result.Code -ne 0 -and $null -eq $result.Journal) 'Auth failure allocated or created a receipt.'
    $passed++
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

    foreach ($scenario in @('success', 'environment_endpoints', 'native_defaults', 'service_default_timeout',
            'exec_nonzero', 'exec_negative', 'exec_timeout', 'checkout_error_id',
            'checkout_nonzero', 'readiness_failure', 'readiness_live', 'readiness_invalid',
            'primary_and_cleanup_failure', 'large_output', 'long_readiness', 'journal_write_failure')) {
        $extra = if ($scenario -eq 'native_defaults') { @('-ForceSignIn') }
            else { @('-WorkingDirectory', 'C:\existing guest path', '-ExpectedUserObjectId', $owner, '-ForceSignIn') }
        if ($scenario -eq 'service_default_timeout') { $extra += @('-TimeoutMs', '0') }
        $result = Invoke-Scenario $scenario -EnvironmentEndpoints:($scenario -eq 'environment_endpoints') -Extra $extra
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
        Assert (@($result.Events | Where-Object { $_.operation -eq 'auth' -and $_.force }).Count -eq 1) 'ForceSignIn not forwarded.'
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
    $configured = Invoke-Scenario 'minimal_config' -Config
    Assert ($configured.Code -eq 0 -and $configured.Journal.sessionId -ceq $id) 'Minimal shared deployment config was not used.'
    $passed++
    $first = Invoke-Scenario 'reusable'
    Assert ($first.Code -eq 0 -and $first.Journal.sessionId -ceq $id) 'Initial run did not return opaque identity.'
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
    foreach ($bad in @('44444444-4444-4444-4444-444444444444', "w365:${client}:44444444-4444-4444-4444-444444444444")) {
        $result = Invoke-Scenario ('bad_id_' + $passed) -Extra @('-SessionId', $bad)
        Assert ($result.Code -ne 0 -and $result.Events.Count -eq 0) 'Invalid identity reached auth or native calls.'
        $passed++
    }

    Add-Type -Path (Join-Path $PSScriptRoot 'lib\W365Process.cs')
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.ArgumentList.Add('hang')
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $result = [Mxc.W365Manual.ChildProcess]::Run($start, 150, $false)
    Assert ($result.Failure -eq 'client_deadline_outcome_unknown' -and $clock.ElapsedMilliseconds -lt 7000) 'Local deadline/worker cleanup was unbounded or called remote termination.'
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
