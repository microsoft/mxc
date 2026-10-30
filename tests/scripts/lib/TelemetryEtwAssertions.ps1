# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Assert-TelemetryExecutionTrace {
    param(
        [Parameter(Mandatory)][string]$XmlText,
        [Parameter(Mandatory)][guid]$ProviderGuid,
        [Parameter(Mandatory)][object[]]$Invocations,
        [switch]$RequireLifecycles
    )

    if ($Invocations.Count -eq 0) { throw 'No executor invocations were recorded.' }
    $processIds = @($Invocations | ForEach-Object { [int]$_.ProcessId })
    if (@($processIds | Where-Object { $_ -le 0 }).Count -gt 0 -or
        @($processIds | Select-Object -Unique).Count -ne $Invocations.Count) {
        throw 'Each invocation must have a distinct positive executor PID.'
    }
    if ($RequireLifecycles) {
        foreach ($lifecycle in 1, 2) {
            $phases = @($Invocations | Where-Object { $_.Lifecycle -eq $lifecycle } | ForEach-Object Phase)
            if (($phases -join ',') -cne 'provision,start,exec,exec,stop,deprovision') {
                throw "Lifecycle $lifecycle did not complete provision/start/repeated-exec/stop/deprovision."
            }
        }
        if ($Invocations.Count -ne 12) { throw 'Expected exactly two complete lifecycles.' }
    }

    [xml]$trace = $XmlText
    $executionEvents = @(
        foreach ($event in $trace.SelectNodes("//*[local-name()='Event']")) {
            if ([string]$event.System.Provider.Guid -ne "{$ProviderGuid}" -and
                [string]$event.System.Provider.Guid -ne "$ProviderGuid") { continue }
            $task = [string]$event.RenderingInfo.Task
            if ($task -eq 'MXC.Execution') { throw 'The retired MXC.Execution event was emitted.' }
            if ($task -notin @('MXC.ExecutionStart', 'MXC.ExecutionEnd')) { continue }
            $fields = @{}
            foreach ($node in $event.SelectNodes("*[local-name()='EventData']/*[local-name()='Data']")) {
                $fields[$node.GetAttribute('Name')] = $node.InnerText
            }
            [pscustomobject]@{
                Task = $task
                ProcessId = [int]$event.System.Execution.ProcessID
                Timestamp = [DateTimeOffset]$event.System.TimeCreated.SystemTime
                Fields = $fields
            }
        }
    )
    $expectedFields = @(
        'PartA_PrivacyProduct', 'PartA_PrivacyDataCategory', 'PartA_PrivTags',
        'mxc.session_id', 'mxc.capture_denials', 'mxc.sandbox_kind', 'mxc.backend',
        'mxc.exit_code', 'mxc.outcome', 'mxc.duration_ms', 'mxc.failure_reason',
        'mxc.phase', '__TlgCV__'
    )
    $lifecycleSessions = @{}
    $lifecycleRoots = @{}
    foreach ($invocation in $Invocations) {
        $emitted = @($executionEvents | Where-Object { $_.ProcessId -eq $invocation.ProcessId })
        $starts = @($emitted | Where-Object { $_.Task -eq 'MXC.ExecutionStart' })
        $ends = @($emitted | Where-Object { $_.Task -eq 'MXC.ExecutionEnd' })
        if ($starts.Count -ne 1 -or $ends.Count -ne 1) {
            throw "Executor $($invocation.ProcessId) needs one Start/End pair; found $($starts.Count)/$($ends.Count)."
        }
        $startFields = $starts[0].Fields
        $endFields = $ends[0].Fields
        foreach ($field in $expectedFields) {
            if (-not $startFields.ContainsKey($field) -or -not $endFields.ContainsKey($field)) {
                throw "The execution pair is missing required field '$field'."
            }
        }
        if ($startFields.ContainsKey('mxc.host_app') -or $endFields.ContainsKey('mxc.host_app')) {
            throw 'ExecutionStart and ExecutionEnd must not include host application attribution.'
        }
        if ($startFields['mxc.outcome'] -cne 'started' -or
            $startFields['mxc.exit_code'] -ne '0' -or
            $startFields['mxc.duration_ms'] -ne '0' -or
            $startFields['mxc.failure_reason'] -ne '') {
            throw 'ExecutionStart did not preserve the documented result placeholders.'
        }
        if ($endFields['mxc.outcome'] -cnotin @('success', 'failure')) {
            throw 'ExecutionEnd did not report a terminal outcome.'
        }
        foreach ($mode in @($startFields['mxc.capture_denials'], $endFields['mxc.capture_denials'])) {
            if ($mode -cnotin @('enforce', 'deny-and-record', 'allow-and-record', 'not_applicable')) {
                throw 'The execution pair has an invalid denial-capture mode.'
            }
        }
        foreach ($field in @('mxc.session_id', 'mxc.capture_denials', 'mxc.backend', 'mxc.sandbox_kind', 'mxc.phase', '__TlgCV__')) {
            if ($startFields[$field] -cne $endFields[$field]) {
                throw "ExecutionStart and ExecutionEnd have different '$field' attribution."
            }
        }
        $sessionId = [guid]::Empty
        if (-not [guid]::TryParse($startFields['mxc.session_id'], [ref]$sessionId) -or
            $sessionId -eq [guid]::Empty) {
            throw 'The execution pair did not contain a valid random session ID.'
        }
        if ($starts[0].Timestamp -gt $ends[0].Timestamp) {
            throw 'ExecutionEnd preceded ExecutionStart.'
        }
        if ($RequireLifecycles) {
            if ($startFields['mxc.phase'] -cne $invocation.Phase -or
                $startFields['mxc.backend'] -cne 'isolation_session' -or
                $startFields['mxc.sandbox_kind'] -cne 'isolation_session' -or
                $startFields['mxc.capture_denials'] -cne 'not_applicable' -or
                $endFields['mxc.outcome'] -cne 'success' -or
                $endFields['mxc.exit_code'] -ne '0' -or
                $invocation.ExitCode -ne 0) {
                throw "Lifecycle executor $($invocation.ProcessId) has incorrect phase, backend, mode or outcome."
            }
            $root = ($startFields['__TlgCV__'] -split '\.')[0]
            if ([string]::IsNullOrWhiteSpace($root)) { throw 'Missing lifecycle correlation vector.' }
            $key = [string]$invocation.Lifecycle
            if ($lifecycleSessions.ContainsKey($key)) {
                if ($lifecycleSessions[$key] -ne $sessionId -or $lifecycleRoots[$key] -cne $root) {
                    throw "Session ID or correlation root changed within lifecycle $key."
                }
            } else {
                $lifecycleSessions[$key] = $sessionId
                $lifecycleRoots[$key] = $root
            }
        }
    }
    if ($RequireLifecycles -and
        ($lifecycleSessions['1'] -eq $lifecycleSessions['2'] -or
         $lifecycleRoots['1'] -ceq $lifecycleRoots['2'])) {
        throw 'The new lifecycle reused attribution from the cleaned-up lifecycle.'
    }
}
