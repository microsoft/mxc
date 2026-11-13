# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-NativeFixtureSecuritySnapshot {
    param([Parameter(Mandatory)][string[]]$Paths)

    $snapshot = @{}
    foreach ($path in $Paths) {
        $acl = Get-Acl -LiteralPath $path
        $snapshot[$path] = @{ Acl = $acl; Sddl = $acl.Sddl }
    }
    $snapshot
}

function Assert-NativeFixtureSecurity {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Snapshot
    )

    $changed = @()
    foreach ($entry in $Snapshot.GetEnumerator()) {
        if ((Get-Acl -LiteralPath $entry.Key).Sddl -cne $entry.Value.Sddl) {
            $changed += $entry.Key
            # Restore only the owned fixture before reporting the violation.
            $directory = [IO.DirectoryInfo]::new($entry.Key)
            $restore = [IO.FileSystemAclExtensions]::GetAccessControl($directory)
            $sections = [Security.AccessControl.AccessControlSections]::Access
            $sid = [Security.Principal.SecurityIdentifier]
            if ($restore.GetOwner($sid) -ne $entry.Value.Acl.GetOwner($sid)) {
                $sections = $sections -bor [Security.AccessControl.AccessControlSections]::Owner
            }
            if ($restore.GetGroup($sid) -ne $entry.Value.Acl.GetGroup($sid)) {
                $sections = $sections -bor [Security.AccessControl.AccessControlSections]::Group
            }
            $restore.SetSecurityDescriptorSddlForm($entry.Value.Sddl, $sections)
            [IO.FileSystemAclExtensions]::SetAccessControl($directory, $restore)
            if ((Get-Acl -LiteralPath $entry.Key).Sddl -cne $entry.Value.Sddl) {
                throw "$Name could not restore owned fixture security: $($entry.Key)"
            }
        }
    }
    if ($changed.Count) { throw "$Name changed fixture security descriptors: $($changed -join ', ')" }
}

function Invoke-NativeProcessContainer {
    param(
        [Parameter(Mandatory)][string]$WxcExec,
        [Parameter(Mandatory)][string]$ScratchRoot,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments,
        [scriptblock]$Observe,
        [hashtable]$Environment = @{},
        [string]$WorkingDirectory
    )
    $logPath = Join-Path $ScratchRoot "$Name.log"
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $WxcExec
    foreach ($argument in (@('--log-file', $logPath) + $Arguments)) {
        $info.ArgumentList.Add($argument)
    }

    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    foreach ($entry in $Environment.GetEnumerator()) { $info.Environment[$entry.Key] = $entry.Value }
    if ($WorkingDirectory) { $info.WorkingDirectory = $WorkingDirectory }
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($Observe) { & $Observe $process }
        $timedOut = -not $process.WaitForExit(45000)
        if ($timedOut) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) {
                throw "$Name timed out and executor PID $($process.Id) did not stop."
            }
        }
        $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
        if (-not $drain.Wait(5000)) {
            throw [TimeoutException]::new("$Name redirected output did not close within 5 seconds after executor exit. See $ScratchRoot.")
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Set-Content -LiteralPath (Join-Path $ScratchRoot "$Name.stdout.txt") -Value $stdout
        Set-Content -LiteralPath (Join-Path $ScratchRoot "$Name.stderr.txt") -Value $stderr
        if ($timedOut) { throw "$Name timed out. See $ScratchRoot." }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
            # The probe exits before the executor initializes its diagnostic file sink.
            Log = if ($Arguments -contains '--probe') { '' } else {
                Get-Content -LiteralPath $logPath -Raw
            }
        }
    } finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) {
                    throw "$Name executor PID $($process.Id) did not stop during cleanup."
                }
            }
        } finally {
            $process.Dispose()
        }
    }
}
