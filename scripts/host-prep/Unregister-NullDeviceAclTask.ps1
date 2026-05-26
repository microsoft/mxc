<#
.SYNOPSIS
    Unregister the boot-trigger scheduled task created by
    `Register-NullDeviceAclTask.ps1`.

.DESCRIPTION
    Removes the `mxc-null-device-acl` scheduled task from the local
    task scheduler. The current `\Device\Null` SD is NOT reverted —
    Windows restores the kernel default SD on reboot, so the
    recommended recovery path is "reboot, then verify". Until reboot
    the tightened SD remains in effect.

    With `-RemoveLogs`, the log file used by
    `wxc-host-prep.exe prepare-null-device`
    (`%ProgramData%\mxc\null-device-acl.log` and rotated copies) is
    deleted as well. Other MXC log files are left alone.

.PARAMETER TaskName
    Name of the scheduled task to remove. Default
    `mxc-null-device-acl`.

.PARAMETER TaskPath
    Task Scheduler folder. Default `\` (root).

.PARAMETER RemoveLogs
    Also delete the null-device ACL log file(s) under
    `%ProgramData%\mxc\`.

.EXAMPLE
    PS C:\> .\Unregister-NullDeviceAclTask.ps1
    Removes the scheduled task. Logs untouched.

.EXAMPLE
    PS C:\> .\Unregister-NullDeviceAclTask.ps1 -RemoveLogs
    Removes the scheduled task and the null-device ACL log files.

.NOTES
    Requires elevation. After running, reboot to restore the kernel
    default `\Device\Null` SD.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $TaskName = 'mxc-null-device-acl',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $TaskPath = '\',

    [Parameter()]
    [switch] $RemoveLogs
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Unregister-NullDeviceAclTask.ps1 requires elevation. Re-launch from an elevated PowerShell session."
    }
}

Assert-Elevated

$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Host "Unregistered task $TaskPath$TaskName" -ForegroundColor Green
} else {
    Write-Host "Task $TaskPath$TaskName not found; nothing to remove." -ForegroundColor Yellow
}

if ($RemoveLogs) {
    $logDir = Join-Path $env:ProgramData 'mxc'
    if (Test-Path -LiteralPath $logDir -PathType Container) {
        $patterns = @('null-device-acl.log', 'null-device-acl.log.*')
        foreach ($pattern in $patterns) {
            Get-ChildItem -LiteralPath $logDir -Filter $pattern -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force
                    Write-Host "Removed $($_.FullName)" -ForegroundColor Yellow
                }
        }
    }
}

Write-Host "Reboot to restore the kernel-default \Device\Null SD." -ForegroundColor Cyan
