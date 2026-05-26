<#
.SYNOPSIS
    Register a boot-trigger scheduled task that hardens the security
    descriptor on `\Device\Null`.

.DESCRIPTION
    The Windows kernel resets the SD on `\Device\Null` to a default
    open value at every boot. The MXC AppContainer-based backends
    need a tighter SD that grants the well-known AppContainer SIDs
    (and `ALL RESTRICTED APPLICATION PACKAGES` in particular)
    read/write/execute on `\Device\Null` and labels it Low-IL via a
    mandatory integrity label. Without this, AppContainer processes
    that open `NUL` for stdin/stdout/stderr redirection fail with
    `ERROR_ACCESS_DENIED` partway through startup.

    This script registers a task named `mxc-null-device-acl` that
    runs once at boot under the SYSTEM account, invoking
    `wxc-host-prep.exe prepare-null-device --quiet`. The task is
    fired once at registration so the SD is applied immediately
    without waiting for reboot.

    Re-running the script replaces any pre-existing task with the
    same name.

.PARAMETER ExePath
    Full path to `wxc-host-prep.exe`. Defaults to a side-by-side
    lookup next to this script (`..\wxc-host-prep.exe`), falling
    back to the script directory itself.

.PARAMETER TaskName
    Name of the scheduled task. Default `mxc-null-device-acl`.

.PARAMETER TaskPath
    Task Scheduler folder. Default `\` (root).

.EXAMPLE
    PS C:\> .\Register-NullDeviceAclTask.ps1
    Registers the task using the default location of wxc-host-prep.exe.

.EXAMPLE
    PS C:\> .\Register-NullDeviceAclTask.ps1 -ExePath 'C:\Program Files\Mxc\wxc-host-prep.exe'
    Registers the task with an explicit binary path.

.NOTES
    Requires elevation. The script aborts with a clear message if
    not invoked as Administrator.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $ExePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $TaskName = 'mxc-null-device-acl',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $TaskPath = '\'
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Register-NullDeviceAclTask.ps1 requires elevation. Re-launch from an elevated PowerShell session."
    }
}

function Resolve-WxcHostPrepPath {
    param([string] $Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) {
            throw "Specified -ExePath does not exist: $Explicit"
        }
        return (Resolve-Path -LiteralPath $Explicit).ProviderPath
    }

    $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
    $candidates = @(
        Join-Path $scriptDir '..\wxc-host-prep.exe',
        Join-Path $scriptDir 'wxc-host-prep.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    throw "Could not locate wxc-host-prep.exe. Pass -ExePath explicitly."
}

Assert-Elevated

$exe = Resolve-WxcHostPrepPath -Explicit $ExePath
Write-Host "Using wxc-host-prep.exe at $exe" -ForegroundColor Cyan

# Remove any existing task with the same name (idempotent re-registration).
$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing task $TaskPath$TaskName" -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute $exe -Argument 'prepare-null-device --quiet'

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId 'S-1-5-18' `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::FromMinutes(1)) `
    -MultipleInstances IgnoreNew

$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description 'Reapplies the MXC-managed security descriptor on \Device\Null after each boot. See docs/host-prep.md.'

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $task | Out-Null
Write-Host "Registered task $TaskPath$TaskName" -ForegroundColor Green

# Fire the task once so the SD is applied without waiting for reboot.
Write-Host "Starting task to apply SD immediately..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath

Write-Host "Done. The task will rerun at every boot." -ForegroundColor Green
