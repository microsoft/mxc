<#
.SYNOPSIS
    Grants the AppContainer "ALL APPLICATION PACKAGES" and "ALL RESTRICTED
    APPLICATION PACKAGES" groups the minimum rights needed to stat the
    system-drive root (e.g. C:\).

.DESCRIPTION
    AppContainers do not, by default, have any rights on the system-drive
    root, so calls like _stat("C:\\"), GetFileAttributesW("C:\\"),
    [System.IO.DirectoryInfo]::new("C:\\").GetAccessControl(), etc., fail
    with ERROR_ACCESS_DENIED inside an AppContainer process. That makes
    many common tools (cmd.exe, powershell.exe, pwsh.exe, node.exe) error
    out during startup.

    This script adds two persistent, non-inheriting allow ACEs to the
    system-drive root for the two well-known AppContainer groups:
        S-1-15-2-1  ALL APPLICATION PACKAGES
        S-1-15-2-2  ALL RESTRICTED APPLICATION PACKAGES

    The granted mask is metadata-only — no FILE_LIST_DIRECTORY, no
    FILE_READ_DATA, no write rights:
        FILE_READ_ATTRIBUTES  (0x00000080)
        FILE_READ_EA          (0x00000008)
        READ_CONTROL          (0x00020000)
        SYNCHRONIZE           (0x00100000)
        ----------------------------------
        total                 (0x00120088)

    The ACEs are applied to the system-drive root only (no inheritance),
    so descendant files and directories are unaffected.

    Re-running this script is safe: AddAccessRule merges into the existing
    ACE if one already exists for the same (SID, type, flags) tuple.

.PARAMETER Path
    The path to grant the ACE on. Defaults to $env:SystemDrive + '\'.

.EXAMPLE
    PS C:\> .\Prepare-SystemDriveForAppContainer.ps1
    Prepares C:\ (or whatever the system drive is) with default settings.

.EXAMPLE
    PS C:\> .\Prepare-SystemDriveForAppContainer.ps1 -WhatIf
    Prints what would change without committing.

.NOTES
    Must run elevated. To undo, see Unprepare-SystemDriveForAppContainer.ps1.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$Path = ($env:SystemDrive + '\')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Verify elevation explicitly (in addition to #Requires -RunAsAdministrator,
# which only fires when the script is invoked from a script file in some
# hosts). Failing here gives a clear message instead of a confusing ACL
# error 20 lines later.
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run elevated. Re-run from an Administrator PowerShell prompt."
}

# Metadata-only mask: FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE.
$rights = [System.Security.AccessControl.FileSystemRights]'ReadAttributes, ReadExtendedAttributes, ReadPermissions, Synchronize'

$trustees = @(
    @{ Name = 'ALL APPLICATION PACKAGES';            Sid = 'S-1-15-2-1' },
    @{ Name = 'ALL RESTRICTED APPLICATION PACKAGES'; Sid = 'S-1-15-2-2' }
)

Write-Host "Target path : $Path"
Write-Host ("Rights mask : {0} (0x{1:X8})" -f $rights, [uint32]$rights)

$acl = Get-Acl -LiteralPath $Path

foreach ($t in $trustees) {
    $sid = [System.Security.Principal.SecurityIdentifier]::new($t.Sid)

    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        $rights,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $acl.AddAccessRule($rule)
    Write-Host ("  + {0,-45} ({1})" -f $t.Name, $t.Sid)
}

if ($PSCmdlet.ShouldProcess($Path, "Add metadata-read ACEs for AppContainer groups")) {
    Set-Acl -LiteralPath $Path -AclObject $acl
    Write-Host "Done." -ForegroundColor Green
} else {
    Write-Host "(WhatIf) ACL changes not committed." -ForegroundColor Yellow
}
