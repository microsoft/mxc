<#
.SYNOPSIS
    Removes the persistent allow ACEs added by
    Prepare-SystemDriveForAppContainer.ps1.

.DESCRIPTION
    Uses RemoveAccessRuleSpecific so only ACEs that exactly match the tuple
    we added (SID + rights mask + inheritance flags + propagation flags +
    Allow) are removed. ACEs for the same SIDs that were authored by
    something else (different rights or inheritance) are left untouched.

    Safe to run when the ACEs are already absent — no-op in that case.

.PARAMETER Path
    The path to revoke the ACE from. Defaults to $env:SystemDrive + '\'.

.EXAMPLE
    PS C:\> .\Unprepare-SystemDriveForAppContainer.ps1

.EXAMPLE
    PS C:\> .\Unprepare-SystemDriveForAppContainer.ps1 -WhatIf

.NOTES
    Must run elevated.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$Path = ($env:SystemDrive + '\')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run elevated. Re-run from an Administrator PowerShell prompt."
}

# Must match exactly what Prepare-* added.
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

    # RemoveAccessRuleSpecific is a no-op when no matching ACE exists.
    $acl.RemoveAccessRuleSpecific($rule)
    Write-Host ("  - {0,-45} ({1})" -f $t.Name, $t.Sid)
}

if ($PSCmdlet.ShouldProcess($Path, "Remove metadata-read ACEs for AppContainer groups")) {
    Set-Acl -LiteralPath $Path -AclObject $acl
    Write-Host "Done." -ForegroundColor Green
} else {
    Write-Host "(WhatIf) ACL changes not committed." -ForegroundColor Yellow
}
