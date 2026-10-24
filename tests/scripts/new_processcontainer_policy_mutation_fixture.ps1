# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Directory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Directory = [IO.Path]::GetFullPath($Directory)
if (Test-Path -LiteralPath $Directory) { throw 'Use a fresh fixture directory.' }
if (-not [IO.Path]::IsPathRooted($Directory) -or
    $Directory -eq [IO.Path]::GetPathRoot($Directory) -or
    $Directory -match '[\x00-\x1f"%!^&|<>]') {
    throw 'The fixture requires a literal absolute directory below a drive root.'
}
foreach ($name in @('', 'a', 'a\denied', 'b', 'b\denied', 'certs', 'ledger')) {
    New-Item -ItemType Directory -Path (Join-Path $Directory $name) | Out-Null
}
$acl = Get-Acl -LiteralPath $Directory
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent().User,
    [Security.AccessControl.FileSystemRights]::Modify,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow))
Set-Acl -LiteralPath $Directory -AclObject $acl
$utf8 = [Text.UTF8Encoding]::new($false)
foreach ($name in @('a', 'a\denied', 'b', 'b\denied')) {
    [IO.File]::WriteAllText((Join-Path $Directory "$name\seed.txt"), 'test sentinel', $utf8)
}
foreach ($index in 1..4) {
    [IO.File]::WriteAllText((Join-Path $Directory "certs\ca-$index.pem"), "ca-$index", $utf8)
}
[IO.File]::WriteAllText((Join-Path $Directory 'ledger\launches.txt'), '', $utf8)
[IO.File]::WriteAllText((Join-Path $Directory 'fixture.json'),
    (@{root=$Directory} | ConvertTo-Json), $utf8)
Write-Output "Fixture: $Directory\fixture.json"
Write-Output 'Requires a governed SDK creator with RW access to a, b and ledger, RO access to Windows and certs, and no access to a\denied and b\denied.'
Write-Output 'No administrative policy or process identity was changed.'
