# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# One-off guard against publishing non-alpha crates.  Throws unless every
# .crate in a directory starts with the literal prefix mxc-alpha-.  A bad
# publish cannot be undone: crates.io never lets a name or version be deleted
# or reused.  Delete this and its two call sites when the crates take their
# production names.
#
#   pwsh scripts/ci/Assert-CratePrefix.ps1 -CratesDir out/crates

[CmdletBinding()]
param
(
    # Not recursive: cargo writes the closure flat, and recursing would pick
    # up stale archives from earlier runs.
    [Parameter(Mandatory)]
    [string] $CratesDir,

    [string] $Prefix = 'mxc-alpha-'
)

$ErrorActionPreference = 'Stop'

# An empty directory would otherwise pass vacuously.
$crates = @(Get-ChildItem -Path $CratesDir -Filter '*.crate' -File | Sort-Object Name)
if ($crates.Count -eq 0)
{
    throw "no .crate files found in $CratesDir -- nothing to check, so the packaging step produced nothing or ran against the wrong directory"
}

# Ordinal so the verdict does not depend on the agent's culture.
$rejected = @()
foreach ($crate in $crates)
{
    if ($crate.Name.StartsWith($Prefix, [System.StringComparison]::Ordinal))
    {
        Write-Host "  ok      $($crate.Name)"
    }
    else
    {
        Write-Host "  REJECT  $($crate.Name)"
        $rejected += $crate.Name
    }
}

# Lists every offender, not just the first.
if ($rejected.Count -gt 0)
{
    Write-Host "##vso[task.logissue type=error]$($rejected.Count) of $($crates.Count) crates do not start with '$Prefix': $($rejected -join ', ')"
    throw "alpha prefix guard failed -- $($rejected.Count) of $($crates.Count) crates do not start with '$Prefix'; refusing to continue"
}

Write-Host "alpha prefix guard passed: all $($crates.Count) crates start with '$Prefix'"
