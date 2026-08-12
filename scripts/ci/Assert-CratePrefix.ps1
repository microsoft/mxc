# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# TEMPORARY ALPHA GUARD -- DELETE THIS SCRIPT BEFORE PRODUCTION.
#
# Throws if any .crate in a directory does not start with the literal prefix
# mxc-alpha-.  A single wrong name fails the caller, which fails its job,
# which fails the stage and stops the pipeline.  Nothing is published and no
# artifact is produced.
#
# The test is an exact, case-sensitive, literal prefix match.  It is not a
# pattern match: mxc_alpha_ with underscores does NOT satisfy it, even though
# crates.io would treat the two spellings as the same name.  Every crate in
# the closure declares the hyphenated form, so a rejection means the packaging
# job ran against a commit that predates that rename.
#
# Publishing the wrong name is unrecoverable: crates.io does not allow a name
# or a version to be deleted or reused, so a bad publish cannot be corrected
# afterwards or redone under the right name.  That is why this is a
# precondition rather than a post-publish assertion.
#
# Runnable by hand from the repo root to reproduce what the pipeline checks:
#
#   pwsh scripts/ci/Assert-CratePrefix.ps1 -CratesDir out/crates
#
# WHY IT GOES AWAY: it encodes the alpha naming scheme, which is a property of
# this pre-release period and not of the release process.  Once the crates
# graduate to their production names this script rejects every correct name,
# so delete it -- and its two call sites -- in the same change that renames
# them.  Do not soften it into a warning, and do not parameterize it into
# something that looks permanent.

[CmdletBinding()]
param
(
    # Directory holding the .crate files to check.  Not recursive: cargo
    # writes the closure flat, and recursing would pick up stale archives
    # left in nested target directories by earlier runs.
    [Parameter(Mandatory)]
    [string] $CratesDir,

    [string] $Prefix = 'mxc-alpha-'
)

$ErrorActionPreference = 'Stop'

# An empty directory would otherwise pass vacuously, reporting success for a
# publish that has nothing to publish.
$crates = @(Get-ChildItem -Path $CratesDir -Filter '*.crate' -File | Sort-Object Name)
if ($crates.Count -eq 0)
{
    throw "no .crate files found in $CratesDir -- nothing to check, so the packaging step produced nothing or ran against the wrong directory"
}

# Ordinal, matching the comparison Get-CrateOrder.ps1 uses, so the verdict
# does not depend on the agent's culture.
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

# Every offender is listed rather than just the first, so one run names all
# the crates still needing the rename instead of surfacing them one per build.
if ($rejected.Count -gt 0)
{
    Write-Host "##vso[task.logissue type=error]$($rejected.Count) of $($crates.Count) crates do not start with '$Prefix': $($rejected -join ', ')"
    throw "alpha prefix guard failed -- $($rejected.Count) of $($crates.Count) crates do not start with '$Prefix'; refusing to continue"
}

Write-Host "alpha prefix guard passed: all $($crates.Count) crates start with '$Prefix'"
