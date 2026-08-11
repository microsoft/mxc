# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Prints the crates.io release closure of mxc_alpha_mxc_sdk, leaf-first.
#
# Two callers:
#   Package.Crates.Job.yml   at run time, to build the cargo package -p list
#   a developer               to regenerate crateOrder in Publish.CratesIo.Job.yml
#
#   pwsh scripts/ci/Get-CrateOrder.ps1 -Yaml

[CmdletBinding()]
param
(
    [string] $ManifestPath = 'src/Cargo.toml',

    # The crate whose dependency closure ships.  Everything reachable from it
    # is released; everything else in the workspace is internal.
    [string] $RootCrate = 'mxc_alpha_mxc_sdk',

    # Emits the YAML list body ready to paste under crateOrder.
    [switch] $Yaml
)

$ErrorActionPreference = 'Stop'

$metadata = cargo metadata --format-version 1 --no-deps --manifest-path $ManifestPath | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit $LASTEXITCODE" }

$members = @{}
foreach ($package in $metadata.packages) { $members[$package.name] = $package }

# A path dependency carrying a version is the one kind cargo rewrites into a
# registry dependency when it packages, so it is the one kind that has to be
# live on crates.io first.  A version-less path dependency is legal only as a
# dev-dependency, which cargo drops from the packaged manifest; as a normal
# dependency cargo refuses to package at all.  Neither constrains release
# order.
function Get-FirstPartyDependencies([string] $Name)
{
    $result = @()
    foreach ($dependency in $members[$Name].dependencies)
    {
        if ($dependency.path -and $members.ContainsKey($dependency.name) -and $dependency.req -and $dependency.req -ne '*')
        {
            $result += $dependency.name
        }
    }
    return $result | Sort-Object -Unique
}

$closure = [System.Collections.Generic.HashSet[string]]::new()
$pending = [System.Collections.Generic.Stack[string]]::new()
if (-not $members.ContainsKey($RootCrate)) { throw "root crate '$RootCrate' is not a member of $ManifestPath" }
$pending.Push($RootCrate)
while ($pending.Count -gt 0)
{
    $name = $pending.Pop()
    if (-not $closure.Add($name)) { continue }
    foreach ($dependency in Get-FirstPartyDependencies $name) { $pending.Push($dependency) }
}

$edges = @{}
foreach ($name in $closure) { $edges[$name] = @(Get-FirstPartyDependencies $name | Where-Object { $closure.Contains($_) }) }

# Kahn, emitting a whole ready batch at a time and sorting each batch
# ordinally, so the output is byte-stable across runs and agent cultures.
$order = @()
$remaining = [System.Collections.Generic.HashSet[string]]::new($closure)
while ($remaining.Count -gt 0)
{
    $ready = @($remaining | Where-Object { @($edges[$_] | Where-Object { $remaining.Contains($_) }).Count -eq 0 })
    if ($ready.Count -eq 0) { throw "dependency cycle among: $($remaining -join ', ')" }

    $ready = [string[]] $ready
    [Array]::Sort($ready, [System.StringComparer]::Ordinal)
    foreach ($name in $ready)
    {
        $order += $name
        $remaining.Remove($name) | Out-Null
    }
}

if ($Yaml)
{
    foreach ($name in $order) { "    - $name" }
}
else
{
    $order
}
