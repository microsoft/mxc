#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}\.\d{2}$')]
    [string]$MonthId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int]$Patch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$yearFull = [int]($MonthId.Substring(0, 4))
$month = [int]($MonthId.Substring(5, 2))
if ($month -lt 1 -or $month -gt 12) {
    throw "MonthId '$MonthId' must contain a calendar month from 01 through 12."
}

$yearShort = $yearFull % 100
$packageId = 'Microsoft.Windows.AI.IsolationSession.SDK'
$strippedMonthId = $MonthId.Replace('.', '')
$monthUnderscore = $MonthId.Replace('.', '_')
$canonicalRelease = "$MonthId.$Patch"
$nugetVersion = "0.$strippedMonthId.$Patch"
$msiVersion = "$yearShort.$month.$Patch.0"

[pscustomobject][ordered]@{
    schema = 'mxc.isosession-release-contract/1'
    monthId = $MonthId
    monthUnderscore = $monthUnderscore
    patch = $Patch
    runtimeInstance = $MonthId
    canonicalRelease = $canonicalRelease
    packageId = $packageId
    nugetVersion = $nugetVersion
    nugetPackageFileName = "$packageId.$nugetVersion.nupkg"
    msiVersion = $msiVersion
    bundleVersion = $msiVersion
}
