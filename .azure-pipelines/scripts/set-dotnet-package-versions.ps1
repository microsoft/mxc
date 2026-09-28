param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectPath,

    [Parameter(Mandatory = $true)]
    [string]$BuildId
)

$ErrorActionPreference = 'Stop'

[xml]$project = Get-Content -LiteralPath $ProjectPath
$versionNode = $project.SelectSingleNode('/Project/PropertyGroup/Version')
if ($null -eq $versionNode) {
    throw "$ProjectPath does not define Version"
}

$version = $versionNode.InnerText.Trim()
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "$ProjectPath defines an empty Version"
}
if ([string]::IsNullOrWhiteSpace($BuildId)) {
    throw "BuildId is required"
}

$internalVersion = "$version-internal-build$BuildId"

Write-Host "##vso[task.setvariable variable=PackageVersion]$version"
Write-Host "##vso[task.setvariable variable=InternalPackageVersion]$internalVersion"
