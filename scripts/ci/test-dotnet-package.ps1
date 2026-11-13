[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$root = Join-Path $tempRoot "dotnet-package-smoke-$([guid]::NewGuid())"
$feed = Join-Path $root 'feed'
$version = '0.0.0-package-smoke'
$originalFfiDir = $env:MXC_FFI_DIR

Push-Location (Join-Path $repoRoot 'sdk\dotnet')
try {
    $env:MXC_FFI_DIR = ''
    dotnet pack Microsoft.Mxc.Sdk -c $Configuration --no-restore -o $feed --nologo -p:PackageVersion=$version -p:MxcPackSingleRid=true
    if ($LASTEXITCODE -ne 0) { throw "Packing the SDK exited $LASTEXITCODE" }
    foreach ($framework in @('net8.0', 'net10.0')) {
        $consumer = Join-Path $root $framework
        New-Item -ItemType Directory -Force -Path $consumer | Out-Null
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$framework</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"@ | Set-Content (Join-Path $consumer 'Consumer.csproj')
        @'
using Microsoft.Mxc.Sdk.V1;

var support = MxcPlatform.GetPlatformSupport();
Console.WriteLine($"platform supported: {support.IsSupported}; reason: {support.Reason}");
foreach (var backend in MxcPlatform.GetAvailableBackends())
{
    Console.WriteLine($"backend: {backend.Backend}");
    Console.WriteLine($"capabilities: {string.Join(", ", backend.Capabilities)}");
    Console.WriteLine($"warnings: {string.Join(", ", backend.Warnings)}");
}
'@ | Set-Content (Join-Path $consumer 'Program.cs')
        $cache = Join-Path $root "cache-$framework"
        dotnet package add Microsoft.Mxc.Sdk --project $consumer --version $version --source $feed --package-directory $cache
        if ($LASTEXITCODE -ne 0) { throw "Restoring the $framework package consumer exited $LASTEXITCODE" }
        dotnet run --project $consumer -c Release --no-restore
        if ($LASTEXITCODE -ne 0) { throw "The $framework packed SDK consumer exited $LASTEXITCODE" }
        $expected = Join-Path $cache "microsoft.mxc.sdk\$version\lib\$framework\Microsoft.Mxc.Sdk.dll"
        $actual = Join-Path $consumer "bin\Release\$framework\Microsoft.Mxc.Sdk.dll"
        if ((Get-FileHash $expected).Hash -ne (Get-FileHash $actual).Hash) {
            throw "The $framework consumer did not use the matching SDK assembly."
        }
        Write-Host "$framework packed SDK discovery and assembly checks passed."
    }
}
finally {
    $env:MXC_FFI_DIR = $originalFfiDir
    Pop-Location
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
