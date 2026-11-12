[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$NvxOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$tempDirectory = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($tempRoot))
for ($ancestor = $tempDirectory; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
    if ((Test-Path -LiteralPath (Join-Path $ancestor.FullName '.git') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $ancestor.FullName 'src\Cargo.toml') -PathType Leaf)) {
        throw "Package smoke temporary directory must be outside a checkout: $tempRoot"
    }
}
$root = Join-Path $tempRoot "dotnet-package-smoke-$([guid]::NewGuid())"
$feed = Join-Path $root 'feed'
$version = '0.0.0-package-smoke'
$originalFfiDir = $env:MXC_FFI_DIR
$originalAgentDir = $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR
$originalLocalAppData = $env:LOCALAPPDATA

Push-Location (Join-Path $repoRoot 'sdk\dotnet')
try {
    $env:MXC_FFI_DIR = ''
    $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR = ''
    if (-not $NvxOnly) {
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

var expectMissing = Environment.GetEnvironmentVariable("MXC_TEST_EXPECT_MISSING_NATIVE") == "1";
try
{
    var support = MxcPlatform.GetPlatformSupport();
    Console.WriteLine($"platform supported: {support.IsSupported}; reason: {support.Reason}");
    foreach (var backend in MxcPlatform.GetAvailableBackends())
    {
        Console.WriteLine($"backend: {backend.Backend}");
        Console.WriteLine($"capabilities: {string.Join(", ", backend.Capabilities)}");
        Console.WriteLine($"warnings: {string.Join(", ", backend.Warnings)}");
    }
}
catch (DllNotFoundException) when (expectMissing)
{
    Console.WriteLine("Missing native library rejected.");
    return 0;
}
if (expectMissing)
{
    Console.Error.WriteLine("Missing native library was unexpectedly loaded.");
    return 1;
}
return 0;
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

            $nativeName = if ($IsWindows) { 'mxc_ffi.dll' } elseif ($IsMacOS) { 'libmxc_ffi.dylib' } else { 'libmxc_ffi.so' }
            $nativeFiles = @(Get-ChildItem -LiteralPath (Join-Path $consumer 'bin'), $cache -Filter $nativeName -File -Recurse)
            if ($nativeFiles.Count -eq 0) { throw "No packaged $nativeName found for the missing-native test." }
            $nativeFiles | Remove-Item -Force
            $originalMissing = $env:MXC_TEST_EXPECT_MISSING_NATIVE
            try {
                $env:MXC_TEST_EXPECT_MISSING_NATIVE = '1'
                $output = & dotnet (Join-Path $consumer "bin\Release\$framework\Consumer.dll") 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0 -or $output -notmatch 'Missing native library rejected\.') {
                    throw "$framework consumer did not reject a missing native library: $output"
                }
            } finally {
                $env:MXC_TEST_EXPECT_MISSING_NATIVE = $originalMissing
            }
            Write-Host "$framework missing packaged native library was rejected."
        }
    }

    if ($IsWindows -and [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'X64') {
        $nvx = Join-Path $root 'nvx'
        . (Join-Path $repoRoot '.azure-pipelines\scripts\get-nvx-bundle-inventory.ps1')
        $files = @(Get-NvxBundleInventory) + @('guest/deep/provenance.txt')
        foreach ($file in $files) {
            $path = Join-Path $nvx $file
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            [IO.File]::WriteAllText($path, "synthetic $file")
        }
        New-Item -ItemType Directory -Force -Path $feed | Out-Null
        if ($NvxOnly) {
            $stub = Join-Path $root 'stub'
            New-Item -ItemType Directory -Force -Path (Join-Path $stub 'lib/net8.0') | Out-Null
            [IO.File]::WriteAllText((Join-Path $stub 'lib/net8.0/_._'), '')
            @"
<?xml version="1.0"?><package><metadata><id>Microsoft.Mxc.Sdk</id><version>$version</version><authors>Microsoft</authors><description>Test stub</description></metadata><files><file src="lib\**" target="lib" /></files></package>
"@ | Set-Content (Join-Path $stub 'Microsoft.Mxc.Sdk.nuspec')
            nuget pack (Join-Path $stub 'Microsoft.Mxc.Sdk.nuspec') -OutputDirectory $feed -NonInteractive
            if ($LASTEXITCODE -ne 0) { throw 'Synthetic base package failed.' }
        }
        $nuspec = Join-Path $repoRoot 'sdk/dotnet/Microsoft.Mxc.Sdk.Nvx.Runtime.Package/Microsoft.Mxc.Sdk.Nvx.Runtime.nuspec'
        nuget pack $nuspec -OutputDirectory $feed -NonInteractive -Properties "version=$version;nvxRuntime=$nvx;repositoryRoot=$repoRoot"
        if ($LASTEXITCODE -ne 0) { throw 'Packing the NVX runtime failed.' }
        $package = Join-Path $feed "Microsoft.Mxc.Sdk.Nvx.Runtime.$version.nupkg"
        $verify = Join-Path $repoRoot '.azure-pipelines/scripts/verify-dotnet-nuget-package.ps1'
        & $verify -PackagePath $package -VerifyNvxRuntime
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        foreach ($mutation in @('missing', 'stray')) {
            $bad = Join-Path $root "$mutation.nupkg"
            Copy-Item $package $bad
            $zip = [IO.Compression.ZipFile]::Open($bad, [IO.Compression.ZipArchiveMode]::Update)
            try {
                if ($mutation -eq 'missing') { $zip.GetEntry('runtimes/win-x64/aci-edge-sandboxes/guest/vmlinux.config').Delete() }
                else { [void]$zip.CreateEntry('runtimes/win-x64/aci-edge-sandboxes/bin/mxc_ffi.dll') }
            } finally { $zip.Dispose() }
            $rejected = $false
            try { & $verify -PackagePath $bad -VerifyNvxRuntime } catch {
                if ($mutation -eq 'missing' -and $_.Exception.Message -notmatch 'guest/vmlinux\.config') { throw }
                $rejected = $true
            }
            if (-not $rejected) { throw "Verifier accepted $mutation package." }
        }
        foreach ($framework in @('net8.0', 'net10.0')) {
            $consumer = Join-Path $root "nvx-$framework"
            New-Item -ItemType Directory -Force -Path $consumer | Out-Null
            @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Microsoft.Mxc.Sdk.Nvx.Runtime" Version="$version" /></ItemGroup>
</Project>
"@ | Set-Content (Join-Path $consumer 'Consumer.csproj')
            $project = Join-Path $consumer 'Consumer.csproj'
            dotnet restore $project --source $feed --packages (Join-Path $root 'nvx-cache') --nologo -p:NuGetAudit=false
            if ($LASTEXITCODE -ne 0) { throw "$framework NVX consumer restore failed." }
            dotnet build $project -c Release --no-restore --nologo
            if ($LASTEXITCODE -ne 0) { throw "$framework NVX consumer build failed." }
            $publish = Join-Path $consumer 'publish'
            dotnet publish $project -c Release --no-restore --nologo -o $publish
            if ($LASTEXITCODE -ne 0) { throw "$framework NVX consumer publish failed." }
            foreach ($output in @((Join-Path $consumer "bin/Release/$framework"), $publish)) {
                foreach ($file in $files) {
                    $actual = Join-Path $output "aci-edge-sandboxes/$file"
                    if (-not (Test-Path -LiteralPath $actual -PathType Leaf)) { throw "Missing $actual" }
                    if ((Get-FileHash $actual).Hash -ne (Get-FileHash (Join-Path $nvx $file)).Hash) { throw "Content mismatch: $actual" }
                }
            }
            foreach ($rid in @('win-x64', 'win10-x64')) {
                [string[]]$ridGraph = if ($rid -eq 'win10-x64') { @('-p:UseRidGraph=true') } else { @() }
                dotnet restore $project --source $feed --packages (Join-Path $root 'nvx-cache') --nologo -p:NuGetAudit=false "-p:RuntimeIdentifier=$rid" @ridGraph
                if ($LASTEXITCODE -ne 0) { throw "$framework $rid NVX restore failed." }
                dotnet build $project -c Release --no-restore --nologo "-p:RuntimeIdentifier=$rid" @ridGraph
                if ($LASTEXITCODE -ne 0) { throw "$framework $rid NVX build failed." }
                $ridPublish = Join-Path $consumer "publish-$rid"
                dotnet publish $project -c Release --no-restore --nologo -o $ridPublish "-p:RuntimeIdentifier=$rid" @ridGraph
                if ($LASTEXITCODE -ne 0) { throw "$framework $rid NVX publish failed." }
                foreach ($output in @((Join-Path $consumer "bin/Release/$framework/$rid"), $ridPublish)) {
                    foreach ($file in $files) {
                        $actual = Join-Path $output "aci-edge-sandboxes/$file"
                        if (-not (Test-Path -LiteralPath $actual -PathType Leaf)) { throw "Missing RID output: $actual" }
                        if ((Get-FileHash $actual).Hash -ne (Get-FileHash (Join-Path $nvx $file)).Hash) { throw "Content mismatch: $actual" }
                    }
                }
            }
            $errorOutput = & dotnet build $project -c Release --no-restore --nologo -p:RuntimeIdentifier=win-arm64 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $errorOutput -notmatch 'supports only the win-x64 or win10-x64 RuntimeIdentifier') { throw "Unsupported RID was not rejected by NVX target: $errorOutput" }
            $errorOutput = & dotnet build $project -c Release --no-restore --nologo -p:PlatformTarget=x86 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $errorOutput -notmatch 'requires an x64 or AnyCPU PlatformTarget') { throw "Unsupported platform was not rejected by NVX target: $errorOutput" }
            Write-Host "$framework NVX package build, publish and negative platform checks passed."
        }
        $library = Join-Path $root 'nvx-transitive-lib'
        $application = Join-Path $root 'nvx-transitive-app'
        New-Item -ItemType Directory -Force -Path $library, $application | Out-Null
        @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Microsoft.Mxc.Sdk.Nvx.Runtime" Version="$version" /></ItemGroup></Project>
"@ | Set-Content (Join-Path $library 'Library.csproj')
        @"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="../nvx-transitive-lib/Library.csproj" /></ItemGroup></Project>
"@ | Set-Content (Join-Path $application 'Application.csproj')
        $applicationProject = Join-Path $application 'Application.csproj'
        dotnet restore $applicationProject --source $feed --packages (Join-Path $root 'nvx-cache') --nologo -p:NuGetAudit=false
        if ($LASTEXITCODE -ne 0) { throw 'Transitive NVX consumer restore failed.' }
        dotnet build $applicationProject -c Release --no-restore --nologo
        if ($LASTEXITCODE -ne 0) { throw 'Transitive NVX consumer build failed.' }
        $nested = Join-Path $application 'bin/Release/net10.0/aci-edge-sandboxes/guest/deep/provenance.txt'
        if (-not (Test-Path -LiteralPath $nested -PathType Leaf)) { throw "Missing transitive NVX output: $nested" }
        Write-Host 'Transitive NVX package copy passed.'

        # Use real packages and a fresh process to prove module-relative discovery.
        $realFeed = Join-Path $root 'real-feed'
        New-Item -ItemType Directory -Force -Path $realFeed | Out-Null
        $nativeTarget = Join-Path $repoRoot 'src\target'
        $nativeDir = Join-Path $nativeTarget 'x86_64-pc-windows-msvc\debug'
        Push-Location (Join-Path $repoRoot 'src')
        try {
            cargo build -p mxc_ffi --features 'dotnetsdk,mxc-sdk/microvm' --target x86_64-pc-windows-msvc --target-dir $nativeTarget
            if ($LASTEXITCODE -ne 0) { throw 'Building the real NVX-enabled mxc_ffi.dll failed.' }
        } finally { Pop-Location }
        $realRuntime = Join-Path $nativeDir 'aci-edge-sandboxes'
        foreach ($file in (Join-Path $nativeDir 'mxc_ffi.dll'), (Join-Path $realRuntime 'bundle-manifest.json'), (Join-Path $realRuntime 'bin\aci_edge_agent.dll')) {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing real NVX test asset: $file" }
        }
        dotnet pack Microsoft.Mxc.Sdk -c $Configuration --no-restore -o $realFeed --nologo "-p:PackageVersion=$version" -p:MxcPackSingleRid=true "-p:MxcPrebuiltNativeDir=$nativeDir"
        if ($LASTEXITCODE -ne 0) { throw 'Packing the real base SDK failed.' }
        nuget pack $nuspec -OutputDirectory $realFeed -NonInteractive -Properties "version=$version;nvxRuntime=$realRuntime;repositoryRoot=$repoRoot"
        if ($LASTEXITCODE -ne 0) { throw 'Packing the real NVX runtime failed.' }
        $realConsumer = Join-Path $root 'real-nvx-consumer'
        New-Item -ItemType Directory -Force -Path $realConsumer | Out-Null
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RuntimeIdentifier>win-x64</RuntimeIdentifier><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>
  <ItemGroup><PackageReference Include="Microsoft.Mxc.Sdk.Nvx.Runtime" Version="$version" /></ItemGroup>
</Project>
"@ | Set-Content (Join-Path $realConsumer 'Consumer.csproj')
        @'
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MXC_FFI_DIR")) ||
    !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR")))
    throw new Exception("Native discovery overrides must be empty.");
var mode = args[0];
var support = MxcPlatform.GetPlatformSupport();
var backends = MxcPlatform.GetAvailableBackends();
var native = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
    .Single(module => string.Equals(module.ModuleName, "mxc_ffi.dll", StringComparison.OrdinalIgnoreCase));
if (!Path.GetFullPath(native.FileName).StartsWith(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase))
    throw new Exception("The consumer did not load its packaged mxc_ffi.dll.");
var bundle = Path.Combine(AppContext.BaseDirectory, "aci-edge-sandboxes");
if (Directory.Exists(bundle) != (mode != "absent"))
    throw new Exception($"Unexpected packaged runtime directory for {mode}.");
var detectedWhp = false;
try { detectedWhp = Hypervisor.Present(); } catch (DllNotFoundException) { } catch (EntryPointNotFoundException) { }
var simulatedNoWhp = args.Contains("simulate-no-whp");
var whp = detectedWhp && !simulatedNoWhp;
var found = backends.Any(backend => backend.Backend == ContainmentBackend.MicroVm);
if (mode == "absent" && found)
    throw new Exception("Base-only consumer unexpectedly reported MicroVM.");
if (mode == "present" && whp && !found)
    throw new Exception("The real packaged runtime was not discovered on a WHP host.");
const string request = """{"version":"1.1.0-alpha","phase":"provision","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"}}""";
MxcException? failure = null;
try { Dev.MxcLifecycle.ValidateProvisionJson(request, new Dev.JsonOptions { Experimental = true }); }
catch (MxcException error) { failure = error; }
if (mode == "absent")
{
    if (failure is null || failure.Code != ErrorCode.BackendUnavailable ||
        !failure.Message.Contains("no agent bundle is beside", StringComparison.OrdinalIgnoreCase))
        throw new Exception($"Base-only validation did not report a missing bundle: {failure}");
}
else if (mode == "synthetic")
{
    if (failure is null || failure.Code != ErrorCode.BackendUnavailable ||
        !failure.Message.Contains("signature rejected", StringComparison.OrdinalIgnoreCase) ||
        !failure.Message.Contains(Path.Combine(bundle, "bin", "aci_edge_agent.dll"), StringComparison.OrdinalIgnoreCase))
        throw new Exception($"Synthetic validation did not reach signature verification of the packaged bundle: {failure}");
}
else if (failure is not null)
{
    if (failure.Code != ErrorCode.BackendUnavailable ||
        failure.Message.Contains("no agent bundle", StringComparison.OrdinalIgnoreCase) ||
        failure.Message.Contains("bundle is missing", StringComparison.OrdinalIgnoreCase) ||
        failure.Message.Contains("signature rejected", StringComparison.OrdinalIgnoreCase) ||
        !(failure.Message.Contains("hypervisor", StringComparison.OrdinalIgnoreCase) ||
          failure.Message.Contains("capabilit", StringComparison.OrdinalIgnoreCase) ||
          failure.Message.Contains("WHP", StringComparison.OrdinalIgnoreCase)))
        throw new Exception($"Real packaged runtime failed before capability validation: {failure}");
}
Console.WriteLine($"Native discovery asserted: mode={mode}, supported={support.IsSupported}, hypervisor={detectedWhp}, simulatedNoWhp={simulatedNoWhp}, microvm={found}, validation={(failure is null ? "success" : failure.Message)}");

static class Hypervisor
{
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("WinHvPlatform.dll", ExactSpelling = true)]
    private static extern int WHvGetCapability(uint code, out int value, uint size, out uint written);
    internal static bool Present() => WHvGetCapability(0, out var value, sizeof(int), out var written) >= 0 && written == sizeof(int) && value != 0;
}
'@ | Set-Content (Join-Path $realConsumer 'Program.cs')
        $realProject = Join-Path $realConsumer 'Consumer.csproj'
        dotnet restore $realProject --source $realFeed --packages (Join-Path $root 'real-cache') --nologo -p:NuGetAudit=false
        if ($LASTEXITCODE -ne 0) { throw 'Restoring the real packaged NVX consumer failed.' }
        $realPublish = Join-Path $realConsumer 'publish'
        dotnet publish $realProject -c Release --no-restore --self-contained false --nologo -o $realPublish
        if ($LASTEXITCODE -ne 0) { throw 'Publishing the real packaged NVX consumer failed.' }
        $realExe = Join-Path $realPublish 'Consumer.exe'
        $publishedRuntime = Join-Path $realPublish 'aci-edge-sandboxes'
        if (-not (Test-Path -LiteralPath (Join-Path $publishedRuntime 'bundle-manifest.json') -PathType Leaf)) { throw 'Real NVX runtime was not copied into the published consumer.' }
        $env:LOCALAPPDATA = Join-Path $root 'local-appdata'
        New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA | Out-Null
        foreach ($extra in @('', 'simulate-no-whp')) {
            & $realExe present $extra
            if ($LASTEXITCODE -ne 0) { throw 'Real packaged NVX discovery failed.' }
        }
        $syntheticFeed = Join-Path $root 'synthetic-feed'
        New-Item -ItemType Directory -Force -Path $syntheticFeed | Out-Null
        Copy-Item -LiteralPath (Join-Path $realFeed "Microsoft.Mxc.Sdk.$version.nupkg") -Destination $syntheticFeed
        $syntheticRuntime = Join-Path $root 'synthetic-discovery-runtime'
        foreach ($entry in (Get-NvxBundleInventory)) {
            $path = Join-Path $syntheticRuntime $entry
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
            [IO.File]::WriteAllText($path, 'synthetic')
        }
        nuget pack $nuspec -OutputDirectory $syntheticFeed -NonInteractive -Properties "version=$version;nvxRuntime=$syntheticRuntime;repositoryRoot=$repoRoot"
        if ($LASTEXITCODE -ne 0) { throw 'Packing the synthetic discovery runtime failed.' }
        foreach ($scenario in @('absent', 'synthetic')) {
            $consumer = Join-Path $root "real-$scenario-consumer"
            New-Item -ItemType Directory -Force -Path $consumer | Out-Null
            $reference = if ($scenario -eq 'absent') { 'Microsoft.Mxc.Sdk' } else { 'Microsoft.Mxc.Sdk.Nvx.Runtime' }
            $source = if ($scenario -eq 'absent') { $realFeed } else { $syntheticFeed }
            @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><RuntimeIdentifier>win-x64</RuntimeIdentifier><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>
  <ItemGroup><PackageReference Include="$reference" Version="$version" /></ItemGroup>
</Project>
"@ | Set-Content (Join-Path $consumer 'Consumer.csproj')
            Copy-Item -LiteralPath (Join-Path $realConsumer 'Program.cs') -Destination $consumer
            $project = Join-Path $consumer 'Consumer.csproj'
            dotnet restore $project --source $source --packages (Join-Path $root "$scenario-cache") --nologo -p:NuGetAudit=false
            if ($LASTEXITCODE -ne 0) { throw "$scenario packaged consumer restore failed." }
            $publish = Join-Path $consumer 'publish'
            dotnet publish $project -c Release --no-restore --self-contained false --nologo -o $publish
            if ($LASTEXITCODE -ne 0) { throw "$scenario packaged consumer publish failed." }
            foreach ($extra in @('', 'simulate-no-whp')) {
                & (Join-Path $publish 'Consumer.exe') $scenario $extra
                if ($LASTEXITCODE -ne 0) { throw "$scenario packaged NVX validation failed." }
            }
        }
        Write-Host 'Real packaged .NET NVX discovery passed with overrides cleared.'
    } elseif ($NvxOnly) { throw 'NVX package consumer test requires a Windows x64 host.' }
}
finally {
    $env:MXC_FFI_DIR = $originalFfiDir
    $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR = $originalAgentDir
    $env:LOCALAPPDATA = $originalLocalAppData
    Pop-Location
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
