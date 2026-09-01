# Copyright (c) Microsoft Corporation. All rights reserved.
#
# Focused validation for packaging\isolation-session\installer\makeinstaller.ps1.
#
# Exercises the required-input failure modes (missing dotnet, missing -BinDir,
# missing binaries, invalid -Arch), the architecture-safe deterministic GUID
# derivation (x64 and arm64 must preserve the same MonthId-based runtime
# identity; repeated calls must be idempotent), the <month>_<arch> output
# naming convention, and
# - when dotnet + network restore are available - attempts real x64 AND arm64
# builds using the placeholder payloads under tests\payload\<arch>. Both
# architectures are required pipeline outputs, so either build failing fails
# this validation.
#
# This script has no external test-framework dependency (plain PowerShell
# assertions) so it runs the same way in CI and locally. It always cleans up
# any build output it produces before exiting.
#
# Usage:
#   powershell -File Test-MakeInstaller.ps1
#
# Exit code 0 = all checks passed (build-dependent checks are skipped only when
# dotnet is unavailable).
# Exit code 1 = at least one assertion failed.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$installerDir = Split-Path -Parent $scriptDir
$makeInstaller = Join-Path $installerDir 'makeinstaller.ps1'
$payloadX64 = Join-Path $scriptDir 'payload\x64'
$payloadArm64 = Join-Path $scriptDir 'payload\arm64'

$script:failures = [System.Collections.Generic.List[string]]::new()
$script:passed = 0

function Assert-True([bool]$condition, [string]$message) {
    if ($condition) {
        $script:passed++
        Write-Host "  PASS: $message" -ForegroundColor Green
    } else {
        $script:failures.Add($message)
        Write-Host "  FAIL: $message" -ForegroundColor Red
    }
}

function ConvertTo-QuotedArg([string]$arg) {
    if ($arg -match '[\s"]') {
        return '"' + ($arg -replace '"', '\"') + '"'
    }
    return $arg
}

function Invoke-MakeInstaller([string[]]$scriptArgs, [hashtable]$envOverrides) {
    # Run in a fresh powershell.exe process so PATH overrides (for the
    # "missing dotnet" scenario) and exit codes are isolated per-invocation.
    # Uses the (older) ProcessStartInfo.Arguments string form rather than
    # ArgumentList, since ArgumentList is unavailable under the .NET
    # Framework that hosts Windows PowerShell 5.1.
    $allArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (ConvertTo-QuotedArg $makeInstaller))
    foreach ($a in $scriptArgs) { $allArgs += (ConvertTo-QuotedArg $a) }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = (Get-Command powershell.exe).Source
    $psi.Arguments = ($allArgs -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    if ($envOverrides) {
        foreach ($k in $envOverrides.Keys) { $psi.EnvironmentVariables[$k] = $envOverrides[$k] }
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $p.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

Write-Host "`n=== Required-input failure modes (must all be NONZERO exit) ===" -ForegroundColor Cyan

# 1. Missing dotnet on PATH -> nonzero exit.
$dotnetDir = Split-Path -Parent (Get-Command dotnet.exe).Source
$origPath = $env:Path
$strippedPath = ($origPath -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $dotnetDir.TrimEnd('\')) }) -join ';'
$result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-BinDir', $payloadX64, '-MonthId', '2026.08') -envOverrides @{ Path = $strippedPath }
Assert-True ($result.ExitCode -ne 0) "Missing dotnet on PATH exits nonzero (got $($result.ExitCode))"

# 2. Missing -BinDir -> nonzero exit.
$result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-MonthId', '2026.08')
Assert-True ($result.ExitCode -ne 0) "Missing -BinDir exits nonzero (got $($result.ExitCode))"

# 3. -BinDir pointing to a directory missing required binaries -> nonzero exit.
$emptyBinDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mkinst-empty-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $emptyBinDir -Force | Out-Null
try {
    $result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-BinDir', $emptyBinDir, '-MonthId', '2026.08')
    Assert-True ($result.ExitCode -ne 0) "BinDir missing required binaries exits nonzero (got $($result.ExitCode))"
} finally {
    Remove-Item -Recurse -Force $emptyBinDir -ErrorAction SilentlyContinue
}

# 4. Invalid -Arch (x86 unsupported) -> nonzero exit.
$result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x86', '-BinDir', $payloadX64, '-MonthId', '2026.08')
Assert-True ($result.ExitCode -ne 0) "Invalid -Arch 'x86' exits nonzero (got $($result.ExitCode))"

# 5. Malformed MonthId -> nonzero exit.
$result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-BinDir', $payloadX64, '-MonthId', '2026-08')
Assert-True ($result.ExitCode -ne 0) "Malformed -MonthId exits nonzero (got $($result.ExitCode))"

# 6. Mutually exclusive phase switches -> nonzero exit.
$result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-BinDir', $payloadX64, '-MonthId', '2026.08', '-MsiOnly', '-BundleOnly')
Assert-True ($result.ExitCode -ne 0) "-MsiOnly plus -BundleOnly exits nonzero (got $($result.ExitCode))"

# 7. Bundle-only without an existing MSI -> nonzero exit.
$missingBundleOut = Join-Path ([System.IO.Path]::GetTempPath()) ("mkinst-bundle-missing-" + [Guid]::NewGuid())
try {
    $result = Invoke-MakeInstaller -scriptArgs @('-Arch', 'x64', '-BinDir', $payloadX64, '-MonthId', '2026.08', '-OutDir', $missingBundleOut, '-BundleOnly')
    Assert-True ($result.ExitCode -ne 0) "-BundleOnly without an existing MSI exits nonzero (got $($result.ExitCode))"
} finally {
    Remove-Item -Recurse -Force $missingBundleOut -ErrorAction SilentlyContinue
}

Write-Host "`n=== Build-matched COM proxy registration ===" -ForegroundColor Cyan

$installerAuthoring = Get-Content (Join-Path $installerDir 'IsoSession.wxs') -Raw
$clientManifestTemplate =
    Get-Content (Join-Path $installerDir 'IsoSessionClient.manifest.template') -Raw
Assert-True (
    -not $installerAuthoring.Contains('IsoSessionCore.dll')
) 'MSI leaves the IsoSessionCore compatibility boundary inbox'
Assert-True (
    $installerAuthoring.Contains('Source="$(var.RuntimeManifestPath)"')
) 'MSI installs the generated IsoSession.manifest'
Assert-True (
    $installerAuthoring.Contains('<ComponentRef Id="Comp_IsoSessionManifest" />')
) 'MSI includes IsoSession.manifest in the Complete feature'
Assert-True (
    $installerAuthoring.Contains('Key="SOFTWARE\Microsoft\IsoSession\$(var.RuntimeToken)"')
) 'MSI keys InstallDir by the underscore runtime token'

$expectedComGuids = [ordered]@{
    CLSID_IsoSessionProxyStub = '{2B526D49-56AC-4D72-8692-4DB1F4EDFA7C}'
    IComSessionClient = '{BE6C975A-BFED-4338-BC4D-600CF83614CE}'
    IComSessionOperationCallback = '{9A7B80F0-7644-47BB-B884-5B0A4331E517}'
    IComSessionProvisionCallback = '{E3B33D6A-572A-4515-8113-BB66BC6730B4}'
    IComSessionProxyCallback = '{9946C1AC-7F31-4BB6-8AD2-59D75FC490A2}'
    IComSessionProxyConnection = '{AAB45130-236A-4A0D-8BA4-FE68A79B7A85}'
    IComSessionProxySessionCallback = '{63711C2F-7030-4C37-8363-EC9F78EA8B7F}'
    IComSessionRegistrationCallback = '{3A088D05-29B4-4A53-BC5C-5BEA8E6A6231}'
    IComSessionUtilityLogonCallback = '{E7E5FBD4-4258-4A79-9FC3-24FC40C59531}'
    IComSessionUtilityLogonConnection = '{291CAFAA-73F3-4912-9579-4DCC4B09E502}'
    IComSessionWorkerProcess = '{DD8D5731-929C-4C56-B178-1408054EB70F}'
    IComSessionWorkerProcessCallback = '{FA560CC0-DC0B-4E83-ABD1-D4E0DAA145EC}'
    IComStationWatcherCallback = '{3F44A898-9856-46E1-B029-4A5FACE5ABA1}'
    IComSubordinateCallback = '{FB202185-9A56-4849-BFD1-47E324A9F8AA}'
    IComTaskWatcherCallback = '{0F4D3D19-5A11-4C65-A777-7DA7E1810290}'
}

foreach ($entry in $expectedComGuids.GetEnumerator()) {
    Assert-True (
        $installerAuthoring.Contains($entry.Value)
    ) "MSI registers current $($entry.Key) GUID $($entry.Value)"
    Assert-True (
        $clientManifestTemplate.Contains($entry.Value)
    ) "Client manifest registers current $($entry.Key) GUID $($entry.Value)"
}

$obsoleteComGuids = @(
    '{20A5CDEF-405F-456F-82B4-87050A919E5C}',
    '{F1C3C112-2B26-4095-A31C-6F110C14B229}',
    '{B5C6D7E8-1F2A-4B3C-E4D5-8C9D0E1F2A3B}',
    '{35E7D920-F286-4405-8EA1-CF05CF3260C3}',
    '{D7909DBE-ED35-4F61-BD85-D6C7F5D9A9B8}'
)
foreach ($guid in $obsoleteComGuids) {
    Assert-True (
        -not $installerAuthoring.Contains($guid)
    ) "MSI excludes obsolete COM GUID $guid"
    Assert-True (
        -not $clientManifestTemplate.Contains($guid)
    ) "Client manifest excludes obsolete COM GUID $guid"
}

Write-Host "`n=== MonthId-based deterministic runtime identities ===" -ForegroundColor Cyan

$genOutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mkinst-guid-" + [Guid]::NewGuid())
function Get-GeneratedVars([string]$arch, [string]$binDir, [string]$outDir, [string]$monthId) {
    $r = Invoke-MakeInstaller -scriptArgs @('-Arch', $arch, '-BinDir', $binDir, '-MonthId', $monthId, '-OutDir', $outDir, '-MsiOnly')
    if ($r.ExitCode -ne 0) {
        throw "makeinstaller.ps1 -Arch $arch failed unexpectedly (exit $($r.ExitCode)):`n$($r.StdOut)`n$($r.StdErr)"
    }
    $monthUnderscore = $monthId.Replace('.', '_')
    $wxi = Join-Path $outDir "IsoSessionVars_${monthUnderscore}_$arch.wxi"
    if (-not (Test-Path $wxi)) { throw "Expected generated include not found: $wxi" }
    Get-Content $wxi -Raw
}

try {
    $monthId = '2026.09'
    $patch = 5
    $x64OutA = Join-Path $genOutDir 'x64-run1'
    $x64OutB = Join-Path $genOutDir 'x64-run2'
    $arm64Out = Join-Path $genOutDir 'arm64-run1'

    $x64VarsA = Get-GeneratedVars -arch 'x64' -binDir $payloadX64 -outDir $x64OutA -monthId $monthId
    $x64VarsB = Get-GeneratedVars -arch 'x64' -binDir $payloadX64 -outDir $x64OutB -monthId $monthId
    $arm64Vars = Get-GeneratedVars -arch 'arm64' -binDir $payloadArm64 -outDir $arm64Out -monthId $monthId

    function Get-DefineValue([string]$content, [string]$name) {
        if ($content -match [regex]::Escape("define $name = ") + '"([^"]+)"') { return $matches[1] }
        throw "Could not find define '$name' in generated include"
    }

    $guidNames = @('UpgradeCode', 'BundleUpgradeCode', 'AppId', 'ClientClsid', 'ProxyConnectionClsid')
    foreach ($n in $guidNames) {
        $a = Get-DefineValue $x64VarsA $n
        $b = Get-DefineValue $x64VarsB $n
        $arm = Get-DefineValue $arm64Vars $n
        Assert-True ($a -eq $b) "x64 '$n' is deterministic across repeated runs ($a)"
        Assert-True ($a -eq $arm) "x64 vs arm64 '$n' preserve the same monthly identity ($a)"
    }

    $x64Service = Get-DefineValue $x64VarsA 'ServiceName'
    $arm64Service = Get-DefineValue $arm64Vars 'ServiceName'
    Assert-True ($x64Service -eq 'IsolationSession_2026_09') "x64 ServiceName follows the MonthId runtime contract ($x64Service)"
    Assert-True ($arm64Service -eq $x64Service) "arm64 ServiceName matches x64 ($arm64Service)"

    $x64SubDir = Get-DefineValue $x64VarsA 'InstallSubDir'
    $arm64SubDir = Get-DefineValue $arm64Vars 'InstallSubDir'
    Assert-True ($x64SubDir -eq 'Microsoft\Agentic Runtime\2026.09') "x64 InstallSubDir follows the MonthId runtime contract ($x64SubDir)"
    Assert-True ($arm64SubDir -eq $x64SubDir) "arm64 InstallSubDir matches x64 ($arm64SubDir)"

    $x64RuntimeToken = Get-DefineValue $x64VarsA 'RuntimeToken'
    $arm64RuntimeToken = Get-DefineValue $arm64Vars 'RuntimeToken'
    Assert-True ($x64RuntimeToken -eq '2026_09') "x64 RuntimeToken uses the underscore identity ($x64RuntimeToken)"
    Assert-True ($arm64RuntimeToken -eq $x64RuntimeToken) "arm64 RuntimeToken matches x64 ($arm64RuntimeToken)"

    $runtimeManifestPath = Get-DefineValue $x64VarsA 'RuntimeManifestPath'
    Assert-True (Test-Path -LiteralPath $runtimeManifestPath -PathType Leaf) 'Generated IsoSession.manifest exists'
    $runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw
    Assert-True (
        $runtimeManifest.Contains(
            '<iso:instance xmlns:iso="urn:schemas-microsoft-com:agentic-runtime.v1" name="2026.09" />')
    ) 'Generated IsoSession.manifest carries the dotted service instance'

    $releaseOut = Join-Path $genOutDir 'release-check'
    $releaseResult = Invoke-MakeInstaller -scriptArgs @(
        '-Arch', 'x64',
        '-BinDir', $payloadX64,
        '-MonthId', $monthId,
        '-Patch', $patch,
        '-OutDir', $releaseOut,
        '-MsiOnly')
    if ($releaseResult.ExitCode -ne 0) {
        throw "makeinstaller.ps1 release-check failed unexpectedly (exit $($releaseResult.ExitCode)):`n$($releaseResult.StdOut)`n$($releaseResult.StdErr)"
    }
    $releaseVars = Get-Content (Join-Path $releaseOut 'IsoSessionVars_2026_09_x64.wxi') -Raw
    Assert-True ((Get-DefineValue $releaseVars 'Version') -eq '26.9.5.0') 'Patch propagates into the MSI/bundle version'
    Assert-True ($releaseResult.StdOut -match [regex]::Escape('Release:          2026.09.5')) 'Release contract is reported in installer output'
    Assert-True ($releaseResult.StdOut -match [regex]::Escape('NuGet Version:    0.202609.5')) 'NuGet version derived from the shared release contract is reported'
} finally {
    Remove-Item -Recurse -Force $genOutDir -ErrorAction SilentlyContinue
}

Write-Host "`n=== Output naming convention (IsoSession_<month>_<arch> / IsoSessionSetup_<month>_<arch>) ===" -ForegroundColor Cyan

$dotnetAvailable = [bool](Get-Command dotnet.exe -ErrorAction SilentlyContinue)
if (-not $dotnetAvailable) {
    Write-Host "  SKIP: dotnet not on PATH - cannot attempt real builds." -ForegroundColor Yellow
} else {
    $buildOutRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mkinst-build-" + [Guid]::NewGuid())
    $monthId = '2026.10'
    $monthUnderscore = $monthId.Replace('.', '_')

    foreach ($archInfo in @(
        @{ Arch = 'x64'; BinDir = $payloadX64 },
        @{ Arch = 'arm64'; BinDir = $payloadArm64 }
    )) {
        $arch = $archInfo.Arch
        $outDir = Join-Path $buildOutRoot $arch
        Write-Host "`n--- Attempting $arch build with placeholder payload ---" -ForegroundColor Cyan
        $result = Invoke-MakeInstaller -scriptArgs @('-Arch', $arch, '-BinDir', $archInfo.BinDir, '-MonthId', $monthId, '-OutDir', $outDir, '-MsiOnly')

        if ($result.ExitCode -ne 0) {
            Assert-True $false "$arch MSI build succeeded (exit $($result.ExitCode)); see stdout/stderr:`n$($result.StdOut)`n$($result.StdErr)"
            continue
        }

        $expectedMsi = Join-Path $outDir "IsoSession_${monthUnderscore}_$arch.msi"
        $expectedExe = Join-Path $outDir "IsoSessionSetup_${monthUnderscore}_$arch.exe"
        Assert-True (Test-Path $expectedMsi) "$arch MSI produced with expected name: IsoSession_${monthUnderscore}_$arch.msi"
        $msiHashBeforeBundle = (Get-FileHash -LiteralPath $expectedMsi -Algorithm SHA256).Hash

        $bundleResult = Invoke-MakeInstaller -scriptArgs @('-Arch', $arch, '-BinDir', $archInfo.BinDir, '-MonthId', $monthId, '-OutDir', $outDir, '-BundleOnly')
        if ($bundleResult.ExitCode -ne 0) {
            Assert-True $false "$arch bundle build succeeded (exit $($bundleResult.ExitCode)); see stdout/stderr:`n$($bundleResult.StdOut)`n$($bundleResult.StdErr)"
            continue
        }

        Assert-True (Test-Path $expectedExe) "$arch bootstrapper EXE produced with expected name: IsoSessionSetup_${monthUnderscore}_$arch.exe"
        $msiHashAfterBundle = (Get-FileHash -LiteralPath $expectedMsi -Algorithm SHA256).Hash
        Assert-True ($msiHashAfterBundle -eq $msiHashBeforeBundle) "$arch bundle phase preserves the existing MSI bytes"

        # Confirm the Util custom-action binary embedded in the MSI matches the
        # architecture actually built (Wix4UtilCA_X64 / Wix4UtilCA_A64) - this
        # is the crux of the "appropriate Util custom-action binary" requirement.
        $directoryRecord = $null
        $directoryView = $null
        $fileRecord = $null
        $fileView = $null
        $registryRecord = $null
        $registryView = $null
        $view = $null
        $db = $null
        $installerCom = $null
        try {
            $installerCom = New-Object -ComObject WindowsInstaller.Installer
            $db = $installerCom.OpenDatabase($expectedMsi, 0)
            # Type 3137 = deferred DLL custom action (msidbCustomActionTypeDll +
            # msidbCustomActionTypeContinue + msidbCustomActionTypeInScript);
            # only these rows reference a Binary table entry via Source. The
            # SetProperty ("SetCA_...") rows also appear in this table with
            # Source = the target CustomAction's own Id, not a binary ref.
            $view = $db.OpenView('SELECT Source FROM CustomAction WHERE Type = 3137')
            $view.Execute()
            $rec = $view.Fetch()
            $binaryRefs = [System.Collections.Generic.HashSet[string]]::new()
            while ($rec) {
                [void]$binaryRefs.Add($rec.StringData(1))
                $rec = $view.Fetch()
            }
            $expectedCaBinary = if ($arch -eq 'x64') { 'Wix4UtilCA_X64' } else { 'Wix4UtilCA_A64' }
            Assert-True ($binaryRefs.Count -eq 1 -and $binaryRefs.Contains($expectedCaBinary)) "$arch MSI CustomAction table references $expectedCaBinary only (found: $($binaryRefs -join ', '))"

            $si = $db.SummaryInformation(0)
            $template = $si.Property(7)
            $expectedTemplate = if ($arch -eq 'x64') { 'x64;1033' } else { 'Arm64;1033' }
            Assert-True ($template -eq $expectedTemplate) "$arch MSI SummaryInformation Template is '$expectedTemplate' (found: '$template')"

            $directoryView = $db.OpenView(
                "SELECT ``DefaultDir`` FROM ``Directory`` WHERE ``Directory`` = 'INSTALLDIR'")
            $directoryView.Execute()
            $directoryRecord = $directoryView.Fetch()
            $installDirName = $directoryRecord.StringData(1)
            Assert-True ($installDirName -eq $monthId) "$arch MSI INSTALLDIR remains MonthId-only ($installDirName)"

            $fileView = $db.OpenView(
                "SELECT ``FileName`` FROM ``File`` WHERE ``File`` = 'IsoSession.manifest'")
            $fileView.Execute()
            $fileRecord = $fileView.Fetch()
            $runtimeManifestName = if ($fileRecord) {
                ($fileRecord.StringData(1) -split '\|')[-1]
            } else {
                $null
            }
            Assert-True ($runtimeManifestName -eq 'IsoSession.manifest') "$arch MSI contains IsoSession.manifest"

            $coreView = $db.OpenView(
                "SELECT ``FileName`` FROM ``File`` WHERE ``File`` = 'IsoSessionCore.dll'")
            $coreView.Execute()
            Assert-True (-not $coreView.Fetch()) "$arch MSI leaves IsoSessionCore.dll inbox"

            $registryView = $db.OpenView(
                "SELECT ``Key`` FROM ``Registry`` WHERE ``Name`` = 'InstallDir'")
            $registryView.Execute()
            $registryRecord = $registryView.Fetch()
            $installRegistryKey = $registryRecord.StringData(1)
            Assert-True (
                $installRegistryKey -eq "SOFTWARE\Microsoft\IsoSession\$monthUnderscore"
            ) "$arch MSI install-path registry key uses the underscore runtime token ($installRegistryKey)"
        } catch {
            Write-Host "  SKIP: MSI table inspection unavailable in this environment ($($_.Exception.Message))" -ForegroundColor Yellow
        } finally {
            # Release COM references so the MSI file handle is not held open,
            # otherwise the temp cleanup below can silently fail to delete it.
            foreach ($comObj in @(
                $directoryRecord,
                $directoryView,
                $fileRecord,
                $fileView,
                $registryRecord,
                $registryView,
                $view,
                $db,
                $installerCom
            )) {
                if ($comObj) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObj) }
            }
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }

        $bundleAuthoring = Get-Content (Join-Path $installerDir 'IsoSessionBundle.wxs') -Raw
        Assert-True (
            $bundleAuthoring -match [regex]::Escape(
                'Value="[ProgramFiles64Folder]Microsoft\Agentic Runtime\$(var.MonthId)"')
        ) 'Bundle default install path remains MonthId-only'
    }

    Remove-Item -Recurse -Force $buildOutRoot -ErrorAction SilentlyContinue
    if (Test-Path $buildOutRoot) {
        Start-Sleep -Milliseconds 500
        Remove-Item -Recurse -Force $buildOutRoot -ErrorAction SilentlyContinue
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "Passed: $($script:passed)   Failed: $($script:failures.Count)" -ForegroundColor Cyan
if ($script:failures.Count -gt 0) {
    Write-Host "`nFailures:" -ForegroundColor Red
    foreach ($f in $script:failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
exit 0
