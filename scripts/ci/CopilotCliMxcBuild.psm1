#Requires -Version 7.0

<#
.SYNOPSIS
    Testable build primitives for compiling Copilot CLI against a local MXC checkout.

.DESCRIPTION
    Provides functions for prerequisite validation, MSVC environment setup,
    Cargo dependency rewriting, provenance verification, and sanitized manifest
    creation. Every function is independently testable without private CLI source.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CopilotCliBuildPrerequisites {
    <#
    .SYNOPSIS
        Validates that all required build tools are present and at least 25 GB
        of free disk is available. Fails with one consolidated error listing
        every missing requirement. Does not install software.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$WorkspacePath = (Get-Location).Path
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    # PowerShell 7+
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $errors.Add("PowerShell 7+ required (found $($PSVersionTable.PSVersion))")
    }
    else {
        Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
    }

    # Git
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        $errors.Add('git not found on PATH')
    }
    else {
        $gitVersion = & git --version 2>&1
        Write-Host "Git: $gitVersion"
    }

    # Node.js and npm
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        $errors.Add('node not found on PATH')
    }
    else {
        $nodeVersion = & node --version 2>&1
        Write-Host "Node: $nodeVersion"
    }

    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npm) {
        $errors.Add('npm not found on PATH')
    }
    else {
        $npmVersion = & npm --version 2>&1
        Write-Host "npm: $npmVersion"
    }

    # Rust toolchain: cargo, rustc, rustup
    foreach ($tool in @('cargo', 'rustc', 'rustup')) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if (-not $cmd) {
            $errors.Add("$tool not found on PATH")
        }
        else {
            $ver = & $tool --version 2>&1
            Write-Host "${tool}: $ver"
        }
    }

    # Visual Studio via vswhere.exe
    $vswherePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    $vswhere = $vswherePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vswhere) {
        $errors.Add('vswhere.exe not found (Visual Studio required)')
    }
    else {
        Write-Host "vswhere: $vswhere"
    }

    # Disk space — 25 GB minimum on the workspace volume
    try {
        $workspaceDrive = (Get-Item -LiteralPath $WorkspacePath -ErrorAction Stop).PSDrive
    }
    catch {
        $workspaceDrive = $null
        $errors.Add("Cannot inspect workspace volume '$WorkspacePath': $($_.Exception.Message)")
    }
    if ($workspaceDrive) {
        $freeGB = [math]::Round($workspaceDrive.Free / 1GB, 1)
        Write-Host "Free disk ($($workspaceDrive.Name):): ${freeGB} GB"
        if ($freeGB -lt 25) {
            $errors.Add("At least 25 GB free required (found ${freeGB} GB)")
        }
    }
    elseif (-not ($errors | Where-Object { $_ -like 'Cannot inspect workspace volume*' })) {
        $errors.Add("Cannot determine free space for workspace '$WorkspacePath'")
    }

    if ($errors.Count -gt 0) {
        $joined = ($errors | ForEach-Object { "  - $_" }) -join "`n"
        throw "Build prerequisites not met:`n$joined"
    }

    Write-Host 'All build prerequisites satisfied.'
}

function Enter-MsvcBuildEnvironment {
    <#
    .SYNOPSIS
        Locates the latest Visual Studio installation via vswhere.exe, runs
        VsDevCmd.bat for x64, and imports the resulting NAME=VALUE pairs into
        the current PowerShell process. Fails unless cl.exe and link.exe
        resolve afterward.
    #>
    [CmdletBinding()]
    param()

    $vswherePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    $vswhere = $vswherePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vswhere) {
        throw 'vswhere.exe not found. Visual Studio is required for MSVC builds.'
    }

    $installPath = & $vswhere -latest -property installationPath 2>&1
    if (-not $installPath -or -not (Test-Path $installPath)) {
        throw 'vswhere found no Visual Studio installation.'
    }
    Write-Host "Visual Studio: $installPath"

    $vsDevCmd = Join-Path $installPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path $vsDevCmd)) {
        throw "VsDevCmd.bat not found at $vsDevCmd"
    }

    # Run VsDevCmd.bat inside cmd.exe and capture the resulting environment
    $envPairs = cmd.exe /s /c "`"$vsDevCmd`" -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw "VsDevCmd.bat failed with exit code $LASTEXITCODE"
    }

    foreach ($line in $envPairs) {
        $eqIdx = $line.IndexOf('=')
        if ($eqIdx -gt 0) {
            $name = $line.Substring(0, $eqIdx)
            $value = $line.Substring($eqIdx + 1)
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }

    # Verify cl.exe and link.exe are resolvable
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $cl) {
        throw 'cl.exe not found after importing MSVC environment.'
    }
    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    if (-not $link) {
        throw 'link.exe not found after importing MSVC environment.'
    }

    Write-Host "cl.exe: $($cl.Source)"
    Write-Host "link.exe: $($link.Source)"
    Write-Host 'MSVC build environment imported.'
}

function Set-CopilotCliMxcDependency {
    <#
    .SYNOPSIS
        Rewrites the mxc-sdk dependency in the CLI Cargo.toml to point at the
        local MXC checkout via an absolute forward-slash Cargo path. Rejects
        zero or multiple matches.

    .PARAMETER CliRoot
        Root of the Copilot CLI checkout.

    .PARAMETER MxcRoot
        Root of the MXC checkout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CliRoot,
        [Parameter(Mandatory)][string]$MxcRoot
    )

    $cliCargoToml = Join-Path $CliRoot 'src\runtime\src\sandbox_engine\Cargo.toml'
    $mxcCargoToml = Join-Path $MxcRoot 'src\core\mxc-sdk\Cargo.toml'

    if (-not (Test-Path $cliCargoToml)) {
        throw "CLI Cargo.toml not found: $cliCargoToml"
    }
    if (-not (Test-Path $mxcCargoToml)) {
        throw "MXC Cargo.toml not found: $mxcCargoToml"
    }

    $lines = @(Get-Content $cliCargoToml)
    $matchIndices = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*mxc-sdk\s*=') {
            $matchIndices += $i
        }
    }

    if ($matchIndices.Count -eq 0) {
        throw "No 'mxc-sdk =' dependency found in $cliCargoToml"
    }
    if ($matchIndices.Count -gt 1) {
        throw "Multiple 'mxc-sdk =' lines found in $cliCargoToml (lines: $($matchIndices -join ', ')). Expected exactly one."
    }

    # Resolve the MXC SDK path and convert to forward slashes for Cargo
    $mxcSdkPath = (Resolve-Path (Join-Path $MxcRoot 'src\core\mxc-sdk')).Path -replace '\\', '/'
    $newLine = "mxc-sdk = { path = `"$mxcSdkPath`" }"
    $originalLine = $lines[$matchIndices[0]]
    $lines[$matchIndices[0]] = $newLine

    Set-Content -Path $cliCargoToml -Value $lines -Encoding utf8NoBOM
    Write-Host "Rewrote mxc-sdk dependency in $cliCargoToml"
    Write-Host "  From: $originalLine"
    Write-Host "  To:   $newLine"
}

function Assert-CopilotCliMxcProvenance {
    <#
    .SYNOPSIS
        Runs 'cargo metadata' and verifies that exactly one mxc-sdk package
        has source = null and its manifest_path equals the intended MXC checkout.

    .PARAMETER CliRoot
        Root of the Copilot CLI checkout.

    .PARAMETER MxcRoot
        Root of the MXC checkout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CliRoot,
        [Parameter(Mandatory)][string]$MxcRoot
    )

    $manifestPath = Join-Path $CliRoot 'src\runtime\src\sandbox_engine\Cargo.toml'
    if (-not (Test-Path $manifestPath)) {
        throw "CLI manifest not found: $manifestPath"
    }

    $cargo = Get-Command cargo -ErrorAction Stop
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $cargo.Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.ArgumentList.Add('metadata')
    $startInfo.ArgumentList.Add('--format-version')
    $startInfo.ArgumentList.Add('1')
    $startInfo.ArgumentList.Add('--manifest-path')
    $startInfo.ArgumentList.Add($manifestPath)

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Failed to start cargo metadata.'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $raw = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
    if ($process.ExitCode -ne 0) {
        throw "cargo metadata failed (exit $($process.ExitCode)): $stderr"
    }

    try {
        $metadata = $raw | ConvertFrom-Json
    }
    catch {
        throw "cargo metadata returned invalid JSON: $($_.Exception.Message)"
    }
    $mxcSdkPackages = $metadata.packages | Where-Object { $_.name -eq 'mxc-sdk' }

    $mxcSdkPackages = @($mxcSdkPackages)
    if ($mxcSdkPackages.Count -ne 1) {
        throw "Expected exactly 1 mxc-sdk package in cargo metadata, found $($mxcSdkPackages.Count)."
    }

    $localPackages = @($mxcSdkPackages | Where-Object { $null -eq $_.source })
    if ($localPackages.Count -ne 1) {
        throw 'The resolved mxc-sdk package is not local (source must be null).'
    }

    $expectedManifest = (Resolve-Path (Join-Path $MxcRoot 'src\core\mxc-sdk\Cargo.toml')).Path
    $actualManifest = $localPackages[0].manifest_path -replace '/', '\'
    if ($actualManifest -ne $expectedManifest) {
        throw "mxc-sdk manifest_path mismatch. Expected: $expectedManifest, Got: $actualManifest"
    }

    Write-Host "Provenance verified: mxc-sdk is resolved from $actualManifest (local, source=null)."
}

function New-CopilotCliMxcManifest {
    <#
    .SYNOPSIS
        Writes a sanitized provenance manifest JSON. Excludes tokens, environment
        values, absolute private-source paths, checkout URLs, Git configuration,
        and raw Cargo metadata.

    .PARAMETER ManifestPath
        Output file path.

    .PARAMETER MxcSha
        40-character hex SHA of the MXC checkout.

    .PARAMETER CliSha
        40-character hex SHA of the CLI checkout.

    .PARAMETER MxcSdkManifest
        Relative path to the MXC SDK Cargo.toml.

    .PARAMETER RuntimeSourceSha256
        SHA-256 of the compiled runtime .node before bundling.

    .PARAMETER RuntimeBundleSha256
        SHA-256 of the runtime .node after bundling.

    .PARAMETER CliVersion
        Output of the CLI --version command.

    .PARAMETER CargoBuildJobs
        Number of Cargo parallel jobs used.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$MxcSha,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$CliSha,
        [Parameter(Mandatory)][string]$MxcSdkManifest,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$RuntimeSourceSha256,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$RuntimeBundleSha256,
        [Parameter(Mandatory)][string]$CliVersion,
        [Parameter(Mandatory)][ValidateSet(2)][int]$CargoBuildJobs
    )

    if ($MxcSdkManifest -ne 'src/core/mxc-sdk/Cargo.toml') {
        throw "mxcSdkManifest must be the repository-relative path 'src/core/mxc-sdk/Cargo.toml'."
    }
    if ($CliVersion -notmatch '^GitHub Copilot CLI [^\\/\r\n]+$') {
        throw "CLI version must be a single 'GitHub Copilot CLI ...' line without a path."
    }

    $manifest = [ordered]@{
        schemaVersion       = 1
        mxcSha              = $MxcSha
        cliSha              = $CliSha
        mxcSdkManifest      = $MxcSdkManifest
        runtimeSourceSha256 = $RuntimeSourceSha256
        runtimeBundleSha256 = $RuntimeBundleSha256
        runtimeHashesMatch  = ($RuntimeSourceSha256 -eq $RuntimeBundleSha256)
        cliVersion          = $CliVersion
        osVersion           = [System.Environment]::OSVersion.ToString()
        pool                = '1es-mxc-windows-prerelease-t1-x64'
        cargoBuildJobs      = $CargoBuildJobs
    }

    $json = $manifest | ConvertTo-Json -Depth 4
    Set-Content -Path $ManifestPath -Value $json -Encoding utf8NoBOM
    Write-Host "Manifest written to $ManifestPath"

    # Post-write sanitization check — reject if the file contains tokens,
    # private checkout paths, or environment secret names.
    $content = Get-Content $ManifestPath -Raw
    $suspiciousPatterns = @(
        'ghp_'             # GitHub PAT prefix
        'gho_'             # GitHub OAuth prefix
        'github_pat_'      # Fine-grained PAT prefix
        'GHCP_CLI_'        # Environment secret name fragment
        '\\source\\cli'    # Private CLI absolute path (backslash)
        '/source/cli'      # Private CLI absolute path (forward slash)
    )
    foreach ($pattern in $suspiciousPatterns) {
        if ($content -match [regex]::Escape($pattern)) {
            Remove-Item $ManifestPath -Force -ErrorAction SilentlyContinue
            throw "Manifest contains suspicious content matching '$pattern'. File removed."
        }
    }

    return $manifest
}

Export-ModuleMember -Function @(
    'Assert-CopilotCliBuildPrerequisites',
    'Enter-MsvcBuildEnvironment',
    'Set-CopilotCliMxcDependency',
    'Assert-CopilotCliMxcProvenance',
    'New-CopilotCliMxcManifest'
)
