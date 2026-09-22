#Requires -Version 5.1

<#
.SYNOPSIS
    Prepares a Windows host for a backend's artifact-only test suite.

.PARAMETER Backend
    Matrix backend id.

.PARAMETER BinaryDirectory
    Directory holding the downloaded build artifact.

.EXAMPLE
    ./scripts/ci/prepare-windows-host.ps1 -Backend process-t3 -BinaryDirectory artifacts/bin
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'process-t1',
        'process-t3',
        'isolation-session',
        'wslc',
        'windows-sandbox',
        'microvm'
    )]
    [string]$Backend,

    [Parameter(Mandatory)]
    [string]$BinaryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WingetPath = $null

function Exit-WithError {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "::error::$Message"
    exit 1
}

function Assert-RequiredFile {
    param(
        [Parameter(Mandatory)][string[]]$RelativePath
    )

    $missing = $RelativePath | Where-Object { -not (Test-Path (Join-Path $BinaryDirectory $_)) }
    if ($missing) {
        Exit-WithError "Missing binaries: $($missing -join ', ')"
    }

    $leaves = $RelativePath | ForEach-Object { Split-Path $_ -Leaf }
    Get-ChildItem $BinaryDirectory -Include $leaves -Recurse | Format-Table FullName, Length
}

# Read a Windows optional feature's state without throwing, so both the
# diagnostic and assertion paths can share one query. A host that cannot answer
# (querying needs elevation) reports the reason as its state rather than
# aborting, which keeps the failure message actionable.
function Get-OptionalFeatureState {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
    } catch {
        return "query-failed: $($_.Exception.Message.Trim())"
    }

    if ($null -eq $feature) {
        return 'unknown'
    }
    return [string]$feature.State
}

# Require every named optional feature to be Enabled. Enabling one needs a
# reboot the runner cannot take mid-job, so this verifies rather than installs:
# a mis-imaged pool fails here with a pointed message instead of surfacing
# later as an opaque backend error. $Remedy names the image-level fix.
function Assert-RequiredFeature {
    param(
        [Parameter(Mandatory)][string[]]$Name,
        [Parameter(Mandatory)][string]$Remedy
    )

    $notEnabled = @()
    foreach ($feature in $Name) {
        $state = Get-OptionalFeatureState -Name $feature
        Write-Host "  $feature = $state"
        if ($state -ne 'Enabled') {
            $notEnabled += "$feature ($state)"
        }
    }

    if ($notEnabled) {
        Exit-WithError "Required Windows optional feature(s) not enabled: $($notEnabled -join '; '). $Remedy"
    }
}

# Report the hypervisor state a VM-backed backend depends on. Purely
# diagnostic: never fails, so a hypervisor problem surfaces as the explicit
# check below rather than as an unexplained collection error.
function Write-HypervisorDiagnostic {
    Write-Host '=== Hypervisor Diagnostics ==='
    Write-Host "OS: $([System.Environment]::OSVersion)"

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $hypervisorPresent = if ($null -eq $computerSystem) { 'unknown' } else { $computerSystem.HypervisorPresent }
    Write-Host "HypervisorPresent: $hypervisorPresent"
    Write-Host "WinHvPlatform.dll exists: $(Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")"
    Write-Host '=== end diagnostics ==='
}

# The feature can be enabled while the hypervisor is not actually running (for
# example when a host reboot is still pending), so both are required.
function Assert-HypervisorPlatform {
    Assert-RequiredFeature -Name 'HypervisorPlatform' `
        -Remedy 'This backend requires Windows Hypervisor Platform on the runner image.'

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($null -eq $computerSystem -or -not $computerSystem.HypervisorPresent) {
        Exit-WithError 'HypervisorPresent is false - WHP feature is enabled but hypervisor is not running.'
    }

    Write-Host 'WHP is enabled and hypervisor is present.'
}

# The matrix schedules by pool name, so this is the only evidence in the log
# that a pool really booted the release it advertises. Which tier a
# process-container job selects is a function of that build.
function Write-HostOsVersion {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $values = @{}
    foreach ($name in 'ProductName', 'DisplayVersion', 'ReleaseId', 'CurrentBuild', 'UBR', 'EditionID') {
        try {
            $values[$name] = (Get-ItemProperty -Path $key -Name $name -ErrorAction Stop).$name
        } catch {
            $values[$name] = $null
        }
    }

    # Win32_OperatingSystem is the only reliable product name: the registry's
    # ProductName still reads "Windows 10" on Windows 11 hosts.
    $caption = $null
    try {
        $caption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
    } catch {
        Write-Host "Could not query Win32_OperatingSystem ($($_.Exception.Message)); falling back to the registry product name."
        $caption = $values['ProductName']
    }

    $release = if ($values['DisplayVersion']) { $values['DisplayVersion'] } else { $values['ReleaseId'] }
    $build = if ($null -ne $values['UBR']) {
        "$($values['CurrentBuild']).$($values['UBR'])"
    } else {
        $values['CurrentBuild']
    }

    Write-Host "Host OS: $caption"
    Write-Host "Host OS release: $release (build $build)"
    # PROCESSOR_ARCHITECTURE describes this process, which reads as AMD64 when
    # the runner starts an emulated shell on an Arm64 host; the machine
    # environment block keeps the native value.
    $archKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
        -Name PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue
    $architecture = if ($archKey) { $archKey.PROCESSOR_ARCHITECTURE } else { $env:PROCESSOR_ARCHITECTURE }

    Write-Host "Host OS edition: $($values['EditionID']); architecture: $architecture"
}

function Initialize-ProcessContainerHost {
    $hostPrep = Join-Path $BinaryDirectory 'wxc-host-prep.exe'
    if (-not (Test-Path $hostPrep)) {
        Exit-WithError "wxc-host-prep.exe not found in $BinaryDirectory"
    }

    # The AppContainer tier needs the system-drive ACEs and the \Device\Null
    # security descriptor. --no-sacl keeps the descriptor within what a CI host
    # can grant without SeSecurityPrivilege.
    #
    # This runs for process-t1 as well as process-t3. A T1 host selects
    # BaseContainer for most policies, but the suite deliberately drives the
    # AppContainer fallback tiers too (and an unprepared host fails the launch
    # with WIN32_ERROR(5) rather than reporting a policy result), so the T1 job
    # needs the same preparation to test anything beyond config validation.
    & $hostPrep prepare-system-drive
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "wxc-host-prep prepare-system-drive failed with exit code $LASTEXITCODE"
    }

    & $hostPrep prepare-null-device --no-sacl
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "wxc-host-prep prepare-null-device failed with exit code $LASTEXITCODE"
    }
}

# Inventory the interpreters test suites drive inside the sandbox, after
# Install-WorkloadTooling has installed the ones this job owns.
function Assert-WorkloadInterpreters {
    $interpreters = @(
        @{ Name = 'pwsh';    Candidates = @('pwsh');              Required = $true;  Remedy = 'installed per job by Install-WorkloadTooling; see the winget output above' },
        @{ Name = 'git';     Candidates = @('git');               Required = $false; Remedy = 'install Git for Windows in the image' },
        @{ Name = 'node';    Candidates = @('node');              Required = $false; Remedy = 'installed per job by Install-WorkloadTooling; see the winget output above' },
        @{ Name = 'npm';     Candidates = @('npm');               Required = $false; Remedy = 'ships with Node, which Install-WorkloadTooling installs' },
        @{ Name = 'npx';     Candidates = @('npx');               Required = $false; Remedy = 'ships with Node, which Install-WorkloadTooling installs' },
        @{ Name = 'python';  Candidates = @('python', 'python3'); Required = $false; Remedy = 'installed per job by Install-WorkloadTooling; see the winget output above' },
        @{ Name = 'pip';     Candidates = @('pip', 'pip3');       Required = $false; Remedy = 'ships with Python, which Install-WorkloadTooling installs' },
        @{ Name = 'dotnet';  Candidates = @('dotnet');            Required = $false; Remedy = 'install the .NET SDK in the image' },
        @{ Name = 'az';      Candidates = @('az');                Required = $false; Remedy = 'install the Azure CLI in the image' },
        @{ Name = 'gh';      Candidates = @('gh');                Required = $false; Remedy = 'install the GitHub CLI in the image' },
        @{ Name = 'openssl'; Candidates = @('openssl');           Required = $false; Remedy = 'only published as a packaged application, so it is installed by Install-WorkloadTooling rather than baked into the image' },
        # Windows-only
        @{ Name = 'nuget';   Candidates = @('nuget');             Required = $false; Remedy = 'install the NuGet CLI in the image' },
        @{ Name = 'winapp';  Candidates = @('winapp');            Required = $false; Remedy = 'only published as a packaged application, so it is installed by Install-WorkloadTooling rather than baked into the image' },
        @{ Name = 'winget';  Candidates = @('winget');            Required = $false; AllowStoreAlias = $true; Remedy = 'install the Windows Package Manager (App Installer) in the image' },
        @{ Name = 'scoop';   Candidates = @('scoop');             Required = $false; Remedy = 'install Scoop in the image' },
        @{ Name = 'choco';   Candidates = @('choco');             Required = $false; Remedy = 'install Chocolatey in the image' }
    )

    $missing = @()
    foreach ($tool in $interpreters) {
        $resolved = $null
        foreach ($candidate in $tool.Candidates) {
            # A command resolving into WindowsApps is normally a Microsoft Store
            # AppExecutionAlias stub: a 0-byte redirect that opens the Store
            # rather than running, which the suite deliberately ignores.
            #
            # WindowsApps is also how App Installer legitimately delivers winget,
            # and a working alias is indistinguishable from a stub by path or by
            # size (both are 0-byte reparse points). So entries that ship that
            # way opt out of the filter via AllowStoreAlias; blanket-filtering
            # them reports an installed tool as missing.
            #
            # -All is required: a stub shadows the real interpreter whenever
            # WindowsApps precedes the install directory on PATH, and without
            # every match the search would stop at the stub and report a tool
            # that is installed as absent.
            $found = Get-Command $candidate -All -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Source -and ($tool['AllowStoreAlias'] -or $_.Source -notlike '*\WindowsApps\*')
                } |
                Select-Object -First 1
            if ($found) {
                $resolved = $found.Source
                break
            }
        }
        if ($resolved) {
            Write-Host "Workload interpreter '$($tool.Name)' found at $resolved"
        } elseif ($tool.Required) {
            $missing += "$($tool.Name) ($($tool.Remedy))"
        } else {
            Write-Host "::warning::Workload interpreter '$($tool.Name)' is absent ($($tool.Remedy))"
        }
    }

    if ($missing) {
        Exit-WithError "Workload interpreters missing from this image: $($missing -join '; ')"
    }
}

# Returns whether winget can actually run, which is not the same as being on
# PATH: an unregistered App Installer leaves an alias that resolves and then
# fails to launch. The explicit alias path is a second candidate because
# PowerShell caches command lookups, so a repair inside this process is not
# guaranteed to be visible through Get-Command.
function Test-WingetOperational {
    $candidates = @()
    $command = Get-Command winget -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        try {
            $version = & $candidate --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $version) {
                Write-Host "winget is operational ($($version | Select-Object -First 1)) at $candidate"
                $script:WingetPath = $candidate
                return $true
            }
        } catch {
            # A broken alias throws rather than returning an exit code.
        }
    }
    return $false
}

# winget ships as an AppExecutionAlias belonging to the App Installer package.
# CI images routinely carry the package while leaving it unregistered for the
# account the job runs as, which produces an alias that resolves on PATH but
# fails with "The file cannot be accessed by the system". Registering the
# package already on the image is the documented repair and downloads nothing.
#
# This is the one exception to the verify-never-install rule above, and only
# barely: it installs nothing, it re-registers what the image already shipped.
# It is best effort -- winget is optional, so nothing here fails the job.
function Repair-Winget {
    if (Test-WingetOperational) {
        return
    }

    Write-Host "winget did not run; checking whether the App Installer package is present."

    $package = $null
    try {
        $package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
            Select-Object -First 1
    } catch {
        Write-Host "::warning::Could not query Appx packages, so winget cannot be repaired: $($_.Exception.Message)"
        return
    }

    if (-not $package) {
        Write-Host "::warning::winget is unavailable and the App Installer package is absent; install it in the image."
        return
    }

    Write-Host "App Installer $($package.Version) is present (status $($package.Status)); registering it for the current user."
    try {
        # PackageFamilyName is Microsoft.DesktopAppInstaller_8wekyb3d8bbwe, read
        # off the package rather than hard-coded.
        Add-AppxPackage -RegisterByFamilyName -MainPackage $package.PackageFamilyName -ErrorAction Stop
    } catch {
        Write-Host "::warning::Could not register the App Installer package: $($_.Exception.Message)"
        return
    }

    if (Test-WingetOperational) {
        Write-Host "winget is operational after registering App Installer."
    } else {
        Write-Host "::warning::winget is still not operational after registering App Installer."
    }
}

# Makes a directory resolvable by this process and by the steps that follow.
function Add-PathEntry {
    param([Parameter(Mandatory)][string]$Directory)

    # Already resolvable in this process means already inherited by the steps
    # that follow, so there is nothing to publish.
    if (($env:Path -split ';') -contains $Directory) {
        return
    }
    $env:Path = "$env:Path;$Directory"

    if ($env:GITHUB_PATH) {
        # Not Add-Content or Out-File: Windows PowerShell's UTF-8 writers emit
        # a BOM, which the runner would read as part of the directory name.
        [System.IO.File]::AppendAllText(
            $env:GITHUB_PATH, "$Directory`r`n", (New-Object System.Text.UTF8Encoding $false))
    }
}

# Appends the registry PATH entries this process has not picked up yet, so a
# directory an installer just published becomes visible to a process that
# otherwise keeps the PATH it started with.
function Update-ProcessPath {
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $env:Path -split ';') {
        if ($entry) { [void]$seen.Add($entry.TrimEnd('\')) }
    }

    foreach ($scope in 'Machine', 'User') {
        $value = [Environment]::GetEnvironmentVariable('Path', $scope)
        if (-not $value) { continue }
        foreach ($entry in $value -split ';') {
            if ($entry -and $seen.Add($entry.TrimEnd('\'))) {
                Add-PathEntry -Directory $entry
            }
        }
    }
}

# Resolves a command the way Assert-WorkloadInterpreters does, so a tool this
# step installs is judged by the same rule that reports it later.
function Resolve-Interpreter {
    param([Parameter(Mandatory)][string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        # -All is required: a Store alias stub shadows the real interpreter
        # whenever WindowsApps precedes the install directory on PATH.
        $found = Get-Command $candidate -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -and $_.Source -notlike '*\WindowsApps\*' } |
            Select-Object -First 1
        if ($found) {
            return $found.Source
        }
    }
    return $null
}

# winget has no floating "latest Python 3" package: every minor is published
# under its own id, so the newest one the source offers is resolved at run time
# rather than pinned here and left to rot.
function Get-LatestPythonPackageId {
    $fallback = 'Python.Python.3.14'
    if (-not $script:WingetPath) { return $fallback }

    try {
        $output = & $script:WingetPath search --id 'Python.Python.3.' --source winget `
            --accept-source-agreements --disable-interactivity 2>&1 | Out-String
    } catch {
        return $fallback
    }

    # Read the ids straight out of the result table instead of parsing its
    # columns, whose widths and headers move with console width and locale.
    $minors = [regex]::Matches($output, 'Python\.Python\.3\.(\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value }
    if (-not $minors) {
        Write-Host "::warning::No Python package ids in the winget source; falling back to $fallback."
        return $fallback
    }

    return "Python.Python.3.$(($minors | Measure-Object -Maximum).Maximum)"
}

# The workload interpreters a job installs rather than inherits from its image,
# plus the two tools that cannot be baked into an image at all: openssl and the
# Windows App Development CLI are published only as packaged applications, and
# no packaged application can be registered while an image is being
# provisioned. All of them are installed on the running machine, which is the
# first point at which winget works.
#
# Every entry asks winget for a conventional installer. A packaged build would
# land behind a WindowsApps execution alias, which is indistinguishable from a
# Store stub and so is not counted as present by the inventory that follows.
# Microsoft.PowerShell in particular offers its msixbundle first, so the
# installer type is stated rather than left to winget's own ranking.
#
# pwsh is the one entry whose failure is fatal: the steps after this one run in
# it. The rest are best effort -- a failure warns, and the inventory that
# follows reports what the machine actually ended up with.
function Install-WorkloadTooling {
    # 0 is success; the other two are "already installed" and "no applicable
    # upgrade", which both mean the tool is present and are equally fine.
    $success = @(0, -1978335135, -1978335189)

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if (-not $programFilesX86) { $programFilesX86 = $env:ProgramFiles }

    $packages = @(
        @{
            Name       = 'pwsh'
            Candidates = @('pwsh')
            Id         = 'Microsoft.PowerShell'
            Required   = $true
            Extra      = @('--installer-type', 'wix', '--scope', 'machine')
            PathHints  = @((Join-Path $env:ProgramFiles 'PowerShell\7'))
        },
        @{
            Name       = 'node'
            Candidates = @('node')
            # Tracks whichever release line is current LTS; npm and npx ship
            # with it.
            Id         = 'OpenJS.NodeJS.LTS'
            Required   = $false
            Extra      = @('--installer-type', 'wix', '--scope', 'machine')
            PathHints  = @((Join-Path $env:ProgramFiles 'nodejs'))
        },
        @{
            Name       = 'python'
            Candidates = @('python', 'python3')
            Id         = Get-LatestPythonPackageId
            Required   = $false
            # The bundle prepends its own directories to PATH, but the
            # directory name carries the architecture, so the hints cover the
            # case where it did not.
            Extra      = @('--installer-type', 'burn', '--scope', 'machine')
            PathHints  = @(
                (Join-Path $env:ProgramFiles 'Python3*'),
                (Join-Path $env:ProgramFiles 'Python3*\Scripts')
            )
        },
        @{
            Name       = 'winapp'
            Candidates = @('winapp')
            Id         = 'Microsoft.WinAppCli'
            Required   = $false
            # The portable build puts a real executable on PATH; the packaged
            # one would only put an execution alias there.
            Extra      = @('--installer-type', 'zip')
            PathHints  = @(
                (Join-Path $env:ProgramFiles 'WinGet\Links'),
                (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links')
            )
        },
        @{
            Name       = 'openssl'
            Candidates = @('openssl')
            Id         = 'ShiningLight.OpenSSL.Light'
            Required   = $false
            Extra      = @()
            # This installer does not publish its own bin directory, and names
            # it for the architecture it built for.
            PathHints  = @(
                (Join-Path $env:ProgramFiles 'OpenSSL*\bin'),
                (Join-Path $programFilesX86 'OpenSSL*\bin')
            )
        }
    )

    $wanted = $packages | Where-Object { -not (Resolve-Interpreter -Candidates $_.Candidates) }
    if (-not $wanted) {
        Write-Host "Workload tooling is already present."
        $global:LASTEXITCODE = 0
        return
    }

    if (-not $script:WingetPath) {
        $message = "winget is unavailable, so $(($wanted.Name) -join ', ') cannot be installed."
        if ($wanted | Where-Object { $_.Required }) {
            Exit-WithError "$message Repair the App Installer package on the runner image."
        }
        Write-Host "::warning::$message"
        $global:LASTEXITCODE = 0
        return
    }

    foreach ($package in $wanted) {
        Write-Host "Installing $($package.Name) ($($package.Id))."
        $arguments = @(
            'install', '--id', $package.Id, '--exact', '--silent',
            '--disable-interactivity', '--accept-source-agreements',
            '--accept-package-agreements', '--source', 'winget'
        ) + $package.Extra

        try {
            $output = & $script:WingetPath @arguments 2>&1
            $code = $LASTEXITCODE
        } catch {
            $detail = ($_.Exception.Message -split "`r?`n" | Select-Object -First 1).Trim()
            if ($package.Required) {
                Exit-WithError "Could not install $($package.Name): $detail"
            }
            Write-Host "::warning::Could not install $($package.Name): $detail"
            continue
        }

        if ($success -notcontains $code) {
            $detail = ($output | Select-Object -Last 3 | Out-String).Trim()
            if ($detail) { Write-Host $detail }
            if ($package.Required) {
                Exit-WithError "Installing $($package.Name) reported exit code $code."
            }
            Write-Host "::warning::Installing $($package.Name) reported exit code $code."
            continue
        }

        Update-ProcessPath
        # Hints may be wildcards: an installer's directory name can carry the
        # architecture (Python314-arm64, OpenSSL-Win64-ARM), so the pattern
        # matches whichever one this host actually got.
        foreach ($hint in $package.PathHints) {
            foreach ($match in (Resolve-Path -Path $hint -ErrorAction SilentlyContinue)) {
                if (Test-Path -LiteralPath $match.Path -PathType Container) {
                    Add-PathEntry -Directory $match.Path
                }
            }
        }

        $resolved = Resolve-Interpreter -Candidates $package.Candidates
        if ($resolved) {
            Write-Host "$($package.Name) is available at $resolved"
        } elseif ($package.Required) {
            Exit-WithError "$($package.Name) installed but still does not resolve on PATH."
        } else {
            Write-Host "::warning::$($package.Name) installed but still does not resolve on PATH (searched $($package.PathHints -join ', '))."
        }
    }

    $global:LASTEXITCODE = 0
}

function Initialize-MicroVmHost {
    # Staged next to wxc-exec.exe by the --features microvm build, so their
    # absence means a broken artifact rather than a host problem. Snapshots are
    # excluded: they are a warm-start cache the runner regenerates on demand.
    Assert-RequiredFile @(
        'wxc-exec.exe',
        'nanvixd.exe',
        'nanvix_rootfs.img',
        'python3.initrd',
        'bin\kernel.elf'
    )

    # NanVix boots a VM from these images on every invocation; Defender scanning
    # them can push boot past its timeout.
    Add-MpPreference -ExclusionPath $BinaryDirectory
    Write-Host "Added Defender exclusion for $BinaryDirectory"

    Write-HypervisorDiagnostic
    Assert-HypervisorPlatform
}

# The optional features must be baked into the pool image (enabling one needs a
# reboot this job cannot take), but the WSL runtime package is installed here if
# missing. Container images are pulled by the suite itself
# (tests/scripts/run_wslc_all_tests.ps1).
function Initialize-WslcHost {
    # wslcsdk.dll ships beside wxc-exec.exe only in a --features wslc build.
    Assert-RequiredFile @('wxc-exec.exe', 'wslcsdk.dll')

    Assert-RequiredFeature -Name 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform' `
        -Remedy 'WSL2 must be baked into the runner image; enabling these features requires a host reboot this job cannot take.'

    Write-Host "=== wsl.exe presence + status ==="
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($wsl) {
        Write-Host "wsl.exe: $($wsl.Source)"
    } else {
        Write-Host "wsl.exe NOT found on PATH"
        Exit-WithError 'WSL2 is not installed on this runner. The runner image must include WSL2 for this backend.'
    }

    $previousEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $output = wsl.exe --status  2>&1 | Out-String
    Write-Host $output
    [Console]::OutputEncoding = $previousEncoding

    # # if unicode output mentions wsl.exe --install, skip version check for now
    if ($output -match 'wsl.exe --install') {
        Exit-WithError 'WSL2 is not installed on this runner. The runner image must include WSL2 for this backend.'
    }

    if ((Invoke-Wsl @('--version') -Quiet) -ne 0) {
        Write-Host 'version command failed, so WSL2 is installed but not updated.'
        Write-Host "=== updating inbox WSL to modern version ==="    

        if ((Invoke-Wsl @('--update', '--web-download') -Quiet) -ne 0 -and
            (Invoke-Wsl @('--update')) -ne 0) {
            Exit-WithError 'wsl --update failed; the WSL2 runtime could not be installed on this runner.'
        }

        if ((Invoke-Wsl @('--version') -Quiet) -ne 0) {
            Exit-WithError 'wsl --version failed after updating; the WSL2 runtime is not usable on this runner.'
        }

        Write-Host 'WSL2 is installed and updated (not prerelease, yet)'
       
    }

    # WSLC needs a runtime at least as new as the pinned WSLC SDK, and those
    # builds ship only on the pre-release ring -- the stable ring lands well
    # behind it. Without this the SDK fails at run time with
    # "WSLC runtime unavailable. Missing components: WslPackage".
    $required = Get-RequiredWslVersion
    $installed = Get-InstalledWslVersion
    if ($null -ne $required -and ($null -eq $installed -or $installed -lt $required)) {
        Write-Host "WSL $installed is older than the $required WSLC requires; updating to pre-release..."
        if ((Invoke-Wsl @('--update', '--pre-release', '--web-download') -Quiet) -ne 0 -and
            (Invoke-Wsl @('--update', '--pre-release')) -ne 0) {
            Exit-WithError "wsl --update --pre-release failed; WSLC requires WSL $required or newer."
        }
        $installed = Get-InstalledWslVersion
    }

    if ($null -eq $installed) {
        Exit-WithError 'wsl --version failed after updating; the WSL2 runtime is not usable on this runner.'
    }
    if ($null -ne $required -and $installed -lt $required) {
        Exit-WithError "WSL $installed is installed, but WSLC requires $required or newer."
    }
    Write-Host "WSL runtime $installed is ready (WSLC requires $required or newer)."

    Write-Host "=== done. ===" 
}

# Minimum WSL runtime for WSLC, read from the pinned SDK version so the two
# cannot drift. The SDK's own runtime error names this same version.
function Get-RequiredWslVersion {
    $buildScript = Join-Path $PSScriptRoot '..\..\src\backends\wslc\common\build.rs'
    if (-not (Test-Path $buildScript)) {
        Write-Host "WARNING: $buildScript not found; skipping the WSL version gate."
        return $null
    }

    $match = [regex]::Match((Get-Content $buildScript -Raw), 'WSLC_SDK_VERSION:\s*&str\s*=\s*"([0-9]+(?:\.[0-9]+)+)"')
    if (-not $match.Success) {
        Write-Host 'WARNING: could not parse WSLC_SDK_VERSION; skipping the WSL version gate.'
        return $null
    }
    return [version]$match.Groups[1].Value
}

# Installed modern-runtime version, or $null when wsl.exe is the legacy inbox
# build (no --version) or otherwise unusable.
function Get-InstalledWslVersion {
    $result = Invoke-WslCapture -Arguments @('--version')
    if ($result.ExitCode -ne 0) {
        return $null
    }

    $match = [regex]::Match($result.Output, '(?im)^\s*WSL version:\s*([0-9]+(?:\.[0-9]+)+)')
    if (-not $match.Success) {
        return $null
    }
    return [version]$match.Groups[1].Value
}


# wsl.exe emits UTF-16LE, which the default console encoding renders as
# null-separated garbage. Returns @{ ExitCode; Output } with the output decoded.
function Invoke-WslCapture {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $output = & wsl.exe @Arguments 2>&1 | Out-String
        return @{ ExitCode = $LASTEXITCODE; Output = $output }
    } catch {
        return @{ ExitCode = 1; Output = "wsl.exe could not be run: $($_.Exception.Message)" }
    } finally {
        [Console]::OutputEncoding = $previousEncoding
    }
}

# Run wsl.exe and return its exit code. -Quiet suppresses output for probes,
# where the legacy wsl.exe dumps its whole usage text on an unknown switch.
function Invoke-Wsl {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Quiet
    )

    $result = Invoke-WslCapture -Arguments $Arguments
    if (-not $Quiet -and $result.Output.Trim()) {
        Write-Host $result.Output.Trim()
    }
    return $result.ExitCode
}

if (-not (Test-Path $BinaryDirectory)) {
    Exit-WithError "Binary directory not found: $BinaryDirectory"
}
$BinaryDirectory = (Resolve-Path $BinaryDirectory).Path

Write-Host "Preparing Windows host for backend '$Backend' using $BinaryDirectory"

Write-HostOsVersion

# Run for every backend: this is host inventory, not a backend prerequisite.
# The winget repair comes first so the tooling install below can use it, and
# the inventory reports the state after both.
Repair-Winget
Install-WorkloadTooling
Assert-WorkloadInterpreters

switch ($Backend) {
    'process-t1' { Initialize-ProcessContainerHost }
    'process-t3' { Initialize-ProcessContainerHost }
    'microvm' { Initialize-MicroVmHost }
    'wslc' { Initialize-WslcHost }
    default { Write-Host "$Backend has no artifact-only Windows test prerequisites yet." }
}
