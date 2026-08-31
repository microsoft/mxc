#Requires -Version 5.1

<#
.SYNOPSIS
    Installation script for MXC Windows machines.

.DESCRIPTION
    Installs the command-line tooling an MXC machine is expected to provide:
    Chocolatey, Scoop, the Azure CLI, the GitHub CLI and the NuGet CLI.

    Everything is installed from an official installer or install script that
    is downloaded directly. The Windows Package Manager is deliberately not
    used and no packaged application is registered, because neither is
    available while an image is being provisioned. Tooling that is only
    published as a packaged application is installed later, when the machine
    is running, rather than here.

    The .NET SDK, Node.js, Python, PowerShell 7 and Git arrive with the image
    from other provisioning artifacts rather than being installed here, but
    they are still inventoried at the end so the image is reported on as a
    whole.

    Every step is best effort. Nothing here aborts the run and the script always
    exits 0; what the machine actually ended up with is printed in the summary
    at the end.

    Installs are machine-scoped and every directory this script adds to PATH is
    added to the machine PATH, because the account that runs workloads later is
    usually not the account that runs this script.

.EXAMPLE
    ./Setup.ps1

.EXAMPLE
    ./Setup.ps1 -Architecture arm64
#>

[CmdletBinding()]
param(
    # The machine's processor architecture, which selects the installer variant
    # to download. Defaults to what this machine reports.
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }),

    # Where Scoop is installed. Deliberately outside a user profile so every
    # account on the machine can reach it.
    [string]$ScoopRoot = 'C:\Scoop'
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Provisioning is best effort: an unexpected terminating error reports what went
# wrong and still leaves the image in a usable state, so the exit code is always 0.
trap {
    Write-Host ''
    Write-Host "Setup stopped early: $($_.Exception.Message)"
    Write-Host "  at $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"
    Write-Host 'Setup finished.'
    exit 0
}

# TLS 1.2 is not the default on older hosts and every download below is HTTPS.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # A host that pins its own protocols is left alone.
}

$script:Notes = New-Object System.Collections.Generic.List[string]
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Scratch = Join-Path ([IO.Path]::GetTempPath()) ("mxc-setup-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "=== $Message ==="
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "OK: $Message"
}

function Write-Note {
    param([Parameter(Mandatory)][string]$Message)
    # An exception message can span lines; the summary reads better on one.
    $flat = ($Message -replace '\s+', ' ').Trim()
    Write-Host "NOTE: $flat"
    $script:Notes.Add($flat)
}

function Write-Failure {
    param([Parameter(Mandatory)][string]$Message)
    $flat = ($Message -replace '\s+', ' ').Trim()
    Write-Host "FAILED: $flat"
    $script:Failures.Add($flat)
}

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

# Installers edit the stored PATH, not this process's copy of it. Re-reading it
# is what lets a tool installed a moment ago be found by the step after it.
function Update-ProcessPath {
    $parts = @()
    foreach ($scope in 'Machine', 'User') {
        $value = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ($value) { $parts += $value }
    }
    if ($parts.Count -gt 0) {
        $env:Path = ($parts -join ';')
    }
}

# Adds a directory to the machine PATH if it exists and is not already there.
function Add-MachinePath {
    param([Parameter(Mandatory)][string]$Directory)

    if (-not (Test-Path -LiteralPath $Directory)) {
        return $false
    }

    $normalized = $Directory.TrimEnd('\')
    $current = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = @()
    if ($current) {
        $entries = $current -split ';' | Where-Object { $_ -and $_.Trim() }
    }

    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\') -ieq $normalized) {
            Update-ProcessPath
            return $true
        }
    }

    try {
        $updated = (@($entries) + $normalized) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $updated, 'Machine')
        Update-ProcessPath
        Write-Ok "added '$normalized' to the machine PATH."
        return $true
    } catch {
        Write-Failure "could not add '$normalized' to the machine PATH: $($_.Exception.Message.Trim())"
        return $false
    }
}

# Resolves a command the same way the workload inventory does. A command that
# resolves inside WindowsApps is normally an execution-alias stub that opens the
# Store rather than running, so it does not count as present unless the tool is
# known to ship that way.
function Resolve-Tool {
    param(
        [Parameter(Mandatory)][string[]]$Candidates,
        [switch]$AllowStoreAlias
    )

    foreach ($candidate in $Candidates) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found -and ($AllowStoreAlias -or $found.Source -notlike '*\WindowsApps\*')) {
            return $found.Source
        }
    }
    return $null
}

function Test-Tool {
    param([Parameter(Mandatory)][string[]]$Candidates)
    return [bool](Resolve-Tool -Candidates $Candidates)
}

# Runs a program and reports only whether it succeeded, keeping installer chatter
# out of the transcript unless something goes wrong.
function Invoke-Program {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int[]]$SuccessCodes = @(0)
    )

    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
        if ($SuccessCodes -contains $code) {
            return $true
        }
        $detail = ($output | Select-Object -Last 3 | Out-String).Trim()
        if ($detail) {
            Write-Host "  $($detail -replace "`r?`n", "`n  ")"
        }
        Write-Host "  exit code $code"
        return $false
    } catch {
        # A native launch failure embeds a position trace after the first line.
        $reason = ($_.Exception.Message -split "`r?`n" | Select-Object -First 1).Trim()
        Write-Host "  $reason"
        return $false
    }
}

function Get-Download {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile
    )

    try {
        if (-not (Test-Path -LiteralPath $script:Scratch)) {
            New-Item -ItemType Directory -Path $script:Scratch -Force | Out-Null
        }
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 600
        return (Test-Path -LiteralPath $OutFile)
    } catch {
        Write-Host "  $($_.Exception.Message.Trim())"
        return $false
    }
}

function Install-Msi {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Name
    )

    $package = Join-Path $script:Scratch $Name
    if (-not (Get-Download -Uri $Uri -OutFile $package)) {
        return $false
    }
    return (Invoke-Program -FilePath 'msiexec.exe' -Arguments @('/i', $package, '/quiet', '/norestart') -SuccessCodes @(0, 3010))
}

# ---------------------------------------------------------------------------
# Machine
# ---------------------------------------------------------------------------

Write-Step 'Machine'
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Host "Windows      : $($os.Caption) $($os.Version)"
} catch {
    Write-Host "Windows      : $([Environment]::OSVersion.VersionString)"
}
Write-Host "Architecture : $env:PROCESSOR_ARCHITECTURE"
Write-Host "PowerShell   : $($PSVersionTable.PSVersion)"
Write-Host "User         : $([Environment]::UserName)"

$isAdministrator = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    # Left false; the warning below covers it.
}
Write-Host "Elevated     : $isAdministrator"

if (-not $isAdministrator) {
    Write-Note 'this session is not elevated; machine-wide installs and PATH changes will not take effect.'
}

Update-ProcessPath

# Install-Tool orchestrates one tool: skip if already present, otherwise work
# through the attempts in order, re-checking after each. PATH is refreshed
# between attempts because an installer's PATH edit is not visible to this
# process until it is re-read.
function Install-Tool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Candidates,
        [Parameter(Mandatory)][hashtable[]]$Attempts,
        [string[]]$PathCandidates = @()
    )

    Write-Step "Installing $Name"

    if (Test-Tool -Candidates $Candidates) {
        Write-Ok "$Name is already present at $(Resolve-Tool -Candidates $Candidates)."
        return
    }

    foreach ($attempt in $Attempts) {
        Write-Host "Trying $($attempt.Description)..."
        $succeeded = $false
        try {
            $succeeded = [bool](& $attempt.Action)
        } catch {
            Write-Host "  $($_.Exception.Message.Trim())"
        }

        Update-ProcessPath
        foreach ($directory in $PathCandidates) {
            if (Test-Path -LiteralPath $directory) {
                Add-MachinePath -Directory $directory | Out-Null
            }
        }

        $resolved = Resolve-Tool -Candidates $Candidates
        if ($resolved) {
            Write-Ok "$Name is available at $resolved."
            return
        }
        if ($succeeded) {
            Write-Host "  reported success but '$($Candidates[0])' still does not resolve."
        }
    }

    Write-Failure "could not install $Name."
}

# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------

# Installed first so the tools below can fall back to them.

Install-Tool -Name 'Chocolatey' -Candidates @('choco') -PathCandidates @(
    (Join-Path $env:ProgramData 'chocolatey\bin')
) -Attempts @(
    @{
        Description = 'the official install script'
        Action      = {
            $installer = Join-Path $script:Scratch 'install-chocolatey.ps1'
            if (-not (Get-Download -Uri 'https://community.chocolatey.org/install.ps1' -OutFile $installer)) {
                return $false
            }
            $env:ChocolateyUseWindowsCompression = 'false'
            & $installer | Out-Null
            return $true
        }
    }
)

Install-Tool -Name 'Scoop' -Candidates @('scoop') -PathCandidates @(
    (Join-Path $ScoopRoot 'shims')
) -Attempts @(
    @{
        Description = 'the official install script'
        Action      = {
            # Scoop is normally per-user, which would hide it from the account
            # that runs workloads later. Pointing it at a fixed directory and
            # publishing that location machine-wide is what makes it shared.
            try {
                [Environment]::SetEnvironmentVariable('SCOOP', $ScoopRoot, 'Machine')
            } catch {
                # Without machine scope the install still succeeds; only the
                # variable is missing for other accounts.
                Write-Host '  could not publish SCOOP machine-wide.'
            }
            $env:SCOOP = $ScoopRoot

            $installer = Join-Path $script:Scratch 'install-scoop.ps1'
            if (-not (Get-Download -Uri 'https://get.scoop.sh' -OutFile $installer)) {
                return $false
            }
            # The installer refuses to run elevated unless told that is intended.
            $arguments = @{ ScoopDir = $ScoopRoot; ScoopGlobalDir = (Join-Path $ScoopRoot 'global') }
            if ($isAdministrator) { $arguments['RunAsAdmin'] = $true }
            & $installer @arguments | Out-Null
            return $true
        }
    }
)

# ---------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------

Install-Tool -Name 'the Azure CLI' -Candidates @('az') -PathCandidates @(
    (Join-Path $env:ProgramFiles 'Microsoft SDKs\Azure\CLI2\wbin'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft SDKs\Azure\CLI2\wbin')
) -Attempts @(
    @{
        Description = 'the official installer'
        # The Azure CLI publishes no ARM64 build, so an ARM64 machine gets the
        # x64 one and runs it emulated.
        Action      = { Install-Msi -Uri 'https://aka.ms/installazurecliwindowsx64' -Name 'azure-cli.msi' }
    },
    @{
        Description = 'Chocolatey'
        Action      = {
            if (-not (Test-Tool -Candidates @('choco'))) { return $false }
            return (Invoke-Program -FilePath 'choco' -Arguments @('install', 'azure-cli', '-y', '--no-progress'))
        }
    }
)

Install-Tool -Name 'the GitHub CLI' -Candidates @('gh') -PathCandidates @(
    (Join-Path $env:ProgramFiles 'GitHub CLI')
) -Attempts @(
    @{
        Description = 'the latest published installer'
        Action      = {
            try {
                $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/cli/cli/releases/latest' `
                    -UseBasicParsing -Headers @{ 'User-Agent' = 'mxc-setup' } -TimeoutSec 120
            } catch {
                Write-Host "  $($_.Exception.Message.Trim())"
                return $false
            }
            # Assets are named by Go's architecture, not Windows'.
            $suffix = if ($Architecture -eq 'arm64') { 'windows_arm64.msi' } else { 'windows_amd64.msi' }
            $asset = $release.assets |
                Where-Object { $_.name -like "*$suffix" } |
                Select-Object -First 1
            if (-not $asset) {
                Write-Host "  no $suffix asset in release $($release.tag_name)."
                return $false
            }
            return (Install-Msi -Uri $asset.browser_download_url -Name 'gh.msi')
        }
    },
    @{
        Description = 'Chocolatey'
        Action      = {
            if (-not (Test-Tool -Candidates @('choco'))) { return $false }
            return (Invoke-Program -FilePath 'choco' -Arguments @('install', 'gh', '-y', '--no-progress'))
        }
    }
)

Install-Tool -Name 'the NuGet CLI' -Candidates @('nuget') -PathCandidates @(
    (Join-Path $env:ProgramData 'MXC\bin')
) -Attempts @(
    @{
        Description = 'a direct download of the standalone executable'
        Action      = {
            # Published as a bare executable rather than a package, so it needs
            # a directory of its own and an entry on PATH.
            $target = Join-Path $env:ProgramData 'MXC\bin'
            if (-not (Test-Path -LiteralPath $target)) {
                New-Item -ItemType Directory -Path $target -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (-not (Test-Path -LiteralPath $target)) {
                Write-Host "  could not create $target."
                return $false
            }
            return (Get-Download -Uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' `
                    -OutFile (Join-Path $target 'nuget.exe'))
        }
    }
)

# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

Update-ProcessPath

Write-Step 'Inventory'

# Everything the finished image is expected to provide, whoever put it there.
# openssl, winapp and winget are the exception: the first two are only published
# as packaged applications and are installed once the machine is running, and
# the third cannot be added to an image at all. They are listed so the log shows
# the whole picture, but they are not counted as missing.
$deferred = @('openssl', 'winapp', 'winget')

$inventory = @(
    @{ Name = 'pwsh';    Candidates = @('pwsh') },
    @{ Name = 'git';     Candidates = @('git') },
    @{ Name = 'node';    Candidates = @('node') },
    @{ Name = 'npm';     Candidates = @('npm') },
    @{ Name = 'npx';     Candidates = @('npx') },
    @{ Name = 'python';  Candidates = @('python', 'python3') },
    @{ Name = 'pip';     Candidates = @('pip', 'pip3') },
    @{ Name = 'dotnet';  Candidates = @('dotnet') },
    @{ Name = 'az';      Candidates = @('az') },
    @{ Name = 'gh';      Candidates = @('gh') },
    @{ Name = 'nuget';   Candidates = @('nuget') },
    @{ Name = 'scoop';   Candidates = @('scoop') },
    @{ Name = 'choco';   Candidates = @('choco') },
    @{ Name = 'openssl'; Candidates = @('openssl') },
    @{ Name = 'winapp';  Candidates = @('winapp') },
    @{ Name = 'winget';  Candidates = @('winget'); AllowStoreAlias = $true }
)

$absent = @()
foreach ($tool in $inventory) {
    $resolved = Resolve-Tool -Candidates $tool.Candidates -AllowStoreAlias:([bool]$tool['AllowStoreAlias'])
    if ($resolved) {
        Write-Host ("  {0,-10} {1}" -f $tool.Name, $resolved)
    } elseif ($deferred -contains $tool.Name) {
        Write-Host ("  {0,-10} absent (installed once the machine is running)" -f $tool.Name)
    } else {
        Write-Host ("  {0,-10} ABSENT" -f $tool.Name)
        $absent += $tool.Name
    }
}

# ---------------------------------------------------------------------------
# Cleanup and summary
# ---------------------------------------------------------------------------

Write-Step 'Cleaning up'
if (Test-Path -LiteralPath $script:Scratch) {
    Remove-Item -LiteralPath $script:Scratch -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Ok 'removed the temporary download directory.'

Write-Step 'Summary'
if ($absent.Count -gt 0) {
    Write-Host "Absent after installation: $($absent -join ', ')"
} else {
    Write-Host 'Every expected program is present.'
}

if ($script:Notes.Count -gt 0) {
    Write-Host ''
    Write-Host 'Notes:'
    foreach ($entry in $script:Notes) { Write-Host "  - $entry" }
}

if ($script:Failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failures:'
    foreach ($entry in $script:Failures) { Write-Host "  - $entry" }
} else {
    Write-Host ''
    Write-Host 'No failures.'
}

Write-Host ''
Write-Host 'A new session is needed for the PATH changes to be visible.'
Write-Host 'Setup finished.'

exit 0
