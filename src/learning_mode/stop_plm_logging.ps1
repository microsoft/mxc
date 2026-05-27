
#Param for file locations
param(
    [string]$LogDir = (Join-Path $PSScriptRoot "logs" (Get-Date -Format "yyyy-MM-dd_HHmmss")),
    [string]$BinPath = ([System.IO.Path]::GetFullPath($PSScriptRoot)),
    [string]$ConfigPath,

    # When set, per-event and per-ACE diagnostic lines are emitted to the
    # host. Off by default so the script's host output is limited to the
    # summary sections (requested capabilities, included/skipped caps).
    [switch]$VerboseLogging
)

# Gate for the script-wide Write-Host wrapper below.
$script:VerboseLogEnabled = [bool]$VerboseLogging

# Write-Host wrapper: emits only when -VerboseLogging is set. Every
# Write-Host call below routes through this so a non-verbose run produces
# no host output at all.
function Write-VHost {
    param(
        [Parameter(Position = 0)][AllowEmptyString()][string] $Message = '',
        [string] $ForegroundColor
    )
    if (-not $script:VerboseLogEnabled) { return }
    if ($ForegroundColor) { Write-Host $Message -ForegroundColor $ForegroundColor }
    else                  { Write-Host $Message }
}

class LearningModeAccessEvent {
    [datetime]$TimeCreated
    [int]     $ProcessId
    [int]     $ThreadId
    [string]  $LearningMode
    [string]  $ResourceType
    [string]  $FilePath
    [string]  $AppPath
    [uint32]  $AccessMask

    LearningModeAccessEvent(
        [datetime]$timeCreated,
        [int]     $processId,
        [int]     $threadId,
        [string]  $learningMode,
        [string]  $resourceType,
        [string]  $filePath,
        [string]  $appPath,
        [uint32]  $accessMask
    ) {
        $this.TimeCreated  = $timeCreated
        $this.ProcessId    = $processId
        $this.ThreadId     = $threadId
        $this.LearningMode = $learningMode # Permissive/Enforcing
        $this.ResourceType = $resourceType # File/Directory
        $this.FilePath     = $filePath
        $this.AppPath      = $appPath
        $this.AccessMask   = $accessMask
    }
}

$TraceFile = Join-Path $LogDir "trace.etl"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
# Event ID 14 is permissive learning mode file accessfailure.

wpr -stop $TraceFile

write-vhost "Beginning event parsing, this may take several minutes"

$events = get-winevent -path $TraceFile -Oldest -FilterXPath "*[System[EventID=14 or EventID=27]]"

. (Join-Path $PSScriptRoot 'event_dacl_parser.ps1')

$parseResult = Invoke-EventDaclParser -Events $events -VerboseLogging:$VerboseLogging

[LearningModeAccessEvent[]]$ValidAccessEvents = $parseResult.ValidAccessEvents.ToArray()
$AllRequestedCapabilities                     = $parseResult.RequestedCapabilities
$NeedUI                                       = $parseResult.NeedUI

Write-VHost ""
Write-VHost ("All requested capabilities ({0}):" -f $AllRequestedCapabilities.Count) -ForegroundColor Cyan
if ($AllRequestedCapabilities.Count -gt 0) {
    $AllRequestedCapabilities | Sort-Object | ForEach-Object { Write-VHost "  $_" }
} else {
    Write-VHost "  (none)"
}

# Write Masks
$FileWriteMask = 0x2
$FileAppendMask = 0x4
$WriteExtendedAttributeWriteMask = 0x10
$DirectoryDeleteMask = 0x40 
$WriteAttributeWriteMask = 0x100
$FileDeleteMask = 0x10000 
$FileWriteDAC = 0x40000
$FileWriteOwner = 0x80000

$WriteMask = $FileWriteMask -bor $FileAppendMask -bor $WriteAttributeWriteMask -bor $WriteExtendedAttributeWriteMask -bor $DirectoryDeleteMask -bor $FileDeleteMask -bor $FileWriteDAC -bor $FileWriteOwner

# Read Masks
$ReadDataMask = 0x1
$ReadExtendedAttributeMask = 0x8
$DirectoryTraverseMask = 0x20
$ReadAttributeMask = 0x80
$ReadControlMask = 0x20000
$SynchronizeMask = 0x100000

$ReadMask = $ReadDataMask -bor $ReadExtendedAttributeMask -bor $DirectoryTraverseMask -bor $ReadAttributeMask -bor $ReadControlMask -bor $SynchronizeMask

# Only process config changes if we have a valid config path and at least one access event
# or at least one requested capability.
if ($ConfigPath -and (($ValidAccessEvents.Count -gt 0) -or ($AllRequestedCapabilities.Count -gt 0)))
{
    # Copy original config
    $destConfig = Join-Path $logDir (Split-Path $ConfigPath -Leaf)
    Copy-Item -Path $ConfigPath -Destination $destConfig -Force
    $config = Get-Content $destConfig -Raw | ConvertFrom-Json

    if (-not $config.PSObject.Properties['filesystem']) {
        $config | Add-Member -NotePropertyName filesystem -NotePropertyValue ([pscustomobject]@{})
    }

    if (-not $config.filesystem.PSObject.Properties['readwritePaths']) {
        $config.filesystem | Add-Member -NotePropertyName readwritePaths -NotePropertyValue @()
    }

    if (-not $config.filesystem.PSObject.Properties['readonlyPaths']) {
        $config.filesystem | Add-Member -NotePropertyName readonlyPaths -NotePropertyValue @()
    }

    $denyFileSet = [System.Collections.Generic.HashSet[string]]::new()
    if ( $config.filesystem.PSObject.Properties['deniedPaths']) 
    {
        #import all existing denied paths into a hashset for easy lookup when processing events
        foreach ($path in $config.filesystem.deniedPaths)
        {
            $denyFileSet.Add($path) | Out-Null
        }
    }

    # Track entries appended to the readwritePaths / readonlyPaths arrays
    # during the loop below. These lists are printed unconditionally at the
    # end of the script (regardless of -VerboseLogging) so the operator
    # always sees what was learned. Order-preserving with case-insensitive
    # dedupe so the same path isn't reported twice.
    $addedReadWritePaths     = New-Object 'System.Collections.Generic.List[string]'
    $addedReadOnlyPaths      = New-Object 'System.Collections.Generic.List[string]'
    $addedReadWriteSeen      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $addedReadOnlySeen       = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ev in $ValidAccessEvents)
    {
        $ignoreCurrentFile = $false
        # write-host "$($ev.AppPath) requested $($ev.FilePath) with access mask: $($ev.AccessMask)"

        if ($ev.FilePath.Equals($BinPath, [StringComparison]::OrdinalIgnoreCase)) 
        {
            Write-VHost "File $($ev.FilePath) is the binary path, skipping event." -ForegroundColor Yellow
            continue
        }

        # Check if the file is in a deny path
        foreach ($path in $denyFileSet) 
        {
            if ($ev.FilePath.StartsWith($path)) 
            {
                # This file is already denied, so we skip it.
                $ignoreCurrentFile = $true
                break
            }
        }

        # Another file has already been marked as readwrite in the same directory.
        foreach ($path in $config.filesystem.readwritePaths) 
        {
            if ($ev.FilePath.StartsWith($path)) 
            {
                # a parent directory is already marked as readwrite, so we skip this file.
                $ignoreCurrentFile = $true
                break
            }
        }

        if ($ignoreCurrentFile) 
        {
            continue
        }

        # Process Write Requests
        if (-not $ignoreCurrentFile -and ($ev.AccessMask -band $WriteMask))
        {
            # Since writing to files require parent directory access, we only look at the parent directory
            if (test-path -PathType leaf $ev.FilePath) 
            {
                $parent = Split-Path $ev.FilePath -Parent
            }
            if (test-path -PathType container $ev.FilePath) 
            {
                $parent = $ev.FilePath
            }
            
            # Writing to files requires readwrite for the parent directory. 
            $config.filesystem.readwritePaths += $parent
            if ($addedReadWriteSeen.Add($parent)) { $addedReadWritePaths.Add($parent) }
            continue
        }

        if (-not $ignoreCurrentFile -and ($ev.AccessMask -band $ReadMask))
        {

            foreach ($path in $config.filesystem.readonlyPaths) 
            {
                if ($ev.FilePath.StartsWith($path)) 
                {
                    # a parent directory is already marked as readonly, so we skip this file.
                    # write-host "File $($ev.FilePath) is already marked as readonly by parent path $path, skipping event." -ForegroundColor Yellow
                    $ignoreCurrentFile = $true
                    break
                }
            }
            if ($ignoreCurrentFile) 
            {
                continue
            }

            $config.filesystem.readonlyPaths += $ev.FilePath
            if ($addedReadOnlySeen.Add($ev.FilePath)) { $addedReadOnlyPaths.Add($ev.FilePath) }
            continue
        }
    }

    # Merge any capabilities discovered while parsing DACL ACE bytes into
    # the containment-specific block, e.g. config.processContainer.capabilities.
    if ($AllRequestedCapabilities.Count -gt 0)
    {

        $containmentName = [string]$config.containment
        if (-not [string]::IsNullOrWhiteSpace($containmentName)) {
            # Locate the containment sub-object case-insensitively so we don't
            # accidentally create a duplicate property when the JSON uses
            # camelCase (e.g. "processContainer") and containment is lowercase.
            $containmentProp = $config.PSObject.Properties |
                Where-Object { $_.Name -ieq $containmentName } |
                Select-Object -First 1

            if (-not $containmentProp) {
                $config | Add-Member -NotePropertyName $containmentName -NotePropertyValue ([pscustomobject]@{})
                $containmentObj = $config.$containmentName
            } else {
                $containmentObj = $containmentProp.Value
                if ($null -eq $containmentObj) {
                    $containmentObj = [pscustomobject]@{}
                    $config.($containmentProp.Name) = $containmentObj
                }
            }

            if (-not $containmentObj.PSObject.Properties['capabilities']) {
                $containmentObj | Add-Member -NotePropertyName capabilities -NotePropertyValue @()
            }

            # Dedupe against existing entries (case-insensitive). Track which
            # requested capabilities were newly included vs. skipped because
            # they were already in the config.
            $existingCaps = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($existing in $containmentObj.capabilities) {
                if (-not [string]::IsNullOrWhiteSpace($existing)) { [void]$existingCaps.Add([string]$existing) }
            }

            $includedCaps = New-Object 'System.Collections.Generic.List[string]'
            $skippedCaps  = New-Object 'System.Collections.Generic.List[string]'
            foreach ($cap in $AllRequestedCapabilities) {
                if ($existingCaps.Add($cap)) {
                    $includedCaps.Add($cap)
                } else {
                    $skippedCaps.Add($cap)
                }
            }

            $containmentObj.capabilities = @($existingCaps | Sort-Object)

            # Always display which capabilities were added, even when -Verboselogging  is not set
            Write-VHost ""
            if ($includedCaps.Count -gt 0) {
                write-Host ("Capabilities included into '$containmentName.capabilities' ({0}):" -f $includedCaps.Count) -ForegroundColor Green
                $includedCaps | Sort-Object | ForEach-Object { write-Host "  + $_" -ForegroundColor Green }
            } else {
                Write-VHost "  (none)"
            }

            if ($skippedCaps.Count -gt 0) {
                Write-VHost ("Capabilities skipped (already present) ({0}):" -f $skippedCaps.Count) -ForegroundColor Yellow
                $skippedCaps | Sort-Object | ForEach-Object { Write-VHost "  = $_" -ForegroundColor Yellow }
            } else {
                Write-VHost "  (none)"
            }
        }
    }

    if ($NeedUI) 
    {
        if (-not $config.PSObject.Properties['ui']) {
            $config | Add-Member -NotePropertyName ui -NotePropertyValue ([pscustomobject]@{})
        }
        if (-not $config.ui.PSObject.Properties['disable']) {
            $config.ui | Add-Member -NotePropertyName disable -NotePropertyValue $true
        }
        else {
            $config.ui.disable = $false
        }

        Write-Host ("Enabling access to GUI subsystem ") -ForegroundColor Cyan
    }

    # Write out new config next to original with adjusted_ prefix.
    $adjustedPath = Join-Path (Split-Path $destConfig -Parent) ("Adjusted_" + (Split-Path $destConfig -Leaf))
    Set-Content -Path $adjustedPath -Value ($config | ConvertTo-Json -Depth 10)

    # Unconditional summary of filesystem entries added during this run.
    # Uses Write-Host directly (not Write-VHost) so it always prints even
    # when -VerboseLogging is not set.
    Write-Host ""
    if ($addedReadWritePaths.Count -gt 0) {
        Write-Host ("Added to readwritePaths ({0}):" -f $addedReadWritePaths.Count) -ForegroundColor Cyan
        foreach ($p in $addedReadWritePaths) { Write-Host "  + $p" -ForegroundColor Cyan }
    }

    if ($addedReadOnlyPaths.Count -gt 0) {
        Write-Host ("Added to readonlyPaths ({0}):" -f $addedReadOnlyPaths.Count) -ForegroundColor Cyan
        foreach ($p in $addedReadOnlyPaths) { Write-Host "  + $p" -ForegroundColor Cyan }
    }
}

