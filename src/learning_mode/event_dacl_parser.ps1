# event_dacl_parser.ps1
#
# Walks a sequence of WinEvent records produced by the permissive learning
# mode trace and returns:
#   - ValidAccessEvents     : [LearningModeAccessEvent[]] of file-access events
#                              that survived filtering (real, non-self file paths).
#   - RequestedCapabilities : HashSet[string] of capability names discovered by
#                              feeding each event's DACL ACE blob through
#                              extract_caps.ps1.
#   - NeedUI                : $true if any UI event (id 27) was observed.
#
# The LearningModeAccessEvent class is expected to be loaded in the caller's
# runspace (defined in stop_plm_logging.ps1). This script is dot-sourced from
# the caller, so the function lives in the caller's scope and resolves the
# type there. Object instantiation uses New-Object so type lookup happens by
# name at runtime.

# Event property indexes for EventID=14 access events. Defined at script
# scope so they can be tweaked alongside the parser without touching the
# function body or the caller.
$LearningModeIndex         = 0
$ResourceTypeIndex         = 1
$FilePathIndex             = 2
$AppPathIndex              = 3
$AccessMaskIndex           = 5

# Index of the DACL-ACE-bearing ComplexData element on the XML side.
$ComplexDataDaclAceIndex   = 4

# File path we treat as "no useful info" and skip.
$MountPointManager         = "\Device\MountPointManager"

# Current working directory at parse time. Events under this path are
# treated as test/script scaffolding noise and skipped. Captured here (at
# dot-source time) so the value is stable for the whole parser run.
$CurrentDirectory          = (Get-Location).Path.TrimEnd('\')

# Path to extract_caps.ps1. Resolved once at dot-source time relative to this
# script so the function doesn't depend on the caller's current directory.
$ExtractCapsScript         = Join-Path $PSScriptRoot 'extract_caps.ps1'

function Invoke-EventDaclParser {
    [CmdletBinding()]
    param(
        # Array of EventLogRecord objects (e.g. from Get-WinEvent).
        [Parameter(Mandatory = $true)]
        $Events,

        # When set, per-event diagnostic lines (and per-ACE lines from
        # extract_caps.ps1) are emitted via Write-Host. When unset, the
        # parser runs silently and only returns its result object.
        [switch] $VerboseLogging
    )

    if (-not (Test-Path -LiteralPath $ExtractCapsScript)) {
        throw "extract_caps.ps1 not found at '$ExtractCapsScript'."
    }

    # Gate for the per-function Write-Host wrapper below.
    $verboseEnabled = [bool]$VerboseLogging
    function Write-VHost {
        param(
            [Parameter(Position = 0)][AllowEmptyString()][string] $Message = '',
            [string] $ForegroundColor
        )
        if (-not $verboseEnabled) { return }
        if ($ForegroundColor) { Write-Host $Message -ForegroundColor $ForegroundColor }
        else                  { Write-Host $Message }
    }

    # Outputs accumulated below. Generic lists avoid the O(n^2) cost of `+=`
    # on a typed array and let the caller treat the result like any IEnumerable.
    $validAccessEvents        = New-Object 'System.Collections.Generic.List[object]'
    $requestedCapabilities    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $needUI                   = $false

    foreach ($ev in $Events) {
        [xml] $xmlEvent = $ev.ToXml()

        # Event ID 27 is a UI event. It doesn't contribute to filesystem or
        # capability config, but it tells us we need to enable UI later.
        # It currently only means 
        if ($ev.Id -eq 27) {
            Write-VHost "UI Injection event observed"
            $needUI = $true
            continue
        }

        # If the event carries a DACL ACE blob, feed it through extract_caps.ps1
        # and merge any matched capability names into the result set. Some
        # event payloads don't have a populated ComplexData[4] node, so we
        # guard on both presence and non-empty InnerText.
        $complexNode = $xmlEvent.event.EventData.ComplexData[$ComplexDataDaclAceIndex]
        if ($complexNode -and -not [string]::IsNullOrWhiteSpace($complexNode.InnerText)) {
            $caps = & $ExtractCapsScript -HexBytes $complexNode.InnerText -VerboseLogging:$VerboseLogging
            if ($caps) {
                foreach ($c in $caps) { [void]$requestedCapabilities.Add($c) }
            }
        }

        # Remaining events are EventID=14 file-access failures. Pull the
        # file path; absent paths typically indicate capability-resource
        # access events whose capabilities have already been collected from
        # the DACL ACE blob above.
        $filePath = $ev.Properties[$FilePathIndex].Value
        if (-not $filePath) { continue }

        # The MountPointManager device path appears in some events but
        # gives us no actionable information.
        if ($filePath.Equals($MountPointManager, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $filePath = $filePath.Trim()
        # Strip leading "\??\" so the path is in the familiar drive-letter
        # form used elsewhere in the script.
        if ($filePath.StartsWith('\??\', [StringComparison]::Ordinal)) {
            $filePath = $filePath.Substring(4)
        }

        # Skip events targeting the parser's current working directory or
        # anything underneath it -- these are typically the test harness's
        # own scaffolding files, not anything the sandboxed app needs
        # captured into the adjusted config.
        if ($CurrentDirectory) {
            $normalized = $filePath.TrimEnd('\')
            if ($normalized.Equals($CurrentDirectory, [StringComparison]::OrdinalIgnoreCase) -or
                $normalized.StartsWith($CurrentDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) {
                Write-VHost "Skipping current-directory event: $filePath" -ForegroundColor Yellow
                continue
            }
        }

        # Skip events with very short paths that are unlikely to be real file accesses or full drive access
        if ($filePath.Length -lt 4) {
            Write-VHost "Skipping too-short path event: $filePath" -ForegroundColor Yellow
            continue
        }

        # We can only handle drive-letter paths, so skip anything that doesn't start with a drive letter. 
        if ($filePath[1] -ne ':') {
            Write-VHost "Skipping non-drive-letter path event: $filePath" -ForegroundColor Yellow
            continue
        }

        # Skip events where the app is just accessing its own binary -- the
        # app path is stored without a drive letter (HardDiskVolume form),
        # so we compare against the file path minus its drive letter.
        if ($ev.Properties[$AppPathIndex].Value.EndsWith($filePath.Substring(3))) {
            continue
        }

        $accessEvent = New-Object LearningModeAccessEvent -ArgumentList @(
            $ev.TimeCreated,
            $ev.ProcessId,
            $ev.ThreadId,
            $ev.Properties[$LearningModeIndex].Value,
            $ev.Properties[$ResourceTypeIndex].Value,
            $filePath.Trim('\'),
            $ev.Properties[$AppPathIndex].Value,
            $ev.Properties[$AccessMaskIndex].Value
        )

        Write-VHost $ev.Properties[$AppPathIndex].Value
        # Filter out paths the OS would reject (Test-Path -IsValid).
        if (Test-Path $filePath -IsValid) {
            [void]$validAccessEvents.Add($accessEvent)
            Write-VHost $filePath
        }
    }

    return [pscustomobject]@{
        ValidAccessEvents     = $validAccessEvents
        RequestedCapabilities = $requestedCapabilities
        NeedUI                = $needUI
    }
}
