# extract_caps.ps1
#
# Takes an input hex string containing N ACEs in the form:
#   [0]      ACE type        (1 byte)
#   [1..3]   Padding         (3 bytes)
#   [4..7]   ACE flags       (4 bytes, only low byte is meaningful)
#   [8..11]  Access mask     (4 bytes, little-endian)
#   [12..]   SID:
#               [0]    Revision         (1 byte)
#               [1]    SubAuthorityCount (1 byte)
#               [2..7] IdentifierAuthority (6 bytes)
#               [8..]  SubAuthorities   (4 bytes each, SubAuthorityCount entries)
#
# Iterates through each ACE, extracts the SID, and prints:
#   - SID string (S-1-...)
#   - resolved capability name (via DeriveCapabilitySidsFromName) or NTAccount fallback.
#
# Returns a case-insensitive HashSet[string] of matched capability names on
# the pipeline so callers can capture and merge results:
#   $caps = & .\extract_caps.ps1 -HexBytes $hex

# ---------------------------------------------------------------------------
# Parameters & global error policy
#
# $HexBytes is the concatenated hex of every ACE body after the ACL header
# in the source event. Whitespace and casing are normalized later. Errors
# are made terminating so a malformed buffer fails fast instead of producing
# nonsense offsets downstream.
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $HexBytes,

    # When set, per-ACE diagnostic lines are emitted via Write-Host. When
    # unset (default), the script runs silently and only returns the
    # capability HashSet on the pipeline.
    [switch] $VerboseLogging
)

$ErrorActionPreference = 'Stop'

# Gate for the per-script Write-Host wrapper below. Captured into a
# script-scope variable so the helper can see it without re-checking the
# parameter on every call.
$script:VerboseLogEnabled = [bool]$VerboseLogging

# Write-Host wrapper: emits only when -VerboseLogging is set. Preserves the
# optional -ForegroundColor argument used by the existing call sites.
function Write-VHost {
    param(
        [Parameter(Position = 0)][AllowEmptyString()][string] $Message = '',
        [string] $ForegroundColor
    )
    if (-not $script:VerboseLogEnabled) { return }
    if ($ForegroundColor) { Write-Host $Message -ForegroundColor $ForegroundColor }
    else                  { Write-Host $Message }
}

# ---------------------------------------------------------------------------
# P/Invoke helpers
#
# LookupAccountSid cannot resolve capability SIDs (S-1-15-3-...), so we call
# the Win32 capability API directly. We also need GetLengthSid to size SID
# copies and LocalFree to release the unmanaged buffers the API hands back.
# The type is defined once per session and reused on subsequent invocations.
# ---------------------------------------------------------------------------
if (-not ('Win32.CapHelper' -as [type])) {
    Add-Type -Namespace Win32 -Name CapHelper -MemberDefinition @'
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern System.IntPtr LocalFree(System.IntPtr hMem);

        [System.Runtime.InteropServices.DllImport("api-ms-win-security-base-l1-2-0.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        public static extern bool DeriveCapabilitySidsFromName(
            string capName,
            out System.IntPtr capabilityGroupSids,
            out uint capabilityGroupSidCount,
            out System.IntPtr capabilitySids,
            out uint capabilitySidCount);

        [System.Runtime.InteropServices.DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(System.IntPtr pSid);
'@
}

function Get-SidBytesFromPtr([System.IntPtr] $pSid) {
    if ($pSid -eq [System.IntPtr]::Zero) { return $null }
    $len = [Win32.CapHelper]::GetLengthSid($pSid)
    if ($len -le 0) { return $null }
    $bytes = New-Object byte[] $len
    [System.Runtime.InteropServices.Marshal]::Copy($pSid, $bytes, 0, [int]$len)
    return ,$bytes
}

# Which capabilities do we want to deny list, and should we prefer a deny list over an allow list?
function Build-CapabilityTable {
    $knownCapabilities = @(
        'graphicsCapture'
        'graphicsCaptureProgrammatic'
        'graphicsCaptureWithoutBorder'
        'microphone'
        'webcam'
        'location'
        'contacts'
        'appointments'
        'chat'
        'phoneCall'
        'voipCall'
        'documentsLibrary'
        'picturesLibrary'
        'musicLibrary'
        'videosLibrary'
        'removableStorage'
        #'broadFileSystemAccess'
        'internetClient'
        'internetClientServer'
        'privateNetworkClientServer'
        #'enterpriseAuthentication'
        'sharedUserCertificates'
        'userAccountInformation'
        'backgroundMediaPlayback'
        #'runFullTrust'
        #'packageManagement' // Will people be asking for their apps to install packages for them?
        'objects3D'
        'radios'
        'bluetooth'
        'serialcommunication'
        'usb'
        'humaninterfacedevice'
        'pointOfService'
    )

    $table = @()
    foreach ($name in $knownCapabilities) {
        # Out-parameter slots for the four values returned by
        # DeriveCapabilitySidsFromName: group-SID array + count, capability-
        # SID array + count.
        $groupSids  = [System.IntPtr]::Zero
        $groupCount = 0
        $capSids    = [System.IntPtr]::Zero
        $capCount   = 0
        $ok = [Win32.CapHelper]::DeriveCapabilitySidsFromName(
            $name, [ref]$groupSids, [ref]$groupCount, [ref]$capSids, [ref]$capCount)
        # Some capability names are rejected on older OS builds; skip those
        # rather than failing the whole table build.
        if (-not $ok) { continue }

        # Copy the FIRST SID from each array into managed bytes. The first
        # entry is the canonical SID; additional entries (when present) are
        # alternate encodings we don't currently try to match.
        $appPackageSid = $null
        $groupSid      = $null
        if ($capCount -gt 0 -and $capSids -ne [System.IntPtr]::Zero) {
            $first = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($capSids)
            $appPackageSid = Get-SidBytesFromPtr $first
        }
        if ($groupCount -gt 0 -and $groupSids -ne [System.IntPtr]::Zero) {
            $first = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($groupSids)
            $groupSid = Get-SidBytesFromPtr $first
        }

        $table += [pscustomobject]@{
            Name          = $name
            AppPackageSid = $appPackageSid
            GroupSid      = $groupSid
        }

        # LocalFree every SID pointer in the capability array, then the
        # array itself. Skipping this would leak unmanaged memory across
        # repeated runs in the same PowerShell session.
        for ($i = 0; $i -lt $capCount; ++$i) {
            $p = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($capSids, $i * [System.IntPtr]::Size)
            [void][Win32.CapHelper]::LocalFree($p)
        }
        [void][Win32.CapHelper]::LocalFree($capSids)
        # Same cleanup for the group-SID array.
        for ($i = 0; $i -lt $groupCount; ++$i) {
            $p = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($groupSids, $i * [System.IntPtr]::Size)
            [void][Win32.CapHelper]::LocalFree($p)
        }
        [void][Win32.CapHelper]::LocalFree($groupSids)
    }
    # Unary comma keeps PowerShell from unrolling a single-row table into a
    # scalar at the function boundary.
    return ,$table
}

# ---------------------------------------------------------------------------
# Compare-SidBytes
#
# Byte-by-byte equality check for two SID buffers. We use this instead of
# stringifying each side via SecurityIdentifier.Value because some input
# SIDs may be malformed, and we don't want lookup to throw mid-walk.
# ---------------------------------------------------------------------------
function Compare-SidBytes([byte[]] $a, [byte[]] $b) {
    if ($null -eq $a -or $null -eq $b) { return $false }
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; ++$i) {
        if ($a[$i] -ne $b[$i]) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# Resolve-Sid
#
# Attempts to map a SID (as bytes) to a name in this priority order:
#   1. A known capability via AppPackage SID match.
#   2. A known capability via Group SID match.
#   3. A traditional NTAccount via SecurityIdentifier.Translate (users,
#      groups, well-known SIDs).
#   4. A "no match" sentinel string.
#
# When a capability match is found, $capabilityName (a [ref] supplied by
# the caller) is set so the outer loop can record it in the result set.
# ---------------------------------------------------------------------------
function Resolve-Sid([byte[]] $sidBytes, $capabilityTable, [ref] $capabilityName) {
    foreach ($entry in $capabilityTable) {
        if (Compare-SidBytes $sidBytes $entry.AppPackageSid) {
            $capabilityName.Value = $entry.Name
            return "capability `"$($entry.Name)`""
        }
        if (Compare-SidBytes $sidBytes $entry.GroupSid) {
            $capabilityName.Value = $entry.Name
            return "capability `"$($entry.Name)`" (group SID)"
        }
    }
    # No capability matched -- fall back to LSA translation.
    $capabilityName.Value = $null
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
        $nt = $sid.Translate([System.Security.Principal.NTAccount])
        return $nt.Value
    } catch {
        return "<no known capability/account matches this SID>"
    }
}

# ---------------------------------------------------------------------------
# Hex string -> byte array
#
# Strip whitespace, validate non-empty / even-length / hex-only, then
# convert two characters at a time into bytes. Bad input is fatal because
# every downstream offset depends on byte-accurate input.
# ---------------------------------------------------------------------------
$hex = ($HexBytes -replace '\s+', '').Trim()
if ([string]::IsNullOrEmpty($hex) -or ($hex.Length % 2) -ne 0) {
    throw "Hex string must be non-empty and have an even length."
}
if ($hex -notmatch '^[0-9A-Fa-f]+$') {
    throw "Hex string contains non-hex characters."
}

$totalLength = $hex.Length / 2
$inputBytes = New-Object byte[] $totalLength
for ($i = 0; $i -lt $totalLength; ++$i) {
    $inputBytes[$i] = [byte][System.Convert]::ToInt32($hex.Substring($i * 2, 2), 16)
}

# ---------------------------------------------------------------------------
# Walk N ACEs
#
# The input is a sequence of variable-length ACEs. Each ACE is laid out as
# documented in the file header: a 12-byte ACE header (type + 3 pad bytes
# + 4-byte flags + 4-byte access mask) followed by a SID whose total
# length is derived from its SubAuthorityCount byte.
# ---------------------------------------------------------------------------
$kInputAceHeaderSize = 1 + 3 + 4 + 4  # type + 3 padding + 4-byte flags + mask
$kSidFixedHeaderSize = 1 + 1 + 6       # revision + subauth count + id auth

# Capability lookup table is independent of any ACE, so build it once and
# reuse for every iteration of the walk below.
$capabilityTable = Build-CapabilityTable

# Case-insensitive HashSet of capability names matched while walking the
# input. Returned to callers at the end of the script.
$foundCapabilities = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

$cursor = 0
$aceIndex = 0
while ($cursor -lt $totalLength) {
    # Bail out early if the remaining buffer isn't big enough to hold even
    # an ACE header plus a SID prelude -- the input is truncated.
    if (($totalLength - $cursor) -lt ($kInputAceHeaderSize + $kSidFixedHeaderSize)) {
        throw "Truncated ACE header at byte offset $cursor (need at least $($kInputAceHeaderSize + $kSidFixedHeaderSize) more bytes)."
    }

    # Decode the per-ACE header fields. Type is at +0, then 3 padding bytes,
    # then the 4-byte AceFlags at +4 (only the low byte is meaningful).
    # Type/flags are surfaced in the diagnostic output below but not used
    # to filter.
    $aceType  = $inputBytes[$cursor + 0]
    $aceFlags = $inputBytes[$cursor + 4]

    # Access mask (little-endian DWORD) at +8.
    $accessMask = [BitConverter]::ToUInt32($inputBytes, $cursor + 8)

    # SID starts immediately after the 12-byte ACE header. Read its
    # SubAuthorityCount, compute the SID's total length, and verify the
    # buffer has enough bytes to satisfy it.
    $sidOffset = $cursor + $kInputAceHeaderSize
    $subAuthorityCount = $inputBytes[$sidOffset + 1]
    $sidSize = $kSidFixedHeaderSize + (4 * $subAuthorityCount)

    if (($totalLength - $sidOffset) -lt $sidSize) {
        throw "Truncated SID at byte offset $sidOffset (need $sidSize bytes, have $($totalLength - $sidOffset))."
    }

    # Slice the SID into its own buffer so downstream code can both
    # stringify and resolve it without worrying about shared-buffer state.
    $sidBytes = New-Object byte[] $sidSize
    [Array]::Copy($inputBytes, $sidOffset, $sidBytes, 0, $sidSize)

    # Best-effort string form for diagnostics. If the bytes don't form a
    # valid SID, fall back to an inline error message rather than throwing.
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
        $sidString = $sidObj.Value
    } catch {
        $sidString = "<invalid SID: $($_.Exception.Message)>"
    }

    # Resolve the SID. If it matches a known capability, add the name to
    # the result set so the caller can act on it.
    $matchedCapability = $null
    $resolved = Resolve-Sid $sidBytes $capabilityTable ([ref]$matchedCapability)
    if ($matchedCapability) {
        [void]$foundCapabilities.Add($matchedCapability)
    }

    # Per-ACE diagnostic line. Routed through Write-VHost so it only
    # appears when the caller passes -VerboseLogging; the pipeline output
    # (the HashSet at the end) is unaffected either way.
    Write-VHost ("ACE {0}: type=0x{1:X2}, flags=0x{2:X2}, mask=0x{3:X8}, subAuthCount={4}" -f `
        $aceIndex, $aceType, $aceFlags, $accessMask, $subAuthorityCount)
    Write-VHost ("  SID:      $sidString")
    Write-VHost ("  Resolved: $resolved")
    Write-VHost ""

    # Advance past this ACE's SID to the start of the next ACE.
    $cursor = $sidOffset + $sidSize
    $aceIndex += 1
}

# ---------------------------------------------------------------------------
# Summary + pipeline output
#
# Print a human-readable summary to the host stream, then emit the populated
# HashSet on the pipeline so callers can capture it:
#   $caps = & .\extract_caps.ps1 -HexBytes $hex
#   if ($caps.Contains('graphicsCaptureProgrammatic')) { ... }
# The leading comma prevents PowerShell from unrolling the HashSet into its
# individual elements as it crosses the script boundary.
# ---------------------------------------------------------------------------
# Write-Host "Total ACEs parsed: $aceIndex"
# Write-Host ("Capabilities matched ({0}): {1}" -f `
#     $foundCapabilities.Count,
#     (($foundCapabilities | Sort-Object) -join ', '))

,$foundCapabilities
