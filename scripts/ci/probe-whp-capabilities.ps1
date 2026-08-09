<#
.SYNOPSIS
    Reports Windows Hypervisor Platform capabilities via the real WHP API.

.DESCRIPTION
    `Get-WindowsOptionalFeature` only reports whether the HypervisorPlatform
    feature is installed, and `HypervisorPresent` only says a hypervisor is
    running. Neither proves that WHP can actually create a partition, which is
    what a VM monitor such as nanvixd needs.

    This probe P/Invokes WinHvPlatform.dll directly to:

      1. Query capabilities through WHvGetCapability.
      2. Attempt a real WHvCreatePartition / WHvSetupPartition and delete it.

    Step 2 is the important one: it is the first call that genuinely exercises
    the hypervisor, and the most likely place for a host that reports WHP as
    "enabled" to fail or block.

    Run this on both a working host and a failing one and compare the output.

    Diagnostic only: always exits 0.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host '=== WHP Capability Probe ==='
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) {
        Write-Host "Model: $($cs.Model)"
        Write-Host "HypervisorPresent: $($cs.HypervisorPresent)"
    }
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpu) {
        Write-Host "CPU: $($cpu.Name)"
        Write-Host "VirtualizationFirmwareEnabled: $($cpu.VirtualizationFirmwareEnabled)"
    }
} catch {
    Write-Host "Could not read system info: $($_.Exception.Message)"
}

if (-not (Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")) {
    Write-Host '::warning::WinHvPlatform.dll is absent - WHP is not installed.'
    exit 0
}

$signature = @'
using System;
using System.Runtime.InteropServices;

public static class Whp
{
    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvGetCapability(
        uint CapabilityCode,
        IntPtr CapabilityBuffer,
        uint CapabilityBufferSizeInBytes,
        out uint WrittenSizeInBytes);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvCreatePartition(out IntPtr Partition);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvSetupPartition(IntPtr Partition);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvDeletePartition(IntPtr Partition);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvSetPartitionProperty(
        IntPtr Partition,
        uint PropertyCode,
        IntPtr PropertyBuffer,
        uint PropertyBufferSizeInBytes);
}
'@

try {
    Add-Type -TypeDefinition $signature -ErrorAction Stop
} catch {
    Write-Host "::warning::Could not bind to WinHvPlatform.dll: $($_.Exception.Message)"
    exit 0
}

function Get-WhpCapability {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][uint32]$Code
    )

    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($buffer, 0)
        $written = 0
        $hr = [Whp]::WHvGetCapability($Code, $buffer, 8, [ref]$written)
        if ($hr -eq 0) {
            $value = [Runtime.InteropServices.Marshal]::ReadInt64($buffer)
            Write-Host ("  {0,-28} 0x{1:X16}" -f $Name, $value)
            return $value
        }
        Write-Host ("  {0,-28} FAILED (hr=0x{1:X8})" -f $Name, $hr)
        return $null
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

Write-Host ''
Write-Host '--- WHvGetCapability ---'
$hypervisorPresent = Get-WhpCapability -Name 'HypervisorPresent' -Code 0x00000000
$features = Get-WhpCapability -Name 'Features' -Code 0x00000001
Get-WhpCapability -Name 'ExtendedVmExits' -Code 0x00000002 | Out-Null
Get-WhpCapability -Name 'ProcessorVendor' -Code 0x00001000 | Out-Null
Get-WhpCapability -Name 'ProcessorFeatures' -Code 0x00001001 | Out-Null

# Nested-virtualization capabilities. A host that cannot expose VMX to a guest
# will fail or omit these, which is the difference we are looking for between a
# working runner and one where a VM monitor cannot boot.
Write-Host ''
Write-Host '--- Nested virtualization (VMX) capabilities ---'
Get-WhpCapability -Name 'VmxBasic' -Code 0x00002000 | Out-Null
Get-WhpCapability -Name 'VmxPinbasedCtls' -Code 0x00002001 | Out-Null
Get-WhpCapability -Name 'VmxProcbasedCtls' -Code 0x00002002 | Out-Null
Get-WhpCapability -Name 'VmxEptVpidCap' -Code 0x0000200C | Out-Null

if ($null -ne $features) {
    # Bit layout from WHV_CAPABILITY_FEATURES (x64).
    $bits = [ordered]@{
        PartialUnmap            = 0
        LocalApicEmulation      = 1
        Xsave                   = 2
        DirtyPageTracking       = 3
        SpeculationControl      = 4
        ApicRemoteRead          = 5
        IdleSuspend             = 6
        VirtualPciDeviceSupport = 7
        IommuSupport            = 8
        VpHotAddRemove          = 9
        DeviceAccessTracking    = 10
    }
    Write-Host ''
    Write-Host '--- Feature bits ---'
    foreach ($entry in $bits.GetEnumerator()) {
        $set = (($features -shr $entry.Value) -band 1) -eq 1
        Write-Host ("  {0,-28} {1}" -f $entry.Key, $set)
    }
}

if ($hypervisorPresent -eq 0) {
    Write-Host ''
    Write-Host '::warning::WHvCapabilityCodeHypervisorPresent is 0 - WHP reports no usable hypervisor.'
}

# The decisive test. Feature flags can look correct on a host where partition
# creation still fails or blocks; this is the call a VM monitor makes first.
Write-Host ''
Write-Host '--- WHvCreatePartition (the call that actually exercises the hypervisor) ---'

$partition = [IntPtr]::Zero
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$hr = [Whp]::WHvCreatePartition([ref]$partition)
$stopwatch.Stop()
Write-Host ("  WHvCreatePartition   hr=0x{0:X8}  ({1} ms)" -f $hr, $stopwatch.ElapsedMilliseconds)

if ($hr -ne 0) {
    Write-Host '::warning::WHvCreatePartition failed - WHP cannot host a VM here even though the feature is enabled.'
    Write-Host ''
    Write-Host 'RESULT: partition creation FAILED.'
    exit 0
}

try {
    # A partition needs both a processor count and an extended-VM-exit
    # configuration before setup will accept it; omitting the latter yields
    # WHV_E_INVALID_PARTITION_CONFIG (0x80370304) on an otherwise healthy host.
    $propertyBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($propertyBuffer, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($propertyBuffer, 1)
        # WHvPartitionPropertyCodeProcessorCount = 0x00001002
        $hrProp = [Whp]::WHvSetPartitionProperty($partition, 0x00001002, $propertyBuffer, 4)
        Write-Host ("  SetProcessorCount    hr=0x{0:X8}" -f $hrProp)

        # WHvPartitionPropertyCodeExtendedVmExits = 0x00000002
        [Runtime.InteropServices.Marshal]::WriteInt64($propertyBuffer, 0)
        $hrExits = [Whp]::WHvSetPartitionProperty($partition, 0x00000002, $propertyBuffer, 8)
        Write-Host ("  SetExtendedVmExits   hr=0x{0:X8}" -f $hrExits)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($propertyBuffer)
    }

    $stopwatch.Restart()
    $hrSetup = [Whp]::WHvSetupPartition($partition)
    $stopwatch.Stop()
    Write-Host ("  WHvSetupPartition    hr=0x{0:X8}  ({1} ms)" -f $hrSetup, $stopwatch.ElapsedMilliseconds)

    Write-Host ''
    if ($hrSetup -eq 0) {
        Write-Host 'RESULT: WHP can create and set up a partition - the hypervisor is usable.'
        Write-Host '        A VM monitor hanging here is failing for some other reason.'
    } else {
        # 0x80370304 here means this probe built an incomplete partition, not
        # necessarily that the host is broken; compare against a known-good host.
        Write-Host ("RESULT: partition setup returned 0x{0:X8}." -f $hrSetup)
        Write-Host '        Compare this value against a host where the VM monitor works.'
    }
} finally {
    $hrDelete = [Whp]::WHvDeletePartition($partition)
    Write-Host ("  WHvDeletePartition   hr=0x{0:X8}" -f $hrDelete)
}

exit 0
