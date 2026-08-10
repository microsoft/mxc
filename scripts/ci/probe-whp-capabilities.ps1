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
      2. Build a complete partition (WHvCreatePartition / WHvSetupPartition /
         WHvCreateVirtualProcessor), map a guest page, and actually execute
         guest code on it.

    Step 2 is the decisive one. Capability flags can look correct on a host
    where a partition cannot be set up, and a partition can be set up on a host
    where the hypervisor never actually executes guest instructions -- which is
    what a VM monitor such as nanvixd needs. The guest here is a single `hlt`
    placed at the x86 reset vector, so a healthy host reports exit reason
    `WHvRunVpExitReasonX64Halt` and no register or paging setup is required.

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

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvCreateVirtualProcessor(
        IntPtr Partition,
        uint VpIndex,
        uint Flags);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvDeleteVirtualProcessor(
        IntPtr Partition,
        uint VpIndex);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvMapGpaRange(
        IntPtr Partition,
        IntPtr SourceAddress,
        ulong GuestAddress,
        ulong SizeInBytes,
        uint Flags);

    [DllImport("WinHvPlatform.dll")]
    public static extern int WHvRunVirtualProcessor(
        IntPtr Partition,
        uint VpIndex,
        IntPtr ExitContext,
        uint ExitContextSizeInBytes);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
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
# setup fails, and setup can succeed on a host that never executes guest code.
Write-Host ''
Write-Host '--- Partition setup and guest execution (what a VM monitor actually needs) ---'

# WHV_PARTITION_PROPERTY_CODE values from WinHvPlatformDefs.h. These are easy to
# get wrong: ProcessorCount is 0x00001fff, NOT 0x00001002 (ProcessorClFlushSize),
# and ExtendedVmExits is 0x00000001, NOT 0x00000002 (ExceptionExitBitmap).
# Setting the wrong code makes WHvSetupPartition fail with
# WHV_E_INVALID_PARTITION_CONFIG (0x80370304) on a perfectly healthy host.
$PropertyCodeExtendedVmExits = 0x00000001
$PropertyCodeProcessorCount = 0x00001fff

# WHV_RUN_VP_EXIT_REASON values worth naming in the output.
$exitReasons = @{
    0x00000000 = 'None'
    0x00000001 = 'MemoryAccess'
    0x00000002 = 'X64IoPortAccess'
    0x00000004 = 'UnrecoverableException'
    0x00000005 = 'InvalidVpRegisterValue'
    0x00000006 = 'UnsupportedFeature'
    0x00000007 = 'X64InterruptWindow'
    0x00000008 = 'X64Halt'
    0x00001000 = 'X64MsrAccess'
    0x00001001 = 'X64Cpuid'
    0x00001002 = 'Exception'
    0x00002001 = 'Canceled'
}

$partition = [IntPtr]::Zero
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$hr = [Whp]::WHvCreatePartition([ref]$partition)
$stopwatch.Stop()
Write-Host ("  WHvCreatePartition        hr=0x{0:X8}  ({1} ms)" -f $hr, $stopwatch.ElapsedMilliseconds)

if ($hr -ne 0) {
    Write-Host '::warning::WHvCreatePartition failed - WHP cannot host a VM here even though the feature is enabled.'
    Write-Host ''
    Write-Host 'RESULT: partition creation FAILED - the hypervisor is unusable on this host.'
    exit 0
}

$guestMemory = @()
$vpCreated = $false
try {
    $propertyBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($propertyBuffer, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($propertyBuffer, 1)
        $hrProp = [Whp]::WHvSetPartitionProperty($partition, $PropertyCodeProcessorCount, $propertyBuffer, 4)
        Write-Host ("  SetProcessorCount(1)      hr=0x{0:X8}" -f $hrProp)

        [Runtime.InteropServices.Marshal]::WriteInt64($propertyBuffer, 0)
        $hrExits = [Whp]::WHvSetPartitionProperty($partition, $PropertyCodeExtendedVmExits, $propertyBuffer, 8)
        Write-Host ("  SetExtendedVmExits(0)     hr=0x{0:X8}" -f $hrExits)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($propertyBuffer)
    }

    $stopwatch.Restart()
    $hrSetup = [Whp]::WHvSetupPartition($partition)
    $stopwatch.Stop()
    Write-Host ("  WHvSetupPartition         hr=0x{0:X8}  ({1} ms)" -f $hrSetup, $stopwatch.ElapsedMilliseconds)
    if ($hrSetup -ne 0) {
        Write-Host ''
        Write-Host ('::warning::WHvSetupPartition failed with 0x{0:X8}.' -f $hrSetup)
        Write-Host 'RESULT: partition setup FAILED - a VM monitor cannot start here.'
        exit 0
    }

    $stopwatch.Restart()
    $hrVp = [Whp]::WHvCreateVirtualProcessor($partition, 0, 0)
    $stopwatch.Stop()
    Write-Host ("  WHvCreateVirtualProcessor hr=0x{0:X8}  ({1} ms)" -f $hrVp, $stopwatch.ElapsedMilliseconds)
    if ($hrVp -ne 0) {
        Write-Host ''
        Write-Host '::warning::WHvCreateVirtualProcessor failed - no vCPU can be created on this host.'
        Write-Host 'RESULT: vCPU creation FAILED.'
        exit 0
    }
    $vpCreated = $true

    # Map HLT-filled pages at the addresses a fresh vCPU can start from and let
    # the guest run. WHP resets a vCPU to real mode at CS.Base 0xF0000 /
    # RIP 0xFFF0 (linear 0xFFFF0, page 0xFF000); the zero page is mapped too so
    # the probe stays valid if that reset state ever changes. Either way the
    # first instruction fetched is HLT (0xF4).
    $pageSize = 4096
    $MEM_COMMIT_RESERVE = 0x3000
    $PAGE_EXECUTE_READWRITE = 0x40
    # WHvMapGpaRangeFlagRead | Write | Execute
    $mapFlags = 0x00000007
    $guestPages = @(
        @{ Name = 'reset vector'; Gpa = [uint64]0xFF000 },
        @{ Name = 'zero page'; Gpa = [uint64]0 }
    )

    foreach ($page in $guestPages) {
        $host_address = [Whp]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new($pageSize), $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE)
        if ($host_address -eq [IntPtr]::Zero) {
            Write-Host '::warning::VirtualAlloc for guest memory failed - cannot complete the execution test.'
            exit 0
        }
        $guestMemory += $host_address
        for ($offset = 0; $offset -lt $pageSize; $offset++) {
            [Runtime.InteropServices.Marshal]::WriteByte($host_address, $offset, 0xF4)
        }

        $hrMap = [Whp]::WHvMapGpaRange($partition, $host_address, $page.Gpa, $pageSize, $mapFlags)
        Write-Host ("  WHvMapGpaRange {0,-11} hr=0x{1:X8}" -f $page.Name, $hrMap)
        if ($hrMap -ne 0) {
            Write-Host ''
            Write-Host '::warning::WHvMapGpaRange failed - guest memory cannot be mapped on this host.'
            Write-Host 'RESULT: guest memory mapping FAILED.'
            exit 0
        }
    }

    # WHV_RUN_VP_EXIT_CONTEXT is 224 bytes (x64, SDK 10.0.26100).
    $exitContextSize = 224
    $exitContext = [Runtime.InteropServices.Marshal]::AllocHGlobal($exitContextSize)
    try {
        # If the hypervisor never actually dispatches guest code this call is
        # where a host blocks; the CI step timeout bounds it.
        $stopwatch.Restart()
        $hrRun = [Whp]::WHvRunVirtualProcessor($partition, 0, $exitContext, $exitContextSize)
        $stopwatch.Stop()
        $exitReason = [Runtime.InteropServices.Marshal]::ReadInt32($exitContext)
        $reasonName = if ($exitReasons.ContainsKey($exitReason)) { $exitReasons[$exitReason] } else { 'Unknown' }
        # WHV_RUN_VP_EXIT_CONTEXT layout: ExitReason(0), Reserved(4),
        # VpContext(8) { ExecutionState, InstructionLength/Cr8, Reserved,
        # Reserved2, Cs @16, Rip @32, Rflags @40 }, union @48. For a
        # MemoryAccess exit the union holds WHV_MEMORY_ACCESS_CONTEXT with
        # Gpa at offset 72.
        $csBase = [Runtime.InteropServices.Marshal]::ReadInt64($exitContext, 16)
        $rip = [Runtime.InteropServices.Marshal]::ReadInt64($exitContext, 32)
        Write-Host ("  WHvRunVirtualProcessor    hr=0x{0:X8}  ({1} ms)" -f $hrRun, $stopwatch.ElapsedMilliseconds)
        Write-Host ("  Guest exit reason         0x{0:X8} ({1})" -f $exitReason, $reasonName)
        Write-Host ("  Guest CS.Base/RIP         0x{0:X16} / 0x{1:X16}" -f $csBase, $rip)
        if ($exitReason -eq 0x00000001) {
            $gpa = [Runtime.InteropServices.Marshal]::ReadInt64($exitContext, 72)
            Write-Host ("  Faulting GPA              0x{0:X16}" -f $gpa)
        }

        Write-Host ''
        if ($hrRun -eq 0 -and $exitReason -eq 0x00000008) {
            Write-Host 'RESULT: WHP executed guest code and halted as expected.'
            Write-Host '        The hypervisor is fully usable here - a VM monitor that hangs'
            Write-Host '        or fails is doing so for a reason above WHP.'
        } elseif ($hrRun -ne 0) {
            Write-Host ('::warning::WHvRunVirtualProcessor failed with 0x{0:X8}.' -f $hrRun)
            Write-Host 'RESULT: the hypervisor refused to run guest code on this host.'
        } else {
            Write-Host ("::warning::Guest exited for {0} instead of X64Halt." -f $reasonName)
            Write-Host 'RESULT: guest code ran but did not reach HLT - compare against a working host.'
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($exitContext)
    }
} finally {
    if ($vpCreated) {
        $hrDeleteVp = [Whp]::WHvDeleteVirtualProcessor($partition, 0)
        Write-Host ("  WHvDeleteVirtualProcessor hr=0x{0:X8}" -f $hrDeleteVp)
    }
    $hrDelete = [Whp]::WHvDeletePartition($partition)
    Write-Host ("  WHvDeletePartition        hr=0x{0:X8}" -f $hrDelete)
    foreach ($address in $guestMemory) {
        [void][Whp]::VirtualFree($address, [UIntPtr]::Zero, 0x8000)
    }
}

exit 0
