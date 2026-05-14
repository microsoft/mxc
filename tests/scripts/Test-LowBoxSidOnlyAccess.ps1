# Test-LowBoxSidOnlyAccess.ps1
#
# Settles: when a LowBox (AppContainer) token attempts read access to
# an object whose DACL grants ONLY the AppContainer SID (no user, no
# group, no Authenticated Users / Users / Everyone), does the access
# check grant FILE_GENERIC_READ?
#
# If yes → SID-alone-suffices → cross-user attack via deterministic
#         AppContainer SIDs is real → persistent ancestor ACEs need
#         user-SID namespacing.
# If no  → standard access check still requires a user/group grant →
#         user's interpretation is correct → persistent design is safe
#         from cross-user.
#
# Avoids the filesystem-traversal problem entirely by calling
# AccessCheck() against an in-memory security descriptor with a
# LowBox token created via NtCreateLowBoxToken. No process spawn, no
# directory traversal, no admin needed.

[CmdletBinding()]
param(
    [string]$ContainerId = 'MxcAclSidAccessTest'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -Language CSharp -ReferencedAssemblies System.Runtime.InteropServices @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class LowBoxAccessTest {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalAlloc(uint flags, UIntPtr bytes);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr p);

    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int DeriveAppContainerSidFromAppContainerName(string n, out IntPtr sid);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool ConvertStringSidToSidW(string s, out IntPtr sid);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string s, uint rev, out IntPtr sd, out uint size);
    [DllImport("advapi32.dll")]
    public static extern int GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(
        IntPtr existing, uint access, IntPtr attrs, uint impLevel,
        uint type, out IntPtr dup);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateLowBoxToken(
        out IntPtr token, IntPtr existing, uint access, IntPtr objAttrs,
        IntPtr packageSid, uint capCount, IntPtr capabilities,
        uint handleCount, IntPtr handles);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AccessCheck(
        IntPtr sd, IntPtr clientToken, uint desiredAccess,
        IntPtr genericMapping, IntPtr privilegeSet, ref uint privSize,
        out uint grantedAccess, out int accessStatus);

    [StructLayout(LayoutKind.Sequential)]
    public struct GENERIC_MAPPING {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public const uint SecurityImpersonation = 2;
    public const uint TokenImpersonation = 2;
    public const uint FILE_GENERIC_READ = 0x00120089;

    public static string Run(string sddl, string containerName) {
        // Derive the AppContainer SID.
        IntPtr packageSid;
        int hr = DeriveAppContainerSidFromAppContainerName(containerName, out packageSid);
        if (hr != 0) { return "ERR: derive 0x" + hr.ToString("X8"); }

        // For diagnostics.
        IntPtr sidStrPtr;
        ConvertSidToStringSidW(packageSid, out sidStrPtr);
        string sidStr = Marshal.PtrToStringUni(sidStrPtr);
        LocalFree(sidStrPtr);

        // Build SD via the SDDL the caller passed, substituting the
        // container SID in for the {SID} placeholder.
        string filledSddl = sddl.Replace("{SID}", sidStr);
        IntPtr sd; uint sdSize;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(filledSddl, 1, out sd, out sdSize)) {
            return "ERR: SDDL parse, gle=" + Marshal.GetLastWin32Error() + " sddl=" + filledSddl;
        }

        // Open current process token, duplicate as impersonation, then
        // wrap with NtCreateLowBoxToken.
        IntPtr procToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, out procToken)) {
            return "ERR: OpenProcessToken gle=" + Marshal.GetLastWin32Error();
        }
        IntPtr dupToken;
        if (!DuplicateTokenEx(procToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                              SecurityImpersonation, TokenImpersonation, out dupToken)) {
            CloseHandle(procToken);
            return "ERR: DuplicateTokenEx gle=" + Marshal.GetLastWin32Error();
        }
        CloseHandle(procToken);

        IntPtr lowBox;
        int ntstatus = NtCreateLowBoxToken(
            out lowBox, dupToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
            packageSid, 0, IntPtr.Zero, 0, IntPtr.Zero);
        CloseHandle(dupToken);
        if (ntstatus != 0) {
            return "ERR: NtCreateLowBoxToken 0x" + ntstatus.ToString("X8");
        }
        // NtCreateLowBoxToken returns a primary token; AccessCheck needs
        // an impersonation token. Re-duplicate.
        IntPtr lowBoxImp;
        if (!DuplicateTokenEx(lowBox, TOKEN_ALL_ACCESS, IntPtr.Zero,
                              SecurityImpersonation, TokenImpersonation, out lowBoxImp)) {
            int gleDup = Marshal.GetLastWin32Error();
            CloseHandle(lowBox);
            return "ERR: DuplicateTokenEx(lowbox) gle=" + gleDup;
        }
        CloseHandle(lowBox);
        lowBox = lowBoxImp;

        // AccessCheck against the SD.
        GENERIC_MAPPING mapping = new GENERIC_MAPPING {
            GenericRead    = 0x00120089,
            GenericWrite   = 0x00120116,
            GenericExecute = 0x001200A0,
            GenericAll     = 0x001F01FF
        };
        IntPtr mapPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(GENERIC_MAPPING)));
        Marshal.StructureToPtr(mapping, mapPtr, false);

        uint privSize = 256;
        IntPtr privBuf = Marshal.AllocHGlobal((int)privSize);
        uint granted;
        int accessStatus;
        bool ok = AccessCheck(sd, lowBox, FILE_GENERIC_READ, mapPtr,
                              privBuf, ref privSize, out granted, out accessStatus);
        int gle = Marshal.GetLastWin32Error();

        Marshal.FreeHGlobal(mapPtr);
        Marshal.FreeHGlobal(privBuf);
        CloseHandle(lowBox);
        LocalFree(sd);

        if (!ok) { return "ERR: AccessCheck gle=" + gle; }
        return string.Format("sid={0} accessStatus={1} granted=0x{2:X8}",
            sidStr, (accessStatus != 0 ? "GRANTED" : "DENIED"), granted);
    }
}
"@

function Run-Case {
    param([string]$Label, [string]$Sddl, [string]$Expected)
    $r = [LowBoxAccessTest]::Run($Sddl, $ContainerId)
    # Parse on the explicit accessStatus= field, NOT on the word
    # "granted" (which also appears in "granted=0x...").
    $verdict = if ($r -cmatch 'accessStatus=GRANTED') { 'GRANTED' }
               elseif ($r -cmatch 'accessStatus=DENIED') { 'DENIED' }
               else { 'ERR' }
    $match = if ($verdict -eq $Expected) { 'ok' } else { 'UNEXPECTED' }
    Write-Host ("  [{0,-10}] expected={1,-7}  got={2,-7}  {3}" -f $Label, $Expected, $verdict, $match)
    Write-Host "             $r"
    return @{ Label = $Label; Expected = $Expected; Verdict = $verdict; Raw = $r }
}

Write-Host "Container ID: $ContainerId"
Write-Host ""
Write-Host "Test cases (each builds an SD via SDDL, creates a LowBox token, calls AccessCheck for FILE_GENERIC_READ):"
Write-Host ""

# Owner=SY, Group=SY, DACL contains:
#   - SY:FA          (full access for SYSTEM, to keep the file manageable)
#   - {SID}:FR       (the AppContainer SID grant we're testing)
# No Authenticated Users, no Users, no current-user grant.
$results = @()
$results += Run-Case -Label 'SidOnly' `
    -Sddl 'O:SYG:SYD:(A;;FA;;;SY)(A;;FR;;;{SID})' `
    -Expected 'DENIED'   # If your interpretation is right.

# Control 1: identical SD plus AU:FR — should grant (proves the
# AccessCheck wiring works and the SID derivation is consistent).
$results += Run-Case -Label 'Sid+AU' `
    -Sddl 'O:SYG:SYD:(A;;FA;;;SY)(A;;FR;;;AU)(A;;FR;;;{SID})' `
    -Expected 'GRANTED'

# Control 2: AU only, no SID. Initially expected GRANTED on the
# theory that standard-side AU would suffice. First-run revealed
# this is also DENIED — the LowBox restricted check has to match
# independently. Updated expectation reflects the actual two-check
# semantics.
$results += Run-Case -Label 'AU only' `
    -Sddl 'O:SYG:SYD:(A;;FA;;;SY)(A;;FR;;;AU)' `
    -Expected 'DENIED'

# Control 3: SYSTEM only — should deny (proves the token doesn't have
# SY, so we'd see DENIED if neither AU nor our SID matches).
$results += Run-Case -Label 'SY only' `
    -Sddl 'O:SYG:SYD:(A;;FA;;;SY)' `
    -Expected 'DENIED'

# Control 4: ALL APP PKGS only — interesting: does the LowBox half
# count if standard side has nothing?
$results += Run-Case -Label 'AAP only' `
    -Sddl 'O:SYG:SYD:(A;;FR;;;AC)' `
    -Expected 'DENIED'

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Interpretation" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$sidOnly = $results | Where-Object { $_.Label -eq 'SidOnly' } | Select-Object -First 1
if ($sidOnly.Verdict -eq 'GRANTED') {
    Write-Host "  SID-alone-suffices. Cross-user attack via deterministic SIDs is REAL." -ForegroundColor Yellow
    Write-Host "  Persistent ancestor-traverse ACEs need user-SID namespacing or randomization." -ForegroundColor Yellow
} elseif ($sidOnly.Verdict -eq 'DENIED') {
    Write-Host "  Both-needed. The standard access check still rejects when only the AppContainer" -ForegroundColor Green
    Write-Host "  SID is granted (no user/group grant matches). User's interpretation confirmed." -ForegroundColor Green
    Write-Host "  → Persistent ancestor-traverse ACEs are safe from cross-user escalation." -ForegroundColor Green
} else {
    Write-Host "  Indeterminate — test errored. See output above." -ForegroundColor Yellow
}
