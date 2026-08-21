# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Exercises the four proxy identity shapes accepted by the schema 0.8
# ProcessContainer network model: packaged/unpackaged AppContainer peers,
# a packaged full-trust peer, and host loopback for unpackaged full trust.

[CmdletBinding()]
param(
    [string]$BinDir = (Join-Path $PSScriptRoot '..\..\src\target\debug'),
    [string]$PackageOutput = (Join-Path $env:TEMP 'mxc-proxy-test-packages')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$proxyPort = 8080
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$wxc = Join-Path $BinDir 'wxc-exec.exe'
$proxy = Join-Path $BinDir 'wxc-test-proxy.exe'
$packageBuilder = Join-Path $repoRoot 'tests\assets\processcontainer-proxy-packages\build-proxy-test-packages.ps1'
$testRoot = Join-Path $env:TEMP "mxc-proxy-identity-$PID"
$firewallRules = @()
$processes = @()
$trustedCertificate = $null
$appContainerProfile = "MXC-Unpackaged-AppContainer-Proxy-$PID"

if (-not (Test-Path $wxc) -or -not (Test-Path $proxy)) {
    throw "Expected wxc-exec.exe and wxc-test-proxy.exe in $BinDir"
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Proxy identity E2E tests require an elevated PowerShell session.'
}

if (-not ([System.Management.Automation.PSTypeName]'MxcProxyActivation').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MxcProxyActivation
{
    [ComImport, Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    private class ApplicationActivationManager {}

    [ComImport, Guid("2e941141-7f97-4756-ba1d-9decde894a3d"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        int ActivateApplication(
            [MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments,
            uint options,
            out uint processId);
        int ActivateForFile(string appUserModelId, IntPtr itemArray, string verb, out uint processId);
        int ActivateForProtocol(string appUserModelId, IntPtr itemArray, out uint processId);
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(
        string name, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static uint Activate(string appUserModelId, string arguments)
    {
        var manager = (IApplicationActivationManager)new ApplicationActivationManager();
        int hr = manager.ActivateApplication(appUserModelId, arguments, 0, out uint pid);
        Marshal.ThrowExceptionForHR(hr);
        return pid;
    }

    public static string DeriveSid(string profile)
    {
        int hr = DeriveAppContainerSidFromAppContainerName(profile, out IntPtr sid);
        Marshal.ThrowExceptionForHR(hr);
        try
        {
            byte[] bytes = new byte[GetLengthSid(sid)];
            Marshal.Copy(sid, bytes, 0, bytes.Length);
            return new System.Security.Principal.SecurityIdentifier(bytes, 0).Value;
        }
        finally { FreeSid(sid); }
    }
}

public static class MxcUnpackagedAppContainer
{
    private const uint SE_GROUP_ENABLED = 0x00000004;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private static readonly IntPtr SecurityCapabilitiesAttribute = new IntPtr(0x00020009);

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int CreateAppContainerProfile(
        string name, string displayName, string description,
        IntPtr capabilities, uint capabilityCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(
        string name, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string name);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSidToSid(string text, out IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr list, uint flags, IntPtr attribute, IntPtr value,
        IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string applicationName, System.Text.StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string currentDirectory,
        ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private static void ThrowLastError(string operation)
    {
        throw new System.ComponentModel.Win32Exception(
            Marshal.GetLastWin32Error(), operation);
    }

    public static uint Launch(string profile, string executable, string arguments)
    {
        IntPtr internetClient = IntPtr.Zero;
        IntPtr privateNetwork = IntPtr.Zero;
        IntPtr capabilityArray = IntPtr.Zero;
        IntPtr appContainerSid = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr securityCapabilities = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSid("S-1-15-3-1", out internetClient))
                ThrowLastError("ConvertStringSidToSid(internetClient)");
            if (!ConvertStringSidToSid("S-1-15-3-3", out privateNetwork))
                ThrowLastError("ConvertStringSidToSid(privateNetworkClientServer)");

            int sidAttributeSize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
            capabilityArray = Marshal.AllocHGlobal(sidAttributeSize * 2);
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES {
                Sid = internetClient, Attributes = SE_GROUP_ENABLED
            }, capabilityArray, false);
            Marshal.StructureToPtr(new SID_AND_ATTRIBUTES {
                Sid = privateNetwork, Attributes = SE_GROUP_ENABLED
            }, IntPtr.Add(capabilityArray, sidAttributeSize), false);

            int hr = CreateAppContainerProfile(
                profile, profile, profile, capabilityArray, 2, out appContainerSid);
            if (hr == unchecked((int)0x800700B7))
                hr = DeriveAppContainerSidFromAppContainerName(profile, out appContainerSid);
            Marshal.ThrowExceptionForHR(hr);

            var capabilities = new SECURITY_CAPABILITIES {
                AppContainerSid = appContainerSid,
                Capabilities = capabilityArray,
                CapabilityCount = 2,
                Reserved = 0
            };
            securityCapabilities = Marshal.AllocHGlobal(
                Marshal.SizeOf<SECURITY_CAPABILITIES>());
            Marshal.StructureToPtr(capabilities, securityCapabilities, false);

            IntPtr attributeSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            attributeList = Marshal.AllocHGlobal(attributeSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeSize))
                ThrowLastError("InitializeProcThreadAttributeList");
            if (!UpdateProcThreadAttribute(
                attributeList, 0, SecurityCapabilitiesAttribute,
                securityCapabilities,
                new IntPtr(Marshal.SizeOf<SECURITY_CAPABILITIES>()),
                IntPtr.Zero, IntPtr.Zero))
                ThrowLastError("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)");

            var startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            startup.lpAttributeList = attributeList;
            string command = "\"" + executable + "\" " + arguments;
            if (!CreateProcess(
                executable, new System.Text.StringBuilder(command),
                IntPtr.Zero, IntPtr.Zero, false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero, System.IO.Path.GetDirectoryName(executable),
                ref startup, out PROCESS_INFORMATION process))
                ThrowLastError("CreateProcessW(AppContainer proxy)");

            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            return process.dwProcessId;
        }
        finally
        {
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (securityCapabilities != IntPtr.Zero)
                Marshal.FreeHGlobal(securityCapabilities);
            if (appContainerSid != IntPtr.Zero) FreeSid(appContainerSid);
            if (capabilityArray != IntPtr.Zero) Marshal.FreeHGlobal(capabilityArray);
            if (privateNetwork != IntPtr.Zero) LocalFree(privateNetwork);
            if (internetClient != IntPtr.Zero) LocalFree(internetClient);
        }
    }
}
'@
}

function Wait-Proxy {
    param([int]$Port)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $lastError = $null
    do {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return
        } catch [Net.Sockets.SocketException] {
            $lastError = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        } finally {
            $client.Dispose()
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Proxy did not listen on 127.0.0.1:$Port. Last socket error: $lastError"
}

function Invoke-Client {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$AllowedPeer,
        [ValidateSet('allow', 'deny')][string]$HostLoopback = 'deny',
        [switch]$ExpectFailure
    )

    $clientCommand = 'powershell.exe -NoProfile -Command "$h=New-Object -ComObject ' +
        'WinHttp.WinHttpRequest.5.1; $h.Open(''GET'',''https://www.example.com'',$false); ' +
        '$h.Send(); if ($h.Status -ne 200) { exit 1 }; Write-Output $h.ResponseText"'
    $config = @{
        version = '0.8.0-alpha'
        containerId = "proxy-client-$Name"
        containment = 'processcontainer'
        process = @{ commandLine = $clientCommand }
        network = @{
            egress = @{ default = 'deny' }
            ingress = @{ default = 'allow'; hostLoopback = $HostLoopback }
        }
        runtimeConfig = @{ networkProxy = "http://127.0.0.1:$proxyPort" }
        processContainer = @{}
    }
    if ($AllowedPeer) {
        $config.processContainer.network = @{ allowedProxyPeer = $AllowedPeer }
    }
    $configPath = Join-Path $testRoot "$Name.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding utf8
    & $wxc --config $configPath
    if ($ExpectFailure) {
        if ($LASTEXITCODE -eq 0) {
            throw "$Name unexpectedly succeeded"
        }
        return
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Name client failed with exit code $LASTEXITCODE"
    }
}

function Start-PackagedProxy {
    param([Parameter(Mandatory)][string]$PackageName)
    $package = Get-AppxPackage -Name $PackageName
    if (-not $package) {
        throw "Installed package $PackageName was not found"
    }
    $pidValue = [MxcProxyActivation]::Activate(
        "$($package.PackageFamilyName)!Proxy",
        "--port $proxyPort --standalone"
    )
    $process = Get-Process -Id $pidValue
    $script:processes += $process
    Wait-Proxy $proxyPort
    $process.Refresh()
    if ($process.HasExited) {
        throw "Packaged proxy $PackageName exited before becoming ready"
    }
    return $package.PackageFamilyName
}

function Start-UnpackagedProxy {
    $process = Start-Process $proxy -ArgumentList '--port', $proxyPort, '--standalone' -PassThru
    $script:processes += $process
    Wait-Proxy $proxyPort
    $process.Refresh()
    if ($process.HasExited) {
        throw 'Unpackaged full-trust proxy exited before becoming ready'
    }
}

New-Item -ItemType Directory $testRoot -Force | Out-Null
try {
    $packages = & $packageBuilder -ProxyBinary $proxy -OutputDirectory $PackageOutput
    $trustedCertificate = Import-Certificate -FilePath $packages.Certificate `
        -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople'

    foreach ($packagePath in $packages.AppContainerPackage, $packages.FullTrustPackage) {
        Add-AppxPackage $packagePath
    }

    $wrongPeer = (Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.FullTrust').PackageFamilyName
    $peer = Start-PackagedProxy 'Microsoft.MXC.TestProxy.AppContainer'
    Invoke-Client -Name 'packaged-appcontainer-wrong-peer' -AllowedPeer $wrongPeer `
        -ExpectFailure
    Invoke-Client -Name 'packaged-appcontainer' -AllowedPeer $peer
    $processes[-1] | Stop-Process -Force
    $processes[-1].WaitForExit()

    $peer = Start-PackagedProxy 'Microsoft.MXC.TestProxy.FullTrust'
    Invoke-Client -Name 'packaged-fulltrust' -AllowedPeer $peer
    $processes[-1] | Stop-Process -Force
    $processes[-1].WaitForExit()

    $proxyPid = [MxcUnpackagedAppContainer]::Launch(
        $appContainerProfile,
        $proxy,
        "--port $proxyPort --standalone"
    )
    $process = Get-Process -Id $proxyPid
    $processes += $process
    $profileSid = [MxcProxyActivation]::DeriveSid($appContainerProfile)
    $rule = "MXC proxy test $PID appcontainer"
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $proxyPort -Program $proxy -Package $profileSid | Out-Null
    $firewallRules += $rule

    Wait-Proxy $proxyPort
    $process.Refresh()
    if ($process.HasExited) {
        throw 'Unpackaged AppContainer proxy exited before becoming ready'
    }
    Invoke-Client -Name 'unpackaged-appcontainer' -AllowedPeer $appContainerProfile
    $process | Stop-Process -Force
    $process.WaitForExit()

    $rule = "MXC proxy test $PID fulltrust"
    New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $proxyPort -Program $proxy | Out-Null
    $firewallRules += $rule
    Start-UnpackagedProxy
    Invoke-Client -Name 'unpackaged-fulltrust' -HostLoopback allow
} finally {
    foreach ($process in $processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($rule in $firewallRules) {
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    }
    Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.AppContainer' |
        Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.FullTrust' |
        Remove-AppxPackage -ErrorAction SilentlyContinue
    if ($trustedCertificate) {
        Remove-Item "Cert:\CurrentUser\TrustedPeople\$($trustedCertificate.Thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
    [MxcUnpackagedAppContainer]::DeleteAppContainerProfile(
        $appContainerProfile
    ) | Out-Null
    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
