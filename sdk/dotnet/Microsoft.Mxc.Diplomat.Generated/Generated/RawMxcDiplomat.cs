using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomat
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_version", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatVersionMxcDiplomatError Version();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_discover", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatDiscoveryMxcDiplomatError Discover();

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_run", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatRunResultMxcDiplomatError Run(DiplomatSliceU8 requestJson);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_spawn", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatSandboxMxcDiplomatError Spawn(DiplomatSliceU8 requestJson);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_provision", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatStateAwareEnvelopeMxcDiplomatError Provision(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool dryRun, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_start", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatStateAwareEnvelopeMxcDiplomatError Start(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool dryRun, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_stop", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatStateAwareEnvelopeMxcDiplomatError Stop(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool dryRun, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_deprovision", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatStateAwareEnvelopeMxcDiplomatError Deprovision(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool dryRun, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_exec", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatSandboxMxcDiplomatError Exec(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_exec_attached", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultMxcDiplomatWaitResultMxcDiplomatError ExecAttached(DiplomatSliceU8 requestJson, [MarshalAs(UnmanagedType.U1)] bool experimental);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomat_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomat* handle);
}