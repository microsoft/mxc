using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatRunResult
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_exit_code", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern int ExitCode(MxcDiplomatRunResult* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_timed_out", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool TimedOut(MxcDiplomatRunResult* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_stdout", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Stdout(MxcDiplomatRunResult* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_stderr", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Stderr(MxcDiplomatRunResult* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_has_output_metadata", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool HasOutputMetadata(MxcDiplomatRunResult* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_output_metadata_json", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit OutputMetadataJson(MxcDiplomatRunResult* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_warnings_json", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit WarningsJson(MxcDiplomatRunResult* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatRunResult_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatRunResult* handle);
}