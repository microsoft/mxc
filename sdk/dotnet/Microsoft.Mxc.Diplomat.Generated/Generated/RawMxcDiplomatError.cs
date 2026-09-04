using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatError
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_code", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern MxcDiplomatErrorCode Code(MxcDiplomatError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_message", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Message(MxcDiplomatError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_has_operation", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool HasOperation(MxcDiplomatError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_operation", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Operation(MxcDiplomatError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_has_native_code", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool HasNativeCode(MxcDiplomatError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_native_code", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit NativeCode(MxcDiplomatError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_has_remediation", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static unsafe extern bool HasRemediation(MxcDiplomatError* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_remediation", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Remediation(MxcDiplomatError* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatError_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatError* handle);
}