using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatVersion
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatVersion_value", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit Value(MxcDiplomatVersion* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatVersion_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatVersion* handle);
}