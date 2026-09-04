using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatInputStream
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatInputStream_write", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultULongMxcDiplomatError Write(MxcDiplomatInputStream* handle, DiplomatSliceU8 bytes);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatInputStream_flush", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidMxcDiplomatError Flush(MxcDiplomatInputStream* handle);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatInputStream_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatInputStream* handle);
}