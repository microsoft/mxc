using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatOutputStream
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatOutputStream_read", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultULongMxcDiplomatError Read(MxcDiplomatOutputStream* handle, DiplomatSliceMutU8 bytes);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatOutputStream_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatOutputStream* handle);
}