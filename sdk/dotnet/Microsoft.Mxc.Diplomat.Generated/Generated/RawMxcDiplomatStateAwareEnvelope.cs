using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

namespace Microsoft.Mxc.Diplomat.Raw;

[StructLayout(LayoutKind.Sequential)]
internal partial struct MxcDiplomatStateAwareEnvelope
{

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatStateAwareEnvelope_response_json", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern DiplomatResultVoidUnit ResponseJson(MxcDiplomatStateAwareEnvelope* handle, DiplomatWrite* writeable);

    [DllImport(DiplomatNativeLib.Name, EntryPoint = "MxcDiplomatStateAwareEnvelope_destroy", CallingConvention = CallingConvention.Cdecl)]
    internal static unsafe extern void Destroy(MxcDiplomatStateAwareEnvelope* handle);
}