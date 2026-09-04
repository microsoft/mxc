using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Diplomat.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct DiplomatSliceU8
{
    public byte* Ptr;
    public nuint Len;
}