using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Diplomat.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct DiplomatSliceU32
{
    public uint* Ptr;
    public nuint Len;
}