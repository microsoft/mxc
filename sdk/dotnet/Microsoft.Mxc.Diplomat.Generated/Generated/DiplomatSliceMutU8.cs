using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Diplomat.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct DiplomatSliceMutU8
{
    public byte* Ptr;
    public nuint Len;
}