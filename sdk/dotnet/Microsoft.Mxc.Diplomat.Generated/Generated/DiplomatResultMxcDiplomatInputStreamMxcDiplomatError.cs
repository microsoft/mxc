using System;
using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Diplomat.Raw;

using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DiplomatResultMxcDiplomatInputStreamMxcDiplomatError
{
    [StructLayout(LayoutKind.Explicit)]
    private unsafe struct InnerUnion
    {
        [FieldOffset(0)] internal MxcDiplomatInputStream* ok;
        [FieldOffset(0)] internal MxcDiplomatError* err;
    }

    private InnerUnion _inner;

    public DiplomatBool IsOk;
    public unsafe MxcDiplomatInputStream* Ok => IsOk ? _inner.ok : throw new InvalidOperationException("Result does not contain Ok value");
    public unsafe MxcDiplomatError* Err => !IsOk ? _inner.err : throw new InvalidOperationException("Result does not contain Err value");
}