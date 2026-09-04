using System;
using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Diplomat.Raw;

using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Diplomat;

[StructLayout(LayoutKind.Sequential)]
internal partial struct DiplomatResultVoidUnit
{

    public DiplomatBool IsOk;
}