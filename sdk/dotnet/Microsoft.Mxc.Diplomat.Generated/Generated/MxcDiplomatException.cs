using System;

namespace Microsoft.Mxc.Diplomat;

/// <summary>
/// If <c>MxcDiplomatError</c> is an opaque error that borrows from an opaque
/// parameter or the receiver, that dependency is retained by <c>Inner</c>'s
/// own native resource state (see <c>RustHandle.cs</c>) rather than by
/// this exception class — so no separate keep-alive plumbing is needed here.
/// </summary>
public class MxcDiplomatException : Exception
{
    public MxcDiplomatError Inner { get; }

    public MxcDiplomatException(MxcDiplomatError inner) : base(
        inner.Message()
    )
    {
        Inner = inner;
    }
}