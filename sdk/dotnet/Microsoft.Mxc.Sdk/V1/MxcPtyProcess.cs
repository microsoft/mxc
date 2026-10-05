// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>Dimensions of an MXC pseudo-terminal.</summary>
public readonly record struct MxcPtySize(ushort Rows, ushort Columns)
{
    /// <summary>The default 24-row by 80-column terminal.</summary>
    public static MxcPtySize Default { get; } = new(24, 80);

    internal static MxcPtySize ResolveInitial(MxcPtySize? requested) =>
        requested ?? Default;

    internal void Validate(string paramName)
    {
        if (Rows == 0
            || Columns == 0
            || Rows > short.MaxValue
            || Columns > short.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                "PTY rows and columns must be between 1 and 32767.");
        }
    }
}

/// <summary>A live container process attached to a caller-driven pseudo-terminal.</summary>
public sealed class MxcPtyProcess : MxcProcess
{
    internal MxcPtyProcess(MxcSandboxHandle handle, uint? timeoutMs)
        : base(handle, timeoutMs)
    {
    }

    /// <summary>
    /// Writable terminal input. Closing it requests terminal EOF in canonical mode;
    /// raw-mode programs must define their own completion protocol.
    /// </summary>
    public Stream Input =>
        StandardInput ?? throw MissingStream("input");

    /// <summary>Readable merged terminal output.</summary>
    public Stream Output =>
        StandardOutput ?? throw MissingStream("output");

    /// <summary>Resize the child terminal.</summary>
    public void Resize(MxcPtySize size)
    {
        size.Validate(nameof(size));
        ResizePty(size);
    }

    private static MxcException MissingStream(string name) =>
        new(
            ErrorCode.BackendError,
            $"the selected backend did not expose PTY {name}");
}
