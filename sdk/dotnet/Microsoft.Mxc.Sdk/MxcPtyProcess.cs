// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>Dimensions of an MXC pseudo-terminal.</summary>
public readonly record struct MxcPtySize(ushort Rows, ushort Columns)
{
    /// <summary>The default 24-row by 80-column terminal.</summary>
    public static MxcPtySize Default { get; } = new(24, 80);

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

/// <summary>A live sandbox process attached to a caller-driven pseudo-terminal.</summary>
public sealed class MxcPtyProcess : MxcSandboxProcess
{
    internal MxcPtyProcess(MxcSandboxHandle handle, uint? timeoutMs)
        : base(handle, timeoutMs)
    {
    }

    /// <summary>Writable terminal input. Closing it sends EOF.</summary>
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
