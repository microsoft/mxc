// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The result of running a sandbox to completion via
/// <see cref="MxcSandbox.Run(SandboxPolicy, string)"/>.
/// </summary>
public sealed class RunResult
{
    /// <summary>The process exit code (valid when <see cref="TimedOut"/> is false).</summary>
    public int ExitCode { get; init; }

    /// <summary>True if the run hit its <see cref="SandboxPolicy.TimeoutMs"/> and was killed.</summary>
    public bool TimedOut { get; init; }

    /// <summary>Everything the sandboxed process wrote to stdout.</summary>
    public string Stdout { get; init; } = string.Empty;

    /// <summary>Everything the sandboxed process wrote to stderr.</summary>
    public string Stderr { get; init; } = string.Empty;
}
