// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The outcome of waiting on an <see cref="MxcSandboxProcess"/> via
/// <see cref="MxcSandboxProcess.Wait"/> / <see cref="MxcSandboxProcess.WaitAsync"/>.
/// </summary>
public readonly struct SandboxWaitResult
{
    /// <summary>The process exit code (valid when <see cref="TimedOut"/> is false).</summary>
    public int ExitCode { get; init; }

    /// <summary>
    /// True if the run hit its <see cref="SandboxPolicy.TimeoutMs"/> and the
    /// process (and its tree) were killed before exiting normally.
    /// </summary>
    public bool TimedOut { get; init; }
}
