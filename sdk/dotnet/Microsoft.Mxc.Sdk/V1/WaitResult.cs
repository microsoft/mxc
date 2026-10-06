// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// The result of waiting for a contained process to finish.
/// </summary>
public readonly struct WaitResult
{
    /// <summary>The process exit code (valid when <see cref="TimedOut"/> is false).</summary>
    public int ExitCode { get; init; }

    /// <summary>
    /// True if the run hit its <see cref="ContainerRequest.TimeoutMs"/> and the
    /// process (and its tree) were killed before exiting normally.
    /// </summary>
    public bool TimedOut { get; init; }
}
