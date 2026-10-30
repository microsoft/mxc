// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// The result of running a container workload to completion via
/// <see cref="MxcContainer.Run(ContainerRequest)"/>.
/// </summary>
public sealed class ExecutionResult
{
    /// <summary>The process exit code (valid when <see cref="TimedOut"/> is false).</summary>
    public int ExitCode { get; init; }

    /// <summary>True if the run hit its <see cref="ContainerRequest.TimeoutMs"/> and was killed.</summary>
    public bool TimedOut { get; init; }

    /// <summary>Text decoded from the first 1 MiB of stdout; see <see cref="Warnings"/> for truncation.</summary>
    public string Stdout { get; init; } = string.Empty;

    /// <summary>Text decoded from the first 1 MiB of stderr; see <see cref="Warnings"/> for truncation.</summary>
    public string Stderr { get; init; } = string.Empty;

    /// <summary>Structured outputs produced by optional containment features.</summary>
    public ExecutionMetadata? OutputMetadata { get; init; }

    /// <summary>
    /// Security, operational, and output truncation warnings raised during the run.
    /// </summary>
    /// <remarks>
    /// A policy that relaxes containment raises one — notably
    /// <c>permissiveLearningMode</c>, which disables deny-by-default. These are
    /// never written to the host's stderr, so inspecting this is the only way to
    /// see them.
    /// </remarks>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
