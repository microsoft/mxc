// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// The result of running a sandbox to completion via
/// <see cref="MxcSandbox.Run(ContainerRequest)"/>.
/// </summary>
public sealed class Output
{
    /// <summary>The process exit code (valid when <see cref="TimedOut"/> is false).</summary>
    public int ExitCode { get; init; }

    /// <summary>True if the run hit its <see cref="ContainerRequest.TimeoutMs"/> and was killed.</summary>
    public bool TimedOut { get; init; }

    /// <summary>Everything the sandboxed process wrote to stdout.</summary>
    public string Stdout { get; init; } = string.Empty;

    /// <summary>Everything the sandboxed process wrote to stderr.</summary>
    public string Stderr { get; init; } = string.Empty;

    /// <summary>Structured outputs produced by optional sandbox features.</summary>
    public SandboxOutputMetadata? OutputMetadata { get; init; }

    /// <summary>
    /// Security warnings raised during the run, empty when there were none.
    /// </summary>
    /// <remarks>
    /// A policy that relaxes containment raises one — notably
    /// <c>permissiveLearningMode</c>, which disables deny-by-default. These are
    /// never written to the host's stderr, so inspecting this is the only way to
    /// see them.
    /// </remarks>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
