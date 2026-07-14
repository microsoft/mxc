// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Optional Entra credentials for provisioning an IsolationSession cloud-agent
/// sandbox. When supplied at provision, the same credentials must be supplied at
/// start. Hosts that do not support Entra agents surface a
/// <see cref="ErrorCode.BackendUnavailable"/> error.
/// </summary>
public sealed class SandboxUserCredentials
{
    /// <summary>The user principal name (UPN).</summary>
    public string Upn { get; set; } = string.Empty;

    /// <summary>The WAM token authorising the identity.</summary>
    public string WamToken { get; set; } = string.Empty;
}

/// <summary>Options for <see cref="MxcLifecycle.ProvisionSandbox"/>.</summary>
public sealed class ProvisionSandboxOptions
{
    /// <summary>
    /// Filesystem policy applied at provision (immutable for the sandbox's
    /// lifetime). Shares the same shape as one-shot <see cref="FilesystemPolicy"/>.
    /// </summary>
    public FilesystemPolicy? Filesystem { get; set; }

    /// <summary>Optional Entra credentials for a cloud-agent sandbox.</summary>
    public SandboxUserCredentials? User { get; set; }
}

/// <summary>Options for <see cref="MxcLifecycle.StartSandbox"/>.</summary>
public sealed class StartSandboxOptions
{
    /// <summary>
    /// Selected IsoSession size profile. Unknown values are warned and
    /// downgraded to <c>composable</c> on the native side.
    /// </summary>
    public string? Size { get; set; }

    /// <summary>Optional Entra credentials (must match those given at provision).</summary>
    public SandboxUserCredentials? User { get; set; }
}

/// <summary>The result of <see cref="MxcLifecycle.ProvisionSandbox"/>.</summary>
public sealed class ProvisionResult
{
    /// <summary>The freshly minted sandbox id, used for the later lifecycle phases.</summary>
    public SandboxId SandboxId { get; init; }

    /// <summary>
    /// Backend-typed provision metadata as raw JSON (e.g. the per-instance agent
    /// user identity), or null when the backend produced none.
    /// </summary>
    public string? MetadataJson { get; init; }
}
