// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// The containment backend a sandbox is provisioned under. Selected at
/// provision; the later phases identify the sandbox by the <see cref="SandboxId"/>
/// provision returned, so they take no containment.
/// </summary>
public enum StateAwareContainment
{
    /// <summary>Windows IsolationSession (experimental; requires its OS-side service).</summary>
    IsolationSession,
}

/// <summary>
/// The default action for traffic with no matching rule. The zero value is
/// <see cref="Block"/>, so a policy left unset denies rather than allows.
/// </summary>
public enum StateAwareNetworkDefault
{
    /// <summary>Deny traffic by default.</summary>
    Block,

    /// <summary>Allow traffic by default.</summary>
    Allow,
}

/// <summary>
/// Network posture sent on a state-aware lifecycle request. This is the wire
/// vocabulary the lifecycle phases use, a different layer from the one-shot
/// <see cref="NetworkPolicy"/>.
/// </summary>
public sealed class StateAwareNetworkPolicy
{
    /// <summary>The default action for outbound traffic.</summary>
    public StateAwareNetworkDefault DefaultPolicy { get; set; }

    /// <summary>Whether the sandbox may reach the local network.</summary>
    public bool AllowLocalNetwork { get; set; }
}

/// <summary>
/// Filesystem posture sent on a state-aware lifecycle request. This is the wire
/// vocabulary the lifecycle phases use, a different layer from the one-shot
/// <see cref="FilesystemPolicy"/>.
/// </summary>
public sealed class StateAwareFilesystemPolicy
{
    /// <summary>Paths the sandbox can read and write.</summary>
    public List<string> ReadwritePaths { get; set; } = new();

    /// <summary>Paths the sandbox can read but not write.</summary>
    public List<string> ReadonlyPaths { get; set; } = new();

    /// <summary>Paths explicitly denied, overriding broader allow rules.</summary>
    public List<string> DeniedPaths { get; set; } = new();
}

/// <summary>Options for <see cref="MxcLifecycle.ProvisionSandbox"/>.</summary>
public sealed class ProvisionSandboxOptions
{
    /// <summary>
    /// Network posture for the sandbox, fixed for its lifetime. Sent only when
    /// supplied; a backend may refuse an absent policy rather than default it.
    /// </summary>
    public StateAwareNetworkPolicy? Network { get; set; }

    /// <summary>
    /// Filesystem policy applied at provision, immutable for the sandbox's
    /// lifetime.
    /// </summary>
    public StateAwareFilesystemPolicy? Filesystem { get; set; }

    /// <summary>
    /// Application identity for the sandbox, fixed at provision. A packaged app
    /// passes its Package Family Name as <c>PFN:&lt;packageFamilyName&gt;</c>.
    /// Validated structurally only: no control characters, at most 256
    /// characters; an explicitly supplied empty string is a distinct value from
    /// omitting the field.
    /// </summary>
    public string? AppId { get; set; }
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
