// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Mxc.Sdk;

/// <summary>Schema versions supported by this SDK release.</summary>
/// <remarks>
/// These values mirror <c>schemas/schema-version.json</c>. The repository's
/// schema-version drift gate enforces that the canonical file, Rust parser,
/// TypeScript SDK, and this managed surface remain synchronized.
/// </remarks>
public static class SchemaVersions
{
    /// <summary>Oldest accepted schema version.</summary>
    public const string Minimum = "0.6.0-alpha";

    /// <summary>Newest accepted schema version, including development contracts.</summary>
    public const string MaximumSupported = "0.9.0-alpha";

    /// <summary>Newest immutable released schema.</summary>
    public const string LatestStable = "0.8.0-alpha";

    /// <summary>Default state-aware version for IsolationSession and Windows Sandbox.</summary>
    public const string StateAware = "0.6.0-alpha";

    /// <summary>Default state-aware version for WSLC.</summary>
    public const string WslcStateAware = "0.8.0-alpha";

    /// <summary>Default state-aware version for LXC.</summary>
    public const string LxcStateAware = "0.8.0-alpha";
}
