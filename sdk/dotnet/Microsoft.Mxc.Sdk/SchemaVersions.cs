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
    private const string V0_7_0Alpha = "0.7.0-alpha";

    /// <summary>Oldest accepted schema version.</summary>
    public const string Minimum = GeneratedSchemaVersions.Minimum;

    /// <summary>Newest accepted schema version, including development contracts.</summary>
    public const string MaximumSupported = GeneratedSchemaVersions.MaximumSupported;

    /// <summary>Newest immutable released schema.</summary>
    public const string LatestStable = GeneratedSchemaVersions.LatestStable;

    /// <summary>Default state-aware version for IsolationSession.</summary>
    public const string StateAware = GeneratedSchemaVersions.StateAware;

    /// <summary>Default state-aware version for Windows Sandbox.</summary>
    public const string WindowsSandboxStateAware =
        GeneratedSchemaVersions.WindowsSandboxStateAware;

    /// <summary>Default state-aware version for WSLC.</summary>
    public const string WslcStateAware = GeneratedSchemaVersions.WslcStateAware;

    internal static bool IsPublished(string version) =>
        version is Minimum or V0_7_0Alpha or "0.8.0-alpha" or LatestStable;

    internal static bool UsesLegacyNetworkDefaults(string version) =>
        version is Minimum or V0_7_0Alpha or "0.8.0-alpha";

    internal static bool IsSupported(string version) =>
        IsPublished(version) || version == MaximumSupported;
}
