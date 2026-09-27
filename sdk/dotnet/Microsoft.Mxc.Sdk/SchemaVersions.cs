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
    private const string V0_9_0Alpha = "0.9.0-alpha";

    /// <summary>Oldest accepted schema version.</summary>
    public const string Minimum = "0.6.0-alpha";

    /// <summary>Newest accepted schema version, including development contracts.</summary>
    public const string MaximumSupported = "1.1.0-alpha";

    /// <summary>Newest immutable released schema.</summary>
    public const string LatestStable = "1.0.0";

    /// <summary>Exact contract owned by the v1 high-level SDK.</summary>
    internal const string SdkContract = LatestStable;

    internal const string StateAware = SdkContract;

    internal static bool IsPublished(string version) =>
        version is Minimum or V0_7_0Alpha or "0.8.0-alpha" or V0_9_0Alpha or LatestStable;

    internal static bool UsesLegacyNetworkDefaults(string version) =>
        version is Minimum or V0_7_0Alpha or "0.8.0-alpha";

    internal static bool IsSupported(string version) =>
        IsPublished(version) || version == MaximumSupported;
}
