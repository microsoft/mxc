// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The live-host gate for Bubblewrap tests: Linux with a usable `bwrap` that
/// <see cref="MxcPlatform.GetAvailableBackends"/> reports.
/// </summary>
internal static class BubblewrapHost
{
    // Evaluated once: this answer decides failure versus skip, so it has to be
    // the same for every test that consults it.
    private static readonly Lazy<bool> Available = new(() =>
        OperatingSystem.IsLinux()
        && MxcPlatform.GetAvailableBackends()
            .Any(b => b.Backend == ContainmentBackend.Bubblewrap));

    // The same variable the Rust Bubblewrap suites honour.
    private static bool SkipsAreFailures =>
        Environment.GetEnvironmentVariable("MXC_BWRAP_TESTS_REQUIRE_EXECUTION") is "1" or "true";

    /// <summary>Skips the calling test when Bubblewrap is unavailable, or fails
    /// it when skips have been declared failures.</summary>
    internal static void Require()
    {
        Assert.False(
            SkipsAreFailures && !Available.Value,
            "MXC_BWRAP_TESTS_REQUIRE_EXECUTION is set, but this host cannot run "
                + "Bubblewrap. That needs Linux and a usable bwrap that "
                + "GetAvailableBackends() reports.");
        Assert.SkipUnless(Available.Value, "this host has no Bubblewrap backend");
    }
}
