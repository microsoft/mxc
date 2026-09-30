// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The live-host gate the LXC suites share. A live run needs Linux, an
/// installed LXC, and root, because LXC creates, starts, and attaches to a
/// system container.
/// </summary>
internal static class LxcHost
{
    // Evaluated once: this answer decides failure versus skip, so it has to be
    // the same for every test that consults it.
    private static readonly Lazy<bool> Available = new(() =>
        OperatingSystem.IsLinux()
        && Environment.IsPrivilegedProcess
        && MxcPlatform.GetAvailableBackends()
            .Any(b => b.Backend == ContainmentBackend.Lxc));

    // Without this, a run in which everything skipped is indistinguishable from
    // one that passed. The same variable the Rust and shell LXC suites honour.
    private static bool SkipsAreFailures =>
        Environment.GetEnvironmentVariable("MXC_LXC_TESTS_REQUIRE_EXECUTION") is "1" or "true";

    /// <summary>Skips the calling test when LXC is unavailable, or fails it when
    /// skips have been declared failures.</summary>
    internal static void Require()
    {
        Assert.False(
            SkipsAreFailures && !Available.Value,
            "MXC_LXC_TESTS_REQUIRE_EXECUTION is set, but this host cannot run LXC. "
                + "That needs Linux, root, and an installed LXC that "
                + "GetAvailableBackends() reports.");
        Assert.SkipUnless(
            Available.Value,
            "this host has no LXC backend, or the test is not running as root");
    }
}
