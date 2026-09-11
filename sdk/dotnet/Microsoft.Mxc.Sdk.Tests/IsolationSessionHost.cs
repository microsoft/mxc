// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The live-host gate the isolation-session suites share. A live run needs
/// Windows, the OS-side service, and a native library built with the
/// isolation_session feature.
/// </summary>
internal static class IsolationSessionHost
{
    // Evaluated once: this answer decides failure versus skip, so it has to be
    // the same for every test that consults it.
    private static readonly Lazy<bool> Available = new(() =>
        MxcSandbox.GetAvailableBackends()
            .Any(b => b.Backend == ContainmentBackend.IsolationSession));

    // Without this, a run in which everything skipped is indistinguishable from
    // one that passed. The same variable the Rust isolation-session suite honours.
    private static bool SkipsAreFailures =>
        Environment.GetEnvironmentVariable("MXC_ISO_TESTS_REQUIRED") is "1" or "true";

    /// <summary>Skips the calling test when the backend is unavailable, or fails
    /// it when skips have been declared failures.</summary>
    internal static void Require()
    {
        Assert.False(
            SkipsAreFailures && !Available.Value,
            "MXC_ISO_TESTS_REQUIRED is set, but GetAvailableBackends() does not "
                + "report the isolation-session backend. That needs both a build "
                + "with MxcWithIsolationSession and a host running the OS-side "
                + "service.");
        Assert.SkipUnless(
            Available.Value,
            "GetAvailableBackends() does not report the isolation-session backend");
    }
}
