// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcLifecycleTests
{
    // The only state-aware backend (IsolationSession) is Windows-only,
    // experimental, and needs its OS-side service, so end-to-end lifecycle runs
    // are CI/host-gated. These host-independent tests assert the facade's
    // contract: request routing and typed error mapping. Because the packaged
    // native library does not enable the engine's isolation_session feature,
    // provisioning surfaces UnsupportedPhase rather than attempting a backend
    // call — which still exercises envelope construction + the native round trip
    // + error mapping.

    [Fact]
    public void ProvisionSandbox_WithoutBackend_ThrowsUnsupportedPhase()
    {
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ProvisionSandbox());
        Assert.Equal(ErrorCode.UnsupportedPhase, ex.Code);
    }

    [Fact]
    public void ProvisionSandbox_WithFilesystemAndUser_ThrowsUnsupportedPhase()
    {
        // Exercises the fuller envelope (cross-cutting filesystem lifted to top
        // level, user nested under experimental.isolation_session.provision).
        var options = new ProvisionSandboxOptions
        {
            Filesystem = new FilesystemPolicy { ReadwritePaths = { @"C:\Temp" } },
            User = new SandboxUserCredentials { Upn = "agent@contoso.com", WamToken = "token" },
        };
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ProvisionSandbox(options));
        Assert.Equal(ErrorCode.UnsupportedPhase, ex.Code);
    }

    [Fact]
    public void StartSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        // A non-provision phase resolves the backend from the id prefix; an
        // unknown prefix is unsupported_containment.
        var id = new SandboxId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StartSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void StopSandbox_MalformedId_ThrowsMalformedId()
    {
        // No backend prefix at all is a malformed id.
        var id = new SandboxId("no-prefix");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void ExecInSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        var id = new SandboxId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ExecInSandbox(id, "echo hi"));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void ExecInSandbox_NullCommand_Throws()
    {
        var id = new SandboxId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.ExecInSandbox(id, null!));
    }

    [Fact]
    public void SandboxId_RoundTripsAndCompares()
    {
        var a = new SandboxId("iso:abc");
        var b = new SandboxId("iso:abc");
        var c = new SandboxId("iso:xyz");
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal("iso:abc", a.Value);
        Assert.Equal("iso:abc", a.ToString());
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void SandboxId_EmptyValue_Throws()
    {
        Assert.Throws<ArgumentException>(() => new SandboxId(""));
        Assert.Throws<ArgumentException>(() => new SandboxId(null!));
    }
}
