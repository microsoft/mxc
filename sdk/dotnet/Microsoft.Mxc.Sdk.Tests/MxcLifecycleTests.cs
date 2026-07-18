// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcLifecycleTests
{
    // The only state-aware backend (IsolationSession) is Windows-only,
    // experimental, and needs its OS-side service, so end-to-end lifecycle runs
    // are CI/host-gated. These host-independent tests assert the facade's
    // contract: request routing and typed error mapping. Provisioning without a
    // usable backend surfaces a typed error — UnsupportedPhase when the native
    // library is built without the engine's isolation_session feature (the
    // default dotnetsdk build), or BackendUnavailable when it is built with the
    // feature but the OS-side service is absent — either way exercising envelope
    // construction + the native round trip + error mapping.
    private static void AssertNoUsableBackend(MxcException ex) =>
        Assert.True(
            ex.Code is ErrorCode.UnsupportedPhase or ErrorCode.BackendUnavailable,
            $"expected UnsupportedPhase or BackendUnavailable, got {ex.Code}");

    [Fact]
    public void ProvisionSandbox_WithoutBackend_FailsWithTypedError()
    {
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ProvisionSandbox());
        AssertNoUsableBackend(ex);
    }

    [Fact]
    public void ProvisionSandbox_WithFilesystemAndUser_FailsWithTypedError()
    {
        // Exercises the fuller envelope (cross-cutting filesystem lifted to top
        // level, user nested under experimental.isolation_session.provision).
        var options = new ProvisionSandboxOptions
        {
            Filesystem = new FilesystemPolicy { ReadwritePaths = { @"C:\Temp" } },
            User = new SandboxUserCredentials { Upn = "agent@contoso.com", WamToken = "token" },
        };
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ProvisionSandbox(options));
        AssertNoUsableBackend(ex);
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

    [Fact]
    public void BuildProvisionEnvelope_LiftsFilesystem_NestsUserUnderExperimental()
    {
        var options = new ProvisionSandboxOptions
        {
            Filesystem = new FilesystemPolicy { ReadwritePaths = { @"C:\Temp" } },
            User = new SandboxUserCredentials { Upn = "agent@contoso.com", WamToken = "tok" },
        };

        var json = MxcLifecycle.BuildProvisionEnvelope(options).ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("provision", root.GetProperty("phase").GetString());
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());
        // Cross-cutting filesystem lifted to the top level.
        Assert.Equal(@"C:\Temp",
            root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());
        // Backend-specific user nested under experimental.isolation_session.provision.
        var user = root.GetProperty("experimental")
            .GetProperty("isolation_session")
            .GetProperty("provision")
            .GetProperty("user");
        Assert.Equal("agent@contoso.com", user.GetProperty("upn").GetString());
        Assert.Equal("tok", user.GetProperty("wamToken").GetString());
    }

    [Fact]
    public void BuildProvisionEnvelope_Minimal_HasNoExperimentalOrFilesystem()
    {
        var json = MxcLifecycle.BuildProvisionEnvelope(null).ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("provision", root.GetProperty("phase").GetString());
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());
        Assert.False(root.TryGetProperty("filesystem", out _));
        Assert.False(root.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void BuildExecEnvelope_CarriesSandboxIdAndCommandLine()
    {
        var json = MxcLifecycle.BuildExecEnvelope(new SandboxId("iso:abc"), "cmd /c echo hi").ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("exec", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        Assert.Equal("cmd /c echo hi",
            root.GetProperty("process").GetProperty("commandLine").GetString());
    }

    [Fact]
    public void BuildStartEnvelope_EmitsSizeAsConfigurationId()
    {
        // The sizing profile must reach the wire under `configurationId` — the
        // key the IsolationSessionPhase wire model actually reads. Emitting it as
        // `size` (the historical bug) is silently dropped by the permissive
        // experimental block, discarding every StartSandboxOptions.Size value.
        var options = new StartSandboxOptions { Size = "large" };
        var json = MxcLifecycle.BuildStartEnvelope(new SandboxId("iso:abc"), options).ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var start = doc.RootElement
            .GetProperty("experimental")
            .GetProperty("isolation_session")
            .GetProperty("start");

        Assert.Equal("large", start.GetProperty("configurationId").GetString());
        Assert.False(start.TryGetProperty("size", out _), "size profile must not be emitted under the ignored 'size' key");
    }

    [Fact]
    public void BuildStartEnvelope_Minimal_HasNoExperimental()
    {
        var json = MxcLifecycle.BuildStartEnvelope(new SandboxId("iso:abc"), null).ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("start", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        Assert.False(root.TryGetProperty("experimental", out _));
    }
}
