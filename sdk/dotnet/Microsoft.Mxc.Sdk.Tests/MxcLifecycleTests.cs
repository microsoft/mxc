// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcLifecycleTests
{
    [Fact]
    public void StartSandbox_PassesTheExperimentalOptIn()
    {
        // Without the opt-in the engine refuses an experimental backend *before*
        // backend dispatch, with BackendUnavailable naming "experimental". This
        // facade always passes it, so that specific refusal must not appear.
        // A registered prefix carrying an id that was never provisioned cannot
        // succeed, so the assertion holds whether or not the isolation_session
        // feature was compiled in and whether or not the host has the service --
        // and it provisions nothing.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartSandbox(new SandboxId("iso:0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        // A non-provision phase resolves the backend from the id prefix; an
        // unknown prefix is unsupported_containment, independent of host and
        // build features.
        var id = new SandboxId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StartSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void ExecInSandbox_PassesTheExperimentalOptIn()
    {
        // The streaming entry point carries the opt-in on its own path: it and the
        // envelope phases reach the same gate by different routes, so hardcoding
        // the flag in one would leave the other green. A `wsb:` id resolves to an
        // experimental backend without a host, a compiled-in isolation_session
        // feature, or a provisioned sandbox.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.ExecInSandbox(new SandboxId("wsb:0a1b2c3d"), "echo hi"));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void ExecInSandboxAttached_WithoutATerminal_ThrowsMalformedRequest()
    {
        // Crosses mxc_state_aware_exec_attached itself, which the envelope tests
        // cannot: it is a separate entry point. That gate short-circuits ahead of
        // backend dispatch, which is also why this test cannot pin the
        // experimental opt-in.
        Assert.SkipUnless(
            Console.IsOutputRedirected && Console.IsInputRedirected,
            "a console host satisfies the terminal gate, so the call would "
                + "dispatch a real attached exec rather than be refused by it");

        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.ExecInSandboxAttached(
                new SandboxId("iso:0123456789abcdef"), "echo hi"));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
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
    public void ExecInSandboxAttached_NullCommand_Throws()
    {
        var id = new SandboxId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.ExecInSandboxAttached(id, null!));
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
    public void BuildProvisionEnvelope_LiftsNetworkAndFilesystem_NestsAppId()
    {
        var options = new ProvisionSandboxOptions
        {
            Network = new StateAwareNetworkPolicy
            {
                DefaultPolicy = StateAwareNetworkDefault.Allow,
                AllowLocalNetwork = true,
            },
            Filesystem = new StateAwareFilesystemPolicy { ReadwritePaths = { @"C:\Temp" } },
            AppId = "PFN:Contoso.App_8wekyb3d8bbwe",
        };

        var json = MxcLifecycle
            .BuildProvisionEnvelope(StateAwareContainment.IsolationSession, options)
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("provision", root.GetProperty("phase").GetString());
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());

        // Cross-cutting policy is lifted to the envelope top level. The backend
        // reads `network` there; nesting it under experimental would leave the
        // acknowledgment unseen and provision would be refused as default-deny.
        var network = root.GetProperty("network");
        Assert.Equal("allow", network.GetProperty("defaultPolicy").GetString());
        Assert.True(network.GetProperty("allowLocalNetwork").GetBoolean());
        Assert.Equal(@"C:\Temp",
            root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());

        // Backend-specific config nests.
        var provision = root.GetProperty("experimental")
            .GetProperty("isolation_session")
            .GetProperty("provision");
        Assert.Equal("PFN:Contoso.App_8wekyb3d8bbwe", provision.GetProperty("appId").GetString());
    }

    [Fact]
    public void BuildProvisionEnvelope_DefaultsTheNetworkPostureToBlock()
    {
        // The enum's zero value is Block, so a caller who constructs the policy
        // without setting a posture sends one the backend can refuse on its
        // merits rather than a value the wire cannot decode.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                new ProvisionSandboxOptions { Network = new StateAwareNetworkPolicy() })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);

        Assert.Equal(
            "block",
            doc.RootElement.GetProperty("network").GetProperty("defaultPolicy").GetString());
    }

    [Fact]
    public void BuildProvisionEnvelope_SendsOnlyTheFilesystemFieldsTheWireAccepts()
    {
        // The lifecycle wire rejects an unknown filesystem member outright, so
        // this type carries only the members it accepts.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                new ProvisionSandboxOptions { Filesystem = new StateAwareFilesystemPolicy() })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);

        var names = doc.RootElement.GetProperty("filesystem")
            .EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[] { "deniedPaths", "readonlyPaths", "readwritePaths" }, names);

        // Serialization omits nulls, so the assertion above cannot see a nullable
        // member — the shape of the one-shot member this type exists to exclude.
        // Pin the public surface itself, as MxcExceptionTests does for its
        // constructor.
        var properties = typeof(StateAwareFilesystemPolicy)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[] { "DeniedPaths", "ReadonlyPaths", "ReadwritePaths" }, properties);
    }

    [Fact]
    public void BuildProvisionEnvelope_OmitsAnUnsuppliedNetwork()
    {
        // The acknowledgment is never emitted implicitly: supplying it on the
        // caller's behalf would accept an unfilterable network for them.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(StateAwareContainment.IsolationSession, null)
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("provision", root.GetProperty("phase").GetString());
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());
        Assert.False(root.TryGetProperty("network", out _));
        Assert.False(root.TryGetProperty("filesystem", out _));
        Assert.False(root.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void BuildExecEnvelope_CarriesSandboxIdAndCommandLine()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(new SandboxId("iso:abc"), "cmd /c echo hi")
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("exec", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        var process = root.GetProperty("process");
        Assert.Equal("cmd /c echo hi", process.GetProperty("commandLine").GetString());
        Assert.False(process.TryGetProperty("timeout", out _));
    }

    [Fact]
    public void BuildStartEnvelope_CarriesVersionAndSandboxIdOnly()
    {
        // The backend's start config is empty, so anything else on this envelope
        // would be a field the backend rejects or silently drops.
        var json = MxcLifecycle
            .BuildStartEnvelope(new SandboxId("iso:abc"))
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("start", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        Assert.False(root.TryGetProperty("experimental", out _));
        Assert.False(root.TryGetProperty("network", out _));
    }
}
