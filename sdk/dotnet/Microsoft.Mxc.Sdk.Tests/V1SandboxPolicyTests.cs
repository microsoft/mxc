// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class V1SandboxPolicyTests
{
    [Fact]
    public void SandboxPolicy_RejectsRemovedVersionDuringDeserialization()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SandboxPolicy>(
                """{"version":"0.9.0-alpha"}"""));
    }

    [Theory]
    [InlineData("allowOutbound")]
    [InlineData("unknownNetworkField")]
    public void SandboxPolicy_RejectsUnknownNetworkDuringDeserialization(string field)
    {
        var error = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SandboxPolicy>(
                $$$"""{"network":{"{{{field}}}":true}}"""));
        Assert.Contains(field, error.Message);
    }

    [Theory]
    [InlineData("egress")]
    [InlineData("ingress")]
    public void SandboxPolicy_RejectsExplicitNullNetworkSections(string field)
    {
        var error = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SandboxPolicy>(
                $$$"""{"network":{"{{{field}}}":null}}"""));
        Assert.Contains("cannot be null", error.Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"network":{}}""")]
    public void SandboxPolicy_AllowsOmittedNetworkSections(string json)
    {
        var policy = JsonSerializer.Deserialize<SandboxPolicy>(json);
        Assert.NotNull(policy);
        Assert.Null(policy.Network?.Egress);
        Assert.Null(policy.Network?.Ingress);

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        Assert.Equal(
            policy.Network is not null,
            document.RootElement.TryGetProperty("network", out _));
        if (document.RootElement.TryGetProperty("network", out var network))
        {
            Assert.Empty(network.EnumerateObject());
        }
    }

    [Fact]
    public void SandboxPolicy_ProgrammaticNullNetworkSectionsAreOmitted()
    {
        var network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy(),
            Ingress = new NetworkIngressPolicy(),
        };
        network.Egress = null;
        network.Ingress = null;
        var policy = new SandboxPolicy { Network = network };

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        Assert.Empty(document.RootElement.GetProperty("network").EnumerateObject());
    }

    [Fact]
    public void SandboxPolicy_DeserializesDirectionalNetworkSections()
    {
        var options = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        };
        var policy = JsonSerializer.Deserialize<SandboxPolicy>(
            """
            {"network":{"egress":{"default":"deny"},"ingress":{"hostLoopback":"allow"}}}
            """,
            options);
        Assert.NotNull(policy);
        Assert.Equal(NetworkAction.Deny, policy.Network?.Egress?.Default);
        Assert.Equal(NetworkAction.Allow, policy.Network?.Ingress?.HostLoopback);

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var network = document.RootElement.GetProperty("network");
        Assert.Equal("deny", network.GetProperty("egress").GetProperty("default").GetString());
        Assert.Equal("allow", network.GetProperty("ingress").GetProperty("hostLoopback").GetString());
    }

    [Fact]
    public void SandboxPolicy_IsVersionFreeAndDirectional()
    {
        var policy = new SandboxPolicy
        {
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Allow,
                    HostLoopback = NetworkAction.Deny,
                },
                RuntimeConfig = new NetworkRuntimeConfig
                {
                    NetworkProxy = "http://127.0.0.1:8080",
                },
            },
        };

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var root = document.RootElement;
        Assert.False(root.TryGetProperty("version", out _));
        var network = root.GetProperty("network");
        Assert.Equal("deny", network.GetProperty("egress").GetProperty("default").GetString());
        Assert.Equal("allow", network.GetProperty("ingress").GetProperty("default").GetString());
        Assert.Equal(
            "http://127.0.0.1:8080",
            network.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString());
    }

    [Fact]
    public void SandboxRequest_UsesVersionFreePrivateBindingPolicy()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { TimeoutMs = 5000 },
            "echo test");

        using var document = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var policy = document.RootElement.GetProperty("policy");
        Assert.False(policy.TryGetProperty("version", out _));
        Assert.Equal(5000, policy.GetProperty("timeoutMs").GetInt32());
        Assert.Equal("echo test", document.RootElement.GetProperty("command").GetString());
    }

    [Fact]
    public void SandboxRequest_SerializesCompleteV1Policy()
    {
        var request = new SandboxRequest(
            new SandboxPolicy
            {
                Filesystem = new FilesystemPolicy
                {
                    ReadwritePaths = [@"C:\work"],
                    ReadonlyPaths = [@"C:\input"],
                    DeniedPaths = [@"C:\secret"],
                    ClearPolicyOnExit = false,
                },
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = NetworkAction.Deny,
                        Allow =
                        [
                            new NetworkRulePolicy
                            {
                                To = [new NetworkPeerPolicy("192.0.2.0/24")],
                            },
                        ],
                    },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Deny,
                        HostLoopback = NetworkAction.Allow,
                    },
                },
                Ui = new UiPolicy
                {
                    AllowWindows = true,
                    Clipboard = ClipboardPolicy.Read,
                },
            },
            "echo parity")
        {
            Containment = new ProcessContainerContainment
            {
                Filesystem = new ProcessContainerFilesystemPolicy
                {
                    EnumeratePaths = [@"C:\tools"],
                },
                Network = new ProcessContainerNetworkPolicy
                {
                    AllowedProxyPeer = "Contoso.Proxy_123",
                },
            },
            ContainerName = "sample",
        };

        using var document = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = document.RootElement;
        Assert.Equal("sample", root.GetProperty("containerName").GetString());
        Assert.Equal(
            @"C:\tools",
            root.GetProperty("containment")
                .GetProperty("filesystem")
                .GetProperty("enumeratePaths")[0]
                .GetString());
        Assert.Equal(
            "allow",
            root.GetProperty("policy")
                .GetProperty("network")
                .GetProperty("ingress")
                .GetProperty("hostLoopback")
                .GetString());
    }

    [Fact]
    public void SandboxRequest_MigratesCaptureDenialsToContainment()
    {
#pragma warning disable MXC0001
        var policy = new SandboxPolicy
        {
            CaptureDenials = new CaptureDenialsPolicy
            {
                Mode = CaptureDenialsMode.Allow,
            },
        };
#pragma warning restore MXC0001
        var request = new SandboxRequest(policy, "echo test");

        using var document = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        Assert.True(
            document.RootElement.GetProperty("containment")
                .TryGetProperty("captureDenials", out _));
        Assert.False(
            document.RootElement.GetProperty("policy")
                .TryGetProperty("captureDenials", out _));
    }

    [Fact]
    public void RunAndSpawnRejectNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(null!, "echo"));
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(new SandboxPolicy(), null!));
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Spawn(null!, "echo"));
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Spawn(new SandboxPolicy(), null!));
    }

    [Fact]
    public void DiscoveryMapsKnownAndUnknownBackends()
    {
        const string json =
            """
            [
              { "backend": "bubblewrap", "capabilities": ["proxyEnforcement"] },
              { "backend": "future_backend", "capabilities": ["futureCapability"] }
            ]
            """;

        var backends = MxcSandbox.ParseAvailableBackends(json);
        Assert.Equal(ContainmentBackend.Bubblewrap, backends[0].Backend);
        Assert.Equal(BackendCapability.ProxyEnforcement, Assert.Single(backends[0].Capabilities));
        Assert.Equal(ContainmentBackend.Unknown, backends[1].Backend);
        Assert.Equal(BackendCapability.Unknown, Assert.Single(backends[1].Capabilities));
    }
}
