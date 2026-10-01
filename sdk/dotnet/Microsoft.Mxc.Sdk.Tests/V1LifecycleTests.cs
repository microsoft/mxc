// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class V1LifecycleTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private static StateAwareNetworkPolicy IsolationNetwork() => new()
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
        Ingress = new NetworkIngressPolicy
        {
            Default = NetworkAction.Allow,
            HostLoopback = NetworkAction.Allow,
        },
    };

    [Theory]
    [InlineData("allowOutbound")]
    [InlineData("unknownNetworkField")]
    public void StateAwareOptions_RejectUnknownNetworkDuringDeserialization(string field)
    {
        var error = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<WslcProvisionOptions>(
                $$$"""{"network":{"{{{field}}}":true}}""",
                JsonOptions));
        Assert.Contains(field, error.Message);
    }

    [Theory]
    [InlineData("egress")]
    [InlineData("ingress")]
    public void StateAwareOptions_RejectExplicitNullNetworkSections(string field)
    {
        var error = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<StateAwareNetworkPolicy>(
                $$$"""{"{{{field}}}":null}""",
                MxcJson.Options));
        Assert.Contains("cannot be null", error.Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"network":{}}""")]
    public void StateAwareOptions_AllowOmittedNetworkSections(string json)
    {
        var options = JsonSerializer.Deserialize<WslcProvisionOptions>(json, JsonOptions);
        Assert.NotNull(options);
        Assert.Null(options.Network?.Egress);
        Assert.Null(options.Network?.Ingress);

        var envelope = MxcLifecycle.BuildProvisionEnvelope(StateAwareContainment.Wslc, options);
        Assert.Equal(options.Network is not null, envelope.ContainsKey("network"));
        if (envelope.TryGetPropertyValue("network", out var network))
        {
            Assert.NotNull(network);
            Assert.Empty(network.AsObject());
        }
    }

    [Fact]
    public void StateAwareOptions_ProgrammaticNullNetworkSectionsAreOmitted()
    {
        var network = new StateAwareNetworkPolicy
        {
            Egress = new NetworkEgressPolicy(),
            Ingress = new NetworkIngressPolicy(),
        };
        network.Egress = null;
        network.Ingress = null;

        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            StateAwareContainment.Wslc,
            new WslcProvisionOptions { Network = network });
        Assert.Empty(envelope["network"]!.AsObject());
    }

    [Fact]
    public void StateAwareOptions_DeserializeDirectionalNetworkSections()
    {
        var options = JsonSerializer.Deserialize<WslcProvisionOptions>(
            """
            {"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}}}
            """,
            JsonOptions);
        Assert.NotNull(options);
        Assert.Equal(NetworkAction.Deny, options.Network?.Egress?.Default);
        Assert.Equal(NetworkAction.Deny, options.Network?.Ingress?.Default);
        Assert.Equal(NetworkAction.Deny, options.Network?.Ingress?.HostLoopback);

        var envelope = MxcLifecycle.BuildProvisionEnvelope(StateAwareContainment.Wslc, options);
        Assert.Equal("deny", envelope["network"]?["egress"]?["default"]?.GetValue<string>());
        Assert.Equal("deny", envelope["network"]?["ingress"]?["default"]?.GetValue<string>());
        Assert.Equal("deny", envelope["network"]?["ingress"]?["hostLoopback"]?.GetValue<string>());
    }

    [Fact]
    public void ProvisionEnvelopeTargetsSdkOwnedV1Contract()
    {
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            StateAwareContainment.IsolationSession,
            new IsolationSessionProvisionOptions(IsolationNetwork()));

        Assert.Equal("1.0.0", envelope["version"]?.GetValue<string>());
        Assert.Equal("provision", envelope["phase"]?.GetValue<string>());
        Assert.Equal("isolation_session", envelope["containment"]?.GetValue<string>());
    }

    [Fact]
    public void WslcProvisionPreservesDirectionalPolicy()
    {
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            StateAwareContainment.Wslc,
            new WslcProvisionOptions
            {
                Network = new StateAwareNetworkPolicy
                {
                    Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Deny,
                        HostLoopback = NetworkAction.Deny,
                    },
                },
                Image = "alpine:latest",
            });

        Assert.Equal("1.0.0", envelope["version"]?.GetValue<string>());
        Assert.Equal("deny", envelope["network"]?["egress"]?["default"]?.GetValue<string>());
        Assert.Equal(
            "alpine:latest",
            envelope["wslc"]?["provision"]?["image"]?.GetValue<string>());
    }

    [Fact]
    public void ExecEnvelopeTargetsV1AndKeepsRuntimeProxySeparate()
    {
        var envelope = MxcLifecycle.BuildExecEnvelope(
            new SandboxId("wslc:sample"),
            "echo test",
            new WslcExecOptions
            {
                RuntimeConfig = new NetworkRuntimeConfig
                {
                    NetworkProxy = "http://127.0.0.1:8080",
                },
            });

        Assert.Equal("1.0.0", envelope["version"]?.GetValue<string>());
        Assert.Equal("echo test", envelope["process"]?["commandLine"]?.GetValue<string>());
        Assert.Equal(
            "http://127.0.0.1:8080",
            envelope["runtimeConfig"]?["networkProxy"]?.GetValue<string>());
    }

    [Fact]
    public void EveryIdPhaseTargetsV1()
    {
        var id = new SandboxId("iso:sample");
        foreach (JsonObject envelope in new[]
        {
            MxcLifecycle.BuildStartEnvelope(id),
            MxcLifecycle.BuildStopEnvelope(id),
            MxcLifecycle.BuildDeprovisionEnvelope(id),
        })
        {
            Assert.Equal("1.0.0", envelope["version"]?.GetValue<string>());
        }
    }

    [Fact]
    public void IsolationSessionRequiresAllAllowWithoutRules()
    {
        var invalid = IsolationNetwork();
        invalid.Egress!.Default = NetworkAction.Deny;

        Assert.Throws<ArgumentException>(() =>
            MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                new IsolationSessionProvisionOptions(invalid)));
    }

    [Fact]
    public void WslcRuntimeProxyRequiresHttpOrHttps()
    {
        Assert.Throws<ArgumentException>(() =>
            MxcLifecycle.BuildExecEnvelope(
                new SandboxId("wslc:sample"),
                "echo test",
                new WslcExecOptions
                {
                    RuntimeConfig = new NetworkRuntimeConfig
                    {
                        NetworkProxy = "ftp://proxy.example",
                    },
                }));
    }

    [Fact]
    public void DevelopmentOnlyWindowsSandboxIsAbsentFromV1Surface()
    {
        Assert.DoesNotContain(
            "WindowsSandbox",
            Enum.GetNames<StateAwareContainment>());
        Assert.Null(
            typeof(MxcLifecycle).Assembly.GetType(
                "Microsoft.Mxc.Sdk.WindowsSandboxProvisionOptions"));
    }
}
