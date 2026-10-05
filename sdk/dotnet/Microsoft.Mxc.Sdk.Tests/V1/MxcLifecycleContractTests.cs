// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcLifecycleContractTests
{
    [Fact]
    public void CreationAndExistingContainerRequestsMapTheSameProcessSettings()
    {
        var environment = new Dictionary<string, string>
        {
            ["Z"] = "",
            ["Path"] = "value",
        };
        var creation = new ContainerRequest("echo test")
        {
            WorkingDirectory = "C:\\work",
            Environment = environment,
            InheritDefaultEnvironment = true,
            TimeoutMs = 1234,
        };
        var execution = new ExecutionRequest(creation.Command)
        {
            WorkingDirectory = creation.WorkingDirectory,
            Environment = environment,
            InheritDefaultEnvironment = creation.InheritDefaultEnvironment,
            TimeoutMs = creation.TimeoutMs,
        };
        var envelope = MxcLifecycle.BuildExecEnvelope(new ContainerId("wslc:sample"), execution);
        using var exact = JsonDocument.Parse(MxcContainer.SerializeRequest(creation));
        Assert.True(JsonNode.DeepEquals(
            JsonNode.Parse(exact.RootElement.GetProperty("process").GetRawText()),
            envelope["process"]));
    }

    [Fact]
    public void ProvisionKeepsRuntimeValuesSeparateWithoutDroppingUnsupportedInput()
    {
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            LifecycleContainmentKind.Wslc,
            new WslcProvisionRequest
            {
                Filesystem = new FilesystemPolicy { ClearPolicyOnExit = false },
                Network = new NetworkPolicy
                {
                    RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" },
                },
            });
        Assert.False(envelope["network"]!.AsObject().ContainsKey("runtimeConfig"));
        Assert.Equal(
            "http://127.0.0.1:8080",
            envelope["runtimeConfig"]!["networkProxy"]!.GetValue<string>());
        Assert.False(envelope["filesystem"]!["clearPolicyOnExit"]!.GetValue<bool>());
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private static NetworkPolicy IsolationNetwork() => new()
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
            JsonSerializer.Deserialize<WslcProvisionRequest>(
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
            JsonSerializer.Deserialize<NetworkPolicy>(
                $$$"""{"{{{field}}}":null}""",
                MxcJson.Options));
        Assert.Contains("cannot be null", error.Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"network":{}}""")]
    public void StateAwareOptions_AllowOmittedNetworkSections(string json)
    {
        var options = JsonSerializer.Deserialize<WslcProvisionRequest>(json, JsonOptions);
        Assert.NotNull(options);
        Assert.Null(options.Network?.Egress);
        Assert.Null(options.Network?.Ingress);

        var envelope = MxcLifecycle.BuildProvisionEnvelope(LifecycleContainmentKind.Wslc, options);
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
        var network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy(),
            Ingress = new NetworkIngressPolicy(),
        };
        network.Egress = null;
        network.Ingress = null;

        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            LifecycleContainmentKind.Wslc,
            new WslcProvisionRequest { Network = network });
        Assert.Empty(envelope["network"]!.AsObject());
    }

    [Fact]
    public void StateAwareOptions_DeserializeDirectionalNetworkSections()
    {
        var options = JsonSerializer.Deserialize<WslcProvisionRequest>(
            """
            {"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}}}
            """,
            JsonOptions);
        Assert.NotNull(options);
        Assert.Equal(NetworkAction.Deny, options.Network?.Egress?.Default);
        Assert.Equal(NetworkAction.Deny, options.Network?.Ingress?.Default);
        Assert.Equal(NetworkAction.Deny, options.Network?.Ingress?.HostLoopback);

        var envelope = MxcLifecycle.BuildProvisionEnvelope(LifecycleContainmentKind.Wslc, options);
        Assert.Equal("deny", envelope["network"]?["egress"]?["default"]?.GetValue<string>());
        Assert.Equal("deny", envelope["network"]?["ingress"]?["default"]?.GetValue<string>());
        Assert.Equal("deny", envelope["network"]?["ingress"]?["hostLoopback"]?.GetValue<string>());
    }

    [Fact]
    public void ProvisionEnvelopeTargetsSdkOwnedV1Contract()
    {
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            LifecycleContainmentKind.IsolationSession,
            new IsolationSessionProvisionRequest(IsolationNetwork()));

        Assert.Equal("1.0.0", envelope["version"]?.GetValue<string>());
        Assert.Equal("provision", envelope["phase"]?.GetValue<string>());
        Assert.Equal("isolation_session", envelope["containment"]?.GetValue<string>());
    }

    [Fact]
    public void WslcProvisionPreservesDirectionalPolicy()
    {
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            LifecycleContainmentKind.Wslc,
            new WslcProvisionRequest
            {
                Network = new NetworkPolicy
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
            new ContainerId("wslc:sample"),
            new ExecutionRequest("echo test")
            {
                Network = new ProcessNetworkPolicy
                {
                    RuntimeConfig = new NetworkRuntimeConfig
                    {
                        NetworkProxy = "http://127.0.0.1:8080",
                    },
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
        var id = new ContainerId("iso:sample");
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
                LifecycleContainmentKind.IsolationSession,
                new IsolationSessionProvisionRequest(invalid)));
    }

    [Fact]
    public void WslcRuntimeProxyRequiresHttpOrHttps()
    {
        Assert.Throws<ArgumentException>(() =>
            MxcLifecycle.BuildExecEnvelope(
                new ContainerId("wslc:sample"),
                new ExecutionRequest("echo test")
                {
                    Network = new ProcessNetworkPolicy
                    {
                        RuntimeConfig = new NetworkRuntimeConfig
                        {
                            NetworkProxy = "ftp://proxy.example",
                        },
                    },
                }));
    }

    [Fact]
    public void DevelopmentOnlyWindowsSandboxIsAbsentFromV1Surface()
    {
        Assert.DoesNotContain(
            "WindowsSandbox",
            Enum.GetNames<LifecycleContainmentKind>());
        Assert.Null(
            typeof(MxcLifecycle).Assembly.GetType(
                "Microsoft.Mxc.Sdk.WindowsSandboxProvisionOptions"));
    }
}
