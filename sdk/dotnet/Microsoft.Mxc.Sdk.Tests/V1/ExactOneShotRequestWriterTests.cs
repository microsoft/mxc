// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Tests;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public sealed class ExactOneShotRequestWriterTests
{
    public static IEnumerable<object[]> SdkV1Cases =>
        ResourceNames("input")
            .Select(name => new object[] { name });

    [Theory]
    [MemberData(nameof(SdkV1Cases))]
    public void Writer_MatchesSdkV1Golden(string name)
    {
        var input = ReadSdkV1("input", name);
        var expected = ReadSdkV1("expected", name);
        var request = RequestFromFixture(input);

        var actual = ExactOneShotRequestWriter.Serialize(request);

        JsonAssert.MatchesJson(actual, expected, $"sdk-v1/{name}.json");
    }

    [Fact]
    public void Writer_MintsContainerIdForUnnamedRequests()
    {
        var first = ExactOneShotRequestWriter.Serialize(
            new SandboxRequest(new SandboxPolicy(), "echo first"));
        var second = ExactOneShotRequestWriter.Serialize(
            new SandboxRequest(new SandboxPolicy(), "echo second"));

        using var firstDocument = JsonDocument.Parse(first);
        using var secondDocument = JsonDocument.Parse(second);
        var firstId = firstDocument.RootElement.GetProperty("containerId").GetString();
        var secondId = secondDocument.RootElement.GetProperty("containerId").GetString();

        Assert.False(string.IsNullOrWhiteSpace(firstId));
        Assert.False(string.IsNullOrWhiteSpace(secondId));
        Assert.NotEqual(firstId, secondId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("user-selected")]
    public void Writer_PreservesSuppliedContainerNames(string name)
    {
        var request = new SandboxRequest(new SandboxPolicy(), "echo id")
        {
            ContainerName = name,
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        Assert.Equal(name, document.RootElement.GetProperty("containerId").GetString());
    }

    [Fact]
    public void Writer_PreservesEnvironmentOrderEmptyValuesAndCaseVariants()
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Z"] = "",
            ["PATH"] = "first",
            ["Path"] = "second",
            ["A"] = "last",
        };
        environment["PATH"] = "updated";
        var request = new SandboxRequest(new SandboxPolicy(), "echo env")
        {
            Environment = environment,
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        var values = document.RootElement.GetProperty("process").GetProperty("env")
            .EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Equal(new[] { "Z=", "PATH=updated", "Path=second", "A=last" }, values);
    }

    [Fact]
    public void Writer_RespectsDictionaryComparerThroughLegacyCaptureMigration()
    {
#pragma warning disable MXC0001
        var policy = new SandboxPolicy { CaptureDenials = new CaptureDenialsPolicy() };
#pragma warning restore MXC0001
        var request = new SandboxRequest(policy, "echo env")
        {
            Environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["PATH"] = "first",
                ["Path"] = "second",
            },
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        var values = document.RootElement.GetProperty("process").GetProperty("env")
            .EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Equal(new[] { "PATH=first", "Path=second" }, values);
    }

    [Fact]
    public void Writer_RespectsCaseInsensitiveDictionaryDuplicateSemantics()
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Key"] = "first",
            ["Other"] = "middle",
        };
        environment["KEY"] = "last";
        var request = new SandboxRequest(new SandboxPolicy(), "echo env")
        {
            Environment = environment,
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        var values = document.RootElement.GetProperty("process").GetProperty("env")
            .EnumerateArray().Select(value => value.GetString()).ToArray();
        Assert.Equal(new[] { "Key=last", "Other=middle" }, values);
    }

    [Theory]
    [InlineData("")]
    [InlineData("BAD=KEY")]
    public void Writer_RejectsMalformedEnvironmentKeys(string key)
    {
        var request = new SandboxRequest(new SandboxPolicy(), "echo env")
        {
            Environment = new Dictionary<string, string> { [key] = "" },
        };

        var error = Assert.Throws<ArgumentException>(
            () => ExactOneShotRequestWriter.Serialize(request));
        Assert.Equal("request", error.ParamName);
        Assert.Contains("Environment keys", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(9223372036854775808UL)]
    [InlineData(ulong.MaxValue)]
    public void Writer_PreservesFullUnsignedWslcMemoryMb(ulong memoryMb)
    {
        var request = new SandboxRequest(new SandboxPolicy(), "echo memory")
        {
            Containment = new WslcContainment { MemoryMb = memoryMb },
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        Assert.Equal(
            memoryMb,
            document.RootElement.GetProperty("wslc").GetProperty("memoryMb").GetUInt64());
    }

    [Fact]
    public void Writer_RejectsExperimentalOptInBeforeAliasMigration()
    {
#pragma warning disable MXC0001
        var request = new SandboxRequest(
            new SandboxPolicy { CaptureDenials = new CaptureDenialsPolicy() }, "echo")
        {
            Experimental = true,
            Containment = new WslcContainment(),
        };
#pragma warning restore MXC0001

        var error = Assert.Throws<ArgumentException>(
            () => ExactOneShotRequestWriter.Serialize(request));
        Assert.Equal("request", error.ParamName);
        Assert.Contains("Stable V1", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Writer_IgnoresInheritDefaultEnvironmentWithoutEnvironment()
    {
        var request = new SandboxRequest(new SandboxPolicy(), "echo env")
        {
            InheritDefaultEnvironment = true,
        };

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        var process = document.RootElement.GetProperty("process");

        Assert.False(process.TryGetProperty("env", out _));
        Assert.False(process.TryGetProperty("inheritDefaultEnv", out _));
    }

    [Fact]
    public void Writer_RejectsUndefinedNetworkAction()
    {
        var request = new SandboxRequest(
            new SandboxPolicy
            {
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = (NetworkAction)42,
                    },
                },
            },
            "echo invalid");

        var exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => ExactOneShotRequestWriter.Serialize(request));

        Assert.Equal("network.egress.default", exception.ParamName);
        Assert.Contains(
            "NetworkAction value '42' is not supported.",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Writer_RejectsCommaSeparatedProcessContainerCapability()
    {
        var request = new SandboxRequest(new SandboxPolicy(), "echo invalid")
        {
            Containment = new ProcessContainerContainment
            {
                Capabilities = ["internetClient,registryRead"],
            },
        };

        var exception = Assert.Throws<ArgumentException>(
            () => ExactOneShotRequestWriter.Serialize(request));

        Assert.Equal("request", exception.ParamName);
        Assert.Contains(
            "must not contain a comma",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Writer_MigratesLegacyCaptureDenialsToProcessContainer()
    {
#pragma warning disable MXC0001
        var request = new SandboxRequest(
            new SandboxPolicy
            {
                CaptureDenials = new CaptureDenialsPolicy
                {
                    Mode = CaptureDenialsMode.Allow,
                    RetainEtl = true,
                },
            },
            "echo capture");
#pragma warning restore MXC0001

        using var document = JsonDocument.Parse(ExactOneShotRequestWriter.Serialize(request));
        var root = document.RootElement;
        var processContainer = root.GetProperty("processContainer");

        Assert.Equal("processcontainer", root.GetProperty("containment").GetString());
        Assert.Equal(
            "allow",
            processContainer.GetProperty("captureDenials").GetProperty("mode").GetString());
        Assert.True(
            processContainer.GetProperty("captureDenials").GetProperty("retainEtl").GetBoolean());
        Assert.False(root.TryGetProperty("captureDenials", out _));
    }

    private static SandboxRequest RequestFromFixture(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var policy = Policy(root.GetProperty("policy"));
        if (root.TryGetProperty("telemetry", out var telemetry)
            && telemetry.GetBoolean())
        {
            policy.Telemetry = new TelemetrySettings { Enabled = true };
        }

        var request = new SandboxRequest(policy, root.GetProperty("command").GetString()!)
        {
            Containment = Containment(root.GetProperty("containment")),
            ContainerName = root.TryGetProperty("containerName", out var containerName)
                ? containerName.GetString()
                : null,
            WorkingDirectory = root.TryGetProperty("workingDirectory", out var workingDirectory)
                ? workingDirectory.GetString()
                : null,
            InheritDefaultEnvironment =
                root.TryGetProperty("inheritDefaultEnv", out var inherit)
                && inherit.GetBoolean(),
        };
        if (root.TryGetProperty("environment", out var environment))
        {
            request.Environment = environment.EnumerateObject()
                .ToDictionary(
                    property => property.Name,
                    property => property.Value.GetString() ?? string.Empty,
                    StringComparer.Ordinal);
        }
        return request;
    }

    private static SandboxPolicy Policy(JsonElement policy)
    {
        var result = new SandboxPolicy();
        if (policy.TryGetProperty("filesystem", out var filesystem))
        {
            result.Filesystem = Filesystem(filesystem);
        }
        if (policy.TryGetProperty("network", out var network))
        {
            result.Network = Network(network);
        }
        if (policy.TryGetProperty("ui", out var ui))
        {
            result.Ui = Ui(ui);
        }
        if (policy.TryGetProperty("timeoutMs", out var timeout))
        {
            result.TimeoutMs = timeout.GetUInt32();
        }
        return result;
    }

    private static FilesystemPolicy Filesystem(JsonElement filesystem) => new()
    {
        ReadwritePaths = StringList(filesystem, "readwritePaths"),
        ReadonlyPaths = StringList(filesystem, "readonlyPaths"),
        DeniedPaths = StringList(filesystem, "deniedPaths"),
        ClearPolicyOnExit = filesystem.TryGetProperty("clearPolicyOnExit", out var clear)
            ? clear.GetBoolean()
            : null,
    };

    private static NetworkPolicy Network(JsonElement network)
    {
        var policy = new NetworkPolicy
        {
            Egress = network.TryGetProperty("egress", out var egress) ? Egress(egress) : null,
            Ingress = network.TryGetProperty("ingress", out var ingress) ? Ingress(ingress) : null,
            RuntimeConfig = network.TryGetProperty("runtimeConfig", out var runtime)
                ? new NetworkRuntimeConfig
                {
                    NetworkProxy = runtime.GetProperty("networkProxy").GetString(),
                }
                : null,
        };
        return policy;
    }

    private static NetworkEgressPolicy Egress(JsonElement egress) => new()
    {
        Default = egress.TryGetProperty("default", out var defaultAction)
            ? Action(defaultAction)
            : null,
        Allow = Rules(egress, "allow"),
        Deny = Rules(egress, "deny"),
    };

    private static NetworkIngressPolicy Ingress(JsonElement ingress) => new()
    {
        Default = ingress.TryGetProperty("default", out var defaultAction)
            ? Action(defaultAction)
            : null,
        HostLoopback = ingress.TryGetProperty("hostLoopback", out var hostLoopback)
            ? Action(hostLoopback)
            : null,
    };

    private static List<NetworkRulePolicy>? Rules(JsonElement egress, string property) =>
        egress.TryGetProperty(property, out var rules)
            ? rules.EnumerateArray().Select(Rule).ToList()
            : null;

    private static NetworkRulePolicy Rule(JsonElement rule) => new()
    {
        To = rule.TryGetProperty("to", out var to)
            ? to.EnumerateArray()
                .Select(peer => new NetworkPeerPolicy(peer.GetProperty("cidr").GetString()!)
                {
                    Except = StringListOrNull(peer, "except"),
                })
                .ToList()
            : null,
        Ports = rule.TryGetProperty("ports", out var ports)
            ? ports.EnumerateArray().Select(Port).ToList()
            : null,
    };

    private static NetworkPortPolicy Port(JsonElement port) => new()
    {
        Protocol = port.TryGetProperty("protocol", out var protocol) ? Protocol(protocol) : null,
        Port = port.TryGetProperty("port", out var value) ? value.GetUInt16() : null,
        EndPort = port.TryGetProperty("endPort", out var endPort)
            ? endPort.GetUInt16()
            : null,
    };

    private static UiPolicy Ui(JsonElement ui) => new()
    {
        AllowWindows = ui.TryGetProperty("allowWindows", out var allowWindows)
            && allowWindows.GetBoolean(),
        Clipboard = ui.TryGetProperty("clipboard", out var clipboard)
            ? Clipboard(clipboard)
            : ClipboardPolicy.None,
        AllowInputInjection =
            ui.TryGetProperty("allowInputInjection", out var injection)
            && injection.GetBoolean(),
    };

    private static SandboxContainment Containment(JsonElement containment)
    {
        var kind = containment.GetProperty("kind").GetString();
        return kind switch
        {
            "process" => new ProcessContainment(),
            "processContainer" => ProcessContainer(containment),
            "lxc" => new LxcContainment
            {
                Distribution = containment.GetProperty("distribution").GetString()!,
                Release = containment.GetProperty("release").GetString()!,
            },
            "bubblewrap" => new BubblewrapContainment(),
            "seatbelt" => Seatbelt(containment),
            "isolationSession" => new IsolationSessionContainment(),
            "wslc" => Wslc(containment),
            _ => throw new InvalidOperationException($"unknown fixture containment {kind}"),
        };
    }

    private static ProcessContainerContainment ProcessContainer(JsonElement containment) => new()
    {
        LeastPrivilege =
            containment.TryGetProperty("leastPrivilege", out var leastPrivilege)
            && leastPrivilege.GetBoolean(),
        LearningMode =
            containment.TryGetProperty("learningMode", out var learningMode)
            && learningMode.GetBoolean(),
        Capabilities = StringList(containment, "capabilities"),
        Network = containment.TryGetProperty("allowedProxyPeer", out var allowedProxyPeer)
            ? new ProcessContainerNetworkPolicy
            {
                AllowedProxyPeer = allowedProxyPeer.GetString(),
            }
            : null,
    };

    private static SeatbeltContainment Seatbelt(JsonElement containment) => new()
    {
        GuiAccess = containment.TryGetProperty("guiAccess", out var guiAccess)
            && guiAccess.GetBoolean(),
        NestedPty = !containment.TryGetProperty("nestedPty", out var nestedPty)
            || nestedPty.GetBoolean(),
        KeychainAccess = containment.TryGetProperty("keychainAccess", out var keychainAccess)
            && keychainAccess.GetBoolean(),
        ExtraMachLookups = StringList(containment, "extraMachLookups"),
    };

    private static WslcContainment Wslc(JsonElement containment) => new()
    {
        Image = containment.GetProperty("image").GetString()!,
        CpuCount = containment.TryGetProperty("cpuCount", out var cpuCount)
            ? cpuCount.GetUInt32()
            : null,
        MemoryMb = containment.TryGetProperty("memoryMb", out var memoryMb)
            ? memoryMb.GetUInt64()
            : null,
        Gpu = containment.GetProperty("gpu").GetBoolean(),
        PortMappings = containment.TryGetProperty("portMappings", out var portMappings)
            ? portMappings.EnumerateArray()
                .Select(mapping => new WslcPortMapping(
                    mapping[0].GetInt32(),
                    mapping[1].GetInt32()))
                .ToList()
            : [],
    };

    private static NetworkAction Action(JsonElement value) => value.GetString() switch
    {
        "allow" => NetworkAction.Allow,
        "deny" => NetworkAction.Deny,
        var other => throw new InvalidOperationException($"unknown fixture action {other}"),
    };

    private static NetworkProtocol Protocol(JsonElement value) => value.GetString() switch
    {
        "tcp" => NetworkProtocol.Tcp,
        "udp" => NetworkProtocol.Udp,
        "icmp" => NetworkProtocol.Icmp,
        "any" => NetworkProtocol.Any,
        var other => throw new InvalidOperationException($"unknown fixture protocol {other}"),
    };

    private static ClipboardPolicy Clipboard(JsonElement value) => value.GetString() switch
    {
        "none" => ClipboardPolicy.None,
        "read" => ClipboardPolicy.Read,
        "write" => ClipboardPolicy.Write,
        "all" => ClipboardPolicy.All,
        var other => throw new InvalidOperationException($"unknown fixture clipboard {other}"),
    };

    private static List<string> StringList(JsonElement root, string property) =>
        StringListOrNull(root, property) ?? [];

    private static List<string>? StringListOrNull(JsonElement root, string property) =>
        root.TryGetProperty(property, out var values)
            ? values.EnumerateArray().Select(value => value.GetString()!).ToList()
            : null;

    private static IEnumerable<string> ResourceNames(string kind)
    {
        var marker = $".policy.sdk_v1.{kind}.";
        return typeof(ExactOneShotRequestWriterTests).Assembly
            .GetManifestResourceNames()
            .Where(name => name.Contains(marker, StringComparison.Ordinal))
            .Select(name =>
            {
                var start = name.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
                return name[start..^".json".Length];
            })
            .Order(StringComparer.Ordinal);
    }

    private static string ReadSdkV1(string kind, string name)
    {
        var suffix = $".policy.sdk_v1.{kind}.{name}.json";
        var resourceName = typeof(ExactOneShotRequestWriterTests).Assembly
            .GetManifestResourceNames()
            .Single(resource => resource.EndsWith(suffix, StringComparison.Ordinal));
        using var stream = typeof(ExactOneShotRequestWriterTests).Assembly
            .GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Missing embedded fixture {resourceName}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
