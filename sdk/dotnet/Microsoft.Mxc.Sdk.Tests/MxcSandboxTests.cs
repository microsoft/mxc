// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcSandboxTests
{
    [Fact]
    public void FullRequestSerialization_MatchesCrossLanguageGoldens()
    {
        var processContainer = new SandboxRequest(
            new SandboxPolicy
            {
                Version = "0.8.0-alpha",
                Filesystem = new FilesystemPolicy
                {
                    ReadwritePaths = ["C:\\work"],
                    ReadonlyPaths = ["C:\\input"],
                    DeniedPaths = ["C:\\secret"],
                    ClearPolicyOnExit = true,
                },
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = NetworkAction.Deny,
                    },
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
                Ui = new UiPolicy
                {
                    Clipboard = ClipboardPolicy.Read,
                },
                TimeoutMs = 30000,
            },
            "echo parity")
        {
            Containment = new ProcessContainerContainment
            {
                LeastPrivilege = true,
                Capabilities = ["internetClient"],
                CaptureDenials = new CaptureDenialsPolicy
                {
                    OutputPath = "C:\\logs\\denials.json",
                    RetainEtl = true,
                },
                Ui = new ProcessContainerUiPolicy
                {
                    Isolation = ProcessContainerUiIsolation.Handles,
                    SystemSettings = ProcessContainerSystemSettings.Parameters,
                    Ime = true,
                },
                Network = new ProcessContainerNetworkPolicy
                {
                    AllowedProxyPeer = "Contoso.App_123",
                },
            },
            ContainerName = "golden-process-container",
            WorkingDirectory = "C:\\work",
            Environment = new() { ["PARITY"] = "true" },
        };

        var directionalNetwork = new SandboxRequest(
            new SandboxPolicy
            {
                Version = "0.8.0-alpha",
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = NetworkAction.Deny,
                        Allow =
                        [
                            new NetworkRulePolicy
                            {
                                To =
                                [
                                    new NetworkPeerPolicy("10.20.0.0/16")
                                    {
                                        Except = ["10.20.30.0/24"],
                                    },
                                ],
                                Ports =
                                [
                                    new NetworkPortPolicy
                                    {
                                        Protocol = NetworkProtocol.Tcp,
                                        Port = 443,
                                        EndPort = 444,
                                    },
                                ],
                            },
                        ],
                    },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Deny,
                        HostLoopback = NetworkAction.Deny,
                    },
                },
            },
            "echo network");

        var wslc = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "printf parity")
        {
            Containment = new WslcContainment
            {
                Image = "alpine:3.20",
                ImageTarPath = "C:\\images\\alpine.tar",
                CpuCount = 2,
                MemoryMb = 1024,
                Gpu = true,
                StoragePath = "C:\\wslc",
                PortMappings = [new WslcPortMapping(8080, 80)],
            },
            ContainerName = "golden-wslc",
            Experimental = true,
        };

        JsonAssert.MatchesGolden(
            MxcSandbox.SerializeRequest(processContainer),
            "request-process-container.json");
        JsonAssert.MatchesGolden(
            MxcSandbox.SerializeRequest(directionalNetwork),
            "request-directional-network.json");
        JsonAssert.MatchesGolden(MxcSandbox.SerializeRequest(wslc), "request-wslc.json");
    }

    [Fact]
    public void NativeVersion_IsNotEmpty()
    {
        // Exercises the native load path + mxc_version() end-to-end.
        Assert.False(string.IsNullOrEmpty(MxcSandbox.NativeVersion));
    }

    [Fact]
    public void GetAvailableBackends_ReturnsTypedNativeProbe()
    {
        var backends = MxcSandbox.GetAvailableBackends();

        Assert.NotNull(backends);
        if (OperatingSystem.IsWindows())
        {
            var processContainer = Assert.Single(
                backends,
                backend => backend.Backend == ContainmentBackend.ProcessContainer);
            Assert.NotNull(processContainer.Tier);
        }
    }

    [Fact]
    public void GetPlatformSupport_ReturnsTypedNativeProbe()
    {
        var support = MxcSandbox.GetPlatformSupport();

        Assert.NotNull(support.AvailableMethods);
        if (support.IsSupported)
        {
            Assert.NotEmpty(support.AvailableMethods);
        }
        else
        {
            Assert.False(string.IsNullOrWhiteSpace(support.Reason));
        }
    }

    [Theory]
    [InlineData("processcontainer", ContainmentBackend.ProcessContainer)]
    [InlineData("windows_sandbox", ContainmentBackend.WindowsSandbox)]
    [InlineData("lxc", ContainmentBackend.Lxc)]
    [InlineData("wslc", ContainmentBackend.Wslc)]
    [InlineData("seatbelt", ContainmentBackend.Seatbelt)]
    [InlineData("isolation_session", ContainmentBackend.IsolationSession)]
    [InlineData("bubblewrap", ContainmentBackend.Bubblewrap)]
    [InlineData("hyperlight", ContainmentBackend.Hyperlight)]
    public void Discovery_MapsEveryNativeBackend(
        string wireName,
        ContainmentBackend expected)
    {
        Assert.Equal(expected, MxcSandbox.ParseBackend(wireName));
    }

    [Theory]
    [InlineData("base-container", IsolationTier.BaseContainer)]
    [InlineData("appcontainer-bfs", IsolationTier.AppContainerBfs)]
    [InlineData("appcontainer-dacl", IsolationTier.AppContainerDacl)]
    public void Discovery_MapsEveryNativeIsolationTier(
        string wireName,
        IsolationTier expected)
    {
        Assert.Equal(expected, MxcSandbox.ParseIsolationTier(wireName));
    }

    [Fact]
    public void Discovery_MapsEveryNativeCapability()
    {
        Assert.Equal(
            BackendCapability.CaptureDenials,
            MxcSandbox.ParseBackendCapability("captureDenials"));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("processContainer")]
    public void Discovery_PreservesUnknownNativeBackend(string wireName)
    {
        Assert.Equal(ContainmentBackend.Unknown, MxcSandbox.ParseBackend(wireName));
        Assert.Equal(IsolationTier.Unknown, MxcSandbox.ParseIsolationTier(wireName));
        Assert.Equal(
            BackendCapability.Unknown,
            MxcSandbox.ParseBackendCapability(wireName));
    }

    [Fact]
    public void Run_MalformedPolicy_ThrowsMalformedRequest()
    {
        // A version-less policy is rejected by the native parser before any
        // sandbox is spawned, so this runs on any host (no host-prep needed).
        var policy = new SandboxPolicy { Version = string.Empty };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(policy, "echo hi"));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.False(string.IsNullOrEmpty(ex.Message));
    }

    [Fact]
    public void Run_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(null!, "echo hi"));
    }

    [Fact]
    public void Run_NullCommand_Throws()
    {
        var policy = new SandboxPolicy { Version = "0.7.0-alpha" };
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(policy, null!));
    }

    [Fact]
    public void SandboxPolicy_SerializesToCamelCaseJson()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.7.0-alpha",
            TimeoutMs = 5000,
            Filesystem = new FilesystemPolicy { ReadwritePaths = { "/tmp" } },
            Network = new NetworkPolicy
            {
                Proxy = new LocalhostNetworkProxyPolicy(8080),
            },
            Ui = new UiPolicy { AllowWindows = true, Clipboard = ClipboardPolicy.Read },
        };

        var json = MxcSandbox.SerializePolicy(policy);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("0.7.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal(5000, root.GetProperty("timeoutMs").GetInt32());
        Assert.Equal("/tmp", root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());
        Assert.Equal(8080,
            root.GetProperty("network").GetProperty("proxy").GetProperty("localhost").GetInt32());
        Assert.Equal("read", root.GetProperty("ui").GetProperty("clipboard").GetString());
        Assert.True(root.GetProperty("ui").GetProperty("allowWindows").GetBoolean());
        Assert.False(root.TryGetProperty("captureDenials", out _));
    }

    [Fact]
    public void NetworkPolicy_SerializesUrlProxyToWireUnion()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.8.0-alpha",
            Network = new NetworkPolicy
            {
                Proxy = new UrlNetworkProxyPolicy("http://proxy.example:3128"),
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var proxy = doc.RootElement.GetProperty("network").GetProperty("proxy");

        Assert.Equal("http://proxy.example:3128", proxy.GetProperty("url").GetString());
        Assert.Single(proxy.EnumerateObject());
    }

    [Theory]
    [InlineData("""{"localhost":8080}""", typeof(LocalhostNetworkProxyPolicy))]
    [InlineData("""{"url":"http://proxy.example:3128"}""", typeof(UrlNetworkProxyPolicy))]
    public void NetworkProxyPolicy_DeserializesWireUnion(string json, Type expectedType)
    {
        var proxy = JsonSerializer.Deserialize<NetworkProxyPolicy>(json);

        Assert.NotNull(proxy);
        Assert.IsType(expectedType, proxy);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void LocalhostNetworkProxyPolicy_RejectsInvalidPort(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new LocalhostNetworkProxyPolicy(port));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void UrlNetworkProxyPolicy_RejectsEmptyUrl(string url)
    {
        Assert.Throws<ArgumentException>(() => new UrlNetworkProxyPolicy(url));
    }

    [Fact]
    public void SandboxRequest_NestsCaptureDenialsUnderProcessContainer()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.8.0-alpha" },
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                CaptureDenials = new CaptureDenialsPolicy(),
            },
        };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;
        var containment = root.GetProperty("containment");
        var capture = containment.GetProperty("captureDenials");

        Assert.Equal("processContainer", containment.GetProperty("type").GetString());
        Assert.Equal("block", capture.GetProperty("mode").GetString());
        Assert.False(capture.GetProperty("retainEtl").GetBoolean());
        Assert.False(capture.TryGetProperty("outputPath", out _));
        Assert.False(root.GetProperty("policy").TryGetProperty("captureDenials", out _));
    }

    [Fact]
    public void SandboxRequest_MigratesLegacyCaptureDenialsWithoutMutation()
    {
        var captureDenials = new CaptureDenialsPolicy
        {
            Mode = CaptureDenialsMode.Allow,
            RetainEtl = true,
        };
        var request = new SandboxRequest(
            CreateLegacyCaptureDenialsPolicy(captureDenials),
            "echo hi");
        var originalContainment = request.Containment;

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;
        var containment = root.GetProperty("containment");

        Assert.Equal("processContainer", containment.GetProperty("type").GetString());
        Assert.Equal(
            "allow",
            containment.GetProperty("captureDenials").GetProperty("mode").GetString());
        Assert.True(
            containment.GetProperty("captureDenials").GetProperty("retainEtl").GetBoolean());
        Assert.False(root.GetProperty("policy").TryGetProperty("captureDenials", out _));
        Assert.Same(originalContainment, request.Containment);
    }

    [Fact]
    public void SandboxRequest_RejectsConflictingLegacyCaptureDenials()
    {
        var request = new SandboxRequest(
            CreateLegacyCaptureDenialsPolicy(
                new CaptureDenialsPolicy { Mode = CaptureDenialsMode.Block }),
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                CaptureDenials = new CaptureDenialsPolicy
                {
                    Mode = CaptureDenialsMode.Allow,
                },
            },
        };

        var exception = Assert.Throws<ArgumentException>(
            () => MxcSandbox.SerializeRequest(request));

        Assert.Contains("conflicts", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SandboxRequest_AllowsEquivalentLegacyCaptureDenials()
    {
        var captureDenials = new CaptureDenialsPolicy
        {
            OutputPath = @"C:\logs\denials.json",
            RetainEtl = true,
        };
        var request = new SandboxRequest(
            CreateLegacyCaptureDenialsPolicy(captureDenials),
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                LeastPrivilege = true,
                CaptureDenials = new CaptureDenialsPolicy
                {
                    OutputPath = captureDenials.OutputPath,
                    RetainEtl = true,
                },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var containment = doc.RootElement.GetProperty("containment");

        Assert.True(containment.GetProperty("leastPrivilege").GetBoolean());
        Assert.Equal(
            captureDenials.OutputPath,
            containment.GetProperty("captureDenials").GetProperty("outputPath").GetString());
    }

    [Fact]
    public void SandboxRequest_RejectsLegacyCaptureDenialsForWslc()
    {
        var request = new SandboxRequest(
            CreateLegacyCaptureDenialsPolicy(new CaptureDenialsPolicy()),
            "echo hi")
        {
            Containment = new WslcContainment(),
        };

        var exception = Assert.Throws<ArgumentException>(
            () => MxcSandbox.SerializeRequest(request));

        Assert.Contains(
            nameof(WslcContainment),
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void SandboxRequest_SerializesExecutionSettings()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.8.0-alpha" },
            "echo hi")
        {
            ContainerName = "test-container",
            WorkingDirectory = @"C:\work",
            Experimental = true,
            Environment =
            {
                ["GREETING"] = "hello",
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        Assert.Equal("echo hi", root.GetProperty("command").GetString());
        Assert.Equal("process", root.GetProperty("containment").GetProperty("type").GetString());
        Assert.Equal("test-container", root.GetProperty("containerName").GetString());
        Assert.Equal(@"C:\work", root.GetProperty("workingDirectory").GetString());
        Assert.Equal("hello", root.GetProperty("environment").GetProperty("GREETING").GetString());
        Assert.True(root.GetProperty("experimental").GetBoolean());
    }

    [Fact]
    public void SandboxRequest_SerializesCompleteProcessContainerOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.8.0-alpha" },
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                LeastPrivilege = true,
                LearningMode = true,
                Capabilities = { "internetClient" },
                CaptureDenials = new CaptureDenialsPolicy
                {
                    Mode = CaptureDenialsMode.Allow,
                    RetainEtl = true,
                },
                Ui = new ProcessContainerUiPolicy
                {
                    Isolation = ProcessContainerUiIsolation.Atoms,
                    DesktopSystemControl = true,
                    SystemSettings = ProcessContainerSystemSettings.Parameters,
                    Ime = true,
                },
                Network = new ProcessContainerNetworkPolicy
                {
                    AllowedProxyPeer = "Contoso.Proxy_123",
                },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var containment = doc.RootElement.GetProperty("containment");

        Assert.True(containment.GetProperty("leastPrivilege").GetBoolean());
        Assert.True(containment.GetProperty("learningMode").GetBoolean());
        Assert.Equal("internetClient", containment.GetProperty("capabilities")[0].GetString());
        Assert.Equal("allow",
            containment.GetProperty("captureDenials").GetProperty("mode").GetString());
        Assert.Equal("atoms", containment.GetProperty("ui").GetProperty("isolation").GetString());
        Assert.Equal("parameters",
            containment.GetProperty("ui").GetProperty("systemSettings").GetString());
        Assert.Equal("Contoso.Proxy_123",
            containment.GetProperty("network").GetProperty("allowedProxyPeer").GetString());
    }

    [Fact]
    public void SandboxRequest_SerializesWslcOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.8.0-alpha" },
            "python3 -c 'print(42)'")
        {
            Experimental = true,
            Containment = new WslcContainment
            {
                Image = "python:3.12",
                ImageTarPath = @"C:\images\python.tar",
                CpuCount = 4,
                MemoryMb = 4096,
                Gpu = true,
                StoragePath = @"C:\wslc",
                PortMappings = { new WslcPortMapping(8080, 80) },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var containment = doc.RootElement.GetProperty("containment");

        Assert.Equal("wslc", containment.GetProperty("type").GetString());
        Assert.Equal("python:3.12", containment.GetProperty("image").GetString());
        Assert.Equal(4, containment.GetProperty("cpuCount").GetInt32());
        Assert.Equal(4096, containment.GetProperty("memoryMb").GetInt64());
        Assert.True(containment.GetProperty("gpu").GetBoolean());
        Assert.Equal(8080,
            containment.GetProperty("portMappings")[0].GetProperty("windowsPort").GetInt32());
        Assert.Equal(80,
            containment.GetProperty("portMappings")[0].GetProperty("containerPort").GetInt32());
    }

    [Fact]
    public void SandboxPolicy_SerializesDirectionalNetworking()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.8.0-alpha",
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy
                {
                    Default = NetworkAction.Deny,
                    Allow =
                    [
                        new NetworkRulePolicy
                        {
                            To =
                            [
                                new NetworkPeerPolicy("192.0.2.0/24")
                                {
                                    Except = ["192.0.2.10/32"],
                                },
                            ],
                            Ports =
                            [
                                new NetworkPortPolicy
                                {
                                    Protocol = NetworkProtocol.Tcp,
                                    Port = 443,
                                },
                            ],
                        },
                    ],
                },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Deny,
                    HostLoopback = NetworkAction.Allow,
                },
                RuntimeConfig = new NetworkRuntimeConfig
                {
                    NetworkProxy = "http://127.0.0.1:8080",
                },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var network = doc.RootElement.GetProperty("network");

        Assert.Equal("deny", network.GetProperty("egress").GetProperty("default").GetString());
        var allow = network.GetProperty("egress").GetProperty("allow")[0];
        Assert.Equal("192.0.2.0/24", allow.GetProperty("to")[0].GetProperty("cidr").GetString());
        Assert.Equal("tcp", allow.GetProperty("ports")[0].GetProperty("protocol").GetString());
        Assert.Equal(443, allow.GetProperty("ports")[0].GetProperty("port").GetInt32());
        Assert.Equal("allow",
            network.GetProperty("ingress").GetProperty("hostLoopback").GetString());
        Assert.Equal("http://127.0.0.1:8080",
            network.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString());
    }

    [Fact]
    public void SandboxPolicy_OmitsCaptureDenialsWhenNotConfigured()
    {
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));

        Assert.False(doc.RootElement.TryGetProperty("captureDenials", out _));
    }

    [Fact]
    public void SandboxPolicy_RoundTripsLegacyCaptureDenials()
    {
        const string json =
            """{"version":"0.8.0-alpha","captureDenials":{"mode":"block"}}""";

        var policy = JsonSerializer.Deserialize<SandboxPolicy>(
            json,
            new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
            });

        Assert.NotNull(GetLegacyCaptureDenials(policy!));

        // The property stays serializable so that legacy policy JSON survives a
        // round trip. The request path strips it separately, so the native
        // layer still only sees `containment.captureDenials`.
        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy!));
        Assert.Equal(
            "block",
            doc.RootElement.GetProperty("captureDenials").GetProperty("mode").GetString());
    }

    [Fact]
    public void RunRequest_CaptureDenialsReachesNativeVersionValidation()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.7.0-alpha" },
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                CaptureDenials = new CaptureDenialsPolicy(),
            },
        };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(request));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.Contains(
            "processContainer.captureDenials requires schema version 0.8",
            ex.Message);
    }

    [Fact]
    public void RunCompatibilityOverload_MapsCaptureDenialsOnWindows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "ProcessContainer is Windows-specific");

        var policy = CreateLegacyCaptureDenialsPolicy(
            new CaptureDenialsPolicy(),
            "0.7.0-alpha");

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(policy, "echo hi"));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.Contains(
            "processContainer.captureDenials requires schema version 0.8",
            ex.Message);
    }

    [Fact]
    public void RunRequest_DirectionalNetworkingReachesNativeVersionValidation()
    {
        var request = new SandboxRequest(
            new SandboxPolicy
            {
                Version = "0.7.0-alpha",
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy
                    {
                        Default = NetworkAction.Deny,
                    },
                },
            },
            "echo hi");

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(request));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.Contains("network egress/ingress/runtimeConfig", ex.Message);
    }

    [Theory]
    [InlineData(0, 80)]
    [InlineData(8080, 65536)]
    public void WslcPortMapping_RejectsInvalidPorts(int windowsPort, int containerPort)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new WslcPortMapping(windowsPort, containerPort));
    }

    [Fact]
    public void SpawnRequest_CaptureDenialsReachesNativeVersionValidation()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.7.0-alpha" },
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                CaptureDenials = new CaptureDenialsPolicy(),
            },
        };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Spawn(request));

        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.Contains(
            "processContainer.captureDenials requires schema version 0.8",
            ex.Message);
    }

    [Fact]
    public void Run_NullRequest_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run((SandboxRequest)null!));
    }

    [Fact]
    public void CaptureDenialsOutput_DeserializesRetainedEtlPath()
    {
        const string json = """
            {
              "type": "captureDenials",
              "outputPath": "denials.json",
              "exitCode": 0,
              "totalDenials": 1,
              "deniedResourcesTruncated": false,
              "etlPath": "capture.etl"
            }
            """;

        var output = JsonSerializer.Deserialize<CaptureDenialsOutput>(json);

        Assert.NotNull(output);
        Assert.Equal("capture.etl", output.EtlPath);
    }

    [Fact]
    public void SandboxOutputMetadata_DeserializesCaptureFailure()
    {
        const string json = """
            {
              "captureDenialsError": {
                "message": "decode failed",
                "etlPath": "capture.etl"
              }
            }
            """;

        var metadata = JsonSerializer.Deserialize<SandboxOutputMetadata>(json);

        var error = metadata?.CaptureDenialsError;
        Assert.NotNull(error);
        Assert.Equal("decode failed", error.Message);
        Assert.Equal("capture.etl", error.EtlPath);
    }

    [Fact]
    public void SandboxPolicy_CaptureDenialsIsObsoleteWithMigrationGuidance()
    {
#pragma warning disable MXC0001 // Verifies the obsolete migration contract.
        var property = typeof(SandboxPolicy).GetProperty(nameof(SandboxPolicy.CaptureDenials));
#pragma warning restore MXC0001
        var obsolete = property?.GetCustomAttributes(typeof(ObsoleteAttribute), inherit: false)
            .Cast<ObsoleteAttribute>()
            .SingleOrDefault();

        Assert.NotNull(obsolete);
        Assert.Equal(
            "Set ProcessContainerContainment.CaptureDenials instead. Removed in 1.0.",
            obsolete.Message);
        Assert.Equal("MXC0001", obsolete.DiagnosticId);
    }

    [Fact]
    public void SerializeRequest_StripsLegacyCaptureDenialsFromThePolicy()
    {
        // The policy property is serializable so legacy JSON round-trips, so the
        // request path must be what keeps it off the wire — the native contract
        // rejects `policy.captureDenials`.
        var request = new SandboxRequest(
            CreateLegacyCaptureDenialsPolicy(new CaptureDenialsPolicy()),
            "echo hi");

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        Assert.False(root.GetProperty("policy").TryGetProperty("captureDenials", out _));
        Assert.Equal(
            "block",
            root.GetProperty("containment")
                .GetProperty("captureDenials")
                .GetProperty("mode")
                .GetString());
    }

    private static SandboxPolicy CreateLegacyCaptureDenialsPolicy(
        CaptureDenialsPolicy captureDenials,
        string version = "0.8.0-alpha")
    {
        var policy = new SandboxPolicy { Version = version };
#pragma warning disable MXC0001 // Exercises compatibility migration.
        policy.CaptureDenials = captureDenials;
#pragma warning restore MXC0001
        return policy;
    }

    private static CaptureDenialsPolicy? GetLegacyCaptureDenials(SandboxPolicy policy)
    {
#pragma warning disable MXC0001 // Verifies compatibility deserialization.
        return policy.CaptureDenials;
#pragma warning restore MXC0001
    }
}
