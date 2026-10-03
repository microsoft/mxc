// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Tests;
using MxcSandbox = Microsoft.Mxc.Sdk.V1.MxcSandbox;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcSandboxTests
{
    private const string CompleteProbeJson = """
        {
          "tier": "appcontainer-dacl",
          "needsDaclAugmentation": true,
          "warnings": ["fell through"],
          "probes": {
            "baseContainerApiPresent": true,
            "nativeCaptureAvailable": false,
            "guardedCaptureAvailable": true,
            "bfscfgPresent": false,
            "bfsCompiledIn": false,
            "baseContainerSupportsDenyPaths": true,
            "baseContainerSupportsEnumeratePaths": false,
            "baseContainerSupportsIngressHostLoopbackAllow": true,
            "isolationSessionAvailable": true,
            "hyperlightAvailable": false,
            "uiCapabilities": {
              "canBlockClipboardRead": true,
              "canBlockClipboardWrite": false,
              "canBlockInputInjection": true,
              "canBlockInputMethodChanges": false,
              "canBlockExternalUiObjects": true,
              "canBlockGlobalUiNamespace": false,
              "canBlockDesktopSwitching": true,
              "canBlockLogoffOrShutdown": false,
              "canBlockSystemParameterChanges": true,
              "canBlockDisplaySettingsChanges": false
            }
          }
        }
        """;

    private static JsonObject CreateCompleteProbeJson() =>
        JsonNode.Parse(CompleteProbeJson)!.AsObject();

    private static void AssertProbeJsonRejected(Action<JsonObject> mutate)
    {
        var json = CreateCompleteProbeJson();
        mutate(json);
        Assert.Throws<JsonException>(() => MxcSandbox.ParseProbeOutput(json.ToJsonString()));
    }

    private static void AssertNoExplicitNulls(JsonElement element, string path = "$")
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                var propertyPath = $"{path}.{property.Name}";
                Assert.True(
                    property.Value.ValueKind != JsonValueKind.Null,
                    $"Generated probe config contains explicit null at {propertyPath}.");
                AssertNoExplicitNulls(property.Value, propertyPath);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                var itemPath = $"{path}[{index}]";
                Assert.True(
                    item.ValueKind != JsonValueKind.Null,
                    $"Generated probe config contains explicit null at {itemPath}.");
                AssertNoExplicitNulls(item, itemPath);
                index++;
            }
        }
    }

    [Fact]
    public void Probe_UsesCanonicalRequestJsonAndFreesNativeResults()
    {
        using var native = new FakeRequestProbeInterop
        {
            OutputJson = CompleteProbeJson,
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
            var request = new SandboxRequest(
                new SandboxPolicy(),
                "cmd /c exit 0")
            {
                ContainerName = "dotnet-exact-probe",
            };
            var output = MxcSandbox.Probe(request);

            Assert.Equal(IsolationTier.AppContainerDacl, output.Tier);
            Assert.True(output.Probes.BaseContainerApiPresent);
            Assert.Equal(MxcSandbox.SerializeRequest(request), native.RequestJson);
            using var document = JsonDocument.Parse(native.RequestJson!);
            Assert.Equal(
                "process",
                document.RootElement.GetProperty("containment").GetString());
            Assert.Equal(
                "cmd /c exit 0",
                document.RootElement.GetProperty("process").GetProperty("commandLine").GetString());
            Assert.Equal("1.0.0", document.RootElement.GetProperty("version").GetString());
            Assert.Equal("dotnet-exact-probe", document.RootElement.GetProperty("containerId").GetString());
            Assert.False(document.RootElement.TryGetProperty("policy", out _));
            AssertNoExplicitNulls(document.RootElement);
            Assert.True(native.OutputFreed);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Probe_WithoutRequestPassesNullToNative()
    {
        using var native = new FakeRequestProbeInterop
        {
            OutputJson = CompleteProbeJson,
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
            var output = MxcSandbox.Probe();

            Assert.Equal(IsolationTier.AppContainerDacl, output.Tier);
            Assert.Null(native.RequestJson);
            Assert.True(native.OutputFreed);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void StableTypedEntrypoints_RejectExperimentalOptInBeforeNativeCall()
    {
        using var native = new FakeRequestProbeInterop
        {
            OutputJson = CompleteProbeJson,
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
#pragma warning disable MXC0001
            var request = new SandboxRequest(new SandboxPolicy(), "echo")
            {
                Experimental = true,
            };
#pragma warning restore MXC0001
            foreach (var action in new Action[]
                     {
                         () => MxcSandbox.Run(request),
                         () => MxcSandbox.Spawn(request),
                         () => MxcSandbox.Probe(request),
                     })
            {
                var error = Assert.Throws<ArgumentException>(action);
                Assert.Equal("request", error.ParamName);
                Assert.Contains("Stable V1", error.Message, StringComparison.Ordinal);
            }
            Assert.Equal(0, native.ProbeCalls);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Theory]
    [InlineData(ErrorCode.MalformedRequest)]
    [InlineData(ErrorCode.UnsupportedContainment)]
    [InlineData(ErrorCode.BackendError)]
    public void Probe_MapsStructuredNativeFailure(ErrorCode code)
    {
        using var native = new FakeRequestProbeInterop
        {
            Status = (int)code,
            ErrorMessage = "probe exploded",
            ErrorOperation = "ProcessModel.Probe",
            ErrorNativeCode = "0x80070005",
            ErrorRemediation = "check policy",
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
            var error = Assert.Throws<MxcException>(() => MxcSandbox.Probe(
                new SandboxRequest(
                    new SandboxPolicy(),
                    "cmd /c exit 0")));
            Assert.Equal(code, error.Code);
            Assert.Contains("probe exploded", error.Message);
            Assert.Equal("ProcessModel.Probe", error.Operation);
            Assert.Equal("0x80070005", error.NativeCode);
            Assert.Equal("check policy", error.Remediation);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Probe_SurfacesMalformedOutput()
    {
        using var native = new FakeRequestProbeInterop { OutputJson = "not json" };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
            Assert.Throws<JsonException>(() => MxcSandbox.Probe(
                new SandboxRequest(
                    new SandboxPolicy(),
                    "cmd /c exit 0")));
            Assert.True(native.OutputFreed);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Probe_WhenInteropReportsUnsupportedPlatform_ThrowsBeforeNativeCall()
    {
        using var native = new FakeRequestProbeInterop
        {
            IsSupportedOnCurrentPlatform = false,
            OutputJson = CompleteProbeJson,
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;

        try
        {
            var error = Assert.Throws<MxcException>(() => MxcSandbox.Probe());
            Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
            Assert.Equal(0, native.ProbeCalls);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void ProbeParser_RejectsCompleteFactsWithoutTierOrError()
    {
        AssertProbeJsonRejected(json =>
        {
            json.Remove("tier");
            json.Remove("needsDaclAugmentation");
        });
    }

    [Fact]
    public void ProbeParser_RejectsMissingWarnings()
    {
        AssertProbeJsonRejected(json => json.Remove("warnings"));
    }

    [Fact]
    public void ProbeParser_RejectsUnknownEnvelopeField()
    {
        AssertProbeJsonRejected(json => json["unknownEnvelopeField"] = true);
    }

    [Fact]
    public void ProbeParser_RejectsUnknownProbeFactsField()
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!["unknownProbeField"] = true);
    }

    [Fact]
    public void ProbeParser_RejectsUnknownUiCapabilityField()
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!["uiCapabilities"]!["unknownUiField"] = true);
    }

    [Fact]
    public void ProbeParser_RejectsMissingRequiredProbeBoolean()
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!.AsObject().Remove("bfscfgPresent"));
    }

    [Fact]
    public void ProbeParser_RejectsMissingRequiredUiBoolean()
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!["uiCapabilities"]!.AsObject()
                .Remove("canBlockClipboardRead"));
    }

    [Theory]
    [InlineData("unknown-tier")]
    [InlineData("baseContainer")]
    public void ProbeParser_RejectsUnknownTier(string tier)
    {
        AssertProbeJsonRejected(json => json["tier"] = tier);
    }

    [Fact]
    public void ProbeParser_RejectsNonStringTier()
    {
        AssertProbeJsonRejected(json => json["tier"] = 1);
    }

    [Fact]
    public void ProbeParser_RejectsSuccessWithoutDaclAugmentationState()
    {
        AssertProbeJsonRejected(json => json.Remove("needsDaclAugmentation"));
    }

    [Fact]
    public void ProbeParser_AcceptsErrorWithoutTierSelectionFields()
    {
        var json = CreateCompleteProbeJson();
        json.Remove("tier");
        json.Remove("needsDaclAugmentation");
        json["error"] = "tier detection failed";

        var output = MxcSandbox.ParseProbeOutput(json.ToJsonString());

        Assert.Null(output.Tier);
        Assert.Null(output.NeedsDaclAugmentation);
        Assert.Equal("tier detection failed", output.Error);
    }

    [Fact]
    public void ProbeParser_RejectsDaclAugmentationStateWithError()
    {
        AssertProbeJsonRejected(json =>
        {
            json.Remove("tier");
            json["error"] = "tier detection failed";
        });
    }

    [Fact]
    public void Probe_RejectsNonProcessContainerRequest()
    {
        using var native = new FakeRequestProbeInterop
        {
            Status = (int)ErrorCode.UnsupportedContainment,
            ErrorMessage = "request-aware probe supports ProcessContainer only; got wslc",
        };
        var previous = MxcSandbox.RequestProbeInterop;
        MxcSandbox.RequestProbeInterop = native;
        var request = new SandboxRequest(
            new SandboxPolicy(),
            "echo hi")
        {
            Containment = new WslcContainment(),
        };

        try
        {
            var error = Assert.Throws<MxcException>(() => MxcSandbox.Probe(request));
            Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
            Assert.Contains("got wslc", error.Message);
            Assert.Equal(1, native.ProbeCalls);
            using var document = JsonDocument.Parse(native.RequestJson!);
            Assert.Equal(
                "wslc",
                document.RootElement.GetProperty("containment").GetString());
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcSandbox.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Serialization_V09PreservesDirectionalAndRuntimeAuthoring()
    {
        var policy = new SandboxPolicy { Version = "0.9.0-alpha" };
        using var absent = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        Assert.False(absent.RootElement.TryGetProperty("network", out _));
        policy.Network = new NetworkPolicy();
        using var empty = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        Assert.Equal("{}", empty.RootElement.GetProperty("network").GetRawText());

        policy.Network.Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny };
        policy.Network.Ingress = new NetworkIngressPolicy { HostLoopback = NetworkAction.Deny };
        policy.Network.RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" };
        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var network = document.RootElement.GetProperty("network");
        Assert.Equal(
            new[] { "egress", "ingress", "runtimeConfig" },
            network.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal("deny", network.GetProperty("egress").GetProperty("default").GetString());
        Assert.False(network.GetProperty("ingress").TryGetProperty("default", out _));
        Assert.Equal("http://127.0.0.1:8080",
            network.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString());
    }

    [Fact]
    public void NativeVersion_IsNotEmpty()
    {
        // Exercises the native load path + mxc_version() end-to-end.
        Assert.False(string.IsNullOrEmpty(MxcPlatform.NativeVersion));
    }

    [Fact]
    public void GetAvailableBackends_ReturnsTypedNativeProbe()
    {
        var backends = MxcPlatform.GetAvailableBackends();

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
        var support = MxcPlatform.GetPlatformSupport();

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
        Assert.Equal(expected, MxcPlatform.ParseBackend(wireName));
    }

    [Theory]
    [InlineData("base-container", IsolationTier.BaseContainer)]
    [InlineData("appcontainer-bfs", IsolationTier.AppContainerBfs)]
    [InlineData("appcontainer-dacl", IsolationTier.AppContainerDacl)]
    public void Discovery_MapsEveryNativeIsolationTier(
        string wireName,
        IsolationTier expected)
    {
        Assert.Equal(expected, MxcPlatform.ParseIsolationTier(wireName));
    }

    [Theory]
    [InlineData("captureDenials", BackendCapability.CaptureDenials)]
    [InlineData("filesystemDeniedPaths", BackendCapability.FilesystemDeniedPaths)]
    [InlineData("filesystemEnumeratePaths", BackendCapability.FilesystemEnumeratePaths)]
    [InlineData("ingressHostLoopbackAllow", BackendCapability.IngressHostLoopbackAllow)]
    [InlineData("proxyEnforcement", BackendCapability.ProxyEnforcement)]
    public void Discovery_MapsEveryNativeCapability(
        string wireName,
        BackendCapability expected)
    {
        Assert.Equal(expected, MxcPlatform.ParseBackendCapability(wireName));
    }

    [Fact]
    public void BackendCapability_PreservesReleasedNumericValues()
    {
        Assert.Equal(0, (int)BackendCapability.Unknown);
        Assert.Equal(1, (int)BackendCapability.CaptureDenials);
        Assert.Equal(2, (int)BackendCapability.ProxyEnforcement);
        Assert.Equal(3, (int)BackendCapability.FilesystemDeniedPaths);
        Assert.Equal(4, (int)BackendCapability.IngressHostLoopbackAllow);
        Assert.Equal(5, (int)BackendCapability.FilesystemEnumeratePaths);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("processContainer")]
    public void Discovery_PreservesUnknownNativeBackend(string wireName)
    {
        Assert.Equal(ContainmentBackend.Unknown, MxcPlatform.ParseBackend(wireName));
        Assert.Equal(IsolationTier.Unknown, MxcPlatform.ParseIsolationTier(wireName));
        Assert.Equal(
            BackendCapability.Unknown,
            MxcPlatform.ParseBackendCapability(wireName));
    }

    /// <summary>
    /// The payload a Linux host emits when it has bubblewrap but cannot enforce
    /// proxy-only egress. Dropping the warning would leave callers with an
    /// absent capability and no way to learn why.
    /// </summary>
    [Fact]
    public void Discovery_CarriesWarningsFromAnUnsupportedCapability()
    {
        const string json = """
            [
              {
                "backend": "bubblewrap",
                "warnings": ["Bubblewrap: network.proxy requires 'slirp4netns' on PATH"]
              },
              { "backend": "lxc" }
            ]
            """;

        var backends = MxcPlatform.ParseAvailableBackends(json);

        var bubblewrap = Assert.Single(
            backends,
            backend => backend.Backend == ContainmentBackend.Bubblewrap);
        Assert.Empty(bubblewrap.Capabilities);
        Assert.Equal(
            "Bubblewrap: network.proxy requires 'slirp4netns' on PATH",
            Assert.Single(bubblewrap.Warnings));

        // An entry the native side omitted `warnings` from must still project
        // an empty collection rather than null.
        var lxc = Assert.Single(backends, backend => backend.Backend == ContainmentBackend.Lxc);
        Assert.Empty(lxc.Warnings);
    }

    [Fact]
    public void Discovery_CarriesProxyEnforcementCapabilityWithoutWarnings()
    {
        const string json =
            """[{ "backend": "bubblewrap", "capabilities": ["proxyEnforcement"] }]""";

        var bubblewrap = Assert.Single(MxcPlatform.ParseAvailableBackends(json));

        Assert.Equal(ContainmentBackend.Bubblewrap, bubblewrap.Backend);
        Assert.Equal(
            BackendCapability.ProxyEnforcement,
            Assert.Single(bubblewrap.Capabilities));
        Assert.Empty(bubblewrap.Warnings);
    }

    [Fact]
    public void Run_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(null!, "echo hi"));
    }

    [Fact]
    public void Run_NullCommand_Throws()
    {
        var policy = new SandboxPolicy { Version = "0.9.0-alpha" };
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(policy, null!));
    }

    [Fact]
    public void SandboxPolicy_SerializesEnumeratePaths()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.9.0-alpha",
        };
        var request = new SandboxRequest(policy, "echo parity")
        {
            Containment = new ProcessContainerContainment
            {
                Filesystem = new ProcessContainerFilesystemPolicy
                {
                    EnumeratePaths = [@"C:\input"],
                },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));

        Assert.Equal(
            @"C:\input",
            doc.RootElement
                .GetProperty("processContainer")
                .GetProperty("filesystem")
                .GetProperty("enumeratePaths")[0]
                .GetString());
    }

    [Fact]
    public void SandboxRequest_NestsCaptureDenialsUnderProcessContainer()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            Containment = new ProcessContainerContainment
            {
                CaptureDenials = new CaptureDenialsPolicy(),
            },
        };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;
        var processContainer = root.GetProperty("processContainer");
        var capture = processContainer.GetProperty("captureDenials");

        Assert.Equal("processcontainer", root.GetProperty("containment").GetString());
        Assert.Equal("block", capture.GetProperty("mode").GetString());
        Assert.False(capture.TryGetProperty("retainEtl", out _));
        Assert.False(capture.TryGetProperty("outputPath", out _));
        Assert.False(root.TryGetProperty("captureDenials", out _));
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
        var processContainer = root.GetProperty("processContainer");

        Assert.Equal("processcontainer", root.GetProperty("containment").GetString());
        Assert.Equal(
            "allow",
            processContainer.GetProperty("captureDenials").GetProperty("mode").GetString());
        Assert.True(
            processContainer.GetProperty("captureDenials").GetProperty("retainEtl").GetBoolean());
        Assert.False(root.TryGetProperty("captureDenials", out _));
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
        var processContainer = doc.RootElement.GetProperty("processContainer");

        Assert.True(processContainer.GetProperty("leastPrivilege").GetBoolean());
        Assert.Equal(
            captureDenials.OutputPath,
            processContainer.GetProperty("captureDenials").GetProperty("outputPath").GetString());
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
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            ContainerName = "test-container",
            WorkingDirectory = @"C:\work",
            InheritDefaultEnvironment = true,
            Environment = new()
            {
                ["GREETING"] = "hello",
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        Assert.Equal("echo hi", root.GetProperty("process").GetProperty("commandLine").GetString());
        Assert.Equal("process", root.GetProperty("containment").GetString());
        Assert.Equal("test-container", root.GetProperty("containerId").GetString());
        var process = root.GetProperty("process");
        Assert.Equal(@"C:\work", process.GetProperty("cwd").GetString());
        Assert.Contains(
            process.GetProperty("env").EnumerateArray(),
            item => item.GetString() == "GREETING=hello");
        Assert.True(process.GetProperty("inheritDefaultEnv").GetBoolean());
        Assert.False(root.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void SandboxRequest_DistinguishesOmittedAndExplicitlyEmptyEnvironment()
    {
        var omitted = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi");
        using var omittedDoc = JsonDocument.Parse(MxcSandbox.SerializeRequest(omitted));
        Assert.False(omittedDoc.RootElement.GetProperty("process").TryGetProperty("env", out _));
        Assert.False(omittedDoc.RootElement.GetProperty("process").TryGetProperty("inheritDefaultEnv", out _));

        var explicitlyEmpty = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            Environment = new(),
        };
        using var explicitlyEmptyDoc =
            JsonDocument.Parse(MxcSandbox.SerializeRequest(explicitlyEmpty));
        var environment = explicitlyEmptyDoc.RootElement.GetProperty("process").GetProperty("env");
        Assert.Equal(JsonValueKind.Array, environment.ValueKind);
        Assert.Empty(environment.EnumerateArray());
    }

    [Fact]
    public void SandboxRequest_SerializesCompleteProcessContainerOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
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
        var processContainer = doc.RootElement.GetProperty("processContainer");

        Assert.Equal("processcontainer", doc.RootElement.GetProperty("containment").GetString());
        Assert.True(processContainer.GetProperty("leastPrivilege").GetBoolean());
        Assert.True(processContainer.GetProperty("learningMode").GetBoolean());
        Assert.Equal("internetClient", processContainer.GetProperty("capabilities")[0].GetString());
        Assert.Equal("allow",
            processContainer.GetProperty("captureDenials").GetProperty("mode").GetString());
        Assert.Equal("atoms", processContainer.GetProperty("ui").GetProperty("isolation").GetString());
        Assert.Equal("parameters",
            processContainer.GetProperty("ui").GetProperty("systemSettings").GetString());
        Assert.Equal("Contoso.Proxy_123",
            processContainer.GetProperty("network").GetProperty("allowedProxyPeer").GetString());
    }

    [Fact]
    public void SandboxRequest_SerializesWslcOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "python3 -c 'print(42)'")
        {
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
        var wslc = doc.RootElement.GetProperty("wslc");

        Assert.Equal("wslc", doc.RootElement.GetProperty("containment").GetString());
        Assert.Equal("python:3.12", wslc.GetProperty("image").GetString());
        Assert.Equal(4, wslc.GetProperty("cpuCount").GetInt32());
        Assert.Equal(4096, wslc.GetProperty("memoryMb").GetInt64());
        Assert.True(wslc.GetProperty("gpu").GetBoolean());
        Assert.Equal(8080,
            wslc.GetProperty("portMappings")[0].GetProperty("windowsPort").GetInt32());
        Assert.Equal(80,
            wslc.GetProperty("portMappings")[0].GetProperty("containerPort").GetInt32());
    }

    [Fact]
    public void SandboxRequest_SerializesSeatbeltOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            Containment = new SeatbeltContainment
            {
                ProfileOverride = "(version 1)",
                GuiAccess = true,
                NestedPty = false,
                KeychainAccess = true,
                ExtraMachLookups = { "com.example.service" },
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var seatbelt = doc.RootElement.GetProperty("seatbelt");

        Assert.Equal("seatbelt", doc.RootElement.GetProperty("containment").GetString());
        Assert.Equal("(version 1)", seatbelt.GetProperty("profileOverride").GetString());
        Assert.True(seatbelt.GetProperty("guiAccess").GetBoolean());
        Assert.False(seatbelt.GetProperty("nestedPty").GetBoolean());
        Assert.True(seatbelt.GetProperty("keychainAccess").GetBoolean());
        Assert.Equal(
            "com.example.service",
            seatbelt.GetProperty("extraMachLookups")[0].GetString());
    }

    [Fact]
    public void SandboxRequest_SerializesLxcOptions()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            Containment = new LxcContainment
            {
                Distribution = "ubuntu",
                Release = "24.04",
            },
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var lxc = doc.RootElement.GetProperty("lxc");

        Assert.Equal("lxc", doc.RootElement.GetProperty("containment").GetString());
        Assert.Equal("ubuntu", lxc.GetProperty("distribution").GetString());
        Assert.Equal("24.04", lxc.GetProperty("release").GetString());
    }

    [Fact]
    public void SandboxRequest_SerializesBubblewrapContainment()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            "echo hi")
        {
            Containment = new BubblewrapContainment(),
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        Assert.Equal("bubblewrap", root.GetProperty("containment").GetString());
        Assert.False(root.TryGetProperty("bubblewrap", out _));
    }

    [Fact]
    public void SandboxRequest_SerializesIsolationSessionContainment()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            @"cmd.exe /c echo hi")
        {
            Containment = new IsolationSessionContainment(),
        };

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        // The native side derives this spelling from a serde attribute while the
        // managed side names it in an attribute of its own.
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());

        // The backend takes no configuration, so the discriminator is the whole
        // object.
        Assert.False(root.TryGetProperty("isolationSession", out _));
    }

    [Fact]
    public void SandboxRequest_IsolationSessionDoesNotEnableExperimentalMode()
    {
        var request = new SandboxRequest(
            new SandboxPolicy { Version = "0.9.0-alpha" },
            @"cmd.exe /c echo hi")
        {
            Containment = new IsolationSessionContainment(),
        };

        using var document = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        Assert.False(document.RootElement.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void SandboxPolicy_SerializesDirectionalNetworking()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.9.0-alpha",
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
        var policy = new SandboxPolicy { Version = "0.9.0-alpha" };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));

        Assert.False(doc.RootElement.TryGetProperty("captureDenials", out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SandboxPolicy_TelemetrySerializesCanonicalNestedShape(bool enabled)
    {
        var policy = new SandboxPolicy
        {
            Version = "0.9.0-alpha",
            Telemetry = new TelemetrySettings { Enabled = enabled },
        };

        var json = MxcSandbox.SerializePolicy(policy);

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(enabled, root.GetProperty("telemetry").GetProperty("enabled").GetBoolean());
        Assert.False(root.TryGetProperty("telemetryEnabled", out _));

        var roundTrip = JsonSerializer.Deserialize<SandboxPolicy>(json);
        Assert.NotNull(roundTrip);
        Assert.Equal(enabled, roundTrip.Telemetry?.Enabled);
    }

    [Fact]
    public void SandboxPolicy_OmittedTelemetrySerializesNoTelemetryField()
    {
        var policy = new SandboxPolicy { Version = "0.9.0-alpha" };

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var root = document.RootElement;
        Assert.False(root.TryGetProperty("telemetry", out _));
        Assert.False(root.TryGetProperty("telemetryEnabled", out _));
    }

    [Fact]
    public void SandboxPolicy_DefaultTelemetrySettingsSerializeDisabled()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.9.0-alpha",
            Telemetry = new TelemetrySettings(),
        };

        using var document = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));

        Assert.False(
            document.RootElement
                .GetProperty("telemetry")
                .GetProperty("enabled")
                .GetBoolean());
    }

    [Fact]
    public void SandboxPolicy_RoundTripsLegacyCaptureDenials()
    {
        const string json = """{"captureDenials":{"mode":"block"}}""";

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

    [Theory]
    [InlineData(0, 80)]
    [InlineData(8080, 65536)]
    public void WslcPortMapping_RejectsInvalidPorts(int windowsPort, int containerPort)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new WslcPortMapping(windowsPort, containerPort));
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

        Assert.False(root.TryGetProperty("captureDenials", out _));
        Assert.Equal(
            "block",
            root.GetProperty("processContainer")
                .GetProperty("captureDenials")
                .GetProperty("mode")
                .GetString());
    }

    [Fact]
    public void SerializeRequest_PreservesTelemetryInExactRequest()
    {
        var policy = CreateLegacyCaptureDenialsPolicy(
            new CaptureDenialsPolicy(),
            "0.9.0-alpha");
        policy.Telemetry = new TelemetrySettings { Enabled = true };
        var request = new SandboxRequest(policy, "echo hi");

        using var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var root = doc.RootElement;

        Assert.True(
            root.GetProperty("telemetry")
                .GetProperty("enabled")
                .GetBoolean());
        Assert.False(root.TryGetProperty("captureDenials", out _));
    }

    private sealed unsafe class FakeRequestProbeInterop : IRequestProbeInterop, IDisposable
    {
        private readonly HashSet<nint> allocations = [];
        private byte* outputPointer;

        internal int Status { get; init; }
        internal string? OutputJson { get; init; }
        internal string? ErrorMessage { get; init; }
        internal string? ErrorOperation { get; init; }
        internal string? ErrorNativeCode { get; init; }
        internal string? ErrorRemediation { get; init; }
        internal string? RequestJson { get; private set; }
        internal bool OutputFreed { get; private set; }
        internal bool ErrorFreed { get; private set; }
        internal int ProbeCalls { get; private set; }

        public bool IsSupportedOnCurrentPlatform { get; init; } = true;

        public int Probe(
            byte* requestJsonUtf8,
            byte** outputJsonUtf8,
            MxcErrorDetail* error)
        {
            ProbeCalls++;
            RequestJson = requestJsonUtf8 is null
                ? null
                : Marshal.PtrToStringUTF8((IntPtr)requestJsonUtf8);
            outputPointer = Allocate(OutputJson);
            *outputJsonUtf8 = outputPointer;
            error->message_utf8 = Allocate(ErrorMessage);
            error->operation_utf8 = Allocate(ErrorOperation);
            error->native_code_utf8 = Allocate(ErrorNativeCode);
            error->remediation_utf8 = Allocate(ErrorRemediation);
            return Status;
        }

        public void FreeString(byte* value)
        {
            OutputFreed = value == outputPointer;
            Free(value);
        }

        public void FreeError(MxcErrorDetail* error)
        {
            Free(error->message_utf8);
            Free(error->operation_utf8);
            Free(error->native_code_utf8);
            Free(error->remediation_utf8);
            *error = default;
            ErrorFreed = true;
        }

        public void Dispose()
        {
            foreach (var allocation in allocations)
            {
                Marshal.FreeCoTaskMem(allocation);
            }
            allocations.Clear();
        }

        private byte* Allocate(string? value)
        {
            if (value is null)
            {
                return null;
            }

            var allocation = Marshal.StringToCoTaskMemUTF8(value);
            allocations.Add(allocation);
            return (byte*)allocation;
        }

        private void Free(byte* value)
        {
            if (value is null)
            {
                return;
            }

            var allocation = (nint)value;
            if (allocations.Remove(allocation))
            {
                Marshal.FreeCoTaskMem(allocation);
            }
        }
    }

    private static SandboxPolicy CreateLegacyCaptureDenialsPolicy(
        CaptureDenialsPolicy captureDenials,
        string version = "0.9.0-alpha")
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
