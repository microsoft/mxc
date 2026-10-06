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
using MxcContainer = Microsoft.Mxc.Sdk.V1.MxcContainer;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcContainerTests
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
            "baseContainerSupportsIdentitylessLoopbackProxy": true,
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
        Assert.Throws<JsonException>(() => MxcContainer.ParseProbeOutput(json.ToJsonString()));
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
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;

        try
        {
            var request = new ContainerRequest("cmd /c exit 0")
            {
                ContainerName = "dotnet-exact-probe",
            };
            var output = MxcContainer.Probe(request);

            Assert.Equal(IsolationTier.AppContainerDacl, output.Tier);
            Assert.True(output.Probes.BaseContainerApiPresent);
            Assert.Equal(MxcContainer.SerializeRequest(request), native.RequestJson);
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
            MxcContainer.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Probe_WithoutRequestPassesNullToNative()
    {
        using var native = new FakeRequestProbeInterop
        {
            OutputJson = CompleteProbeJson,
        };
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;

        try
        {
            var output = MxcContainer.Probe();

            Assert.Equal(IsolationTier.AppContainerDacl, output.Tier);
            Assert.Null(native.RequestJson);
            Assert.True(native.OutputFreed);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcContainer.RequestProbeInterop = previous;
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
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;

        try
        {
            var error = Assert.Throws<MxcException>(
                () => MxcContainer.Probe(new ContainerRequest("cmd /c exit 0")));
            Assert.Equal(code, error.Code);
            Assert.Contains("probe exploded", error.Message);
            Assert.Equal("ProcessModel.Probe", error.Operation);
            Assert.Equal("0x80070005", error.NativeCode);
            Assert.Equal("check policy", error.Remediation);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcContainer.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Probe_SurfacesMalformedOutput()
    {
        using var native = new FakeRequestProbeInterop { OutputJson = "not json" };
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;

        try
        {
            Assert.Throws<JsonException>(
                () => MxcContainer.Probe(new ContainerRequest("cmd /c exit 0")));
            Assert.True(native.OutputFreed);
            Assert.True(native.ErrorFreed);
        }
        finally
        {
            MxcContainer.RequestProbeInterop = previous;
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
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;

        try
        {
            var error = Assert.Throws<MxcException>(() => MxcContainer.Probe());
            Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
            Assert.Equal(0, native.ProbeCalls);
        }
        finally
        {
            MxcContainer.RequestProbeInterop = previous;
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

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ProbeParser_PreservesIdentitylessLoopbackProxy(bool supported, bool ingressSupported)
    {
        var json = CreateCompleteProbeJson();
        json["tier"] = "base-container";
        json["needsDaclAugmentation"] = false;
        json["probes"]!["baseContainerSupportsIngressHostLoopbackAllow"] = ingressSupported;
        json["probes"]!["baseContainerSupportsIdentitylessLoopbackProxy"] = supported;

        var output = MxcContainer.ParseProbeOutput(json.ToJsonString());

        Assert.Equal(supported, output.Probes.BaseContainerSupportsIdentitylessLoopbackProxy);
        Assert.Equal(ingressSupported, output.Probes.BaseContainerSupportsIngressHostLoopbackAllow);
    }

    [Fact]
    public void ProbeParser_RejectsMissingIdentitylessLoopbackProxy()
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!.AsObject().Remove("baseContainerSupportsIdentitylessLoopbackProxy"));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("\"true\"")]
    [InlineData("1")]
    public void ProbeParser_RejectsInvalidIdentitylessLoopbackProxy(string value)
    {
        AssertProbeJsonRejected(json =>
            json["probes"]!["baseContainerSupportsIdentitylessLoopbackProxy"] = JsonNode.Parse(value));
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

        var output = MxcContainer.ParseProbeOutput(json.ToJsonString());

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
        var previous = MxcContainer.RequestProbeInterop;
        MxcContainer.RequestProbeInterop = native;
        var request = new ContainerRequest("echo hi")
        {
            Containment = new Containment.Wslc(),
        };

        try
        {
            var error = Assert.Throws<MxcException>(() => MxcContainer.Probe(request));
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
            MxcContainer.RequestProbeInterop = previous;
        }
    }

    [Fact]
    public void Serialization_V09PreservesDirectionalAndRuntimeAuthoring()
    {
        var request = new ContainerRequest("echo network")
        {
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy { HostLoopback = NetworkAction.Deny },
                RuntimeConfig = new NetworkRuntimeConfig
                {
                    NetworkProxy = "http://127.0.0.1:8080",
                },
            },
        };
        using var document = JsonDocument.Parse(MxcContainer.SerializeRequest(request));
        var root = document.RootElement;
        var network = root.GetProperty("network");
        Assert.Equal(
            new[] { "egress", "ingress" },
            network.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal("deny", network.GetProperty("egress").GetProperty("default").GetString());
        Assert.False(network.GetProperty("ingress").TryGetProperty("default", out _));
        Assert.Equal("http://127.0.0.1:8080",
            root.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString());
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
    [InlineData("identitylessLoopbackProxy", BackendCapability.IdentitylessLoopbackProxy)]
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
        Assert.Equal(6, (int)BackendCapability.IdentitylessLoopbackProxy);
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
    public void Run_NullRequest_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcContainer.Run((ContainerRequest)null!));
    }

    [Fact]
    public void ContainerRequest_NullCommand_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ContainerRequest(null!));
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

        var output = JsonSerializer.Deserialize<CaptureDenialsResult>(json);

        Assert.NotNull(output);
        Assert.Equal("capture.etl", output.EtlPath);
    }

    [Fact]
    public void OutputMetadata_DeserializesCaptureFailure()
    {
        const string json = """
            {
              "captureDenialsError": {
                "message": "decode failed",
                "etlPath": "capture.etl"
              }
            }
            """;

        var metadata = JsonSerializer.Deserialize<ExecutionMetadata>(json);

        var error = metadata?.CaptureDenialsError;
        Assert.NotNull(error);
        Assert.Equal("decode failed", error.Message);
        Assert.Equal("capture.etl", error.EtlPath);
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

}
