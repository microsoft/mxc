// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Native AOT smoke test for the SDK's JSON layer (issue #1305).
//
// This program exercises every production serialize/deserialize path in
// isolation - it never calls native code, so it needs neither mxc_ffi nor its
// cargo build. It is meant to be published with `dotnet publish -p:PublishAot=true`:
// the ILCompiler then fails the publish if any reachable JSON path still relies
// on reflection. At runtime the System.Text.Json reflection fallback is disabled
// (see the csproj), so a missing source-generated registration throws instead of
// silently falling back.

using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

static void Check(bool condition, string what)
{
    if (!condition)
    {
        throw new InvalidOperationException($"AOT smoke check failed: {what}");
    }
}

// Reflection-free serialization must be in force, or this test proves nothing.
Check(!JsonSerializer.IsReflectionEnabledByDefault, "reflection fallback is disabled");

// 1. Serialize a directional high-level policy: directional network,
//    filesystem, and UI sections, exercising the camelCase enum converters.
//    The v1 high-level SDK is version-free (it owns its contract internally),
//    so no "version" field is emitted.
var devPolicy = new SandboxPolicy
{
    TimeoutMs = 5000,
    Filesystem = new FilesystemPolicy
    {
        ReadwritePaths = { "C:\\work" },
        ReadonlyPaths = { "C:\\input" },
        DeniedPaths = { "C:\\secret" },
    },
    Network = new NetworkPolicy
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
        Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny },
        RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" },
    },
    Ui = new UiPolicy { AllowWindows = true, Clipboard = ClipboardPolicy.Read },
};

using (var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(devPolicy)))
{
    var root = doc.RootElement;
    Check(!root.TryGetProperty("version", out _), "policy is version-free");
    var network = root.GetProperty("network");
    Check(network.GetProperty("egress").GetProperty("default").GetString() == "deny", "egress default enum");
    Check(network.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString()
        == "http://127.0.0.1:8080", "runtime proxy");
    Check(root.GetProperty("ui").GetProperty("clipboard").GetString() == "read", "clipboard enum");
}

// 2. Serialize a full exact request with ProcessContainer-specific policy.
var request = new SandboxRequest(devPolicy, "echo hello")
{
    Containment = new ProcessContainerContainment
    {
        LeastPrivilege = true,
        Capabilities = { "internetClient" },
    },
};
using (var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(request)))
{
    var root = doc.RootElement;
    Check(root.GetProperty("version").GetString() == "1.0.0", "SDK-owned exact request version");
    Check(!root.TryGetProperty("policy", out _), "private policy envelope is absent");
    Check(root.GetProperty("process").GetProperty("commandLine").GetString() == "echo hello",
        "exact request command line");
    Check(root.GetProperty("network").GetProperty("egress").GetProperty("default").GetString() == "deny",
        "exact request carries directional policy");
    Check(root.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString()
        == "http://127.0.0.1:8080", "exact runtime proxy");
    Check(root.GetProperty("containment").GetString() == "processcontainer", "exact containment discriminator");
    Check(root.GetProperty("processContainer").GetProperty("leastPrivilege").GetBoolean(),
        "exact backend policy");
}

// The generated exact wire type must preserve the full unsigned WSLC bound.
var wslcRequest = new SandboxRequest(new SandboxPolicy(), "echo memory")
{
    Containment = new WslcContainment { MemoryMb = ulong.MaxValue },
};
using (var doc = JsonDocument.Parse(MxcSandbox.SerializeRequest(wslcRequest)))
{
    Check(doc.RootElement.GetProperty("wslc").GetProperty("memoryMb").GetUInt64()
        == ulong.MaxValue, "full unsigned WSLC memory bound");
}

#pragma warning disable MXC0001
var experimentalRequest = new SandboxRequest(new SandboxPolicy(), "echo unsupported")
{
    Experimental = true,
};
#pragma warning restore MXC0001
try
{
    _ = MxcSandbox.SerializeRequest(experimentalRequest);
    throw new InvalidOperationException("Stable experimental opt-in was silently accepted.");
}
catch (ArgumentException ex) when (ex.ParamName == "request")
{
    // Expected: stable typed requests cannot authorize development features.
}

// 3. Deserialize a native backend probe array - including an entry that omits
//    the (empty) capabilities/warnings arrays, guarding the source-gen
//    initializer regression fixed alongside this test.
const string backendsJson = """
[
  {"backend":"processcontainer","tier":"base-container","capabilities":["captureDenials"]},
  {"backend":"lxc"}
]
""";
var backends = MxcJson.Deserialize<NativeAvailableBackend[]>(backendsJson);
Check(backends is { Length: 2 }, "two backends parsed");
Check(backends![0].Capabilities.Length == 1, "first backend capability parsed");
Check(backends[1].Capabilities.Length == 0, "omitted capabilities default to empty, not null");
Check(backends[1].Warnings.Length == 0, "omitted warnings default to empty, not null");
var publicBackends = MxcPlatform.ParseAvailableBackends(backendsJson);
Check(publicBackends.Count == 2, "root discovery facade parses both backends");
Check(publicBackends[1].Backend == ContainmentBackend.Lxc, "root discovery maps LXC");

// 4. Deserialize platform support.
const string supportJson = """{"isSupported":true,"availableMethods":["processcontainer"]}""";
var support = MxcJson.Deserialize<NativePlatformSupport>(supportJson);
Check(support is { IsSupported: true }, "platform support parsed");
Check(support!.AvailableMethods.Length == 1, "available methods parsed");

// 5. Deserialize structured output metadata: both the nested captureDenials
//    success object and the captureDenialsError failure object, so both output
//    roots are exercised.
const string metadataJson = """
{"captureDenials":{"type":"captureDenials","outputPath":"C:\\out.json","exitCode":0,"totalDenials":3,"deniedResourcesTruncated":false},"captureDenialsError":{"message":"finalize failed","etlPath":"C:\\trace.etl"}}
""";
var metadata = MxcJson.Deserialize<SandboxOutputMetadata>(metadataJson);
Check(metadata?.CaptureDenials?.OutputPath == "C:\\out.json", "output metadata parsed");
Check(metadata!.CaptureDenials!.TotalDenials == 3, "denial count parsed");
Check(metadata.CaptureDenialsError?.Message == "finalize failed", "capture denials error parsed");
Check(metadata.CaptureDenialsError!.EtlPath == "C:\\trace.etl", "capture denials error etl path parsed");

// 6. Deserialize a warnings array (string[]).
var warnings = MxcJson.Deserialize<string[]>("""["a","b"]""");
Check(warnings is { Length: 2 }, "warnings array parsed");

// 7. Round-trip a state-aware network policy: exercises the non-null section
//    converter on the state-aware directional model.
var stateNetwork = MxcJson.Deserialize<StateAwareNetworkPolicy>(
    """{"egress":{"default":"allow"},"ingress":{"default":"deny"}}""");
Check(stateNetwork?.Egress?.Default == NetworkAction.Allow, "state-aware network parsed");
JsonNode? stateNode = MxcJson.SerializeToNode(stateNetwork!, MxcJson.Options);
Check(stateNode?["egress"]?["default"]?.GetValue<string>() == "allow", "state-aware network round-trips");

// 8. Build the state-aware lifecycle envelopes through the real MxcLifecycle
//    builders. These are native-free (the P/Invoke lives in a separate step),
//    so publishing them here exercises the provision/exec serialization call
//    sites - filesystem, telemetry, directional network, environment, and
//    runtime config - under reflection-disabled execution, which the
//    run-to-completion path above does not cover.
var provisionEnvelope = MxcLifecycle.BuildProvisionEnvelope(
    StateAwareContainment.Wslc,
    new WslcProvisionOptions
    {
        Filesystem = new StateAwareFilesystemPolicy { ReadwritePaths = { "C:\\work" } },
        Network = new StateAwareNetworkPolicy
        {
            Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
            Ingress = new NetworkIngressPolicy
            {
                Default = NetworkAction.Allow,
                HostLoopback = NetworkAction.Allow,
            },
        },
        Telemetry = new TelemetrySettings { Enabled = true },
    });
Check(provisionEnvelope["phase"]?.GetValue<string>() == "provision", "provision phase");
Check(provisionEnvelope["containment"]?.GetValue<string>() == "wslc", "provision containment");
Check(provisionEnvelope["filesystem"]?["readwritePaths"]?[0]?.GetValue<string>() == "C:\\work",
    "provision filesystem serialized");
Check(provisionEnvelope["network"]?["egress"]?["default"]?.GetValue<string>() == "allow",
    "provision directional egress enum serialized");
Check(provisionEnvelope["telemetry"]?["enabled"]?.GetValue<bool>() == true, "provision telemetry serialized");

var execEnvelope = MxcLifecycle.BuildExecEnvelope(
    new SandboxId("wslc:smoke-test"),
    "echo hello",
    new WslcExecOptions
    {
        Environment = new List<string> { "FOO=bar" },
        RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" },
        Telemetry = new TelemetrySettings { Enabled = true },
    });
Check(execEnvelope["phase"]?.GetValue<string>() == "exec", "exec phase");
Check(execEnvelope["sandboxId"]?.GetValue<string>() == "wslc:smoke-test", "exec sandbox id");
Check(execEnvelope["process"]?["commandLine"]?.GetValue<string>() == "echo hello", "exec command line");
Check(execEnvelope["process"]?["env"]?[0]?.GetValue<string>() == "FOO=bar", "exec environment serialized");
Check(execEnvelope["runtimeConfig"]?["networkProxy"]?.GetValue<string>() == "http://127.0.0.1:8080",
    "exec runtime config serialized");

// An id-only phase (start/stop/deprovision share this envelope shape).
var startEnvelope = MxcLifecycle.BuildStartEnvelope(
    new SandboxId("iso:smoke-test"),
    new StateAwarePhaseOptions { Telemetry = new TelemetrySettings { Enabled = true } });
Check(startEnvelope["phase"]?.GetValue<string>() == "start", "start phase");
Check(startEnvelope["sandboxId"]?.GetValue<string>() == "iso:smoke-test", "start sandbox id");
Check(startEnvelope["telemetry"]?["enabled"]?.GetValue<bool>() == true, "start telemetry serialized");

// 9. Deserialize IsolationSession provision metadata - the remaining native
//     provision-output root.
const string provisionMetadataJson =
    """{"agentUserName":"sandbox-agent","agentUserSid":"S-1-5-21","ephemeralWorkspacePath":"C:\\ws"}""";
var provisionMetadata = MxcJson.Deserialize<IsolationSessionProvisionMetadata>(provisionMetadataJson);
Check(provisionMetadata?.AgentUserName == "sandbox-agent", "provision metadata agent user parsed");
Check(provisionMetadata!.EphemeralWorkspacePath == "C:\\ws", "provision metadata workspace parsed");

// 10. Parse a native request-probe output. This exercises the NativeProbeOutput
//     root and MxcJson.ProbeOptions (strict unmapped-member handling), the
//     deserialize path added with the request-aware probe.
const string probeJson = """
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
var probe = MxcSandbox.ParseProbeOutput(probeJson);
Check(probe.Tier == IsolationTier.AppContainerDacl, "probe tier parsed");
Check(probe.NeedsDaclAugmentation == true, "probe dacl augmentation parsed");
Check(probe.Probes.BaseContainerApiPresent, "probe facts parsed");
Check(probe.Probes.UiCapabilities.CanBlockClipboardRead, "probe ui capabilities parsed");

Console.WriteLine("AOT smoke test passed: all JSON paths are reflection-free.");
