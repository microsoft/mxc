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

static void CheckRoundTrip<T>(T value, Func<T, bool> check, string name)
{
    var restored = MxcJson.Deserialize<T>(MxcJson.Serialize(value, MxcJson.Options));
    Check(restored is not null && check(restored), name);
}

var initialPtySize = new MxcPtySize(40, 120);
CheckRoundTrip(new TelemetryConfig(), x => x.Enabled is null, "omitted telemetry enabled");
CheckRoundTrip(new TelemetryConfig { Enabled = false }, x => x.Enabled == false, "explicit disabled telemetry");
foreach (var enabled in new bool?[] { null, true, false })
{
    var telemetry = enabled.HasValue ? new TelemetryConfig { Enabled = enabled.Value } : null;
    CheckRoundTrip(new RunOptions { Telemetry = telemetry },
        x => x.Telemetry?.Enabled == enabled, "run options");
    CheckRoundTrip(new SpawnOptions { Telemetry = telemetry },
        x => x.Telemetry?.Enabled == enabled, "spawn options");
    CheckRoundTrip(
        new SpawnWithPtyOptions { Size = initialPtySize, Telemetry = telemetry },
        x => x.Size == initialPtySize && x.Telemetry?.Enabled == enabled,
        "PTY options, telemetry, and initial dimensions");
}
CheckRoundTrip(new ProvisionOptions(), x => x.Telemetry is null, "provision options");
CheckRoundTrip(new StartOptions(), x => x.Telemetry is null, "start options");
CheckRoundTrip(new StopOptions(), x => x.Telemetry is null, "stop options");
CheckRoundTrip(new DeprovisionOptions(), x => x.Telemetry is null, "deprovision options");
CheckRoundTrip(new SpawnInContainerOptions(), x => x.Telemetry is null, "container spawn options");
CheckRoundTrip(new RunInContainerOptions(), x => x.Telemetry is null, "container run options");
CheckRoundTrip(
    new SpawnInContainerWithPtyOptions { Size = initialPtySize },
    x => x.Size == initialPtySize,
    "container PTY options and initial dimensions");
CheckRoundTrip<ProvisionRequest>(
    new WslcProvisionRequest { Image = "alpine:latest" },
    x => x is WslcProvisionRequest { Image: "alpine:latest" }, "closed provision request");
CheckRoundTrip(new ExecutionRequest("echo hello") { TimeoutMs = 1000 },
    x => x.Command == "echo hello" && x.TimeoutMs == 1000, "process request");

// 1. Serialize a complete request with directional network, filesystem, and UI
//    sections, exercising the camelCase enum converters and exact V1 contract.
var request = new ContainerRequest("echo hello")
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
    Ui = new UiPolicy { Disable = false, Clipboard = ClipboardPolicy.Read },
    Containment = new Containment.ProcessContainer
    {
        Capabilities = { "internetClient" },
    },
};
using (var doc = JsonDocument.Parse(MxcJson.Serialize(request, MxcJson.Options)))
{
    var root = doc.RootElement;
    Check(!root.TryGetProperty("version", out _), "authoring request is version-free");
    Check(!root.TryGetProperty("experimental", out _), "authoring request cannot authorize experimental features");
    Check(!root.TryGetProperty("policy", out _), "aggregate policy envelope is absent");
    var network = root.GetProperty("network");
    Check(network.GetProperty("egress").GetProperty("default").GetString() == "deny", "egress default enum");
    Check(network.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString()
        == "http://127.0.0.1:8080", "runtime proxy");
    Check(root.GetProperty("ui").GetProperty("clipboard").GetString() == "read", "clipboard enum");

    var restored = MxcJson.Deserialize<ContainerRequest>(root.GetRawText());
    Check(restored?.Containment is Containment.ProcessContainer processContainer
        && processContainer.Capabilities.Contains("internetClient"),
        "request containment round-trips without reflection");
    Check(!root.GetProperty("containment").TryGetProperty("leastPrivilege", out _),
        "authoring request has no least-privilege option");
}

using (var doc = JsonDocument.Parse(MxcContainer.SerializeRequest(request)))
{
    var root = doc.RootElement;
    Check(root.GetProperty("version").GetString() == "1.0.0", "SDK-owned exact request version");
    Check(!root.TryGetProperty("policy", out _), "private policy envelope is absent");
    Check(!root.TryGetProperty("experimental", out _), "exact request cannot authorize experimental features");
    Check(root.GetProperty("process").GetProperty("commandLine").GetString() == "echo hello",
        "exact request command line");
    Check(root.GetProperty("network").GetProperty("egress").GetProperty("default").GetString() == "deny",
        "exact request carries directional policy");
    Check(root.GetProperty("runtimeConfig").GetProperty("networkProxy").GetString()
        == "http://127.0.0.1:8080", "exact runtime proxy");
    Check(root.GetProperty("ui").GetProperty("clipboard").GetString() == "read", "clipboard enum");
    Check(root.GetProperty("process").GetProperty("timeout").GetUInt32() == 5000,
        "request timeout");
    Check(root.GetProperty("containment").GetString() == "processcontainer", "exact containment discriminator");
    Check(!root.GetProperty("processContainer").GetProperty("leastPrivilege").GetBoolean(),
        "exact backend policy retains the SDK default");
}

Containment[] containments =
[
    new Containment.Process(),
    new Containment.ProcessContainer(),
    new Containment.Bubblewrap(),
    new Containment.Lxc { Distribution = "ubuntu", Release = "24.04" },
    new Containment.Seatbelt { GuiAccess = true },
    new Containment.Wslc { MemoryMb = 2048 },
    new Containment.IsolationSession(),
];
foreach (var containment in containments)
{
    var json = MxcJson.Serialize(containment, MxcJson.Options);
    var restored = MxcJson.Deserialize<Containment>(json);
    Check(restored is not null
        && MxcJson.Serialize(restored, MxcJson.Options) == json,
        "SDK containment configuration round-trips without reflection");
}

// The generated exact wire type must preserve the full unsigned WSLC bound.
var wslcRequest = new ContainerRequest("echo memory")
{
    Containment = new Containment.Wslc { MemoryMb = ulong.MaxValue },
};
using (var doc = JsonDocument.Parse(MxcContainer.SerializeRequest(wslcRequest)))
{
    Check(doc.RootElement.GetProperty("wslc").GetProperty("memoryMb").GetUInt64()
        == ulong.MaxValue, "full unsigned WSLC memory bound");
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
var metadata = MxcJson.Deserialize<ExecutionMetadata>(metadataJson);
Check(metadata?.CaptureDenials?.OutputPath == "C:\\out.json", "output metadata parsed");
Check(metadata!.CaptureDenials!.TotalDenials == 3, "denial count parsed");
Check(metadata.CaptureDenialsError?.Message == "finalize failed", "capture denials error parsed");
Check(metadata.CaptureDenialsError!.EtlPath == "C:\\trace.etl", "capture denials error etl path parsed");
CheckRoundTrip(metadata,
    x => x.CaptureDenials?.TotalDenials == 3 && x.CaptureDenialsError?.EtlPath == "C:\\trace.etl",
    "execution metadata");
CheckRoundTrip(metadata.CaptureDenials,
    x => x.OutputPath == "C:\\out.json" && x.TotalDenials == 3,
    "capture denials result");
CheckRoundTrip(metadata.CaptureDenialsError,
    x => x.Message == "finalize failed" && x.EtlPath == "C:\\trace.etl",
    "capture denials error");

// 6. Deserialize a warnings array (string[]).
var warnings = MxcJson.Deserialize<string[]>("""["a","b"]""");
Check(warnings is { Length: 2 }, "warnings array parsed");

// 7. Round-trip a state-aware network policy: exercises the non-null section
//    converter on the state-aware directional model.
var stateNetwork = MxcJson.Deserialize<NetworkPolicy>(
    """{"egress":{"default":"allow"},"ingress":{"default":"deny"}}""");
Check(stateNetwork?.Egress?.Default == NetworkAction.Allow, "state-aware network parsed");
JsonNode? stateNode = MxcJson.SerializeToNode(stateNetwork!, MxcJson.Options);
Check(stateNode?["egress"]?["default"]?.GetValue<string>() == "allow", "state-aware network round-trips");

var validationResult = MxcLifecycle.ParseValidationResult(
    JsonNode.Parse("""{"warnings":["policy warning"]}""")!.AsObject());
CheckRoundTrip(validationResult,
    static value => value.Warnings.SequenceEqual(["policy warning"]),
    "validation result");
Check(MxcLifecycle.ParseValidationResult(new JsonObject()).Warnings.Length == 0,
    "omitted validation warnings produce an empty collection");

// 8. Build the state-aware lifecycle envelopes through the real MxcLifecycle
//    builders. These are native-free (the P/Invoke lives in a separate step),
//    so publishing them here exercises the provision/exec serialization call
//    sites - filesystem, telemetry, directional network, environment, and
//    runtime config - under reflection-disabled execution, which the
//    run-to-completion path above does not cover.
var provisionEnvelope = MxcLifecycle.BuildProvisionEnvelope(
    LifecycleContainmentKind.Wslc,
    new WslcProvisionRequest
    {
        Filesystem = new FilesystemPolicy { ReadwritePaths = { "C:\\work" } },
        Network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
            Ingress = new NetworkIngressPolicy
            {
                Default = NetworkAction.Allow,
                HostLoopback = NetworkAction.Allow,
            },
        },
        Telemetry = new TelemetryConfig { Enabled = true },
    });
Check(provisionEnvelope["phase"]?.GetValue<string>() == "provision", "provision phase");
Check(provisionEnvelope["containment"]?.GetValue<string>() == "wslc", "provision containment");
Check(provisionEnvelope["filesystem"]?["readwritePaths"]?[0]?.GetValue<string>() == "C:\\work",
    "provision filesystem serialized");
Check(provisionEnvelope["network"]?["egress"]?["default"]?.GetValue<string>() == "allow",
    "provision directional egress enum serialized");
Check(provisionEnvelope["telemetry"]?["enabled"]?.GetValue<bool>() == true, "provision telemetry serialized");

var execEnvelope = MxcLifecycle.BuildExecEnvelope(
    new ContainerId("wslc:smoke-test"),
    new ExecutionRequest("echo hello")
    {
        Environment = new Dictionary<string, string> { ["FOO"] = "bar" },
        Network = new ProcessNetworkPolicy
        {
            RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" },
        },
        Telemetry = new TelemetryConfig { Enabled = true },
    });
Check(execEnvelope["phase"]?.GetValue<string>() == "exec", "exec phase");
Check(execEnvelope["sandboxId"]?.GetValue<string>() == "wslc:smoke-test", "exec sandbox id");
Check(execEnvelope["process"]?["commandLine"]?.GetValue<string>() == "echo hello", "exec command line");
Check(execEnvelope["process"]?["env"]?[0]?.GetValue<string>() == "FOO=bar", "exec environment serialized");
Check(execEnvelope["runtimeConfig"]?["networkProxy"]?.GetValue<string>() == "http://127.0.0.1:8080",
    "exec runtime config serialized");

var processNetwork = MxcJson.Deserialize<ProcessNetworkPolicy>(
    MxcJson.Serialize(new ProcessNetworkPolicy
    {
        RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8080" },
    }, MxcJson.Options));
Check(processNetwork?.RuntimeConfig?.NetworkProxy == "http://127.0.0.1:8080",
    "process network request round-trips without reflection");

// An id-only phase (start/stop/deprovision share this envelope shape).
var startEnvelope = MxcLifecycle.BuildStartEnvelope(
    new ContainerId("iso:smoke-test"),
    new StartOptions { Telemetry = new TelemetryConfig { Enabled = true } });
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
CheckRoundTrip<ProvisionMetadata>(
    provisionMetadata,
    x => x is IsolationSessionProvisionMetadata
    {
        AgentUserName: "sandbox-agent",
        AgentUserSid: "S-1-5-21",
        EphemeralWorkspacePath: "C:\\ws",
    },
    "polymorphic provision metadata");
var provisionResult = MxcLifecycle.ParseProvisionResult(
    LifecycleContainmentKind.IsolationSession,
    JsonNode.Parse($$"""{"sandboxId":"iso:metadata-smoke","metadata":{{provisionMetadataJson}}}""")!.AsObject());
Check(provisionResult.Metadata is IsolationSessionProvisionMetadata { AgentUserName: "sandbox-agent" },
    "native provision result maps to typed metadata");
CheckRoundTrip(new LifecycleResult { Warnings = ["cleanup warning"] },
    x => x.Warnings.SequenceEqual(["cleanup warning"]), "lifecycle result warnings");
CheckRoundTrip(new LifecycleResult(), x => x.Warnings.Length == 0, "empty lifecycle warnings");
CheckRoundTrip(provisionResult.ContainerId,
    x => x == provisionResult.ContainerId, "container identity");
CheckRoundTrip(new ProvisionResult
{
    ContainerId = provisionResult.ContainerId,
    Metadata = provisionResult.Metadata,
    Warnings = ["provision warning"],
}, x => x.ContainerId == provisionResult.ContainerId
    && x.Metadata is IsolationSessionProvisionMetadata { AgentUserName: "sandbox-agent" }
    && x.Warnings.SequenceEqual(["provision warning"]), "provision result identity metadata and warnings");

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
var probe = MxcContainer.ParseProbeOutput(probeJson);
Check(probe.Tier == IsolationTier.AppContainerDacl, "probe tier parsed");
Check(probe.NeedsDaclAugmentation == true, "probe dacl augmentation parsed");
Check(probe.Probes.BaseContainerApiPresent, "probe facts parsed");
Check(probe.Probes.UiCapabilities.CanBlockClipboardRead, "probe ui capabilities parsed");

Console.WriteLine("AOT smoke test passed: all JSON paths are reflection-free.");
