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
using System.Text.Encodings.Web;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

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
CheckRoundTrip(new Dev.JsonOptions { Experimental = true },
    x => x.Experimental, "dev JSON execution options");
CheckRoundTrip(new Dev.PolicyPreparationOptions { Experimental = true },
    x => x.Experimental, "policy preparation options");
const uint unknownResultVersion = Dev.PolicyFailureVersions.Result + 98;
const uint unknownMinimumReaderVersion = Dev.PolicyFailureVersions.MinimumReader + 97;
var policyFailures = new Dev.PolicyFailures
{
    Results =
    [
        new()
        {
            Version = unknownResultVersion,
            MinimumReaderVersion = unknownMinimumReaderVersion,
            Outcome = uint.MaxValue,
            Details =
            [
                new()
                {
                    FailureClass = uint.MaxValue,
                    FailureReason = Dev.PolicyFailureReasons.AccessExceedsCeiling,
                    RequiredAction = Dev.PolicyFailureActions.RestrictFilesystemAccess,
                    ResourceKind = Dev.PolicyFailureResourceKinds.Path,
                    ValueKind = Dev.PolicyFailureValueKinds.Access,
                    Flags = uint.MaxValue,
                    RequestedValue = ulong.MaxValue,
                    RequiredValue = 9_007_199_254_740_993,
                    Resource = "C:\\data\0",
                },
                new() { Resource = string.Empty },
                new(),
                new() { Resource = "C:\\data\\\u00e9" },
            ],
        },
        new() { Outcome = Dev.PolicyFailureOutcomes.EvaluationFailed },
    ],
};
var storedFailures = policyFailures.ToJson();
var restoredFailures = Dev.PolicyFailures.FromJson(storedFailures);
Check(restoredFailures.Results.Length == 2
    && restoredFailures.Results[0].Version == unknownResultVersion
    && restoredFailures.Results[0].MinimumReaderVersion == unknownMinimumReaderVersion
    && restoredFailures.Results[0].Outcome == uint.MaxValue
    && restoredFailures.Results[0].Details[0].RequestedValue == ulong.MaxValue
    && restoredFailures.Results[0].Details[0].RequiredValue == 9_007_199_254_740_993
    && restoredFailures.Results[0].Details[0].Resource == "C:\\data\0"
    && restoredFailures.Results[0].Details[1].Resource == string.Empty
    && restoredFailures.Results[0].Details[2].Resource is null
    && restoredFailures.Results[0].Details[3].Resource == "C:\\data\\\u00e9",
    "public policy-failure JSON helpers preserve batches, values, and resource presence");
try
{
    _ = new Dev.PolicyFailures
    {
        Results = [new() { Details = [new() { Resource = "\uD800" }] }],
    }.ToJson();
    Check(false, "policy-failure storage rejects a lone-surrogate resource string");
}
catch (JsonException)
{
}
CheckRoundTrip(policyFailures, x => x.ToJson() == storedFailures, "policy failures root");
CheckRoundTrip(policyFailures.Results[0],
    x => x.Version == unknownResultVersion && x.Details[0].RequestedValue == ulong.MaxValue,
    "native policy-result root");
CheckRoundTrip(policyFailures.Results[0].Details[0],
    x => x.Flags == uint.MaxValue && x.RequiredValue == 9_007_199_254_740_993, "native policy-detail root");
var mergedFailures = restoredFailures.MergedWith(Dev.PolicyFailures.FromJson(storedFailures));
Check(mergedFailures.ToJson() == storedFailures
    && !ReferenceEquals(mergedFailures.Results[0].Details[0],
        restoredFailures.Results[0].Details[0]),
    "public policy-failure merge deduplicates whole batches into owned storage");
Dev.PreparedPolicyRequest preparedPolicy;
using (var document = JsonDocument.Parse("""{"null":null,"value":{"large":18446744073709551615}}"""))
{
    var root = document.RootElement;
    preparedPolicy = new Dev.PreparedPolicyRequest
    {
        RequestJson = """{"version":"1.1.0-alpha","process":{"commandLine":"echo"}}""",
        Changes =
        [
            new()
            {
                Operation = Dev.PolicyChangeOperation.Add, Path = "/new",
                Before = root.GetProperty("null"), After = root.GetProperty("value"),
            },
            new()
            {
                Operation = Dev.PolicyChangeOperation.Remove, Path = "/old",
                Before = root.GetProperty("value"), After = root.GetProperty("null"),
            },
            new()
            {
                Operation = Dev.PolicyChangeOperation.Replace, Path = "/a~1b/~0field",
                Before = root.GetProperty("null"), After = root.GetProperty("null"),
            },
        ],
    };
}
var storedPreparation = preparedPolicy.ToJson();
Check(Dev.PreparedPolicyRequest.FromJson(storedPreparation).ToJson() == storedPreparation,
    "public prepared-policy storage retains owned JSON values and required null placeholders");
const string annotatedRequest = """ {"_comment":{"x":1,"x":2},"process":{"commandLine":"<>&'"}} """;
var annotatedStorage = "{\"requestJson\":\""
    + JsonEncodedText.Encode(annotatedRequest, JavaScriptEncoder.UnsafeRelaxedJsonEscaping)
    + "\",\"changes\":[]}";
var annotatedPreparation = Dev.PreparedPolicyRequest.FromJson(annotatedStorage);
Check(annotatedPreparation.ToJson() == annotatedStorage
    && annotatedPreparation.RequestJson == annotatedRequest,
    "preparation storage preserves arbitrary comment JSON text and compact escaping");
Check(MxcJson.Serialize("<", MxcJson.Options) == "\"\\u003C\"",
    "preparation storage leaves the shared SDK encoder unchanged");
foreach (var missingValue in new[]
{
    """{"requestJson":"{}","changes":[{"operation":"add","path":"/x","after":true}]}""",
    """{"requestJson":"{}","changes":[{"operation":"remove","path":"/x","before":true}]}""",
})
{
    try
    {
        _ = Dev.PreparedPolicyRequest.FromJson(missingValue);
        Check(false, "missing policy change values are rejected");
    }
    catch (JsonException error)
    {
        Check(error.InnerException is null, "missing policy change values have safe validation errors");
    }
}
CheckRoundTrip(preparedPolicy, x => x.ToJson() == storedPreparation, "prepared-policy request root");
CheckRoundTrip(preparedPolicy.Changes[0],
    x => x.Before.ValueKind == JsonValueKind.Null
        && x.After.GetProperty("large").GetUInt64() == ulong.MaxValue, "policy change root");
CheckRoundTrip(Dev.PolicyChangeOperation.Replace,
    x => x == Dev.PolicyChangeOperation.Replace, "policy change operation root");
using (var document = JsonDocument.Parse(storedPreparation))
{
    Check(document.RootElement.GetProperty("changes").EnumerateArray()
        .Select(change => change.GetProperty("operation").GetString())
        .SequenceEqual(["add", "remove", "replace"]), "lowercase policy change operations");
    Check(document.RootElement.GetProperty("changes").EnumerateArray()
        .All(change => change.TryGetProperty("before", out _) && change.TryGetProperty("after", out _)),
        "both policy change values are serialized even when JSON null");
}
var errorDetailsJson = $$$"""{"policyFailures":{{{storedFailures}}},"other":{"retained":true}}""";
CheckRoundTrip(MxcJson.Deserialize<JsonElement>(errorDetailsJson),
    x => x.GetProperty("other").GetProperty("retained").GetBoolean(), "generic backend error details");
MxcException policyError;
using (var document = JsonDocument.Parse(errorDetailsJson))
{
    const string accessDeniedHResult = "0x80070005";
    policyError = new MxcException(ErrorCode.BackendError, "creation refused",
        "PSEC.Create", accessDeniedHResult, null, document.RootElement);
}
Check(Dev.PolicyFailures.FromException(policyError)?.ToJson() == storedFailures
    && policyError.Details!.Value.GetProperty("other").GetProperty("retained").GetBoolean()
    && policyError.Message == "creation refused",
    "public policy-failure extraction retains generic details independently of the original document");
CheckRoundTrip(new Dev.PtyJsonOptions(),
    x => !x.Experimental && x.Size is null, "dev PTY options without initial dimensions");
CheckRoundTrip(new Dev.PtyJsonOptions { Experimental = true, Size = initialPtySize },
    x => x.Experimental && x.Size == initialPtySize,
    "dev PTY options experimental authorization and initial dimensions");
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
  {"backend":"lxc"},
  {"backend":"microvm"}
]
""";
var backends = MxcJson.Deserialize<NativeAvailableBackend[]>(backendsJson);
Check(backends is { Length: 3 }, "three backends parsed");
Check(backends![0].Capabilities.Length == 1, "first backend capability parsed");
Check(backends[1].Capabilities.Length == 0, "omitted capabilities default to empty, not null");
Check(backends[1].Warnings.Length == 0, "omitted warnings default to empty, not null");
var publicBackends = MxcPlatform.ParseAvailableBackends(backendsJson);
Check(publicBackends.Count == 3, "root discovery facade parses all backends");
Check(publicBackends[1].Backend == ContainmentBackend.Lxc, "root discovery maps LXC");
Check(publicBackends[2].Backend == ContainmentBackend.MicroVm, "root discovery maps NVX");
Check(publicBackends[2].Tier is null && publicBackends[2].Capabilities.Count == 0
    && publicBackends[2].Warnings.Count == 0, "NVX discovery preserves omitted optional fields");

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
    "baseContainerSupportsIngressHostLoopbackAllow": false,
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
var probe = MxcContainer.ParseProbeOutput(probeJson);
Check(probe.Tier == IsolationTier.AppContainerDacl, "probe tier parsed");
Check(probe.NeedsDaclAugmentation == true, "probe dacl augmentation parsed");
Check(probe.Probes.BaseContainerApiPresent, "probe facts parsed");
Check(probe.Probes.BaseContainerSupportsIdentitylessLoopbackProxy, "identity-less loopback proxy parsed");
Check(probe.Probes.UiCapabilities.CanBlockClipboardRead, "probe ui capabilities parsed");
var nativeProbe = MxcJson.Deserialize<NativeProbeOutput>(probeJson, MxcJson.ProbeOptions)!;
CheckRoundTrip(nativeProbe.Probes!,
    x => x.BaseContainerSupportsIdentitylessLoopbackProxy, "identity-less loopback proxy facts");
var discovery = MxcPlatform.ParseAvailableBackends(
    """[{"backend":"processcontainer","tier":"base-container","capabilities":["identitylessLoopbackProxy"]}]""");
Check(discovery.Single().Capabilities.SequenceEqual([BackendCapability.IdentitylessLoopbackProxy]),
    "identity-less loopback proxy discovery");

Console.WriteLine("AOT smoke test passed: all JSON paths are reflection-free.");
