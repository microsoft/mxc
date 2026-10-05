// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// Drives an IsolationSession or WSLC container through provision, start, execution,
/// stop, and deprovision. Windows Sandbox lifecycle requests are available only
/// through raw exact 1.1.0-alpha requests.
/// </summary>
public static class MxcLifecycle
{
    static MxcLifecycle()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>Exact contract owned by this v1 SDK.</summary>
    public const string SdkContractVersion = SchemaVersions.SdkContract;

    /// <summary>IsolationSession containment wire key.</summary>
    public const string IsolationSessionContainment = "isolation_session";

    /// <summary>WSLC containment wire key.</summary>
    public const string WslcContainment = "wslc";

    private const int ExperimentalOptIn = 1;
    private const int NoExperimentalOptIn = 0;

    /// <summary>Provision a new container.</summary>
    /// <exception cref="MxcException">Provisioning failed.</exception>
    public static ProvisionResult ProvisionContainer(
        ProvisionRequest request,
        ProvisionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var containment = request.Containment;
        var result = RunEnvelopePhase(
            BuildProvisionEnvelope(containment, request, options?.Telemetry),
            dryRun: false,
            experimental: options?.Experimental == true)
            ?? throw new MxcException(
                ErrorCode.BackendError,
                "provision response carried no result object");
        return ParseProvisionResult(containment, result);
    }

    internal static ProvisionResult ParseProvisionResult(
        LifecycleContainmentKind containment,
        JsonObject result)
    {
        if (result["sandboxId"] is not JsonValue identity
            || !identity.TryGetValue<string>(out var sandboxId) || sandboxId is null)
        {
            throw new MxcException(
                ErrorCode.BackendError,
                "provision response carried no sandboxId");
        }
        var metadata = result["metadata"];
        var metadataJson = metadata?.ToJsonString();
        ProvisionMetadata? parsedMetadata = null;
        if (metadataJson is not null)
        {
            if (containment != LifecycleContainmentKind.IsolationSession)
            {
                throw new MxcException(ErrorCode.BackendError,
                    $"provision response carried unsupported metadata for {containment}");
            }
            IsolationSessionProvisionMetadata? isolation;
            try
            {
                isolation = MxcJson.Deserialize<IsolationSessionProvisionMetadata>(metadataJson);
            }
            catch (JsonException error)
            {
                throw new MxcException(ErrorCode.BackendError,
                    $"provision response carried malformed IsolationSession metadata: {error.Message}");
            }
            if (isolation is null || isolation.AgentUserName is null
                || isolation.AgentUserSid is null || isolation.EphemeralWorkspacePath is null)
            {
                throw new MxcException(ErrorCode.BackendError,
                    "provision response carried incomplete IsolationSession metadata");
            }
            parsedMetadata = isolation;
        }
        return new ProvisionResult
        {
            ContainerId = new ContainerId(sandboxId),
            Metadata = parsedMetadata,
            Warnings = ParseLifecycleResult(result).Warnings,
        };
    }

    /// <summary>
    /// Parse and validate a provision request without allocating a container.
    /// </summary>
    public static ValidationResult ValidateProvision(
        ProvisionRequest request,
        ProvisionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ParseValidationResult(RunEnvelopePhase(
            BuildProvisionEnvelope(request.Containment, request, options?.Telemetry),
            dryRun: true,
            experimental: options?.Experimental == true));
    }

    internal static JsonObject BuildProvisionEnvelope(
        LifecycleContainmentKind containment,
        ProvisionRequest? options,
        TelemetryConfig? telemetry = null)
    {
        ValidateProvisionOptions(containment, options);
        var backend = ContainmentKey(containment);
        var envelope = NewEnvelope("provision");
        envelope["containment"] = backend;

        switch (options)
        {
            case IsolationSessionProvisionRequest isolation:
                SetCrossCuttingPolicies(envelope, null, isolation.Network);
                SetOptionalBackendConfig(
                    envelope,
                    backend,
                    "provision",
                    "appId",
                    isolation.AppId);
                break;
            case WslcProvisionRequest wslc:
                SetCrossCuttingPolicies(envelope, wslc.Filesystem, wslc.Network);
                SetOptionalBackendConfig(
                    envelope,
                    backend,
                    "provision",
                    "image",
                    wslc.Image);
                SetOptionalBackendConfig(
                    envelope,
                    backend,
                    "provision",
                    "imageTarPath",
                    wslc.ImageTarPath);
                break;
        }

        ApplyTelemetry(envelope, telemetry ?? options?.Telemetry);

        return envelope;
    }

    /// <summary>Start a provisioned container.</summary>
    public static LifecycleResult StartContainer(ContainerId id, StartOptions? options = null)
    {
        return ParseLifecycleResult(RunEnvelopePhase(BuildStartEnvelope(id, options), dryRun: false,
            experimental: options?.Experimental == true));
    }

    /// <summary>Validate a start request without starting the container.</summary>
    public static ValidationResult ValidateStart(ContainerId id, StartOptions? options = null)
    {
        return ParseValidationResult(RunEnvelopePhase(BuildStartEnvelope(id, options), dryRun: true,
            experimental: options?.Experimental == true));
    }

    internal static JsonObject BuildStartEnvelope(
        ContainerId id,
        StartOptions? options = null)
    {
        var envelope = BuildIdEnvelope("start", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    /// <summary>
    /// Run a command in a started container and return live stdio streams.
    /// IsolationSession and WSLC support this streaming form. Windows Sandbox
    /// lifecycle requests are available only through raw exact 1.1.0-alpha
    /// requests.
    /// </summary>
    public static MxcProcess SpawnInContainer(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var requestJson = BuildExecEnvelope(id, request, options?.Telemetry).ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_exec_state_aware_json(
                    requestPtr, options?.Experimental == true ? 1 : 0, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(status, error, "unknown error");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }
                return new MxcProcess(
                    MxcSandboxHandle.FromRaw(handle),
                    MxcProcess.NormalizeTimeout(request.TimeoutMs));
            }
        }
    }

    /// <summary>Spawn a command asynchronously and return live stdio streams.</summary>
    public static Task<MxcProcess> SpawnInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null,
        CancellationToken cancellationToken = default) =>
        RunBlockingOperationAsync(
            () => SpawnInContainer(id, request, options),
            lateProc => lateProc.Dispose(),
            cancellationToken);

    /// <summary>
    /// Run a command in a started container and attach it to a caller-resized PTY.
    /// </summary>
    public static MxcPtyProcess SpawnInContainerWithPty(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerWithPtyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var terminalSize = MxcPtySize.ResolveInitial(options?.Size);
        terminalSize.Validate(nameof(options));
        var requestBuf = ToNullTerminatedUtf8(
            BuildExecEnvelope(id, request, options?.Telemetry).ToJsonString());

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec_pty(
                    requestPtr,
                    options?.Experimental == true ? 1 : 0,
                    terminalSize.Rows,
                    terminalSize.Columns,
                    &handle,
                    &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(
                            status,
                            error,
                            "spawning process with PTY failed");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }

                return new MxcPtyProcess(
                    MxcSandboxHandle.FromRaw(handle),
                    MxcProcess.NormalizeTimeout(request.TimeoutMs));
            }
        }
    }

    /// <summary>
    /// Validate an execution request without starting a process.
    /// </summary>
    public static ValidationResult ValidateProcess(
        ContainerId id,
        ExecutionRequest request,
        SpawnInContainerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ParseValidationResult(RunEnvelopePhase(
            BuildExecEnvelope(id, request, options?.Telemetry),
            dryRun: true,
            experimental: options?.Experimental == true));
    }

    internal static JsonObject BuildExecEnvelope(
        ContainerId id,
        ExecutionRequest request,
        TelemetryConfig? telemetry = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateExecOptions(id, request);
        var envelope = BuildIdEnvelope("exec", id);
        var process = new JsonObject { ["commandLine"] = request.Command };
        if (request.WorkingDirectory is { } cwd)
        {
            process["cwd"] = cwd;
        }
        if (request.Environment is { } env)
        {
            process["env"] = SerializeToNode(ExactOneShotRequestWriter.Environment(env));
        }
        if (request.InheritDefaultEnvironment is { } inheritDefaultEnv)
        {
            process["inheritDefaultEnv"] = inheritDefaultEnv;
        }
        if (request.TimeoutMs is { } timeout)
        {
            process["timeout"] = timeout;
        }
        envelope["process"] = process;
        var runtimeConfig = request.Network?.RuntimeConfig;
        if (runtimeConfig is not null)
        {
            envelope["runtimeConfig"] = SerializeToNode(runtimeConfig);
        }
        ApplyTelemetry(envelope, telemetry ?? request.Telemetry);
        return envelope;
    }

    /// <summary>Run an execution request to completion and capture its output.</summary>
    public static async Task<ExecutionResult> RunInContainerAsync(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var proc = await SpawnInContainerAsync(
            id,
            request,
            new SpawnInContainerOptions
            {
                Experimental = options?.Experimental == true,
                Telemetry = options?.Telemetry,
            },
            cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var (result, stdout, stderr) = await proc
                .WaitForExitWithOutputAsync(cancellationToken)
                .ConfigureAwait(false);
            return new ExecutionResult
            {
                ExitCode = result.ExitCode,
                TimedOut = result.TimedOut,
                Stdout = Encoding.UTF8.GetString(stdout),
                Stderr = Encoding.UTF8.GetString(stderr),
                OutputMetadata = proc.OutputMetadata,
                Warnings = proc.Warnings,
            };
        }
        finally
        {
            proc.Dispose();
        }
    }

    /// <summary>Run an <see cref="ExecutionRequest"/> synchronously and capture its output.</summary>
    public static ExecutionResult RunInContainer(
        ContainerId id,
        ExecutionRequest request,
        RunInContainerOptions? options = null) =>
        RunInContainerAsync(id, request, options).GetAwaiter().GetResult();

    private static WaitResult ExecuteInContainerAttached(
        ContainerId id,
        ExecutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var requestBuf = ToNullTerminatedUtf8(BuildExecEnvelope(id, request).ToJsonString());

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcExecOutcome outcome = default;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_exec_state_aware_attached_json(
                    requestPtr,
                    ExperimentalOptInFor(id),
                    &outcome,
                    &error);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, error, "unknown error");
                    }

                    return new WaitResult
                    {
                        ExitCode = outcome.exit_code,
                        TimedOut = outcome.timed_out != 0,
                    };
                }
                finally
                {
                    NativeMethods.mxc_error_detail_free(&error);
                }
            }
        }
    }

    // Runs a synchronous blocking call on a background thread so it can be
    // awaited with cancellation. If the caller cancels while the operation is
    // still running the returned Task faults with an OperationCanceledException
    // immediately, but the background call is *not* aborted — it continues to
    // completion and, if it produced a resource the caller would otherwise own,
    // the late-result cleanup callback is invoked so the resource isn't leaked.
    internal static async Task<T> RunBlockingOperationAsync<T>(
        Func<T> operation,
        Action<T> disposeLateResult,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var task = Task.Run(operation, cancellationToken);
        try
        {
            return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = task.ContinueWith(
                t =>
                {
                    if (t.Status == TaskStatus.RanToCompletion)
                    {
                        try { disposeLateResult(t.Result); }
                        catch { /* best-effort cleanup */ }
                    }
                    else if (t.IsFaulted)
                    {
                        _ = t.Exception;
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>Stop a running container.</summary>
    public static LifecycleResult StopContainer(ContainerId id, StopOptions? options = null)
    {
        return ParseLifecycleResult(RunEnvelopePhase(BuildStopEnvelope(id, options), dryRun: false,
            experimental: options?.Experimental == true));
    }

    /// <summary>Validate a stop request without stopping the container.</summary>
    public static ValidationResult ValidateStop(ContainerId id, StopOptions? options = null)
    {
        return ParseValidationResult(RunEnvelopePhase(BuildStopEnvelope(id, options), dryRun: true,
            experimental: options?.Experimental == true));
    }

    internal static JsonObject BuildStopEnvelope(
        ContainerId id,
        StopOptions? options = null)
    {
        var envelope = BuildIdEnvelope("stop", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    /// <summary>Destroy a container and release its resources.</summary>
    public static LifecycleResult DeprovisionContainer(
        ContainerId id,
        DeprovisionOptions? options = null)
    {
        return ParseLifecycleResult(RunEnvelopePhase(BuildDeprovisionEnvelope(id, options), dryRun: false,
            experimental: options?.Experimental == true));
    }

    /// <summary>Validate a deprovision request without destroying the container.</summary>
    public static ValidationResult ValidateDeprovision(
        ContainerId id,
        DeprovisionOptions? options = null)
    {
        return ParseValidationResult(RunEnvelopePhase(BuildDeprovisionEnvelope(id, options), dryRun: true,
            experimental: options?.Experimental == true));
    }

    internal static ValidationResult ParseValidationResult(JsonObject? result)
    {
        return new ValidationResult { Warnings = ParseWarnings(result, "validation") };
    }

    internal static LifecycleResult ParseLifecycleResult(JsonObject? result)
    {
        return new LifecycleResult { Warnings = ParseWarnings(result, "lifecycle") };
    }

    private static string[] ParseWarnings(JsonObject? result, string operation)
    {
        if (result is null)
        {
            throw new MxcException(ErrorCode.BackendError,
                $"{operation} response carried no result object");
        }
        ValidationResult? validation;
        try
        {
            validation = MxcJson.Deserialize<ValidationResult>(result.ToJsonString());
        }
        catch (JsonException error)
        {
            throw new MxcException(ErrorCode.BackendError,
                $"{operation} response carried malformed warnings: {error.Message}");
        }
        if (validation?.Warnings is null || validation.Warnings.Any(warning => warning is null))
        {
            throw new MxcException(ErrorCode.BackendError,
                $"{operation} response carried malformed warnings");
        }
        return validation.Warnings;
    }

    internal static JsonObject BuildDeprovisionEnvelope(
        ContainerId id,
        DeprovisionOptions? options = null)
    {
        var envelope = BuildIdEnvelope("deprovision", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    private static JsonObject BuildIdEnvelope(string phase, ContainerId id)
    {
        ContainmentForId(id);
        var envelope = NewEnvelope(phase);
        envelope["sandboxId"] = id.Value;
        return envelope;
    }

    private static JsonObject NewEnvelope(string phase) => new()
    {
        ["version"] = SchemaVersions.SdkContract,
        ["phase"] = phase,
    };

    // Stable, top-level telemetry request for this phase. Consent and
    // administrative policy still gate emission independently. Never carries a
    // caller-supplied correlationVector — that identifier is internal-only.
    private static void ApplyTelemetry(
        JsonObject envelope,
        TelemetryConfig? telemetry)
    {
        if (telemetry is not null)
        {
            envelope["telemetry"] = SerializeToNode(telemetry);
        }
    }

    private static string ContainmentKey(LifecycleContainmentKind containment) => containment switch
    {
        LifecycleContainmentKind.IsolationSession => IsolationSessionContainment,
        LifecycleContainmentKind.Wslc => WslcContainment,
        _ => throw new MxcException(
            ErrorCode.UnsupportedContainment,
            $"unknown state-aware containment '{containment}'"),
    };

    private static void ValidateProvisionOptions(
        LifecycleContainmentKind containment,
        ProvisionRequest? options)
    {
        var valid = (containment, options) switch
        {
            (LifecycleContainmentKind.IsolationSession, null) => false,
            (_, null) => true,
            (LifecycleContainmentKind.IsolationSession, IsolationSessionProvisionRequest) => true,
            (LifecycleContainmentKind.Wslc, WslcProvisionRequest) => true,
            _ => false,
        };
        if (!valid)
        {
            throw new ArgumentException(
                options is null
                    ? $"{containment} requires backend-specific provision options"
                    : $"{options.GetType().Name} cannot configure {containment}",
                nameof(options));
        }
        if (options is IsolationSessionProvisionRequest isolation)
        {
            ValidateDirectionalNetwork(isolation.Network);
            if (isolation.Network.Egress?.Default != NetworkAction.Allow
                || isolation.Network.Egress.Allow is not null
                || isolation.Network.Egress.Deny is not null
                || isolation.Network.Ingress?.Default != NetworkAction.Allow
                || isolation.Network.Ingress.HostLoopback != NetworkAction.Allow)
            {
                throw new ArgumentException(
                    "IsolationSession requires directional egress, ingress, and host-loopback "
                        + "defaults set to Allow, with no rules.",
                    nameof(options));
            }
        }
        if (options is WslcProvisionRequest { Network: { } network })
        {
            ValidateDirectionalNetwork(network);
        }
    }

    private static void ValidateExecOptions(ContainerId id, ExecutionRequest? options)
    {
        var containment = ContainmentForId(id);
        var runtimeConfig = options?.Network?.RuntimeConfig;
        if (runtimeConfig is not null
            && containment != LifecycleContainmentKind.Wslc)
        {
            throw new ArgumentException(
                "network.runtimeConfig requires a wslc: container id",
                nameof(options));
        }
        if (runtimeConfig?.NetworkProxy is { } proxy
            && (string.IsNullOrWhiteSpace(proxy)
                || proxy.Trim() != proxy
                || !Uri.TryCreate(proxy, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)))
        {
            throw new ArgumentException(
                "network.runtimeConfig.networkProxy must be an HTTP/S URL string.",
                nameof(options));
        }
    }

    private static void ValidateDirectionalNetwork(NetworkPolicy network)
    {
        ArgumentNullException.ThrowIfNull(network);
    }

    private static LifecycleContainmentKind ContainmentForId(ContainerId id)
    {
        // Mirrors the native `parse_sandbox_id_prefix`, which folds a missing
        // `:` and an empty prefix into one MalformedId: both are structural,
        // not an unregistered backend. `default(ContainerId)` leaves Value null
        // and is handled here too, so it reports a typed error rather than
        // faulting on the IndexOf.
        var value = id.Value;
        var separator = value is null ? -1 : value.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0)
        {
            throw new MxcException(
                ErrorCode.MalformedId,
                $"container id '{id}' is missing the '<prefix>:...' form");
        }

        return value![..separator] switch
        {
            "iso" => LifecycleContainmentKind.IsolationSession,
            "wslc" => LifecycleContainmentKind.Wslc,
            "wsb" => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                "Windows Sandbox container ids with the 'wsb:' prefix require "
                    + "the raw exact 1.1.0-alpha state-aware executor route "
                    + "with explicit experimental authorization; stable MxcLifecycle "
                    + "accepts only 'iso:' and 'wslc:' ids."),
            _ => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                $"no state-aware backend is registered for container id '{id.Value}'"),
        };
    }

    private static void SetCrossCuttingPolicies(
        JsonObject envelope,
        FilesystemPolicy? filesystem,
        NetworkPolicy? network)
    {
        if (filesystem is not null)
        {
            envelope["filesystem"] = SerializeToNode(filesystem);
        }
        if (network is not null)
        {
            var networkNode = SerializeToNode(network)!.AsObject();
            networkNode.Remove("runtimeConfig");
            envelope["network"] = networkNode;
            if (network.RuntimeConfig is not null)
            {
                envelope["runtimeConfig"] = SerializeToNode(network.RuntimeConfig);
            }
        }
    }

    private static void SetOptionalBackendConfig(
        JsonObject envelope,
        string backend,
        string phase,
        string key,
        string? value)
    {
        if (value is not null)
        {
            SetBackendConfig(envelope, backend, phase, key, value);
        }
    }

    private static void SetBackendConfig(
        JsonObject envelope,
        string backend,
        string phase,
        string key,
        JsonNode? value)
    {
        var section = backend switch
        {
            IsolationSessionContainment => "isolationSession",
            WslcContainment => "wslc",
            _ => throw new ArgumentException($"Unsupported state-aware backend '{backend}'.", nameof(backend)),
        };
        if (envelope[section] is not JsonObject backendConfig)
        {
            backendConfig = new JsonObject();
            envelope[section] = backendConfig;
        }
        if (backendConfig[phase] is not JsonObject phaseConfig)
        {
            phaseConfig = new JsonObject();
            backendConfig[phase] = phaseConfig;
        }
        phaseConfig[key] = value;
    }

    private static JsonObject? RunEnvelopePhase(
        JsonObject envelope,
        bool dryRun,
        bool experimental = false)
    {
        var requestBuf = ToNullTerminatedUtf8(envelope.ToJsonString());

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcStateAwareResult result = default;
                var status = NativeMethods.mxc_run_state_aware_json(
                    requestPtr,
                    dryRun ? 1 : 0,
                    experimental ? ExperimentalOptIn : NoExperimentalOptIn,
                    &result);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, result.error, "unknown error");
                    }

                    var responseJson = PtrToString(result.response_json_utf8) ?? "{}";
                    var root = JsonNode.Parse(responseJson) as JsonObject;
                    return root?["result"] as JsonObject;
                }
                finally
                {
                    NativeMethods.mxc_state_aware_result_free(&result);
                }
            }
        }
    }

    private static int ExperimentalOptInFor(ContainerId id)
    {
        ContainmentForId(id);
        return NoExperimentalOptIn;
    }

    private static int ExperimentalOptInFor(JsonObject envelope)
    {
        if (envelope["containment"]?.GetValue<string>() is not null)
        {
            return NoExperimentalOptIn;
        }
        if (envelope["sandboxId"]?.GetValue<string>() is { } sandboxId)
        {
            return ExperimentalOptInFor(new ContainerId(sandboxId));
        }
        return NoExperimentalOptIn;
    }

    private static JsonNode? SerializeToNode<T>(T value) =>
        MxcJson.SerializeToNode(value, MxcJson.Options);

    private static byte[] ToNullTerminatedUtf8(string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var buffer = new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, 0);
        buffer[byteCount] = 0;
        return buffer;
    }

    private static unsafe string? PtrToString(byte* p) =>
        p is null ? null : System.Runtime.InteropServices.Marshal.PtrToStringUTF8((IntPtr)p);
}
