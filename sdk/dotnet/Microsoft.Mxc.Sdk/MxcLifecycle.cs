// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Drives an IsolationSession, Windows Sandbox, or WSLC sandbox through
/// provision, start, exec, stop, and deprovision.
/// </summary>
public static class MxcLifecycle
{
    static MxcLifecycle()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>
    /// Default state-aware schema for IsolationSession and Windows Sandbox.
    /// </summary>
    public const string StateAwareVersion = SchemaVersions.StateAware;

    /// <summary>Default state-aware schema for WSLC.</summary>
    public const string WslcStateAwareVersion = SchemaVersions.WslcStateAware;

    /// <summary>IsolationSession containment wire key.</summary>
    public const string IsolationSessionContainment = "isolation_session";

    /// <summary>Windows Sandbox containment wire key.</summary>
    public const string WindowsSandboxContainment = "windows_sandbox";

    /// <summary>WSLC containment wire key.</summary>
    public const string WslcContainment = "wslc";

    private const int ExperimentalOptIn = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters =
        {
            new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
            new NetworkProxyPolicyJsonConverter(),
        },
    };

    /// <summary>Provision a new sandbox.</summary>
    /// <exception cref="MxcException">Provisioning failed.</exception>
    public static ProvisionResult ProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null)
    {
        var result = RunEnvelopePhase(BuildProvisionEnvelope(containment, options), dryRun: false)
            ?? throw new MxcException(
                ErrorCode.BackendError,
                "provision response carried no result object");
        var sandboxId = result["sandboxId"]?.GetValue<string>()
            ?? throw new MxcException(
                ErrorCode.BackendError,
                "provision response carried no sandboxId");
        var metadata = result["metadata"];
        var metadataJson = metadata?.ToJsonString();
        return new ProvisionResult
        {
            SandboxId = new SandboxId(sandboxId),
            MetadataJson = metadataJson,
            IsolationSessionMetadata =
                containment == StateAwareContainment.IsolationSession
                && metadataJson is not null
                    ? JsonSerializer.Deserialize<IsolationSessionProvisionMetadata>(
                        metadataJson,
                        JsonOptions)
                    : null,
        };
    }

    /// <summary>
    /// Parse and validate a provision request without allocating a sandbox.
    /// </summary>
    public static void DryRunProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null)
    {
        RunEnvelopePhase(BuildProvisionEnvelope(containment, options), dryRun: true);
    }

    internal static JsonObject BuildProvisionEnvelope(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options)
    {
        ValidateProvisionOptions(containment, options);
        var backend = ContainmentKey(containment);
        var envelope = NewEnvelope(
            "provision",
            options?.Version ?? DefaultVersion(containment));
        envelope["containment"] = backend;

        switch (options)
        {
            case IsolationSessionProvisionOptions isolation:
                envelope["network"] = SerializeToNode(isolation.Network);
                SetOptionalBackendConfig(
                    envelope,
                    backend,
                    "provision",
                    "appId",
                    isolation.AppId);
                break;
            case ProvisionSandboxOptions legacy:
                SetCrossCuttingPolicies(envelope, legacy.Filesystem, legacy.Network);
                SetOptionalBackendConfig(
                    envelope,
                    backend,
                    "provision",
                    "appId",
                    legacy.AppId);
                break;
            case WindowsSandboxProvisionOptions windowsSandbox:
                SetCrossCuttingPolicies(envelope, windowsSandbox.Filesystem, network: null);
                break;
            case WslcProvisionOptions wslc:
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

        ApplyTelemetry(envelope, options?.Telemetry, options?.Version);

        return envelope;
    }

    /// <summary>Start a provisioned sandbox.</summary>
    public static void StartSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildStartEnvelope(id, options), dryRun: false);
    }

    /// <summary>Validate a start request without starting the sandbox.</summary>
    public static void DryRunStartSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildStartEnvelope(id, options), dryRun: true);
    }

    internal static JsonObject BuildStartEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("start", options);
        var envelope = BuildIdEnvelope("start", id, options?.Version);
        ApplyTelemetry(envelope, options?.Telemetry, options?.Version);
        return envelope;
    }

    /// <summary>
    /// Run a command in a started sandbox and return live stdio streams.
    /// Windows Sandbox and WSLC currently support attached exec and exec
    /// dry-run, but not this streaming form.
    /// </summary>
    public static MxcSandboxProcess ExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        var requestJson = BuildExecEnvelope(id, command, options).ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec(
                    requestPtr, ExperimentalOptIn, &handle, &error);
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
                return new MxcSandboxProcess(
                    MxcSandboxHandle.FromRaw(handle),
                    MxcSandboxProcess.NormalizeTimeout(options?.TimeoutMs));
            }
        }
    }

    /// <summary>
    /// Run a command attached to this process's terminal and wait for it.
    /// </summary>
    public static SandboxWaitResult ExecInSandboxAttached(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        var requestJson = BuildExecEnvelope(id, command, options).ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcExecOutcome outcome = default;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec_attached(
                    requestPtr, ExperimentalOptIn, &outcome, &error);
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
                return new SandboxWaitResult
                {
                    ExitCode = outcome.exit_code,
                    TimedOut = outcome.timed_out != 0,
                };
            }
        }
    }

    /// <summary>
    /// Validate an exec request without starting a process.
    /// </summary>
    public static void DryRunExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        RunEnvelopePhase(BuildExecEnvelope(id, command, options), dryRun: true);
    }

    internal static JsonObject BuildExecEnvelope(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateExecOptions(id, options);
        var envelope = BuildIdEnvelope("exec", id, options?.Version);
        var process = new JsonObject { ["commandLine"] = command };
        if (options?.WorkingDirectory is { } cwd)
        {
            process["cwd"] = cwd;
        }
        if (options?.Environment is { } env)
        {
            process["env"] = SerializeToNode(env);
        }
        if (options?.TimeoutMs is { } timeout)
        {
            process["timeout"] = timeout;
        }
        envelope["process"] = process;
        if (options is WslcExecOptions { Network: { } network })
        {
            envelope["network"] = SerializeToNode(network);
        }
        ApplyTelemetry(envelope, options?.Telemetry, options?.Version);
        return envelope;
    }

    /// <summary>Run a command to completion and capture its output.</summary>
    public static Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        CancellationToken cancellationToken = default) =>
        ExecInSandboxAsync(id, command, options: null, cancellationToken);

    /// <summary>
    /// Run a command with process options to completion and capture its output.
    /// </summary>
    public static async Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        StateAwareExecOptions? options,
        CancellationToken cancellationToken = default)
    {
        var proc = await RunBlockingOperationAsync(
                () => ExecInSandbox(id, command, options),
                lateProc => lateProc.Dispose(),
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var (result, stdout, stderr) = await proc
                .WaitForExitWithOutputAsync(cancellationToken)
                .ConfigureAwait(false);
            return new RunResult
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
        var task = Task.Run(operation, CancellationToken.None);
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

    /// <summary>Stop a running sandbox.</summary>
    public static void StopSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildStopEnvelope(id, options), dryRun: false);
    }

    /// <summary>Validate a stop request without stopping the sandbox.</summary>
    public static void DryRunStopSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildStopEnvelope(id, options), dryRun: true);
    }

    internal static JsonObject BuildStopEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("stop", options);
        var envelope = BuildIdEnvelope("stop", id, options?.Version);
        ApplyTelemetry(envelope, options?.Telemetry, options?.Version);
        return envelope;
    }

    /// <summary>Destroy a sandbox and release its resources.</summary>
    public static void DeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildDeprovisionEnvelope(id, options), dryRun: false);
    }

    /// <summary>Validate a deprovision request without destroying the sandbox.</summary>
    public static void DryRunDeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        RunEnvelopePhase(BuildDeprovisionEnvelope(id, options), dryRun: true);
    }

    internal static JsonObject BuildDeprovisionEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("deprovision", options);
        var envelope = BuildIdEnvelope("deprovision", id, options?.Version);
        ApplyTelemetry(envelope, options?.Telemetry, options?.Version);
        return envelope;
    }

    private static void ValidateNonExecOptions(
        string phase,
        StateAwarePhaseOptions? options)
    {
        if (options is StateAwareExecOptions)
        {
            throw new ArgumentException(
                $"{options.GetType().Name} cannot configure the {phase} phase; "
                    + $"use {nameof(StateAwarePhaseOptions)}.",
                nameof(options));
        }
    }

    private static JsonObject BuildIdEnvelope(
        string phase,
        SandboxId id,
        string? version)
    {
        var containment = ContainmentForId(id);
        var envelope = NewEnvelope(
            phase,
            version ?? DefaultVersion(containment));
        envelope["sandboxId"] = id.Value;
        return envelope;
    }

    private static JsonObject NewEnvelope(string phase, string version) => new()
    {
        ["version"] = version,
        ["phase"] = phase,
    };

    // Stable, top-level telemetry request for this phase. Consent and
    // administrative policy still gate emission independently. Never carries a
    // caller-supplied correlationVector — that identifier is internal-only.
    private static void ApplyTelemetry(
        JsonObject envelope,
        TelemetrySettings? telemetry,
        string? suppliedVersion)
    {
        if (telemetry is not null)
        {
            if (suppliedVersion is null)
            {
                envelope["version"] = SchemaVersions.MaximumSupported;
            }
            envelope["telemetry"] = SerializeToNode(telemetry);
        }
    }

    private static string ContainmentKey(StateAwareContainment containment) => containment switch
    {
        StateAwareContainment.IsolationSession => IsolationSessionContainment,
        StateAwareContainment.WindowsSandbox => WindowsSandboxContainment,
        StateAwareContainment.Wslc => WslcContainment,
        _ => throw new MxcException(
            ErrorCode.UnsupportedContainment,
            $"unknown state-aware containment '{containment}'"),
    };

    private static string DefaultVersion(StateAwareContainment containment) =>
        containment == StateAwareContainment.Wslc
            ? WslcStateAwareVersion
            : StateAwareVersion;

    private static void ValidateProvisionOptions(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options)
    {
        var valid = (containment, options) switch
        {
            (StateAwareContainment.IsolationSession, null) => false,
            (_, null) => true,
            (StateAwareContainment.IsolationSession, IsolationSessionProvisionOptions) => true,
            (StateAwareContainment.IsolationSession, ProvisionSandboxOptions) => true,
            (StateAwareContainment.WindowsSandbox, WindowsSandboxProvisionOptions) => true,
            (StateAwareContainment.Wslc, WslcProvisionOptions) => true,
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
        if (options is IsolationSessionProvisionOptions isolation)
        {
            IsolationSessionProvisionOptions.ValidateNetwork(
                isolation.Network,
                nameof(options));
        }
    }

    private static void ValidateExecOptions(SandboxId id, StateAwareExecOptions? options)
    {
        var containment = ContainmentForId(id);
        if (options is WslcExecOptions
            && containment != StateAwareContainment.Wslc)
        {
            throw new ArgumentException(
                $"{nameof(WslcExecOptions)} requires a wslc: sandbox id",
                nameof(options));
        }
    }

    private static StateAwareContainment ContainmentForId(SandboxId id)
    {
        // Mirrors the native `parse_sandbox_id_prefix`, which folds a missing
        // `:` and an empty prefix into one MalformedId: both are structural,
        // not an unregistered backend. `default(SandboxId)` leaves Value null
        // and is handled here too, so it reports a typed error rather than
        // faulting on the IndexOf.
        var value = id.Value;
        var separator = value is null ? -1 : value.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0)
        {
            throw new MxcException(
                ErrorCode.MalformedId,
                $"sandbox id '{id}' is missing the '<prefix>:...' form");
        }

        return value![..separator] switch
        {
            "iso" => StateAwareContainment.IsolationSession,
            "wsb" => StateAwareContainment.WindowsSandbox,
            "wslc" => StateAwareContainment.Wslc,
            _ => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                $"no state-aware backend is registered for sandbox id '{id.Value}'"),
        };
    }

    private static void SetCrossCuttingPolicies(
        JsonObject envelope,
        StateAwareFilesystemPolicy? filesystem,
        StateAwareNetworkPolicy? network)
    {
        if (filesystem is not null)
        {
            envelope["filesystem"] = SerializeToNode(filesystem);
        }
        if (network is not null)
        {
            envelope["network"] = SerializeToNode(network);
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
        if (envelope["experimental"] is not JsonObject experimental)
        {
            experimental = new JsonObject();
            envelope["experimental"] = experimental;
        }
        if (experimental[backend] is not JsonObject backendConfig)
        {
            backendConfig = new JsonObject();
            experimental[backend] = backendConfig;
        }
        if (backendConfig[phase] is not JsonObject phaseConfig)
        {
            phaseConfig = new JsonObject();
            backendConfig[phase] = phaseConfig;
        }
        phaseConfig[key] = value;
    }

    private static JsonObject? RunEnvelopePhase(JsonObject envelope, bool dryRun)
    {
        var requestBuf = ToNullTerminatedUtf8(envelope.ToJsonString());

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcStateAwareResult result = default;
                var status = NativeMethods.mxc_state_aware(
                    requestPtr,
                    dryRun ? 1 : 0,
                    ExperimentalOptIn,
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

    private static JsonNode? SerializeToNode<T>(T value) =>
        JsonSerializer.SerializeToNode(value, JsonOptions);

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
