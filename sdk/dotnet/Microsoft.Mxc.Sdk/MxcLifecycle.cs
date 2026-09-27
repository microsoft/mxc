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

    /// <summary>Exact contract owned by this v1 SDK.</summary>
    public const string StateAwareVersion = SchemaVersions.SdkContract;

    /// <summary>IsolationSession containment wire key.</summary>
    public const string IsolationSessionContainment = "isolation_session";

    /// <summary>WSLC containment wire key.</summary>
    public const string WslcContainment = "wslc";

    private const int ExperimentalOptIn = 1;
    private const int NoExperimentalOptIn = 0;

    private enum LifecycleBackend
    {
        IsolationSession,
        Wslc,
        WindowsSandbox,
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters =
        {
            new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
        },
    };

    /// <summary>Provision a new sandbox.</summary>
    /// <exception cref="MxcException">Provisioning failed.</exception>
    public static ProvisionResult ProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null)
    {
        ValidateProvisionOptions(containment, options);
        using var marshaller = TypedRequestMarshaller.ForProvision(containment, options);
        var result = RunTypedPhase(marshaller, dryRun: false);
        var sandboxId = result.SandboxId
            ?? throw new MxcException(
                ErrorCode.BackendError,
                "provision response carried no sandboxId");
        return new ProvisionResult
        {
            SandboxId = new SandboxId(sandboxId),
            MetadataJson = result.MetadataJson,
            IsolationSessionMetadata = result.IsolationSessionMetadata,
        };
    }

    /// <summary>
    /// Parse and validate a provision request without allocating a sandbox.
    /// </summary>
    public static void DryRunProvisionSandbox(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options = null)
    {
        ValidateProvisionOptions(containment, options);
        using var marshaller = TypedRequestMarshaller.ForProvision(containment, options);
        RunTypedPhase(marshaller, dryRun: true);
    }

    internal static JsonObject BuildProvisionEnvelope(
        StateAwareContainment containment,
        StateAwareProvisionOptions? options)
    {
        ValidateProvisionOptions(containment, options);
        var backend = ContainmentKey(containment);
        var envelope = NewEnvelope("provision");
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

        ApplyTelemetry(envelope, options?.Telemetry);

        return envelope;
    }

    /// <summary>Start a provisioned sandbox.</summary>
    public static void StartSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(TypedRequestMarshaller.StateAwareStart, id, options, dryRun: false);
    }

    /// <summary>Validate a start request without starting the sandbox.</summary>
    public static void DryRunStartSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(TypedRequestMarshaller.StateAwareStart, id, options, dryRun: true);
    }

    internal static JsonObject BuildStartEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("start", options);
        var envelope = BuildIdEnvelope("start", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    /// <summary>
    /// Run a command in a started sandbox and return live stdio streams.
    /// IsolationSession and WSLC support this streaming form. Windows Sandbox
    /// currently supports attached exec and exec dry-run only.
    /// </summary>
    public static MxcSandboxProcess ExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateExecOptions(id, options);

        if (BackendForId(id) == LifecycleBackend.WindowsSandbox)
        {
            return ExecInSandboxJson(id, command, options);
        }

        using var marshaller = TypedRequestMarshaller.ForExec(id, command, options);

        unsafe
        {
            NativeSandbox* handle = null;
            MxcErrorDetail error = default;
            var status = NativeMethods.mxc_state_aware_exec_typed(
                marshaller.StateAwareRequest, &handle, &error);
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

    /// <summary>
    /// Run a command attached to this process's terminal and wait for it.
    /// </summary>
    public static SandboxWaitResult ExecInSandboxAttached(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateExecOptions(id, options);

        if (BackendForId(id) == LifecycleBackend.WindowsSandbox)
        {
            return ExecInSandboxAttachedJson(id, command, options);
        }

        using var marshaller = TypedRequestMarshaller.ForExec(id, command, options);

        unsafe
        {
            MxcExecOutcome outcome = default;
            MxcErrorDetail error = default;
            var status = NativeMethods.mxc_state_aware_exec_attached_typed(
                marshaller.StateAwareRequest, &outcome, &error);
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

    /// <summary>
    /// Validate an exec request without starting a process.
    /// </summary>
    public static void DryRunExecInSandbox(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateExecOptions(id, options);
        if (BackendForId(id) == LifecycleBackend.WindowsSandbox)
        {
            RunEnvelopePhase(BuildExecEnvelope(id, command, options), dryRun: true);
            return;
        }

        using var marshaller = TypedRequestMarshaller.ForExec(id, command, options);
        RunTypedPhase(marshaller, dryRun: true);
    }

    internal static JsonObject BuildExecEnvelope(
        SandboxId id,
        string command,
        StateAwareExecOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateExecOptions(id, options);
        var envelope = BuildIdEnvelope("exec", id);
        var process = new JsonObject { ["commandLine"] = command };
        if (options?.WorkingDirectory is { } cwd)
        {
            process["cwd"] = cwd;
        }
        if (options?.Environment is { } env)
        {
            process["env"] = SerializeToNode(env);
        }
        if (options?.InheritDefaultEnvironment is { } inheritDefaultEnv)
        {
            process["inheritDefaultEnv"] = inheritDefaultEnv;
        }
        if (options?.TimeoutMs is { } timeout)
        {
            process["timeout"] = timeout;
        }
        envelope["process"] = process;
        if (options is WslcExecOptions { RuntimeConfig: { } runtime })
        {
            envelope["runtimeConfig"] = SerializeToNode(runtime);
        }
        ApplyTelemetry(envelope, options?.Telemetry);
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

    /// <summary>Stop a running sandbox.</summary>
    public static void StopSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(TypedRequestMarshaller.StateAwareStop, id, options, dryRun: false);
    }

    /// <summary>Validate a stop request without stopping the sandbox.</summary>
    public static void DryRunStopSandbox(SandboxId id, StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(TypedRequestMarshaller.StateAwareStop, id, options, dryRun: true);
    }

    internal static JsonObject BuildStopEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("stop", options);
        var envelope = BuildIdEnvelope("stop", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    /// <summary>Destroy a sandbox and release its resources.</summary>
    public static void DeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(
            TypedRequestMarshaller.StateAwareDeprovision,
            id,
            options,
            dryRun: false);
    }

    /// <summary>Validate a deprovision request without destroying the sandbox.</summary>
    public static void DryRunDeprovisionSandbox(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        RunNonExecPhase(
            TypedRequestMarshaller.StateAwareDeprovision,
            id,
            options,
            dryRun: true);
    }

    internal static JsonObject BuildDeprovisionEnvelope(
        SandboxId id,
        StateAwarePhaseOptions? options = null)
    {
        ValidateNonExecOptions("deprovision", options);
        var envelope = BuildIdEnvelope("deprovision", id);
        ApplyTelemetry(envelope, options?.Telemetry);
        return envelope;
    }

    private static void ValidateNonExecOptions(
        string phase,
        StateAwarePhaseOptions? options)
    {
        if (options is WslcExecOptions wslc
            && wslc.RuntimeConfig is not null)
        {
            throw new ArgumentException(
                "Runtime proxy configuration is accepted only on WSLC exec, not start, stop or deprovision.",
                nameof(options));
        }
        if (options is StateAwareExecOptions)
        {
            throw new ArgumentException(
                $"{options.GetType().Name} cannot configure the {phase} phase; "
                    + $"use {nameof(StateAwarePhaseOptions)}.",
                nameof(options));
        }
    }

    private static JsonObject BuildIdEnvelope(string phase, SandboxId id)
    {
        var backend = BackendForId(id);
        var envelope = NewEnvelope(
            phase,
            backend == LifecycleBackend.WindowsSandbox
                ? SchemaVersions.MaximumSupported
                : StateAwareVersion);
        envelope["sandboxId"] = id.Value;
        return envelope;
    }

    private static JsonObject NewEnvelope(
        string phase,
        string version = StateAwareVersion) => new()
    {
        ["version"] = version,
        ["phase"] = phase,
    };

    // Stable, top-level telemetry request for this phase. Consent and
    // administrative policy still gate emission independently. Never carries a
    // caller-supplied correlationVector — that identifier is internal-only.
    private static void ApplyTelemetry(
        JsonObject envelope,
        TelemetrySettings? telemetry)
    {
        if (telemetry is not null)
        {
            envelope["telemetry"] = SerializeToNode(telemetry);
        }
    }

    private static string ContainmentKey(StateAwareContainment containment) => containment switch
    {
        StateAwareContainment.IsolationSession => IsolationSessionContainment,
        StateAwareContainment.Wslc => WslcContainment,
        _ => throw new MxcException(
            ErrorCode.UnsupportedContainment,
            $"unknown state-aware containment '{containment}'"),
    };

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
        if (options is ProvisionSandboxOptions)
        {
            throw new ArgumentException(
                "Schema 0.9 no longer accepts legacy IsolationSession network fields. "
                    + "Use IsolationSessionProvisionOptions with directional egress, ingress, "
                    + "and host-loopback defaults set to Allow.",
                nameof(options));
        }
        if (options is IsolationSessionProvisionOptions isolation)
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
        if (options is WslcProvisionOptions { Network: { } network })
        {
            ValidateDirectionalNetwork(network);
        }
    }

    private static void ValidateExecOptions(SandboxId id, StateAwareExecOptions? options)
    {
        var containment = BackendForId(id);
        if (options is WslcExecOptions
            && containment != LifecycleBackend.Wslc)
        {
            throw new ArgumentException(
                $"{nameof(WslcExecOptions)} requires a wslc: sandbox id",
                nameof(options));
        }
        if (options is WslcExecOptions wslc)
        {
            if (wslc.RuntimeConfig?.NetworkProxy is { } proxy
                && (string.IsNullOrWhiteSpace(proxy)
                    || proxy.Trim() != proxy
                    || !Uri.TryCreate(proxy, UriKind.Absolute, out var uri)
                    || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)))
            {
                throw new ArgumentException(
                    "runtimeConfig.networkProxy must be an HTTP/S URL string.",
                    nameof(options));
            }
        }
    }

    private static void ValidateDirectionalNetwork(StateAwareNetworkPolicy network)
    {
        ArgumentNullException.ThrowIfNull(network);
    }

    private static LifecycleBackend BackendForId(SandboxId id)
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
            "iso" => LifecycleBackend.IsolationSession,
            "wslc" => LifecycleBackend.Wslc,
            "wsb" => LifecycleBackend.WindowsSandbox,
            _ => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                $"no state-aware backend is registered for sandbox id '{id.Value}'"),
        };
    }

    private static StateAwareContainment ContainmentForId(SandboxId id)
    {
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
            "wslc" => StateAwareContainment.Wslc,
            _ => throw new MxcException(
                ErrorCode.UnsupportedContainment,
                $"no typed state-aware backend is registered for sandbox id '{id.Value}'"),
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

    private sealed record TypedLifecycleResult(
        string? SandboxId,
        string? MetadataJson,
        IsolationSessionProvisionMetadata? IsolationSessionMetadata,
        IReadOnlyList<string> Warnings);

    private static void RunNonExecPhase(
        int operation,
        SandboxId id,
        StateAwarePhaseOptions? options,
        bool dryRun)
    {
        ValidateNonExecOptions(OperationName(operation), options);
        if (BackendForId(id) == LifecycleBackend.WindowsSandbox)
        {
            RunEnvelopePhase(BuildEnvelopeForOperation(operation, id, options), dryRun);
            return;
        }

        using var marshaller = TypedRequestMarshaller.ForLifecycleId(operation, id, options);
        RunTypedPhase(marshaller, dryRun);
    }

    private static JsonObject BuildEnvelopeForOperation(
        int operation,
        SandboxId id,
        StateAwarePhaseOptions? options) => operation switch
        {
            TypedRequestMarshaller.StateAwareStart => BuildStartEnvelope(id, options),
            TypedRequestMarshaller.StateAwareStop => BuildStopEnvelope(id, options),
            TypedRequestMarshaller.StateAwareDeprovision => BuildDeprovisionEnvelope(id, options),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "unknown lifecycle operation"),
        };

    private static string OperationName(int operation) => operation switch
    {
        TypedRequestMarshaller.StateAwareStart => "start",
        TypedRequestMarshaller.StateAwareStop => "stop",
        TypedRequestMarshaller.StateAwareDeprovision => "deprovision",
        _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "unknown lifecycle operation"),
    };

    private static unsafe TypedLifecycleResult RunTypedPhase(
        TypedRequestMarshaller marshaller,
        bool dryRun)
    {
        MxcTypedStateAwareResult result = default;
        var status = NativeMethods.mxc_state_aware_typed(
            marshaller.StateAwareRequest,
            dryRun ? 1 : 0,
            &result);
        try
        {
            if (status != (int)ErrorCode.Success)
            {
                throw NativeError.ToException(status, result.error, "unknown error");
            }

            var warnings = DeserializeWarnings(PtrToString(result.warnings_json_utf8));
            var metadata = ParseTypedMetadata(result);
            return new TypedLifecycleResult(
                PtrToString(result.sandbox_id_utf8),
                metadata.Json,
                metadata.IsolationSession,
                warnings);
        }
        finally
        {
            NativeMethods.mxc_state_aware_typed_result_free(&result);
        }
    }

    internal static unsafe (string? Json, IsolationSessionProvisionMetadata? IsolationSession)
        ParseTypedMetadata(MxcTypedStateAwareResult result)
    {
        if (result.metadata_kind == TypedRequestMarshaller.ProvisionMetadataNone)
        {
            return (null, null);
        }
        if (result.metadata_kind != TypedRequestMarshaller.ProvisionMetadataIsolationSession)
        {
            throw new MxcException(
                ErrorCode.BackendError,
                $"typed lifecycle returned unsupported metadata kind {result.metadata_kind}");
        }

        var metadata = new IsolationSessionProvisionMetadata
        {
            AgentUserName = PtrToString(result.agent_user_name_utf8),
            AgentUserSid = PtrToString(result.agent_user_sid_utf8),
            EphemeralWorkspacePath = PtrToString(result.ephemeral_workspace_path_utf8),
        };
        return (JsonSerializer.Serialize(metadata, JsonOptions), metadata);
    }

    private static MxcSandboxProcess ExecInSandboxJson(
        SandboxId id,
        string command,
        StateAwareExecOptions? options)
    {
        var requestJson = BuildExecEnvelope(id, command, options).ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec_json(
                    requestPtr, ExperimentalOptInFor(id), &handle, &error);
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

    private static SandboxWaitResult ExecInSandboxAttachedJson(
        SandboxId id,
        string command,
        StateAwareExecOptions? options)
    {
        var requestJson = BuildExecEnvelope(id, command, options).ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcExecOutcome outcome = default;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec_attached_json(
                    requestPtr, ExperimentalOptInFor(id), &outcome, &error);
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

    private static JsonObject? RunEnvelopePhase(JsonObject envelope, bool dryRun)
    {
        var requestBuf = ToNullTerminatedUtf8(envelope.ToJsonString());

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcStateAwareResult result = default;
                var status = NativeMethods.mxc_state_aware_json(
                    requestPtr,
                    dryRun ? 1 : 0,
                    ExperimentalOptInFor(envelope),
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

    private static int ExperimentalOptInFor(SandboxId id)
    {
        return BackendForId(id) == LifecycleBackend.WindowsSandbox
            ? ExperimentalOptIn
            : NoExperimentalOptIn;
    }

    private static int ExperimentalOptInFor(JsonObject envelope)
    {
        if (envelope["containment"]?.GetValue<string>() is not null)
        {
            return NoExperimentalOptIn;
        }
        if (envelope["sandboxId"]?.GetValue<string>() is { } sandboxId)
        {
            return ExperimentalOptInFor(new SandboxId(sandboxId));
        }
        return NoExperimentalOptIn;
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

    private static IReadOnlyList<string> DeserializeWarnings(string? json) =>
        string.IsNullOrEmpty(json)
            ? Array.Empty<string>()
            : JsonSerializer.Deserialize<string[]>(json) ?? Array.Empty<string>();
}
