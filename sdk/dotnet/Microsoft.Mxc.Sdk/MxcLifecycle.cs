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
/// The state-aware sandbox lifecycle: drive a sandbox through
/// provision → start → exec → stop → deprovision. The envelope phases
/// (<see cref="ProvisionSandbox"/> / <see cref="StartSandbox"/> /
/// <see cref="StopSandbox"/> / <see cref="DeprovisionSandbox"/>) are
/// request/response; <see cref="ExecInSandbox"/> runs a command as a live
/// streaming <see cref="MxcSandboxProcess"/>.
/// </summary>
/// <remarks>
/// The only in-tree state-aware backend is IsolationSession (Windows-only,
/// experimental), which requires its OS-side service. On a host or build without
/// it, these calls surface an <see cref="MxcException"/> with
/// <see cref="ErrorCode.UnsupportedPhase"/> / <see cref="ErrorCode.BackendUnavailable"/>.
/// </remarks>
public static class MxcLifecycle
{
    static MxcLifecycle()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>The schema version state-aware lifecycle requests use.</summary>
    public const string StateAwareVersion = "0.6.0-alpha";

    /// <summary>The IsolationSession containment key (the only state-aware backend today).</summary>
    public const string IsolationSessionContainment = "isolation_session";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>
    /// Provision a new IsolationSession sandbox, returning its <see cref="SandboxId"/>.
    /// </summary>
    /// <exception cref="MxcException">Provisioning failed.</exception>
    public static ProvisionResult ProvisionSandbox(ProvisionSandboxOptions? options = null)
    {
        var result = RunEnvelopePhase(BuildProvisionEnvelope(options))
            ?? throw new MxcException(ErrorCode.BackendError, "provision response carried no result object");
        var sandboxId = result["sandboxId"]?.GetValue<string>()
            ?? throw new MxcException(ErrorCode.BackendError, "provision response carried no sandboxId");
        var metadata = result["metadata"];
        return new ProvisionResult
        {
            SandboxId = new SandboxId(sandboxId),
            MetadataJson = metadata?.ToJsonString(),
        };
    }

    // Build the provision request envelope: containment + cross-cutting
    // filesystem lifted to the top level, user nested under
    // experimental.isolation_session.provision.
    internal static JsonObject BuildProvisionEnvelope(ProvisionSandboxOptions? options)
    {
        var envelope = NewEnvelope("provision");
        envelope["containment"] = IsolationSessionContainment;
        if (options?.Filesystem is { } fs)
        {
            envelope["filesystem"] = SerializeToNode(fs);
        }
        ApplyTelemetry(envelope, options?.TelemetryEnabled);
        if (options?.User is { } user)
        {
            SetBackendConfig(envelope, "provision", "user", SerializeToNode(user));
        }
        return envelope;
    }

    /// <summary>Start a provisioned sandbox.</summary>
    /// <exception cref="MxcException">Starting failed.</exception>
    public static void StartSandbox(SandboxId id, StartSandboxOptions? options = null)
    {
        RunEnvelopePhase(BuildStartEnvelope(id, options));
    }

    // Build the start request envelope: sandboxId + optional sizing profile /
    // user nested under experimental.isolation_session.start.
    internal static JsonObject BuildStartEnvelope(SandboxId id, StartSandboxOptions? options)
    {
        var envelope = NewEnvelope("start");
        envelope["sandboxId"] = id.Value;
        ApplyOperationOptions(envelope, options?.TelemetryEnabled);
        if (options?.Size is { } size)
        {
            // The wire model reads the sizing profile from `configurationId`
            // (a typed small/medium/large/composable enum). Emitting any other
            // key would be silently dropped by the permissive experimental block.
            SetBackendConfig(envelope, "start", "configurationId", size);
        }
        if (options?.User is { } user)
        {
            SetBackendConfig(envelope, "start", "user", SerializeToNode(user));
        }
        return envelope;
    }

    /// <summary>
    /// Run <paramref name="command"/> in a started sandbox and return a live
    /// <see cref="MxcSandboxProcess"/> streaming its stdio. Dispose the process
    /// to release native resources.
    /// </summary>
    /// <exception cref="MxcException">The exec could not be started.</exception>
    public static MxcSandboxProcess ExecInSandbox(
        SandboxId id,
        string command,
        StateAwareOperationOptions? options = null)
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
                // `experimental` is 0 deliberately. Two things are missing: the engine's
                // `isolation_session` feature is not enabled in the library this project
                // builds, so that backend has no dispatch arm and the request ends at
                // `unsupported_phase`; and the request shape emitted here predates that
                // backend's Preview migration. Passing 1 without fixing both trades
                // `backend_unavailable` for `unsupported_phase`, which
                // `AssertNoUsableBackend` already tolerates — the tests would stay green
                // while nothing worked. Change it together with the feature and the shape.
                var status = NativeMethods.mxc_state_aware_exec(
                    requestPtr, /*experimental*/ 0, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    // See MxcSandbox.Spawn: the release belongs in `finally` so a throw
                    // during marshalling or exception construction cannot strand the
                    // detail's strings.
                    try
                    {
                        throw NativeError.ToException(status, error, "unknown error");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }
                return new MxcSandboxProcess(MxcSandboxHandle.FromRaw(handle));
            }
        }
    }

    // Build the exec request envelope: sandboxId + the command as the
    // cross-cutting process.commandLine.
    internal static JsonObject BuildExecEnvelope(
        SandboxId id,
        string command,
        StateAwareOperationOptions? options = null)
    {
        var envelope = NewEnvelope("exec");
        envelope["sandboxId"] = id.Value;
        ApplyOperationOptions(envelope, options?.TelemetryEnabled);
        envelope["process"] = new JsonObject { ["commandLine"] = command };
        return envelope;
    }

    /// <summary>
    /// Run <paramref name="command"/> in a started sandbox to completion,
    /// draining stdout/stderr concurrently, and return the captured result.
    /// </summary>
    /// <exception cref="MxcException">The exec could not be started.</exception>
    public static async Task<RunResult> ExecInSandboxAsync(
        SandboxId id,
        string command,
        CancellationToken cancellationToken = default,
        StateAwareOperationOptions? options = null)
    {
        var proc = await RunBlockingOperationAsync(
                () => ExecInSandbox(id, command, options),
                static abandoned => abandoned.Dispose(),
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
            };
        }
        finally
        {
            proc.Dispose();
        }
    }

    internal static async Task<T> RunBlockingOperationAsync<T>(
        Func<T> operation,
        Action<T> cleanupAbandonedResult,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var operationTask = Task.Factory.StartNew(
            operation,
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        try
        {
            return await operationTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = operationTask.ContinueWith(
                static (task, cleanup) =>
                {
                    if (task.Status == TaskStatus.RanToCompletion)
                    {
                        ((Action<T>)cleanup!)(task.Result);
                    }
                    else
                    {
                        _ = task.Exception;
                    }
                },
                cleanupAbandonedResult,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>Stop a running sandbox.</summary>
    /// <exception cref="MxcException">Stopping failed.</exception>
    public static void StopSandbox(SandboxId id, StateAwareOperationOptions? options = null)
    {
        var envelope = NewEnvelope("stop");
        envelope["sandboxId"] = id.Value;
        ApplyOperationOptions(envelope, options?.TelemetryEnabled);
        RunEnvelopePhase(envelope);
    }

    /// <summary>Deprovision (destroy) a sandbox, releasing its resources.</summary>
    /// <exception cref="MxcException">Deprovisioning failed.</exception>
    public static void DeprovisionSandbox(
        SandboxId id,
        StateAwareOperationOptions? options = null)
    {
        var envelope = NewEnvelope("deprovision");
        envelope["sandboxId"] = id.Value;
        ApplyOperationOptions(envelope, options?.TelemetryEnabled);
        RunEnvelopePhase(envelope);
    }

    // -- helpers --

    private static JsonObject NewEnvelope(string phase) => new()
    {
        ["version"] = StateAwareVersion,
        ["phase"] = phase,
    };

    private static void ApplyOperationOptions(JsonObject envelope, bool? telemetryEnabled)
    {
        ApplyTelemetry(envelope, telemetryEnabled);
    }

    private static void ApplyTelemetry(JsonObject envelope, bool? telemetryEnabled)
    {
        if (telemetryEnabled is not null)
        {
            envelope["telemetry"] = new JsonObject { ["enabled"] = telemetryEnabled.Value };
        }
    }

    // Nest a backend-specific config value under experimental.isolation_session.<phase>.
    private static void SetBackendConfig(JsonObject envelope, string phase, string key, JsonNode? value)
    {
        if (envelope["experimental"] is not JsonObject experimental)
        {
            experimental = new JsonObject();
            envelope["experimental"] = experimental;
        }
        if (experimental[IsolationSessionContainment] is not JsonObject backend)
        {
            backend = new JsonObject();
            experimental[IsolationSessionContainment] = backend;
        }
        if (backend[phase] is not JsonObject phaseConfig)
        {
            phaseConfig = new JsonObject();
            backend[phase] = phaseConfig;
        }
        phaseConfig[key] = value;
    }

    // Run an envelope phase via mxc_state_aware and return the parsed `result`
    // object (may be an empty object). Throws MxcException on failure.
    private static JsonObject? RunEnvelopePhase(JsonObject envelope)
    {
        var requestJson = envelope.ToJsonString();
        var requestBuf = ToNullTerminatedUtf8(requestJson);

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcStateAwareResult result = default;
                // `experimental` is 0 for the reason given in ExecInSandbox: the backend
                // is not compiled into this build and the request shape is stale, so
                // opting in would only change which error surfaces.
                var status = NativeMethods.mxc_state_aware(
                    requestPtr, /*dry_run*/ 0, /*experimental*/ 0, &result);
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
