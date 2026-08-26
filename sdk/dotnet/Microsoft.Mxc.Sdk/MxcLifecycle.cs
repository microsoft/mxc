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
/// streaming <see cref="MxcSandboxProcess"/>, and <see cref="ExecInSandboxAttached"/>
/// runs one on this process's own console.
/// </summary>
/// <remarks>
/// On a host or build that does not support the selected backend, these calls
/// surface an <see cref="MxcException"/> with
/// <see cref="ErrorCode.BackendUnavailable"/>.
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

    // The experimental opt-in every native entry point takes. Shared so the call
    // sites cannot drift — the attached one is not reachable by a test.
    private const int ExperimentalOptIn = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>
    /// Provision a new sandbox under <paramref name="containment"/>, returning its
    /// <see cref="SandboxId"/>.
    /// </summary>
    /// <exception cref="MxcException">Provisioning failed.</exception>
    public static ProvisionResult ProvisionSandbox(
        StateAwareContainment containment,
        ProvisionSandboxOptions? options = null)
    {
        var result = RunEnvelopePhase(BuildProvisionEnvelope(containment, options))
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

    // Build the provision request envelope. Cross-cutting policy (network,
    // filesystem) sits at the envelope top level; backend-specific config nests
    // under experimental.<containment>.provision.
    internal static JsonObject BuildProvisionEnvelope(
        StateAwareContainment containment,
        ProvisionSandboxOptions? options)
    {
        var backend = ContainmentKey(containment);
        var envelope = NewEnvelope("provision");
        envelope["containment"] = backend;
        if (options?.Network is { } network)
        {
            envelope["network"] = SerializeToNode(network);
        }
        if (options?.Filesystem is { } fs)
        {
            envelope["filesystem"] = SerializeToNode(fs);
        }
        if (options?.AppId is { } appId)
        {
            SetBackendConfig(envelope, backend, "provision", "appId", appId);
        }
        return envelope;
    }

    /// <summary>Start a provisioned sandbox.</summary>
    /// <exception cref="MxcException">Starting failed.</exception>
    public static void StartSandbox(SandboxId id)
    {
        RunEnvelopePhase(BuildStartEnvelope(id));
    }

    // Build the start request envelope. The backend's start config is empty, so
    // nothing nests under experimental.
    internal static JsonObject BuildStartEnvelope(SandboxId id)
    {
        var envelope = NewEnvelope("start");
        envelope["sandboxId"] = id.Value;
        return envelope;
    }

    /// <summary>
    /// Run <paramref name="command"/> in a started sandbox and return a live
    /// <see cref="MxcSandboxProcess"/> streaming its stdio. Dispose the process
    /// to release native resources.
    /// </summary>
    /// <exception cref="MxcException">The exec could not be started.</exception>
    public static MxcSandboxProcess ExecInSandbox(SandboxId id, string command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var requestJson = BuildExecEnvelope(id, command).ToJsonString();
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

    /// <summary>
    /// Run <paramref name="command"/> in a started sandbox with its stdio
    /// attached to this process's console, and wait for it to finish. Use this
    /// for an interactive session: the sandboxed process gets a real terminal,
    /// so a shell inside it renders and resizes normally.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="ExecInSandbox"/> this returns no handle and no captured
    /// output — the stdio is the caller's own. The call blocks until the
    /// sandboxed process exits, and always reports
    /// <see cref="SandboxWaitResult.TimedOut"/> as false.
    /// <para>
    /// It throws <see cref="ErrorCode.MalformedRequest"/> when this process's
    /// stdout and stdin are not both terminals, or when another attached exec is
    /// already running — one runs at a time per process. Use
    /// <see cref="ExecInSandbox"/> for a workload with no terminal. A
    /// pseudo-console carries one output stream, so the sandbox's stderr arrives
    /// merged into stdout.
    /// </para>
    /// <para>
    /// For its duration the workload owns this process's console: raw VT, so no
    /// echo and no line input, and keystrokes — <c>Ctrl-C</c> included — reach
    /// the workload rather than this process. The console is restored on return.
    /// </para>
    /// </remarks>
    /// <exception cref="MxcException">The exec could not be started.</exception>
    public static SandboxWaitResult ExecInSandboxAttached(SandboxId id, string command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var requestJson = BuildExecEnvelope(id, command).ToJsonString();
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
                    // As in ExecInSandbox: the release belongs in `finally` so a throw
                    // during exception construction cannot strand the detail's strings.
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

    // Build the exec request envelope: sandboxId + the command as the
    // cross-cutting `process` section.
    internal static JsonObject BuildExecEnvelope(SandboxId id, string command)
    {
        var envelope = NewEnvelope("exec");
        envelope["sandboxId"] = id.Value;
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
        CancellationToken cancellationToken = default)
    {
        // Offload the blocking exec-start P/Invoke so this method never blocks
        // the caller's thread (for a backend that relays exec internally, the
        // whole exec runs during ExecInSandbox).
        var proc = await Task.Run(() => ExecInSandbox(id, command), cancellationToken)
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

    /// <summary>Stop a running sandbox.</summary>
    /// <exception cref="MxcException">Stopping failed.</exception>
    public static void StopSandbox(SandboxId id)
    {
        var envelope = NewEnvelope("stop");
        envelope["sandboxId"] = id.Value;
        RunEnvelopePhase(envelope);
    }

    /// <summary>Deprovision (destroy) a sandbox, releasing its resources.</summary>
    /// <exception cref="MxcException">Deprovisioning failed.</exception>
    public static void DeprovisionSandbox(SandboxId id)
    {
        var envelope = NewEnvelope("deprovision");
        envelope["sandboxId"] = id.Value;
        RunEnvelopePhase(envelope);
    }

    // -- helpers --

    private static JsonObject NewEnvelope(string phase) => new()
    {
        ["version"] = StateAwareVersion,
        ["phase"] = phase,
    };

    // Map the public containment selector to its wire key.
    private static string ContainmentKey(StateAwareContainment containment) => containment switch
    {
        StateAwareContainment.IsolationSession => IsolationSessionContainment,
        _ => throw new MxcException(
            ErrorCode.UnsupportedContainment,
            $"unknown state-aware containment '{containment}'"),
    };

    // Nest a backend-specific config value under experimental.<backend>.<phase>.
    private static void SetBackendConfig(
        JsonObject envelope, string backend, string phase, string key, JsonNode? value)
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
                var status = NativeMethods.mxc_state_aware(
                    requestPtr, /*dry_run*/ 0, ExperimentalOptIn, &result);
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
