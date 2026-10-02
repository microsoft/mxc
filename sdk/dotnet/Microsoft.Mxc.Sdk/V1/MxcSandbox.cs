// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.V1;

/// <summary>
/// V1 entry point for running MXC sandboxes from C#. Wraps the native
/// <c>mxc_ffi</c> library and runs or spawns a complete
/// <see cref="SandboxRequest"/>.
/// </summary>
public static class MxcSandbox
{
    private const int NoExperimentalOptIn = 0;

    static MxcSandbox()
    {
        NativeLibraryResolver.Initialize();
    }

    internal static IRequestProbeInterop RequestProbeInterop { get; set; } =
        PInvokeRequestProbeInterop.Instance;

    /// <summary>
    /// Probe which Windows ProcessContainer tier can serve a request.
    /// </summary>
    /// <remarks>
    /// This diagnostic does not create a sandbox. It calls the packaged
    /// <c>mxc_ffi</c> library in process. It is intentionally not part of
    /// <see cref="ISandboxRunner"/>, preserving compatibility for existing
    /// interface implementations.
    /// </remarks>
    public static ProbeOutput Probe(SandboxRequest? request = null)
    {
        var requestJson = request is null ? null : SerializeRequest(request);
        if (!RequestProbeInterop.IsSupportedOnCurrentPlatform)
        {
            throw new MxcException(
                ErrorCode.UnsupportedContainment,
                "the request-aware probe is available only for Windows ProcessContainer");
        }

        return ParseProbeOutput(ProbeNative(requestJson));
    }

    private static unsafe string ProbeNative(string? configJson)
    {
        if (configJson is null)
        {
            return InvokeNativeProbe(null);
        }

        var requestBuffer = ToNullTerminatedUtf8(configJson);
        fixed (byte* requestPtr = requestBuffer)
        {
            return InvokeNativeProbe(requestPtr);
        }
    }

    private static unsafe string InvokeNativeProbe(byte* requestPtr)
    {
        byte* output = null;
        MxcErrorDetail error = default;
        var callCompleted = false;
        try
        {
            var status = RequestProbeInterop.Probe(requestPtr, &output, &error);
            callCompleted = true;
            if (status != (int)ErrorCode.Success)
            {
                throw NativeError.ToException(
                    status,
                    error,
                    "native request probe failed");
            }
            if (output is null)
            {
                throw new MxcException(
                    ErrorCode.BackendError,
                    "native request probe returned no output");
            }

            return Marshal.PtrToStringUTF8((IntPtr)output)
                ?? throw new MxcException(
                    ErrorCode.BackendError,
                    "native request probe returned invalid JSON");
        }
        finally
        {
            if (callCompleted)
            {
                if (output is not null)
                {
                    RequestProbeInterop.FreeString(output);
                }
                RequestProbeInterop.FreeError(&error);
            }
        }
    }

    internal static ProbeOutput ParseProbeOutput(string json)
    {
        var output = MxcJson.Deserialize<NativeProbeOutput>(json, MxcJson.ProbeOptions)
            ?? throw new JsonException("native request probe returned null JSON.");
        var warnings = output.Warnings
            ?? throw new JsonException("native request probe returned null warnings.");
        if (warnings.Any(static warning => warning is null))
        {
            throw new JsonException(
                "native request probe returned a non-string warning.");
        }

        var probes = output.Probes
            ?? throw new JsonException("native request probe omitted probes.");
        var ui = probes.UiCapabilities
            ?? throw new JsonException("native request probe omitted UI capabilities.");

        IsolationTier? tier;
        if (!output.HasTier)
        {
            if (!output.HasError)
            {
                throw new JsonException(
                    "native request probe omitted both tier and error.");
            }
            if (output.Error is null)
            {
                throw new JsonException(
                    "native request probe returned a null error.");
            }
            if (output.HasNeedsDaclAugmentation)
            {
                throw new JsonException(
                    "native request probe returned DACL augmentation with an error.");
            }
            tier = null;
        }
        else
        {
            if (output.Tier is null)
            {
                throw new JsonException(
                    "native request probe returned a null tier.");
            }
            if (output.HasError)
            {
                throw new JsonException(
                    "native request probe returned both tier and error.");
            }
            if (!output.HasNeedsDaclAugmentation
                || output.NeedsDaclAugmentation is null)
            {
                throw new JsonException(
                    "native request probe omitted DACL augmentation for a selected tier.");
            }
            tier = ParseProbeIsolationTier(output.Tier);
        }

        return new ProbeOutput
        {
            Tier = tier,
            NeedsDaclAugmentation = output.NeedsDaclAugmentation,
            Warnings = warnings.Select(static warning => warning!).ToArray(),
            Error = output.Error,
            Probes = new ProbeFacts
            {
                BaseContainerApiPresent = probes.BaseContainerApiPresent,
                NativeCaptureAvailable = probes.NativeCaptureAvailable,
                GuardedCaptureAvailable = probes.GuardedCaptureAvailable,
                BfscfgPresent = probes.BfscfgPresent,
                BfsCompiledIn = probes.BfsCompiledIn,
                BaseContainerSupportsDenyPaths = probes.BaseContainerSupportsDenyPaths,
                BaseContainerSupportsEnumeratePaths =
                    probes.BaseContainerSupportsEnumeratePaths,
                BaseContainerSupportsIngressHostLoopbackAllow =
                    probes.BaseContainerSupportsIngressHostLoopbackAllow,
                IsolationSessionAvailable = probes.IsolationSessionAvailable,
                HyperlightAvailable = probes.HyperlightAvailable,
                UiCapabilities = new UiCapabilitySupport
                {
                    CanBlockClipboardRead = ui.CanBlockClipboardRead,
                    CanBlockClipboardWrite = ui.CanBlockClipboardWrite,
                    CanBlockInputInjection = ui.CanBlockInputInjection,
                    CanBlockInputMethodChanges = ui.CanBlockInputMethodChanges,
                    CanBlockExternalUiObjects = ui.CanBlockExternalUiObjects,
                    CanBlockGlobalUiNamespace = ui.CanBlockGlobalUiNamespace,
                    CanBlockDesktopSwitching = ui.CanBlockDesktopSwitching,
                    CanBlockLogoffOrShutdown = ui.CanBlockLogoffOrShutdown,
                    CanBlockSystemParameterChanges = ui.CanBlockSystemParameterChanges,
                    CanBlockDisplaySettingsChanges = ui.CanBlockDisplaySettingsChanges,
                },
            },
        };
    }

    /// <summary>
    /// Run <paramref name="command"/> in a sandbox described by
    /// <paramref name="policy"/>, to completion, capturing its output.
    /// </summary>
    /// <param name="policy">What to restrict.</param>
    /// <param name="command">The command line to run (the <c>process.commandLine</c> equivalent).</param>
    /// <returns>The captured stdout/stderr and exit outcome.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="MxcException">The sandbox could not be built or run.</exception>
    public static RunResult Run(SandboxPolicy policy, string command)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(command);
        return Run(CreateCompatibilityRequest(policy, command));
    }

    /// <summary>Run a complete one-shot request to completion.</summary>
    public static RunResult Run(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var requestBuf = ToNullTerminatedUtf8(SerializeRequest(request));

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                MxcRunResult result = default;
                var status = NativeMethods.mxc_run_json(
                    requestPtr,
                    NoExperimentalOptIn,
                    &result);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, result.error, "unknown error");
                    }

                    return new RunResult
                    {
                        ExitCode = result.exit_code,
                        TimedOut = result.timed_out != 0,
                        Stdout = PtrToString(result.stdout_utf8) ?? string.Empty,
                        Stderr = PtrToString(result.stderr_utf8) ?? string.Empty,
                        OutputMetadata = DeserializeOutputMetadata(
                            PtrToString(result.output_metadata_json_utf8)),
                        Warnings = DeserializeWarnings(
                            PtrToString(result.warnings_json_utf8)),
                    };
                }
                finally
                {
                    NativeMethods.mxc_run_result_free(&result);
                }
            }
        }
    }

    /// <summary>
    /// Asynchronous wrapper over <see cref="Run(SandboxPolicy, string)"/>. The
    /// native call is blocking, so this offloads it to the thread pool.
    /// </summary>
    public static Task<RunResult> RunAsync(SandboxPolicy policy, string command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(command);
        return Task.Run(() => Run(policy, command), cancellationToken);
    }

    /// <summary>Asynchronous wrapper over <see cref="Run(SandboxRequest)"/>.</summary>
    public static Task<RunResult> RunAsync(
        SandboxRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.Run(() => Run(request), cancellationToken);
    }

    /// <summary>
    /// Spawn <paramref name="command"/> in a sandbox described by
    /// <paramref name="policy"/> and return a live <see cref="MxcSandboxProcess"/>
    /// you can stream stdio through, wait on, and kill while it runs.
    /// </summary>
    /// <param name="policy">What to restrict.</param>
    /// <param name="command">The command line to run (the <c>process.commandLine</c> equivalent).</param>
    /// <returns>A live process handle. Dispose it to release native resources (killing the child if still running).</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="MxcException">The sandbox could not be built or spawned.</exception>
    public static MxcSandboxProcess Spawn(SandboxPolicy policy, string command)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(command);
        return Spawn(CreateCompatibilityRequest(policy, command));
    }

    /// <summary>Spawn a complete one-shot request and return its live process handle.</summary>
    public static MxcSandboxProcess Spawn(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var requestBuf = ToNullTerminatedUtf8(SerializeRequest(request));

        unsafe
        {
            fixed (byte* requestPtr = requestBuf)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_spawn_json(
                    requestPtr,
                    NoExperimentalOptIn,
                    &handle,
                    &error);
                if (status != (int)ErrorCode.Success)
                {
                    // `finally`, not a straight-line free: marshalling the strings or
                    // allocating the exception can throw, and on that path the detail
                    // would never be released. Ownership has to be discharged however
                    // we leave this block.
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
                    request.Policy.TimeoutMs);
            }
        }
    }

    private static SandboxRequest CreateCompatibilityRequest(
        SandboxPolicy policy,
        string command) =>
        new(policy, command);

    private static byte[] ToNullTerminatedUtf8(string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var buffer = new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, 0);
        buffer[byteCount] = 0;
        return buffer;
    }

    internal static string SerializePolicy(SandboxPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return MxcJson.Serialize(policy, MxcJson.Options);
    }

    internal static string SerializeRequest(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ExactOneShotRequestWriter.Serialize(request);
    }

    private static IsolationTier ParseProbeIsolationTier(string value) =>
        value switch
        {
            "base-container" => IsolationTier.BaseContainer,
            "appcontainer-bfs" => IsolationTier.AppContainerBfs,
            "appcontainer-dacl" => IsolationTier.AppContainerDacl,
            _ => throw new JsonException(
                $"native request probe returned unknown tier '{value}'."),
        };

    private static unsafe string? PtrToString(byte* p) =>
        p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);

    private static SandboxOutputMetadata? DeserializeOutputMetadata(string? json) =>
        string.IsNullOrEmpty(json)
            ? null
            : MxcJson.Deserialize<SandboxOutputMetadata>(json);

    private static IReadOnlyList<string> DeserializeWarnings(string? json) =>
        string.IsNullOrEmpty(json)
            ? Array.Empty<string>()
            : MxcJson.Deserialize<string[]>(json) ?? Array.Empty<string>();
}
