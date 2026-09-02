// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Entry point for running MXC sandboxes from C#. Wraps the native
/// <c>mxc_ffi</c> library, selecting the right containment backend for the host
/// and running or spawning a complete <see cref="SandboxRequest"/>.
/// </summary>
public static class MxcSandbox
{
    private const string LegacyCaptureDenialsName = "CaptureDenials";

    static MxcSandbox()
    {
        NativeLibraryResolver.Initialize();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters =
        {
            new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
            new NetworkProxyPolicyJsonConverter(),
        },
    };

    /// <summary>
    /// The version of the native <c>mxc_ffi</c> library.
    /// </summary>
    public static string NativeVersion
    {
        get
        {
            unsafe
            {
                var p = NativeMethods.mxc_version();
                return p is null ? string.Empty : Marshal.PtrToStringUTF8((IntPtr)p) ?? string.Empty;
            }
        }
    }

    /// <summary>
    /// Probe every containment backend the current host can run.
    /// </summary>
    /// <remarks>
    /// This includes host-capability backends the public SDK cannot necessarily
    /// launch. Cross-check <see cref="GetPlatformSupport"/> before using a
    /// backend with <see cref="Run(SandboxRequest)"/> or
    /// <see cref="Spawn(SandboxRequest)"/>.
    /// </remarks>
    public static IReadOnlyList<AvailableBackend> GetAvailableBackends()
    {
        unsafe
        {
            var json = ReadOwnedJson(
                NativeMethods.mxc_available_backends_json(),
                "probing available backends");
            var backends = JsonSerializer.Deserialize<NativeAvailableBackend[]>(json, JsonOptions)
                ?? throw new JsonException("Native backend discovery returned null JSON.");
            return backends.Select(MapAvailableBackend).ToArray();
        }
    }

    /// <summary>
    /// Probe whether the public SDK can launch sandboxes on this host and which
    /// backends it can launch.
    /// </summary>
    public static PlatformSupport GetPlatformSupport()
    {
        unsafe
        {
            var json = ReadOwnedJson(
                NativeMethods.mxc_platform_support_json(),
                "probing platform support");
            var support = JsonSerializer.Deserialize<NativePlatformSupport>(json, JsonOptions)
                ?? throw new JsonException("Native platform support returned null JSON.");
            return new PlatformSupport
            {
                IsSupported = support.IsSupported,
                Reason = support.Reason,
                AvailableMethods = support.AvailableMethods.Select(ParseBackend).ToArray(),
            };
        }
    }

    /// <summary>
    /// Run <paramref name="command"/> in a sandbox described by
    /// <paramref name="policy"/>, to completion, capturing its output.
    /// </summary>
    /// <param name="policy">What to restrict. Its <see cref="SandboxPolicy.Version"/> must be set.</param>
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
                var status = NativeMethods.mxc_run_request(requestPtr, &result);
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
    /// <param name="policy">What to restrict. Its <see cref="SandboxPolicy.Version"/> must be set.</param>
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
                var status = NativeMethods.mxc_spawn_request(requestPtr, &handle, &error);
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
        ValidateTelemetryVersion(policy);
        return JsonSerializer.Serialize(policy, JsonOptions);
    }

    internal static string SerializeRequest(SandboxRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return JsonSerializer.Serialize(PrepareRequest(request), JsonOptions);
    }

    private static SandboxRequest PrepareRequest(SandboxRequest request)
    {
        ValidateTelemetryVersion(request.Policy);
#pragma warning disable MXC0001 // Compatibility migration for the obsolete policy field.
        var legacyCaptureDenials = request.Policy.CaptureDenials;
#pragma warning restore MXC0001
        if (legacyCaptureDenials is null)
        {
            return request;
        }

        var containment = request.Containment switch
        {
            ProcessContainment => new ProcessContainerContainment
            {
                CaptureDenials = legacyCaptureDenials,
            },
            ProcessContainerContainment processContainer =>
                CloneProcessContainer(processContainer, legacyCaptureDenials),
            _ => throw new ArgumentException(
                $"{nameof(SandboxPolicy)}.{LegacyCaptureDenialsName} "
                    + $"cannot be used with {request.Containment.GetType().Name}; set "
                    + $"{nameof(ProcessContainerContainment)}."
                    + $"{nameof(ProcessContainerContainment.CaptureDenials)} instead.",
                nameof(request)),
        };

        return new SandboxRequest(ClonePolicyWithoutCaptureDenials(request.Policy), request.Command)
        {
            Containment = containment,
            ContainerName = request.ContainerName,
            WorkingDirectory = request.WorkingDirectory,
            Environment = new Dictionary<string, string>(request.Environment),
            Experimental = request.Experimental,
        };
    }

    private static void ValidateTelemetryVersion(SandboxPolicy policy)
    {
        if (policy.Telemetry is null)
        {
            return;
        }

        var coreVersion = policy.Version.Split('-', 2)[0];
        if (Version.TryParse(coreVersion, out var version)
            && version < new Version(0, 9, 0))
        {
            throw new MxcException(
                ErrorCode.MalformedRequest,
                $"telemetry requires schema version {SchemaVersions.MaximumSupported} or later; got {policy.Version}");
        }
    }

    private static ProcessContainerContainment CloneProcessContainer(
        ProcessContainerContainment containment,
        CaptureDenialsPolicy legacyCaptureDenials)
    {
        if (containment.CaptureDenials is not null
            && !CaptureDenialsEqual(containment.CaptureDenials, legacyCaptureDenials))
        {
            throw new ArgumentException(
                $"{nameof(SandboxPolicy)}.{LegacyCaptureDenialsName} conflicts "
                    + $"with {nameof(ProcessContainerContainment)}."
                    + $"{nameof(ProcessContainerContainment.CaptureDenials)}.",
                "request");
        }

        return new ProcessContainerContainment
        {
            LeastPrivilege = containment.LeastPrivilege,
            LearningMode = containment.LearningMode,
            Capabilities = new List<string>(containment.Capabilities),
            CaptureDenials = containment.CaptureDenials ?? legacyCaptureDenials,
            Ui = containment.Ui,
            Network = containment.Network,
        };
    }

    // Keep in sync with SandboxPolicy's properties: every property except the
    // obsolete CaptureDenials must be copied, or it is silently dropped from
    // any request that carries the legacy field.
    private static SandboxPolicy ClonePolicyWithoutCaptureDenials(SandboxPolicy policy) =>
        new()
        {
            Version = policy.Version,
            Filesystem = policy.Filesystem,
            Network = policy.Network,
            Ui = policy.Ui,
            TimeoutMs = policy.TimeoutMs,
        };

    private static bool CaptureDenialsEqual(
        CaptureDenialsPolicy left,
        CaptureDenialsPolicy right) =>
        left.Mode == right.Mode
            && string.Equals(left.OutputPath, right.OutputPath, StringComparison.Ordinal)
            && left.RetainEtl == right.RetainEtl;

    private static AvailableBackend MapAvailableBackend(NativeAvailableBackend backend) =>
        new()
        {
            Backend = ParseBackend(backend.Backend),
            Tier = backend.Tier is null ? null : ParseIsolationTier(backend.Tier),
            Capabilities = backend.Capabilities.Select(ParseBackendCapability).ToArray(),
        };

    internal static ContainmentBackend ParseBackend(string value) =>
        value switch
        {
            "processcontainer" => ContainmentBackend.ProcessContainer,
            "windows_sandbox" => ContainmentBackend.WindowsSandbox,
            "lxc" => ContainmentBackend.Lxc,
            "wslc" => ContainmentBackend.Wslc,
            "seatbelt" => ContainmentBackend.Seatbelt,
            "isolation_session" => ContainmentBackend.IsolationSession,
            "bubblewrap" => ContainmentBackend.Bubblewrap,
            "hyperlight" => ContainmentBackend.Hyperlight,
            _ => ContainmentBackend.Unknown,
        };

    internal static IsolationTier ParseIsolationTier(string value) =>
        value switch
        {
            "base-container" => IsolationTier.BaseContainer,
            "appcontainer-bfs" => IsolationTier.AppContainerBfs,
            "appcontainer-dacl" => IsolationTier.AppContainerDacl,
            _ => IsolationTier.Unknown,
        };

    internal static BackendCapability ParseBackendCapability(string value) =>
        value switch
        {
            "captureDenials" => BackendCapability.CaptureDenials,
            _ => BackendCapability.Unknown,
        };

    private static unsafe string ReadOwnedJson(byte* value, string operation)
    {
        if (value is null)
        {
            throw new MxcException(ErrorCode.BackendError, $"{operation} failed");
        }

        try
        {
            return Marshal.PtrToStringUTF8((IntPtr)value)
                ?? throw new MxcException(ErrorCode.BackendError, $"{operation} returned invalid JSON");
        }
        finally
        {
            NativeMethods.mxc_string_free(value);
        }
    }

    private static unsafe string? PtrToString(byte* p) =>
        p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);

    private static SandboxOutputMetadata? DeserializeOutputMetadata(string? json) =>
        string.IsNullOrEmpty(json)
            ? null
            : JsonSerializer.Deserialize<SandboxOutputMetadata>(json);

    private static IReadOnlyList<string> DeserializeWarnings(string? json) =>
        string.IsNullOrEmpty(json)
            ? Array.Empty<string>()
            : JsonSerializer.Deserialize<string[]>(json) ?? Array.Empty<string>();
}
