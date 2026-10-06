// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>One-shot caller-authored exact-JSON entry points.</summary>
public static class MxcContainer
{
    static MxcContainer() => NativeLibraryResolver.Initialize();

    public static ExecutionResult RunJson(string json, JsonOptions? options = null)
    {
        DevJsonRequest.Inspect(json, nameof(RunJson));
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                MxcRunResult result = default;
                var status = NativeMethods.mxc_run_json(
                    requestPtr, options?.Experimental == true ? 1 : 0, &result);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, result.error, "running exact JSON failed");
                    }

                    var metadataJson = PtrToString(result.output_metadata_json_utf8);
                    var warningsJson = PtrToString(result.warnings_json_utf8);
                    return new ExecutionResult
                    {
                        ExitCode = result.exit_code,
                        TimedOut = result.timed_out != 0,
                        Stdout = PtrToString(result.stdout_utf8) ?? string.Empty,
                        Stderr = PtrToString(result.stderr_utf8) ?? string.Empty,
                        OutputMetadata = string.IsNullOrEmpty(metadataJson)
                            ? null : MxcJson.Deserialize<ExecutionMetadata>(metadataJson),
                        Warnings = string.IsNullOrEmpty(warningsJson)
                            ? Array.Empty<string>() : MxcJson.Deserialize<string[]>(warningsJson)
                                ?? throw new MxcException(ErrorCode.BackendError,
                                    "native runtime returned null warnings"),
                    };
                }
                finally
                {
                    NativeMethods.mxc_run_result_free(&result);
                }
            }
        }
    }

    public static Task<ExecutionResult> RunJsonAsync(
        string json,
        JsonOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Microsoft.Mxc.Sdk.V1.MxcLifecycle.RunBlockingOperationAsync(
            () => RunJson(json, options), _ => { }, cancellationToken);

    public static MxcProcess SpawnJson(string json, JsonOptions? options = null)
    {
        var timeout = DevJsonRequest.Inspect(json, nameof(SpawnJson));
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_spawn_json(
                    requestPtr, options?.Experimental == true ? 1 : 0, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(status, error, "spawning exact JSON failed");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }
                return new MxcProcess(MxcSandboxHandle.FromRaw(handle), timeout);
            }
        }
    }

    public static Task<MxcProcess> SpawnJsonAsync(
        string json,
        JsonOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Microsoft.Mxc.Sdk.V1.MxcLifecycle.RunBlockingOperationAsync(
            () => SpawnJson(json, options), late => late.Dispose(), cancellationToken);

    public static MxcPtyProcess SpawnWithPtyJson(string json, PtyJsonOptions? options = null)
    {
        var timeout = DevJsonRequest.Inspect(json, nameof(SpawnWithPtyJson));
        var size = MxcPtySize.ResolveInitial(options?.Size);
        size.Validate(nameof(options));
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_spawn_pty_json(
                    requestPtr, options?.Experimental == true ? 1 : 0,
                    size.Rows, size.Columns, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(status, error, "spawning exact JSON PTY failed");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }
                return new MxcPtyProcess(MxcSandboxHandle.FromRaw(handle), timeout);
            }
        }
    }

    private static unsafe string? PtrToString(byte* pointer) =>
        pointer is null ? null : Marshal.PtrToStringUTF8((IntPtr)pointer);
}
