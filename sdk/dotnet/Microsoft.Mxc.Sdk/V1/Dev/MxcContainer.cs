// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Creation entry points for caller-authored MXC request JSON.</summary>
public static class MxcContainer
{
    static MxcContainer() => NativeLibraryResolver.Initialize();

    public static ExecutionResult RunJson(string json, JsonOptions? options = null)
    {
        var (request, _) = DevJsonRequest.Prepare(json, nameof(RunJson));
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                MxcRunResult result = default;
                var status = NativeMethods.mxc_run_json(
                    requestPtr, options?.Experimental == true ? 1 : 0, &result);
                try
                {
                    return ReadRunResult(status, result);
                }
                finally
                {
                    NativeMethods.mxc_run_result_free(&result);
                }
            }
        }
    }

    internal static unsafe ExecutionResult ReadRunResult(int status, MxcRunResult result)
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

    public static Task<ExecutionResult> RunJsonAsync(
        string json,
        JsonOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Microsoft.Mxc.Sdk.V1.MxcLifecycle.RunBlockingOperationAsync(
            () => RunJson(json, options), _ => { }, cancellationToken);

    public static MxcProcess SpawnJson(string json, JsonOptions? options = null)
    {
        var (request, timeout) = DevJsonRequest.Prepare(json, nameof(SpawnJson));
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

    /// <summary>Prepare restrictive policy changes without creating a container.</summary>
    /// <remarks>The caller decides whether to accept the changes and execute RequestJson.</remarks>
    public static PreparedPolicyRequest PreparePolicyJson(
        string json,
        PolicyFailures failures,
        PolicyPreparationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(failures);
        byte[] request;
        try
        {
            PolicyPreparationJson.ValidateRequestSize(json);
            (request, _) = DevJsonRequest.Prepare(json, nameof(PreparePolicyJson));
        }
        catch (JsonException)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                "invalid MXC request JSON for policy preparation");
        }
        catch (MxcException error) when (error.Code == ErrorCode.MalformedRequest)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                "invalid MXC request JSON for policy preparation");
        }

        byte[] failuresJson;
        try
        {
            failuresJson = Encoding.UTF8.GetBytes(failures.ToJson() + "\0");
        }
        catch (JsonException)
        {
            throw new MxcException(ErrorCode.MalformedRequest,
                "invalid PolicyFailures for policy preparation");
        }

        unsafe
        {
            fixed (byte* requestPtr = request)
            fixed (byte* failuresPtr = failuresJson)
            {
                byte* output = null;
                MxcErrorDetail error = default;
                try
                {
                    var status = NativeMethods.mxc_prepare_policy_json(
                        requestPtr, failuresPtr, options?.Experimental == true ? 1 : 0,
                        &output, &error);
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, error, "preparing policy JSON failed");
                    }
                    return ReadPreparedPolicyRequest(output);
                }
                finally
                {
                    NativeMethods.mxc_string_free(output);
                    NativeMethods.mxc_error_detail_free(&error);
                }
            }
        }
    }

    /// <summary>Prepare policy JSON off the caller's thread; cancellation stops awaiting the operation.</summary>
    public static Task<PreparedPolicyRequest> PreparePolicyJsonAsync(
        string json,
        PolicyFailures failures,
        PolicyPreparationOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Microsoft.Mxc.Sdk.V1.MxcLifecycle.RunBlockingOperationAsync(
            () => PreparePolicyJson(json, failures, options), _ => { }, cancellationToken);

    internal static unsafe PreparedPolicyRequest ReadPreparedPolicyRequest(byte* output)
    {
        if (output is null)
        {
            throw new MxcException(ErrorCode.BackendError,
                "native policy preparation returned no JSON");
        }
        var length = 0;
        while (length <= PolicyPreparationJson.MaximumResultBytes && output[length] != 0)
        {
            length++;
        }
        if (length > PolicyPreparationJson.MaximumResultBytes)
        {
            throw new MxcException(ErrorCode.BackendError,
                "native policy preparation result exceeds the byte limit");
        }
        try
        {
            return PreparedPolicyRequest.FromJson(
                PolicyPreparationJson.StrictUtf8.GetString(new ReadOnlySpan<byte>(output, length)));
        }
        catch (Exception error) when (error is JsonException or DecoderFallbackException)
        {
            throw new MxcException(ErrorCode.BackendError,
                "native policy preparation returned invalid JSON");
        }
    }

    public static MxcPtyProcess SpawnWithPtyJson(string json, PtyJsonOptions? options = null)
    {
        var (request, timeout) = DevJsonRequest.Prepare(json, nameof(SpawnWithPtyJson));
        var size = MxcPtySize.ResolveInitial(options?.Size);
        size.Validate(nameof(options));
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
