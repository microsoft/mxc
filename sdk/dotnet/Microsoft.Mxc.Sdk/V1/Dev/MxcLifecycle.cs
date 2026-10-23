// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using NativeSandbox = Microsoft.Mxc.Sdk.Native.MxcSandbox;

namespace Microsoft.Mxc.Sdk.V1.Dev;

/// <summary>Caller-authored exact-JSON execution and lifecycle operations.</summary>
public static class MxcLifecycle
{
    static MxcLifecycle() => NativeLibraryResolver.Initialize();

    public static ExecutionResult RunInContainerJson(string json, JsonOptions? options = null) =>
        RunInContainerJsonAsync(json, options).GetAwaiter().GetResult();

    public static async Task<ExecutionResult> RunInContainerJsonAsync(
        string json,
        JsonOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        DevJsonRequest.Inspect(json, nameof(RunInContainerJson), "exec");
        using var process = await SpawnInContainerJsonAsync(json, options, cancellationToken)
            .ConfigureAwait(false);
        var (outcome, stdout, stderr) = await process
            .WaitForExitWithOutputAsync(cancellationToken).ConfigureAwait(false);
        return new ExecutionResult
        {
            ExitCode = outcome.ExitCode,
            TimedOut = outcome.TimedOut,
            Stdout = Encoding.UTF8.GetString(stdout),
            Stderr = Encoding.UTF8.GetString(stderr),
            OutputMetadata = process.OutputMetadata,
            Warnings = process.Warnings,
        };
    }

    public static MxcProcess SpawnInContainerJson(string json, JsonOptions? options = null)
    {
        var timeout = DevJsonRequest.Inspect(json, nameof(SpawnInContainerJson), "exec");
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_exec_state_aware_json(
                    requestPtr, options?.Experimental == true ? 1 : 0, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(status, error, "spawning exact JSON exec failed");
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

    public static Task<MxcProcess> SpawnInContainerJsonAsync(
        string json,
        JsonOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Microsoft.Mxc.Sdk.V1.MxcLifecycle.RunBlockingOperationAsync(
            () => SpawnInContainerJson(json, options), late => late.Dispose(), cancellationToken);

    public static MxcPtyProcess SpawnInContainerWithPtyJson(
        string json,
        PtyJsonOptions? options = null)
    {
        var timeout = DevJsonRequest.Inspect(json, nameof(SpawnInContainerWithPtyJson), "exec");
        var size = MxcPtySize.ResolveInitial(options?.Size);
        size.Validate(nameof(options));
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                NativeSandbox* handle = null;
                MxcErrorDetail error = default;
                var status = NativeMethods.mxc_state_aware_exec_pty(
                    requestPtr, options?.Experimental == true ? 1 : 0,
                    size.Rows, size.Columns, &handle, &error);
                if (status != (int)ErrorCode.Success)
                {
                    try
                    {
                        throw NativeError.ToException(status, error, "spawning exact JSON exec PTY failed");
                    }
                    finally
                    {
                        NativeMethods.mxc_error_detail_free(&error);
                    }
                }
                return new MxcPtyProcess(
                    MxcSandboxHandle.FromRaw(handle), MxcProcess.NormalizeTimeout(timeout));
            }
        }
    }

    public static string ProvisionContainerJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ProvisionContainerJson), "provision", false, options);

    public static Task<string> ProvisionContainerJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => ProvisionContainerJson(json, options));

    public static string StartContainerJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(StartContainerJson), "start", false, options);

    public static Task<string> StartContainerJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => StartContainerJson(json, options));

    public static string StopContainerJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(StopContainerJson), "stop", false, options);

    public static Task<string> StopContainerJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => StopContainerJson(json, options));

    public static string DeprovisionContainerJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(DeprovisionContainerJson), "deprovision", false, options);

    public static Task<string> DeprovisionContainerJsonAsync(
        string json,
        JsonOptions? options = null) =>
        Task.Run(() => DeprovisionContainerJson(json, options));

    public static string ValidateProvisionJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ValidateProvisionJson), "provision", true, options);

    public static Task<string> ValidateProvisionJsonAsync(
        string json,
        JsonOptions? options = null) =>
        Task.Run(() => ValidateProvisionJson(json, options));

    public static string ValidateStartJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ValidateStartJson), "start", true, options);

    public static Task<string> ValidateStartJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => ValidateStartJson(json, options));

    public static string ValidateStopJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ValidateStopJson), "stop", true, options);

    public static Task<string> ValidateStopJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => ValidateStopJson(json, options));

    public static string ValidateDeprovisionJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ValidateDeprovisionJson), "deprovision", true, options);

    public static Task<string> ValidateDeprovisionJsonAsync(
        string json,
        JsonOptions? options = null) =>
        Task.Run(() => ValidateDeprovisionJson(json, options));

    public static string ValidateProcessJson(string json, JsonOptions? options = null) =>
        RunPhase(json, nameof(ValidateProcessJson), "exec", true, options);

    public static Task<string> ValidateProcessJsonAsync(string json, JsonOptions? options = null) =>
        Task.Run(() => ValidateProcessJson(json, options));

    private static string RunPhase(
        string json, string operation, string phase, bool dryRun, JsonOptions? options)
    {
        DevJsonRequest.Inspect(json, operation, phase);
        var request = DevJsonRequest.ToNullTerminatedUtf8(json);
        unsafe
        {
            fixed (byte* requestPtr = request)
            {
                MxcStateAwareResult result = default;
                var status = NativeMethods.mxc_run_state_aware_json(
                    requestPtr, dryRun ? 1 : 0, options?.Experimental == true ? 1 : 0, &result);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw NativeError.ToException(status, result.error, "exact JSON lifecycle failed");
                    }
                    var responseJson = result.response_json_utf8 is null
                        ? null : Marshal.PtrToStringUTF8((IntPtr)result.response_json_utf8);
                    return string.IsNullOrEmpty(responseJson)
                        ? throw new MxcException(ErrorCode.BackendError,
                            "native lifecycle response has no JSON")
                        : responseJson;
                }
                finally
                {
                    NativeMethods.mxc_state_aware_result_free(&result);
                }
            }
        }
    }
}
