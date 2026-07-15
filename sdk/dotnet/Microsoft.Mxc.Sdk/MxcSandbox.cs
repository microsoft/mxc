// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Entry point for running MXC sandboxes from C#. Wraps the native
/// <c>mxc_ffi</c> library, selecting the right containment backend for the host
/// and running a command to completion with the given <see cref="SandboxPolicy"/>.
/// </summary>
public static class MxcSandbox
{
    static MxcSandbox()
    {
        NativeLibraryResolver.Initialize();
    }

    private static readonly JsonSerializerOptions PolicyJsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
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

        var policyJson = JsonSerializer.Serialize(policy, PolicyJsonOptions);
        var policyBuf = ToNullTerminatedUtf8(policyJson);
        var commandBuf = ToNullTerminatedUtf8(command);

        unsafe
        {
            fixed (byte* policyPtr = policyBuf)
            fixed (byte* commandPtr = commandBuf)
            {
                MxcRunResult result = default;
                var status = NativeMethods.mxc_run(policyPtr, commandPtr, &result);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        var message = PtrToString(result.error_utf8) ?? "unknown error";
                        throw new MxcException((ErrorCode)status, message);
                    }

                    return new RunResult
                    {
                        ExitCode = result.exit_code,
                        TimedOut = result.timed_out != 0,
                        Stdout = PtrToString(result.stdout_utf8) ?? string.Empty,
                        Stderr = PtrToString(result.stderr_utf8) ?? string.Empty,
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

    private static byte[] ToNullTerminatedUtf8(string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var buffer = new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, 0);
        buffer[byteCount] = 0;
        return buffer;
    }

    private static unsafe string? PtrToString(byte* p) =>
        p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);
}
