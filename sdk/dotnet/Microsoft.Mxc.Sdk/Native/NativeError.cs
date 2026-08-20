// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Sdk.Native;

/// <summary>
/// Turns the native failure detail into an <see cref="MxcException"/>.
/// </summary>
/// <remarks>
/// Shared rather than repeated per call site so every entry point reports a
/// failure the same way. Each field is carried across independently: an
/// operation with no status is a supported and tested shape, so this preserves
/// whatever the native layer supplied per field rather than treating the three
/// as a unit. Absence stays distinguishable from the empty string.
/// </remarks>
internal static unsafe class NativeError
{
    /// <summary>
    /// Build an exception from a native detail.
    /// </summary>
    /// <param name="status">The native status code.</param>
    /// <param name="detail">The detail the native layer filled.</param>
    /// <param name="fallbackMessage">
    /// Used when the native layer supplied no message — which should not happen
    /// on a failure, but leaves the caller with something actionable if it does.
    /// </param>
    internal static MxcException ToException(
        int status,
        MxcErrorDetail detail,
        string fallbackMessage)
    {
        return new MxcException(
            (ErrorCode)status,
            ToStringOrNull(detail.message_utf8) ?? fallbackMessage,
            ToStringOrNull(detail.operation_utf8),
            ToStringOrNull(detail.native_code_utf8),
            ToStringOrNull(detail.remediation_utf8));
    }

    /// <summary>
    /// Marshal a native UTF-8 string, mapping a null pointer to
    /// <see langword="null"/> rather than to the empty string — the native layer
    /// uses null to mean "the API supplied nothing here".
    /// </summary>
    internal static string? ToStringOrNull(byte* p) =>
        p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);
}
