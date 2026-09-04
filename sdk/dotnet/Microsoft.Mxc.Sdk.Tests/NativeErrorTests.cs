// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.Native;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The marshalling step itself: a populated native detail becoming an
/// <see cref="MxcException"/>.
/// </summary>
/// <remarks>
/// <see cref="MxcExceptionTests"/> covers the halves either side of this one —
/// the managed exception's own behaviour, and the all-null detail that a
/// library-raised failure produces. Neither reaches
/// <c>NativeError.ToException</c> with the call fields filled, because the
/// native layer only fills them when a real platform API fails, which needs a
/// prepared host and a backend. So nothing pinned the field-to-property
/// mapping: transposing <c>operation_utf8</c> and <c>native_code_utf8</c> in
/// the marshalling left the whole suite green. Every value below is distinct
/// so that a transposition fails.
/// </remarks>
public unsafe class NativeErrorTests
{
    /// <summary>
    /// Allocate a native UTF-8 string, keeping <see langword="null"/> distinct
    /// from the empty string — the distinction the native contract rests on.
    /// </summary>
    private static byte* Utf8(string? value) =>
        value is null ? null : (byte*)Marshal.StringToCoTaskMemUTF8(value);

    private static MxcErrorDetail Detail(
        string? message,
        string? operation = null,
        string? nativeCode = null,
        string? remediation = null) =>
        new()
        {
            message_utf8 = Utf8(message),
            operation_utf8 = Utf8(operation),
            native_code_utf8 = Utf8(nativeCode),
            remediation_utf8 = Utf8(remediation),
        };

    /// <summary>
    /// Releases what <see cref="Utf8"/> allocated. Freeing a null pointer is a
    /// no-op, so every field can be released unconditionally.
    /// </summary>
    /// <remarks>
    /// Test-owned memory: it was allocated here, so it is freed here. Product
    /// code never does this — a real detail is allocated by the native layer and
    /// released back to it, by <c>mxc_error_detail_free</c> when the detail
    /// stands alone or by the owning result's free function when it is embedded
    /// in one, because only the allocator that produced a pointer can free it.
    /// </remarks>
    private static void Free(MxcErrorDetail detail)
    {
        Marshal.FreeCoTaskMem((IntPtr)detail.message_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.operation_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.native_code_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.remediation_utf8);
    }

    [Fact]
    public void EachNativeFieldLandsOnItsOwnProperty()
    {
        var detail = Detail(
            "The provision was not found.",
            "IsoSessionOps.StopSessionAsync",
            "0x80070490",
            "Provision the session first.");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "unused fallback");

            Assert.Equal(ErrorCode.BackendError, ex.Code);
            Assert.Equal("The provision was not found.", ex.Message);
            Assert.Equal("IsoSessionOps.StopSessionAsync", ex.Operation);
            Assert.Equal("0x80070490", ex.NativeCode);
            Assert.Equal("Provision the session first.", ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void AnAbsentFieldBecomesNullAndAnEmptyOneStaysEmpty()
    {
        // The native layer uses null for "the API supplied nothing here" and
        // reserves the empty string for "it supplied an empty value". Marshalling
        // must not collapse the two, or a caller cannot tell them apart.
        var detail = Detail("boom", "Iface.Call", nativeCode: string.Empty);

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "unused fallback");

            Assert.Equal("Iface.Call", ex.Operation);
            Assert.Equal(string.Empty, ex.NativeCode);
            Assert.Null(ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void AMessagelessDetailFallsBackRatherThanThrowingOrReportingNothing()
    {
        // Should not happen on a failure, but a null message must still leave
        // the caller with something actionable rather than an empty exception.
        var detail = Detail(null, "Iface.Call");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "the fallback");

            Assert.Equal("the fallback", ex.Message);
            Assert.Equal("Iface.Call", ex.Operation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void TheStatusCodeCrossesAsTheErrorCode()
    {
        var detail = Detail("bad json");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.MalformedRequest, detail, "unused fallback");

            Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
            Assert.Null(ex.Operation);
            Assert.Null(ex.NativeCode);
            Assert.Null(ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }
}
