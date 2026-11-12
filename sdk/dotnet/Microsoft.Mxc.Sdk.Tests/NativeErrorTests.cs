// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Native;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
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
        string? remediation = null,
        string? detailsJson = null) =>
        new()
        {
            message_utf8 = Utf8(message),
            operation_utf8 = Utf8(operation),
            native_code_utf8 = Utf8(nativeCode),
            remediation_utf8 = Utf8(remediation),
            details_json_utf8 = Utf8(detailsJson),
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
        Marshal.FreeCoTaskMem((IntPtr)detail.details_json_utf8);
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
            Assert.Null(ex.Details);
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

    [Fact]
    public void MergedPolicyFailuresAndOtherDetailsOutliveNativeMemory()
    {
        const string resourceMarker = "MXC_POLICY_RESOURCE_STRUCTURED_ONLY_7B30AC71";
        const string capabilityMarker = "MXC_POLICY_CAPABILITY_STRUCTURED_ONLY_2AE56531";
        const uint unknownResultVersion = Dev.PolicyFailureVersions.Result + 98;
        const uint unknownMinimumReaderVersion = Dev.PolicyFailureVersions.MinimumReader + 97;
        var failures = new Dev.PolicyFailures
        {
            Results =
            [
                new()
                {
                    Outcome = Dev.PolicyFailureOutcomes.Blocked,
                    Details =
                    [
                        new()
                        {
                            RequestedValue = ulong.MaxValue,
                            RequiredValue = 9_007_199_254_740_993,
                            Resource = resourceMarker,
                        },
                    ],
                },
                new()
                {
                    Version = unknownResultVersion,
                    MinimumReaderVersion = unknownMinimumReaderVersion,
                    Outcome = uint.MaxValue,
                    Details = [new() { FailureClass = uint.MaxValue, Resource = "C:\\data\0" }],
                },
            ],
        };
        var detailsJson = $$$"""
            {"policyFailures":{{{failures.ToJson()}}},"policyFeedbackError":{"code":"feedbackLimitExceeded","reason":"result limit"},
             "policyResultUnavailable":"no new result",
             "other":{"native":[true,18446744073709551615],"capability":"{{{capabilityMarker}}}"}}
            """;
        var detail = Detail("creation refused", "CreateProcessSecurityEnvironment",
            Dev.PolicyFailureNativeCodes.PolicyBlocked, "check policy", detailsJson);
        var warnings = Utf8("""["ordinary native warning"]""");
        MxcException exception;
        ExecutionResult success;
        try
        {
            var result = new MxcRunResult
            {
                error = detail,
                exit_code = 7,
                warnings_json_utf8 = warnings,
            };
            exception = Assert.Throws<MxcException>(
                () => Dev.MxcContainer.ReadRunResult((int)ErrorCode.BackendError, result));
            // Even a success-shaped result must not turn its error details into warnings.
            success = Dev.MxcContainer.ReadRunResult((int)ErrorCode.Success, result);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)warnings);
        }

        Assert.Equal(ErrorCode.BackendError, exception.Code);
        Assert.Equal("creation refused", exception.Message);
        Assert.Equal("CreateProcessSecurityEnvironment", exception.Operation);
        Assert.Equal(Dev.PolicyFailureNativeCodes.PolicyBlocked, exception.NativeCode);
        Assert.Equal("check policy", exception.Remediation);
        Assert.DoesNotContain("policyFailures", exception.ToString());
        Assert.NotNull(exception.StackTrace);
        Assert.Equal(7, success.ExitCode);
        Assert.Equal(new[] { "ordinary native warning" }, success.Warnings);
        var rendered = new[] { exception.Message, exception.ToString(), exception.StackTrace! }
            .Concat(success.Warnings);
        foreach (var text in rendered)
        {
            Assert.DoesNotContain(resourceMarker, text);
            Assert.DoesNotContain(capabilityMarker, text);
            Assert.DoesNotContain("18446744073709551615", text);
            Assert.DoesNotContain("9007199254740993", text);
            Assert.DoesNotContain("feedbackLimitExceeded", text);
            Assert.DoesNotContain("result limit", text);
            Assert.DoesNotContain(failures.ToJson(), text);
        }
        var details = exception.Details!.Value;
        var terminal = details.GetProperty("policyFeedbackError");
        Assert.Equal("feedbackLimitExceeded", terminal.GetProperty("code").GetString());
        Assert.Equal("result limit", terminal.GetProperty("reason").GetString());
        Assert.Equal("no new result", details.GetProperty("policyResultUnavailable").GetString());
        Assert.Equal(ulong.MaxValue, details.GetProperty("other").GetProperty("native")[1].GetUInt64());
        Assert.Equal(capabilityMarker, details.GetProperty("other").GetProperty("capability").GetString());
        var extracted = Dev.PolicyFailures.FromException(exception);
        Assert.NotNull(extracted);
        Assert.Equal(2, extracted.Results.Length);
        Assert.Equal(resourceMarker, extracted.Results[0].Details[0].Resource);
        Assert.Equal(uint.MaxValue, extracted.Results[1].Outcome);
        Assert.Equal(unknownResultVersion, extracted.Results[1].Version);
        Assert.Equal("C:\\data\0", extracted.Results[1].Details[0].Resource);
        Assert.Equal(failures.ToJson(), Dev.PolicyFailures.FromJson(extracted.ToJson()).ToJson());
        Assert.Equal(resourceMarker,
            Dev.PolicyFailures.FromJson(extracted.ToJson()).Results[0].Details[0].Resource);
    }

    [Fact]
    public void MalformedOrNonObjectNativeDetailsAreBackendErrors()
    {
        foreach (var json in new[] { "{", "[]", "null", "\"text\"" })
        {
            var detail = Detail("original error", detailsJson: json);
            try
            {
                var exception = NativeError.ToException(
                    (int)ErrorCode.PolicyValidation, detail, "unused");
                Assert.Equal(ErrorCode.BackendError, exception.Code);
                Assert.Equal("native runtime returned malformed error details", exception.Message);
                Assert.Equal(
                    (int)ErrorCode.PolicyValidation,
                    exception.Details!.Value.GetProperty("ffiStatus").GetInt32());
            }
            finally
            {
                Free(detail);
            }
        }
    }

    [Fact]
    public void PolicyFailureExtractionDistinguishesAbsenceFromMalformedObservations()
    {
        Assert.Null(Dev.PolicyFailures.FromException(new MxcException(ErrorCode.BackendError, "ordinary error")));
        const uint unsupportedFormat = Dev.PolicyFailureVersions.Format + 1;
        foreach (var json in new[]
        {
            """{"other":"retained"}""",
            """{"other":"retained","policyFailures":null}""",
            $$$"""{"other":"retained","policyFailures":{"formatVersion":{{{unsupportedFormat}}},"results":[]}}""",
        })
        {
            var detail = Detail("original error", detailsJson: json);
            try
            {
                var exception = NativeError.ToException((int)ErrorCode.BackendError, detail, "unused");
                if (json.Contains("policyFailures", StringComparison.Ordinal))
                {
                    var extraction = Assert.Throws<MxcException>(() => Dev.PolicyFailures.FromException(exception));
                    Assert.Equal(ErrorCode.BackendError, extraction.Code);
                }
                else
                {
                    Assert.Null(Dev.PolicyFailures.FromException(exception));
                }
                Assert.Equal("original error", exception.Message);
                Assert.Equal("retained", exception.Details!.Value.GetProperty("other").GetString());
            }
            finally
            {
                Free(detail);
            }
        }
    }
}
