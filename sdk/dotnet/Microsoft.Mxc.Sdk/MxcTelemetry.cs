// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Administers MXC's persisted, MXC-owned telemetry consent flag. See
/// docs/telemetry/telemetry-consent-design.md for the full design.
///
/// This is deliberately UI-agnostic: it invokes a host presenter with the
/// complete canonical prompt. Only the typed decision returned from that
/// invocation may be persisted. A host that never requests consent leaves
/// telemetry off. <see cref="WithdrawConsent"/> remains available at any time.
///
/// Prefer <see cref="NeedsConsentPrompt"/> over testing
/// <see cref="GetConsent"/> against
/// <see cref="TelemetryConsentState.Undetermined"/>: only the former also
/// accounts for administrative policy. Under a blocking policy the stored
/// consent is still <see cref="TelemetryConsentState.Undetermined"/>, so
/// branching on <see cref="GetConsent"/> alone would show a prompt that
/// cannot take effect.
/// </summary>
public static class MxcTelemetry
{
    static MxcTelemetry()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>
    /// Read the persisted telemetry consent state. Never throws for "no
    /// decision yet" or "not on Windows"; both are ordinary return values
    /// (<see cref="TelemetryConsentState.Undetermined"/> and
    /// <see cref="TelemetryConsentState.NotApplicable"/> respectively). A
    /// missing or unloadable native library also fails closed to
    /// <see cref="TelemetryConsentState.Undetermined"/> rather than throwing.
    /// </summary>
    /// <exception cref="MxcException">
    /// The native call returned a non-success status — an FFI-local fault
    /// (null out-pointer, caught panic), not an ordinary consent outcome.
    /// </exception>
    public static TelemetryConsentState GetConsent()
    {
        // Windows-only by design: MXC never collects telemetry on other
        // platforms, so there is nothing to consent to. This guard must come
        // first — without it, the catch below would report Undetermined on a
        // macOS/Linux host with no native library, and a host application
        // that prompts on Undetermined would show a telemetry consent prompt
        // on a platform where MXC collects nothing.
        if (!OperatingSystem.IsWindows())
        {
            return TelemetryConsentState.NotApplicable;
        }

        try
        {
            unsafe
            {
                byte* outUtf8 = null;
                var status = NativeMethods.mxc_telemetry_get_consent(&outUtf8);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        // mxc_telemetry_get_consent only ever fails for FFI-local
                        // reasons (null out-pointer, caught panic); it never fails
                        // because of platform or missing consent.
                        throw new MxcException((ErrorCode)status, "failed to read telemetry consent state");
                    }

                    var value = outUtf8 is null ? null : Marshal.PtrToStringUTF8((IntPtr)outUtf8);
                    return ParseConsentState(value);
                }
                finally
                {
                    if (outUtf8 is not null)
                    {
                        NativeMethods.mxc_string_free(outUtf8);
                    }
                }
            }
        }
        catch (Exception ex) when (IsNativeLoadFailure(ex))
        {
            // The native mxc_ffi library is missing, mismatched, or failed to
            // load (e.g. running on a fresh/broken install). GetConsent must
            // not throw for this — treat it the same as "no decision yet".
            ReportFailClosed("GetConsent", "Undetermined", ex);
            return TelemetryConsentState.Undetermined;
        }
        catch (Exception ex) when (ex is not MxcException)
        {
            // Anything unexpected from the marshalling layer is wrapped rather
            // than allowed to escape raw: this method documents MxcException as
            // its only failure mode, and a host that catches that per the
            // contract would otherwise still be taken down by a surprise type.
            ReportFailClosed("GetConsent", "MxcException", ex);
            throw new MxcException(ErrorCode.BackendError, "failed to read telemetry consent state", ex);
        }
    }

    /// <summary>
    /// Whether an exception means "the native mxc_ffi library could not be
    /// loaded or does not export what we need", as opposed to a genuine
    /// failure from inside the native call.
    /// <see cref="EntryPointNotFoundException"/> is included because an older
    /// mxc_ffi that predates the consent entry points loads fine and only
    /// fails at the call — which must fail closed the same way a missing DLL
    /// does, not throw out of a read-only status query.
    /// </summary>
    internal static bool IsNativeLoadFailure(Exception ex) =>
        ex is DllNotFoundException
            or EntryPointNotFoundException
            or TypeInitializationException
            or BadImageFormatException;

    private static readonly HashSet<string> ReportedFailures = new(StringComparer.Ordinal);

    /// <summary>
    /// Report a failure that was swallowed to keep a privacy gate fail-closed.
    ///
    /// These paths deliberately return a safe value instead of throwing, which
    /// would otherwise make a broken install completely silent and
    /// undiagnosable. Reported once per distinct failure per process: a host
    /// may poll these getters (e.g. to render a settings toggle), and a warning
    /// on every call would be noise rather than signal.
    ///
    /// Never throws: it is called from <c>catch</c> blocks whose whole purpose
    /// is to guarantee the caller cannot crash, so an exception escaping here
    /// would defeat the thing it exists to support.
    /// </summary>
    private static void ReportFailClosed(string operation, string safeResult, object detail)
    {
        try
        {
            var message =
                $"mxc: {operation} failed and is reporting '{safeResult}' to stay fail-closed: {detail}";

            lock (ReportedFailures)
            {
                if (!ReportedFailures.Add(message))
                {
                    return;
                }
            }

            Console.Error.WriteLine(message);
        }
        catch
        {
            // Diagnostics must never be able to break the caller.
        }
    }

    /// <summary>
    /// Whether the hosting application should show its own first-run telemetry
    /// consent prompt: <see langword="true"/> only on Windows, when no decision
    /// has been recorded yet.
    ///
    /// The policy behind this answer lives in Rust
    /// (<c>ConsentState::needs_prompt</c>) and is shared with the Node SDK, the
    /// Rust SDK, and the <c>wxc-exec</c> CLI — it is deliberately not
    /// re-derived here from <see cref="GetConsent"/>, so the definition of
    /// "should we ask?" cannot drift between language bindings.
    ///
    /// Always succeeds. Fails closed to <see langword="false"/> (do not prompt)
    /// on any failure — the native library cannot be reached, the native call
    /// reports an error status, or it panics: prompting would be pointless
    /// there, since a consent request could not persist the answer
    /// either. A read-only status query on a privacy gate must never be able to
    /// crash the host, so nothing is allowed to propagate out of this method.
    /// </summary>
    public static bool NeedsConsentPrompt()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            unsafe
            {
                int needsPrompt = 0;
                var status = NativeMethods.mxc_telemetry_needs_consent_prompt(&needsPrompt);
                if (status != (int)ErrorCode.Success)
                {
                    // Fail closed rather than throw. The native layer reports a
                    // non-Success status for FFI-local reasons including a
                    // caught panic, and this method is documented never to
                    // throw — a host calling it on its startup path must not be
                    // brought down by an unreadable consent store.
                    ReportFailClosed("NeedsConsentPrompt", "false", (ErrorCode)status);
                    return false;
                }

                return needsPrompt != 0;
            }
        }
        catch (Exception ex)
        {
            ReportFailClosed("NeedsConsentPrompt", "false", ex);
            return false;
        }
    }

    /// <summary>
    /// Read the administrative (MDM / Group Policy) telemetry policy for this
    /// machine.
    ///
    /// The policy is a ceiling, never a grant:
    /// <see cref="TelemetryPolicyState.Allowed"/> does not mean telemetry is
    /// on, only that an administrator has not forbidden it — an explicit user
    /// consent grant is still required. <see cref="TelemetryPolicyState.Blocked"/>
    /// means nothing is collected regardless of consent, and
    /// <see cref="NeedsConsentPrompt"/> already returns <see langword="false"/>
    /// in that case.
    ///
    /// Exposed so a host can distinguish "the user has not opted in" from
    /// "telemetry is unavailable on this device" and explain the difference,
    /// rather than rendering a toggle that silently does nothing.
    ///
    /// Always succeeds. Fails closed to <see cref="TelemetryPolicyState.Blocked"/>
    /// on any failure — the native library cannot be reached, the native call
    /// reports an error status, or the returned state string is unrecognized —
    /// since nothing can be collected in that state either. A read-only status
    /// query on a privacy gate must never be able to crash the host.
    ///
    /// This is deliberately stricter than <see cref="GetConsent"/>, which still
    /// throws <see cref="MxcException"/> for a genuine native-layer failure.
    /// Consent has two meaningfully different unknowns a caller must be able to
    /// tell apart — "the user has not decided yet" versus "we could not read the
    /// decision" — so collapsing the latter into
    /// <see cref="TelemetryConsentState.Undetermined"/> would make a host prompt
    /// on a broken install. The policy ceiling has no such distinction:
    /// <see cref="TelemetryPolicyState.Blocked"/> is simultaneously the "unknown"
    /// answer and the safe one, so there is nothing to lose by returning it.
    /// </summary>
    public static TelemetryPolicyState GetPolicy()
    {
        if (!OperatingSystem.IsWindows())
        {
            return TelemetryPolicyState.NotApplicable;
        }

        try
        {
            unsafe
            {
                byte* outUtf8 = null;
                var status = NativeMethods.mxc_telemetry_get_policy(&outUtf8);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        // Fail closed rather than throw: this method is
                        // documented never to throw, and a privacy gate that
                        // cannot be read must deny, not crash the host.
                        ReportFailClosed("GetPolicy", "Blocked", (ErrorCode)status);
                        return TelemetryPolicyState.Blocked;
                    }

                    var value = outUtf8 is null ? null : Marshal.PtrToStringUTF8((IntPtr)outUtf8);
                    return ParsePolicyState(value);
                }
                finally
                {
                    if (outUtf8 is not null)
                    {
                        NativeMethods.mxc_string_free(outUtf8);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Catch-all, not just native-load failures: this method is
            // documented never to throw, so anything unexpected from the
            // marshalling layer must fail closed too rather than reach the host.
            ReportFailClosed("GetPolicy", "Blocked", ex);
            return TelemetryPolicyState.Blocked;
        }
    }

    private sealed class PresenterContext
    {
        internal required Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> Presenter { get; init; }
        internal Exception? Error { get; set; }
    }

    /// <summary>Request consent through a synchronous host presenter.</summary>
    public static TelemetryConsentOutcome RequestConsent(
        Func<TelemetryConsentPrompt, TelemetryConsentDecision> presenter,
        string? locale = null)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        return RequestConsentCore(prompt => ValueTask.FromResult(presenter(prompt)), locale);
    }

    /// <summary>Request consent through an asynchronous host presenter.</summary>
    public static Task<TelemetryConsentOutcome> RequestConsentAsync(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        string? locale = null)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        return Task.Run(() => RequestConsentCore(presenter, locale));
    }

    /// <summary>Read stored/effective consent and the administrative ceiling.</summary>
    public static TelemetryConsentStatus GetConsentStatus()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new(
                TelemetryConsentState.NotApplicable,
                TelemetryConsentState.NotApplicable,
                TelemetryConsentStatusReason.NotApplicable,
                TelemetryPolicyState.NotApplicable);
        }

        try
        {
            unsafe
            {
                byte* outUtf8 = null;
                try
                {
                    EnsureSuccess(
                        NativeMethods.mxc_telemetry_get_consent_status(&outUtf8),
                        "failed to read telemetry consent status");
                    return ParseConsentStatus(Marshal.PtrToStringUTF8((IntPtr)outUtf8));
                }
                finally
                {
                    if (outUtf8 is not null)
                    {
                        NativeMethods.mxc_string_free(outUtf8);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            ReportFailClosed("GetConsentStatus", "Undetermined/Blocked", ex);
            return new(
                TelemetryConsentState.Undetermined,
                TelemetryConsentState.Undetermined,
                TelemetryConsentStatusReason.StoreUnreadable,
                TelemetryPolicyState.Blocked);
        }
    }

    /// <summary>Idempotently withdraw telemetry consent.</summary>
    public static TelemetryConsentOutcome WithdrawConsent()
    {
        try
        {
            unsafe
            {
                byte* outUtf8 = null;
                try
                {
                    EnsureSuccess(
                        NativeMethods.mxc_telemetry_withdraw_consent(&outUtf8),
                        "failed to withdraw telemetry consent");
                    return ParseConsentOutcome(Marshal.PtrToStringUTF8((IntPtr)outUtf8));
                }
                finally
                {
                    if (outUtf8 is not null)
                    {
                        NativeMethods.mxc_string_free(outUtf8);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not MxcException)
        {
            throw new MxcException(
                ErrorCode.ConsentWriteFailed,
                "failed to withdraw telemetry consent",
                ex);
        }
    }

    private static TelemetryConsentOutcome RequestConsentCore(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        string? locale)
    {
        var context = new PresenterContext { Presenter = presenter };
        var handle = GCHandle.Alloc(context);
        var localeBuffer = locale is null ? null : ToNullTerminatedUtf8(locale);
        try
        {
            unsafe
            {
                fixed (byte* localePtr = localeBuffer)
                {
                    byte* outUtf8 = null;
                    var status = NativeMethods.mxc_telemetry_request_consent(
                        localePtr,
                        &PresentConsent,
                        (void*)GCHandle.ToIntPtr(handle),
                        &outUtf8);
                    try
                    {
                        if (context.Error is not null)
                        {
                            throw new MxcException(
                                ErrorCode.BackendError,
                                "telemetry consent presenter failed",
                                context.Error);
                        }
                        EnsureSuccess(status, "failed to request telemetry consent");
                        return ParseConsentOutcome(Marshal.PtrToStringUTF8((IntPtr)outUtf8));
                    }
                    finally
                    {
                        if (outUtf8 is not null)
                        {
                            NativeMethods.mxc_string_free(outUtf8);
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not MxcException)
        {
            throw new MxcException(
                ErrorCode.ConsentWriteFailed,
                "telemetry consent request failed",
                ex);
        }
        finally
        {
            handle.Free();
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe int PresentConsent(byte* promptJsonUtf8, void* contextPointer)
    {
        var context = (PresenterContext)GCHandle.FromIntPtr((IntPtr)contextPointer).Target!;
        try
        {
            var prompt = ParseConsentPrompt(Marshal.PtrToStringUTF8((IntPtr)promptJsonUtf8));
            return context.Presenter(prompt).AsTask().GetAwaiter().GetResult() switch
            {
                TelemetryConsentDecision.No => 0,
                TelemetryConsentDecision.Yes => 1,
                TelemetryConsentDecision.Dismissed => 2,
                _ => -1,
            };
        }
        catch (Exception ex)
        {
            context.Error = ex;
            return -1;
        }
    }

    private static void EnsureSuccess(int status, string message)
    {
        if (status != (int)ErrorCode.Success)
        {
            throw new MxcException((ErrorCode)status, message);
        }
    }

    private static TelemetryConsentPrompt ParseConsentPrompt(string? json)
    {
        using var document = JsonDocument.Parse(json ?? throw new JsonException("missing consent prompt"));
        var root = document.RootElement;
        return new(
            root.GetProperty("resourceVersion").GetUInt32(),
            root.GetProperty("locale").GetString() ?? throw new JsonException("missing locale"),
            ParseConsentMessage(root.GetProperty("title")),
            ParseConsentMessage(root.GetProperty("body")),
            ParseConsentMessage(root.GetProperty("affirmativeLabel")),
            ParseConsentMessage(root.GetProperty("negativeLabel")),
            ParseConsentMessage(root.GetProperty("learnMoreLabel")),
            root.GetProperty("learnMoreUrl").GetString() ?? throw new JsonException("missing learn-more URL"));
    }

    private static TelemetryConsentMessage ParseConsentMessage(JsonElement value) =>
        new(
            value.GetProperty("id").GetString() ?? throw new JsonException("missing message id"),
            value.GetProperty("text").GetString() ?? throw new JsonException("missing message text"));

    private static TelemetryConsentStatus ParseConsentStatus(string? json)
    {
        using var document = JsonDocument.Parse(json ?? throw new JsonException("missing consent status"));
        var root = document.RootElement;
        return new(
            ParseConsentState(root.GetProperty("storedState").GetString()),
            ParseConsentState(root.GetProperty("effectiveState").GetString()),
            ParseConsentStatusReason(root.GetProperty("reason")),
            ParsePolicyState(root.GetProperty("policy").GetString()));
    }

    private static TelemetryConsentOutcome ParseConsentOutcome(string? json)
    {
        using var document = JsonDocument.Parse(json ?? throw new JsonException("missing consent outcome"));
        var root = document.RootElement;
        return new(
            ParseConsentActionResult(root.GetProperty("result").GetString()),
            ParseConsentState(root.GetProperty("storedState").GetString()),
            ParseConsentState(root.GetProperty("effectiveState").GetString()),
            ParseConsentStatusReason(root.GetProperty("reason")),
            ParsePolicyState(root.GetProperty("policy").GetString()));
    }

    private static TelemetryConsentActionResult ParseConsentActionResult(string? value) => value switch
    {
        "granted" => TelemetryConsentActionResult.Granted,
        "denied" => TelemetryConsentActionResult.Denied,
        "dismissed" => TelemetryConsentActionResult.Dismissed,
        "withdrawn" => TelemetryConsentActionResult.Withdrawn,
        "already-granted" => TelemetryConsentActionResult.AlreadyGranted,
        "policy-blocked" => TelemetryConsentActionResult.PolicyBlocked,
        "not-applicable" => TelemetryConsentActionResult.NotApplicable,
        _ => throw new JsonException($"unrecognized consent action result '{value ?? "<null>"}'"),
    };

    private static TelemetryConsentStatusReason? ParseConsentStatusReason(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.GetString() switch
        {
            "no-record" => TelemetryConsentStatusReason.NoRecord,
            "store-unreadable" => TelemetryConsentStatusReason.StoreUnreadable,
            "store-malformed" => TelemetryConsentStatusReason.StoreMalformed,
            "consent-schema-unsupported" => TelemetryConsentStatusReason.ConsentSchemaUnsupported,
            "prompt-version-missing" => TelemetryConsentStatusReason.PromptVersionMissing,
            "prompt-version-unsupported" => TelemetryConsentStatusReason.PromptVersionUnsupported,
            "not-applicable" => TelemetryConsentStatusReason.NotApplicable,
            var reason => throw new JsonException($"unrecognized consent status reason '{reason ?? "<null>"}'"),
        };
    }

    /// <summary>
    /// Maps the native consent string. An unrecognised value (including
    /// <see langword="null"/>) falls through to
    /// <see cref="TelemetryConsentState.Undetermined"/> — never a state that
    /// would let collection proceed — and is reported, so a native/binding
    /// version skew is diagnosable instead of silently reading as "no
    /// decision yet".
    /// </summary>
    private static TelemetryConsentState ParseConsentState(string? value) => value switch
    {
        "granted" => TelemetryConsentState.Granted,
        "denied" => TelemetryConsentState.Denied,
        "undetermined" => TelemetryConsentState.Undetermined,
        "not-applicable" => TelemetryConsentState.NotApplicable,
        _ => UnrecognizedConsentState(value),
    };

    private static TelemetryConsentState UnrecognizedConsentState(string? value)
    {
        ReportFailClosed("GetConsent", "Undetermined", $"unrecognized native consent state '{value ?? "<null>"}'");
        return TelemetryConsentState.Undetermined;
    }

    /// <summary>
    /// Maps the native policy string. Unknown values fall through to
    /// <see cref="TelemetryPolicyState.Blocked"/> rather than
    /// <c>Unrestricted</c>: a binding that cannot understand the native
    /// answer must not report the permissive one. The mismatch is reported
    /// so the skew is diagnosable.
    /// </summary>
    private static TelemetryPolicyState ParsePolicyState(string? value) => value switch
    {
        "unrestricted" => TelemetryPolicyState.Unrestricted,
        "allowed" => TelemetryPolicyState.Allowed,
        "blocked" => TelemetryPolicyState.Blocked,
        "not-applicable" => TelemetryPolicyState.NotApplicable,
        _ => UnrecognizedPolicyState(value),
    };

    private static TelemetryPolicyState UnrecognizedPolicyState(string? value)
    {
        ReportFailClosed("GetPolicy", "Blocked", $"unrecognized native policy state '{value ?? "<null>"}'");
        return TelemetryPolicyState.Blocked;
    }

    private static byte[] ToNullTerminatedUtf8(string value) => System.Text.Encoding.UTF8.GetBytes(value + "\0");
}
