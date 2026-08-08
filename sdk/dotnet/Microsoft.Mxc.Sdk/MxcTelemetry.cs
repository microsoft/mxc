// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Administers MXC's persisted, MXC-owned telemetry consent flag. See
/// docs/telemetry/telemetry-consent-design.md for the full design.
///
/// This is deliberately UI-agnostic: it does not render a consent prompt.
/// A hosting application should call <see cref="NeedsConsentPrompt"/> once
/// (e.g. before its first sandbox run) and, if it returns <c>true</c>, show
/// its own consent UI and then call <see cref="SetConsent"/> with the user's
/// choice. A settings page can call <see cref="GetConsent"/> and
/// <see cref="SetConsent"/> at any later time to let the user change their
/// mind.
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
    /// there, since <see cref="SetConsent"/> could not persist the answer
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

    /// <summary>
    /// Grant or revoke telemetry consent and persist the decision.
    /// </summary>
    /// <param name="granted"><see langword="true"/> to grant, <see langword="false"/> to revoke/deny.</param>
    /// <param name="source">
    /// Optional, free-form provenance for support/debugging (e.g. <c>"prompt"</c>,
    /// <c>"settings-ui"</c>). Never transmitted anywhere. Defaults to <c>"sdk"</c>.
    /// </param>
    /// <exception cref="MxcException">
    /// The decision could not be persisted — always the case on non-Windows
    /// hosts (<see cref="ErrorCode.ConsentWriteFailed"/>), since MXC must not
    /// collect, and therefore must not offer consent for, telemetry there.
    /// </exception>
    public static void SetConsent(bool granted, string? source = null)
    {
        // Windows-only by design; fail here rather than depending on the
        // native layer to refuse, so the contract holds even when mxc_ffi is
        // missing entirely.
        if (!OperatingSystem.IsWindows())
        {
            throw new MxcException(
                ErrorCode.ConsentWriteFailed,
                "telemetry consent could not be persisted (MXC only collects telemetry, and only offers consent, on Windows)");
        }

        var sourceBuf = ToNullTerminatedUtf8(source ?? "sdk");

        try
        {
            unsafe
            {
                fixed (byte* sourcePtr = sourceBuf)
                {
                    var status = NativeMethods.mxc_telemetry_set_consent(granted ? 1 : 0, sourcePtr);
                    if (status != (int)ErrorCode.Success)
                    {
                        throw new MxcException(
                            (ErrorCode)status,
                            status == (int)ErrorCode.ConsentWriteFailed
                                ? "telemetry consent could not be persisted (MXC only collects telemetry, and only offers consent, on Windows)"
                                : "failed to persist telemetry consent");
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not MxcException)
        {
            // A broken install throws DllNotFoundException (and friends) from
            // the marshalling layer. This method documents MxcException as its
            // only failure mode, so convert rather than leak a raw type a host
            // following the contract would not be catching. Unlike the read
            // paths this still throws: the caller asked us to persist a
            // decision and it did not happen, so silence would be a lie.
            ReportFailClosed("SetConsent", "MxcException", ex);
            throw new MxcException(
                ErrorCode.ConsentWriteFailed,
                "telemetry consent could not be persisted (the MXC native library could not be reached)",
                ex);
        }
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
