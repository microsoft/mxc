// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>The user's recorded telemetry consent decision.</summary>
public enum TelemetryConsentState
{
    Granted,
    Denied,
    Undetermined,
    NotApplicable,
}

/// <summary>The administrative telemetry policy for this machine.</summary>
public enum TelemetryPolicyState
{
    Unrestricted,
    Allowed,
    Blocked,
    NotApplicable,
}

/// <summary>The presenter decision returned to MXC.</summary>
public enum TelemetryConsentDecision
{
    No,
    Yes,
    Dismissed,
}

/// <summary>Why stored consent is not currently effective.</summary>
public enum TelemetryConsentStatusReason
{
    NoRecord,
    StoreUnreadable,
    StoreMalformed,
    ConsentSchemaUnsupported,
    PromptVersionMissing,
    PromptVersionUnsupported,
    NotApplicable,
}

/// <summary>Result of a consent request or withdrawal.</summary>
public enum TelemetryConsentResult
{
    Granted,
    Denied,
    Dismissed,
    Withdrawn,
    AlreadyGranted,
    PolicyBlocked,
    NotApplicable,
}

/// <summary>One canonical consent message.</summary>
public sealed class TelemetryConsentMessage
{
    public string Id { get; init; } = string.Empty;
    public string Text { get; init; } = string.Empty;
}

/// <summary>The canonical consent prompt resource passed to a host presenter.</summary>
public sealed class TelemetryConsentPrompt
{
    public uint ResourceVersion { get; init; }
    public string Locale { get; init; } = string.Empty;
    public TelemetryConsentMessage Title { get; init; } = new();
    public TelemetryConsentMessage Body { get; init; } = new();
    public TelemetryConsentMessage AffirmativeLabel { get; init; } = new();
    public TelemetryConsentMessage NegativeLabel { get; init; } = new();
    public TelemetryConsentMessage LearnMoreLabel { get; init; } = new();
    public string LearnMoreUrl { get; init; } = string.Empty;
}

/// <summary>Stored and effective consent plus the current administrative policy.</summary>
public sealed class TelemetryConsentStatus
{
    public TelemetryConsentState StoredState { get; init; }
    public TelemetryConsentState EffectiveState { get; init; }
    public TelemetryConsentStatusReason? Reason { get; init; }
    public TelemetryPolicyState Policy { get; init; }
}

/// <summary>Telemetry consent action result with the resulting status snapshot.</summary>
public sealed class TelemetryConsentOutcome
{
    public TelemetryConsentResult Result { get; init; }
    public TelemetryConsentState StoredState { get; init; }
    public TelemetryConsentState EffectiveState { get; init; }
    public TelemetryConsentStatusReason? Reason { get; init; }
    public TelemetryPolicyState Policy { get; init; }
}

/// <summary>Telemetry consent helpers over the native <c>mxc_ffi</c> surface.</summary>
public static class MxcTelemetry
{
    private const int NativeConsentDecisionNo = 0;
    private const int NativeConsentDecisionYes = 1;
    private const int NativeConsentDecisionDismissed = 2;
    private const int NativeConsentPresenterError = -1;

    private sealed class PresenterContext
    {
        public required Func<TelemetryConsentPrompt, TelemetryConsentDecision> Presenter { get; init; }
    }

    /// <summary>
    /// Return the user's recorded consent state.
    /// Fail-closed native-load failures return <see cref="TelemetryConsentState.Undetermined"/>.
    /// </summary>
    public static TelemetryConsentState GetConsent()
    {
        try
        {
            EnsureNativeInitialized();
            unsafe
            {
                byte* value = null;
                var status = NativeMethods.mxc_telemetry_get_consent(&value);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        throw new MxcException((ErrorCode)status, "retrieving telemetry consent failed");
                    }

                    return ParseConsentState(ReadNativeUtf8(value) ?? "undetermined");
                }
                finally
                {
                    FreeNativeString(value);
                }
            }
        }
        catch (MxcException)
        {
            throw;
        }
        catch
        {
            return TelemetryConsentState.Undetermined;
        }
    }

    /// <summary>
    /// Read stored and effective consent, plus the current administrative policy.
    /// </summary>
    public static TelemetryConsentStatus GetConsentStatus()
    {
        EnsureNativeInitialized();
        unsafe
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_get_consent_status(&value);
            try
            {
                EnsureSuccess(
                    status,
                    "retrieving telemetry consent status failed",
                    ReadNativeUtf8(value));
                return ParseConsentStatus(ReadRequiredJson(value, "telemetry consent status"));
            }
            finally
            {
                FreeNativeString(value);
            }
        }
    }

    /// <summary>
    /// Invoke a host presenter, then persist its decision.
    /// </summary>
    public static TelemetryConsentOutcome RequestConsent(
        Func<TelemetryConsentPrompt, TelemetryConsentDecision> presenter,
        string? locale = null)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        EnsureNativeInitialized();

        var localeBuf = locale is null ? null : ToNullTerminatedUtf8(locale);
        var presenterContext = GCHandle.Alloc(new PresenterContext { Presenter = presenter });
        try
        {
            unsafe
            {
                fixed (byte* localePtr = localeBuf)
                {
                    byte* value = null;
                    var status = NativeMethods.mxc_telemetry_request_consent(
                        localePtr,
                        &PresentConsentBridge,
                        (void*)GCHandle.ToIntPtr(presenterContext),
                        &value);
                    try
                    {
                        EnsureSuccess(
                            status,
                            "requesting telemetry consent failed",
                            ReadNativeUtf8(value));
                        return ParseConsentOutcome(ReadRequiredJson(value, "telemetry consent outcome"));
                    }
                    finally
                    {
                        FreeNativeString(value);
                    }
                }
            }
        }
        finally
        {
            presenterContext.Free();
        }
    }

    /// <summary>
    /// Asynchronous wrapper over <see cref="RequestConsent(Func{TelemetryConsentPrompt, TelemetryConsentDecision}, string?)"/>.
    /// The native API is synchronous and blocking, so this offloads the whole call to the thread pool.
    /// </summary>
    public static Task<TelemetryConsentOutcome> RequestConsentAsync(
        Func<TelemetryConsentPrompt, Task<TelemetryConsentDecision>> presenter,
        string? locale = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        return Task.Run(
            () => RequestConsent(
                prompt => presenter(prompt).ConfigureAwait(false).GetAwaiter().GetResult(),
                locale),
            cancellationToken);
    }

    /// <summary>Persist an idempotent telemetry-consent withdrawal.</summary>
    public static TelemetryConsentOutcome WithdrawConsent()
    {
        EnsureNativeInitialized();
        unsafe
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_withdraw_consent(&value);
            try
            {
                EnsureSuccess(
                    status,
                    "withdrawing telemetry consent failed",
                    ReadNativeUtf8(value));
                return ParseConsentOutcome(ReadRequiredJson(value, "telemetry consent outcome"));
            }
            finally
            {
                FreeNativeString(value);
            }
        }
    }

    /// <summary>
    /// Whether a host should show its first-run consent prompt.
    /// Fails closed to <see langword="false"/> and never throws.
    /// </summary>
    public static bool NeedsConsentPrompt()
    {
        try
        {
            EnsureNativeInitialized();
            unsafe
            {
                int needsPrompt = 0;
                var status = NativeMethods.mxc_telemetry_needs_consent_prompt(&needsPrompt);
                return status == (int)ErrorCode.Success && needsPrompt != 0;
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Read the administrative telemetry policy.
    /// Fails closed to <see cref="TelemetryPolicyState.Blocked"/> and never throws.
    /// </summary>
    public static TelemetryPolicyState GetPolicy()
    {
        try
        {
            EnsureNativeInitialized();
            unsafe
            {
                byte* value = null;
                var status = NativeMethods.mxc_telemetry_get_policy(&value);
                try
                {
                    if (status != (int)ErrorCode.Success)
                    {
                        return TelemetryPolicyState.Blocked;
                    }

                    return ParsePolicyState(ReadNativeUtf8(value) ?? "blocked");
                }
                finally
                {
                    FreeNativeString(value);
                }
            }
        }
        catch
        {
            return TelemetryPolicyState.Blocked;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe int PresentConsentBridge(byte* promptJsonUtf8, void* context)
    {
        try
        {
            var handle = GCHandle.FromIntPtr((IntPtr)context);
            if (handle.Target is not PresenterContext presenterContext)
            {
                return NativeConsentPresenterError;
            }

            var prompt = ParseConsentPrompt(ReadRequiredJson(promptJsonUtf8, "telemetry consent prompt"));
            return presenterContext.Presenter(prompt) switch
            {
                TelemetryConsentDecision.Yes => NativeConsentDecisionYes,
                TelemetryConsentDecision.No => NativeConsentDecisionNo,
                TelemetryConsentDecision.Dismissed => NativeConsentDecisionDismissed,
                _ => NativeConsentPresenterError,
            };
        }
        catch
        {
            return NativeConsentPresenterError;
        }
    }

    private static void EnsureNativeInitialized() => NativeLibraryResolver.Initialize();

    private static void EnsureSuccess(int status, string fallbackMessage, string? nativeMessage)
    {
        if (status == (int)ErrorCode.Success)
        {
            return;
        }

        throw new MxcException(
            (ErrorCode)status,
            string.IsNullOrWhiteSpace(nativeMessage) ? fallbackMessage : nativeMessage);
    }

    private static unsafe string ReadRequiredJson(byte* value, string description) =>
        ReadNativeUtf8(value) ?? throw new MxcException(ErrorCode.BackendError, $"{description} was missing");

    private static unsafe string? ReadNativeUtf8(byte* value) =>
        value is null ? null : Marshal.PtrToStringUTF8((IntPtr)value);

    private static unsafe void FreeNativeString(byte* value)
    {
        if (value is not null)
        {
            NativeMethods.mxc_string_free(value);
        }
    }

    private static byte[] ToNullTerminatedUtf8(string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var buffer = new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, 0);
        buffer[byteCount] = 0;
        return buffer;
    }

    private static TelemetryConsentPrompt ParseConsentPrompt(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        return new TelemetryConsentPrompt
        {
            ResourceVersion = root.GetProperty("resourceVersion").GetUInt32(),
            Locale = root.GetProperty("locale").GetString() ?? string.Empty,
            Title = ParseConsentMessage(root.GetProperty("title")),
            Body = ParseConsentMessage(root.GetProperty("body")),
            AffirmativeLabel = ParseConsentMessage(root.GetProperty("affirmativeLabel")),
            NegativeLabel = ParseConsentMessage(root.GetProperty("negativeLabel")),
            LearnMoreLabel = ParseConsentMessage(root.GetProperty("learnMoreLabel")),
            LearnMoreUrl = root.GetProperty("learnMoreUrl").GetString() ?? string.Empty,
        };
    }

    private static TelemetryConsentMessage ParseConsentMessage(JsonElement value) => new()
    {
        Id = value.GetProperty("id").GetString() ?? string.Empty,
        Text = value.GetProperty("text").GetString() ?? string.Empty,
    };

    private static TelemetryConsentStatus ParseConsentStatus(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return ParseConsentStatus(doc.RootElement);
    }

    private static TelemetryConsentStatus ParseConsentStatus(JsonElement root) => new()
    {
        StoredState = ParseConsentState(root.GetProperty("storedState").GetString() ?? string.Empty),
        EffectiveState = ParseConsentState(root.GetProperty("effectiveState").GetString() ?? string.Empty),
        Reason = root.TryGetProperty("reason", out var reason) && reason.ValueKind != JsonValueKind.Null
            ? ParseConsentStatusReason(reason.GetString() ?? string.Empty)
            : null,
        Policy = ParsePolicyState(root.GetProperty("policy").GetString() ?? string.Empty),
    };

    private static TelemetryConsentOutcome ParseConsentOutcome(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var status = ParseConsentStatus(root);
        return new TelemetryConsentOutcome
        {
            Result = ParseConsentResult(root.GetProperty("result").GetString() ?? string.Empty),
            StoredState = status.StoredState,
            EffectiveState = status.EffectiveState,
            Reason = status.Reason,
            Policy = status.Policy,
        };
    }

    private static TelemetryConsentState ParseConsentState(string value) => value switch
    {
        "granted" => TelemetryConsentState.Granted,
        "denied" => TelemetryConsentState.Denied,
        "undetermined" => TelemetryConsentState.Undetermined,
        "not-applicable" => TelemetryConsentState.NotApplicable,
        _ => throw new JsonException($"unknown telemetry consent state '{value}'"),
    };

    private static TelemetryPolicyState ParsePolicyState(string value) => value switch
    {
        "unrestricted" => TelemetryPolicyState.Unrestricted,
        "allowed" => TelemetryPolicyState.Allowed,
        "blocked" => TelemetryPolicyState.Blocked,
        "not-applicable" => TelemetryPolicyState.NotApplicable,
        _ => throw new JsonException($"unknown telemetry policy state '{value}'"),
    };

    private static TelemetryConsentStatusReason ParseConsentStatusReason(string value) => value switch
    {
        "no-record" => TelemetryConsentStatusReason.NoRecord,
        "store-unreadable" => TelemetryConsentStatusReason.StoreUnreadable,
        "store-malformed" => TelemetryConsentStatusReason.StoreMalformed,
        "consent-schema-unsupported" => TelemetryConsentStatusReason.ConsentSchemaUnsupported,
        "prompt-version-missing" => TelemetryConsentStatusReason.PromptVersionMissing,
        "prompt-version-unsupported" => TelemetryConsentStatusReason.PromptVersionUnsupported,
        "not-applicable" => TelemetryConsentStatusReason.NotApplicable,
        _ => throw new JsonException($"unknown telemetry consent status reason '{value}'"),
    };

    private static TelemetryConsentResult ParseConsentResult(string value) => value switch
    {
        "granted" => TelemetryConsentResult.Granted,
        "denied" => TelemetryConsentResult.Denied,
        "dismissed" => TelemetryConsentResult.Dismissed,
        "withdrawn" => TelemetryConsentResult.Withdrawn,
        "alreadyGranted" => TelemetryConsentResult.AlreadyGranted,
        "policyBlocked" => TelemetryConsentResult.PolicyBlocked,
        "notApplicable" => TelemetryConsentResult.NotApplicable,
        _ => throw new JsonException($"unknown telemetry consent result '{value}'"),
    };
}
