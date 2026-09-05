// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Administers MXC telemetry consent. See
/// docs/telemetry/telemetry-consent-design.md for the contract.
/// </summary>
public static class MxcTelemetry
{
    internal readonly record struct NativePayloadResult(int Status, string? Payload);
    internal readonly record struct NativeBooleanResult(int Status, bool Value);

    internal interface ITelemetryNativeApi
    {
        NativePayloadResult GetConsent();
        NativeBooleanResult NeedsConsentPrompt();
        NativePayloadResult GetPolicy();
        NativePayloadResult GetConsentStatus();
        NativePayloadResult WithdrawConsent();
        NativePayloadResult RequestConsent(string? locale, Func<string, int> presenter);
    }

    private sealed class PInvokeTelemetryNativeApi : ITelemetryNativeApi
    {
        public unsafe NativePayloadResult GetConsent()
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_get_consent(&value);
            return Payload(status, value);
        }

        public unsafe NativeBooleanResult NeedsConsentPrompt()
        {
            int value = 0;
            var status = NativeMethods.mxc_telemetry_needs_consent_prompt(&value);
            return new(status, value != 0);
        }

        public unsafe NativePayloadResult GetPolicy()
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_get_policy(&value);
            return Payload(status, value);
        }

        public unsafe NativePayloadResult GetConsentStatus()
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_get_consent_status(&value);
            return Payload(status, value);
        }

        public unsafe NativePayloadResult WithdrawConsent()
        {
            byte* value = null;
            var status = NativeMethods.mxc_telemetry_withdraw_consent(&value);
            return Payload(status, value);
        }

        public unsafe NativePayloadResult RequestConsent(string? locale, Func<string, int> presenter)
        {
            var localeBuffer = locale is null ? null : ToNullTerminatedUtf8(locale);
            using var callback = new PresenterCallback(presenter);
            fixed (byte* localePtr = localeBuffer)
            {
                byte* value = null;
                var status = NativeMethods.mxc_telemetry_request_consent(
                    localePtr,
                    &PresentConsent,
                    (void*)GCHandle.ToIntPtr(callback.Handle),
                    &value);
                return Payload(status, value);
            }
        }

        private static unsafe NativePayloadResult Payload(int status, byte* value)
        {
            try
            {
                return new(status, value is null ? null : Marshal.PtrToStringUTF8((IntPtr)value));
            }
            finally
            {
                if (value is not null)
                {
                    NativeMethods.mxc_string_free(value);
                }
            }
        }
    }

    private sealed class PresenterCallback : IDisposable
    {
        private readonly Func<string, int> presenter;
        internal GCHandle Handle { get; }

        internal PresenterCallback(Func<string, int> presenter)
        {
            this.presenter = presenter;
            Handle = GCHandle.Alloc(this);
        }

        internal int Invoke(string prompt)
        {
            try
            {
                return presenter(prompt);
            }
            catch
            {
                return -1;
            }
        }

        public void Dispose() => Handle.Free();
    }

    private static readonly ITelemetryNativeApi DefaultNativeApi = new PInvokeTelemetryNativeApi();
    private static readonly FailureCategoryTracker DefaultFailureCategoryTracker = new(capacity: 64);
    private static ITelemetryNativeApi nativeApi = DefaultNativeApi;
    private static FailureCategoryTracker reportedFailures = DefaultFailureCategoryTracker;
    private static bool? windowsHostOverride;

    internal static IDisposable OverrideNativeApiForTesting(ITelemetryNativeApi replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        if (!ReferenceEquals(
                Interlocked.CompareExchange(ref nativeApi, replacement, DefaultNativeApi),
                DefaultNativeApi))
        {
            throw new InvalidOperationException(
                "A telemetry native API test override is already active.");
        }
        return new NativeApiScope(replacement);
    }

    internal static IDisposable OverrideFailureCategoryTrackerForTesting(
        FailureCategoryTracker replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        if (!ReferenceEquals(
                Interlocked.CompareExchange(
                    ref reportedFailures,
                    replacement,
                    DefaultFailureCategoryTracker),
                DefaultFailureCategoryTracker))
        {
            throw new InvalidOperationException(
                "A failure category tracker test override is already active.");
        }
        return new FailureCategoryTrackerScope(replacement);
    }

    internal static IDisposable OverrideWindowsHostForTesting(bool isWindows)
    {
        var previous = windowsHostOverride;
        windowsHostOverride = isWindows;
        return new Scope(() => windowsHostOverride = previous);
    }

    private static bool IsWindowsHost => windowsHostOverride ?? OperatingSystem.IsWindows();

    private sealed class NativeApiScope(ITelemetryNativeApi replacement) : IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            Interlocked.CompareExchange(ref nativeApi, DefaultNativeApi, replacement);
        }
    }

    private sealed class FailureCategoryTrackerScope(
        FailureCategoryTracker replacement) : IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }
            Interlocked.CompareExchange(
                ref reportedFailures,
                DefaultFailureCategoryTracker,
                replacement);
        }
    }

    private sealed class Scope(Action release) : IDisposable
    {
        private bool released;
        public void Dispose()
        {
            if (!released)
            {
                released = true;
                release();
            }
        }
    }

    static MxcTelemetry()
    {
        NativeLibraryResolver.Initialize();
    }

    /// <summary>
    /// Read effective telemetry consent. Returns <see cref="TelemetryConsentState.NotApplicable"/>
    /// off Windows and <see cref="TelemetryConsentState.Undetermined"/> when consent cannot be
    /// determined.
    /// </summary>
    public static TelemetryConsentState GetConsent()
    {
        if (!IsWindowsHost)
        {
            return TelemetryConsentState.NotApplicable;
        }

        try
        {
            var result = nativeApi.GetConsent();
            EnsureSuccess(result.Status, "failed to read telemetry consent state");
            return ParseConsentState(result.Payload, "GetConsent");
        }
        catch (Exception ex)
        {
            ReportFailClosed("GetConsent", "Undetermined", ex);
            return TelemetryConsentState.Undetermined;
        }
    }

    /// <summary>
    /// Whether an exception indicates that the native library is unavailable.
    /// </summary>
    internal static bool IsNativeLoadFailure(Exception ex) =>
        ex is DllNotFoundException
            or EntryPointNotFoundException
            or TypeInitializationException
            or BadImageFormatException;

    internal sealed class FailureCategoryTracker(int capacity)
    {
        private readonly HashSet<FailureCategory> categories = [];

        private readonly record struct FailureCategory(
            string Operation,
            string SafeResult,
            string Kind,
            int Code);

        internal bool TryAdd(string operation, string safeResult, string kind, int code)
        {
            var category = new FailureCategory(operation, safeResult, kind, code);
            lock (categories)
            {
                if (categories.Contains(category) || categories.Count >= capacity)
                {
                    return false;
                }
                categories.Add(category);
                return true;
            }
        }

        internal void Remove(string operation, string safeResult, string kind, int code)
        {
            lock (categories)
            {
                categories.Remove(new FailureCategory(operation, safeResult, kind, code));
            }
        }
    }

    internal static void ReportFailClosed(
        string operation,
        string safeResult,
        Exception exception)
    {
        var exceptionType = exception.GetType().FullName ?? exception.GetType().Name;
        ReportFailClosedCore(
            operation,
            safeResult,
            exceptionType,
            exception.HResult,
            errorCode: null,
            safeDescription: null);
    }

    internal static void ReportFailClosed(
        string operation,
        string safeResult,
        ErrorCode errorCode)
    {
        ReportFailClosedCore(
            operation,
            safeResult,
            nameof(ErrorCode),
            (int)errorCode,
            errorCode,
            safeDescription: null);
    }

    private static void ReportFailClosedCategory(
        string operation,
        string safeResult,
        string category)
    {
        ReportFailClosedCore(
            operation,
            safeResult,
            category,
            code: 0,
            errorCode: null,
            safeDescription: category);
    }

    private static void ReportFailClosedCore(
        string operation,
        string safeResult,
        string kind,
        int code,
        ErrorCode? errorCode,
        string? safeDescription)
    {
        var registered = false;
        try
        {
            if (!reportedFailures.TryAdd(operation, safeResult, kind, code))
            {
                return;
            }
            registered = true;

            var description = safeDescription ?? (errorCode is { } nativeError
                ? $"{nativeError} ({code})"
                : $"{kind} (HRESULT 0x{code:X8})");
            Trace.TraceError(
                "mxc: {0} failed and is reporting '{1}' to stay fail-closed: {2}",
                operation,
                safeResult,
                description);
        }
        catch
        {
            if (registered)
            {
                reportedFailures.Remove(operation, safeResult, kind, code);
            }
            // Diagnostics must not affect the fail-closed result.
        }
    }

    /// <summary>
    /// Whether the host should show the first-run consent prompt.
    ///
    /// Returns <see langword="false"/> on non-Windows hosts or any failure.
    /// </summary>
    public static bool NeedsConsentPrompt()
    {
        if (!IsWindowsHost)
        {
            return false;
        }

        try
        {
            var result = nativeApi.NeedsConsentPrompt();
            if (result.Status != (int)ErrorCode.Success)
            {
                ReportFailClosed("NeedsConsentPrompt", "false", (ErrorCode)result.Status);
                return false;
            }
            return result.Value;
        }
        catch (Exception ex)
        {
            ReportFailClosed("NeedsConsentPrompt", "false", ex);
            return false;
        }
    }

    /// <summary>
    /// Read the administrative telemetry policy. Failures return
    /// <see cref="TelemetryPolicyState.Blocked"/>.
    /// </summary>
    public static TelemetryPolicyState GetPolicy()
    {
        if (!IsWindowsHost)
        {
            return TelemetryPolicyState.NotApplicable;
        }

        try
        {
            var result = nativeApi.GetPolicy();
            if (result.Status != (int)ErrorCode.Success)
            {
                ReportFailClosed("GetPolicy", "Blocked", (ErrorCode)result.Status);
                return TelemetryPolicyState.Blocked;
            }
            return ParsePolicyState(result.Payload, "GetPolicy");
        }
        catch (Exception ex)
        {
            ReportFailClosed("GetPolicy", "Blocked", ex);
            return TelemetryPolicyState.Blocked;
        }
    }

    private sealed class PresenterContext
    {
        internal required Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> Presenter { get; init; }
        internal required CancellationToken CancellationToken { get; init; }
        internal SynchronizationContext? SynchronizationContext { get; init; }
        internal Exception? Error;
    }

    /// <summary>Request consent through a synchronous host presenter.</summary>
    public static TelemetryConsentOutcome RequestConsent(
        Func<TelemetryConsentPrompt, TelemetryConsentDecision> presenter,
        string? locale = null)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        if (!IsWindowsHost)
        {
            return NotApplicableOutcome();
        }
        return RequestConsentCore(
            prompt => ValueTask.FromResult(presenter(prompt)),
            locale,
            CancellationToken.None,
            synchronizationContext: null);
    }

    /// <summary>
    /// Request consent through an asynchronous host presenter.
    /// </summary>
    /// <remarks>
    /// The native request runs on a worker thread. Await this method rather than
    /// blocking a UI thread that the presenter needs to resume on. Cancellation
    /// stops waiting for the presenter and prevents its decision from being
    /// accepted when observed before native persistence. It does not cancel the
    /// presenter's underlying operation.
    /// </remarks>
    public static Task<TelemetryConsentOutcome> RequestConsentAsync(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        string? locale = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(presenter);
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<TelemetryConsentOutcome>(cancellationToken);
        }
        if (!IsWindowsHost)
        {
            return Task.FromResult(NotApplicableOutcome());
        }
        var synchronizationContext = SynchronizationContext.Current;
        return Task.Factory.StartNew(
            () =>
            {
                var outcome = RequestConsentCore(
                    presenter,
                    locale,
                    cancellationToken,
                    synchronizationContext);
                return FinalizeAsyncOutcome(outcome, cancellationToken);
            },
            cancellationToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
    }

    internal static TelemetryConsentOutcome FinalizeAsyncOutcome(
        TelemetryConsentOutcome outcome,
        CancellationToken cancellationToken)
    {
        if (outcome.Result == TelemetryConsentActionResult.Dismissed)
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
        return outcome;
    }

    /// <summary>Read stored/effective consent and the administrative ceiling.</summary>
    public static TelemetryConsentStatus GetConsentStatus()
    {
        if (!IsWindowsHost)
        {
            return new(
                TelemetryConsentState.NotApplicable,
                TelemetryConsentState.NotApplicable,
                TelemetryPolicyState.NotApplicable);
        }

        try
        {
            var result = nativeApi.GetConsentStatus();
            EnsureSuccess(result.Status, "failed to read telemetry consent status");
            return ParseConsentStatus(result.Payload);
        }
        catch (Exception ex) when (
            ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            ReportFailClosed("GetConsentStatus", "Undetermined/Blocked", ex);
            return new(
                TelemetryConsentState.Undetermined,
                TelemetryConsentState.Undetermined,
                TelemetryPolicyState.Blocked);
        }
        catch (MxcException ex)
        {
            ReportFailClosed("GetConsentStatus", "Undetermined/Blocked", ex);
            return new(
                TelemetryConsentState.Undetermined,
                TelemetryConsentState.Undetermined,
                TelemetryPolicyState.Blocked);
        }
        catch (Exception ex)
        {
            ReportFailClosed("GetConsentStatus", "Undetermined/Blocked", ex);
            return new(
                TelemetryConsentState.Undetermined,
                TelemetryConsentState.Undetermined,
                TelemetryPolicyState.Blocked);
        }
    }

    /// <summary>Idempotently withdraw telemetry consent.</summary>
    public static TelemetryConsentOutcome WithdrawConsent()
    {
        if (!IsWindowsHost)
        {
            return NotApplicableOutcome();
        }
        try
        {
            var result = nativeApi.WithdrawConsent();
            EnsureSuccess(result.Status, "failed to withdraw telemetry consent");
            return ParseConsentOutcome(result.Payload, ConsentOutcomeOperation.Withdraw);
        }
        catch (Exception ex) when (ex is not MxcException)
        {
            throw new MxcException(
                ErrorCode.BackendError,
                "failed to withdraw telemetry consent",
                ex);
        }
    }

    private static TelemetryConsentOutcome RequestConsentCore(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        string? locale,
        CancellationToken cancellationToken,
        SynchronizationContext? synchronizationContext)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var context = new PresenterContext
            {
                Presenter = presenter,
                CancellationToken = cancellationToken,
                SynchronizationContext = synchronizationContext,
            };
            var result = nativeApi.RequestConsent(
                locale,
                promptJson =>
                {
                    try
                    {
                        var prompt = ParseConsentPrompt(promptJson);
                        return InvokePresenterWithCancellation(
                            context.Presenter,
                            prompt,
                            context.SynchronizationContext,
                            context.CancellationToken) switch
                        {
                            TelemetryConsentDecision.No => 0,
                            TelemetryConsentDecision.Yes => 1,
                            TelemetryConsentDecision.Dismissed => 2,
                            _ => -1,
                        };
                    }
                    catch (Exception ex)
                    {
                        Interlocked.CompareExchange(ref context.Error, ex, null);
                        return -1;
                    }
                });
            if (context.Error is OperationCanceledException &&
                cancellationToken.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (context.Error is not null)
            {
                throw new MxcException(
                    ErrorCode.BackendError,
                    "telemetry consent presenter failed",
                    context.Error);
            }
            EnsureSuccess(result.Status, "failed to request telemetry consent");
            return ParseConsentOutcome(result.Payload, ConsentOutcomeOperation.Request);
        }
        catch (Exception ex) when (
            ex is not MxcException and not OperationCanceledException)
        {
            throw new MxcException(
                ErrorCode.BackendError,
                "telemetry consent request failed",
                ex);
        }
    }

    private static TelemetryConsentDecision InvokePresenterWithCancellation(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        TelemetryConsentPrompt prompt,
        SynchronizationContext? synchronizationContext,
        CancellationToken cancellationToken)
    {
        Task<TelemetryConsentDecision>? presenterTask = null;
        try
        {
            presenterTask = InvokePresenterAsync(
                presenter,
                prompt,
                synchronizationContext,
                cancellationToken);
            return presenterTask
                .WaitAsync(cancellationToken)
                .GetAwaiter()
                .GetResult();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (presenterTask is not null)
            {
                ObserveAbandonedPresenterFailure(presenterTask);
            }
            return TelemetryConsentDecision.Dismissed;
        }
    }

    private static void ObserveAbandonedPresenterFailure(
        Task<TelemetryConsentDecision> presenterTask)
    {
        _ = presenterTask.ContinueWith(
            static faulted =>
            {
                var exception = faulted.Exception;
                if (exception is null)
                {
                    return;
                }

                try
                {
                    Trace.TraceError(
                        "MXC telemetry consent presenter faulted after cancellation: {0}",
                        exception.GetBaseException());
                }
                catch
                {
                    // Diagnostic listeners must not fault an unobserved continuation.
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private static Task<TelemetryConsentDecision> InvokePresenterAsync(
        Func<TelemetryConsentPrompt, ValueTask<TelemetryConsentDecision>> presenter,
        TelemetryConsentPrompt prompt,
        SynchronizationContext? synchronizationContext,
        CancellationToken cancellationToken)
    {
        if (synchronizationContext is null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return presenter(prompt).AsTask();
        }

        var completion = new TaskCompletionSource<TelemetryConsentDecision>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            synchronizationContext.Post(
                async _ =>
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        completion.TrySetCanceled(cancellationToken);
                        return;
                    }
                    try
                    {
                        completion.SetResult(await presenter(prompt));
                    }
                    catch (Exception ex)
                    {
                        completion.SetException(ex);
                    }
                },
                null);
        }
        catch (Exception ex)
        {
            completion.SetException(ex);
        }

        return completion.Task;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe int PresentConsent(byte* promptJsonUtf8, void* contextPointer)
    {
        try
        {
            var callback = (PresenterCallback)GCHandle.FromIntPtr((IntPtr)contextPointer).Target!;
            return callback.Invoke(Marshal.PtrToStringUTF8((IntPtr)promptJsonUtf8) ?? string.Empty);
        }
        catch
        {
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

    private static TelemetryConsentOutcome NotApplicableOutcome() =>
        new(
            TelemetryConsentActionResult.NotApplicable,
            TelemetryConsentState.NotApplicable,
            TelemetryConsentState.NotApplicable,
            TelemetryPolicyState.NotApplicable);

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
        if (!IsKnownConsentStatusReason(root.GetProperty("reason"), "GetConsentStatus"))
        {
            return FailClosedStatus();
        }
        if (!TryParseConsentFields(
                root,
                "GetConsentStatus",
                out var storedState,
                out var effectiveState,
                out var policy))
        {
            return FailClosedStatus();
        }
        return new(storedState, effectiveState, policy);
    }

    private enum ConsentOutcomeOperation
    {
        Request,
        Withdraw,
    }

    private static TelemetryConsentOutcome ParseConsentOutcome(
        string? json,
        ConsentOutcomeOperation operation)
    {
        using var document = JsonDocument.Parse(json ?? throw new JsonException("missing consent outcome"));
        var root = document.RootElement;
        var result = ParseConsentActionResult(root.GetProperty("result").GetString());
        var operationName = $"{operation}Consent";
        if (!IsResultForOperation(result, operation) ||
            !IsKnownConsentStatusReason(root.GetProperty("reason"), operationName))
        {
            return FailClosedOutcome();
        }
        if (!TryParseConsentFields(
                root,
                operationName,
                out var storedState,
                out var effectiveState,
                out var policy))
        {
            return FailClosedOutcome();
        }
        return new(result, storedState, effectiveState, policy);
    }

    private static bool IsResultForOperation(
        TelemetryConsentActionResult result,
        ConsentOutcomeOperation operation)
    {
        var valid = operation switch
        {
            ConsentOutcomeOperation.Request =>
                result is TelemetryConsentActionResult.Granted
                    or TelemetryConsentActionResult.Denied
                    or TelemetryConsentActionResult.Dismissed
                    or TelemetryConsentActionResult.AlreadyGranted
                    or TelemetryConsentActionResult.PolicyBlocked
                    or TelemetryConsentActionResult.PresentationUnavailable
                    or TelemetryConsentActionResult.NotApplicable,
            ConsentOutcomeOperation.Withdraw =>
                result is TelemetryConsentActionResult.Withdrawn
                    or TelemetryConsentActionResult.NotApplicable,
            _ => false,
        };
        if (!valid && result != TelemetryConsentActionResult.Unknown)
        {
            ReportFailClosedCategory(
                $"{operation}Consent",
                "Unknown",
                "native returned an invalid consent result");
        }
        return valid;
    }

    private static TelemetryConsentStatus FailClosedStatus() =>
        new(
            TelemetryConsentState.Undetermined,
            TelemetryConsentState.Undetermined,
            TelemetryPolicyState.Blocked);

    private static TelemetryConsentOutcome FailClosedOutcome() =>
        new(
            TelemetryConsentActionResult.Unknown,
            TelemetryConsentState.Undetermined,
            TelemetryConsentState.Undetermined,
            TelemetryPolicyState.Blocked);

    private static bool TryParseConsentFields(
        JsonElement root,
        string operation,
        out TelemetryConsentState storedState,
        out TelemetryConsentState effectiveState,
        out TelemetryPolicyState policy)
    {
        storedState = TelemetryConsentState.Undetermined;
        effectiveState = TelemetryConsentState.Undetermined;
        policy = TelemetryPolicyState.Blocked;

        var storedValue = root.GetProperty("storedState").GetString();
        var parsedStoredState = ParseKnownConsentState(storedValue);
        if (parsedStoredState is null)
        {
            _ = UnrecognizedConsentState(storedValue, operation);
            return false;
        }

        var effectiveValue = root.GetProperty("effectiveState").GetString();
        var parsedEffectiveState = ParseKnownConsentState(effectiveValue);
        if (parsedEffectiveState is null)
        {
            _ = UnrecognizedConsentState(effectiveValue, operation);
            return false;
        }

        var policyValue = root.GetProperty("policy").GetString();
        var parsedPolicy = ParseKnownPolicyState(policyValue);
        if (parsedPolicy is null)
        {
            _ = UnrecognizedPolicyState(policyValue, operation);
            return false;
        }

        storedState = parsedStoredState.Value;
        effectiveState = parsedEffectiveState.Value;
        policy = parsedPolicy.Value;
        return true;
    }

    private static TelemetryConsentActionResult ParseConsentActionResult(string? value) => value switch
    {
        "granted" => TelemetryConsentActionResult.Granted,
        "denied" => TelemetryConsentActionResult.Denied,
        "dismissed" => TelemetryConsentActionResult.Dismissed,
        "withdrawn" => TelemetryConsentActionResult.Withdrawn,
        "alreadyGranted" => TelemetryConsentActionResult.AlreadyGranted,
        "policyBlocked" => TelemetryConsentActionResult.PolicyBlocked,
        "presentationUnavailable" => TelemetryConsentActionResult.PresentationUnavailable,
        "notApplicable" => TelemetryConsentActionResult.NotApplicable,
        _ => UnrecognizedConsentActionResult(value),
    };

    private static TelemetryConsentActionResult UnrecognizedConsentActionResult(string? value)
    {
        ReportFailClosedCategory(
            "ConsentOutcome",
            "Unknown",
            "native returned an unrecognized consent action result");
        return TelemetryConsentActionResult.Unknown;
    }

    private static bool IsKnownConsentStatusReason(
        JsonElement value,
        string operation)
    {
        if (value.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        return value.GetString() switch
        {
            "no-record" or
            "store-unreadable" or
            "store-malformed" or
            "consent-schema-unsupported" or
            "prompt-version-missing" or
            "prompt-version-unsupported" or
            "policy-blocked" or
            "presentation-unavailable" or
            "not-applicable" => true,
            var reason => ReportUnrecognizedConsentStatusReason(reason, operation),
        };
    }

    private static bool ReportUnrecognizedConsentStatusReason(
        string? value,
        string operation)
    {
        ReportFailClosedCategory(
            operation,
            "Unknown",
            "native returned an unrecognized consent status reason");
        return false;
    }

    /// <summary>
    /// Map the native consent string, failing closed for unknown values.
    /// </summary>
    private static TelemetryConsentState? ParseKnownConsentState(string? value) => value switch
    {
        "granted" => TelemetryConsentState.Granted,
        "denied" => TelemetryConsentState.Denied,
        "undetermined" => TelemetryConsentState.Undetermined,
        "not-applicable" => TelemetryConsentState.NotApplicable,
        _ => null,
    };

    private static TelemetryConsentState ParseConsentState(string? value, string operation) =>
        ParseKnownConsentState(value) ?? UnrecognizedConsentState(value, operation);

    private static TelemetryConsentState UnrecognizedConsentState(string? value, string operation)
    {
        ReportFailClosedCategory(
            operation,
            "Undetermined",
            "native returned an unrecognized consent state");
        return TelemetryConsentState.Undetermined;
    }

    /// <summary>
    /// Map the native policy string, failing closed for unknown values.
    /// </summary>
    private static TelemetryPolicyState? ParseKnownPolicyState(string? value) => value switch
    {
        "unrestricted" => TelemetryPolicyState.Unrestricted,
        "allowed" => TelemetryPolicyState.Allowed,
        "blocked" => TelemetryPolicyState.Blocked,
        "not-applicable" => TelemetryPolicyState.NotApplicable,
        _ => null,
    };

    private static TelemetryPolicyState ParsePolicyState(string? value, string operation) =>
        ParseKnownPolicyState(value) ?? UnrecognizedPolicyState(value, operation);

    private static TelemetryPolicyState UnrecognizedPolicyState(string? value, string operation)
    {
        ReportFailClosedCategory(
            operation,
            "Blocked",
            "native returned an unrecognized policy state");
        return TelemetryPolicyState.Blocked;
    }

    private static byte[] ToNullTerminatedUtf8(string value) => System.Text.Encoding.UTF8.GetBytes(value + "\0");
}
