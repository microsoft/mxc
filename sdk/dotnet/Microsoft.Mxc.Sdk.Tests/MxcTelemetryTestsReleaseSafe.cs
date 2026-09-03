// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

[Collection("MxcTelemetry")]
public sealed class MxcTelemetryTestsReleaseSafe
{
    private static string ConsentPromptJson() =>
        """
        {"resourceVersion":1,"locale":"en-US","title":{"id":"title","text":"Help improve MXC"},"body":{"id":"body","text":"body"},"affirmativeLabel":{"id":"yes","text":"Yes"},"negativeLabel":{"id":"no","text":"No"},"learnMoreLabel":{"id":"learn","text":"Learn more"},"learnMoreUrl":"https://example.microsoft.com/privacy"}
        """;

    private static string ConsentOutcomeJson(string result, string storedState, string effectiveState, string policy = "unrestricted") =>
        $$"""{"result":"{{result}}","storedState":"{{storedState}}","effectiveState":"{{effectiveState}}","reason":null,"policy":"{{policy}}"}""";

    private static string ConsentStatusJson(string storedState, string effectiveState, string policy, string? reason = null)
    {
        var reasonJson = reason is null ? "null" : $"\"{reason}\"";
        return $$"""{"storedState":"{{storedState}}","effectiveState":"{{effectiveState}}","reason":{{reasonJson}},"policy":"{{policy}}"}""";
    }

    [Fact]
    public void MockedTelemetrySeam_ExercisesThePublicStatusApisWithoutNativeBits()
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentImpl = () => new((int)ErrorCode.Success, "granted"),
            NeedsConsentPromptImpl = () => new((int)ErrorCode.Success, true),
            GetPolicyImpl = () => new((int)ErrorCode.Success, "allowed"),
            GetConsentStatusImpl = () => new((int)ErrorCode.Success, ConsentStatusJson("granted", "granted", "allowed")),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
        Assert.True(MxcTelemetry.NeedsConsentPrompt());
        Assert.Equal(TelemetryPolicyState.Allowed, MxcTelemetry.GetPolicy());

        var status = MxcTelemetry.GetConsentStatus();
        Assert.Equal(TelemetryConsentState.Granted, status.StoredState);
        Assert.Equal(TelemetryConsentState.Granted, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Allowed, status.Policy);
    }

    [Theory]
    [InlineData(typeof(DllNotFoundException), TelemetryConsentState.Undetermined)]
    [InlineData(typeof(EntryPointNotFoundException), TelemetryConsentState.Undetermined)]
    [InlineData(typeof(BadImageFormatException), TelemetryConsentState.Undetermined)]
    public void GetConsent_NativeLoadFailuresFailClosedThroughThePublicApi(Type exceptionType, TelemetryConsentState expected)
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentImpl = () => throw (Exception)Activator.CreateInstance(exceptionType)!,
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        Assert.Equal(expected, MxcTelemetry.GetConsent());
    }

    [Fact]
    public void ReadOnlyQueries_NeverThrow_WhenTheNativeLayerFails()
    {
        var native = new FakeTelemetryNativeApi
        {
            NeedsConsentPromptImpl = () => new((int)ErrorCode.Panic, false),
            GetPolicyImpl = () => throw new DllNotFoundException("missing mxc_ffi"),
            GetConsentStatusImpl = () => new((int)ErrorCode.Success, "{"),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        Assert.False(MxcTelemetry.NeedsConsentPrompt());
        Assert.Equal(TelemetryPolicyState.Blocked, MxcTelemetry.GetPolicy());
        var status = MxcTelemetry.GetConsentStatus();
        Assert.Equal(TelemetryConsentState.Undetermined, status.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Fact]
    public void GetConsentStatus_NativeFailureDoesNotClaimTheStoreWasUnreadable()
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentStatusImpl = () => new((int)ErrorCode.Panic, null),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var status = MxcTelemetry.GetConsentStatus();
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Fact]
    public void RequestConsent_PresenterExceptionsPropagateWithTheOriginalCause()
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(-1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.BackendError, null);
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var ex = Assert.Throws<MxcException>(() => MxcTelemetry.RequestConsent(_ => throw new InvalidOperationException("UI unavailable")));
        Assert.Equal(ErrorCode.BackendError, ex.Code);
        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Equal("UI unavailable", ex.InnerException!.Message);
    }

    [Fact]
    public async Task RequestConsentAsync_CancellationStopsWaitingForThePresenter()
    {
        var presenterEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var presenterCompletion = new TaskCompletionSource<TelemetryConsentDecision>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(-1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.BackendError, null);
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);
        using var cancellation = new CancellationTokenSource();

        var request = MxcTelemetry.RequestConsentAsync(
            _ =>
            {
                presenterEntered.SetResult();
                return new ValueTask<TelemetryConsentDecision>(presenterCompletion.Task);
            },
            cancellationToken: cancellation.Token);
        await presenterEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
    }

    [Fact]
    public async Task RequestConsentAsync_CancellationBeforeUiDispatchSkipsPresenter()
    {
        var synchronizationContext = new QueuedSynchronizationContext();
        var presenterCalls = 0;
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(-1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.BackendError, null);
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);
        using var cancellation = new CancellationTokenSource();

        var previousContext = SynchronizationContext.Current;
        Task<TelemetryConsentOutcome> request;
        try
        {
            SynchronizationContext.SetSynchronizationContext(synchronizationContext);
            request = MxcTelemetry.RequestConsentAsync(
                _ =>
                {
                    presenterCalls += 1;
                    return ValueTask.FromResult(TelemetryConsentDecision.Yes);
                },
                cancellationToken: cancellation.Token);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }

        await synchronizationContext.WaitForPostAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);

        synchronizationContext.RunAll();
        Assert.Equal(0, presenterCalls);
    }

    [Fact]
    public async Task RequestConsentAsync_PostSuccessCancellationDoesNotHidePersistence()
    {
        using var cancellation = new CancellationTokenSource();
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                cancellation.Cancel();
                return new(
                    (int)ErrorCode.Success,
                    ConsentOutcomeJson("granted", "granted", "granted", "unrestricted"));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = await MxcTelemetry.RequestConsentAsync(
            _ => ValueTask.FromResult(TelemetryConsentDecision.Yes),
            cancellationToken: cancellation.Token);

        Assert.Equal(TelemetryConsentActionResult.Granted, outcome.Result);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("""{"storedState":"granted"}""")]
    [InlineData("""{"storedState":"granted","effectiveState":"granted","reason":null}""")]
    public void GetConsentStatus_MalformedOrTruncatedJsonFailsClosed(string payload)
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentStatusImpl = () => new((int)ErrorCode.Success, payload),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var status = MxcTelemetry.GetConsentStatus();
        Assert.Equal(TelemetryConsentState.Undetermined, status.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Theory]
    [InlineData("alreadyGranted", TelemetryConsentActionResult.AlreadyGranted)]
    [InlineData("policyBlocked", TelemetryConsentActionResult.PolicyBlocked)]
    [InlineData("notApplicable", TelemetryConsentActionResult.NotApplicable)]
    public void RequestConsent_ParsesCamelCaseWireResults(string result, TelemetryConsentActionResult expected)
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.Success, ConsentOutcomeJson(result, "undetermined", "undetermined", "blocked"));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);
        Assert.Equal(expected, outcome.Result);
    }

    [Fact]
    public void RequestConsent_UnknownWireResultReturnsFailClosedSentinel()
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new(
                    (int)ErrorCode.Success,
                    ConsentOutcomeJson("futureResult", "granted", "granted", "allowed"));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Fact]
    public void WithdrawConsent_UnknownWireResultReturnsFailClosedSentinel()
    {
        var native = new FakeTelemetryNativeApi
        {
            WithdrawConsentImpl = () => new(
                (int)ErrorCode.Success,
                ConsentOutcomeJson("futureResult", "granted", "granted", "allowed")),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.WithdrawConsent();

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Fact]
    public void RequestConsent_WithdrawnResultReturnsFailClosedSentinel()
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new(
                    (int)ErrorCode.Success,
                    ConsentOutcomeJson("withdrawn", "granted", "granted", "allowed"));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Theory]
    [InlineData("granted")]
    [InlineData("denied")]
    [InlineData("dismissed")]
    [InlineData("alreadyGranted")]
    [InlineData("policyBlocked")]
    [InlineData("presentationUnavailable")]
    public void WithdrawConsent_RequestResultReturnsFailClosedSentinel(string result)
    {
        var native = new FakeTelemetryNativeApi
        {
            WithdrawConsentImpl = () => new(
                (int)ErrorCode.Success,
                ConsentOutcomeJson(result, "granted", "granted", "allowed")),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.WithdrawConsent();

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Fact]
    public void RequestConsent_UnknownWireReasonReturnsFailClosedSentinel()
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new(
                    (int)ErrorCode.Success,
                    """{"result":"granted","storedState":"granted","effectiveState":"granted","reason":"future-reason","policy":"allowed"}""");
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{")]
    [InlineData("""{"result":"granted"}""")]
    public void RequestConsent_MalformedSuccessPayloadIsBackendError(string? payload)
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.Success, payload);
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var ex = Assert.Throws<MxcException>(
            () => MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes));
        Assert.Equal(ErrorCode.BackendError, ex.Code);
        Assert.NotNull(ex.InnerException);
    }

    [Theory]
    [InlineData("policy-blocked")]
    [InlineData("presentation-unavailable")]
    public void GetConsentStatus_AcceptsPrivateStatusReasons(string reason)
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentStatusImpl = () => new(
                (int)ErrorCode.Success,
                ConsentStatusJson("undetermined", "undetermined", "blocked", reason)),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var status = MxcTelemetry.GetConsentStatus();
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Fact]
    public void GetConsentStatus_UnknownWireReasonReturnsFailClosedSentinel()
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentStatusImpl = () => new(
                (int)ErrorCode.Success,
                ConsentStatusJson("granted", "granted", "allowed", "future-reason")),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var status = MxcTelemetry.GetConsentStatus();

        Assert.Equal(TelemetryConsentState.Undetermined, status.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Theory]
    [InlineData("future-state", "granted", "allowed")]
    [InlineData("granted", "future-state", "allowed")]
    [InlineData("granted", "granted", "future-policy")]
    public void GetConsentStatus_UnknownFieldReturnsWholeFailClosedSentinel(
        string storedState,
        string effectiveState,
        string policy)
    {
        var native = new FakeTelemetryNativeApi
        {
            GetConsentStatusImpl = () => new(
                (int)ErrorCode.Success,
                ConsentStatusJson(storedState, effectiveState, policy)),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var status = MxcTelemetry.GetConsentStatus();

        Assert.Equal(TelemetryConsentState.Undetermined, status.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
    }

    [Theory]
    [InlineData("future-state", "granted", "allowed")]
    [InlineData("granted", "future-state", "allowed")]
    [InlineData("granted", "granted", "future-policy")]
    public void RequestConsent_UnknownFieldReturnsWholeFailClosedSentinel(
        string storedState,
        string effectiveState,
        string policy)
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new(
                    (int)ErrorCode.Success,
                    ConsentOutcomeJson("granted", storedState, effectiveState, policy));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var outcome = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);

        Assert.Equal(TelemetryConsentActionResult.Unknown, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Fact]
    public void RequestAndWithdrawConsent_ReturnNotApplicableOffWindowsWithoutTouchingNative()
    {
        var nativeCalls = 0;
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, _presenter) =>
            {
                nativeCalls += 1;
                return new((int)ErrorCode.Success, ConsentOutcomeJson("granted", "granted", "granted"));
            },
            WithdrawConsentImpl = () =>
            {
                nativeCalls += 1;
                return new((int)ErrorCode.Success, ConsentOutcomeJson("withdrawn", "denied", "denied"));
            },
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(false);

        var presented = false;
        var request = MxcTelemetry.RequestConsent(_ =>
        {
            presented = true;
            return TelemetryConsentDecision.Yes;
        });
        var withdraw = MxcTelemetry.WithdrawConsent();

        Assert.False(presented);
        Assert.Equal(0, nativeCalls);
        Assert.Equal(TelemetryConsentActionResult.NotApplicable, request.Result);
        Assert.Equal(TelemetryConsentState.NotApplicable, request.StoredState);
        Assert.Equal(TelemetryPolicyState.NotApplicable, request.Policy);
        Assert.Equal(TelemetryConsentActionResult.NotApplicable, withdraw.Result);
        Assert.Equal(TelemetryConsentState.NotApplicable, withdraw.StoredState);
        Assert.Equal(TelemetryPolicyState.NotApplicable, withdraw.Policy);
    }

    [Fact]
    public void WithdrawConsent_UnexpectedNativeStatusSurfacesAsMxcException()
    {
        var native = new FakeTelemetryNativeApi
        {
            WithdrawConsentImpl = () => new(777, null),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var ex = Assert.Throws<MxcException>(() => MxcTelemetry.WithdrawConsent());
        Assert.Equal(777, (int)ex.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{")]
    [InlineData("""{"result":"withdrawn"}""")]
    public void WithdrawConsent_MalformedSuccessPayloadIsBackendError(string? payload)
    {
        var native = new FakeTelemetryNativeApi
        {
            WithdrawConsentImpl = () => new((int)ErrorCode.Success, payload),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var ex = Assert.Throws<MxcException>(() => MxcTelemetry.WithdrawConsent());
        Assert.Equal(ErrorCode.BackendError, ex.Code);
        Assert.NotNull(ex.InnerException);
    }

    [Fact]
    public void ConsentWriteFailureStatusIsPreservedAcrossRequestAndWithdrawal()
    {
        var native = new FakeTelemetryNativeApi
        {
            RequestConsentImpl = (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.ConsentWriteFailed, null);
            },
            WithdrawConsentImpl = () => new((int)ErrorCode.ConsentWriteFailed, null),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var request = Assert.Throws<MxcException>(
            () => MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes));
        Assert.Equal(ErrorCode.ConsentWriteFailed, request.Code);

        var withdraw = Assert.Throws<MxcException>(() => MxcTelemetry.WithdrawConsent());
        Assert.Equal(ErrorCode.ConsentWriteFailed, withdraw.Code);
    }

    private sealed class FakeTelemetryNativeApi : MxcTelemetry.ITelemetryNativeApi
    {
        public Func<MxcTelemetry.NativePayloadResult> GetConsentImpl { get; init; } =
            () => new((int)ErrorCode.Success, "undetermined");

        public Func<MxcTelemetry.NativeBooleanResult> NeedsConsentPromptImpl { get; init; } =
            () => new((int)ErrorCode.Success, false);

        public Func<MxcTelemetry.NativePayloadResult> GetPolicyImpl { get; init; } =
            () => new((int)ErrorCode.Success, "unrestricted");

        public Func<MxcTelemetry.NativePayloadResult> GetConsentStatusImpl { get; init; } =
            () => new((int)ErrorCode.Success, ConsentStatusJson("undetermined", "undetermined", "blocked", "store-unreadable"));

        public Func<MxcTelemetry.NativePayloadResult> WithdrawConsentImpl { get; init; } =
            () => new((int)ErrorCode.Success, ConsentOutcomeJson("withdrawn", "denied", "denied", "unrestricted"));

        public Func<string?, Func<string, int>, MxcTelemetry.NativePayloadResult> RequestConsentImpl { get; init; } =
            (_locale, presenter) =>
            {
                Assert.Equal(1, presenter(ConsentPromptJson()));
                return new((int)ErrorCode.Success, ConsentOutcomeJson("granted", "granted", "granted", "unrestricted"));
            };

        public MxcTelemetry.NativePayloadResult GetConsent() => GetConsentImpl();

        public MxcTelemetry.NativeBooleanResult NeedsConsentPrompt() => NeedsConsentPromptImpl();

        public MxcTelemetry.NativePayloadResult GetPolicy() => GetPolicyImpl();

        public MxcTelemetry.NativePayloadResult GetConsentStatus() => GetConsentStatusImpl();

        public MxcTelemetry.NativePayloadResult WithdrawConsent() => WithdrawConsentImpl();

        public MxcTelemetry.NativePayloadResult RequestConsent(string? locale, Func<string, int> presenter) =>
            RequestConsentImpl(locale, presenter);
    }

    private sealed class QueuedSynchronizationContext : SynchronizationContext
    {
        private readonly ConcurrentQueue<(SendOrPostCallback Callback, object? State)> callbacks = new();
        private readonly TaskCompletionSource posted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public override void Post(SendOrPostCallback callback, object? state)
        {
            callbacks.Enqueue((callback, state));
            posted.TrySetResult();
        }

        public Task WaitForPostAsync(CancellationToken cancellationToken) =>
            posted.Task.WaitAsync(cancellationToken);

        public void RunAll()
        {
            while (callbacks.TryDequeue(out var item))
            {
                item.Callback(item.State);
            }
        }
    }
}
