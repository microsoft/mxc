// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
        Assert.Null(status.Reason);
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
        Assert.Null(status.Reason);
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
        Assert.Null(status.Reason);
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
        Assert.Equal(TelemetryConsentStatusReason.Unknown, outcome.Reason);
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
        Assert.Equal(TelemetryConsentStatusReason.Unknown, outcome.Reason);
        Assert.Equal(TelemetryPolicyState.Blocked, outcome.Policy);
    }

    [Theory]
    [InlineData("policy-blocked", TelemetryConsentStatusReason.PolicyBlocked)]
    [InlineData("presentation-unavailable", TelemetryConsentStatusReason.PresentationUnavailable)]
    public void GetConsentStatus_ParsesExtendedStatusReasons(string reason, TelemetryConsentStatusReason expected)
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
        Assert.Equal(expected, status.Reason);
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

        Assert.Equal(TelemetryConsentStatusReason.Unknown, status.Reason);
        Assert.Equal(TelemetryConsentState.Undetermined, status.StoredState);
        Assert.Equal(TelemetryConsentState.Undetermined, status.EffectiveState);
        Assert.Equal(TelemetryPolicyState.Blocked, status.Policy);
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
    public void WithdrawConsent_MalformedSuccessPayloadIsWrapped(string? payload)
    {
        var native = new FakeTelemetryNativeApi
        {
            WithdrawConsentImpl = () => new((int)ErrorCode.Success, payload),
        };

        using var nativeScope = MxcTelemetry.OverrideNativeApiForTesting(native);
        using var platformScope = MxcTelemetry.OverrideWindowsHostForTesting(true);

        var ex = Assert.Throws<MxcException>(() => MxcTelemetry.WithdrawConsent());
        Assert.Equal(ErrorCode.ConsentWriteFailed, ex.Code);
        Assert.NotNull(ex.InnerException);
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
}
