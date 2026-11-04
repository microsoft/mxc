// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

// These tests mutate process-global telemetry seams and Trace listeners.
[CollectionDefinition("MxcTelemetry", DisableParallelization = true)]
public sealed class MxcTelemetryCollectionDefinition
{
}

/// <summary>
/// Redirects the debug-build-only <c>MXC_TEST_LOCALAPPDATA_OVERRIDE</c>
/// environment variable (read by <c>mxc_common::telemetry::consent</c> in
/// place of the real <c>LOCALAPPDATA</c> — see that module for the security
/// rationale; a release-profile native build compiles this override out
/// entirely and always resolves the real per-user known-folder path) to a
/// fresh temp directory for the lifetime of the fixture, so these tests
/// never touch the real developer/CI-machine telemetry consent file, and
/// restores the original value on dispose. xUnit runs the [Fact]s within a
/// single class sequentially, while the <c>MxcTelemetry</c> collection keeps
/// this class and <c>MxcTelemetryTestsReleaseSafe</c> from running in parallel.
/// The constructor <em>verifies</em> the redirect took effect and fails
/// the fixture loudly if it did not (see <c>AssertStoreIsRedirected</c>),
/// rather than silently operating on the real per-user store when the native
/// library under test happens to be a release build.
/// </summary>
[Collection("MxcTelemetry")]
public sealed class MxcTelemetryTests : IDisposable
{
    private const string OverrideEnvVar = "MXC_TEST_LOCALAPPDATA_OVERRIDE";
    private const string OverrideOwnerEnvVar = "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID";
    private readonly string? _originalOverride;
    private readonly string? _originalOverrideOwner;
    private readonly string _tempDir;

    public MxcTelemetryTests()
    {
        _originalOverride = Environment.GetEnvironmentVariable(OverrideEnvVar);
        _originalOverrideOwner = Environment.GetEnvironmentVariable(OverrideOwnerEnvVar);
        _tempDir = Path.Combine(Path.GetTempPath(), $"mxc_dotnet_consent_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        Environment.SetEnvironmentVariable(OverrideEnvVar, _tempDir);
        if (OperatingSystem.IsWindows())
        {
            Environment.SetEnvironmentVariable(
                OverrideOwnerEnvVar,
                GetParentProcessId().ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        AssertStoreIsRedirected();
    }

    [Fact]
    public void DefaultTelemetryValuesFailClosed()
    {
        Assert.Equal(TelemetryConsentState.Undetermined, default(TelemetryConsentState));
        Assert.Equal(TelemetryPolicyState.Blocked, default(TelemetryPolicyState));
        Assert.Equal(TelemetryConsentActionResult.Unknown, default(TelemetryConsentActionResult));
    }

    [Fact]
    public void CreationOptions_TelemetrySerializesCanonically()
    {
        var request = new ContainerRequest("echo telemetry");
        var options = new RunOptions { Telemetry = new TelemetryConfig { Enabled = true } };

        using var doc = System.Text.Json.JsonDocument.Parse(
            MxcContainer.SerializeRequest(request, options.Telemetry));

        Assert.True(doc.RootElement.GetProperty("telemetry").GetProperty("enabled").GetBoolean());
    }

    /// <summary>
    /// Prove — without writing anything through the SDK — that the native
    /// library under test actually honours <c>MXC_TEST_LOCALAPPDATA_OVERRIDE</c>.
    /// A release-profile <c>mxc_ffi</c> compiles the override out, in which
    /// case every test below would silently read and (worse) overwrite the
    /// real per-user consent file. Two probes are used because a single one
    /// could coincidentally match the real store's state; the real store
    /// cannot be both granted and denied, so two matching reads prove the
    /// redirect. The test seeds records directly and exercises only the SDK
    /// read path.
    /// </summary>
    private void AssertStoreIsRedirected()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Off Windows GetConsent short-circuits to NotApplicable without
            // touching any store, so there is nothing to redirect.
            return;
        }

        foreach (var (value, expected) in new[]
                 {
                     ("granted", TelemetryConsentState.Granted),
                     ("denied", TelemetryConsentState.Denied),
                 })
        {
            WriteConsentRecord(value);
            var observed = MxcTelemetry.GetConsent();
            if (observed != expected)
            {
                throw new InvalidOperationException(
                    $"telemetry consent store is NOT redirected to '{_tempDir}': wrote '{value}' " +
                    $"there but GetConsent() returned {observed}. These tests refuse to run against " +
                    "the real per-user consent file. The native mxc_ffi library under test is most " +
                    "likely a release build, which compiles out the " + OverrideEnvVar + " override. " +
                    "Rebuild it with `cargo build -p mxc_ffi --features dotnetsdk,test-support` (debug) and re-run.");
            }
        }

        File.Delete(ConsentFilePath());
    }

    private string ConsentFilePath() => Path.Combine(_tempDir, "mxc", "telemetry-consent.json");

    private void WriteConsentRecord(string consent)
    {
        var path = ConsentFilePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(
            path,
            $$"""{"schemaVersion":2,"consent":"{{consent}}","source":"test","promptedMxcVersion":"0.0.0","promptResourceVersion":4,"promptLocale":"en-US","updatedAtEpoch":0}""");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(OverrideEnvVar, _originalOverride);
        Environment.SetEnvironmentVariable(OverrideOwnerEnvVar, _originalOverrideOwner);
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup; not worth failing the test run over.
        }
    }

    [Fact]
    public void GetConsent_FreshStore_ReportsUndeterminedOnWindowsOrNotApplicableElsewhere()
    {
        var state = MxcTelemetry.GetConsent();
        var expected = OperatingSystem.IsWindows()
            ? TelemetryConsentState.Undetermined
            : TelemetryConsentState.NotApplicable;
        Assert.Equal(expected, state);
    }

    [Fact]
    public void RequestConsent_ThenWithdraw_RoundTrips_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var outcome = MxcTelemetry.RequestConsent(prompt =>
        {
            Assert.Equal(4u, prompt.ResourceVersion);
            Assert.Equal("en-US", prompt.Locale);
            Assert.Equal("Help improve Microsoft Products", prompt.Title.Text);
            Assert.Equal(
                """
                Help improve MXC and other Microsoft product including Windows by sharing optional diagnostic data with Microsoft.

                If enabled, MXC sends diagnostic information about product usage, performance, and reliability, including a random session ID that links events from the same container lifecycle. MXC does not send your commands, full file paths, credentials, or other customer content.
                """.ReplaceLineEndings("\n"),
                prompt.Body.Text);
            Assert.Equal("Yes", prompt.AffirmativeLabel.Text);
            Assert.Equal("No", prompt.NegativeLabel.Text);
            Assert.Equal("Privacy Statement", prompt.LearnMoreLabel.Text);
            Assert.Equal("https://go.microsoft.com/fwlink/?linkid=521839", prompt.LearnMoreUrl);
            return TelemetryConsentDecision.Yes;
        });
        Assert.Equal(TelemetryConsentActionResult.Granted, outcome.Result);
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());

        var withdrawal = MxcTelemetry.WithdrawConsent();
        Assert.Equal(TelemetryConsentActionResult.Withdrawn, withdrawal.Result);
        Assert.Equal(TelemetryConsentState.Denied, MxcTelemetry.GetConsent());
    }

    [Fact]
    public void NeedsConsentPrompt_FreshStore_IsTrueOnWindowsAndFalseElsewhere()
    {
        // Off Windows MXC collects nothing, so a host must never be told to
        // ask — prompting there would be a privacy defect, not just noise.
        Assert.Equal(OperatingSystem.IsWindows(), MxcTelemetry.NeedsConsentPrompt());
    }

    [Fact]
    public void NeedsConsentPrompt_AfterAnyDecision_IsFalse_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var denied = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.No);
        Assert.Equal(TelemetryConsentActionResult.Denied, denied.Result);
        Assert.False(MxcTelemetry.NeedsConsentPrompt());

        var granted = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);
        Assert.Equal(TelemetryConsentActionResult.Granted, granted.Result);
        Assert.False(MxcTelemetry.NeedsConsentPrompt());
    }

    [Fact]
    public void RequestConsent_NonWindows_IsNotApplicableAndDoesNotPresent()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var presented = false;
        var outcome = MxcTelemetry.RequestConsent(_ =>
        {
            presented = true;
            return TelemetryConsentDecision.Yes;
        });
        Assert.False(presented);
        Assert.Equal(TelemetryConsentActionResult.NotApplicable, outcome.Result);
    }

    [Fact]
    public void RequestConsent_RejectsLocaleWithEmbeddedNul()
    {
        var exception = Assert.Throws<ArgumentException>(
            () => MxcTelemetry.RequestConsent(
                _ => TelemetryConsentDecision.Yes,
                "en-US\0ignored"));

        Assert.Equal("locale", exception.ParamName);
    }

    [Fact]
    public void RequestConsentAsync_RejectsLocaleWithEmbeddedNulSynchronously()
    {
        var exception = Assert.Throws<ArgumentException>(
            () =>
            {
                _ = MxcTelemetry.RequestConsentAsync(
                    _ => ValueTask.FromResult(TelemetryConsentDecision.Yes),
                    "en-US\0ignored",
                    TestContext.Current.CancellationToken);
            });

        Assert.Equal("locale", exception.ParamName);
    }

    [Theory]
    [InlineData("locale")]
    [InlineData("title.id")]
    [InlineData("title.text")]
    [InlineData("body.id")]
    [InlineData("body.text")]
    [InlineData("affirmativeLabel.id")]
    [InlineData("affirmativeLabel.text")]
    [InlineData("negativeLabel.id")]
    [InlineData("negativeLabel.text")]
    [InlineData("learnMoreLabel.id")]
    [InlineData("learnMoreLabel.text")]
    [InlineData("learnMoreUrl")]
    public void ParseConsentPrompt_RejectsNullRequiredStrings(string path)
    {
        var root = JsonNode.Parse(
            """
            {
              "resourceVersion": 1,
              "locale": "en-US",
              "title": { "id": "title", "text": "Title" },
              "body": { "id": "body", "text": "Body" },
              "affirmativeLabel": { "id": "yes", "text": "Yes" },
              "negativeLabel": { "id": "no", "text": "No" },
              "learnMoreLabel": { "id": "learn", "text": "Learn more" },
              "learnMoreUrl": "https://example.com/privacy"
            }
            """)!.AsObject();
        var segments = path.Split('.');
        var parent = root;
        for (var index = 0; index < segments.Length - 1; index++)
        {
            parent = parent[segments[index]]!.AsObject();
        }
        parent[segments[^1]] = null;

        var error = Assert.Throws<JsonException>(
            () => MxcTelemetry.ParseConsentPrompt(root.ToJsonString()));

        Assert.Contains(path, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetPolicy_IsUnrestrictedOnWindowsAndNotApplicableElsewhere()
    {
        var expected = OperatingSystem.IsWindows()
            ? TelemetryPolicyState.Unrestricted
            : TelemetryPolicyState.NotApplicable;
        Assert.Equal(expected, MxcTelemetry.GetPolicy());
    }

    [Fact]
    public void GetPolicy_IsNeverAGrant_ConsentIsStillRequired_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());
        Assert.True(MxcTelemetry.NeedsConsentPrompt());

        var granted = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);
        Assert.Equal(TelemetryConsentActionResult.Granted, granted.Result);
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
    }

    [Fact]
    public async Task RequestConsentAsync_PersistsPresenterDecision_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var outcome = await MxcTelemetry.RequestConsentAsync(
            prompt => ValueTask.FromResult(
                prompt.Locale == "en-US"
                    ? TelemetryConsentDecision.Yes
                    : TelemetryConsentDecision.Dismissed),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(TelemetryConsentActionResult.Granted, outcome.Result);
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
    }

    [Fact]
    public async Task RequestConsentAsync_PreservesCallerSynchronizationContext_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var context = new PumpSynchronizationContext();
        var previousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var callerThread = Environment.CurrentManagedThreadId;
            var request = MxcTelemetry.RequestConsentAsync(async _ =>
            {
                Assert.Same(context, SynchronizationContext.Current);
                Assert.Equal(callerThread, Environment.CurrentManagedThreadId);
                await Task.Yield();
                Assert.Same(context, SynchronizationContext.Current);
                Assert.Equal(callerThread, Environment.CurrentManagedThreadId);
                return TelemetryConsentDecision.Yes;
            }, cancellationToken: TestContext.Current.CancellationToken);

            context.RunUntilCompleted(request);
            Assert.Equal(TelemetryConsentActionResult.Granted, (await request).Result);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }
    }

    [Fact]
    public async Task RequestConsentAsync_CancellationAfterPresentationStartsDoesNotPersistDecision_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        var presenterStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var stalledPresenter = new TaskCompletionSource<TelemetryConsentDecision>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var request = MxcTelemetry.RequestConsentAsync(_ =>
        {
            presenterStarted.SetResult();
            return new ValueTask<TelemetryConsentDecision>(stalledPresenter.Task);
        }, cancellationToken: cancellation.Token);

        await presenterStarted.Task.WaitAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        var finished = await Task.WhenAny(
            request,
            Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        Assert.Same(request, finished);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        Assert.True(request.IsCanceled);
        Assert.Equal(
            TelemetryConsentState.Undetermined,
            MxcTelemetry.GetConsentStatus().StoredState);
    }

    [Fact]
    public async Task RequestConsentAsync_ReportsPresenterFailureAfterCancellation_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        using var trackerScope = MxcTelemetry.OverrideFailureCategoryTrackerForTesting(
            new MxcTelemetry.FailureCategoryTracker(capacity: 64));
        using var listener = new CapturingTraceListener(
            "mxc: RequestConsentAsync presenter after cancellation failed");
        Trace.Listeners.Add(listener);
        try
        {
            var presenterStarted = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var presenter = new TaskCompletionSource<TelemetryConsentDecision>(
                TaskCreationOptions.RunContinuationsAsynchronously);

            var request = MxcTelemetry.RequestConsentAsync(_ =>
            {
                presenterStarted.SetResult();
                return new ValueTask<TelemetryConsentDecision>(presenter.Task);
            }, cancellationToken: cancellation.Token);

            await presenterStarted.Task.WaitAsync(TestContext.Current.CancellationToken);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
            Assert.True(request.IsCanceled);

            presenter.SetException(new InvalidOperationException("late presenter failure"));
            var diagnostic = await listener.Message.WaitAsync(TestContext.Current.CancellationToken);
            Assert.Contains(typeof(InvalidOperationException).FullName!, diagnostic);
            Assert.Contains("HRESULT 0x", diagnostic);
            Assert.DoesNotContain("late presenter failure", diagnostic);
            Assert.Equal(
                TelemetryConsentState.Undetermined,
                MxcTelemetry.GetConsentStatus().StoredState);
        }
        finally
        {
            Trace.Listeners.Remove(listener);
        }
    }

    [Fact]
    public async Task RequestConsentAsync_ExplicitDismissalCompletesWithoutCancellation_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var outcome = await MxcTelemetry.RequestConsentAsync(
            _ => ValueTask.FromResult(TelemetryConsentDecision.Dismissed),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(TelemetryConsentActionResult.Dismissed, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
    }

    [Fact]
    public async Task RequestConsentAsync_SynchronousPresenterCancellationDoesNotPersistDecision_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        var previousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(null);
        try
        {
            var request = MxcTelemetry.RequestConsentAsync(_ =>
            {
                cancellation.Cancel();
                cancellation.Token.ThrowIfCancellationRequested();
                return ValueTask.FromResult(TelemetryConsentDecision.Yes);
            }, cancellationToken: cancellation.Token);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
            Assert.True(request.IsCanceled);
            Assert.Equal(
                TelemetryConsentState.Undetermined,
                MxcTelemetry.GetConsentStatus().StoredState);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }
    }

    [Fact]
    public void FinalizeAsyncOutcome_PersistedDecisionWinsConcurrentCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var outcome = new TelemetryConsentOutcome(
            TelemetryConsentActionResult.Granted,
            TelemetryConsentState.Granted,
            TelemetryConsentState.Granted,
            TelemetryPolicyState.Unrestricted);

        Assert.Same(outcome, MxcTelemetry.FinalizeAsyncOutcome(outcome, cancellation.Token));
    }

    [Fact]
    public void FinalizeAsyncOutcome_CanceledDismissalThrows()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var outcome = new TelemetryConsentOutcome(
            TelemetryConsentActionResult.Dismissed,
            TelemetryConsentState.Undetermined,
            TelemetryConsentState.Undetermined,
            TelemetryPolicyState.Unrestricted);

        Assert.ThrowsAny<OperationCanceledException>(
            () => MxcTelemetry.FinalizeAsyncOutcome(outcome, cancellation.Token));
    }

    [Theory]
    [InlineData(typeof(DllNotFoundException))]
    [InlineData(typeof(EntryPointNotFoundException))]
    [InlineData(typeof(TypeInitializationException))]
    [InlineData(typeof(BadImageFormatException))]
    public void NativeLoadFailures_AreTreatedAsFailClosed(Type exceptionType)
    {
        // These are the failures GetConsent must swallow into Undetermined
        // rather than throwing out of a read-only status query.
        // EntryPointNotFoundException in particular covers an mxc_ffi that
        // loads but predates the consent entry points.
        var ex = exceptionType == typeof(TypeInitializationException)
            ? new TypeInitializationException("Microsoft.Mxc.Sdk.Native.NativeMethods", null)
            : (Exception)Activator.CreateInstance(exceptionType)!;
        Assert.True(MxcTelemetry.IsNativeLoadFailure(ex));
    }

    [Fact]
    public void GenuineNativeFailures_AreNotSwallowed()
    {
        // A real failure reported by the native layer must not be
        // misclassified as "library missing" and silently downgraded.
        Assert.False(MxcTelemetry.IsNativeLoadFailure(
            new MxcException(ErrorCode.ConsentWriteFailed, "boom")));
        Assert.False(MxcTelemetry.IsNativeLoadFailure(new InvalidOperationException()));
    }

    [Fact]
    public void ReadOnlyQueries_NeverThrow()
    {
        // Read-only status queries must fail closed without throwing.
        var prompt = Record.Exception(() => MxcTelemetry.NeedsConsentPrompt());
        Assert.Null(prompt);

        var policy = Record.Exception(() => MxcTelemetry.GetPolicy());
        Assert.Null(policy);

        var status = Record.Exception(() => MxcTelemetry.GetConsentStatus());
        Assert.Null(status);
    }

    [Fact]
    public void MxcException_PreservesTheUnderlyingCause()
    {
        // The read/write paths convert unexpected exceptions to MxcException so
        // a raw type cannot escape a documented contract; that conversion must
        // not lose the original, which is the only thing that explains why a
        // broken install failed.
        var cause = new DllNotFoundException("mxc_ffi not found");
        var ex = new MxcException(ErrorCode.ConsentWriteFailed, "could not persist", cause);

        Assert.Same(cause, ex.InnerException);
        Assert.Equal(ErrorCode.ConsentWriteFailed, ex.Code);
        Assert.Contains("could not persist", ex.ToString(), StringComparison.Ordinal);
        Assert.Contains("mxc_ffi not found", ex.ToString(), StringComparison.Ordinal);
    }

    private static int GetParentProcessId()
    {
        using var process = Process.GetCurrentProcess();
        var status = NtQueryInformationProcess(
            process.Handle,
            processInformationClass: 0,
            out var processInformation,
            Marshal.SizeOf<ProcessBasicInformation>(),
            out _);
        if (status != 0)
        {
            throw new InvalidOperationException(
                $"NtQueryInformationProcess failed with NTSTATUS 0x{status:X8}");
        }

        return checked((int)processInformation.InheritedFromUniqueProcessId);
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        out ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        internal IntPtr Reserved1;
        internal IntPtr PebBaseAddress;
        internal IntPtr Reserved2_0;
        internal IntPtr Reserved2_1;
        internal IntPtr UniqueProcessId;
        internal IntPtr InheritedFromUniqueProcessId;
    }

    private sealed class PumpSynchronizationContext : SynchronizationContext, IDisposable
    {
        private readonly ConcurrentQueue<(SendOrPostCallback Callback, object? State)> _work = new();
        private readonly AutoResetEvent _workAvailable = new(initialState: false);

        public override void Post(SendOrPostCallback callback, object? state)
        {
            _work.Enqueue((callback, state));
            _workAvailable.Set();
        }

        public void RunUntilCompleted(Task task)
        {
            while (!task.IsCompleted)
            {
                if (_work.TryDequeue(out var work))
                {
                    work.Callback(work.State);
                }
                else
                {
                    _workAvailable.WaitOne(TimeSpan.FromSeconds(5));
                }
            }
        }

        public void Dispose() => _workAvailable.Dispose();
    }

    private sealed class CapturingTraceListener(string messagePrefix) : TraceListener
    {
        private readonly TaskCompletionSource<string> _message = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<string> Message => _message.Task;

        public override void TraceEvent(
            TraceEventCache? eventCache,
            string? source,
            TraceEventType eventType,
            int id,
            string? message)
        {
            Capture(eventType, message);
        }

        public override void TraceEvent(
            TraceEventCache? eventCache,
            string? source,
            TraceEventType eventType,
            int id,
            string? format,
            params object?[]? args)
        {
            Capture(
                eventType,
                args is null ? format : string.Format(format ?? string.Empty, args));
        }

        private void Capture(TraceEventType eventType, string? message)
        {
            if (eventType == TraceEventType.Error &&
                message?.StartsWith(messagePrefix, StringComparison.Ordinal) == true)
            {
                _message.TrySetResult(message);
            }
        }

        public override void Write(string? message)
        {
        }

        public override void WriteLine(string? message)
        {
        }
    }
}
