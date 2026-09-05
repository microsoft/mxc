// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

[CollectionDefinition("MxcTelemetry", DisableParallelization = true)]
public sealed class MxcTelemetryCollectionDefinition
{
}

[Collection("MxcTelemetry")]
public sealed class MxcTelemetryTests
{
    private static readonly JsonSerializerOptions PolicyJsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    [Fact]
    public void SandboxPolicy_TelemetrySerializesCanonically()
    {
        var policy = new SandboxPolicy
        {
            Version = SchemaVersions.MaximumSupported,
            Telemetry = new TelemetrySettings { Enabled = true },
        };

        var json = JsonSerializer.Serialize(policy, PolicyJsonOptions);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.GetProperty("telemetry").GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public void GetPolicy_NeverThrowsAndFailsClosed()
    {
        var policy = MxcTelemetry.GetPolicy();
        Assert.True(Enum.IsDefined(policy));
    }

    [Fact]
    public void FailClosedDiagnostics_AreDeduplicatedAndDoNotExposeExceptionText()
    {
        var operation = $"TestGetPolicy{Guid.NewGuid():N}";
        using var output = new StringWriter();
        using var listener = new TextWriterTraceListener(output);
        var failure = new InvalidOperationException("sensitive\r\n\u001b[31mmessage");
        Trace.Listeners.Add(listener);
        try
        {
            MxcTelemetry.ReportFailClosed(operation, "Blocked", failure);
            MxcTelemetry.ReportFailClosed(operation, "Blocked", failure);
            MxcTelemetry.ReportFailClosed(operation, "false", ErrorCode.BackendError);
            Trace.Flush();

            var messages = output
                .ToString()
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Where(line => line.Contains(operation, StringComparison.Ordinal))
                .ToArray();
            Assert.Equal(2, messages.Length);
            Assert.Contains(typeof(InvalidOperationException).FullName!, messages[0]);
            Assert.Contains("HRESULT 0x", messages[0]);
            Assert.DoesNotContain("sensitive", messages[0]);
            Assert.DoesNotContain('\u001b', messages[0]);
            Assert.Contains("BackendError", messages[1]);
        }
        finally
        {
            Trace.Listeners.Remove(listener);
        }
    }

    [Fact]
    public void FailClosedDiagnosticTracker_DeduplicatesAndEnforcesCapacity()
    {
        var tracker = new MxcTelemetry.FailureCategoryTracker(capacity: 2);

        Assert.True(tracker.TryAdd("GetPolicy", "Blocked", "ExceptionA", 1));
        Assert.False(tracker.TryAdd("GetPolicy", "Blocked", "ExceptionA", 1));
        Assert.True(tracker.TryAdd("NeedsConsentPrompt", "false", "ErrorCode", 2));
        Assert.False(tracker.TryAdd("GetConsent", "Undetermined", "ExceptionB", 3));
    }

    [Fact]
    public void FailClosedDiagnosticTracker_DeduplicatesConcurrentReports()
    {
        var tracker = new MxcTelemetry.FailureCategoryTracker(capacity: 64);
        var accepted = 0;

        Parallel.For(0, 1_000, _ =>
        {
            if (tracker.TryAdd("GetPolicy", "Blocked", "ExceptionA", 1))
            {
                Interlocked.Increment(ref accepted);
            }
        });

        Assert.Equal(1, accepted);
    }

    [Fact]
    public void FailClosedDiagnosticTracker_EnforcesCapacityUnderConcurrentLoad()
    {
        var tracker = new MxcTelemetry.FailureCategoryTracker(capacity: 64);
        var accepted = 0;

        Parallel.For(0, 1_000, index =>
        {
            if (tracker.TryAdd("GetPolicy", "Blocked", "Exception", index))
            {
                Interlocked.Increment(ref accepted);
            }
        });

        Assert.Equal(64, accepted);
    }

    [Fact]
    public void FailClosedDiagnostics_DoNotPropagateTraceListenerFailures()
    {
        using var listener = new ThrowingTraceListener();
        Trace.Listeners.Add(listener);
        try
        {
            var exception = Record.Exception(() =>
                MxcTelemetry.ReportFailClosed(
                    $"ThrowingTrace{Guid.NewGuid():N}",
                    "Blocked",
                    ErrorCode.BackendError));
            Assert.Null(exception);
        }
        finally
        {
            Trace.Listeners.Remove(listener);
        }
    }

    [Fact]
    public void ReadOnlyQueryFailures_ReportAndReturnFailClosedValues()
    {
        var native = new FakeTelemetryQueryApi
        {
            GetConsentImpl = () => throw new DllNotFoundException("sensitive path"),
            NeedsConsentPromptImpl = () => new((int)ErrorCode.BackendError, true),
            GetPolicyImpl = () => throw new InvalidOperationException("sensitive policy"),
        };
        using var nativeScope = MxcTelemetry.OverrideFailClosedTelemetryQueryApiForTesting(native);
        using var output = new StringWriter();
        using var listener = new TextWriterTraceListener(output);
        Trace.Listeners.Add(listener);
        try
        {
            Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());
            Assert.False(MxcTelemetry.NeedsConsentPrompt());
            Assert.Equal(TelemetryPolicyState.Blocked, MxcTelemetry.GetPolicy());
            Trace.Flush();

            var message = output.ToString();
            Assert.Contains("GetConsent", message);
            Assert.Contains("NeedsConsentPrompt", message);
            Assert.Contains("GetPolicy", message);
            Assert.DoesNotContain("sensitive", message);
        }
        finally
        {
            Trace.Listeners.Remove(listener);
        }
    }

    [Fact]
    public void TelemetryQueryApiOverride_AllowsConcurrentDispose()
    {
        var native = new FakeTelemetryQueryApi
        {
            GetConsentImpl = () => new((int)ErrorCode.Success, "undetermined"),
            NeedsConsentPromptImpl = () => new((int)ErrorCode.Success, false),
            GetPolicyImpl = () => new((int)ErrorCode.Success, "blocked"),
        };
        var scope = MxcTelemetry.OverrideFailClosedTelemetryQueryApiForTesting(native);

        Parallel.Invoke(scope.Dispose, scope.Dispose);

        Assert.True(Enum.IsDefined(MxcTelemetry.GetPolicy()));
    }

    [Fact]
    public void RequestConsent_IsNotApplicableWithoutInvokingPresenter_OffWindows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var called = false;
        var outcome = MxcTelemetry.RequestConsent(_ =>
        {
            called = true;
            return TelemetryConsentDecision.Yes;
        });

        Assert.False(called);
        Assert.Equal(TelemetryConsentResult.NotApplicable, outcome.Result);
        Assert.Equal(TelemetryPolicyState.NotApplicable, outcome.Policy);
    }

#if DEBUG
    [Fact]
    public void RequestConsent_PresenterExceptionReturnsBackendError_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var _ = new TelemetryTestEnv();
        var ex = Assert.Throws<MxcException>(() =>
            MxcTelemetry.RequestConsent(_ => throw new InvalidOperationException("boom")));
        Assert.Equal(ErrorCode.BackendError, ex.Code);
    }

    [Fact]
    public async Task RequestConsentAsync_PreservesCallerSynchronizationContext_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var _ = new TelemetryTestEnv();
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
            Assert.Equal(TelemetryConsentResult.Granted, (await request).Result);
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

        using var _ = new TelemetryTestEnv();
        using var cancellation = new CancellationTokenSource();
        var presenterStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var stalledPresenter = new TaskCompletionSource<TelemetryConsentDecision>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var request = MxcTelemetry.RequestConsentAsync(_ =>
        {
            presenterStarted.SetResult();
            return stalledPresenter.Task;
        }, cancellationToken: cancellation.Token);

        await presenterStarted.Task.WaitAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();

        var finished = await Task.WhenAny(
            request,
            Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        Assert.Same(request, finished);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
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

        using var _ = new TelemetryTestEnv();
        using var cancellation = new CancellationTokenSource();
        using var listener = new CapturingTraceListener(
            "MXC telemetry consent presenter faulted after cancellation");
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
                return presenter.Task;
            }, cancellationToken: cancellation.Token);

            await presenterStarted.Task.WaitAsync(TestContext.Current.CancellationToken);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);

            presenter.SetException(new InvalidOperationException("late presenter failure"));
            var diagnostic = await listener.Message.WaitAsync(TestContext.Current.CancellationToken);
            Assert.Contains("late presenter failure", diagnostic);
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

        using var _ = new TelemetryTestEnv();
        var outcome = await MxcTelemetry.RequestConsentAsync(
            _ => Task.FromResult(TelemetryConsentDecision.Dismissed),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(TelemetryConsentResult.Dismissed, outcome.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, outcome.StoredState);
    }

    [Fact]
    public async Task RequestConsentAsync_SynchronousPresenterCancellationDoesNotPersistDecision_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var _ = new TelemetryTestEnv();
        using var cancellation = new CancellationTokenSource();
        var previousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(null);
        try
        {
            var request = MxcTelemetry.RequestConsentAsync(_ =>
            {
                cancellation.Cancel();
                cancellation.Token.ThrowIfCancellationRequested();
                return Task.FromResult(TelemetryConsentDecision.Yes);
            }, cancellationToken: cancellation.Token);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
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
    public void FinalizeAsyncOutcome_PersistedDecisionWinsLateCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var outcome = new TelemetryConsentOutcome
        {
            Result = TelemetryConsentResult.Granted,
            StoredState = TelemetryConsentState.Granted,
            EffectiveState = TelemetryConsentState.Granted,
        };

        Assert.Same(outcome, MxcTelemetry.FinalizeAsyncOutcome(outcome, cancellation.Token));
    }

    [Fact]
    public void FinalizeAsyncOutcome_CanceledDismissalThrows()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var outcome = new TelemetryConsentOutcome
        {
            Result = TelemetryConsentResult.Dismissed,
            StoredState = TelemetryConsentState.Undetermined,
            EffectiveState = TelemetryConsentState.Undetermined,
        };

        Assert.ThrowsAny<OperationCanceledException>(
            () => MxcTelemetry.FinalizeAsyncOutcome(outcome, cancellation.Token));
    }

    [Fact]
    public void ConsentLifecycle_RoundTripsThroughNativeApi_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var _ = new TelemetryTestEnv();
        Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());
        Assert.True(MxcTelemetry.NeedsConsentPrompt());

        var dismissed = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Dismissed);
        Assert.Equal(TelemetryConsentResult.Dismissed, dismissed.Result);
        Assert.Equal(TelemetryConsentState.Undetermined, dismissed.StoredState);

        var granted = MxcTelemetry.RequestConsent(_ => TelemetryConsentDecision.Yes);
        Assert.Equal(TelemetryConsentResult.Granted, granted.Result);
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsentStatus().EffectiveState);
        Assert.False(MxcTelemetry.NeedsConsentPrompt());

        var withdrawn = MxcTelemetry.WithdrawConsent();
        Assert.Equal(TelemetryConsentResult.Withdrawn, withdrawn.Result);
        Assert.Equal(TelemetryConsentState.Denied, MxcTelemetry.GetConsent());
        Assert.False(MxcTelemetry.NeedsConsentPrompt());
    }

    [SupportedOSPlatform("windows")]
    private sealed class TelemetryTestEnv : IDisposable
    {
        private static readonly SemaphoreSlim Gate = new(1, 1);

        private readonly string? _originalLocalAppData;
        private readonly string? _originalLocalAppDataOwnerPid;
        private readonly string? _originalPolicyKey;
        private readonly string? _originalPolicyOwnerPid;
        private readonly string _storeDir;
        private readonly string _policySubkey;

        public TelemetryTestEnv()
        {
            Gate.Wait();
            try
            {
                _originalLocalAppData = Environment.GetEnvironmentVariable("MXC_TEST_LOCALAPPDATA_OVERRIDE");
                _originalLocalAppDataOwnerPid = Environment.GetEnvironmentVariable(
                    "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID");
                _originalPolicyKey = Environment.GetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE");
                _originalPolicyOwnerPid = Environment.GetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID");

                _storeDir = Directory.CreateTempSubdirectory("mxc-dotnet-telemetry-").FullName;
                _policySubkey = $@"Software\MxcTelemetryDotNetTests\{Guid.NewGuid():N}";

                Registry.CurrentUser.CreateSubKey(_policySubkey)?.Dispose();
                Environment.SetEnvironmentVariable("MXC_TEST_LOCALAPPDATA_OVERRIDE", _storeDir);
                Environment.SetEnvironmentVariable(
                    "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID",
                    GetParentProcessId().ToString());
                Environment.SetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE", _policySubkey);
                Environment.SetEnvironmentVariable(
                    "MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID",
                    Environment.ProcessId.ToString());
            }
            catch
            {
                Gate.Release();
                throw;
            }
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable("MXC_TEST_LOCALAPPDATA_OVERRIDE", _originalLocalAppData);
            Environment.SetEnvironmentVariable(
                "MXC_TEST_LOCALAPPDATA_OVERRIDE_OWNER_PID",
                _originalLocalAppDataOwnerPid);
            Environment.SetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE", _originalPolicyKey);
            Environment.SetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE_OWNER_PID", _originalPolicyOwnerPid);

            try
            {
                if (Directory.Exists(_storeDir))
                {
                    Directory.Delete(_storeDir, recursive: true);
                }
            }
            catch
            {
            }

            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(_policySubkey, throwOnMissingSubKey: false);
            }
            catch
            {
            }

            Gate.Release();
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
                args is null || args.Length == 0
                    ? format
                    : string.Format(format ?? string.Empty, args));
        }

        public override void Write(string? message)
        {
        }

        public override void WriteLine(string? message)
        {
        }

        private void Capture(TraceEventType eventType, string? message)
        {
            if (eventType == TraceEventType.Error &&
                message?.StartsWith(messagePrefix, StringComparison.Ordinal) == true)
            {
                _message.TrySetResult(message);
            }
        }
    }
#endif

    private sealed class FakeTelemetryQueryApi : MxcTelemetry.IFailClosedTelemetryQueryApi
    {
        internal required Func<MxcTelemetry.NativePayloadResult> GetConsentImpl { get; init; }
        internal required Func<MxcTelemetry.NativeBooleanResult> NeedsConsentPromptImpl { get; init; }
        internal required Func<MxcTelemetry.NativePayloadResult> GetPolicyImpl { get; init; }

        public MxcTelemetry.NativePayloadResult GetConsent() => GetConsentImpl();

        public MxcTelemetry.NativeBooleanResult NeedsConsentPrompt() =>
            NeedsConsentPromptImpl();

        public MxcTelemetry.NativePayloadResult GetPolicy() => GetPolicyImpl();
    }

    private sealed class ThrowingTraceListener : TraceListener
    {
        public override void TraceEvent(
            TraceEventCache? eventCache,
            string? source,
            TraceEventType eventType,
            int id,
            string? format,
            params object?[]? args) =>
            throw new InvalidOperationException("listener failure");

        public override void Write(string? message) =>
            throw new InvalidOperationException("listener failure");

        public override void WriteLine(string? message) =>
            throw new InvalidOperationException("listener failure");
    }
}
