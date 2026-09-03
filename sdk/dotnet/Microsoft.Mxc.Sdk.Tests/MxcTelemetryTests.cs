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
    public void ConsentLifecycle_RoundTripsThroughNativeApi_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var _ = new TelemetryTestEnv();
        Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());
        Assert.True(MxcTelemetry.NeedsConsentPrompt());

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
#endif
}
