// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    public void SandboxPolicy_TelemetryEnabledSerializesCanonically()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.8.0-alpha",
            TelemetryEnabled = true,
        };

        var json = JsonSerializer.Serialize(policy, PolicyJsonOptions);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.GetProperty("telemetry").GetProperty("enabled").GetBoolean());
        Assert.False(root.TryGetProperty("telemetryEnabled", out _));
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

    [SupportedOSPlatform("windows")]
    private sealed class TelemetryTestEnv : IDisposable
    {
        private static readonly SemaphoreSlim Gate = new(1, 1);

        private readonly string? _originalLocalAppData;
        private readonly string? _originalPolicyKey;
        private readonly string _storeDir;
        private readonly string _policySubkey;

        public TelemetryTestEnv()
        {
            Gate.Wait();
            try
            {
                _originalLocalAppData = Environment.GetEnvironmentVariable("MXC_TEST_LOCALAPPDATA_OVERRIDE");
                _originalPolicyKey = Environment.GetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE");

                _storeDir = Directory.CreateTempSubdirectory("mxc-dotnet-telemetry-").FullName;
                _policySubkey = $@"Software\MxcTelemetryDotNetTests\{Guid.NewGuid():N}";

                Registry.CurrentUser.CreateSubKey(_policySubkey)?.Dispose();
                Environment.SetEnvironmentVariable("MXC_TEST_LOCALAPPDATA_OVERRIDE", _storeDir);
                Environment.SetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE", _policySubkey);
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
            Environment.SetEnvironmentVariable("MXC_TEST_POLICY_KEY_OVERRIDE", _originalPolicyKey);

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
    }
#endif
}
