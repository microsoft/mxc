// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// Redirects the debug-build-only <c>MXC_TEST_LOCALAPPDATA_OVERRIDE</c>
/// environment variable (read by <c>wxc_common::telemetry::consent</c> in
/// place of the real <c>LOCALAPPDATA</c> — see that module for the security
/// rationale; a release-profile native build compiles this override out
/// entirely and always resolves the real per-user known-folder path) to a
/// fresh temp directory for the lifetime of the fixture, so these tests
/// never touch the real developer/CI-machine telemetry consent file, and
/// restores the original value on dispose. xUnit runs the [Fact]s within a
/// single class sequentially by default, so no additional locking is needed
/// here. The constructor <em>verifies</em> the redirect took effect and fails
/// the fixture loudly if it did not (see <c>AssertStoreIsRedirected</c>),
/// rather than silently operating on the real per-user store when the native
/// library under test happens to be a release build.
/// </summary>
public sealed class MxcTelemetryTests : IDisposable
{
    private const string OverrideEnvVar = "MXC_TEST_LOCALAPPDATA_OVERRIDE";
    private const string PolicyOverrideEnvVar = "MXC_TEST_POLICY_KEY_OVERRIDE";
    private readonly string? _originalOverride;
    private readonly string? _originalPolicyOverride;
    private readonly string _tempDir;
    private readonly string _policySubkey;

    public MxcTelemetryTests()
    {
        _originalOverride = Environment.GetEnvironmentVariable(OverrideEnvVar);
        _tempDir = Path.Combine(Path.GetTempPath(), $"mxc_dotnet_consent_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        Environment.SetEnvironmentVariable(OverrideEnvVar, _tempDir);

        // Redirect the administrative policy read to a throwaway HKCU key too,
        // so these tests are unaffected by a real MXC telemetry policy on the
        // build machine and can exercise the policy path without elevation.
        _originalPolicyOverride = Environment.GetEnvironmentVariable(PolicyOverrideEnvVar);
        _policySubkey = $@"Software\MxcTelemetryPolicyDotnetTest\{Guid.NewGuid():N}";
        if (OperatingSystem.IsWindows())
        {
            Microsoft.Win32.Registry.CurrentUser.CreateSubKey(_policySubkey)?.Dispose();
        }
        Environment.SetEnvironmentVariable(PolicyOverrideEnvVar, _policySubkey);

        AssertStoreIsRedirected();
        AssertPolicyKeyIsRedirected();
    }

    /// <summary>
    /// The policy counterpart to <see cref="AssertStoreIsRedirected"/>: prove
    /// the native library honours <c>MXC_TEST_POLICY_KEY_OVERRIDE</c> before
    /// any policy test runs. A release-profile <c>mxc_ffi</c> compiles the
    /// override out and would silently read the machine's real
    /// <c>HKLM\SOFTWARE\Policies\Mxc</c> key instead, making every
    /// policy assertion below meaningless — passing or failing on the build
    /// agent's administrative state rather than on the code under test.
    ///
    /// Two probes are used for the same reason as the consent check: a single
    /// one could coincidentally match the real machine policy, but the real
    /// policy cannot be both Blocked and Allowed.
    /// </summary>
    private void AssertPolicyKeyIsRedirected()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Off Windows GetPolicy short-circuits to NotApplicable without
            // reading any registry, so there is nothing to redirect.
            return;
        }

        foreach (var (value, expected) in new[]
                 {
                     (0, TelemetryPolicyState.Blocked),
                     (3, TelemetryPolicyState.Allowed),
                 })
        {
            SetPolicyValue(value);
            var observed = MxcTelemetry.GetPolicy();
            if (observed != expected)
            {
                throw new InvalidOperationException(
                    $"telemetry policy key is NOT redirected to 'HKCU\\{_policySubkey}': wrote " +
                    $"AllowTelemetry={value} there but GetPolicy() returned {observed}. These tests " +
                    "refuse to run against the real machine policy. The native mxc_ffi library under " +
                    "test is most likely a release build, which compiles out the " +
                    PolicyOverrideEnvVar + " override. Rebuild it with " +
                    "`cargo build -p mxc_ffi --features dotnetsdk` (debug) and re-run.");
            }
        }

        // Leave the fixture in the unmanaged default state.
        SetPolicyValue(null);
    }

    /// <summary>
    /// Writes the administrative <c>AllowTelemetry</c> policy value into the
    /// redirected key, or removes it when <paramref name="value"/> is null.
    /// </summary>
    private void SetPolicyValue(int? value)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(_policySubkey)!;
        if (value is null)
        {
            key.DeleteValue("AllowTelemetry", throwOnMissingValue: false);
        }
        else
        {
            key.SetValue("AllowTelemetry", value.Value, Microsoft.Win32.RegistryValueKind.DWord);
        }
    }

    /// <summary>
    /// Writes <c>AllowTelemetry</c> as a <c>REG_SZ</c> rather than a
    /// <c>REG_DWORD</c> — the mistake an administrator makes by typing the
    /// value in by hand.
    /// </summary>
    private void SetPolicyStringValue(string value)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(_policySubkey)!;
        key.SetValue("AllowTelemetry", value, Microsoft.Win32.RegistryValueKind.String);
    }

    /// <summary>
    /// Prove — without writing anything through the SDK — that the native
    /// library under test actually honours <c>MXC_TEST_LOCALAPPDATA_OVERRIDE</c>.
    /// A release-profile <c>mxc_ffi</c> compiles the override out, in which
    /// case every test below would silently read and (worse) overwrite the
    /// real per-user consent file. Two probes are used because a single one
    /// could coincidentally match the real store's state; the real store
    /// cannot be both granted and denied, so two matching reads prove the
    /// redirect. This is read-only against the SDK: the records are written
    /// directly to the redirected path by this test.
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
                    "Rebuild it with `cargo build -p mxc_ffi --features dotnetsdk` (debug) and re-run.");
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
            $$"""{"schemaVersion":1,"consent":"{{consent}}","source":"test","promptedMxcVersion":"0.0.0","updatedAtEpoch":0}""");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(OverrideEnvVar, _originalOverride);
        Environment.SetEnvironmentVariable(PolicyOverrideEnvVar, _originalPolicyOverride);
        if (OperatingSystem.IsWindows())
        {
            try
            {
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(_policySubkey, throwOnMissingSubKey: false);
            }
            catch (UnauthorizedAccessException)
            {
                // Best-effort cleanup; not worth failing the test run over.
            }
        }
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
    public void SetConsent_ThenGetConsent_RoundTrips_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            // MXC must not gather telemetry off Windows, so consent cannot be
            // persisted there either — see SetConsent_NonWindows_ThrowsConsentWriteFailed.
            return;
        }

        MxcTelemetry.SetConsent(true, "prompt");
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());

        MxcTelemetry.SetConsent(false, "settings-ui");
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

        MxcTelemetry.SetConsent(false, "prompt");
        Assert.False(MxcTelemetry.NeedsConsentPrompt());

        MxcTelemetry.SetConsent(true, "settings-ui");
        Assert.False(MxcTelemetry.NeedsConsentPrompt());
    }

    [Fact]
    public void SetConsent_NonWindows_ThrowsConsentWriteFailed()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var ex = Assert.Throws<MxcException>(() => MxcTelemetry.SetConsent(true));
        Assert.Equal(ErrorCode.ConsentWriteFailed, ex.Code);
    }

    [Fact]
    public void GetPolicy_NoPolicyConfigured_IsUnrestrictedOnWindowsAndNotApplicableElsewhere()
    {
        SetPolicyValue(null);
        var expected = OperatingSystem.IsWindows()
            ? TelemetryPolicyState.Unrestricted
            : TelemetryPolicyState.NotApplicable;
        Assert.Equal(expected, MxcTelemetry.GetPolicy());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(42)]
    [InlineData(-1)]
    public void GetPolicy_AnyValueOtherThanOptional_IsBlocked_OnWindows(int value)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // MXC's data is product-and-service-usage (optional) diagnostic data,
        // so only level 3 permits it. Unrecognised values fail closed rather
        // than being treated as "no policy".
        SetPolicyValue(value);
        Assert.Equal(TelemetryPolicyState.Blocked, MxcTelemetry.GetPolicy());
    }

    [Fact]
    public void GetPolicy_Optional_IsAllowed_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        SetPolicyValue(3);
        Assert.Equal(TelemetryPolicyState.Allowed, MxcTelemetry.GetPolicy());
    }

    /// <summary>
    /// An administrator who sets <c>AllowTelemetry</c> as a string instead of a
    /// DWORD has still expressed an intent to manage this machine. The value
    /// cannot be evaluated, so it must fail closed to Blocked — never be read
    /// as an unmanaged machine, which would let a prior consent grant
    /// re-enable the collection the administrator meant to stop.
    /// </summary>
    [Theory]
    [InlineData("0")]
    [InlineData("3")]
    [InlineData("")]
    [InlineData("not-a-number")]
    public void GetPolicy_WrongValueType_IsBlockedNotUnrestricted_OnWindows(string value)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        SetPolicyStringValue(value);
        Assert.Equal(TelemetryPolicyState.Blocked, MxcTelemetry.GetPolicy());
    }

    [Fact]
    public void GetPolicy_IsNeverAGrant_ConsentIsStillRequired_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // An administrator permitting telemetry must not stand in for the
        // user's own decision: the prompt is still owed.
        SetPolicyValue(3);
        Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());
        Assert.True(MxcTelemetry.NeedsConsentPrompt());
    }

    [Fact]
    public void GetPolicy_BlockedSuppressesTheConsentPrompt_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // There is no point asking a user for permission an administrator has
        // already refused, but the recorded consent state is left untouched so
        // relaxing the policy later restores the user's real choice.
        SetPolicyValue(0);
        Assert.False(MxcTelemetry.NeedsConsentPrompt());
        Assert.Equal(TelemetryConsentState.Undetermined, MxcTelemetry.GetConsent());

        MxcTelemetry.SetConsent(true, "settings-ui");
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
        Assert.Equal(TelemetryPolicyState.Blocked, MxcTelemetry.GetPolicy());

        SetPolicyValue(null);
        Assert.Equal(TelemetryPolicyState.Unrestricted, MxcTelemetry.GetPolicy());
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
    }

    [Fact]
    public void SetConsent_NullSource_DefaultsToSdkAndDoesNotThrowOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // Should not throw; "sdk" is the documented default provenance.
        MxcTelemetry.SetConsent(true);
        Assert.Equal(TelemetryConsentState.Granted, MxcTelemetry.GetConsent());
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
        // Both are documented as "always succeeds". NeedsConsentPrompt used to
        // throw MxcException whenever the native layer reported a non-Success
        // status — which includes a caught panic — despite that contract, so a
        // host calling it on its startup path could be taken down by an
        // unreadable consent store.
        var prompt = Record.Exception(() => MxcTelemetry.NeedsConsentPrompt());
        Assert.Null(prompt);

        var policy = Record.Exception(() => MxcTelemetry.GetPolicy());
        Assert.Null(policy);
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
}
