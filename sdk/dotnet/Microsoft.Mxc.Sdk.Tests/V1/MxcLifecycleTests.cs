// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcLifecycleTests
{
    [Fact]
    public void StartSandbox_IsolationSessionDoesNotRequireExperimentalOptIn()
    {
        // IsolationSession must reach backend dispatch without an experimental
        // opt-in, so an experimental-gate refusal must not appear.
        // A registered prefix carrying an id that was never provisioned cannot
        // succeed, so the assertion holds whether or not the isolation_session
        // feature was compiled in and whether or not the host has the service --
        // and it provisions nothing.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartSandbox(new ContainerId("iso:0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartSandbox_WslcDoesNotRequireExperimentalOptIn()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartSandbox(
                new ContainerId("wslc:0123456789abcdef0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"WSLC must reach ordinary backend availability: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        // A non-provision phase resolves the backend from the id prefix; an
        // unknown prefix is unsupported_containment, independent of host and
        // build features.
        var id = new ContainerId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StartSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void SpawnInContainer_RejectsWindowsSandboxIds()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.SpawnInContainer(
                new ContainerId("wsb:0a1b2c3d"),
                new ExecRequest("echo hi")));

        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
        Assert.Contains("raw exact 1.1.0-alpha state-aware executor route", ex.Message, StringComparison.Ordinal);
        Assert.Contains("explicit experimental authorization", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'wsb:'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void StartSandbox_RejectsWindowsSandboxIds()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartSandbox(new ContainerId("wsb:0a1b2c3d")));

        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
        Assert.Contains("raw exact 1.1.0-alpha state-aware executor route", ex.Message, StringComparison.Ordinal);
        Assert.Contains("explicit experimental authorization", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'wsb:'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OtherIdPhases_RejectWindowsSandboxIdsWithRawExactRoute()
    {
        var id = new ContainerId("wsb:0a1b2c3d");
        foreach (var action in new Action[]
                 {
                     () => MxcLifecycle.StopSandbox(id),
                     () => MxcLifecycle.DeprovisionSandbox(id),
                     () => MxcLifecycle.DryRunExecInContainer(id, new ExecRequest("echo hi")),
                 })
        {
            var ex = Assert.Throws<MxcException>(action);
            Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
            Assert.Contains("raw exact 1.1.0-alpha", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void StopSandbox_MalformedId_ThrowsMalformedId()
    {
        // No backend prefix at all is a malformed id.
        var id = new ContainerId("no-prefix");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_MalformedIdWithVersionOverride_ThrowsMalformedId()
    {
        var id = new ContainerId("no-prefix");
        var options = new StateAwarePhaseOptions { Version = "0.8.0-alpha" };

        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StopSandbox(id, options));

        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_EmptyPrefix_ThrowsMalformedId()
    {
        // ":payload" clears the ctor's null/empty check and has a colon, but an
        // empty prefix is structural rather than an unregistered backend. The
        // native parse_sandbox_id_prefix pins the same split.
        var id = new ContainerId(":payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_DefaultId_ThrowsMalformedId()
    {
        // default(ContainerId) is legal and leaves Value null; it must surface a
        // typed error rather than a NullReferenceException.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StopSandbox(default));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_UnknownPrefix_ThrowsUnsupportedContainment()
    {
        // A non-empty prefix is well-formed, so it stays UnsupportedContainment
        // and does not get folded into MalformedId by the guard above.
        var id = new ContainerId("nope:payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void WslcProvisionOptions_RoundTripDoesNotInventLegacyNetworkFields()
    {
        var jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
        var options = new WslcProvisionOptions
        {
            Network = new StateAwareNetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Deny,
                    HostLoopback = NetworkAction.Deny,
                },
            },
        };

        var json = JsonSerializer.Serialize(options, jsonOptions);
        var roundTripped = JsonSerializer.Deserialize<WslcProvisionOptions>(json, jsonOptions)!;
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            StateAwareContainment.Wslc,
            roundTripped);

        Assert.DoesNotContain("defaultPolicy", json, StringComparison.Ordinal);
        Assert.DoesNotContain("allowLocalNetwork", json, StringComparison.Ordinal);
        Assert.NotNull(envelope["network"]);
    }

    [Fact]
    public void IsolationSessionProvisionOptions_RejectsNullNetwork()
    {
        Assert.Throws<ArgumentNullException>(
            () => new IsolationSessionProvisionOptions(null!));
    }

    [Fact]
    public void BuildProvisionEnvelope_RejectsNetworkResetToNull()
    {
        var options = new IsolationSessionProvisionOptions(new StateAwareNetworkPolicy())
        {
            Network = null!,
        };

        var error = Assert.Throws<ArgumentNullException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                options));
        Assert.Equal("network", error.ParamName);
    }

    [Fact]
    public void IsolationSessionProvisionOptions_RequiresNetworkPolicy()
    {
        var constructor = Assert.Single(typeof(IsolationSessionProvisionOptions).GetConstructors());
        Assert.Equal(
            typeof(StateAwareNetworkPolicy),
            Assert.Single(constructor.GetParameters()).ParameterType);
        Assert.NotNull(typeof(IsolationSessionProvisionOptions).GetProperty("Network"));
    }

    [Fact]
    public void SpawnInContainer_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        var id = new ContainerId("bogus:12345");
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.SpawnInContainer(id, new ExecRequest("echo hi")));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void SpawnInContainer_NullRequest_Throws()
    {
        var id = new ContainerId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.SpawnInContainer(id, null!));
    }

    [Fact]
    public void SandboxId_RoundTripsAndCompares()
    {
        var a = new ContainerId("iso:abc");
        var b = new ContainerId("iso:abc");
        var c = new ContainerId("iso:xyz");
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal("iso:abc", a.Value);
        Assert.Equal("iso:abc", a.ToString());
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void SandboxId_EmptyValue_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ContainerId(""));
        Assert.Throws<ArgumentException>(() => new ContainerId(null!));
    }

    [Fact]
    public void BuildProvisionEnvelope_OmitsAnUnspecifiedNetworkPosture()
    {
        // Optional mode fields must remain absent when the caller did not
        // specify them. Post-provision backends reject mode fields by presence.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.Wslc,
                new WslcProvisionOptions { Network = new StateAwareNetworkPolicy() })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);

        var network = doc.RootElement.GetProperty("network");
        Assert.False(network.TryGetProperty("defaultPolicy", out _));
        Assert.False(network.TryGetProperty("allowLocalNetwork", out _));
        Assert.Equal("{}", network.GetRawText());
    }

    [Fact]
    public void BuildProvisionEnvelope_IsolationSessionRequiresOptions()
    {
        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                null));
    }

    [Fact]
    public void BuildExecEnvelope_CarriesSandboxIdAndCommandLine()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(
                new ContainerId("iso:abc"),
                new ExecRequest("cmd /c echo hi"))
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("exec", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        var process = root.GetProperty("process");
        Assert.Equal("cmd /c echo hi", process.GetProperty("commandLine").GetString());
        Assert.False(process.TryGetProperty("timeout", out _));
    }

    [Fact]
    public void BuildExecEnvelope_RejectsRuntimeConfigForAnotherBackend()
    {
        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildExecEnvelope(
                new ContainerId("iso:abc"),
                new ExecRequest("echo hi")
                {
                    RuntimeConfig = new NetworkRuntimeConfig
                    {
                        NetworkProxy = "http://proxy.example:8080",
                    },
                }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-url")]
    [InlineData("ftp://proxy.example:8080")]
    [InlineData(" http://proxy.example:8080")]
    public void BuildExecEnvelope_RejectsInvalidRuntimeProxy(string url)
    {
        Assert.Throws<ArgumentException>(() => MxcLifecycle.BuildExecEnvelope(
            new ContainerId("wslc:0123456789abcdef0123456789abcdef"),
            new ExecRequest("echo test")
            {
                RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = url },
            }));
    }

    [Fact]
    public void StateAwareTypes_KeepNetworkAndAcknowledgmentOutOfLaterPhases()
    {
        Assert.Null(typeof(StateAwarePhaseOptions).GetProperty("Network"));
        Assert.Null(typeof(StateAwarePhaseOptions).GetProperty("RuntimeConfig"));
        Assert.Null(typeof(StateAwarePhaseOptions).GetProperty("AcknowledgeUnrestrictedNetwork"));
        Assert.NotNull(typeof(ExecRequest).GetProperty("RuntimeConfig"));
        Assert.Null(typeof(ExecRequest).GetProperty("Network"));
    }

    [Theory]
    [InlineData("wslc:0123456789abcdef0123456789abcdef")]
    [InlineData("iso:abc")]
    [InlineData("wsb:01234567")]
    public void BuildNonExecEnvelopes_RejectProxyCarriedThroughBaseOptions(string value)
    {
        var id = new ContainerId(value);
        var options = new ExecRequest("echo hi")
        {
            RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://proxy.example:8080" },
        };
        Assert.Throws<ArgumentException>(() => MxcLifecycle.BuildStartEnvelope(id, options));
        Assert.Throws<ArgumentException>(() => MxcLifecycle.BuildStopEnvelope(id, options));
        Assert.Throws<ArgumentException>(() => MxcLifecycle.BuildDeprovisionEnvelope(id, options));
    }

    [Fact]
    public void Lifecycle_ExposesDryRunForEveryPhase()
    {
        var names = typeof(MxcLifecycle)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(method => method.Name)
            .Where(name => name.StartsWith("DryRun", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[]
            {
                "DryRunDeprovisionSandbox",
                "DryRunExecInContainer",
                "DryRunProvisionSandbox",
                "DryRunStartSandbox",
                "DryRunStopSandbox",
            },
            names);
    }

    [Fact]
    public void WslcBuildSwitch_MatchesNativeAvailabilityAndStagesRuntimeUnit()
    {
        Action dryRun = () => MxcLifecycle.DryRunProvisionSandbox(
            StateAwareContainment.Wslc,
            new WslcProvisionOptions { Image = "alpine:latest" });

#if MXC_WITH_WSLC
        dryRun();
        Assert.True(File.Exists(Path.Combine(AppContext.BaseDirectory, "wxc-wslc-daemon.exe")));
        Assert.True(File.Exists(Path.Combine(AppContext.BaseDirectory, "wslcsdk.dll")));
#else
        var ex = Assert.Throws<MxcException>(dryRun);
        Assert.Equal(ErrorCode.BackendUnavailable, ex.Code);
        Assert.Contains("compiled without the `wslc` feature", ex.Message);
#endif
    }

    [Fact]
    public void IsolationSessionBuildSwitch_MatchesNativeAvailability()
    {
        IsolationSessionProvisionOptions[] forms =
        [
            new IsolationSessionProvisionOptions(new StateAwareNetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Allow,
                    HostLoopback = NetworkAction.Allow,
                },
            }),
        ];
        foreach (var options in forms)
        {
            Action dryRun = () => MxcLifecycle.DryRunProvisionSandbox(
                StateAwareContainment.IsolationSession,
                options);

#if MXC_WITH_ISOLATION_SESSION
            dryRun();
#else
            var ex = Assert.Throws<MxcException>(dryRun);
            Assert.Equal(ErrorCode.BackendUnavailable, ex.Code);
            Assert.Contains("`isolation_session` feature", ex.Message);
#endif
        }
    }

    [Fact]
    public void BuildStartEnvelope_RelaysStableTelemetryWithoutCorrelationVector()
    {
        var options = new StateAwarePhaseOptions
        {
            Telemetry = new TelemetrySettings { Enabled = true },
        };
        var root = MxcLifecycle
            .BuildStartEnvelope(new ContainerId("iso:abc"), options);

        Assert.False(root.ContainsKey("correlationVector"));
        Assert.True(root["telemetry"]?["enabled"]?.GetValue<bool>());
        Assert.Equal(SchemaVersions.StateAware, root["version"]?.GetValue<string>());
        Assert.Null(root["experimental"]);
    }

    [Fact]
    public void BuildExecEnvelope_RelaysStableTelemetryWithoutCorrelationVector()
    {
        var options = new ExecRequest("echo hi")
        {
            Telemetry = new TelemetrySettings { Enabled = true },
        };
        var root = MxcLifecycle.BuildExecEnvelope(
            new ContainerId("iso:abc"),
            options);

        Assert.False(root.ContainsKey("correlationVector"));
        Assert.True(root["telemetry"]?["enabled"]?.GetValue<bool>());
        Assert.Equal(SchemaVersions.StateAware, root["version"]?.GetValue<string>());
        Assert.Null(root["experimental"]);
    }

    [Fact]
    public void ExecRequest_IsRejectedByNonExecPhases()
    {
        Assert.True(
            typeof(StateAwarePhaseOptions).IsAssignableFrom(
                typeof(ExecRequest)));

        var id = new ContainerId("iso:abc");
        var options = new ExecRequest("echo hi") { WorkingDirectory = "C:\\" };

        foreach (var build in new Action[]
                 {
                     () => _ = MxcLifecycle.BuildStartEnvelope(id, options),
                     () => _ = MxcLifecycle.BuildStopEnvelope(id, options),
                     () => _ = MxcLifecycle.BuildDeprovisionEnvelope(id, options),
                 })
        {
            var ex = Assert.Throws<ArgumentException>(build);
            Assert.Contains(nameof(StateAwarePhaseOptions), ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RunInContainerAsync_PreservesCancellationTokenAsThirdParameter()
    {
        static Task<Output> InvokeWithDefaultLiteral(ContainerId id, string command) =>
            MxcLifecycle.RunInContainerAsync(id, new ExecRequest(command), default);

        Assert.NotNull((Func<ContainerId, string, Task<Output>>)InvokeWithDefaultLiteral);
    }

    [Fact]
    public async Task RunBlockingOperationAsync_CancellationCleansUpLateResult()
    {
        using var releaseOperation = new ManualResetEventSlim();
        var operationStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var cleanedUp = new TaskCompletionSource<int>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();

        var task = MxcLifecycle.RunBlockingOperationAsync(
            () =>
            {
                operationStarted.SetResult();
                releaseOperation.Wait();
                return 42;
            },
            cleanedUp.SetResult,
            cancellation.Token);

        await operationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);

        releaseOperation.Set();
        Assert.Equal(42, await cleanedUp.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RunBlockingOperationAsync_PreCancelledTokenDoesNotStartOperation()
    {
        var started = false;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MxcLifecycle.RunBlockingOperationAsync(
                () =>
                {
                    started = true;
                    return 42;
                },
                _ => { },
                cancellation.Token));

        Assert.False(started);
    }
}
