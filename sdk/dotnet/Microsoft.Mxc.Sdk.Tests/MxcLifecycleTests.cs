// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcLifecycleTests
{
    [Fact]
    public void StateAwareSerialization_MatchesCrossLanguageGoldens()
    {
        var provision = MxcLifecycle.BuildProvisionEnvelope(
            StateAwareContainment.Wslc,
            new WslcProvisionOptions
            {
                Filesystem = new StateAwareFilesystemPolicy
                {
                    ReadwritePaths = [@"C:\work"],
                },
                Network = new StateAwareNetworkPolicy
                {
                    DefaultPolicy = StateAwareNetworkDefault.Allow,
                },
                Image = "alpine:3.20",
                ImageTarPath = @"C:\images\alpine.tar",
            });
        var exec = MxcLifecycle.BuildExecEnvelope(
            new SandboxId("wslc:0123456789abcdef0123456789abcdef"),
            "printf parity",
            new WslcExecOptions
            {
                WorkingDirectory = "/work",
                Environment = ["A=1", "B=two"],
                TimeoutMs = 1234,
                Network = new WslcExecNetworkPolicy
                {
                    Proxy = new UrlNetworkProxyPolicy("http://proxy.example:8080"),
                },
            });

        JsonAssert.MatchesGolden(
            provision.ToJsonString(),
            "state-aware-wslc-provision.json");
        JsonAssert.MatchesGolden(exec.ToJsonString(), "state-aware-wslc-exec.json");
    }

    [Fact]
    public void StartSandbox_PassesTheExperimentalOptIn()
    {
        // Without the opt-in the engine refuses an experimental backend *before*
        // backend dispatch, with BackendUnavailable naming "experimental". This
        // facade always passes it, so that specific refusal must not appear.
        // A registered prefix carrying an id that was never provisioned cannot
        // succeed, so the assertion holds whether or not the isolation_session
        // feature was compiled in and whether or not the host has the service --
        // and it provisions nothing.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartSandbox(new SandboxId("iso:0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        // A non-provision phase resolves the backend from the id prefix; an
        // unknown prefix is unsupported_containment, independent of host and
        // build features.
        var id = new SandboxId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StartSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void ExecInSandbox_PassesTheExperimentalOptIn()
    {
        // The streaming entry point carries the opt-in on its own path: it and the
        // envelope phases reach the same gate by different routes, so hardcoding
        // the flag in one would leave the other green. A `wsb:` id resolves to an
        // experimental backend without a host, a compiled-in isolation_session
        // feature, or a provisioned sandbox.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.ExecInSandbox(new SandboxId("wsb:0a1b2c3d"), "echo hi"));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void ExecInSandboxAttached_WithoutATerminal_ThrowsMalformedRequest()
    {
        // Crosses mxc_state_aware_exec_attached itself, which the envelope tests
        // cannot: it is a separate entry point. That gate short-circuits ahead of
        // backend dispatch, which is also why this test cannot pin the
        // experimental opt-in.
        Assert.SkipUnless(
            Console.IsOutputRedirected && Console.IsInputRedirected,
            "a console host satisfies the terminal gate, so the call would "
                + "dispatch a real attached exec rather than be refused by it");

        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.ExecInSandboxAttached(
                new SandboxId("iso:0123456789abcdef"), "echo hi"));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
    }

    [Fact]
    public void StopSandbox_MalformedId_ThrowsMalformedId()
    {
        // No backend prefix at all is a malformed id.
        var id = new SandboxId("no-prefix");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_MalformedIdWithVersionOverride_ThrowsMalformedId()
    {
        var id = new SandboxId("no-prefix");
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
        var id = new SandboxId(":payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopSandbox_DefaultId_ThrowsMalformedId()
    {
        // default(SandboxId) is legal and leaves Value null; it must surface a
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
        var id = new SandboxId("nope:payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopSandbox(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData(StateAwareNetworkDefault.Allow, null)]
    [InlineData(StateAwareNetworkDefault.Block, true)]
    [InlineData(StateAwareNetworkDefault.Allow, false)]
    public void IsolationSessionProvisionOptions_RejectsNonAcknowledgingNetwork(
        StateAwareNetworkDefault? defaultPolicy,
        bool? allowLocalNetwork)
    {
        var network = new StateAwareNetworkPolicy
        {
            DefaultPolicy = defaultPolicy,
            AllowLocalNetwork = allowLocalNetwork,
        };

        Assert.Throws<ArgumentException>(
            () => new IsolationSessionProvisionOptions(network));
    }

    [Fact]
    public void BuildProvisionEnvelope_RevalidatesMutatedIsolationSessionNetwork()
    {
        var options = new IsolationSessionProvisionOptions(
            new StateAwareNetworkPolicy
            {
                DefaultPolicy = StateAwareNetworkDefault.Allow,
                AllowLocalNetwork = true,
            });
        options.Network.AllowLocalNetwork = false;

        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                options));
    }

    [Theory]
    [InlineData("allowedHosts")]
    [InlineData("blockedHosts")]
    [InlineData("proxy")]
    public void BuildProvisionEnvelope_RejectsMutatedIsolationSessionNetworkRestrictions(
        string restriction)
    {
        var options = new IsolationSessionProvisionOptions(
            new StateAwareNetworkPolicy
            {
                DefaultPolicy = StateAwareNetworkDefault.Allow,
                AllowLocalNetwork = true,
            });

        switch (restriction)
        {
            case "allowedHosts":
                options.Network.AllowedHosts = ["example.com"];
                break;
            case "blockedHosts":
                options.Network.BlockedHosts = ["example.com"];
                break;
            case "proxy":
                options.Network.Proxy = new UrlNetworkProxyPolicy(
                    "http://proxy.example:8080");
                break;
        }

        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                options));
    }

    [Fact]
    public void ExecInSandbox_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        var id = new SandboxId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.ExecInSandbox(id, "echo hi"));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void ExecInSandbox_NullCommand_Throws()
    {
        var id = new SandboxId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.ExecInSandbox(id, null!));
    }

    [Fact]
    public void ExecInSandboxAttached_NullCommand_Throws()
    {
        var id = new SandboxId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.ExecInSandboxAttached(id, null!));
    }

    [Fact]
    public void SandboxId_RoundTripsAndCompares()
    {
        var a = new SandboxId("iso:abc");
        var b = new SandboxId("iso:abc");
        var c = new SandboxId("iso:xyz");
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal("iso:abc", a.Value);
        Assert.Equal("iso:abc", a.ToString());
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void SandboxId_EmptyValue_Throws()
    {
        Assert.Throws<ArgumentException>(() => new SandboxId(""));
        Assert.Throws<ArgumentException>(() => new SandboxId(null!));
    }

    [Fact]
    public void BuildProvisionEnvelope_LiftsNetworkAndFilesystem_NestsAppId()
    {
        var options = new ProvisionSandboxOptions
        {
            Network = new StateAwareNetworkPolicy
            {
                DefaultPolicy = StateAwareNetworkDefault.Allow,
                AllowLocalNetwork = true,
            },
            Filesystem = new StateAwareFilesystemPolicy { ReadwritePaths = { @"C:\Temp" } },
            AppId = "PFN:Contoso.App_8wekyb3d8bbwe",
        };

        var json = MxcLifecycle
            .BuildProvisionEnvelope(StateAwareContainment.IsolationSession, options)
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("provision", root.GetProperty("phase").GetString());
        Assert.Equal("isolation_session", root.GetProperty("containment").GetString());

        // Cross-cutting policy is lifted to the envelope top level. The backend
        // reads `network` there; nesting it under experimental would leave the
        // acknowledgment unseen and provision would be refused as default-deny.
        var network = root.GetProperty("network");
        Assert.Equal("allow", network.GetProperty("defaultPolicy").GetString());
        Assert.True(network.GetProperty("allowLocalNetwork").GetBoolean());
        Assert.Equal(@"C:\Temp",
            root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());

        // Backend-specific config nests.
        var provision = root.GetProperty("experimental")
            .GetProperty("isolation_session")
            .GetProperty("provision");
        Assert.Equal("PFN:Contoso.App_8wekyb3d8bbwe", provision.GetProperty("appId").GetString());
    }

    [Fact]
    public void BuildProvisionEnvelope_OmitsAnUnspecifiedNetworkPosture()
    {
        // Optional mode fields must remain absent when the caller did not
        // specify them. Post-provision backends reject mode fields by presence.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                new ProvisionSandboxOptions { Network = new StateAwareNetworkPolicy() })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);

        var network = doc.RootElement.GetProperty("network");
        Assert.False(network.TryGetProperty("defaultPolicy", out _));
        Assert.False(network.TryGetProperty("allowLocalNetwork", out _));
    }

    [Fact]
    public void BuildProvisionEnvelope_SendsOnlyTheFilesystemFieldsTheWireAccepts()
    {
        // The lifecycle wire rejects an unknown filesystem member outright, so
        // this type carries only the members it accepts.
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.IsolationSession,
                new ProvisionSandboxOptions { Filesystem = new StateAwareFilesystemPolicy() })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);

        var names = doc.RootElement.GetProperty("filesystem")
            .EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[] { "deniedPaths", "readonlyPaths", "readwritePaths" }, names);

        // Serialization omits nulls, so the assertion above cannot see a nullable
        // member — the shape of the one-shot member this type exists to exclude.
        // Pin the public surface itself, as MxcExceptionTests does for its
        // constructor.
        var properties = typeof(StateAwareFilesystemPolicy)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[] { "DeniedPaths", "ReadonlyPaths", "ReadwritePaths" }, properties);
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
    public void BuildProvisionEnvelope_WindowsSandboxLiftsFilesystem()
    {
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.WindowsSandbox,
                new WindowsSandboxProvisionOptions
                {
                    Filesystem = new StateAwareFilesystemPolicy
                    {
                        ReadonlyPaths = { @"C:\input" },
                    },
                })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("windows_sandbox", root.GetProperty("containment").GetString());
        Assert.Equal(
            @"C:\input",
            root.GetProperty("filesystem").GetProperty("readonlyPaths")[0].GetString());
        Assert.False(root.TryGetProperty("experimental", out _));
    }

    [Fact]
    public void BuildProvisionEnvelope_WslcUsesV08AndNestsImageOptions()
    {
        var json = MxcLifecycle
            .BuildProvisionEnvelope(
                StateAwareContainment.Wslc,
                new WslcProvisionOptions
                {
                    Image = "alpine:latest",
                    ImageTarPath = @"C:\images\alpine.tar",
                    Network = new StateAwareNetworkPolicy
                    {
                        DefaultPolicy = StateAwareNetworkDefault.Allow,
                    },
                })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.8.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("wslc", root.GetProperty("containment").GetString());
        Assert.Equal(
            "allow",
            root.GetProperty("network").GetProperty("defaultPolicy").GetString());
        var provision = root.GetProperty("experimental")
            .GetProperty("wslc")
            .GetProperty("provision");
        Assert.Equal("alpine:latest", provision.GetProperty("image").GetString());
        Assert.Equal(
            @"C:\images\alpine.tar",
            provision.GetProperty("imageTarPath").GetString());
    }

    [Fact]
    public void BuildProvisionEnvelope_RejectsOptionsForAnotherBackend()
    {
        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                StateAwareContainment.WindowsSandbox,
                new WslcProvisionOptions()));
    }

    [Fact]
    public void BuildExecEnvelope_CarriesSandboxIdAndCommandLine()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(new SandboxId("iso:abc"), "cmd /c echo hi")
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
    public void BuildExecEnvelope_CarriesProcessOptionsAndWslcProxy()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(
                new SandboxId("wslc:0123456789abcdef0123456789abcdef"),
                "echo hi",
                new WslcExecOptions
                {
                    WorkingDirectory = "/work",
                    Environment = new List<string> { "A=1", "B=two" },
                    TimeoutMs = 1234,
                    Network = new WslcExecNetworkPolicy
                    {
                        Proxy = new UrlNetworkProxyPolicy("http://proxy.example:8080"),
                    },
                })
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.8.0-alpha", root.GetProperty("version").GetString());
        var process = root.GetProperty("process");
        Assert.Equal("/work", process.GetProperty("cwd").GetString());
        Assert.Equal("A=1", process.GetProperty("env")[0].GetString());
        Assert.Equal("B=two", process.GetProperty("env")[1].GetString());
        Assert.Equal(1234, process.GetProperty("timeout").GetInt32());
        var network = root.GetProperty("network");
        Assert.Equal(
            "http://proxy.example:8080",
            network.GetProperty("proxy").GetProperty("url").GetString());
        Assert.False(network.TryGetProperty("defaultPolicy", out _));
        Assert.False(network.TryGetProperty("allowLocalNetwork", out _));
    }

    [Fact]
    public void BuildExecEnvelope_RejectsWslcOptionsForAnotherBackend()
    {
        Assert.Throws<ArgumentException>(
            () => MxcLifecycle.BuildExecEnvelope(
                new SandboxId("iso:abc"),
                "echo hi",
                new WslcExecOptions()));
    }

    [Fact]
    public void BuildStartEnvelope_CarriesVersionAndSandboxIdOnly()
    {
        // The backend's start config is empty, so anything else on this envelope
        // would be a field the backend rejects or silently drops.
        var json = MxcLifecycle
            .BuildStartEnvelope(new SandboxId("iso:abc"))
            .ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("0.6.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal("start", root.GetProperty("phase").GetString());
        Assert.Equal("iso:abc", root.GetProperty("sandboxId").GetString());
        Assert.False(root.TryGetProperty("experimental", out _));
        Assert.False(root.TryGetProperty("network", out _));
    }

    [Fact]
    public void IdPhases_InferBackendVersionAndHonorOverrides()
    {
        var wslcStart = MxcLifecycle.BuildStartEnvelope(
            new SandboxId("wslc:0123456789abcdef0123456789abcdef"));
        var wsbStop = MxcLifecycle.BuildStopEnvelope(new SandboxId("wsb:01234567"));
        var overridden = MxcLifecycle.BuildDeprovisionEnvelope(
            new SandboxId("iso:abc"),
            new StateAwarePhaseOptions { Version = "0.9.0-alpha" });

        Assert.Equal("0.8.0-alpha", wslcStart["version"]!.GetValue<string>());
        Assert.Equal("0.6.0-alpha", wsbStop["version"]!.GetValue<string>());
        Assert.Equal("0.9.0-alpha", overridden["version"]!.GetValue<string>());
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
                "DryRunExecInSandbox",
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
        Action dryRun = () => MxcLifecycle.DryRunProvisionSandbox(
            StateAwareContainment.IsolationSession,
            new IsolationSessionProvisionOptions(
                new StateAwareNetworkPolicy
                {
                    DefaultPolicy = StateAwareNetworkDefault.Allow,
                    AllowLocalNetwork = true,
                }));

#if MXC_WITH_ISOLATION_SESSION
        dryRun();
#else
        var ex = Assert.Throws<MxcException>(dryRun);
        Assert.Equal(ErrorCode.BackendUnavailable, ex.Code);
        Assert.Contains("`isolation_session` feature", ex.Message);
#endif
    }

    [Fact]
    public void BuildStartEnvelope_RelaysStableTelemetryWithoutCorrelationVector()
    {
        var options = new StartSandboxOptions
        {
            Telemetry = new TelemetrySettings { Enabled = true },
        };
        var root = MxcLifecycle
            .BuildStartEnvelope(new SandboxId("iso:abc"), options);

        Assert.False(root.ContainsKey("correlationVector"));
        Assert.True(root["telemetry"]?["enabled"]?.GetValue<bool>());
        Assert.Equal(SchemaVersions.MaximumSupported, root["version"]?.GetValue<string>());
        Assert.Null(root["experimental"]);
    }

    [Fact]
    public void BuildExecEnvelope_RelaysStableTelemetryWithoutCorrelationVector()
    {
        var options = new StateAwareExecOptions
        {
            Telemetry = new TelemetrySettings { Enabled = true },
        };
        var root = MxcLifecycle.BuildExecEnvelope(
            new SandboxId("iso:abc"),
            "echo hi",
            options);

        Assert.False(root.ContainsKey("correlationVector"));
        Assert.True(root["telemetry"]?["enabled"]?.GetValue<bool>());
        Assert.Equal(SchemaVersions.MaximumSupported, root["version"]?.GetValue<string>());
        Assert.Null(root["experimental"]);
    }

    [Fact]
    public void ExecOptions_AreNotAcceptedByNonExecPhases()
    {
        Assert.False(
            typeof(StateAwarePhaseOptions).IsAssignableFrom(
                typeof(StateAwareExecOptions)));
    }

    [Fact]
    public void BuildStartEnvelope_LeavesExplicitTelemetryVersionForNativeValidation()
    {
        var options = new StartSandboxOptions
        {
            Version = SchemaVersions.LatestStable,
            Telemetry = new TelemetrySettings { Enabled = false },
        };

        var root = MxcLifecycle.BuildStartEnvelope(new SandboxId("iso:abc"), options);
        Assert.Equal(SchemaVersions.LatestStable, root["version"]?.GetValue<string>());
        Assert.False(root["telemetry"]?["enabled"]?.GetValue<bool>());
    }

    [Fact]
    public void ExecInSandboxAsync_PreservesCancellationTokenAsThirdParameter()
    {
        static Task<RunResult> InvokeWithDefaultLiteral(SandboxId id, string command) =>
            MxcLifecycle.ExecInSandboxAsync(id, command, default);

        Assert.NotNull((Func<SandboxId, string, Task<RunResult>>)InvokeWithDefaultLiteral);
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
