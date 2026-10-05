// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcLifecycleTests
{
    [Theory]
    [InlineData("StartContainer")]
    [InlineData("StopContainer")]
    [InlineData("DeprovisionContainer")]
    public void LifecycleApis_ReturnLifecycleResult(string method)
    {
        Assert.Equal(typeof(LifecycleResult), typeof(MxcLifecycle).GetMethod(method)!.ReturnType);
    }

    [Fact]
    public void LifecycleAndProvisionResults_PreserveWarnings()
    {
        var result = JsonNode.Parse("""{"sandboxId":"wslc:test","warnings":["cleanup warning"]}""")!.AsObject();
        Assert.Equal(["cleanup warning"], MxcLifecycle.ParseLifecycleResult(result).Warnings);
        Assert.Equal(["cleanup warning"],
            MxcLifecycle.ParseProvisionResult(LifecycleContainmentKind.Wslc, result).Warnings);
        Assert.Empty(MxcLifecycle.ParseLifecycleResult(new JsonObject()).Warnings);
    }

    [Theory]
    [InlineData("""{"warnings":null}""")]
    [InlineData("""{"warnings":[null]}""")]
    [InlineData("""{"warnings":[1]}""")]
    [InlineData("""{"warnings":"warning"}""")]
    public void LifecycleAndProvisionResults_RejectMalformedWarnings(string json)
    {
        var result = JsonNode.Parse(json)!.AsObject();
        Assert.Equal(ErrorCode.BackendError,
            Assert.Throws<MxcException>(() => MxcLifecycle.ParseLifecycleResult(result)).Code);
        result["sandboxId"] = "wslc:test";
        Assert.Equal(ErrorCode.BackendError, Assert.Throws<MxcException>(() =>
            MxcLifecycle.ParseProvisionResult(LifecycleContainmentKind.Wslc, result)).Code);
    }

    [Theory]
    [InlineData("""{}""")]
    [InlineData("""{"agentUserName":null,"agentUserSid":"sid","ephemeralWorkspacePath":"path"}""")]
    [InlineData("""{"agentUserName":"agent","agentUserSid":1,"ephemeralWorkspacePath":"path"}""")]
    public void ProvisionResult_RejectsIncompleteMetadata(string json)
    {
        var result = new JsonObject { ["sandboxId"] = "iso:test", ["metadata"] = JsonNode.Parse(json) };
        Assert.Equal(ErrorCode.BackendError, Assert.Throws<MxcException>(() =>
            MxcLifecycle.ParseProvisionResult(LifecycleContainmentKind.IsolationSession, result)).Code);
    }

    [Theory]
    [InlineData("ValidateProvision")]
    [InlineData("ValidateStart")]
    [InlineData("ValidateStop")]
    [InlineData("ValidateDeprovision")]
    [InlineData("ValidateProcess")]
    public void ValidationApis_ReturnValidationResult(string method)
    {
        Assert.Equal(typeof(ValidationResult), typeof(MxcLifecycle).GetMethod(method)!.ReturnType);
    }

    [Fact]
    public void ValidationResult_PreservesWarningsAndDefaultsOnlyOmittedWarnings()
    {
        var result = MxcLifecycle.ParseValidationResult(
            JsonNode.Parse("""{"warnings":["policy warning","telemetry warning"]}""")!.AsObject());
        Assert.Equal(["policy warning", "telemetry warning"], result.Warnings);
        Assert.Empty(MxcLifecycle.ParseValidationResult(new JsonObject()).Warnings);
        Assert.Empty(MxcLifecycle.ParseValidationResult(
            JsonNode.Parse("""{"warnings":[]}""")!.AsObject()).Warnings);
    }

    [Theory]
    [InlineData("""{"warnings":null}""")]
    [InlineData("""{"warnings":"warning"}""")]
    [InlineData("""{"warnings":[null]}""")]
    [InlineData("""{"warnings":[1]}""")]
    public void ValidationResult_RejectsMalformedWarnings(string json)
    {
        var error = Assert.Throws<MxcException>(() => MxcLifecycle.ParseValidationResult(
            JsonNode.Parse(json)!.AsObject()));
        Assert.Equal(ErrorCode.BackendError, error.Code);
    }

    [Fact]
    public void ValidationResult_RejectsMissingResult()
    {
        var error = Assert.Throws<MxcException>(() => MxcLifecycle.ParseValidationResult(null));
        Assert.Equal(ErrorCode.BackendError, error.Code);
    }

    [Fact]
    public void ProvisionResult_MapsNativeMetadataToClosedTypedSurface()
    {
        var result = MxcLifecycle.ParseProvisionResult(
            LifecycleContainmentKind.IsolationSession,
            JsonNode.Parse("""
                {"sandboxId":"iso:test","metadata":{"agentUserName":"agent","agentUserSid":"S-1-5-21","ephemeralWorkspacePath":"C:\\workspace"}}
                """)!.AsObject());

        Assert.Equal(new ContainerId("iso:test"), result.ContainerId);
        var metadata = Assert.IsType<IsolationSessionProvisionMetadata>(result.Metadata);
        Assert.Equal("agent", metadata.AgentUserName);
        Assert.Equal("S-1-5-21", metadata.AgentUserSid);
        Assert.Equal("C:\\workspace", metadata.EphemeralWorkspacePath);
        Assert.Null(typeof(ProvisionResult).GetProperty("MetadataJson"));
        Assert.Null(typeof(ProvisionResult).GetProperty("IsolationSessionMetadata"));
        var constructor = Assert.Single(typeof(ProvisionMetadata).GetConstructors(
            BindingFlags.Instance | BindingFlags.NonPublic));
        Assert.True(constructor.IsFamilyAndAssembly);
    }

    [Theory]
    [InlineData(LifecycleContainmentKind.IsolationSession)]
    [InlineData(LifecycleContainmentKind.Wslc)]
    public void ProvisionResult_PreservesAbsentMetadata(LifecycleContainmentKind containment)
    {
        var result = MxcLifecycle.ParseProvisionResult(
            containment,
            JsonNode.Parse("""{"sandboxId":"opaque-id"}""")!.AsObject());
        Assert.Null(result.Metadata);
    }

    [Fact]
    public void ProvisionResult_RejectsUnsupportedMetadataAndMissingIdentity()
    {
        var error = Assert.Throws<MxcException>(() => MxcLifecycle.ParseProvisionResult(
            LifecycleContainmentKind.Wslc,
            JsonNode.Parse("""{"sandboxId":"wslc:test","metadata":{"unexpected":true}}""")!.AsObject()));
        Assert.Equal(ErrorCode.BackendError, error.Code);
        Assert.Contains("unsupported metadata", error.Message);
        Assert.Throws<MxcException>(() => MxcLifecycle.ParseProvisionResult(
            LifecycleContainmentKind.IsolationSession,
            new JsonObject()));
    }

    [Fact]
    public void StartContainer_IsolationSessionDoesNotRequireExperimentalOptIn()
    {
        // IsolationSession must reach backend dispatch without an experimental
        // opt-in, so an experimental-gate refusal must not appear.
        // A registered prefix carrying an id that was never provisioned cannot
        // succeed, so the assertion holds whether or not the isolation_session
        // feature was compiled in and whether or not the host has the service --
        // and it provisions nothing.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartContainer(new ContainerId("iso:0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"the experimental opt-in did not reach the engine: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartContainer_WslcDoesNotRequireExperimentalOptIn()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartContainer(
                new ContainerId("wslc:0123456789abcdef0123456789abcdef")));

        Assert.False(
            ex.Code == ErrorCode.BackendUnavailable
                && ex.Message.Contains("experimental", StringComparison.OrdinalIgnoreCase),
            $"WSLC must reach ordinary backend availability: {ex.Code}: {ex.Message}");
    }

    [Fact]
    public void StartContainer_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        // A non-provision phase resolves the backend from the id prefix; an
        // unknown prefix is unsupported_containment, independent of host and
        // build features.
        var id = new ContainerId("bogus:12345");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StartContainer(id));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void SpawnInContainer_RejectsWindowsSandboxIds()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.SpawnInContainer(
                new ContainerId("wsb:0a1b2c3d"),
                new ExecutionRequest("echo hi")));

        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
        Assert.Contains("raw exact 1.1.0-alpha state-aware executor route", ex.Message, StringComparison.Ordinal);
        Assert.Contains("explicit experimental authorization", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'wsb:'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void StartContainer_RejectsWindowsSandboxIds()
    {
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StartContainer(new ContainerId("wsb:0a1b2c3d")));

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
                     () => MxcLifecycle.StopContainer(id),
                     () => MxcLifecycle.DeprovisionContainer(id),
                     () => MxcLifecycle.ValidateProcess(id, new ExecutionRequest("echo hi")),
                 })
        {
            var ex = Assert.Throws<MxcException>(action);
            Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
            Assert.Contains("raw exact 1.1.0-alpha", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void StopContainer_MalformedId_ThrowsMalformedId()
    {
        // No backend prefix at all is a malformed id.
        var id = new ContainerId("no-prefix");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopContainer(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopContainer_MalformedIdWithVersionOverride_ThrowsMalformedId()
    {
        var id = new ContainerId("no-prefix");
        var options = new StopOptions { Version = "0.8.0-alpha" };

        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StopContainer(id, options));

        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopContainer_EmptyPrefix_ThrowsMalformedId()
    {
        // ":payload" clears the ctor's null/empty check and has a colon, but an
        // empty prefix is structural rather than an unregistered backend. The
        // native parse_sandbox_id_prefix pins the same split.
        var id = new ContainerId(":payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopContainer(id));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopContainer_DefaultId_ThrowsMalformedId()
    {
        // default(ContainerId) is legal and leaves Value null; it must surface a
        // typed error rather than a NullReferenceException.
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.StopContainer(default));
        Assert.Equal(ErrorCode.MalformedId, ex.Code);
    }

    [Fact]
    public void StopContainer_UnknownPrefix_ThrowsUnsupportedContainment()
    {
        // A non-empty prefix is well-formed, so it stays UnsupportedContainment
        // and does not get folded into MalformedId by the guard above.
        var id = new ContainerId("nope:payload");
        var ex = Assert.Throws<MxcException>(() => MxcLifecycle.StopContainer(id));
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
        var options = new WslcProvisionRequest
        {
            Network = new NetworkPolicy
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
        var roundTripped = JsonSerializer.Deserialize<WslcProvisionRequest>(json, jsonOptions)!;
        var envelope = MxcLifecycle.BuildProvisionEnvelope(
            LifecycleContainmentKind.Wslc,
            roundTripped);

        Assert.DoesNotContain("defaultPolicy", json, StringComparison.Ordinal);
        Assert.DoesNotContain("allowLocalNetwork", json, StringComparison.Ordinal);
        Assert.NotNull(envelope["network"]);
    }

    [Fact]
    public void IsolationSessionProvisionOptions_RejectsNullNetwork()
    {
        Assert.Throws<ArgumentNullException>(
            () => new IsolationSessionProvisionRequest(null!));
    }

    [Fact]
    public void BuildProvisionEnvelope_RejectsNetworkResetToNull()
    {
        var options = new IsolationSessionProvisionRequest(new NetworkPolicy())
        {
            Network = null!,
        };

        var error = Assert.Throws<ArgumentNullException>(
            () => MxcLifecycle.BuildProvisionEnvelope(
                LifecycleContainmentKind.IsolationSession,
                options));
        Assert.Equal("network", error.ParamName);
    }

    [Fact]
    public void IsolationSessionProvisionOptions_RequiresNetworkPolicy()
    {
        var constructor = Assert.Single(typeof(IsolationSessionProvisionRequest).GetConstructors());
        Assert.Equal(
            typeof(NetworkPolicy),
            Assert.Single(constructor.GetParameters()).ParameterType);
        Assert.NotNull(typeof(IsolationSessionProvisionRequest).GetProperty("Network"));
    }

    [Fact]
    public void SpawnInContainer_UnregisteredPrefix_ThrowsUnsupportedContainment()
    {
        var id = new ContainerId("bogus:12345");
        var ex = Assert.Throws<MxcException>(
            () => MxcLifecycle.SpawnInContainer(id, new ExecutionRequest("echo hi")));
        Assert.Equal(ErrorCode.UnsupportedContainment, ex.Code);
    }

    [Fact]
    public void SpawnInContainer_NullRequest_Throws()
    {
        var id = new ContainerId("iso:12345");
        Assert.Throws<ArgumentNullException>(() => MxcLifecycle.SpawnInContainer(id, null!));
    }

    [Fact]
    public void ExecuteInContainerAttached_RemainsPrivateAndUnused()
    {
        var method = typeof(MxcLifecycle).GetMethod(
            "ExecuteInContainerAttached",
            System.Reflection.BindingFlags.NonPublic
                | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        Assert.True(method!.IsPrivate);
        Assert.Equal(typeof(WaitResult), method.ReturnType);
        Assert.Null(typeof(IContainerLifecycle).GetMethod("ExecuteInContainerAttached"));
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
                LifecycleContainmentKind.Wslc,
                new WslcProvisionRequest { Network = new NetworkPolicy() })
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
                LifecycleContainmentKind.IsolationSession,
                null));
    }

    [Fact]
    public void BuildExecEnvelope_CarriesSandboxIdAndCommandLine()
    {
        var json = MxcLifecycle
            .BuildExecEnvelope(
                new ContainerId("iso:abc"),
                new ExecutionRequest("cmd /c echo hi"))
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
                new ExecutionRequest("echo hi")
                {
                    Network = new ProcessNetworkPolicy
                    {
                        RuntimeConfig = new NetworkRuntimeConfig
                        {
                            NetworkProxy = "http://proxy.example:8080",
                        },
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
            new ExecutionRequest("echo test")
            {
                Network = new ProcessNetworkPolicy
                {
                    RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = url },
                },
            }));
    }

    [Fact]
    public void StateAwareTypes_KeepNetworkAndAcknowledgmentOutOfLaterPhases()
    {
        Assert.Null(typeof(StartOptions).GetProperty("Network"));
        Assert.Null(typeof(StartOptions).GetProperty("RuntimeConfig"));
        Assert.Null(typeof(StartOptions).GetProperty("AcknowledgeUnrestrictedNetwork"));
        Assert.NotNull(typeof(ExecutionRequest).GetProperty("Network"));
        Assert.Null(typeof(ExecutionRequest).GetProperty("RuntimeConfig"));
        Assert.NotNull(typeof(ProcessNetworkPolicy).GetProperty("RuntimeConfig"));
        Assert.Null(typeof(ProcessNetworkPolicy).GetProperty("Egress"));
        Assert.Null(typeof(ProcessNetworkPolicy).GetProperty("Ingress"));
    }

    [Theory]
    [InlineData(nameof(MxcLifecycle.StartContainer), typeof(StartOptions))]
    [InlineData(nameof(MxcLifecycle.StopContainer), typeof(StopOptions))]
    [InlineData(nameof(MxcLifecycle.DeprovisionContainer), typeof(DeprovisionOptions))]
    public void NonExecPhases_RequireTheirOwnOptions(string operation, Type optionsType)
    {
        var method = typeof(MxcLifecycle).GetMethod(operation);
        Assert.NotNull(method);
        Assert.Equal(optionsType, method.GetParameters()[1].ParameterType);
        Assert.False(optionsType.IsAssignableFrom(typeof(ExecutionRequest)));
        Assert.Null(optionsType.GetProperty(nameof(ExecutionRequest.Network)));
    }

    [Fact]
    public void Lifecycle_ExposesDryRunForEveryPhase()
    {
        var names = typeof(MxcLifecycle)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(method => method.Name)
            .Where(name => name.StartsWith("Validate", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[]
            {
                "ValidateDeprovision",
                "ValidateProcess",
                "ValidateProvision",
                "ValidateStart",
                "ValidateStop",
            },
            names);
    }

    [Fact]
    public void WslcBuildSwitch_MatchesNativeAvailabilityAndStagesRuntimeUnit()
    {
        Action dryRun = () => MxcLifecycle.ValidateProvision(
            new WslcProvisionRequest { Image = "alpine:latest" });

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
        IsolationSessionProvisionRequest[] forms =
        [
            new IsolationSessionProvisionRequest(new NetworkPolicy
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
            Action dryRun = () => MxcLifecycle.ValidateProvision(
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
        var options = new StartOptions
        {
            Telemetry = new TelemetryConfig { Enabled = true },
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
        var options = new ExecutionRequest("echo hi")
        {
            Telemetry = new TelemetryConfig { Enabled = true },
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
    public void ProcessRequest_IsRejectedByNonExecPhases()
    {
        Assert.False(
            typeof(StartOptions).IsAssignableFrom(
                typeof(ExecutionRequest)));
        Assert.Null(typeof(ExecutionRequest).GetProperty(nameof(StartOptions.Experimental)));
    }

    [Fact]
    public void RunInContainerAsync_AcceptsOptionsBeforeCancellation()
    {
        static Task<ExecutionResult> InvokeWithDefaultLiteral(ContainerId id, string command) =>
            MxcLifecycle.RunInContainerAsync(id, new ExecutionRequest(command), default, default);

        Assert.NotNull((Func<ContainerId, string, Task<ExecutionResult>>)InvokeWithDefaultLiteral);
        var parameters = typeof(MxcLifecycle)
            .GetMethod(nameof(MxcLifecycle.RunInContainerAsync))!.GetParameters();
        Assert.Equal(typeof(RunInContainerOptions), parameters[2].ParameterType);
        Assert.Equal(typeof(CancellationToken), parameters[3].ParameterType);
    }

    [Fact]
    public async Task RunAsync_PreCancelledTokenDoesNotExecuteRequest()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MxcContainer.RunAsync(
                new ContainerRequest(""),
                cancellationToken: cancellation.Token));
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
