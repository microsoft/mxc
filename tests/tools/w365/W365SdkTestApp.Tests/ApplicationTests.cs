// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace W365SdkTestApp.Tests;

public sealed class ApplicationTests : IDisposable
{
    internal const string Pool = "11111111-1111-1111-1111-111111111111";
    internal const string Owner = "33333333-3333-3333-3333-333333333333";
    internal const string Id = $"w365:{Pool}:22222222-2222-2222-2222-222222222222";
    private readonly string directory = Path.Combine(Path.GetTempPath(), $"mxc-w365-app-tests-{Guid.NewGuid():N}");
    private readonly string configPath;
    private readonly string receiptPath;
    private readonly Configuration config = new()
    {
        PoolId = Pool, TenantId = Pool, ClientId = Pool,
        ControlPlaneHost = "control.example.invalid", DataPlaneSuffix = "data.example.invalid",
    };

    public ApplicationTests()
    {
        Directory.CreateDirectory(directory);
        configPath = Path.Combine(directory, "config.json");
        receiptPath = Path.Combine(directory, "receipt.json");
        File.WriteAllText(configPath, JsonSerializer.Serialize(config, Configuration.JsonOptions));
    }

    private async Task<(int Exit, JsonObject Result)> Run(FakeSdk sdk, string operation = "run",
        string? id = null, FakeAuth? auth = null, bool dry = false)
    {
        var args = new List<string> { operation, "--config", configPath, "--receipt-path", receiptPath };
        if (operation == "run") args.AddRange(["--command", "cmd.exe /c echo fixture"]);
        if (id is not null) args.AddRange(["--session-id", id]);
        if (dry) args.Add("--dry-run");
        return await Invoke(args.ToArray(), auth ?? new FakeAuth(), sdk);
    }

    internal static async Task<(int Exit, JsonObject Result)> Invoke(string[] args, IAuthentication auth, ISdk sdk)
    {
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exit = await Application.RunAsync(args, auth, sdk);
            var text = output.ToString();
            Assert.DoesNotContain("SYNTHETIC_PRIVATE_TOKEN", text);
            return (exit, JsonNode.Parse(text)!.AsObject());
        }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task RunCreatesOnceThenReusesAndReleasesExplicitly()
    {
        var sdk = new FakeSdk();
        var first = await Run(sdk);
        Assert.Equal(0, first.Exit);
        Assert.Equal(Id, first.Result["sessionId"]!.GetValue<string>());
        Assert.Equal(new[] { "provision", "start", "exec" }, sdk.Live);
        sdk.Live.Clear();
        Assert.Equal(0, (await Run(sdk, id: Id)).Exit);
        Assert.Equal(new[] { "start", "exec" }, sdk.Live);
        sdk.Live.Clear();
        var release = await Run(sdk, "release", Id);
        Assert.Equal(0, release.Exit);
        Assert.True(release.Result["releaseAccepted"]!.GetValue<bool>());
        Assert.False(release.Result["remoteResetConfirmed"]!.GetValue<bool>());
        Assert.Equal(new[] { "deprovision" }, sdk.Live);
        sdk.Live.Clear();
        Assert.Equal(1, (await Run(sdk, id: Id)).Exit);
        Assert.Empty(sdk.Live);
        Assert.DoesNotContain("SYNTHETIC_PRIVATE_TOKEN", File.ReadAllText(receiptPath));
    }

    [Theory]
    [InlineData("provision")]
    [InlineData("start")]
    [InlineData("exec")]
    public async Task FailuresRetainKnownIdentityAndNeverReleaseOrReplay(string phase)
    {
        var sdk = new FakeSdk { Failure = phase };
        var result = await Run(sdk);
        Assert.Equal(1, result.Exit);
        Assert.DoesNotContain("deprovision", sdk.Live);
        Assert.Equal(1, sdk.Live.Count(item => item == "provision"));
        if (phase != "provision") Assert.Equal(Id, result.Result["sessionId"]!.GetValue<string>());
        sdk.Failure = null;
        sdk.Live.Clear();
        Assert.Equal(1, (await Run(sdk)).Exit);
        Assert.Empty(sdk.Live);
    }

    [Fact]
    public async Task GuestNonzeroIsReturnedWithoutRelease()
    {
        var sdk = new FakeSdk { ExitCode = 23 };
        Assert.Equal(23, (await Run(sdk)).Exit);
        Assert.DoesNotContain("deprovision", sdk.Live);
        Assert.Equal("Completed", JsonNode.Parse(File.ReadAllText(receiptPath))!["state"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("receiptless-run")]
    [InlineData("release")]
    public async Task ExplicitIdNeverAllocatesEvenWithoutReceipt(string operation)
    {
        var sdk = new FakeSdk();
        Assert.Equal(0, (await Run(sdk, operation == "release" ? "release" : "run", Id)).Exit);
        Assert.DoesNotContain("provision", sdk.Live);
    }

    [Fact]
    public async Task PreflightNeverAuthenticatesOrCreatesReceipt()
    {
        var auth = new FakeAuth { Failure = true };
        var sdk = new FakeSdk();
        Assert.Equal(0, (await Run(sdk, auth: auth, dry: true)).Exit);
        Assert.Empty(sdk.Live);
        Assert.Equal(0, auth.Calls);
        Assert.False(File.Exists(receiptPath));
    }

    [Theory]
    [InlineData("22222222-2222-2222-2222-222222222222")]
    [InlineData("w365:33333333-3333-3333-3333-333333333333:22222222-2222-2222-2222-222222222222")]
    public async Task InvalidIdentityFailsBeforeAuth(string id)
    {
        var auth = new FakeAuth();
        Assert.Equal(1, (await Run(new FakeSdk(), id: id, auth: auth)).Exit);
        Assert.Equal(0, auth.Calls);
    }

    [Fact]
    public async Task OwnerAndDeploymentMismatchCannotReuseReceipt()
    {
        Assert.Equal(0, (await Run(new FakeSdk())).Exit);
        var auth = new FakeAuth { OwnerId = Pool };
        Assert.Equal(1, (await Run(new FakeSdk(), id: Id, auth: auth)).Exit);
        config.ControlPlaneHost = "other.example.invalid";
        File.WriteAllText(configPath, JsonSerializer.Serialize(config, Configuration.JsonOptions));
        auth = new FakeAuth();
        Assert.Equal(1, (await Run(new FakeSdk(), id: Id, auth: auth)).Exit);
        Assert.Equal(0, auth.Calls);
    }

    [Fact]
    public async Task JournalLockFailurePreventsAuthentication()
    {
        using var locked = new FileStream(receiptPath + ".lock", FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        var auth = new FakeAuth();
        Assert.Equal(1, (await Run(new FakeSdk(), auth: auth)).Exit);
        Assert.Equal(0, auth.Calls);
    }

    [Fact]
    public async Task UncertainReleaseIsNeverReplayed()
    {
        var sdk = new FakeSdk { Failure = "deprovision" };
        Assert.Equal(1, (await Run(sdk, "release", Id)).Exit);
        sdk.Live.Clear();
        Assert.Equal(1, (await Run(sdk, "release", Id)).Exit);
        Assert.Empty(sdk.Live);
    }

    [Fact]
    public async Task ExpiringTokenRenewsSilentlyBeforeServiceSubmission()
    {
        var auth = new FakeAuth { ExpiredFirst = true };
        Assert.Equal(0, (await Run(new FakeSdk(), auth: auth)).Exit);
        Assert.Equal(new[] { false, true }, auth.Silent);
    }

    [Fact]
    public void AccountSelectionSupportsGuestsAndRefusesAmbiguity()
    {
        var one = new Account("fixture-one");
        var two = new Account("fixture-two");
        Assert.Same(one, Authentication.SelectAccount([one], null));
        Assert.Throws<ToolException>(() => Authentication.SelectAccount([one, two], null));
        Assert.Same(two, Authentication.SelectAccount([one, two], "FIXTURE-TWO"));
        Assert.Null(Authentication.SelectAccount([one], "no-match"));
    }

    [Fact]
    public void TokenChecksRequireExactIdentityAudienceScopesAndLifetime()
    {
        var claims = new JsonObject
        {
            ["tid"] = Pool, ["oid"] = Owner, ["azp"] = Pool, ["aud"] = Authentication.Resource,
            ["scp"] = "Computer.Get Computer.See Computer.Do Computer.Control",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
        };
        string Token() => "header." + Convert.ToBase64String(Encoding.UTF8.GetBytes(claims.ToJsonString()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".signature";
        Assert.Equal(Owner, Authentication.Verify(Token(), config, Owner).UserObjectId);
        foreach (var name in new[] { "tid", "oid", "azp", "aud", "scp", "exp" })
        {
            var saved = claims[name]!.DeepClone();
            claims[name] = name == "exp" ? JsonValue.Create(0) : JsonValue.Create("wrong");
            Assert.Throws<ToolException>(() => Authentication.Verify(Token(), config, Owner));
            claims[name] = saved;
        }
    }

    [Theory]
    [InlineData("Waiting")]
    [InlineData("Live")]
    [InlineData("Ready")]
    [InlineData(null)]
    public void ReadinessStateSurvivesSanitization(string? state)
    {
        var source = new JsonObject { ["lastState"] = state, ["accessToken"] = "SYNTHETIC_PRIVATE_TOKEN" };
        using var document = JsonDocument.Parse(source.ToJsonString());
        var safe = Application.SafeDetails(document.RootElement)!;
        Assert.True(safe.ContainsKey("lastState"));
        Assert.Equal(state, safe["lastState"]?.GetValue<string>());
        Assert.DoesNotContain("SYNTHETIC_PRIVATE_TOKEN", safe.ToJsonString());
    }

    [Theory]
    [InlineData("\"SYNTHETIC_PRIVATE_TOKEN\"")]
    [InlineData("\"Waiting\\r\\nprivate\"")]
    [InlineData("123")]
    [InlineData("{}")]
    public void InvalidReadinessStateIsNotLogged(string json)
    {
        using var document = JsonDocument.Parse("{\"lastState\":" + json + "}");
        Assert.False(Application.SafeDetails(document.RootElement)!.ContainsKey("lastState"));
    }

    [Fact]
    public async Task PublicSdkAppAgainstTrustedTlsFixture()
    {
        var mode = Environment.GetEnvironmentVariable("MXC_W365_TEST_APP_MODE");
        Assert.SkipUnless(mode is not null, "requires offline app trusted-TLS fixture selector");
        config.ControlPlaneHost = "localhost";
        config.DataPlaneSuffix = "localhost";
        File.WriteAllText(configPath, JsonSerializer.Serialize(config, Configuration.JsonOptions));
        var receipt = Environment.GetEnvironmentVariable("MXC_W365_TEST_APP_RECEIPT")!;
        var args = new List<string> { mode == "release" ? "release" : "run", "--config", configPath, "--receipt-path", receipt };
        if (mode != "release") args.AddRange(["--command", "cmd.exe /c echo fixture"]);
        if (mode is not ("new" or "checkout-error" or "readiness-timeout"))
        {
            var id = JsonNode.Parse(File.ReadAllText(receipt))!["sessionId"]!.GetValue<string>();
            args.AddRange(["--session-id", id]);
        }
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        var result = await Invoke(args.ToArray(), new FakeAuth(), new Sdk());
        Assert.Equal(mode is "checkout-error" or "readiness-timeout" ? 1 : 0, result.Exit);
        Assert.Equal(Id, result.Result["sessionId"]!.GetValue<string>());
        if (mode == "readiness-timeout")
        {
            Assert.True(elapsed.Elapsed >= TimeSpan.FromSeconds(120));
            Assert.Equal("attach_timeout", result.Result["error"]!["details"]!["code"]!.GetValue<string>());
            Assert.Equal("Waiting", result.Result["error"]!["details"]!["lastState"]!.GetValue<string>());
            var journal = JsonNode.Parse(File.ReadAllText(receipt))!;
            Assert.Equal("Waiting", journal["errorDetails"]!["lastState"]!.GetValue<string>());
            Assert.Equal(Id, journal["sessionId"]!.GetValue<string>());
            Assert.Equal("FailedOrUnknown", journal["state"]!.GetValue<string>());
            Assert.False(journal["releaseAccepted"]!.GetValue<bool>());
            Assert.Equal(new[] { "provision" }, journal["operations"]!.AsArray().Select(value => value!.GetValue<string>()));
            args.AddRange(["--session-id", Id]);
            var replay = await Invoke(args.ToArray(), new FakeAuth { Failure = true }, new Sdk());
            Assert.Equal(1, replay.Exit);
            Assert.Equal("reconciliation_required", replay.Result["error"]!["code"]!.GetValue<string>());
        }
        else if (mode == "checkout-error")
        {
            var journal = JsonNode.Parse(File.ReadAllText(receipt))!;
            Assert.Equal(Id, journal["sessionId"]!.GetValue<string>());
            Assert.Equal("fixture-request", journal["errorDetails"]!["requestId"]!.GetValue<string>());
            Assert.True(journal["errorDetails"]!["possiblySucceeded"]!.GetValue<bool>());
        }
        else if (mode != "release") Assert.Equal("fixture-out", result.Result["result"]!["stdout"]!.GetValue<string>());
        File.WriteAllText(Environment.GetEnvironmentVariable("MXC_W365_TEST_SDK_MARKER")!, mode!);
    }

    public void Dispose() => Directory.Delete(directory, recursive: true);

    private sealed class FakeAuth : IAuthentication
    {
        internal int Calls;
        internal bool Failure;
        internal bool ExpiredFirst;
        internal List<bool> Silent { get; } = [];
        internal string OwnerId = Owner;
        public Task<Credentials> AcquireAsync(Configuration config, Arguments args, string? expectedOwner, bool silentOnly)
        {
            Calls++;
            Silent.Add(silentOnly);
            if (Failure) throw new ToolException("fixture_auth_failure", "Controlled authentication failure.");
            return Task.FromResult(new Credentials("SYNTHETIC_PRIVATE_TOKEN", OwnerId,
                ExpiredFirst && Calls == 1 ? DateTimeOffset.UtcNow : DateTimeOffset.UtcNow.AddHours(1)));
        }
    }

    private sealed class Account(string username) : Microsoft.Identity.Client.IAccount
    {
        public string Username => username;
        public string Environment => "login.microsoftonline.com";
        public Microsoft.Identity.Client.AccountId HomeAccountId => null!;
    }

    private sealed class FakeSdk : ISdk
    {
        internal List<string> Live { get; } = [];
        internal string? Failure;
        internal int ExitCode;
        public JsonObject Call(string phase, JsonObject request, bool dryRun)
        {
            if (dryRun) return new JsonObject();
            Live.Add(phase);
            Assert.Equal("SYNTHETIC_PRIVATE_TOKEN", Environment.GetEnvironmentVariable("W365A_CP_TOKEN"));
            if (phase != "provision") Assert.Equal(Id, request["sandboxId"]!.GetValue<string>());
            if (phase == Failure) throw new ToolException("fixture_failure", "Controlled SDK failure.");
            return phase switch
            {
                "provision" => new JsonObject { ["sandboxId"] = Id, ["metadata"] = new JsonObject {
                    ["poolId"] = Pool, ["sessionId"] = Id.Split(':')[2], ["computerId"] = Id.Split(':')[2] } },
                "start" => new JsonObject { ["metadata"] = new JsonObject { ["status"] = "Ready" } },
                "exec" => new JsonObject { ["exitCode"] = ExitCode, ["stdout"] = "fixture-out", ["stderr"] = "" },
                "deprovision" => new JsonObject { ["metadata"] = new JsonObject { ["releaseRequested"] = true, ["restartable"] = false } },
                _ => throw new InvalidOperationException(),
            };
        }
    }
}
