// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Drives live WSLC create-and-run containers, which needs WSL2 with the WSLC
/// runtime, a build with MxcWithWslc, alpine:latest in the create-and-run image
/// store, outbound HTTPS for the built-in proxy tests, and MXC_ENABLE_WSLC_TESTS=1.
/// </summary>
[Collection("MxcLiveHost")]
public class MxcContainerWslcE2ETests
{
    private static void RequireWslc()
    {
#if MXC_WITH_WSLC
        Assert.SkipUnless(
            Environment.GetEnvironmentVariable("MXC_ENABLE_WSLC_TESTS") == "1",
            "WSLC tests require MXC_ENABLE_WSLC_TESTS=1 on Windows with WSL2 and the WSLC runtime");
#else
        Assert.Skip("built without MxcWithWslc");
#endif
    }

    private static ContainerRequest Request(string command) => new(command)
    {
        TimeoutMs = 60_000,
        Containment = new Containment.Wslc(),
    };

    [Fact]
    public async Task SpawnWithStdin_ForwardsEveryByteAndClosingStdinEndsInput()
    {
        RequireWslc();
        var payload = new byte[64 * 1024];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i % 256);
        }

        using var proc = MxcContainer.SpawnWithStdin(Request("cat"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var output = proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);
        await stdin.WriteAsync(payload, TestContext.Current.CancellationToken);
        stdin.Dispose();
        var (result, stdout, _) = await output;

        Assert.False(result.TimedOut, "cat must end once stdin is closed");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(payload, stdout);
    }

    [Fact]
    public async Task SpawnWithStdin_WaitClosesAnUntakenStdin()
    {
        RequireWslc();

        using var proc = MxcContainer.SpawnWithStdin(Request("sh -c 'cat; echo WAIT-SAW-EOF'"));
        var (result, stdout, _) =
            await proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);

        Assert.False(result.TimedOut, "waiting must close a stdin the caller never took");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("WAIT-SAW-EOF", Encoding.UTF8.GetString(stdout).Trim());
    }

    [Fact]
    public async Task SpawnWithStdin_ACommandThatLeavesStdinUnreadFinishesWithoutTimingOut()
    {
        RequireWslc();

        // The WSLc SDK reports this exit about 50 seconds late, so a timeout
        // shorter than that only passes if the exit is seen when it happens.
        var request = new ContainerRequest("sh -c 'head -c 1 >/dev/null; echo LATE-DONE'")
        {
            TimeoutMs = 40_000,
            Containment = new Containment.Wslc(),
        };
        using var proc = MxcContainer.SpawnWithStdin(request);
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var flood = stdin.WriteAsync(new byte[4 * 1024 * 1024], TestContext.Current.CancellationToken).AsTask();
        var (result, stdout, _) =
            await proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);

        Assert.False(result.TimedOut, "the command exited long before its timeout");
        Assert.Equal(0, result.ExitCode);
        var lateWarning = proc.Warnings.Any(w => w.Contains("reported the command's exit late"));
        Assert.True(
            Encoding.UTF8.GetString(stdout).Contains("LATE-DONE") || lateWarning,
            "missing output must come with the late-exit warning");
        var finished = await Task.WhenAny(flood, Task.Delay(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        Assert.Same(flood, finished);
        Assert.True(flood.IsFaulted, "input the command never read must not be reported as delivered");
        stdin.Dispose();
    }

    // Starts a write too large for the WSLc SDK to buffer to a command that
    // never reads stdin, and checks that it stays blocked.
    private static async Task<Task> StartBlockedWriteAsync(Stream stdin)
    {
        var write = Task.Run(() => stdin.Write(new byte[16 * 1024 * 1024]), TestContext.Current.CancellationToken);
        var finished = await Task.WhenAny(
            write,
            Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken));
        Assert.NotSame(write, finished);
        return write;
    }

    private static async Task AssertFinishesWithinAsync(Task task, TimeSpan limit, string message)
    {
        var finished = await Task.WhenAny(
            task,
            Task.Delay(limit, TestContext.Current.CancellationToken));
        Assert.True(finished == task, message);
    }

    [Fact]
    public async Task SpawnWithStdin_ACommandExitingReleasesAWriteStartedBeforeAnyWait()
    {
        RequireWslc();

        using var proc = MxcContainer.SpawnWithStdin(Request("sh -c 'sleep 5'"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var write = await StartBlockedWriteAsync(stdin);

        await AssertFinishesWithinAsync(write, TimeSpan.FromSeconds(60), "the command's exit did not release the write");
        Assert.True(write.IsFaulted, "input the command never read must not be reported as delivered");
        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the command never finished");
        stdin.Dispose();
    }

    [Fact]
    public async Task SpawnWithStdin_KillDoesNotWaitForTheCleanupOfAnExitedCommand()
    {
        RequireWslc();

        // Unread stdin makes the WSLc SDK report the exit about 50 seconds
        // late, and the wait spends that time inside its native cleanup.
        using var proc = MxcContainer.SpawnWithStdin(Request("sh -c 'head -c 1 >/dev/null'"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var flood = stdin.WriteAsync(new byte[4 * 1024 * 1024], TestContext.Current.CancellationToken).AsTask();
        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(flood, TimeSpan.FromSeconds(30), "the command's exit did not release the write");
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        await AssertFinishesWithinAsync(Task.Run(proc.Kill, TestContext.Current.CancellationToken), TimeSpan.FromSeconds(5), "Kill waited for the cleanup");
        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the command never finished");
        Assert.False((await wait).TimedOut);
        stdin.Dispose();
    }

    // Unread stdin makes the WSLc SDK report this command's exit about 50 seconds late.
    private static async Task<(MxcProcess Process, Stream Stdin)> SpawnCommandWithLateExitAsync()
    {
        var proc = MxcContainer.SpawnWithStdin(Request("sh -c 'sleep 2; head -c 1 >/dev/null'"));
        try
        {
            var stdin = proc.StandardInput;
            Assert.NotNull(stdin);
            var flood = stdin.WriteAsync(new byte[4 * 1024 * 1024], TestContext.Current.CancellationToken).AsTask();
            await AssertFinishesWithinAsync(flood, TimeSpan.FromSeconds(30), "the command's exit did not release the write");
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
            while (!proc.TryGetExitCode(out _))
            {
                Assert.True(DateTime.UtcNow < deadline, "the command's exit was never reported");
                await Task.Delay(TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken);
            }
            return (proc, stdin);
        }
        catch
        {
            proc.Dispose();
            throw;
        }
    }

    [Fact]
    public async Task SpawnWithStdin_CancellingAWaitDoesNotWaitForTheCleanupOfAnExitedCommand()
    {
        RequireWslc();

        var late = await SpawnCommandWithLateExitAsync();
        using var proc = late.Process;
        var stdin = late.Stdin;
        using var cancel = new CancellationTokenSource();
        var cancelled = proc.WaitAsync(cancel.Token);
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        cancel.Cancel();

        await AssertFinishesWithinAsync(cancelled, TimeSpan.FromSeconds(5), "the cancelled wait waited for the cleanup");
        if (!cancelled.IsCompletedSuccessfully)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        }
        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the command never finished");
        Assert.False((await wait).TimedOut);
        stdin.Dispose();
    }

    [Fact]
    public async Task SpawnWithStdin_WarningsAndDisposeDoNotWaitForTheCleanupOfAnExitedCommand()
    {
        RequireWslc();

        var (proc, stdin) = await SpawnCommandWithLateExitAsync();
        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        var warnings = Task.Run(() => proc.Warnings, TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(warnings, TimeSpan.FromSeconds(5), "Warnings waited for the cleanup");
        await warnings;
        var dispose = Task.Run(proc.Dispose, TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(dispose, TimeSpan.FromSeconds(5), "Dispose waited for the cleanup");
        await dispose;
        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the command never finished");
        Assert.False((await wait).TimedOut);
        Assert.Throws<ObjectDisposedException>(() => proc.Warnings);
        stdin.Dispose();
        var next = await MxcContainer.RunAsync(
            Request("true"),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(next.ExitCode == 0, "the disposed process did not release its session before its wait returned");
    }

    [Fact]
    public async Task SpawnWithStdin_ATimeoutEndsACommandThatIgnoresSigtermAndReleasesItsBlockedWrite()
    {
        RequireWslc();

        var request = new ContainerRequest("sh -c 'trap \"\" TERM; sleep 300'")
        {
            TimeoutMs = 5_000,
            Containment = new Containment.Wslc(),
        };
        using var proc = MxcContainer.SpawnWithStdin(request);
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var write = await StartBlockedWriteAsync(stdin);

        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);

        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the timed-out command never finished");
        Assert.True((await wait).TimedOut);
        await AssertFinishesWithinAsync(write, TimeSpan.FromSeconds(10), "the timeout did not release the write");
        Assert.True(write.IsFaulted, "input the command never read must not be reported as delivered");
        stdin.Dispose();
    }

    [Fact]
    public async Task SpawnWithStdin_KillReleasesAWriteBlockedOnStdin()
    {
        RequireWslc();

        using var proc = MxcContainer.SpawnWithStdin(Request("sleep 300"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var write = await StartBlockedWriteAsync(stdin);

        proc.Kill();

        await AssertFinishesWithinAsync(write, TimeSpan.FromSeconds(10), "the kill did not release the write");
        Assert.True(write.IsFaulted, "input the command never read must not be reported as delivered");
        var wait = proc.WaitAsync(TestContext.Current.CancellationToken);
        await AssertFinishesWithinAsync(wait, TimeSpan.FromSeconds(150), "the killed command never finished");
        stdin.Dispose();
    }

    [Fact]
    public async Task SpawnWithStdin_DisposeReleasesAWriteBlockedOnStdin()
    {
        RequireWslc();

        var proc = MxcContainer.SpawnWithStdin(Request("sleep 300"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var write = await StartBlockedWriteAsync(stdin);

        var dispose = Task.Run(proc.Dispose, TestContext.Current.CancellationToken);

        await AssertFinishesWithinAsync(write, TimeSpan.FromSeconds(10), "disposing did not release the write");
        Assert.True(write.IsFaulted, "input the command never read must not be reported as delivered");
        await AssertFinishesWithinAsync(dispose, TimeSpan.FromSeconds(150), "disposing never finished");
    }

    [Fact]
    public async Task Spawn_GivesACommandEndOfFileSoReadingOutputBeforeWaitingFinishes()
    {
        RequireWslc();

        using var proc = MxcContainer.Spawn(Request("sh -c 'cat; echo SPAWN-SAW-EOF'"));
        Assert.Null(proc.StandardInput);
        using var reader = new StreamReader(proc.StandardOutput!, Encoding.UTF8);
        var reading = reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        var finished = await Task.WhenAny(
            reading,
            Task.Delay(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken));
        if (finished != reading)
        {
            proc.Kill();
        }
        var result = await proc.WaitAsync(TestContext.Current.CancellationToken);

        Assert.Same(reading, finished);
        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("SPAWN-SAW-EOF", (await reading).Trim());
    }

    [Fact]
    public async Task Run_GivesACommandThatReadsStdinEndOfFile()
    {
        RequireWslc();

        var run = await MxcContainer.RunAsync(
            Request("sh -c 'cat; echo RUN-SAW-EOF'"),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(run.TimedOut, "a captured run has no input to wait for");
        Assert.Equal(0, run.ExitCode);
        Assert.Equal("RUN-SAW-EOF", run.Stdout.Trim());
    }

    [Fact]
    public async Task Run_ReportsATimedOutRunAsTimedOut()
    {
        RequireWslc();

        var request = Request("sh -c 'echo STARTED; sleep 300'");
        request.TimeoutMs = 10_000;
        var run = await MxcContainer.RunAsync(
            request,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(run.TimedOut);
        Assert.Equal("STARTED", run.Stdout.Trim());
    }

    // Egress rules run through the built-in proxy. `p` sends a raw CONNECT to
    // the injected proxy and prints its status code: 200 allowed, 403 denied.
    private const string ProxyProbe =
        "hp=${HTTPS_PROXY#http://}\n" +
        "p() { printf 'CONNECT %s HTTP/1.1\\r\\n\\r\\n' \"$1\" | nc -w 3 \"${hp%:*}\" \"${hp##*:}\" | head -n1 | cut -d' ' -f2; }";

    private static string DirectProbe(string target) =>
        $"nc -z -w 3 {target} && echo DIRECT=REACHED || echo DIRECT=BLOCKED";

    private static NetworkIngressPolicy DenyIngress() =>
        new() { Default = NetworkAction.Deny, HostLoopback = NetworkAction.Deny };

    private static NetworkRulePolicy Rule(string cidr, NetworkProtocol? protocol = null, ushort? port = null) => new()
    {
        To = [new NetworkPeerPolicy(cidr)],
        Ports = protocol is null && port is null ? null : [new NetworkPortPolicy { Protocol = protocol, Port = port }],
    };

    private static NetworkPolicy AllowCloudflare443() => new()
    {
        Egress = new NetworkEgressPolicy
        {
            Default = NetworkAction.Deny,
            Allow = [Rule("1.1.1.1/32", NetworkProtocol.Tcp, 443)],
        },
        Ingress = DenyIngress(),
    };

    private static ContainerRequest ProxyRequest(NetworkPolicy network, uint timeoutMs, params string[] commands) =>
        new(string.Join('\n', [ProxyProbe, .. commands]))
        {
            TimeoutMs = timeoutMs,
            Network = network,
            Containment = new Containment.Wslc(),
        };

    private static void AssertProbes(string stdout, IReadOnlyDictionary<string, string> expected)
    {
        var actual = new Dictionary<string, string>();
        foreach (var line in stdout.Split('\n'))
        {
            var eq = line.IndexOf('=');
            if (eq > 0)
            {
                actual[line[..eq].Trim()] = line[(eq + 1)..].Trim();
            }
        }
        foreach (var (name, value) in expected)
        {
            Assert.True(
                actual.TryGetValue(name, out var got) && got == value,
                $"{name} expected '{value}', got '{got}'\nstdout={stdout}");
        }
    }

    // Only succeeds if the previous run released the store and removed its proxy.
    private static async Task AssertProxyStillWorksAsync()
    {
        var run = await MxcContainer.RunAsync(
            ProxyRequest(AllowCloudflare443(), 120_000, "echo ALLOWED=$(p 1.1.1.1:443)"),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(0, run.ExitCode);
        AssertProbes(run.Stdout, new Dictionary<string, string> { ["ALLOWED"] = "200" });
    }

    [Fact]
    public async Task Run_BuiltInProxyFiltersEgressByCidrPortAndException()
    {
        RequireWslc();
        var network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy
            {
                Default = NetworkAction.Deny,
                Allow =
                [
                    new NetworkRulePolicy
                    {
                        To =
                        [
                            new NetworkPeerPolicy("1.1.1.0/24") { Except = ["1.1.1.2/32"] },
                            new NetworkPeerPolicy("1.0.0.0/24"),
                        ],
                        Ports = [new NetworkPortPolicy { Protocol = NetworkProtocol.Tcp, Port = 443 }],
                    },
                ],
                Deny = [Rule("1.1.1.3/32")],
            },
            Ingress = DenyIngress(),
        };

        var run = await MxcContainer.RunAsync(
            ProxyRequest(
                network,
                120_000,
                "[ \"$HTTPS_PROXY\" = http://10.231.1.254:3128 ] && echo PROXY_ENV=OK || echo PROXY_ENV=MISSING",
                "grep -qx 'nameserver 10.231.1.254' /etc/resolv.conf && echo RESOLV=GATEWAY || echo RESOLV=OTHER",
                "echo IN_RANGE=$(p 1.1.1.1:443)",
                "echo SECOND_TARGET=$(p 1.0.0.1:443)",
                "echo EXCEPT=$(p 1.1.1.2:443)",
                "echo DENY_WINS=$(p 1.1.1.3:443)",
                "echo WRONG_PORT=$(p 1.1.1.1:80)",
                "echo OUTSIDE=$(p 8.8.8.8:443)",
                "echo NAME_ALLOWED=$(p one.one.one.one:443)",
                "echo NAME_DENIED=$(p dns.google:443)",
                "nslookup one.one.one.one 2>&1 | grep -q '1\\.[01]\\.[01]\\.1' && echo DNS=RESOLVED || echo DNS=FAILED",
                DirectProbe("1.1.1.1 443")),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(0, run.ExitCode);
        AssertProbes(run.Stdout, new Dictionary<string, string>
        {
            ["PROXY_ENV"] = "OK", ["RESOLV"] = "GATEWAY", ["IN_RANGE"] = "200", ["SECOND_TARGET"] = "200",
            ["EXCEPT"] = "403", ["DENY_WINS"] = "403", ["WRONG_PORT"] = "403", ["OUTSIDE"] = "403",
            ["NAME_ALLOWED"] = "200", ["NAME_DENIED"] = "403", ["DNS"] = "RESOLVED", ["DIRECT"] = "BLOCKED",
        });
        Assert.DoesNotContain(run.Warnings, w => w.Contains("WSLc"));
    }

    [Fact]
    public async Task Run_BuiltInProxyAppliesDenyRulesAndWarnsAboutRulesItCannotEnforce()
    {
        RequireWslc();
        var network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy
            {
                Default = NetworkAction.Allow,
                Deny =
                [
                    Rule("1.1.1.0/24"),
                    Rule("9.9.9.9/32", NetworkProtocol.Tcp, 443),
                    new NetworkRulePolicy { Ports = [new NetworkPortPolicy { Protocol = NetworkProtocol.Udp, Port = 53 }] },
                ],
            },
            Ingress = DenyIngress(),
        };

        var run = await MxcContainer.RunAsync(
            ProxyRequest(
                network,
                120_000,
                "echo DENIED=$(p 1.1.1.1:443)",
                "echo PORT_DENIED=$(p 9.9.9.9:443)",
                "echo PORT_OTHER=$(p 9.9.9.9:853)",
                "echo ALLOWED=$(p 8.8.8.8:443)",
                "echo LOOPBACK=$(p 127.0.0.1:443)",
                "nslookup dns.google 2>&1 | grep -q '8\\.8\\.[48]\\.[48]' && echo DNS=RESOLVED || echo DNS=FAILED",
                DirectProbe("8.8.8.8 443")),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(0, run.ExitCode);
        AssertProbes(run.Stdout, new Dictionary<string, string>
        {
            ["DENIED"] = "403", ["PORT_DENIED"] = "403", ["PORT_OTHER"] = "200", ["ALLOWED"] = "200",
            ["LOOPBACK"] = "403", ["DNS"] = "RESOLVED", ["DIRECT"] = "BLOCKED",
        });
        Assert.Contains(run.Warnings, w => w.Contains("network.egress.deny entry for 'udp' has no effect"));
    }

    [Fact]
    public async Task Spawn_BuiltInProxyStreamsOutputAndPassesTheExitCodeThrough()
    {
        RequireWslc();

        using var proc = MxcContainer.Spawn(ProxyRequest(
            AllowCloudflare443(),
            120_000,
            "echo ALLOWED=$(p 1.1.1.1:443)",
            "echo OTHER=$(p 8.8.8.8:443)",
            "exit 7"));
        var (result, stdout, _) =
            await proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);

        Assert.False(result.TimedOut);
        Assert.Equal(7, result.ExitCode);
        AssertProbes(Encoding.UTF8.GetString(stdout), new Dictionary<string, string>
        {
            ["ALLOWED"] = "200", ["OTHER"] = "403",
        });
    }

    [Fact]
    public async Task SpawnWithStdin_BuiltInProxyProbesTargetsReadFromStdin()
    {
        RequireWslc();

        using var proc = MxcContainer.SpawnWithStdin(ProxyRequest(
            AllowCloudflare443(),
            120_000,
            "while read -r t; do echo \"$t=$(p \"$t\")\"; done"));
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var output = proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);
        await stdin.WriteAsync(Encoding.UTF8.GetBytes("1.1.1.1:443\n8.8.8.8:443\n1.1.1.1:80\n"), TestContext.Current.CancellationToken);
        stdin.Dispose();
        var (result, stdout, _) = await output;

        Assert.Equal(0, result.ExitCode);
        AssertProbes(Encoding.UTF8.GetString(stdout), new Dictionary<string, string>
        {
            ["1.1.1.1:443"] = "200", ["8.8.8.8:443"] = "403", ["1.1.1.1:80"] = "403",
        });
    }

    [Fact]
    public async Task Run_BuiltInProxyIsRemovedAfterATimeout()
    {
        RequireWslc();

        var run = await MxcContainer.RunAsync(
            ProxyRequest(AllowCloudflare443(), 20_000, "echo STARTED", "sleep 300"),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(run.TimedOut);
        await AssertProxyStillWorksAsync();
    }

    [Fact]
    public async Task Spawn_BuiltInProxyIsRemovedAfterKill()
    {
        RequireWslc();

        using (var proc = MxcContainer.Spawn(ProxyRequest(AllowCloudflare443(), 180_000, "echo STARTED", "sleep 300")))
        {
            using var reader = new StreamReader(proc.StandardOutput!, Encoding.UTF8);
            var line = await reader.ReadLineAsync(TestContext.Current.CancellationToken);
            Assert.Equal("STARTED", line);

            proc.Kill();
            var result = await proc.WaitAsync(TestContext.Current.CancellationToken);

            Assert.NotEqual(0, result.ExitCode);
            Assert.DoesNotContain(proc.Warnings, w => w.Contains("built-in proxy"));
        }
        await AssertProxyStillWorksAsync();
    }

    public static TheoryData<string, string> UnenforceableEgressCases() => new()
    {
        { "port mappings", "wslc.portMappings cannot be combined with egress filtering" },
        { "external proxy", "runtimeConfig.networkProxy cannot be combined with egress filtering" },
        { "host loopback", "hostLoopback 'allow' cannot be combined with egress filtering" },
        { "UDP allow", "network.egress.allow supports only protocol 'tcp' (got 'udp')" },
        { "IPv6", "network.egress CIDR 2606:4700::/32 is IPv6" },
        { "reserved subnet", "which the built-in proxy reserves for its own networks" },
    };

    [Theory]
    [MemberData(nameof(UnenforceableEgressCases))]
    public async Task BuiltInProxyRejectsEgressItCannotEnforceBeforeStartingAContainer(string name, string message)
    {
        RequireWslc();
        var network = AllowCloudflare443();
        var containment = new Containment.Wslc();
        switch (name)
        {
            case "port mappings":
                containment.PortMappings.Add(new WslcPortMapping(39001, 80));
                break;
            case "external proxy":
                network.RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = "http://127.0.0.1:8888" };
                break;
            case "host loopback":
                network.Ingress!.HostLoopback = NetworkAction.Allow;
                break;
            case "UDP allow":
                network.Egress!.Allow = [Rule("1.1.1.1/32", NetworkProtocol.Udp, 53)];
                break;
            case "IPv6":
                network.Egress!.Allow = [Rule("2606:4700::/32", NetworkProtocol.Tcp, 443)];
                break;
            case "reserved subnet":
                network.Egress!.Allow = [Rule("10.231.0.0/16", NetworkProtocol.Tcp, 443)];
                break;
        }
        var request = new ContainerRequest("echo WSLC_EGRESS_RULES_SHOULD_NOT_RUN")
        {
            Network = network,
            Containment = containment,
        };

        var run = await Assert.ThrowsAsync<MxcException>(
            () => MxcContainer.RunAsync(request, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.PolicyValidation, run.Code);
        Assert.Contains(message, run.Message);
        var spawn = Assert.Throws<MxcException>(() => MxcContainer.Spawn(request));
        Assert.Equal(ErrorCode.PolicyValidation, spawn.Code);
        Assert.Contains(message, spawn.Message);
    }
}
