// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Drives stdin through a live WSLC create-and-run container, which needs WSL2
/// with the WSLC runtime, a build with MxcWithWslc, alpine:latest in the
/// create-and-run image store, and MXC_ENABLE_WSLC_TESTS=1.
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
}
