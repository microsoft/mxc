// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcSandboxProcessTests
{
    // Real spawn requires a host able to launch a sandboxed process (an
    // elevated, host-prepped Windows host, or a capable Linux/macOS host). CI
    // lanes that provide one set MXC_E2E_HOST_PREPPED=1 to opt in; elsewhere the
    // streaming round-trip test returns early (skips), mirroring the Rust
    // `#[ignore]` gating.
    private static bool HostCanSpawn =>
        Environment.GetEnvironmentVariable("MXC_E2E_HOST_PREPPED") == "1";

    [Fact]
    public void Spawn_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Spawn(null!, "echo hi"));
    }

    [Fact]
    public void Spawn_NullCommand_Throws()
    {
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Spawn(policy, null!));
    }

    [Fact]
    public void Spawn_MalformedPolicy_ThrowsMalformedRequest()
    {
        // A version-less policy is rejected by the native parser before any
        // sandbox is spawned, so this runs on any host.
        var policy = new SandboxPolicy { Version = string.Empty };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Spawn(policy, "echo hi"));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.False(string.IsNullOrEmpty(ex.Message));
    }

    [Fact]
    public void StreamingEchoRoundTrip_ReadsStdout_AndExitsZero()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /c echo mxc_stream_ok"
            : "echo mxc_stream_ok";

        using var proc = MxcSandbox.Spawn(policy, command);

        var stdout = proc.StandardOutput;
        Assert.NotNull(stdout);
        using var reader = new StreamReader(stdout!, Encoding.UTF8);
        var text = reader.ReadToEnd();

        var result = proc.Wait();
        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mxc_stream_ok", text);
    }

    [Fact]
    public async Task StreamingEcho_WaitForExitWithOutputAsync_CapturesStdout()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /c echo mxc_async_ok"
            : "echo mxc_async_ok";

        using var proc = MxcSandbox.Spawn(policy, command);
        var (result, stdout, _) = await proc.WaitForExitWithOutputAsync();

        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mxc_async_ok", Encoding.UTF8.GetString(stdout));
    }

    [Fact]
    public async Task Streaming_WritesStdin_AndReadsEchoedStdout()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // A cmd builtin (set /p) reads one stdin line and echoes it with delayed
        // expansion — no external process spawn, so it is robust to the sandbox
        // cwd. Exercises the stdin write path with the stdout read path.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /v:on /c set /p L= & echo GOT:!L!"
            : "cat";

        using var proc = MxcSandbox.Spawn(policy, command);

        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var stdoutTask = Task.Run(() =>
        {
            using var reader = new StreamReader(proc.StandardOutput!);
            return reader.ReadToEnd();
        });

        var bytes = System.Text.Encoding.UTF8.GetBytes("mxc_stdin_echo\n");
        stdin!.Write(bytes, 0, bytes.Length);
        stdin.Flush();
        stdin.Dispose(); // close stdin -> EOF so the child produces output and exits

        var stdout = await stdoutTask;
        var result = proc.Wait();

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mxc_stdin_echo", stdout);
    }

    [Fact]
    public void Wait_IgnoringOutput_DoesNotDeadlock_AndExitsZero()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // The caller never touches StandardOutput/Error; Wait() must drain the
        // untaken streams so a chatty child cannot wedge on a full pipe.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /c echo a& echo b& echo c"
            : "printf 'a\\nb\\nc\\n'";

        using var proc = MxcSandbox.Spawn(policy, command);
        var result = proc.Wait();

        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void Dispose_AfterSpawn_IsIdempotent()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /c echo bye"
            : "echo bye";

        var proc = MxcSandbox.Spawn(policy, command);
        proc.Wait();
        proc.Dispose();
        proc.Dispose(); // second dispose must be a no-op, not a double-free
    }

    [Fact]
    public async Task Dispose_WhileReadingStdout_DoesNotCrash()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // Regression guard for the stream use-after-free: take stdout, start a
        // blocking read on a background thread, then dispose the process from
        // this thread. The SafeHandle refcount must keep the native stream alive
        // across the in-flight read; the read completes (EOF once the child is
        // killed) or throws ObjectDisposedException — never a crash / UAF.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = OperatingSystem.IsWindows()
            ? @"C:\Windows\System32\cmd.exe /c echo hi & ping -n 3 127.0.0.1 >nul"
            : "sh -c 'echo hi; sleep 2'";

        var proc = MxcSandbox.Spawn(policy, command);
        var stdout = proc.StandardOutput!;
        Exception? readError = null;
        var reader = Task.Run(() =>
        {
            try
            {
                var buf = new byte[64];
                // Loop until EOF (0) — Dispose kills the child, closing the pipe.
                while (stdout.Read(buf, 0, buf.Length) > 0) { }
            }
            catch (ObjectDisposedException)
            {
                // Acceptable: the handle was disposed while we read.
            }
            catch (Exception e)
            {
                readError = e;
            }
        });

        // Give the reader a moment to park inside the native read, then dispose.
        await Task.Delay(50);
        proc.Dispose();

        var finished = await Task.WhenAny(reader, Task.Delay(TimeSpan.FromSeconds(10))) == reader;
        Assert.True(finished, "reader should finish after dispose");
        Assert.Null(readError);
    }

    // A cmd builtin that blocks reading a line from stdin. Holding StandardInput
    // open (never writing/closing it) keeps the child parked here, so tests can
    // kill / cancel a genuinely-running process without depending on an external
    // sleep (unavailable under the sandbox's invalid cwd on an un-prepped host).
    private const string BlockerCommand =
        @"C:\Windows\System32\cmd.exe /v:on /c set /p x= & echo BLOCKER_DONE";

    [Fact]
    public void Kill_TerminatesRunningChild()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var proc = MxcSandbox.Spawn(policy, BlockerCommand);
        var stdin = proc.StandardInput; // hold stdin open so the child blocks
        Assert.NotNull(stdin);

        proc.Kill();
        var result = proc.Wait();
        // The child was killed while blocked, so it did not reach the clean exit.
        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public async Task Kill_DuringWaitAsync_Unblocks()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // The poll-based Wait design exists so Kill stays responsive during a
        // WaitAsync from another thread; prove the await completes after Kill.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var proc = MxcSandbox.Spawn(policy, BlockerCommand);
        var stdin = proc.StandardInput; // hold stdin open so the child blocks
        Assert.NotNull(stdin);

        var waitTask = proc.WaitAsync();
        await Task.Delay(100); // let the wait loop park
        Assert.False(waitTask.IsCompleted, "child should still be running");

        proc.Kill();

        var finished = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(waitTask, finished);
        var result = await waitTask;
        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public async Task WaitAsync_Cancellation_AbandonsWithoutKilling()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // Cancelling WaitAsync abandons the wait (throwing) without killing the
        // child — the exact path that previously triggered the stream UAF.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var proc = MxcSandbox.Spawn(policy, BlockerCommand);
        var stdin = proc.StandardInput; // hold stdin open so the child blocks
        Assert.NotNull(stdin);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => proc.WaitAsync(cts.Token));

        // The child is still alive (cancellation did not kill it); Kill cleans up.
        proc.Kill();
        Assert.NotEqual(0, proc.Wait().ExitCode);
    }

    [Fact]
    public async Task StandardError_IsReadable()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        // Write one line to stdout and one to stderr (both cmd builtins).
        var command = @"C:\Windows\System32\cmd.exe /c echo to-out& echo to-err 1>&2";
        using var proc = MxcSandbox.Spawn(policy, command);

        var (result, stdout, stderr) =
            await proc.WaitForExitWithOutputAsync();

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("to-out", Encoding.UTF8.GetString(stdout));
        Assert.Contains("to-err", Encoding.UTF8.GetString(stderr));
    }

    [Fact]
    public async Task OutputHeavyChild_DoesNotDeadlock()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // Emit well over a pipe buffer (~64KB) on BOTH stdout and stderr. If the
        // streams were not drained concurrently the child would wedge on a full
        // pipe; WaitForExitWithOutputAsync must return both in full.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command =
            @"C:\Windows\System32\cmd.exe /c for /L %i in (1,1,12000) do @(echo out-%i& echo err-%i 1>&2)";
        using var proc = MxcSandbox.Spawn(policy, command);

        var (result, stdout, stderr) = await proc.WaitForExitWithOutputAsync();

        Assert.Equal(0, result.ExitCode);
        Assert.True(stdout.Length > 64 * 1024, $"stdout was {stdout.Length} bytes");
        Assert.True(stderr.Length > 64 * 1024, $"stderr was {stderr.Length} bytes");
        Assert.Contains("out-12000", Encoding.UTF8.GetString(stdout));
        Assert.Contains("err-12000", Encoding.UTF8.GetString(stderr));
    }

    [Fact]
    public void Wait_EnforcesPolicyTimeout()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // A short policy timeout must be honoured by the polling Wait() path:
        // try_wait never kills and spawn starts no native watchdog, so without
        // managed enforcement the blocked child would hang Wait() indefinitely.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha", TimeoutMs = 1000 };
        using var proc = MxcSandbox.Spawn(policy, BlockerCommand);
        var stdin = proc.StandardInput; // hold stdin open so the child blocks
        Assert.NotNull(stdin);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = proc.Wait();
        sw.Stop();

        Assert.True(result.TimedOut, "Wait should report the policy timeout");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"Wait took {sw.Elapsed}");
    }

    [Fact]
    public void StandardOutput_AfterWaitDrains_Throws()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // Wait() drains any untaken standard stream on an internal task. Handing
        // that same stream back to the caller afterwards would race the drainer on
        // one native handle, so StandardOutput/Error must refuse it.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        var command = @"C:\Windows\System32\cmd.exe /c echo drained";
        using var proc = MxcSandbox.Spawn(policy, command);

        proc.Wait(); // drains stdout/stderr internally
        Assert.Throws<InvalidOperationException>(() => proc.StandardOutput);
        Assert.Throws<InvalidOperationException>(() => proc.StandardError);
    }

    [Fact]
    public async Task WaitForExitWithOutputAsync_Cancellation_DoesNotDeadlock()
    {
        if (!HostCanSpawn)
        {
            return; // skipped: no host backend available
        }

        // Cancelling while the child is blocked (its pipes never reach EOF) must
        // not deadlock: the cancellation path kills the child so the parked native
        // reads return, then surfaces the cancellation. Previously it awaited the
        // reads before killing and hung forever, leaking the native child.
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var proc = MxcSandbox.Spawn(policy, BlockerCommand);
        var stdin = proc.StandardInput; // hold stdin open so the child blocks
        Assert.NotNull(stdin);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var call = proc.WaitForExitWithOutputAsync(cts.Token);
        var finished = await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(call, finished);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
    }
}
