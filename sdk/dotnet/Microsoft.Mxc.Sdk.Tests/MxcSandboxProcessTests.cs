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
}
