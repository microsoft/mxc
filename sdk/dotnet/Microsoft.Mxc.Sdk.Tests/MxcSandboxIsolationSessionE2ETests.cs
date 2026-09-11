// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Principal;
using System.Text;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// Runs one-shot isolation sessions against a live host through this binding.
/// </summary>
/// <remarks>
/// The engine's own suite covers the backend; these establish that the managed
/// type, the request envelope, the C ABI and the native library agree, which is
/// the part no Rust test can see.
/// </remarks>
[Collection("MxcLiveHost")]
public class MxcSandboxIsolationSessionE2ETests
{
    // The backend wraps the command in `cmd.exe /c` itself, so these are bare
    // shell commands. Adding another wrapper nests two shells and the outer one
    // consumes the `&`, which silently changes what runs.
    private static SandboxRequest Request(string command) =>
        new(
            new SandboxPolicy
            {
                // The backend cannot restrict the container's network, so it
                // accepts only an explicit acknowledgment of that and refuses an
                // absent policy, whose default is a deny it could not enforce.
                Version = "0.9.0-alpha",
                Network = new NetworkPolicy
                {
                    AllowOutbound = true,
                    AllowLocalNetwork = true,
                },
            },
            command)
        {
            Experimental = true,
            Containment = new IsolationSessionContainment(),
        };

    [Fact]
    public void Run_ReturnsTheWorkloadsOutputAndExitCode()
    {
        IsolationSessionHost.Require();

        var result = MxcSandbox.Run(Request("echo mxc_iso_run_ok & exit /b 3"));

        Assert.False(result.TimedOut);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("mxc_iso_run_ok", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_ExecutesUnderADifferentAccount()
    {
        IsolationSessionHost.Require();

        // `/fo csv /nh` prints `"machine\account","SID"`. The SID is compared
        // because it is canonical, and no account is named in a failure message.
        var result = MxcSandbox.Run(Request("whoami /user /fo csv /nh"));

        Assert.Equal(0, result.ExitCode);
        var sid = result.Stdout.Trim().Split(',').Last().Trim('"');

        Assert.False(
            string.IsNullOrWhiteSpace(sid),
            "the workload reported no account SID");

        if (OperatingSystem.IsWindows())
        {
            var caller = WindowsIdentity.GetCurrent().User?.Value;
            Assert.False(
                string.Equals(sid, caller, StringComparison.OrdinalIgnoreCase),
                "the workload ran as the caller's own account, so it was not isolated");
        }
    }

    [Fact]
    public void Spawn_StreamsStandardOutput()
    {
        IsolationSessionHost.Require();

        using var proc = MxcSandbox.Spawn(Request("echo mxc_iso_stream_ok"));

        var stdout = proc.StandardOutput;
        Assert.NotNull(stdout);
        using var reader = new StreamReader(stdout!, Encoding.UTF8);
        var text = reader.ReadToEnd();

        var result = proc.Wait();
        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("mxc_iso_stream_ok", text, StringComparison.Ordinal);
    }
}
