// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Principal;
using System.Text;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Tests;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Runs one-shot isolation sessions against a live host through this binding.
/// </summary>
/// <remarks>
/// The engine's own suite covers the backend; these establish that the managed
/// type, the request envelope, the C ABI and the native library agree, which is
/// the part no Rust test can see.
/// </remarks>
[Collection("MxcLiveHost")]
public class MxcContainerIsolationSessionE2ETests
{
    // The backend wraps the command in `cmd.exe /c` itself, so these are bare
    // shell commands. Adding another wrapper nests two shells and the outer one
    // consumes the `&`, which silently changes what runs.
    private static ContainerRequest Request(string command) =>
        new(command)
        {
            // The backend cannot restrict the container's network, so it
            // requires the explicit directional all-allow posture and refuses
            // an absent policy, whose default is a deny it could not enforce.
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Allow,
                    HostLoopback = NetworkAction.Allow,
                },
            },
            Containment = new Containment.IsolationSession(),
        };

    [Fact]
    public void Run_ReturnsTheWorkloadsOutputAndExitCode()
    {
        IsolationSessionHost.Require();

        var result = MxcContainer.Run(Request("echo mxc_iso_run_ok & exit /b 3"));

        Assert.False(result.TimedOut);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("mxc_iso_run_ok", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BufferedExecution_BoundsNativeAndManagedCapture()
    {
        IsolationSessionHost.Require();
        var request = Request(
            "powershell.exe -NoProfile -NonInteractive -Command \"$chunk = 'x' * 8192; " +
            "for ($i = 0; $i -lt 256; $i++) { [Console]::Out.Write($chunk); " +
            "[Console]::Error.Write($chunk) }; exit 7\"");
        request.TimeoutMs = 30000;

        using var proc = MxcContainer.Spawn(request);
        var (result, stdout, stderr) = await proc.WaitForExitWithOutputAsync(
            TestContext.Current.CancellationToken);
        Assert.False(result.TimedOut);
        Assert.Equal(7, result.ExitCode);
        Assert.Equal(new string('x', 1048576), Encoding.UTF8.GetString(stdout));
        Assert.Equal(new string('x', 1048576), Encoding.UTF8.GetString(stderr));
        foreach (var stream in new[] { "stdout", "stderr" })
        {
            Assert.Contains(
                $"{stream} capture truncated at 1048576 bytes; use streaming APIs for complete output",
                proc.Warnings);
        }

        var captured = await MxcContainer.RunAsync(request,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(captured.TimedOut);
        Assert.Equal(7, captured.ExitCode);
        Assert.Equal(new string('x', 1048576), captured.Stdout);
        Assert.Equal(new string('x', 1048576), captured.Stderr);
        foreach (var stream in new[] { "stdout", "stderr" })
        {
            Assert.Contains(
                $"{stream} capture truncated at 1048576 bytes; use streaming APIs for complete output",
                captured.Warnings);
        }
    }

    [Fact]
    public void Run_ExecutesUnderADifferentAccount()
    {
        IsolationSessionHost.Require();

        // `/fo csv /nh` prints `"machine\account","SID"`. The SID is compared
        // because it is canonical, and no account is named in a failure message.
        var result = MxcContainer.Run(Request("whoami /user /fo csv /nh"));

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

        using var proc = MxcContainer.Spawn(Request("echo mxc_iso_stream_ok"));

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
