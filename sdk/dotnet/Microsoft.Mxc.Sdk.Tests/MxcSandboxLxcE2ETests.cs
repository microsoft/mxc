// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// Runs LXC sandboxes against a live host through this binding.
/// </summary>
/// <remarks>
/// The engine's own suite covers the backend; these establish that the managed
/// type, the request envelope, the C ABI and the native library agree, which is
/// the part no Rust test can see.
/// </remarks>
[Collection("MxcLiveHost")]
public class MxcSandboxLxcE2ETests
{
    // A healthy run finishes in under a second, so this only trips on a wedged attach.
    private const int WaitBoundMs = 180_000;

    private static SandboxRequest Request(string command, string containerName) =>
        new(
            new SandboxPolicy
            {
                Version = "0.9.0-alpha",
                TimeoutMs = WaitBoundMs,

                // A policy naming no network defaults to `enforcementMode:
                // 'capabilities'`, which LXC refuses outright.
                Network = new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Deny,
                        HostLoopback = NetworkAction.Deny,
                    },
                },
            },
            command)
        {
            ContainerName = containerName,
            Containment = new LxcContainment(),
        };

    [Fact]
    public void Run_ReturnsTheWorkloadsOutputAndExitCode()
    {
        LxcHost.Require();

        var result = MxcSandbox.Run(
            Request("printf 'mxc_lxc_run_ok\\n'; exit 3", "mxc-dotnet-run"));

        Assert.False(result.TimedOut);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("mxc_lxc_run_ok", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public void Spawn_StreamsStandardOutputBeforeTheWorkloadExits()
    {
        LxcHost.Require();

        // Blocking on stdin: the workload cannot reach its exit until this test
        // lets it.
        using var proc = MxcSandbox.Spawn(
            Request(
                "printf 'mxc_lxc_stream_ok\\n'; IFS= read -r _; printf 'mxc_lxc_done\\n'",
                "mxc-dotnet-spawn"));

        var stdin = proc.StandardInput;
        var stdout = proc.StandardOutput;
        Assert.NotNull(stdin);
        Assert.NotNull(stdout);

        using var reader = new StreamReader(stdout!, Encoding.UTF8);
        var first = ReadLineWithin(reader, TimeSpan.FromMinutes(3));
        Assert.Contains("mxc_lxc_stream_ok", first, StringComparison.Ordinal);
        Assert.False(
            proc.TryGetExitCode(out _),
            "the first line arrived only after the workload exited, so it was not streamed");

        using (var writer = new StreamWriter(stdin!, Encoding.UTF8))
        {
            writer.Write("continue\n");
        }

        var result = proc.Wait();
        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
    }

    /// <summary>
    /// Reads one line on a worker thread, so a stream that never delivers fails
    /// here rather than hanging the job.
    /// </summary>
    private static string ReadLineWithin(StreamReader reader, TimeSpan deadline)
    {
        var read = Task.Run(reader.ReadLine);
        Assert.True(read.Wait(deadline), $"no output within {deadline}");
        return read.Result ?? string.Empty;
    }
}
