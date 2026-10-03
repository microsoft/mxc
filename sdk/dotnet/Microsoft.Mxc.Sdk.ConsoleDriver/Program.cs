// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Streams an IsolationSession workload through the public in-process SDK.
//
// Operator scenarios
//
// These have no automated oracle — an operator runs them and judges what they see.
//
//   mxc-isolation-session-console [streaming|<command line>]
//
//   streaming    Output arrives progressively through ordinary pipes.
//
// Running this alongside the Rust drivers isolates whether a failure is in the
// C# binding or beneath it.
//
// Must run at a real interactive console.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

namespace Microsoft.Mxc.Sdk.ConsoleDriver;

/// <summary>The scenarios exercise streamed output through ordinary pipes.</summary>
internal sealed record Scenario(string Name, string Command, string WhatToLookFor);

internal static class Program
{
    private static readonly Scenario[] Scenarios =
    [
        new("streaming",
            "cmd.exe /c echo line_1 & ping -n 3 127.0.0.1 >nul & echo line_2 "
            + "& ping -n 3 127.0.0.1 >nul & echo line_3",
            "The three lines must appear ~2s apart as they are produced, NOT all at once "
            + "when the process exits."),
    ];

    private static int Usage()
    {
        Console.Error.WriteLine(
            "usage: mxc-isolation-session-console [streaming|<command line>]");
        Console.Error.WriteLine();
        foreach (var s in Scenarios)
        {
            Console.Error.WriteLine($"  {s.Name,-12} {s.Command}");
        }
        Console.Error.WriteLine();
        Console.Error.WriteLine(
            "Anything else is treated as a literal command line to run in the session.");
        return 2;
    }

    private static async Task PumpAsync(Stream? stream, Stream destination)
    {
        if (stream is null)
        {
            return;
        }
        await stream.CopyToAsync(destination);
    }

    private static async Task<int> Main(string[] args)
    {
        var arg = args.Length > 0 ? string.Join(' ', args) : "streaming";
        if (arg is "--help" or "-h")
        {
            return Usage();
        }

        var scenario = Array.Find(Scenarios, s => s.Name == arg);
        var label = scenario?.Name ?? "custom";
        var command = scenario?.Command ?? arg;

        ContainerId id;
        try
        {
            var provisioned = MxcLifecycle.ProvisionSandbox(
                StateAwareContainment.IsolationSession,
                new IsolationSessionProvisionOptions(new StateAwareNetworkPolicy
                {
                    Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Allow,
                        HostLoopback = NetworkAction.Allow,
                    },
                }));
            id = provisioned.ContainerId;
        }
        catch (MxcException e)
        {
            Console.Error.WriteLine($"[driver] provision failed [{e.Code}]: {e.Message}");
            if (e.Remediation is { } remediation)
            {
                Console.Error.WriteLine($"[driver] {remediation}");
            }
            return 2;
        }

        // Provision mints a real OS account, so every path out of here tears the
        // sandbox down.
        try
        {
            Console.Error.WriteLine("[driver] provisioned.");
            MxcLifecycle.StartSandbox(id);
            Console.Error.WriteLine($"[driver] started. Scenario: {label}");
            if (scenario is { } s)
            {
                Console.Error.WriteLine($"[driver] WHAT TO LOOK FOR: {s.WhatToLookFor}");
            }
            Console.Error.WriteLine(
                "[driver] streaming workload output through ordinary pipes (no terminal).\n");

            using var proc = MxcLifecycle.SpawnInContainer(id, new ExecRequest(command));
            var stdoutTask = PumpAsync(proc.StandardOutput, Console.OpenStandardOutput());
            var stderrTask = PumpAsync(proc.StandardError, Console.OpenStandardError());
            var outcomeTask = proc.WaitAsync();
            await Task.WhenAll(stdoutTask, stderrTask, outcomeTask);
            var outcome = outcomeTask.Result;
            Console.WriteLine(
                $"\n[driver] timedOut: {outcome.TimedOut}, exitCode: {outcome.ExitCode}");
            return outcome.ExitCode;
        }
        catch (MxcException e)
        {
            Console.WriteLine($"\n[driver] failed [{e.Code}]: {e.Message}");
            return 1;
        }
        finally
        {
            Console.Error.WriteLine("\n[driver] tearing down…");
            try
            {
                MxcLifecycle.StopSandbox(id);
            }
            catch (MxcException)
            {
                // A failed stop must not prevent the deprovision that releases
                // the account.
            }
            try
            {
                MxcLifecycle.DeprovisionSandbox(id);
                Console.Error.WriteLine("[driver] deprovisioned.");
            }
            catch (MxcException e)
            {
                Console.Error.WriteLine(
                    $"[driver] WARNING: deprovision failed, account may leak: {e.Message}");
            }
        }
    }
}
