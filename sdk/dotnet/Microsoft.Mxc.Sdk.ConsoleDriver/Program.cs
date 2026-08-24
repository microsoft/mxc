// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Hosts an interactive terminal inside an isolation session, in-process, from a
// console application — the C# counterpart of the Rust `isolation_session_console`
// and `attached_console_ffi` drivers.
//
// Operator scenarios
//
// These have no automated oracle — an operator runs them and judges what they see.
//
//   mxc-isolation-session-console [interactive|streaming|resize|<command line>]
//
//   interactive  ConPTY rendering, input, and exit-code propagation (`exit 7` → 7)
//   streaming    Output arrives progressively, not as a burst at exit
//   resize       The sandboxed process sees window-size changes live
//
// Running this alongside the Rust drivers isolates whether a failure is in the
// C# binding or beneath it.
//
// Must run at a real interactive console. A single-threaded apartment is refused,
// so this is deliberately a plain console app with no [STAThread].

using Microsoft.Mxc.Sdk;

namespace Microsoft.Mxc.Sdk.ConsoleDriver;

/// <summary>The scenarios differ only in command line; what they check is
/// console behaviour, not the SDK surface.</summary>
internal sealed record Scenario(string Name, string Command, string WhatToLookFor);

internal static class Program
{
    private static readonly Scenario[] Scenarios =
    [
        new("interactive",
            "powershell.exe -NoLogo",
            "The prompt draws and redraws. Colours, cursor movement and tab-completion "
            + "behave. Type commands, then `exit 7` — the outcome printed at the end must "
            + "be exitCode 7."),
        new("streaming",
            "cmd.exe /c echo line_1 & ping -n 3 127.0.0.1 >nul & echo line_2 "
            + "& ping -n 3 127.0.0.1 >nul & echo line_3",
            "The three lines must appear ~2s apart as they are produced, NOT all at once "
            + "when the process exits."),
        new("resize",
            """
            powershell.exe -NoLogo -NoProfile -Command "while ($true) { $w = $Host.UI.RawUI.WindowSize.Width; Write-Host ('{0,-4}' -f $w) -NoNewline; Write-Host ('.' * [Math]::Max(0, $w - 6) + '|'); Start-Sleep -Milliseconds 500 }"
            """,
            "A ruler is drawn to the full window width, with the width printed at the "
            + "left. RESIZE THE WINDOW while it runs: the ruler must track the new width. "
            + "Ctrl-C to finish."),
    ];

    private static int Usage()
    {
        Console.Error.WriteLine(
            "usage: mxc-isolation-session-console [interactive|streaming|resize|<command line>]");
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

    private static int Main(string[] args)
    {
        var arg = args.Length > 0 ? string.Join(' ', args) : "interactive";
        if (arg is "--help" or "-h")
        {
            return Usage();
        }

        var scenario = Array.Find(Scenarios, s => s.Name == arg);
        var label = scenario?.Name ?? "custom";
        var command = scenario?.Command ?? arg;

        SandboxId id;
        try
        {
            var provisioned = MxcLifecycle.ProvisionSandbox(
                StateAwareContainment.IsolationSession,
                new ProvisionSandboxOptions
                {
                    Network = new StateAwareNetworkPolicy
                    {
                        DefaultPolicy = StateAwareNetworkDefault.Allow,
                        AllowLocalNetwork = true,
                    },
                });
            id = provisioned.SandboxId;
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
                "[driver] everything below runs inside the isolation session.\n");

            var outcome = MxcLifecycle.ExecInSandboxAttached(id, command);
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
