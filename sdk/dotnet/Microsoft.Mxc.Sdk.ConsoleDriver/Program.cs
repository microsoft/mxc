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
// Must run at a real interactive console.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using System.ComponentModel;
using System.Runtime.InteropServices;

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

        ContainerId id;
        try
        {
            var provisioned = MxcLifecycle.ProvisionContainer(
                new IsolationSessionProvisionRequest(new NetworkPolicy
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
            MxcLifecycle.StartContainer(id);
            Console.Error.WriteLine($"[driver] started. Scenario: {label}");
            if (scenario is { } s)
            {
                Console.Error.WriteLine($"[driver] WHAT TO LOOK FOR: {s.WhatToLookFor}");
            }
            Console.Error.WriteLine(
                "[driver] everything below runs inside the isolation session.\n");

            using var terminal = MxcLifecycle.SpawnInContainerWithPty(
                id,
                new ExecutionRequest(command),
                new SpawnInContainerWithPtyOptions
                {
                    Size = CurrentConsoleSize(),
                });
            var outcome = AttachToCurrentConsole(terminal);
            Console.WriteLine(
                $"\n[driver] timedOut: {outcome.TimedOut}, exitCode: {outcome.ExitCode}");
            return outcome.ExitCode;
        }
        catch (MxcException e)
        {
            Console.WriteLine($"\n[driver] failed [{e.Code}]: {e.Message}");
            return 1;
        }
        catch (Win32Exception e)
        {
            Console.WriteLine($"\n[driver] console setup failed: {e.Message}");
            return 1;
        }
        finally
        {
            Console.Error.WriteLine("\n[driver] tearing down…");
            try
            {
                MxcLifecycle.StopContainer(id);
            }
            catch (MxcException)
            {
                // A failed stop must not prevent the deprovision that releases
                // the account.
            }
            try
            {
                MxcLifecycle.DeprovisionContainer(id);
                Console.Error.WriteLine("[driver] deprovisioned.");
            }
            catch (MxcException e)
            {
                Console.Error.WriteLine(
                    $"[driver] WARNING: deprovision failed, account may leak: {e.Message}");
            }
        }
    }

    // Attach the caller-controlled PTY to this process's console by relaying its
    // streams and forwarding console input, control characters, and resize events.
    private static WaitResult AttachToCurrentConsole(MxcPtyProcess terminal)
    {
        using var consoleMode = ConsoleModeScope.EnterRaw();
        using var cancellation = new CancellationTokenSource();
        using var input = terminal.Input;
        var output = terminal.Output;
        using var outputCloser = terminal.StandardOutputCloser;
        var outputTask = output.CopyToAsync(Console.OpenStandardOutput());
        var inputTask = Console.OpenStandardInput().CopyToAsync(input, cancellation.Token);
        var resizeTask = TrackConsoleSizeAsync(terminal, cancellation.Token);

        try
        {
            var outcome = terminal.Wait();
            outputCloser?.Close();
            outputTask.GetAwaiter().GetResult();
            return outcome;
        }
        finally
        {
            cancellation.Cancel();
            input.Dispose();
            ObserveInputRelay(inputTask);
            try
            {
                resizeTask.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private static void ObserveInputRelay(Task inputTask)
    {
        _ = inputTask.ContinueWith(
            static task =>
            {
                var error = task.Exception?.GetBaseException();
                if (error is not (OperationCanceledException or ObjectDisposedException))
                {
                    Console.Error.WriteLine(
                        $"[driver] WARNING: console input relay failed: {error?.Message}");
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    // Console has no resize event; poll so the sandboxed TUI can reflow when
    // the operator resizes this window.
    private static async Task TrackConsoleSizeAsync(
        MxcPtyProcess terminal,
        CancellationToken cancellationToken)
    {
        var last = CurrentConsoleSize();
        while (true)
        {
            await Task.Delay(100, cancellationToken);
            var current = CurrentConsoleSize();
            if (current != last)
            {
                terminal.Resize(current);
                last = current;
            }
        }
    }

    // ConPTY dimensions are non-zero signed 16-bit values.
    private static MxcPtySize CurrentConsoleSize() =>
        new(
            checked((ushort)Math.Clamp(Console.WindowHeight, 1, short.MaxValue)),
            checked((ushort)Math.Clamp(Console.WindowWidth, 1, short.MaxValue)));

    private sealed class ConsoleModeScope : IDisposable
    {
        private const int StdInputHandle = -10;
        private const int StdOutputHandle = -11;
        private const uint EnableProcessedInput = 0x0001;
        private const uint EnableLineInput = 0x0002;
        private const uint EnableEchoInput = 0x0004;
        private const uint EnableVirtualTerminalProcessing = 0x0004;
        private const uint DisableNewlineAutoReturn = 0x0008;
        private const uint EnableVirtualTerminalInput = 0x0200;

        private readonly nint _input;
        private readonly nint _output;
        private readonly uint _inputMode;
        private readonly uint _outputMode;
        private bool _disposed;

        private ConsoleModeScope(
            nint input,
            nint output,
            uint inputMode,
            uint outputMode)
        {
            _input = input;
            _output = output;
            _inputMode = inputMode;
            _outputMode = outputMode;
        }

        internal static ConsoleModeScope EnterRaw()
        {
            var input = GetStdHandle(StdInputHandle);
            var output = GetStdHandle(StdOutputHandle);
            if (!GetConsoleMode(input, out var inputMode)
                || !GetConsoleMode(output, out var outputMode))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "the PTY driver must run from a real interactive console");
            }

            var rawInput = (inputMode | EnableVirtualTerminalInput)
                & ~(EnableProcessedInput | EnableLineInput | EnableEchoInput);
            if (!SetConsoleMode(input, rawInput))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "failed to put console input into raw VT mode");
            }

            var rawOutput = outputMode
                | EnableVirtualTerminalProcessing
                | DisableNewlineAutoReturn;
            if (!SetConsoleMode(output, rawOutput))
            {
                var error = Marshal.GetLastWin32Error();
                _ = SetConsoleMode(input, inputMode);
                throw new Win32Exception(error, "failed to enable VT console output");
            }

            return new ConsoleModeScope(input, output, inputMode, outputMode);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _ = SetConsoleMode(_output, _outputMode);
            _ = SetConsoleMode(_input, _inputMode);
            _disposed = true;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint GetStdHandle(int standardHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetConsoleMode(nint consoleHandle, out uint mode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetConsoleMode(nint consoleHandle, uint mode);
    }
}
