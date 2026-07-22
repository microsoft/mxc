// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;

// A minimal end-to-end sample: build a policy, run a command in a sandbox, and
// print what it produced. The command defaults to a simple echo; pass your own
// as arguments (joined into a single command line).
//
// Note: actually running a sandbox requires a working host backend
// (e.g. an elevated, host-prepped Windows host — see docs/host-prep.md). The
// sample reports MXC errors instead of crashing so it is safe to run anywhere.

Console.WriteLine($"mxc_ffi native version: {MxcSandbox.NativeVersion}");

var command = args.Length > 0
    ? string.Join(' ', args)
    : (OperatingSystem.IsWindows() ? "cmd /c echo hello from MXC" : "echo hello from MXC");

var policy = new SandboxPolicy
{
    Version = "0.7.0-alpha",
    Filesystem = new FilesystemPolicy
    {
        ReadwritePaths = { OperatingSystem.IsWindows() ? @"C:\Windows\Temp" : "/tmp" },
    },
    TimeoutMs = 30_000,
};

Console.WriteLine($"Running: {command}");

try
{
    var result = MxcSandbox.Run(policy, command);
    Console.WriteLine($"exit code : {result.ExitCode}");
    Console.WriteLine($"timed out : {result.TimedOut}");
    Console.WriteLine($"stdout    : {result.Stdout.TrimEnd()}");
    if (!string.IsNullOrWhiteSpace(result.Stderr))
    {
        Console.WriteLine($"stderr    : {result.Stderr.TrimEnd()}");
    }

    // Streaming variant: spawn the same command as a live process and stream
    // its stdout as it is produced, then wait for exit.
    Console.WriteLine();
    Console.WriteLine("Streaming the same command live:");
    using (var proc = MxcSandbox.Spawn(policy, command))
    {
        var stdout = proc.StandardOutput;
        if (stdout is not null)
        {
            using var reader = new StreamReader(stdout);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                Console.WriteLine($"  [live] {line}");
            }
        }

        var streamResult = proc.Wait();
        Console.WriteLine($"streamed exit code : {streamResult.ExitCode}");
    }

    // State-aware lifecycle: provision -> start -> exec -> stop -> deprovision.
    // Requires the IsolationSession backend (Windows-only, experimental, with
    // its OS-side service), so this reports the MXC error on hosts without it.
    Console.WriteLine();
    Console.WriteLine("State-aware lifecycle:");
    try
    {
        var provisioned = MxcLifecycle.ProvisionSandbox();
        Console.WriteLine($"  provisioned: {provisioned.SandboxId}");
        try
        {
            MxcLifecycle.StartSandbox(provisioned.SandboxId);
            var lifecycleRun = await MxcLifecycle.ExecInSandboxAsync(provisioned.SandboxId, command);
            Console.WriteLine($"  exec exit={lifecycleRun.ExitCode} stdout={lifecycleRun.Stdout.TrimEnd()}");
            MxcLifecycle.StopSandbox(provisioned.SandboxId);
        }
        finally
        {
            MxcLifecycle.DeprovisionSandbox(provisioned.SandboxId);
        }
    }
    catch (MxcException ex)
    {
        Console.WriteLine($"  lifecycle unavailable on this host [{ex.Code}]: {ex.Message}");
    }

    return result.ExitCode;
}
catch (MxcException ex)
{
    Console.Error.WriteLine($"MXC error [{ex.Code}]: {ex.Message}");
    return 1;
}
