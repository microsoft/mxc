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

    return result.ExitCode;
}
catch (MxcException ex)
{
    Console.Error.WriteLine($"MXC error [{ex.Code}]: {ex.Message}");
    return 1;
}
