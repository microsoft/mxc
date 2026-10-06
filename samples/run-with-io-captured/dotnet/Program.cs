// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

var sampleCommand = OperatingSystem.IsWindows()
    ? "cmd.exe /d /s /c \"echo hello from MXC\""
    : "sh -c \"printf 'hello from MXC\\n'\"";

try
{
    var result = await MxcContainer.RunAsync(new ContainerRequest(sampleCommand)
    {
        TimeoutMs = 30_000,
    });

    // The process has finished, so these strings contain its complete output.
    Console.Write(result.Stdout);
    Console.Error.Write(result.Stderr);
    foreach (var warning in result.Warnings)
    {
        Console.Error.WriteLine($"warning: {warning}");
    }

    if (result.TimedOut)
    {
        Console.Error.WriteLine("workload timed out");
        return 124;
    }

    if (result.ExitCode != 0)
    {
        return result.ExitCode;
    }
    if (!result.Stdout.Contains("hello from MXC", StringComparison.Ordinal))
    {
        Console.Error.WriteLine("captured stdout did not contain the expected greeting");
        return 1;
    }
    return 0;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
