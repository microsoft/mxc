// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

var sampleDirectory = Path.GetFullPath(
    Path.Combine(Environment.CurrentDirectory, ".."));
var sampleCommand = OperatingSystem.IsWindows()
    ? "cmd.exe /d /s /c \"echo unexpected>blocked.txt 2>nul & if exist blocked.txt (del blocked.txt & echo ERROR: write unexpectedly succeeded & exit /b 1) else (type input.txt & echo write access blocked by policy)\""
    : "sh -c \"if printf unexpected > blocked.txt 2>/dev/null; then rm -f blocked.txt; echo 'ERROR: write unexpectedly succeeded' >&2; exit 1; fi; cat input.txt; printf 'write access blocked by policy\\n'\"";

try
{
    var request = new ContainerRequest(sampleCommand)
    {
        Containment = new Containment.Process(),
        Filesystem = new FilesystemPolicy
        {
            ReadonlyPaths = { sampleDirectory },
        },
        WorkingDirectory = sampleDirectory,
        TimeoutMs = 30_000,
    };
    var result = await MxcContainer.RunAsync(request);

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
    return result.ExitCode;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
