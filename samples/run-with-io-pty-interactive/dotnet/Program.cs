// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

if (Console.IsInputRedirected || Console.IsOutputRedirected)
{
    Console.Error.WriteLine("Run this sample from an interactive terminal.");
    return 1;
}

try
{
    var command = OperatingSystem.IsWindows() ? "powershell.exe -NoLogo" : "sh";
    var containment = OperatingSystem.IsWindows()
        ? (Containment)new Containment.IsolationSession()
        : new Containment.Process();
    Console.Error.WriteLine("Starting a contained shell. Type `exit` to leave.");
    using var terminal = MxcContainer.SpawnWithPty(
        new ContainerRequest(command)
        {
            Containment = containment,
        });
    using var inputCancellation = new CancellationTokenSource();
    var input = Console.OpenStandardInput().CopyToAsync(
        terminal.Input,
        inputCancellation.Token);
    var output = terminal.Output.CopyToAsync(Console.OpenStandardOutput());

    var result = await terminal.WaitAsync();
    await output;
    inputCancellation.Cancel();
    try
    {
        await input;
    }
    catch (OperationCanceledException)
    {
    }
    catch (IOException)
    {
        // The PTY input closes when the contained shell exits.
    }

    foreach (var warning in terminal.Warnings)
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
