// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

static async Task ForwardLinesAsync(Stream? stream, TextWriter destination, string prefix)
{
    if (stream is null)
    {
        throw new IOException("The selected backend did not provide an expected output stream.");
    }

    using var reader = new StreamReader(stream);
    while (await reader.ReadLineAsync() is { } line)
    {
        await destination.WriteLineAsync($"{prefix}{line}");
    }
}

var sampleCommand = OperatingSystem.IsWindows()
    ? "powershell.exe -NoProfile -NonInteractive -Command \"Write-Output first; Start-Sleep -Milliseconds 750; Write-Output second\""
    : "sh -c \"printf 'first\\n'; sleep 1; printf 'second\\n'\"";

try
{
    using var process = await MxcContainer.SpawnAsync(new ContainerRequest(sampleCommand)
    {
        TimeoutMs = 30_000,
    });
    var stdout = ForwardLinesAsync(process.StandardOutput, Console.Out, "");
    var stderr = ForwardLinesAsync(process.StandardError, Console.Error, "stderr: ");
    var result = await process.WaitAsync();
    await Task.WhenAll(stdout, stderr);

    foreach (var warning in process.Warnings)
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
catch (IOException error)
{
    Console.Error.WriteLine($"stream error: {error.Message}");
    return 1;
}
