// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine(
        "Denial capture is available only with Windows ProcessContainer.");
    return 1;
}

var deniedPath = Path.GetFullPath(
    Path.Combine(Environment.CurrentDirectory, "..", "denied.txt"));

try
{
    var request = new ContainerRequest(
        "cmd.exe /d /s /c \"type \\\"%MXC_DENIED_FILE%\\\" >nul 2>&1 & "
        + "if errorlevel 1 (exit /b 0) else (echo ERROR: denied file was readable 1>&2 & exit /b 1)\"")
    {
        Containment = new Containment.ProcessContainer
        {
            CaptureDenials = new CaptureDenialsPolicy(),
        },
        Filesystem = new FilesystemPolicy
        {
            DeniedPaths = { deniedPath },
        },
        Environment = new Dictionary<string, string>
        {
            ["MXC_DENIED_FILE"] = deniedPath,
        },
        InheritDefaultEnvironment = true,
        TimeoutMs = 30_000,
    };
    var result = await MxcContainer.RunAsync(request);

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
    if (result.OutputMetadata?.CaptureDenialsError is { } captureError)
    {
        throw new InvalidOperationException(captureError.Message);
    }
    var capture = result.OutputMetadata?.CaptureDenials
        ?? throw new InvalidOperationException("Denial capture returned no report.");
    if (capture.TotalDenials == 0)
    {
        throw new InvalidOperationException("Denial capture returned an empty report.");
    }

    Console.WriteLine(
        $"captured {capture.TotalDenials} denial(s) in {capture.OutputPath}");
    return 0;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
