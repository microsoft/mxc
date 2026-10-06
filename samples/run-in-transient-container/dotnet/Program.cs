// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

var support = MxcPlatform.GetPlatformSupport();
if (!support.IsSupported)
{
    Console.Error.WriteLine($"MXC is not supported: {support.Reason ?? "unknown reason"}");
    return 1;
}

var sampleCommand = OperatingSystem.IsWindows()
    ? "cmd.exe /d /s /c \"echo hello from %MXC_SAMPLE_NAME%\""
    : "sh -c \"printf 'hello from %s\\n' \\\"$MXC_SAMPLE_NAME\\\"\"";

try
{
    var request = new ContainerRequest(sampleCommand)
    {
        Containment = new Containment.Process(),
        TimeoutMs = 30_000,
        Environment = new Dictionary<string, string>
        {
            ["MXC_SAMPLE_NAME"] = "transient-container",
        },
        InheritDefaultEnvironment = true,
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
