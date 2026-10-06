// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

try
{
    var support = MxcPlatform.GetPlatformSupport();
    Console.WriteLine($"platform supported: {support.IsSupported}");
    if (support.Reason is not null)
    {
        Console.WriteLine($"reason: {support.Reason}");
    }

    var backends = MxcPlatform.GetAvailableBackends();
    if (backends.Count == 0)
    {
        Console.WriteLine("no containment backends are currently available");
    }
    foreach (var backend in backends)
    {
        Console.WriteLine($"backend: {backend.Backend}");
        if (backend.Capabilities.Count > 0)
        {
            Console.WriteLine($"  capabilities: {string.Join(", ", backend.Capabilities)}");
        }
        foreach (var warning in backend.Warnings)
        {
            Console.WriteLine($"  warning: {warning}");
        }
    }

    if (OperatingSystem.IsWindows())
    {
        var probe = MxcContainer.Probe(
            new ContainerRequest("cmd.exe /d /s /c \"echo support check only\""));
        foreach (var warning in probe.Warnings)
        {
            Console.WriteLine($"probe warning: {warning}");
        }
        if (probe.Error is not null)
        {
            Console.Error.WriteLine($"probe error: {probe.Error}");
            return 1;
        }
    }

    return support.IsSupported ? 0 : 1;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
