// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("The persisted IsolationSession sample requires Windows.");
    return 1;
}

ContainerId? containerId = null;
var started = false;
var exitCode = 1;
MxcException? operationError = null;
MxcException? cleanupError = null;

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
    containerId = provisioned.ContainerId;
    Console.WriteLine($"provisioned: {containerId}");

    MxcLifecycle.StartContainer(containerId.Value);
    started = true;

    var result = await MxcLifecycle.RunInContainerAsync(
        containerId.Value,
        new ExecutionRequest(
            "cmd.exe /d /s /c \"echo hello from persisted container\"")
        {
            TimeoutMs = 30_000,
        });
    Console.Write(result.Stdout);
    Console.Error.Write(result.Stderr);
    foreach (var warning in result.Warnings)
    {
        Console.Error.WriteLine($"warning: {warning}");
    }
    exitCode = result.TimedOut ? 124 : result.ExitCode;
}
catch (MxcException error)
{
    operationError = error;
}
finally
{
    if (containerId is { } id)
    {
        if (started)
        {
            try
            {
                MxcLifecycle.StopContainer(id);
            }
            catch (MxcException error)
            {
                Console.Error.WriteLine($"cleanup error while stopping container: {error.Message}");
                cleanupError = error;
            }
        }

        try
        {
            MxcLifecycle.DeprovisionContainer(id);
        }
        catch (MxcException error)
        {
            Console.Error.WriteLine($"cleanup error while deprovisioning container: {error.Message}");
            cleanupError ??= error;
        }
    }
}

if (operationError is not null)
{
    Console.Error.WriteLine($"MXC error [{operationError.Code}]: {operationError.Message}");
    return 1;
}
if (cleanupError is not null)
{
    return 1;
}
return exitCode;
