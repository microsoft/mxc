// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;

SandboxId? sandboxId = null;
var started = false;

try
{
    var provisioned = MxcLifecycle.ProvisionSandbox(
        StateAwareContainment.Wslc,
        new WslcProvisionOptions
        {
            Image = "alpine:latest",
            Network = new StateAwareNetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Deny,
                    HostLoopback = NetworkAction.Deny,
                },
            },
        });
    sandboxId = provisioned.SandboxId;
    Console.WriteLine($"Sandbox ID: {sandboxId}");

    MxcLifecycle.StartSandbox(sandboxId.Value);
    started = true;

    var outcome = MxcLifecycle.ExecInSandboxAttached(
        sandboxId.Value,
        "sh -c 'echo \"hello from wslc bash\"; sleep 3; echo \"hello again from wslc bash\"'",
        new WslcExecOptions { TimeoutMs = 30_000 });

    return outcome.ExitCode;
}
catch (MxcException error)
{
    Console.Error.WriteLine($"MXC error [{error.Code}]: {error.Message}");
    return 1;
}
finally
{
    if (sandboxId is { } id)
    {
        try
        {
            if (started)
            {
                MxcLifecycle.StopSandbox(id);
            }
        }
        catch (MxcException error)
        {
            Console.Error.WriteLine($"Stop failed; continuing with deprovision: {error.Message}");
        }

        try
        {
            MxcLifecycle.DeprovisionSandbox(id);
        }
        catch (MxcException error)
        {
            Console.Error.WriteLine($"WARNING: deprovision failed: {error.Message}");
        }
    }
}
