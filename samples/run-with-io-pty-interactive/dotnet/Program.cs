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
    var windows = OperatingSystem.IsWindows();
    var command = windows ? "powershell.exe -NoLogo" : "sh";
    var containment = windows
        ? (Containment)new Containment.IsolationSession()
        : new Containment.Process();
    Console.Error.WriteLine("Starting a contained shell. Type `exit` to leave.");
    using var terminal = MxcContainer.SpawnWithPty(
        new ContainerRequest(command)
        {
            Containment = containment,
            Network = windows
                ? new NetworkPolicy
                {
                    Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
                    Ingress = new NetworkIngressPolicy
                    {
                        Default = NetworkAction.Allow,
                        HostLoopback = NetworkAction.Allow,
                    },
                }
                : null,
        });
    using var inputCancellation = new CancellationTokenSource();
    var input = Console.OpenStandardInput().CopyToAsync(
        terminal.Input,
        inputCancellation.Token);
    var output = terminal.Output.CopyToAsync(Console.OpenStandardOutput());

    var result = await terminal.WaitAsync();
    await output;
    inputCancellation.Cancel();
    terminal.Input.Close();
    ObserveInputRelay(input);

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

static void ObserveInputRelay(Task input)
{
    _ = input.ContinueWith(
        static task =>
        {
            var error = task.Exception?.GetBaseException();
            if (error is not (OperationCanceledException or IOException or ObjectDisposedException))
            {
                Console.Error.WriteLine($"input relay failed: {error?.Message}");
            }
        },
        CancellationToken.None,
        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
        TaskScheduler.Default);
}
