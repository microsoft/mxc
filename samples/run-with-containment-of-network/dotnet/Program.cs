// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;

var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;
var accept = Task.Run(async () =>
{
    using var client = await listener.AcceptTcpClientAsync();
    await client.GetStream().WriteAsync(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"u8.ToArray());
});
var sampleCommand = OperatingSystem.IsWindows()
    ? $"powershell.exe -NoProfile -Command \"$curl = (Get-Command curl.exe -ErrorAction Stop).Source; & $curl --silent --fail --max-time 3 http://127.0.0.1:{port}/ *> $null; if ($LASTEXITCODE -eq 0) {{ Write-Error 'network access unexpectedly succeeded'; exit 1 }}; Write-Output 'network access blocked by policy'\""
    : $"sh -c \"command -v curl >/dev/null || {{ echo 'curl is required' >&2; exit 2; }}; if curl --silent --fail --max-time 3 http://127.0.0.1:{port}/ >/dev/null 2>&1; then echo 'ERROR: network access unexpectedly succeeded' >&2; exit 1; fi; printf 'network access blocked by policy\\n'\"";

try
{
    var request = new ContainerRequest(sampleCommand)
    {
        Containment = new Containment.Process(),
        Network = new NetworkPolicy
        {
            Egress = new NetworkEgressPolicy
            {
                Default = NetworkAction.Deny,
            },
            Ingress = new NetworkIngressPolicy
            {
                Default = NetworkAction.Deny,
                HostLoopback = NetworkAction.Deny,
            },
        },
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
finally
{
    listener.Stop();
    try
    {
        await accept;
    }
    catch (SocketException)
    {
    }
    catch (ObjectDisposedException)
    {
    }
}
