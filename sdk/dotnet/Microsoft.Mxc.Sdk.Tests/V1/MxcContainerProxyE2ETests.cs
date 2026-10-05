// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcContainerProxyE2ETests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Run_UnpackagedProxy_ReachesOrigin(bool asynchronous)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows()
            && Environment.GetEnvironmentVariable("MXC_ENABLE_PROCESSCONTAINER_PROXY_TESTS") == "1",
            "requires an opted-in Windows ProcessContainer proxy host");
        var proxyUrl = Environment.GetEnvironmentVariable("MXC_TEST_PROXY_URL");
        var originUrl = Environment.GetEnvironmentVariable("MXC_TEST_PROXY_ORIGIN_URL");
        var expectedBody = Environment.GetEnvironmentVariable("MXC_TEST_PROXY_EXPECTED_BODY");
        Assert.NotNull(proxyUrl);
        Assert.NotNull(originUrl);
        Assert.False(string.IsNullOrEmpty(expectedBody));

        var request = new ContainerRequest(
            "powershell.exe -NoProfile -Command \""
            + "$ErrorActionPreference = 'Stop'; "
            + "$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1; "
            + "$h.SetTimeouts(5000,5000,5000,5000); "
            + $"$h.Open('GET','{originUrl}',$false); $h.Send(); "
            + "if ($h.Status -ne 200) { throw ('HTTP status ' + $h.Status) }; "
            + "Write-Output ('PROXY_RESPONSE: ' + $h.ResponseText)\"")
        {
            Containment = new Containment.ProcessContainer(),
            Ui = new UiPolicy { Disable = false },
            TimeoutMs = 30000,
            Network = new NetworkPolicy
            {
                Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny },
                Ingress = new NetworkIngressPolicy
                {
                    Default = NetworkAction.Allow,
                    HostLoopback = NetworkAction.Allow,
                },
                RuntimeConfig = new NetworkRuntimeConfig { NetworkProxy = proxyUrl },
            },
        };
        var result = asynchronous
            ? await MxcContainer.RunAsync(request, cancellationToken: TestContext.Current.CancellationToken)
            : MxcContainer.Run(request);

        Assert.False(result.TimedOut);
        Assert.True(result.ExitCode == 0, result.Stderr);
        Assert.Contains("PROXY_RESPONSE: ", result.Stdout);
        Assert.Contains(expectedBody, result.Stdout);
    }
}
