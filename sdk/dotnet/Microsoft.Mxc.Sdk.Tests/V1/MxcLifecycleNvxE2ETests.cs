// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;
using Xunit;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

namespace Microsoft.Mxc.Sdk.Tests.V1;

[Collection("MxcLiveHost")]
public class MxcLifecycleNvxE2ETests
{
    [Fact]
    public async Task DevJson_NvxLifecycleCaptureAndLiveStreams()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64 &&
            Environment.GetEnvironmentVariable("MXC_ENABLE_NVX_TESTS") == "1", "NVX tests require Windows x64 and MXC_ENABLE_NVX_TESTS=1");
        var options = new Dev.JsonOptions { Experimental = true };
        const string image = "mcr.microsoft.com/azurelinux/base/core:3.0";
        var run = JsonSerializer.Serialize(new { version = "1.1.0-alpha", containment = "microvm", microvm = new { image }, process = new { commandLine = "printf 'NVX_ONESHOT\\n'", timeout = 30000 } });
        var oneShot = await Dev.MxcContainer.RunJsonAsync(run, options, TestContext.Current.CancellationToken);
        Assert.Equal(0, oneShot.ExitCode);
        Assert.Contains("NVX_ONESHOT", oneShot.Stdout);
        var provision = JsonSerializer.Serialize(new { version = "1.1.0-alpha", phase = "provision", containment = "microvm", microvm = new { image } });
        using var response = JsonDocument.Parse(await Dev.MxcLifecycle.ProvisionContainerJsonAsync(provision, options));
        var id = response.RootElement.GetProperty("result").GetProperty("sandboxId").GetString();
        Assert.False(string.IsNullOrEmpty(id));
        string Phase(string phase) => JsonSerializer.Serialize(new { version = "1.0.0", phase, sandboxId = id });
        string Exec(string command) => JsonSerializer.Serialize(new { version = "1.1.0-alpha", phase = "exec", sandboxId = id, process = new { commandLine = command, timeout = 30000 } });
        var started = false;
        try
        {
            await Dev.MxcLifecycle.StartContainerJsonAsync(Phase("start"), options);
            started = true;
            var captured = await Dev.MxcLifecycle.RunInContainerJsonAsync(Exec("printf 'NVX_CAPTURE\\n'; printf 'NVX_ERROR\\n' >&2"), options, TestContext.Current.CancellationToken);
            Assert.Equal(0, captured.ExitCode);
            Assert.Contains("NVX_CAPTURE", captured.Stdout);
            Assert.Contains("NVX_ERROR", captured.Stderr);
            using var process = await Dev.MxcLifecycle.SpawnInContainerJsonAsync(Exec("printf 'NVX_LIVE_OUT\\n'; printf 'NVX_LIVE_ERR\\n' >&2; sleep 3"), options, TestContext.Current.CancellationToken);
            using var stdout = new StreamReader(Assert.IsAssignableFrom<Stream>(process.StandardOutput));
            using var stderr = new StreamReader(Assert.IsAssignableFrom<Stream>(process.StandardError));
            var output = Task.WhenAll(stdout.ReadLineAsync(TestContext.Current.CancellationToken).AsTask(), stderr.ReadLineAsync(TestContext.Current.CancellationToken).AsTask());
            var exit = process.WaitAsync(TestContext.Current.CancellationToken);
            Assert.Same(output, await Task.WhenAny(output, exit));
            var lines = await output;
            Assert.Equal("NVX_LIVE_OUT", lines[0]);
            Assert.Equal("NVX_LIVE_ERR", lines[1]);
            Assert.Equal(0, (await exit).ExitCode);
        }
        finally
        {
            try { if (started) await Dev.MxcLifecycle.StopContainerJsonAsync(Phase("stop"), options); }
            finally { await Dev.MxcLifecycle.DeprovisionContainerJsonAsync(Phase("deprovision"), options); }
        }
    }
}
