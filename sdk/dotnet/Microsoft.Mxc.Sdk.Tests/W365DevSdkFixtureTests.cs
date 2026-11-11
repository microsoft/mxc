// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class W365DevSdkFixtureTests
{
    private const string Id = "w365:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222";
    private const string Provision = """
        {"version":"1.1.0-alpha","phase":"provision","containment":"w365_agents",
         "w365Agents":{"provision":{"poolId":"11111111-1111-1111-1111-111111111111","userType":"Local"}}}
        """;
    private static readonly Dev.JsonOptions Options = new() { Experimental = true };
    private static string Request(string phase) =>
        $$"""{"version":"1.1.0-alpha","phase":"{{phase}}","sandboxId":"{{Id}}"}""";

    [Fact]
    public async Task PublicDevLifecycleAgainstTrustedTlsFixture()
    {
        var mode = Environment.GetEnvironmentVariable("MXC_W365_TEST_SDK_MODE");
        Assert.SkipUnless(mode is not null, "requires the offline W365 SDK fixture selector");
        Assert.Equal("localhost", Environment.GetEnvironmentVariable("W365A_CONTROLPLANE_URL"));
        Assert.False(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MXC_W365_TEST_CA")));
        switch (mode)
        {
            case "validate":
                Assert.Equal(ErrorCode.BackendUnavailable,
                    Assert.Throws<MxcException>(() => Dev.MxcLifecycle.ProvisionContainerJson(Provision)).Code);
                Dev.MxcLifecycle.ValidateProvisionJson(Provision, Options);
                Dev.MxcLifecycle.ValidateStopJson(Request("stop"), Options);
                Dev.MxcLifecycle.ValidateDeprovisionJson(Request("deprovision"), Options);
                Assert.Throws<MxcException>(() => Dev.MxcLifecycle.ProvisionContainerJson(
                    Provision.Replace("\"w365Agents\"", "\"filesystem\":{},\"w365Agents\""), Options));
                Dev.MxcLifecycle.ValidateStartJson(Request("start"), Options);
                var exec = Request("exec").Replace("}", ",\"process\":{\"commandLine\":\"echo must-not-run\"}}");
                Dev.MxcLifecycle.ValidateProcessJson(exec, Options);
                Assert.Throws<MxcException>(() => Dev.MxcLifecycle.SpawnInContainerWithPtyJson(
                    exec, new Dev.PtyJsonOptions { Experimental = true }));
                Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(
                    """{"version":"1.1.0-alpha","containment":"w365_agents","process":{"commandLine":"echo must-not-run"}}""", Options));
                break;
            case "ready":
                using (var doc = JsonDocument.Parse(await Dev.MxcLifecycle.StartContainerJsonAsync(Request("start"), Options)))
                    Assert.Equal("Ready", doc.RootElement.GetProperty("result").GetProperty("metadata").GetProperty("status").GetString());
                break;
            case "capture":
                var captured = await Dev.MxcLifecycle.RunInContainerJsonAsync(
                    Request("exec").Replace("}", ",\"process\":{\"commandLine\":\"cmd.exe /c echo fixture\",\"timeout\":1234}}"),
                    Options, TestContext.Current.CancellationToken);
                Assert.Equal(7, captured.ExitCode);
                Assert.False(captured.TimedOut);
                Assert.Equal("fixture-out", captured.Stdout);
                Assert.Equal("fixture-err", captured.Stderr);
                break;
            case "pipe":
                using (var process = Dev.MxcLifecycle.SpawnInContainerJson(
                    Request("exec").Replace("}", ",\"process\":{\"commandLine\":\"cmd.exe /c echo fixture\",\"timeout\":1234}}"), Options))
                {
                    process.StandardInput?.Dispose();
                    var result = await process.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);
                    Assert.Equal(7, result.Item1.ExitCode);
                    Assert.Equal("fixture-out", System.Text.Encoding.UTF8.GetString(result.Item2));
                    Assert.Equal("fixture-err", System.Text.Encoding.UTF8.GetString(result.Item3));
                }
                break;
            case "exec-error":
                var execError = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.RunInContainerJson(
                    Request("exec").Replace("}", ",\"process\":{\"commandLine\":\"cmd.exe /c echo fixture\",\"timeout\":1234}}"), Options));
                Assert.NotNull(execError.Details);
                Assert.Equal("remote_exec_error", execError.Details.Value.GetProperty("code").GetString());
                Assert.True(execError.Details.Value.GetProperty("possiblySucceeded").GetBoolean());
                break;
            case "spawn-error":
                var spawnError = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.SpawnInContainerJson(
                    Request("exec").Replace("}", ",\"process\":{\"commandLine\":\"cmd.exe /c echo fixture\",\"timeout\":1234}}"), Options));
                Assert.Equal("auth_denied", spawnError.Details!.Value.GetProperty("code").GetString());
                Assert.False(spawnError.Details.Value.GetProperty("possiblySucceeded").GetBoolean());
                Assert.Equal(403, spawnError.Details.Value.GetProperty("httpStatus").GetInt32());
                Assert.Equal(Id, spawnError.Details.Value.GetProperty("sandboxId").GetString());
                break;
            case "provision":
                using (var doc = JsonDocument.Parse(await Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision, Options)))
                    Assert.Equal(Id, doc.RootElement.GetProperty("result").GetProperty("sandboxId").GetString());
                break;
            case "stop":
            case "cleanup":
                var response = mode == "stop"
                    ? await Dev.MxcLifecycle.StopContainerJsonAsync(Request("stop"), Options)
                    : await Dev.MxcLifecycle.DeprovisionContainerJsonAsync(Request("deprovision"), Options);
                using (var doc = JsonDocument.Parse(response))
                {
                    var metadata = doc.RootElement.GetProperty("result").GetProperty("metadata");
                    Assert.True(metadata.GetProperty("releaseRequested").GetBoolean());
                    Assert.False(metadata.GetProperty("restartable").GetBoolean());
                }
                break;
            case "uncertain-release":
            case "rejected":
            case "http-error":
            case "unknown":
                var error = mode == "uncertain-release"
                    ? await Assert.ThrowsAsync<MxcException>(() =>
                        Dev.MxcLifecycle.DeprovisionContainerJsonAsync(Request("deprovision"), Options))
                    : Assert.Throws<MxcException>(() => Dev.MxcLifecycle.ProvisionContainerJson(
                        mode == "unknown" ? Provision.Replace(",\"userType\":\"Local\"", "") : Provision, Options));
                Assert.Equal(ErrorCode.BackendError, error.Code);
                var details = Assert.IsType<JsonElement>(error.Details);
                Assert.True(details.GetProperty("possiblySucceeded").GetBoolean());
                Assert.Equal("fixture-request", details.GetProperty("requestId").GetString());
                Assert.False(string.IsNullOrEmpty(details.GetProperty("clientRequestId").GetString()));
                if (mode == "unknown")
                    Assert.False(details.TryGetProperty("sandboxId", out _));
                else
                    Assert.Equal(Id, details.GetProperty("sandboxId").GetString());
                if (mode == "uncertain-release")
                    Assert.Equal(408, details.GetProperty("httpStatus").GetInt32());
                if (mode == "http-error")
                {
                    Assert.Equal(500, details.GetProperty("httpStatus").GetInt32());
                    Assert.Equal("provision_timeout", details.GetProperty("code").GetString());
                }
                Assert.DoesNotContain(Id, error.ToString());
                break;
            default:
                Assert.Fail($"Unknown SDK fixture mode: {mode}");
                break;
        }
        File.WriteAllText(Environment.GetEnvironmentVariable("MXC_W365_TEST_SDK_MARKER")!, mode);
    }
}
