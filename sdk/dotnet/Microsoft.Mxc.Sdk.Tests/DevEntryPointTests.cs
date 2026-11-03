// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class DevEntryPointTests
{
    [Fact]
    public async Task DevEntryPointsRejectInvalidDocumentsWithoutLaunching()
    {
        var synchronous = Assert.Throws<MxcException>(
            () => Dev.MxcContainer.SpawnWithPtyJson("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, synchronous.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync("{}"));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public async Task PhaseSpecificMethodsRejectMismatchesBeforeDispatch()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StopContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        Assert.Contains("requires phase 'stop'", sync.Message);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ValidateProcessJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);

        var exec = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, exec.Code);

        const string duplicate =
            """{"version":"1.0.0","phase":"start","phase":"stop","sandboxId":"iso:unused"}""";
        var repeated = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(duplicate));
        Assert.Equal(ErrorCode.MalformedRequest, repeated.Code);
    }

    [Fact]
    public async Task CapturedExecValidatesBeforeCanceledSpawn()
    {
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""";
        var error = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                start, cancellationToken: new CancellationToken(true)));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
        Assert.Contains("RunInContainerJson requires phase 'exec'", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("exec")]
    public void PreparationPreservesUnicodeJsonAndExtractsTimeout(string? phase)
    {
        var json =
            " {\"version\":\"1.1.0-alpha\",\"_comment\":\"caf\u00e9 \ud83d\ude00\"," +
            (phase is null ? "" : "\"phase\":\"exec\",\"sandboxId\":\"iso:unused\",") +
            "\"process\":{\"commandLine\":\"echo\",\"timeout\":250}} ";
        var (request, timeout) = Dev.DevJsonRequest.Prepare(
            json, nameof(PreparationPreservesUnicodeJsonAndExtractsTimeout), phase);
        Assert.Equal((uint?)250, timeout);
        Assert.Equal((byte)0, request[^1]);
        Assert.Equal(json, Encoding.UTF8.GetString(request.AsSpan(0, request.Length - 1)));
    }

    [Fact]
    public void ExactContractErrorsReachPublicDevFacade()
    {
        const string unregistered =
            """{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}""";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(unregistered));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);

        const string unknownField =
            """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused","extra":true}""";
        error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(unknownField));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Fact]
    public void ExperimentalAuthorizationIsSeparateFromTheDevelopmentContract()
    {
        const string json =
            """{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateProvisionJson(json));
        Assert.Equal(ErrorCode.BackendUnavailable, error.Code);
        Assert.Contains("experimental", error.Message);

        try
        {
            Dev.MxcLifecycle.ValidateProvisionJson(json, new Dev.JsonOptions { Experimental = true });
        }
        catch (MxcException authorized)
        {
            Assert.NotEqual(ErrorCode.BackendUnavailable, authorized.Code);
        }
    }

    [Fact]
    public void EmbeddedNullCannotChangeTheNativeDocument()
    {
        const string json = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + "\0";
        var error = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(json));
        Assert.Equal(ErrorCode.MalformedRequest, error.Code);
    }

    [Theory]
    [InlineData('\uD800')]
    [InlineData('\uDC00')]
    public async Task LoneSurrogatesAreMalformedRequests(char surrogate)
    {
        var creation = """{"version":"1.0.0","process":{"commandLine":"echo"}}""" + surrogate;
        var start = """{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}""" + surrogate;
        var sync = Assert.Throws<MxcException>(() => Dev.MxcContainer.RunJson(creation));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);
        sync = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.StartContainerJson(start));
        Assert.Equal(ErrorCode.MalformedRequest, sync.Code);

        var asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcContainer.RunJsonAsync(
                creation, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
        asynchronous = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJsonAsync(start));
        Assert.Equal(ErrorCode.MalformedRequest, asynchronous.Code);
    }

    [Fact]
    public void DeepCommentReachesNativeExactParser()
    {
        static string Request(int depth) =>
            "{\"version\":\"1.0.0\",\"phase\":\"start\",\"sandboxId\":\"nosuchbackend:abc123\",\"_comment\":" +
            new string('[', depth) + "0" + new string(']', depth) + "}";

        var accepted = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(70)));
        Assert.Equal(ErrorCode.UnsupportedContainment, accepted.Code);

        var tooDeep = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.ValidateStartJson(Request(130)));
        Assert.Equal(ErrorCode.MalformedRequest, tooDeep.Code);
    }

    [Fact]
    public void ExistingContainerExecReachesNativeBackendValidation()
    {
        const string json =
            """{"version":"1.0.0","phase":"exec","sandboxId":"nosuchbackend:abc123","process":{"commandLine":"echo hi"}}""";
        var error = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(json));
        Assert.Equal(ErrorCode.UnsupportedContainment, error.Code);
    }

    [Fact]
    public void PtyEntryPointsHaveNoAsyncOverloads()
    {
        Assert.Null(typeof(Dev.MxcContainer).GetMethod("SpawnWithPtyJsonAsync"));
        Assert.Null(typeof(Dev.MxcLifecycle).GetMethod("SpawnInContainerWithPtyJsonAsync"));
    }

    [Fact]
    public void DevOptionsAreClosedAndTerminalControlsStayWithPtyOperations()
    {
        Assert.True(typeof(Dev.JsonOptions).IsSealed);
        Assert.True(typeof(Dev.PtyJsonOptions).IsSealed);
        Assert.False(typeof(Dev.JsonOptions).IsAssignableFrom(typeof(Dev.PtyJsonOptions)));
    }
}
