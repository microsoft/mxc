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
    public async Task RealNativeLifecycleAndCapturedExecRejectUnsupportedBackend()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() &&
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64 &&
            File.Exists(Path.Combine(AppContext.BaseDirectory, "mxc_ffi.dll")), "Windows x64 mxc_ffi.dll required");
        const string start = """{"version":"1.0.0","phase":"start","sandboxId":"nosuchbackend:abc123"}""";
        const string exec = """{"version":"1.1.0-alpha","phase":"exec","sandboxId":"nosuchbackend:abc123","process":{"commandLine":"echo"}}""";
        var lifecycle = Assert.Throws<MxcException>(() => Dev.MxcLifecycle.ValidateStartJson(start));
        Assert.Equal(ErrorCode.UnsupportedContainment, lifecycle.Code);
        var capture = await Assert.ThrowsAsync<MxcException>(() => Dev.MxcLifecycle.RunInContainerJsonAsync(exec, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.UnsupportedContainment, capture.Code);
    }
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

    [Fact]
    public async Task W365CaptureAndPipeValidateIdentityBeforeServiceWork()
    {
        const string exec = """
            {"version":"1.1.0-alpha","phase":"exec",
             "sandboxId":"w365:invalid",
             "process":{"commandLine":"cmd.exe /c echo must-not-run"}}
            """;
        var options = new Dev.JsonOptions { Experimental = true };
        var captured = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                exec, options, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedId, captured.Code);
        var piped = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJsonAsync(
                exec, options, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedId, piped.Code);
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

    [Theory]
    [InlineData("""{"version":"1.0.0","containment":"wslc","process":{"commandLine":"cat"}}""", null, true)]
    [InlineData("""{"version":"1.0.0","containment":"process","process":{"commandLine":"cat"}}""", null, false)]
    [InlineData("""{"version":"1.0.0","phase":"exec","sandboxId":"wslc:a","process":{"commandLine":"cat"}}""", "exec", true)]
    [InlineData("""{"version":"1.0.0","phase":"exec","sandboxId":"iso:a","process":{"commandLine":"cat"}}""", "exec", false)]
    public void OnlyWslcRequestsAreRecognizedAsWslc(string json, string? phase, bool expected)
    {
        var (request, _) = Dev.DevJsonRequest.Prepare(
            json, nameof(OnlyWslcRequestsAreRecognizedAsWslc), phase);
        Assert.Equal(expected, Dev.DevJsonRequest.TargetsWslc(request));
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
