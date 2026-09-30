// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class PolicyEnforcementTests
{
    [Theory]
    [InlineData("""{"policyEnforcement":null}""")]
    [InlineData("""{"policyEnforcement":false}""")]
    [InlineData("""{"policyEnforcement":[]}""")]
    public void PresentInvalidSectionCannotBecomeLegacyOmission(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ProcessContainerContainment>(json));
        string polymorphic = """{"type":"processContainer",""" + json[1..];
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SandboxContainment>(polymorphic));
    }

    [Fact]
    public void ReportSerializationOmitsAbsentOptionalStringsAndPreservesWideValues()
    {
        const string json = """
            {"reportVersion":1,"requestedMode":"pass-through","modeApplied":true,
            "availability":"available","termination":"nativeFailure","environmentCreated":false,
            "originalPolicyHash":"same","effectivePolicyHash":"same","attempts":[
            {"attempt":1,"hresult":"0x80004005","result":{"version":1,"outcome":{"code":999},"details":[{
            "failureClass":{"code":999},"failureReason":{"code":999},"requiredAction":{"code":999},
            "resourceKind":{"code":0},"valueKind":{"code":0},"requestedValue":"18446744073709551615",
            "requiredValue":"9007199254740993","flags":0,"resourceOffsetChars":0,
            "resourceCharsWritten":0,"resourceCharsRequired":0}],
            "detailsCapacity":64,"detailsCount":1,"resourceCapacityChars":32768,
            "resourceCharsWritten":0,"resourceCharsRequired":0}}]}
            """;
        var report = JsonSerializer.Deserialize<PolicyEnforcementReport>(json)!;
        using var serialized = JsonDocument.Parse(JsonSerializer.Serialize(report));
        Assert.Equal(1u, report.ReportVersion);
        Assert.Equal(1u, serialized.RootElement.GetProperty("reportVersion").GetUInt32());
        Assert.False(serialized.RootElement.TryGetProperty("message", out _));
        var result = serialized.RootElement.GetProperty("attempts")[0].GetProperty("result");
        Assert.False(result.GetProperty("outcome").TryGetProperty("name", out _));
        var detail = result.GetProperty("details")[0];
        Assert.False(detail.TryGetProperty("resource", out _));
        foreach (string field in new[] { "failureClass", "failureReason", "requiredAction", "resourceKind", "valueKind" })
        {
            Assert.False(detail.GetProperty(field).TryGetProperty("name", out _));
        }
        Assert.Equal("18446744073709551615", detail.GetProperty("requestedValue").GetString());
        Assert.Equal("9007199254740993", detail.GetProperty("requiredValue").GetString());
    }

    [Theory]
    [InlineData("""{"mode":"pass-through","maxAttemps":1}""")]
    [InlineData("""{"mode":"pass-through","typo":true}""")]
    [InlineData("""{"mode":null}""")]
    public void InvalidControlsAreRejectedBeforeTheyCanBeDiscarded(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PolicyEnforcementOptions>(json));
    }

    [Fact]
    public void DefaultSerializationPreservesNestedControlOmission()
    {
        Assert.Equal("{}", JsonSerializer.Serialize(new PolicyEnforcementOptions()));
        Assert.Equal(
            """{"mode":"pass-through"}""",
            JsonSerializer.Serialize(new PolicyEnforcementOptions { Mode = PolicyEnforcementMode.PassThrough }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicRequestSerializationPreservesPolicyControlPresence(bool explicitControls)
    {
        var containment = new ProcessContainerContainment
        {
            PolicyEnforcement = explicitControls ? new PolicyEnforcementOptions() : null,
        };
        using var json = JsonDocument.Parse(JsonSerializer.Serialize<SandboxContainment>(containment));
        Assert.Equal(explicitControls, json.RootElement.TryGetProperty("policyEnforcement", out var controls));
        if (explicitControls)
        {
            Assert.Equal(JsonValueKind.Object, controls.ValueKind);
        }
        var roundTrip = JsonSerializer.Deserialize<SandboxContainment>(json.RootElement);
        Assert.Equal(explicitControls,
            Assert.IsType<ProcessContainerContainment>(roundTrip).PolicyEnforcement is not null);
    }

    [Fact]
    public void AbsentReportPreservesLegacyMetadataJson()
    {
        Assert.Equal(
            """{"captureDenials":null,"captureDenialsError":null}""",
            JsonSerializer.Serialize(new SandboxOutputMetadata()));
    }

    [Fact]
    public void AbsentReportsDoNotAddExceptionJsonProperties()
    {
        var exception = new MxcException(ErrorCode.BackendError, "legacy failure");
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(exception));
        Assert.False(json.RootElement.TryGetProperty(nameof(MxcException.PolicyEnforcement), out _));
    }

    [Theory]
    [InlineData(PolicyEnforcementMode.PassThrough, "pass-through")]
    public void RequestPreservesPassThroughWithoutExperimental(PolicyEnforcementMode mode, string wireMode)
    {
        var request = new SandboxRequest(new SandboxPolicy { Version = "0.10.0-alpha" }, "unused")
        {
            Containment = new ProcessContainerContainment
            {
                PolicyEnforcement = new PolicyEnforcementOptions { Mode = mode },
            },
        };
        using var json = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        var settings = json.RootElement.GetProperty("containment").GetProperty("policyEnforcement");
        Assert.Equal(wireMode, settings.GetProperty("mode").GetString());
        Assert.False(settings.TryGetProperty("maxAttempts", out _));
        Assert.False(json.RootElement.TryGetProperty("experimental", out _));
        Assert.Equal(mode, JsonSerializer.Deserialize<PolicyEnforcementOptions>(settings)!.Mode);
    }

    [Fact]
    public void EmptyOptionsRemainPresentWhileNullOptionsStayAbsent()
    {
        var containment = new ProcessContainerContainment();
        var request = new SandboxRequest(new SandboxPolicy { Version = "0.10.0-alpha" }, "unused")
        {
            Containment = containment,
        };
        using var absent = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        Assert.False(absent.RootElement.GetProperty("containment").TryGetProperty("policyEnforcement", out _));
        containment.PolicyEnforcement = new PolicyEnforcementOptions();
        using var present = JsonDocument.Parse(MxcSandbox.SerializeRequest(request));
        Assert.Equal("{}", present.RootElement.GetProperty("containment").GetProperty("policyEnforcement").GetRawText());
        Assert.False(present.RootElement.TryGetProperty("experimental", out _));
    }

    [Theory]
    [InlineData("""{"mode":"mutate"}""")]
    [InlineData("""{"maxAttempts":1}""")]
    [InlineData("""{"mode":"pass-through","maxAttempts":64}""")]
    public void MutationInputsAreRejectedByTheSdkModel(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PolicyEnforcementOptions>(json));
    }

    [Fact]
    public void UnsupportedModeCannotBeSerializedIntoANativeRequest()
    {
        var request = new SandboxRequest(new SandboxPolicy { Version = "0.10.0-alpha" }, "unused")
        {
            Containment = new ProcessContainerContainment
            {
                PolicyEnforcement = new PolicyEnforcementOptions { Mode = (PolicyEnforcementMode)1 },
            },
        };
        Assert.Throws<JsonException>(() => MxcSandbox.SerializeRequest(request));
    }

    [Fact]
    public unsafe void NativeErrorRetainsPolicyDetailsAfterNativeStorageIsFreed()
    {
        const string json = """
            {"policyEnforcement":{"reportVersion":1,"requestedMode":"mutate","modeApplied":true,
            "availability":"available","termination":"unrepairable","environmentCreated":false,
            "originalPolicyHash":"before","effectivePolicyHash":"after","attempts":[
            {"attempt":1,"hresult":"0x800704EC","result":{"version":1,"outcome":{"code":3},"details":[{
            "failureClass":{"code":999},"requestedValue":"18446744073709551615",
            "requiredValue":"9007199254740993"},
            {"failureClass":{"code":2},"resource":"C:\\work","requestedValue":"2","requiredValue":"0"}],
            "detailsCapacity":64,"detailsCount":2}}]}}
            """;
        var text = Marshal.StringToCoTaskMemUTF8(json);
        MxcException exception;
        try
        {
            exception = NativeError.ToException((int)ErrorCode.PolicyValidation,
                new MxcErrorDetail { details_json_utf8 = (byte*)text }, "blocked");
        }
        finally
        {
            Marshal.FreeCoTaskMem(text);
        }
        var report = exception.PolicyEnforcement;
        Assert.NotNull(report);
        Assert.Equal("unrepairable", report.Termination);
        Assert.Equal(2, report.Attempts[0].Result.Details.Count);
        Assert.Equal(ulong.MaxValue, report.Attempts[0].Result.Details[0].RequestedValue);
        Assert.Equal(9007199254740993UL, report.Attempts[0].Result.Details[0].RequiredValue);
        Assert.Equal(999u, report.Attempts[0].Result.Details[0].FailureClass.Code);
        Assert.Equal(@"C:\work", report.Attempts[0].Result.Details[1].Resource);
        using var serialized = JsonDocument.Parse(JsonSerializer.Serialize(exception));
        Assert.True(serialized.RootElement.TryGetProperty(nameof(MxcException.Details), out _));
        Assert.True(serialized.RootElement.TryGetProperty(nameof(MxcException.PolicyEnforcement), out _));
    }

    [Fact]
    public void CaptureAndCreationMetadataCanCoexist()
    {
        var metadata = JsonSerializer.Deserialize<SandboxOutputMetadata>(
            """{"policyEnforcement":{"reportVersion":1,"availability":"unavailable","modeApplied":false,"attempts":[]},"captureDenials":{"type":"captureDenials","outputPath":"denials.json"}}""");
        Assert.NotNull(metadata!.PolicyEnforcement);
        Assert.False(metadata.PolicyEnforcement.ModeApplied);
        Assert.Equal("denials.json", metadata.CaptureDenials!.OutputPath);
        var roundTrip = JsonSerializer.Deserialize<SandboxOutputMetadata>(JsonSerializer.Serialize(metadata));
        Assert.NotNull(roundTrip!.PolicyEnforcement);
    }

    [Fact]
    public void UnsupportedReportVersionIsRejected()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<PolicyEnforcementReport>("""{"reportVersion":99}"""));
    }
}
