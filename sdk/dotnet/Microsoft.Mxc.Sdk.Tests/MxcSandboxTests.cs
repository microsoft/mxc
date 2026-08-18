// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcSandboxTests
{
    [Fact]
    public void NativeVersion_IsNotEmpty()
    {
        // Exercises the native load path + mxc_version() end-to-end.
        Assert.False(string.IsNullOrEmpty(MxcSandbox.NativeVersion));
    }

    [Fact]
    public void Run_MalformedPolicy_ThrowsMalformedRequest()
    {
        // A version-less policy is rejected by the native parser before any
        // sandbox is spawned, so this runs on any host (no host-prep needed).
        var policy = new SandboxPolicy { Version = string.Empty };

        var ex = Assert.Throws<MxcException>(() => MxcSandbox.Run(policy, "echo hi"));
        Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
        Assert.False(string.IsNullOrEmpty(ex.Message));
    }

    [Fact]
    public void Run_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(null!, "echo hi"));
    }

    [Fact]
    public void Run_NullCommand_Throws()
    {
        var policy = new SandboxPolicy { Version = "0.7.0-alpha" };
        Assert.Throws<ArgumentNullException>(() => MxcSandbox.Run(policy, null!));
    }

    [Fact]
    public void SandboxPolicy_SerializesToCamelCaseJson()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.7.0-alpha",
            TimeoutMs = 5000,
            Filesystem = new FilesystemPolicy { ReadwritePaths = { "/tmp" } },
            Ui = new UiPolicy { AllowWindows = true, Clipboard = ClipboardPolicy.Read },
            CaptureDenials = new CaptureDenialsPolicy
            {
                Mode = CaptureDenialsMode.Allow,
                OutputPath = @"C:\logs\denials.json",
                RetainEtl = true,
            },
        };

        var json = MxcSandbox.SerializePolicy(policy);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("0.7.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal(5000, root.GetProperty("timeoutMs").GetInt32());
        Assert.Equal("/tmp", root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());
        Assert.Equal("read", root.GetProperty("ui").GetProperty("clipboard").GetString());
        Assert.True(root.GetProperty("ui").GetProperty("allowWindows").GetBoolean());
        var capture = root.GetProperty("captureDenials");
        Assert.Equal("allow", capture.GetProperty("mode").GetString());
        Assert.Equal(@"C:\logs\denials.json", capture.GetProperty("outputPath").GetString());
        Assert.True(capture.GetProperty("retainEtl").GetBoolean());
    }

    [Fact]
    public void CaptureDenialsPolicy_DefaultsToBlockAndOmitsOutputPath()
    {
        var policy = new SandboxPolicy
        {
            Version = "0.8.0-alpha",
            CaptureDenials = new CaptureDenialsPolicy(),
        };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));
        var capture = doc.RootElement.GetProperty("captureDenials");

        Assert.Equal("block", capture.GetProperty("mode").GetString());
        Assert.False(capture.GetProperty("retainEtl").GetBoolean());
        Assert.False(capture.TryGetProperty("outputPath", out _));
    }

    [Fact]
    public void SandboxPolicy_OmitsCaptureDenialsWhenNotConfigured()
    {
        var policy = new SandboxPolicy { Version = "0.8.0-alpha" };
        using var doc = JsonDocument.Parse(MxcSandbox.SerializePolicy(policy));

        Assert.False(doc.RootElement.TryGetProperty("captureDenials", out _));
    }

    [Fact]
    public void CaptureDenialsOutput_DeserializesRetainedEtlPath()
    {
        const string json = """
            {
              "type": "captureDenials",
              "outputPath": "denials.json",
              "exitCode": 0,
              "totalDenials": 1,
              "deniedResourcesTruncated": false,
              "etlPath": "capture.etl"
            }
            """;

        var output = JsonSerializer.Deserialize<CaptureDenialsOutput>(json);

        Assert.NotNull(output);
        Assert.Equal("capture.etl", output.EtlPath);
    }

    [Fact]
    public void SandboxOutputMetadata_DeserializesCaptureFailure()
    {
        const string json = """
            {
              "captureDenialsError": {
                "message": "decode failed",
                "etlPath": "capture.etl"
              }
            }
            """;

        var metadata = JsonSerializer.Deserialize<SandboxOutputMetadata>(json);

        var error = metadata?.CaptureDenialsError;
        Assert.NotNull(error);
        Assert.Equal("decode failed", error.Message);
        Assert.Equal("capture.etl", error.EtlPath);
    }
}
