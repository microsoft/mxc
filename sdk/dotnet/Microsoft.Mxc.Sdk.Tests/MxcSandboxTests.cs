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
        };

        var options = new JsonSerializerOptions
        {
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        };
        var json = JsonSerializer.Serialize(policy, options);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("0.7.0-alpha", root.GetProperty("version").GetString());
        Assert.Equal(5000, root.GetProperty("timeoutMs").GetInt32());
        Assert.Equal("/tmp", root.GetProperty("filesystem").GetProperty("readwritePaths")[0].GetString());
        Assert.Equal("read", root.GetProperty("ui").GetProperty("clipboard").GetString());
        Assert.True(root.GetProperty("ui").GetProperty("allowWindows").GetBoolean());
    }
}
