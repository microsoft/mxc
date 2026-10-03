// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class MxcPtyProcessTests
{
    [Fact]
    public void DefaultSize_IsStandardTerminalSize()
    {
        Assert.Equal((ushort)24, MxcPtySize.Default.Rows);
        Assert.Equal((ushort)80, MxcPtySize.Default.Columns);
    }

    [Fact]
    public void SpawnWithPty_NullPolicy_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcSandbox.SpawnWithPty(null!, "echo hi"));
    }

    [Fact]
    public void SpawnWithPty_NullCommand_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => MxcSandbox.SpawnWithPty(new SandboxPolicy(), null!));
    }

    [Theory]
    [InlineData(0, 80)]
    [InlineData(24, 0)]
    [InlineData(32768, 80)]
    [InlineData(24, 32768)]
    public void SpawnWithPty_RejectsInvalidDimensionsBeforeNativeCall(
        ushort rows,
        ushort columns)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MxcSandbox.SpawnWithPty(
                new SandboxPolicy(),
                "echo hi",
                new MxcPtySize(rows, columns)));
    }

    [Fact]
    public void PolicyCommandOverload_TargetsIsolationSession()
    {
        var request = MxcSandbox.CreatePtyCompatibilityRequest(
            new SandboxPolicy(),
            "echo hi");

        Assert.IsType<IsolationSessionContainment>(request.Containment);
    }

    [Fact]
    public void ProcessContainerRequest_PreservesContainmentAndTerminalSize()
    {
        var request = new SandboxRequest(
            new SandboxPolicy(),
            "cmd.exe /c echo pty")
        {
            Containment = new ProcessContainerContainment
            {
                LeastPrivilege = true,
            },
        };

        var prepared = MxcSandbox.PreparePtySpawn(
            request,
            new MxcPtySize(42, 132));
        using var document = JsonDocument.Parse(prepared.RequestJson);
        var root = document.RootElement;

        Assert.Equal("processcontainer", root.GetProperty("containment").GetString());
        Assert.Equal(
            "cmd.exe /c echo pty",
            root.GetProperty("process").GetProperty("commandLine").GetString());
        Assert.True(
            root.GetProperty("processContainer").GetProperty("leastPrivilege").GetBoolean());
        Assert.Equal((ushort)42, prepared.Size.Rows);
        Assert.Equal((ushort)132, prepared.Size.Columns);
    }
}
