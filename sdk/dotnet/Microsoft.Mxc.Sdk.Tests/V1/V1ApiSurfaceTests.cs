// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.V1.Policy;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public sealed class V1ApiSurfaceTests
{
    [Fact]
    public void RequestAndRuntimeTypesUseTheirV1Namespaces()
    {
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(ContainerRequest).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(MxcContainer).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(MxcProcess).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(MxcPlatform).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1.Policy", typeof(Filesystem).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1.Policy", typeof(FilesystemPolicyResult).Namespace);
    }

    [Fact]
    public void PublicSurfaceUsesContainerRequestWithoutAggregatePolicyTypes()
    {
        var exportedTypes = typeof(ContainerRequest).Assembly.GetExportedTypes();
        Assert.All(
            exportedTypes,
            type => Assert.Equal(
                type == typeof(Filesystem) || type == typeof(FilesystemPolicyResult)
                    ? "Microsoft.Mxc.Sdk.V1.Policy"
                    : "Microsoft.Mxc.Sdk.V1",
                type.Namespace));

        Assert.Contains(typeof(ContainerRequest), exportedTypes);
        Assert.Contains(typeof(MxcContainer), exportedTypes);
        Assert.Contains(typeof(MxcProcess), exportedTypes);
        Assert.DoesNotContain(
            exportedTypes,
            type => type.Name is "ContainerPolicy" or "SandboxPolicy");

        Assert.DoesNotContain(
            exportedTypes,
            type => (type.Namespace is "Microsoft.Mxc.Sdk" or "Microsoft.Mxc.Sdk.V1")
                && type.Name.Contains("Sandbox", StringComparison.Ordinal)
                && !type.Name.Contains("WindowsSandbox", StringComparison.Ordinal));
    }

    [Fact]
    public void StableOperationOptionsDoNotExposeExperimentalAuthorization()
    {
        var optionTypes = new[]
        {
            typeof(RunOptions),
            typeof(SpawnOptions),
            typeof(SpawnWithPtyOptions),
            typeof(ProvisionOptions),
            typeof(StartOptions),
            typeof(StopOptions),
            typeof(DeprovisionOptions),
            typeof(SpawnInContainerOptions),
            typeof(RunInContainerOptions),
            typeof(SpawnInContainerWithPtyOptions),
        };

        Assert.All(optionTypes, type => Assert.Null(type.GetProperty("Experimental")));
    }
}
