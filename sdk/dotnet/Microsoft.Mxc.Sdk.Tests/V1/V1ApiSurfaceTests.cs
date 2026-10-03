// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public sealed class V1ApiSurfaceTests
{
    [Fact]
    public void RequestAndRuntimeTypesUseTheirV1Namespaces()
    {
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(ContainerRequest).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(MxcSandbox).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk.V1", typeof(MxcProcess).Namespace);
        Assert.Equal("Microsoft.Mxc.Sdk", typeof(MxcPlatform).Namespace);
    }

    [Fact]
    public void PublicSurfaceUsesContainerRequestWithoutAggregatePolicyTypes()
    {
        var exportedTypes = typeof(ContainerRequest).Assembly.GetExportedTypes();

        Assert.Contains(typeof(ContainerRequest), exportedTypes);
        Assert.Contains(typeof(MxcProcess), exportedTypes);
        Assert.DoesNotContain(
            exportedTypes,
            type => type.Name is "ContainerPolicy" or "SandboxPolicy");
    }
}
