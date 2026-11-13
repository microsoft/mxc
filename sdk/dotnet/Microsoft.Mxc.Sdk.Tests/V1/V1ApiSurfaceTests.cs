// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.V1.Policy;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
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
        var devTypes = new[]
        {
            typeof(Dev.JsonOptions),
            typeof(Dev.PtyJsonOptions),
            typeof(Dev.PolicyPreparationOptions),
            typeof(Dev.PreparedPolicyRequest),
            typeof(Dev.PolicyChange),
            typeof(Dev.PolicyChangeOperation),
            typeof(Dev.MxcContainer),
            typeof(Dev.MxcLifecycle),
            typeof(Dev.PolicyFailures),
            typeof(Dev.PolicyFailureResult),
            typeof(Dev.PolicyFailureDetail),
            typeof(Dev.PolicyFailureNativeCodes),
            typeof(Dev.PolicyFailureOutcomes),
            typeof(Dev.PolicyFailureClasses),
            typeof(Dev.PolicyFailureReasons),
            typeof(Dev.PolicyFailureActions),
            typeof(Dev.PolicyFailureResourceKinds),
            typeof(Dev.PolicyFailureValueKinds),
            typeof(Dev.PolicyFailureAccessValues),
            typeof(Dev.PolicyFailureFlags),
            typeof(Dev.PolicyFailureVersions),
        };
        Assert.All(
            exportedTypes,
            type => Assert.Equal(
                type == typeof(Filesystem) || type == typeof(FilesystemPolicyResult)
                    ? "Microsoft.Mxc.Sdk.V1.Policy"
                    : devTypes.Contains(type)
                        ? "Microsoft.Mxc.Sdk.V1.Dev"
                    : "Microsoft.Mxc.Sdk.V1",
                type.Namespace));
        Assert.All(devTypes, type => Assert.Contains(type, exportedTypes));

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

    [Fact]
    public void DevPreparationIsSeparateFromCreationOptionsAndKeepsCancellationLast()
    {
        Assert.Equal(new[] { "Experimental" },
            typeof(Dev.JsonOptions).GetProperties().Select(property => property.Name));
        Assert.Equal(new[] { "Experimental" },
            typeof(Dev.PolicyPreparationOptions).GetProperties().Select(property => property.Name));
        Assert.All(new[]
        {
            typeof(Dev.JsonOptions), typeof(Dev.PolicyPreparationOptions),
            typeof(Dev.PolicyChange), typeof(Dev.PreparedPolicyRequest),
        }, type => Assert.True(type.IsSealed));
        Assert.Equal(typeof(System.Text.Json.JsonElement),
            typeof(Dev.PolicyChange).GetProperty(nameof(Dev.PolicyChange.Before))!.PropertyType);
        Assert.Equal(typeof(System.Text.Json.JsonElement),
            typeof(Dev.PolicyChange).GetProperty(nameof(Dev.PolicyChange.After))!.PropertyType);

        var sync = typeof(Dev.MxcContainer).GetMethod(nameof(Dev.MxcContainer.PreparePolicyJson))!;
        Assert.Equal(typeof(Dev.PreparedPolicyRequest), sync.ReturnType);
        Assert.Equal(new[] { typeof(string), typeof(Dev.PolicyFailures), typeof(Dev.PolicyPreparationOptions) },
            sync.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.True(sync.GetParameters()[^1].IsOptional);
        var async = typeof(Dev.MxcContainer).GetMethod(nameof(Dev.MxcContainer.PreparePolicyJsonAsync))!;
        Assert.Equal(typeof(Task<Dev.PreparedPolicyRequest>), async.ReturnType);
        Assert.Equal(new[]
        {
            typeof(string), typeof(Dev.PolicyFailures), typeof(Dev.PolicyPreparationOptions), typeof(CancellationToken),
        }, async.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.True(async.GetParameters()[^1].IsOptional);
    }
}
