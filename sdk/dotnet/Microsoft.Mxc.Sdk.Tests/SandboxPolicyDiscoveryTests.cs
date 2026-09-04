// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public class SandboxPolicyDiscoveryTests
{
    [Fact]
    public void GetAvailableToolsPolicy_DeduplicatesAndSkipsMissingDirectories()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var environment = new Dictionary<string, string?>
            {
                ["PATH"] = string.Join(
                    Path.PathSeparator,
                    directory,
                    directory,
                    Path.Combine(directory, "missing")),
                ["DOTNET_ROOT"] = directory,
            };

            var result = SandboxPolicyDiscovery.GetAvailableToolsPolicy(environment);

            Assert.Single(result.ReadonlyPaths);
            Assert.Equal(Path.GetFullPath(directory), result.ReadonlyPaths[0]);
            Assert.Empty(result.ReadwritePaths);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void GetAvailableToolsPolicy_ExcludesSystemCriticalDirectories()
    {
        var criticalPath = OperatingSystem.IsWindows()
            ? Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows"
            : "/usr/bin";

        var result = SandboxPolicyDiscovery.GetAvailableToolsPolicy(
            new Dictionary<string, string?> { ["PATH"] = criticalPath });

        Assert.DoesNotContain(
            result.ReadonlyPaths,
            path => string.Equals(
                Path.TrimEndingDirectorySeparator(path),
                Path.TrimEndingDirectorySeparator(criticalPath),
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal));
    }

    [Fact]
    public void GetAvailableToolsPolicy_NeverGrantsDriveRootForPowerShell()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "PowerShell policy is Windows-specific");

        var directory = CreateTemporaryDirectory();
        try
        {
            File.WriteAllText(Path.Combine(directory, "pwsh.exe"), string.Empty);
            var environment = new Dictionary<string, string?>
            {
                ["PATH"] = directory,
                ["USERPROFILE"] = directory,
            };

            var result = SandboxPolicyDiscovery.GetAvailableToolsPolicy(environment);

            Assert.Contains(Path.GetFullPath(directory), result.ReadonlyPaths);
            Assert.DoesNotContain(
                result.ReadonlyPaths,
                path => Path.GetPathRoot(path) == Path.TrimEndingDirectorySeparator(path));
            Assert.Equal(
                Path.Combine(
                    directory,
                    "AppData",
                    "Roaming",
                    "Microsoft",
                    "Windows",
                    "PowerShell",
                    "PSReadLine"),
                Assert.Single(result.ReadwritePaths));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void GetUserProfilePolicy_DiscoversExistingUserToolDirectories()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            string expected;
            IReadOnlyDictionary<string, string?> environment;
            if (OperatingSystem.IsWindows())
            {
                expected = Path.Combine(directory, "Programs", "Tool");
                Directory.CreateDirectory(expected);
                environment = new Dictionary<string, string?>
                {
                    ["LOCALAPPDATA"] = directory,
                };
            }
            else
            {
                expected = Path.Combine(directory, ".local", "bin");
                Directory.CreateDirectory(expected);
                environment = new Dictionary<string, string?>
                {
                    ["HOME"] = directory,
                };
            }

            var result = SandboxPolicyDiscovery.GetUserProfilePolicy(environment);

            Assert.Contains(expected, result.ReadonlyPaths);
            Assert.Empty(result.ReadwritePaths);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void GetTemporaryFilesPolicy_UsesExistingConfiguredDirectory()
    {
        var directory = CreateTemporaryDirectory();
        try
        {
            var variable = OperatingSystem.IsWindows() ? "TEMP" : "TMPDIR";
            var result = SandboxPolicyDiscovery.GetTemporaryFilesPolicy(
                new Dictionary<string, string?> { [variable] = directory });

            Assert.Empty(result.ReadonlyPaths);
            Assert.Equal(new[] { directory }, result.ReadwritePaths);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void GetTemporaryFilesPolicy_SkipsMissingConfiguredDirectory()
    {
        var variable = OperatingSystem.IsWindows() ? "TEMP" : "TMPDIR";
        var missing = Path.Combine(
            Path.GetTempPath(),
            $"mxc-missing-{Guid.NewGuid():N}");

        var result = SandboxPolicyDiscovery.GetTemporaryFilesPolicy(
            new Dictionary<string, string?> { [variable] = missing });

        Assert.Empty(result.ReadonlyPaths);
        Assert.Empty(result.ReadwritePaths);
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mxc-policy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
