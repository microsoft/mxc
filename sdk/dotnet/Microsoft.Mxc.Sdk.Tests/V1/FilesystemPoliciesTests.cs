// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk.V1.Policy;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class FilesystemPoliciesTests
{
    [Fact]
    public void ToolsPolicy_DiscoveryMapCannotOverrideHostWindowsSafetyExclusion()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows safety filtering");
        var hostWindows = Environment.GetEnvironmentVariable("WINDIR")
            ?? Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
        foreach (var windir in new string?[] { null, "", @"C:\SpoofedWindows" })
        {
            var result = Filesystem.GetAvailableToolsPolicy(
                new Dictionary<string, string?> { ["PATH"] = hostWindows, ["WINDIR"] = windir });
            Assert.Empty(result.ReadonlyPaths);
        }
    }

    [Fact]
    public void ExplicitlyEmptyEnvironment_DoesNotDiscoverHostToolsOrProfile()
    {
        var environment = new Dictionary<string, string?>();
        Assert.Empty(Filesystem.GetAvailableToolsPolicy(environment).ReadonlyPaths);
        Assert.Empty(Filesystem.GetUserProfilePolicy(environment).ReadonlyPaths);
    }

    [Fact]
    public void GetAvailableToolsPolicy_RetainsDirectoriesWithAllApplicationPackagesAccess()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("ACL discovery is Windows-specific");
            return;
        }
        var directory = CreateTemporaryDirectory();
        try
        {
            var access = System.IO.FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(directory));
            access.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                new System.Security.Principal.SecurityIdentifier("S-1-15-2-1"),
                System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit
                    | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
            System.IO.FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(directory), access);
            var environment = new Dictionary<string, string?> { ["PATH"] = directory };
            Assert.Contains(directory, Filesystem.GetAvailableToolsPolicy(environment).ReadonlyPaths);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

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

            var result = Filesystem.GetAvailableToolsPolicy(environment);

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

        var result = Filesystem.GetAvailableToolsPolicy(
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

            var result = Filesystem.GetAvailableToolsPolicy(environment);

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

            var result = Filesystem.GetUserProfilePolicy(environment);

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
            var result = Filesystem.GetTemporaryFilesPolicy(
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

        var result = Filesystem.GetTemporaryFilesPolicy(
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
