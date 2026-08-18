// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk.Native;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

public sealed class NativeLibraryResolverTests : IDisposable
{
    private readonly string _tempRoot;

    public NativeLibraryResolverTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"mxc-native-resolver-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempRoot, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup only.
        }
    }

    [Fact]
    public void CandidatePaths_PrioritizeExplicitOverrideThenPackagedLocations()
    {
        var baseDir = Directory.CreateDirectory(Path.Combine(_tempRoot, "app")).FullName;
        var overrideDir = Directory.CreateDirectory(Path.Combine(_tempRoot, "override")).FullName;

        var paths = NativeLibraryResolver.CandidatePathsForTesting(baseDir, "win-x64", overrideDir);

        Assert.Equal(Path.Combine(overrideDir, NativeFileName()), paths[0]);
        Assert.Equal(Path.Combine(baseDir, NativeFileName()), paths[1]);
        Assert.Equal(Path.Combine(baseDir, "runtimes", "win-x64", "native", NativeFileName()), paths[2]);
    }

    [Fact]
    public void CandidatePaths_WalkOnlyTheNearestRepoRoot()
    {
        File.WriteAllText(Path.Combine(_tempRoot, ".git"), "gitdir: outer");
        var repoRoot = Directory.CreateDirectory(Path.Combine(_tempRoot, "repo")).FullName;
        File.WriteAllText(Path.Combine(repoRoot, ".git"), "gitdir: test");

        var nestedBaseDir = Directory.CreateDirectory(Path.Combine(repoRoot, "artifacts", "bin", "Debug", "net8.0")).FullName;

        var paths = NativeLibraryResolver.CandidatePathsForTesting(nestedBaseDir, "win-x64");

        Assert.Contains(Path.Combine(repoRoot, "src", "target", "release", NativeFileName()), paths);
        Assert.DoesNotContain(Path.Combine(_tempRoot, "src", "target", "release", NativeFileName()), paths);
#if DEBUG
        Assert.Contains(Path.Combine(repoRoot, "src", "target", "debug", NativeFileName()), paths);
#else
        Assert.DoesNotContain(Path.Combine(repoRoot, "src", "target", "debug", NativeFileName()), paths);
#endif
    }

    [Fact]
    public void CandidatePaths_RecognizeTheMxCWorkspaceManifestUnderSrc()
    {
        var repoRoot = Directory.CreateDirectory(Path.Combine(_tempRoot, "src-manifest-repo")).FullName;
        Directory.CreateDirectory(Path.Combine(repoRoot, "src"));
        File.WriteAllText(Path.Combine(repoRoot, "src", "Cargo.toml"), "[workspace]");
        var nestedBaseDir = Directory.CreateDirectory(Path.Combine(repoRoot, "artifacts", "bin")).FullName;

        var paths = NativeLibraryResolver.CandidatePathsForTesting(nestedBaseDir, "win-x64");

        Assert.Contains(Path.Combine(repoRoot, "src", "target", "release", NativeFileName()), paths);
    }

    [Fact]
    public void CandidatePaths_StopBeforeAncestorsBeyondTheBound()
    {
        var repoRoot = Directory.CreateDirectory(Path.Combine(_tempRoot, "repo-limit")).FullName;
        File.WriteAllText(Path.Combine(repoRoot, ".git"), "gitdir: test");

        var deepBaseDir = repoRoot;
        for (var i = 0; i < 10; i++)
        {
            deepBaseDir = Directory.CreateDirectory(Path.Combine(deepBaseDir, $"level{i}")).FullName;
        }

        var paths = NativeLibraryResolver.CandidatePathsForTesting(deepBaseDir, "win-x64");

        Assert.DoesNotContain(
            Path.Combine(repoRoot, "src", "target", "release", NativeFileName()),
            paths);
    }

    private static string NativeFileName()
    {
        if (OperatingSystem.IsWindows())
        {
            return "mxc_ffi.dll";
        }

        if (OperatingSystem.IsMacOS())
        {
            return "libmxc_ffi.dylib";
        }

        return "libmxc_ffi.so";
    }
}
