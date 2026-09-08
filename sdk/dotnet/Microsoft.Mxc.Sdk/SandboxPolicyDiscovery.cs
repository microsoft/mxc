// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A composable filesystem-policy fragment discovered from the host.
/// </summary>
public sealed class FilesystemPolicyResult
{
    /// <summary>Paths that should be granted read-only access.</summary>
    public IReadOnlyList<string> ReadonlyPaths { get; init; } = Array.Empty<string>();

    /// <summary>Paths that should be granted read-write access.</summary>
    public IReadOnlyList<string> ReadwritePaths { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Discovers host paths commonly needed by sandboxed developer tools.
/// </summary>
public static class SandboxPolicyDiscovery
{
    private static readonly (string Name, bool IsPathList)[] KnownEnvironmentVariables =
    {
        ("PYTHONPATH", true),
        ("PYTHONHOME", false),
        ("VCINSTALLDIR", false),
        ("VSINSTALLDIR", false),
        ("PSModulePath", true),
        ("VCPKG_ROOT", false),
        ("GOPATH", false),
        ("GOROOT", false),
        ("CARGO_HOME", false),
        ("RUSTUP_HOME", false),
        ("JAVA_HOME", false),
        ("NVM_HOME", false),
        ("NVM_SYMLINK", false),
        ("NODE_PATH", true),
        ("DOTNET_ROOT", false),
        ("CONDA_PREFIX", false),
        ("LD_LIBRARY_PATH", true),
        ("VIRTUAL_ENV", false),
        ("PYENV_ROOT", false),
    };

    /// <summary>
    /// Discover existing tool and SDK directories from PATH and well-known
    /// environment variables. System-critical paths are excluded.
    /// </summary>
    /// <param name="environment">
    /// Environment to inspect, or <see langword="null"/> to snapshot the
    /// current process environment.
    /// </param>
    public static FilesystemPolicyResult GetAvailableToolsPolicy(
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        var env = environment ?? SnapshotEnvironment();
        var pathDirectories = SplitPathList(GetEnvironmentValue(env, "PATH")
            ?? GetEnvironmentValue(env, "Path")
            ?? string.Empty);
        var collected = new List<string>(pathDirectories);

        foreach (var (name, isPathList) in KnownEnvironmentVariables)
        {
            var value = GetEnvironmentValue(env, name);
            if (value is null)
            {
                continue;
            }

            if (isPathList)
            {
                collected.AddRange(SplitPathList(value));
            }
            else if (!string.IsNullOrWhiteSpace(value))
            {
                collected.Add(value.Trim());
            }
        }

        var readonlyPaths = DeduplicatePaths(collected)
            .Where(Directory.Exists)
            .Where(path => !IsSystemCriticalPath(path))
            .ToList();
        var readwritePaths = new List<string>();

        AddPowerShellPolicy(pathDirectories, env, readwritePaths);

        return new FilesystemPolicyResult
        {
            ReadonlyPaths = DeduplicatePaths(readonlyPaths),
            ReadwritePaths = DeduplicatePaths(readwritePaths),
        };
    }

    /// <summary>
    /// Discover standard per-user application directories that should be
    /// granted read-only access.
    /// </summary>
    public static FilesystemPolicyResult GetUserProfilePolicy(
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        var env = environment ?? SnapshotEnvironment();
        var readonlyPaths = new List<string>();
        if (OperatingSystem.IsWindows())
        {
            var localAppData = GetEnvironmentValue(env, "LOCALAPPDATA");
            if (!string.IsNullOrEmpty(localAppData) && Directory.Exists(localAppData))
            {
                var programs = Path.Combine(localAppData, "Programs");
                try
                {
                    readonlyPaths.AddRange(Directory.EnumerateDirectories(programs));
                }
                catch (DirectoryNotFoundException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (IOException)
                {
                }
            }
        }
        else
        {
            var home = GetEnvironmentValue(env, "HOME");
            if (!string.IsNullOrEmpty(home))
            {
                foreach (var path in new[]
                {
                    Path.Combine(home, ".local", "bin"),
                    Path.Combine(home, ".local", "lib"),
                })
                {
                    if (Directory.Exists(path))
                    {
                        readonlyPaths.Add(path);
                    }
                }
            }
        }

        return new FilesystemPolicyResult
        {
            ReadonlyPaths = readonlyPaths,
        };
    }

    /// <summary>
    /// Discover the host temporary directory as a read-write policy fragment.
    /// </summary>
    /// <param name="environment">
    /// Environment to inspect, or <see langword="null"/> to snapshot the
    /// current process environment.
    /// </param>
    public static FilesystemPolicyResult GetTemporaryFilesPolicy(
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        var env = environment ?? SnapshotEnvironment();
        var root = OperatingSystem.IsWindows()
            ? GetEnvironmentValue(env, "TEMP") ?? GetEnvironmentValue(env, "TMP")
            : GetEnvironmentValue(env, "TMPDIR") ?? "/tmp";

        return string.IsNullOrEmpty(root) || !Directory.Exists(root)
            ? new FilesystemPolicyResult()
            : new FilesystemPolicyResult
            {
                ReadwritePaths = new[] { root },
            };
    }

    private static IReadOnlyDictionary<string, string?> SnapshotEnvironment()
    {
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        var result = new Dictionary<string, string?>(comparer);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key)
            {
                result[key] = entry.Value as string;
            }
        }
        return result;
    }

    private static string? GetEnvironmentValue(
        IReadOnlyDictionary<string, string?> environment,
        string name)
    {
        if (environment.TryGetValue(name, out var value))
        {
            return value;
        }

        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        foreach (var pair in environment)
        {
            if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }
        return null;
    }

    private static IEnumerable<string> SplitPathList(string value) =>
        value.Split(
            Path.PathSeparator,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static IReadOnlyList<string> DeduplicatePaths(IEnumerable<string> paths)
    {
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        var seen = new HashSet<string>(comparer);
        var result = new List<string>();

        foreach (var path in paths)
        {
            string resolved;
            try
            {
                resolved = Path.GetFullPath(path);
            }
            catch (Exception exception) when (
                exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (seen.Add(resolved))
            {
                result.Add(resolved);
            }
        }
        return result;
    }

    private static bool IsSystemCriticalPath(string path)
    {
        var normalized = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows())
        {
            var windowsDirectory = Environment.GetEnvironmentVariable("WINDIR")
                ?? Environment.GetEnvironmentVariable("windir")
                ?? @"C:\Windows";
            var normalizedWindows = Path.GetFullPath(windowsDirectory);
            return IsSameOrDescendant(normalized, normalizedWindows, StringComparison.OrdinalIgnoreCase);
        }

        return new[]
        {
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/boot",
            "/proc",
            "/sys",
            "/dev",
        }.Any(critical => IsSameOrDescendant(normalized, critical, StringComparison.Ordinal));
    }

    private static bool IsSameOrDescendant(
        string candidate,
        string parent,
        StringComparison comparison)
    {
        var normalizedParent = Path.TrimEndingDirectorySeparator(parent);
        return string.Equals(
                Path.TrimEndingDirectorySeparator(candidate),
                normalizedParent,
                comparison)
            || candidate.StartsWith(
                normalizedParent + Path.DirectorySeparatorChar,
                comparison);
    }

    private static void AddPowerShellPolicy(
        IEnumerable<string> pathDirectories,
        IReadOnlyDictionary<string, string?> environment,
        ICollection<string> readwritePaths)
    {
        if (!OperatingSystem.IsWindows()
            || !pathDirectories.Any(path => File.Exists(Path.Combine(path, "pwsh.exe"))))
        {
            return;
        }

        var userProfile = GetEnvironmentValue(environment, "USERPROFILE");
        if (!string.IsNullOrEmpty(userProfile))
        {
            readwritePaths.Add(Path.Combine(
                userProfile,
                "AppData",
                "Roaming",
                "Microsoft",
                "Windows",
                "PowerShell",
                "PSReadLine"));
        }
    }
}
