// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Runtime.InteropServices;

namespace Microsoft.Mxc.Sdk.Native;

/// <summary>
/// Resolves the native <c>mxc_ffi</c> library at runtime. When the SDK is
/// packaged as a NuGet with <c>runtimes/{rid}/native</c> assets, the default
/// loader finds it; this resolver additionally covers dev/test scenarios by
/// searching the Cargo build output (<c>src/target/{debug,release}</c>) and an
/// <c>MXC_FFI_DIR</c> override.
/// </summary>
internal static class NativeLibraryResolver
{
    private const string LibraryName = "mxc_ffi";
    private static int _initialized;

    /// <summary>
    /// Register the resolver once. Called from the static constructor of the
    /// SDK's public entry points so it runs before the first P/Invoke.
    /// </summary>
    /// <remarks>
    /// Never throws. <see cref="NativeLibrary.SetDllImportResolver"/> throws if
    /// a resolver is already registered for this assembly (for example, when a
    /// host application registers its own). Because this runs from a static
    /// constructor, letting that escape would raise
    /// <c>TypeInitializationException</c> on *every* subsequent member access
    /// and permanently poison the type — breaking the never-throw contract of
    /// members such as <c>MxcTelemetry.NeedsConsentPrompt</c> and
    /// <c>MxcTelemetry.GetPolicy</c>.
    ///
    /// Swallowing is also the semantically correct outcome: this resolver only
    /// *adds* dev/test search paths. If registration fails, the default loader
    /// (and any resolver the host registered) still resolves the library, and a
    /// genuinely missing library is already handled fail-closed at each call
    /// site.
    /// </remarks>
    internal static void Initialize()
    {
        if (Interlocked.Exchange(ref _initialized, 1) != 0)
        {
            return;
        }

        try
        {
            NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve);
        }
        catch (Exception ex)
        {
            // Deliberately not rethrown; see the remarks above. Reported once
            // (the _initialized latch above guarantees single entry) so the
            // failure is diagnosable rather than silent. The report is itself
            // best-effort: a host may have replaced or closed Console.Error,
            // and letting *that* throw would re-poison the static ctor this
            // catch exists to protect.
            try
            {
                Console.Error.WriteLine(
                    $"mxc: could not register the native library resolver ({ex.GetType().Name}: {ex.Message}). " +
                    "Falling back to the default loader.");
            }
            catch
            {
                // Nothing left to report with. Swallow.
            }
        }
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, LibraryName, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

        foreach (var candidate in CandidatePaths())
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        // Fall back to the default loader (e.g. packaged runtimes/ assets).
        return IntPtr.Zero;
    }

    private static IEnumerable<string> CandidatePaths()
    {
        var overrideDir = Environment.GetEnvironmentVariable("MXC_FFI_DIR");
        foreach (var path in CandidatePathsForTesting(
                     AppContext.BaseDirectory,
                     RuntimeInformation.RuntimeIdentifier,
                     overrideDir))
        {
            yield return path;
        }
    }

    internal static IReadOnlyList<string> CandidatePathsForTesting(
        string baseDir,
        string runtimeIdentifier,
        string? overrideDir = null)
    {
        var file = NativeFileName();
        var paths = new List<string>();
        if (!string.IsNullOrEmpty(overrideDir))
        {
            paths.Add(Path.Combine(overrideDir, file));
        }

        paths.Add(Path.Combine(baseDir, file));
        paths.Add(Path.Combine(baseDir, "runtimes", runtimeIdentifier, "native", file));

        var dir = new DirectoryInfo(baseDir);
        var depth = 0;
        while (dir is not null && depth++ < 8)
        {
            if (File.Exists(Path.Combine(dir.FullName, ".git")) ||
                File.Exists(Path.Combine(dir.FullName, "src", "Cargo.toml")))
            {
#if DEBUG
                paths.Add(Path.Combine(dir.FullName, "src", "target", "debug", file));
#endif
                paths.Add(Path.Combine(dir.FullName, "src", "target", "release", file));
                break;
            }

            dir = dir.Parent;
        }
        return paths;
    }

    private static string NativeFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "mxc_ffi.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libmxc_ffi.dylib";
        }

        return "libmxc_ffi.so";
    }
}
