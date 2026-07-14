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
    /// SDK's public entry point so it runs before the first P/Invoke.
    /// </summary>
    internal static void Initialize()
    {
        if (Interlocked.Exchange(ref _initialized, 1) != 0)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve);
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
        var file = NativeFileName();

        var overrideDir = Environment.GetEnvironmentVariable("MXC_FFI_DIR");
        if (!string.IsNullOrEmpty(overrideDir))
        {
            yield return Path.Combine(overrideDir, file);
        }

        var baseDir = AppContext.BaseDirectory;
        yield return Path.Combine(baseDir, file);
        yield return Path.Combine(baseDir, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", file);

        // Dev layout: walk up looking for the Cargo target dir.
        for (var dir = new DirectoryInfo(baseDir); dir is not null; dir = dir.Parent)
        {
            yield return Path.Combine(dir.FullName, "src", "target", "debug", file);
            yield return Path.Combine(dir.FullName, "src", "target", "release", file);
        }
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
