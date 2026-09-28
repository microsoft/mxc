// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Mxc.Sdk;

internal readonly record struct RequestProbeProcessResult(
    int ExitCode,
    string Stdout,
    string Stderr);

internal static class RequestProbeExecutor
{
    internal static Func<bool> IsWindows { get; set; } = OperatingSystem.IsWindows;
    internal static Func<string?> FindExecutable { get; set; } = FindWxcExecutable;
    internal static Func<string, string?, RequestProbeProcessResult> RunProcess { get; set; } =
        RunWxcProcess;

    internal static string Run(string? configJson)
    {
        if (!IsWindows())
        {
            throw new MxcException(
                ErrorCode.UnsupportedContainment,
                "the request-aware probe is available only for Windows ProcessContainer");
        }

        var executable = FindExecutable();
        if (executable is null)
        {
            throw new MxcException(
                ErrorCode.BackendUnavailable,
                "wxc-exec.exe was not found; the request-aware probe requires the packaged Windows executor");
        }

        string? tempDirectory = null;
        string? configPath = null;

        try
        {
            if (configJson is not null)
            {
                tempDirectory = Path.Combine(
                    Path.GetTempPath(),
                    $"mxc-request-probe-{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDirectory);
                configPath = Path.Combine(tempDirectory, "config.json");
                File.WriteAllText(configPath, configJson);
            }
            RequestProbeProcessResult result;
            try
            {
                result = RunProcess(executable, configPath);
            }
            catch (MxcException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new MxcException(
                    ErrorCode.BackendError,
                    $"failed to start wxc-exec request probe: {ex.Message}",
                    ex);
            }

            if (result.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(result.Stderr)
                    ? $"wxc-exec exited with code {result.ExitCode}"
                    : result.Stderr.Trim();
                var code = detail.Contains(
                    "supports only ProcessContainer containment",
                    StringComparison.Ordinal)
                    ? ErrorCode.UnsupportedContainment
                    : ErrorCode.BackendError;
                throw new MxcException(code, $"wxc-exec request probe failed: {detail}");
            }

            return result.Stdout;
        }
        finally
        {
            if (tempDirectory is not null)
            {
                Directory.Delete(tempDirectory, recursive: true);
            }
        }
    }

    internal static void ResetTestHooks()
    {
        IsWindows = OperatingSystem.IsWindows;
        FindExecutable = FindWxcExecutable;
        RunProcess = RunWxcProcess;
    }

    private static RequestProbeProcessResult RunWxcProcess(
        string executable,
        string? configPath)
    {
        var startInfo = CreateStartInfo(executable, configPath);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Process.Start returned null.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(10_000))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new MxcException(
                ErrorCode.BackendError,
                "wxc-exec request probe timed out after 10 seconds");
        }
        return new RequestProbeProcessResult(
            process.ExitCode,
            stdout.GetAwaiter().GetResult(),
            stderr.GetAwaiter().GetResult());
    }

    internal static ProcessStartInfo CreateStartInfo(string executable, string? configPath)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--probe");
        if (configPath is not null)
        {
            startInfo.ArgumentList.Add(configPath);
        }

        return startInfo;
    }

    private static string? FindWxcExecutable()
    {
        var candidates = new List<string>();
        var overrideDirectory = Environment.GetEnvironmentVariable("MXC_BIN_DIR");
        if (!string.IsNullOrWhiteSpace(overrideDirectory))
        {
            candidates.Add(Path.Combine(overrideDirectory, ArchitectureDirectory(), "wxc-exec.exe"));
            candidates.Add(Path.Combine(overrideDirectory, "wxc-exec.exe"));
        }

        var baseDirectory = AppContext.BaseDirectory;
        candidates.Add(Path.Combine(baseDirectory, "wxc-exec.exe"));
        candidates.Add(Path.Combine(
            baseDirectory,
            "runtimes",
            RuntimeInformation.RuntimeIdentifier,
            "native",
            "wxc-exec.exe"));

        var directory = new DirectoryInfo(baseDirectory);
        for (var depth = 0; directory is not null && depth < 8; depth++, directory = directory.Parent)
        {
            if (!File.Exists(Path.Combine(directory.FullName, "src", "Cargo.toml")))
            {
                continue;
            }

            var target = Path.Combine(directory.FullName, "src", "target");
            var triple = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? "aarch64-pc-windows-msvc"
                : "x86_64-pc-windows-msvc";
            candidates.Add(Path.Combine(target, triple, "release", "wxc-exec.exe"));
            candidates.Add(Path.Combine(target, triple, "debug", "wxc-exec.exe"));
            candidates.Add(Path.Combine(target, "release", "wxc-exec.exe"));
            candidates.Add(Path.Combine(target, "debug", "wxc-exec.exe"));
            break;
        }

        return candidates.FirstOrDefault(File.Exists);
    }

    private static string ArchitectureDirectory() =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "x64";
}
