using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Mxc.Sdk;

var packageVersion = Environment.GetEnvironmentVariable("MXC_TEST_PACKAGE_VERSION")
    ?? throw new InvalidOperationException("MXC_TEST_PACKAGE_VERSION is required.");
var skipBackendTests = string.Equals(
    Environment.GetEnvironmentVariable("MXC_SKIP_BACKEND_INTEGRATION_TESTS"),
    "1",
    StringComparison.Ordinal);

var failures = new List<string>();
var passed = 0;
var skipped = 0;
var managedAssembly = typeof(MxcSandbox).Assembly;
var managedVersion =
    managedAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
        ?.InformationalVersion
        .Split('+', 2)[0]
    ?? throw new InvalidOperationException("The SDK assembly has no informational version.");

Run("managed package identity", () =>
{
    Equal("Microsoft.Mxc.Sdk", managedAssembly.GetName().Name);
    True(
        packageVersion == managedVersion
            || packageVersion.StartsWith($"{managedVersion}-", StringComparison.Ordinal),
        $"Package version '{packageVersion}' is not based on managed version '{managedVersion}'.");
});

Run("native library version", () => Equal(managedVersion, MxcSandbox.NativeVersion));

Run("current RID assets", () =>
{
    var rid = RuntimeInformation.RuntimeIdentifier;
    var nativeDirectory = Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native");
    True(Directory.Exists(nativeDirectory), $"Native asset directory was not copied: {nativeDirectory}");

    var expectedFiles = OperatingSystem.IsWindows()
        ? new[] { "mxc_ffi.dll", "plm.exe" }
        : OperatingSystem.IsMacOS()
            ? new[] { "libmxc_ffi.dylib" }
            : new[] { "libmxc_ffi.so" };

    foreach (var file in expectedFiles)
    {
        True(File.Exists(Path.Combine(nativeDirectory, file)), $"Missing {rid} package asset: {file}");
    }
});

Run("platform support probe", () =>
{
    var support = MxcSandbox.GetPlatformSupport();
    True(
        support.IsSupported || !string.IsNullOrWhiteSpace(support.Reason),
        "An unsupported host must include a reason.");
});

RunBackend("run captures stdout", () =>
{
    var result = MxcSandbox.Run(CreateRequest(HelloCommand()));
    Equal(0, result.ExitCode);
    True(result.Stdout.Contains("hello moto", StringComparison.Ordinal), result.Stdout);
});

RunBackend("run propagates exit code", () =>
{
    var result = MxcSandbox.Run(CreateRequest(ExitCommand(7)));
    Equal(7, result.ExitCode);
    True(!result.TimedOut, "The exit-code test unexpectedly timed out.");
});

Console.WriteLine();
Console.WriteLine($"Integration summary: passed={passed}, skipped={skipped}, failed={failures.Count}");
foreach (var failure in failures)
{
    Console.Error.WriteLine(failure);
}

return failures.Count == 0 ? 0 : 1;

void Run(string name, Action test)
{
    try
    {
        test();
        passed++;
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception ex)
    {
        failures.Add($"FAIL {name}: {ex}");
        Console.Error.WriteLine($"FAIL {name}: {ex.Message}");
    }
}

void RunBackend(string name, Action test)
{
    var reason = BackendSkipReason();
    if (reason is not null)
    {
        skipped++;
        Console.WriteLine($"SKIP {name}: {reason}");
        return;
    }

    Run(name, test);
}

string? BackendSkipReason()
{
    if (skipBackendTests)
    {
        return "MXC_SKIP_BACKEND_INTEGRATION_TESTS=1";
    }

    if (OperatingSystem.IsWindows()
        && !string.Equals(
            Environment.GetEnvironmentVariable("MXC_E2E_HOST_PREPPED"),
            "1",
            StringComparison.Ordinal))
    {
        return "Windows ProcessContainer host preparation is not enabled.";
    }

    if (OperatingSystem.IsLinux() && !CommandExists("bwrap"))
    {
        return "Bubblewrap is not installed.";
    }

    return null;
}

SandboxRequest CreateRequest(string command)
{
    var policy = new SandboxPolicy
    {
        Version = "0.9.0-alpha",
        Filesystem = new FilesystemPolicy
        {
            ReadwritePaths = { Path.GetTempPath() },
        },
        TimeoutMs = 30_000,
    };

    return new SandboxRequest(policy, command)
    {
        Containment = OperatingSystem.IsWindows()
            ? new ProcessContainerContainment()
            : OperatingSystem.IsMacOS()
                ? new SeatbeltContainment()
                : new BubblewrapContainment(),
        Experimental = OperatingSystem.IsMacOS(),
    };
}

static string HelloCommand() =>
    OperatingSystem.IsWindows()
        ? "cmd.exe /d /s /c \"echo hello moto\""
        : "/bin/sh -c \"printf 'hello moto\\n'\"";

static string ExitCommand(int exitCode) =>
    OperatingSystem.IsWindows()
        ? $"cmd.exe /d /s /c \"exit /b {exitCode}\""
        : $"/bin/sh -c \"exit {exitCode}\"";

static bool CommandExists(string command)
{
    var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
    return path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
        .Any(directory => File.Exists(Path.Combine(directory, command)));
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}

static void True(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
