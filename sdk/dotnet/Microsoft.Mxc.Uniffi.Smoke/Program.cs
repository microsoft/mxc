// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk.Uniffi;

if (!System.Text.RegularExpressions.Regex.IsMatch(MxcNative.Version(), @"^\d+\.\d+\.\d+"))
{
    throw new InvalidOperationException("Generated SDK did not load the native MXC library.");
}

var discovery = MxcNative.Discover();
if (!discovery.AvailableBackendsJson.StartsWith('[') ||
    !discovery.PlatformSupportJson.StartsWith('{'))
{
    throw new InvalidOperationException("Generated discovery returned invalid JSON.");
}

AssertMalformed(() => MxcNative.RunSync("{"));
await AssertMalformedAsync(() => MxcNative.Run("{"));
AssertMalformed(() => MxcNative.StateAwareSync("{", true, true));
await AssertMalformedAsync(() => MxcNative.StateAware("{", true, true));

var request =
    """{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c \"echo generated-sdk & exit /b 19\""}""";
var syncResult = MxcNative.RunSync(request);
var asyncResult = await MxcNative.Run(request);
if (syncResult.ExitCode != 19 || asyncResult.ExitCode != 19)
{
    throw new InvalidOperationException("Generated run APIs returned the wrong exit code.");
}

using var sandbox = await MxcNative.Spawn(
    """{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c set /p X="}""");
using var input = sandbox.TakeStdin()
    ?? throw new InvalidOperationException("Expected an owned stdin stream.");
if (sandbox.TakeStdin() is not null)
{
    throw new InvalidOperationException("Stdin must be take-once.");
}

var waiting = sandbox.Wait();
await Task.Delay(200);
try
{
    await sandbox.Kill();
    throw new InvalidOperationException("Concurrent kill should report a busy handle.");
}
catch (BindingException error) when (
    error.Code() == "backend_error" &&
    error.Operation() == "UniFFI handle synchronization")
{
}

input.Dispose();
if ((await waiting).TimedOut)
{
    throw new InvalidOperationException("Live sandbox unexpectedly timed out.");
}

Console.WriteLine("Generated UniFFI C# SDK smoke tests passed.");

static void AssertMalformed(Action operation)
{
    try
    {
        operation();
        throw new InvalidOperationException("Malformed request should fail.");
    }
    catch (BindingException error) when (error.Code() == "malformed_request")
    {
    }
}

static async Task AssertMalformedAsync(Func<Task> operation)
{
    try
    {
        await operation();
        throw new InvalidOperationException("Malformed request should fail.");
    }
    catch (BindingException error) when (error.Code() == "malformed_request")
    {
    }
}
