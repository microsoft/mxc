// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Mxc.Diplomat;
using Microsoft.Mxc.Diplomat.Prototype;

if (!typeof(IDisposable).IsAssignableFrom(typeof(MxcDiplomatSandbox))
    || !typeof(IDisposable).IsAssignableFrom(typeof(MxcDiplomatInputStream))
    || !typeof(IDisposable).IsAssignableFrom(typeof(MxcDiplomatOutputStream)))
{
    throw new InvalidOperationException("Generated live handles must have deterministic disposal.");
}

using (var version = MxcDiplomatPrototype.Version())
{
    if (string.IsNullOrWhiteSpace(version.Value()))
    {
        throw new InvalidOperationException("The generated Diplomat binding returned an empty version.");
    }
}

using (var discovery = MxcDiplomatPrototype.Discover())
{
    using var backends = JsonDocument.Parse(discovery.AvailableBackendsJson());
    using var support = JsonDocument.Parse(discovery.PlatformSupportJson());
    if (backends.RootElement.ValueKind != JsonValueKind.Array
        || !support.RootElement.TryGetProperty("isSupported", out _))
    {
        throw new InvalidOperationException("The generated Diplomat binding returned invalid discovery JSON.");
    }
}

const string invalidRequest = """{"policy":{"version":""},"command":"echo hi"}""";
var synchronousError = CaptureMxcError(
    () => _ = MxcDiplomatPrototype.Run(invalidRequest));
var asynchronousError = await CaptureMxcErrorAsync(
    () => MxcDiplomatPrototype.RunAsync(invalidRequest));
const string invalidStateAwareRequest = "{";
var synchronousStateAwareError = CaptureMxcError(
    () => _ = MxcDiplomatPrototype.Provision(invalidStateAwareRequest, false, false));
var asynchronousStateAwareError = await CaptureMxcErrorAsync(
    () => MxcDiplomatPrototype.ProvisionAsync(invalidStateAwareRequest, false, false));

if (synchronousError.Inner.Code() != MxcDiplomatErrorCode.MalformedRequest
    || asynchronousError.Inner.Code() != MxcDiplomatErrorCode.MalformedRequest
    || synchronousError.Message != asynchronousError.Message
    || synchronousError.Inner.Message() != asynchronousError.Inner.Message()
    || synchronousStateAwareError.Inner.Code() != MxcDiplomatErrorCode.MalformedRequest
    || asynchronousStateAwareError.Inner.Code() != MxcDiplomatErrorCode.MalformedRequest
    || synchronousStateAwareError.Message != asynchronousStateAwareError.Message)
{
    throw new InvalidOperationException("Synchronous and asynchronous malformed-request errors diverged.");
}

if (args.Contains("--exercise-process", StringComparer.Ordinal))
{
    await ExerciseLiveSandboxAsync();
    await ExerciseBusyWaitPolicyAsync();
}

Console.WriteLine("Diplomat public prototype smoke test passed.");

static MxcDiplomatException CaptureMxcError(Action action)
{
    try
    {
        action();
    }
    catch (MxcDiplomatException error)
    {
        return error;
    }

    throw new InvalidOperationException("The invalid request unexpectedly succeeded.");
}

static async Task<MxcDiplomatException> CaptureMxcErrorAsync<T>(Func<Task<T>> action)
{
    try
    {
        _ = await action();
    }
    catch (MxcDiplomatException error)
    {
        return error;
    }

    throw new InvalidOperationException("The invalid request unexpectedly succeeded.");
}

static async Task<MxcDiplomatException> CaptureMxcErrorTaskAsync(Func<Task> action)
{
    try
    {
        await action();
    }
    catch (MxcDiplomatException error)
    {
        return error;
    }

    throw new InvalidOperationException("The invalid request unexpectedly succeeded.");
}

static async Task ExerciseLiveSandboxAsync()
{
    const string request = """{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c exit 23"}""";

    using var sandbox = await MxcDiplomatPrototype.SpawnAsync(request);
    using var stdin = sandbox.TakeStdin()
        ?? throw new InvalidOperationException("The spawned sandbox did not provide stdin.");
    using var stdout = sandbox.TakeStdout()
        ?? throw new InvalidOperationException("The spawned sandbox did not provide stdout.");
    using var stderr = sandbox.TakeStderr()
        ?? throw new InvalidOperationException("The spawned sandbox did not provide stderr.");
    if (sandbox.TakeStdin() is not null
        || sandbox.TakeStdout() is not null
        || sandbox.TakeStderr() is not null)
    {
        throw new InvalidOperationException("Taking a sandbox stream twice must return null.");
    }

    var poll = sandbox.TryWait();
    if (poll.TimedOut)
    {
        throw new InvalidOperationException("The short-lived sandbox timed out before waiting.");
    }

    var outcome = await sandbox.WaitAsync();
    if (outcome.TimedOut || outcome.ExitCode != 23)
    {
        throw new InvalidOperationException(
            $"Unexpected sandbox outcome: timedOut={outcome.TimedOut}, exitCode={outcome.ExitCode}.");
    }

    Console.WriteLine("Diplomat live sandbox lifecycle smoke test passed.");
}

static async Task ExerciseBusyWaitPolicyAsync()
{
    const string request = """{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c timeout /t 4 /nobreak >nul"}""";

    using var sandbox = await MxcDiplomatPrototype.SpawnAsync(request);
    var waitTask = sandbox.WaitAsync();
    var pollError = await WaitForBusyErrorAsync(sandbox, waitTask);
    AssertBusyError(pollError);

    var killErrorTask = CaptureMxcErrorTaskAsync(() => sandbox.KillAsync());
    if (await Task.WhenAny(killErrorTask, Task.Delay(TimeSpan.FromSeconds(1))) != killErrorTask)
    {
        throw new InvalidOperationException("KillAsync did not report sandbox-handle contention promptly.");
    }
    AssertBusyError(await killErrorTask);

    // The current safe bridge cannot invoke kill while wait owns mxc-sdk's
    // mutable Sandbox. The finite child exits naturally, then wait releases it.
    var outcome = await waitTask;
    if (outcome.TimedOut)
    {
        throw new InvalidOperationException(
            $"The long-running sandbox timed out instead of completing naturally (exitCode={outcome.ExitCode}).");
    }

    Console.WriteLine("Diplomat busy sandbox-handle smoke test passed.");
}

static async Task<MxcDiplomatException> WaitForBusyErrorAsync(
    MxcDiplomatSandbox sandbox,
    Task<MxcDiplomatWaitResult> waitTask)
{
    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
    while (DateTime.UtcNow < deadline)
    {
        try
        {
            _ = sandbox.TryWait();
        }
        catch (MxcDiplomatException error) when (IsBusyError(error))
        {
            return error;
        }

        if (waitTask.IsCompleted)
        {
            throw new InvalidOperationException(
                "The long-running sandbox exited before WaitAsync held its handle lock.");
        }

        await Task.Delay(10);
    }

    throw new InvalidOperationException("TryWait did not report sandbox-handle contention promptly.");
}

static void AssertBusyError(MxcDiplomatException error)
{
    if (!IsBusyError(error))
    {
        throw new InvalidOperationException(
            $"Expected a typed busy backend error, got {error.Inner.Code()}: {error.Message}");
    }
}

static bool IsBusyError(MxcDiplomatException error) =>
    error.Inner.Code() == MxcDiplomatErrorCode.BackendError
    && error.Message == "sandbox handle is busy with another operation; wait for it to finish before retrying"
    && error.Inner.HasOperation()
    && error.Inner.Operation() == "Diplomat handle synchronization";
