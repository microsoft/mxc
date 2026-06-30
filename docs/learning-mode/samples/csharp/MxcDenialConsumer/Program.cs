// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// captureDenials C# reference consumer - end-to-end demo.
//
// Drives wxc-exec directly (no SDK) and receives the denial stream live over the
// MXC_DENIALS_PIPE named pipe. See docs/learning-mode/consumer-guide.md for the
// full integration contract.
//
//   dotnet run --project MxcDenialConsumer -- <wxc-exec.exe> <config.json>
//
// The config must set "captureDenials": true (see the consumer guide §3).

using System.Diagnostics;
using Microsoft.Mxc.Samples.DenialConsumer;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: MxcDenialConsumer <path-to-wxc-exec.exe> <path-to-config.json>");
    return 2;
}

string wxcExecPath = args[0];
string configPath = args[1];

// 1) Construct the consumer FIRST. This creates the inbound named pipe so it
//    exists before wxc-exec is spawned and opens it.
using var consumer = new DenialPipeConsumer(applyDefaultFilters: true);

// React to denials live, the moment each one happens. An app such as Copilot
// would surface this to the user / queue a broadened policy for the next run.
consumer.DenialReceived += d =>
{
    string when = DateTimeOffset.FromFileTime((long)d.Filetime).ToLocalTime().ToString("HH:mm:ss");
    Console.WriteLine($"  [blocked {when}] {d.AccessType,-7} {DenialFilters.StripNtPrefix(d.Path)} (pid {d.Pid})");
};

consumer.SummaryReceived += s =>
{
    Console.WriteLine(
        $"  [summary] exit={s.ExitCode} unique={s.TotalDenials} active={s.CaptureDenialsActive} " +
        $"truncated={s.DeniedResourcesTruncated} descendants={s.DescendantPidsCovered}");
};

// 2) Begin accepting on the pipe BEFORE spawning the child.
using var cts = new CancellationTokenSource();
Task consumeTask = consumer.RunAsync(cts.Token);

// 3) Spawn wxc-exec with MXC_DENIALS_PIPE pointing at our pipe's base name.
var psi = new ProcessStartInfo
{
    FileName = wxcExecPath,
    UseShellExecute = false,
};
psi.ArgumentList.Add(configPath);
psi.Environment["MXC_DENIALS_PIPE"] = consumer.BaseName;

Console.WriteLine($"spawning: {wxcExecPath} {configPath}");
Console.WriteLine($"denial pipe: \\\\.\\pipe\\{consumer.BaseName}");
Console.WriteLine();

using var child = Process.Start(psi)
    ?? throw new InvalidOperationException($"failed to start {wxcExecPath}");

await child.WaitForExitAsync();

// 4) Give trailing bytes a brief grace to flush, then release the consumer.
//    If wxc-exec fell back to stderr (pipe could not be opened), no summary
//    will arrive and the cancellation releases the never-completed accept.
try
{
    using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));
    using CancellationTokenSource linked =
        CancellationTokenSource.CreateLinkedTokenSource(grace.Token);

    // Wait for either the stream to end naturally (summary + EOF) or the grace
    // period to elapse.
    Task finished = await Task.WhenAny(consumeTask, Task.Delay(Timeout.Infinite, grace.Token));
    if (finished != consumeTask)
    {
        cts.Cancel();
    }
}
catch (OperationCanceledException)
{
    cts.Cancel();
}

await consumeTask;

Console.WriteLine();
if (consumer.FinalSummary is { } summary)
{
    Console.WriteLine(
        summary.CaptureDenialsActive
            ? $"done: workload exited {summary.ExitCode}, {summary.TotalDenials} denial(s) captured."
            : "done: capture was NOT active (is MxcLearningModeShim installed and running?).");
}
else
{
    // No summary over the pipe: either captureDenials was not enabled, or
    // wxc-exec fell back to stderr. Inspect wxc-exec's stderr in that case.
    Console.WriteLine(
        "done: no denial summary arrived over the pipe. " +
        "Check that the config sets captureDenials:true and inspect wxc-exec stderr for a fallback warning.");
}

return child.ExitCode;
