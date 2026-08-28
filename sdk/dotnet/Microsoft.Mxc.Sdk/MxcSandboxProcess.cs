// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// Injectable handle that interrupts reads from one sandbox output stream.
/// </summary>
public interface ISandboxStreamCloser : IDisposable
{
    /// <summary>Close the associated reader.</summary>
    void Close();
}

/// <summary>
/// Injectable abstraction for a live sandboxed process. Implement this
/// interface in tests to provide in-memory streams and deterministic outcomes.
/// </summary>
public interface ISandboxProcess : IDisposable
{
    /// <summary>The child process identifier, or zero when unavailable.</summary>
    uint Id { get; }

    /// <summary>The child's writable standard input.</summary>
    Stream? StandardInput { get; }

    /// <summary>The child's readable standard output.</summary>
    Stream? StandardOutput { get; }

    /// <summary>The child's readable standard error.</summary>
    Stream? StandardError { get; }

    /// <summary>A handle that can interrupt standard-output reads.</summary>
    ISandboxStreamCloser? StandardOutputCloser { get; }

    /// <summary>A handle that can interrupt standard-error reads.</summary>
    ISandboxStreamCloser? StandardErrorCloser { get; }

    /// <summary>Security warnings emitted while applying the policy.</summary>
    IReadOnlyList<string> Warnings { get; }

    /// <summary>Structured feature output available after terminal completion.</summary>
    SandboxOutputMetadata? OutputMetadata { get; }

    /// <summary>Wait for the child to exit.</summary>
    SandboxWaitResult Wait();

    /// <summary>Wait asynchronously for the child to exit.</summary>
    Task<SandboxWaitResult> WaitAsync(CancellationToken cancellationToken = default);

    /// <summary>Check whether the child has exited without blocking.</summary>
    bool TryGetExitCode(out int exitCode);

    /// <summary>Wait while capturing standard output and error.</summary>
    Task<(SandboxWaitResult Result, byte[] Stdout, byte[] Stderr)> WaitForExitWithOutputAsync(
        CancellationToken cancellationToken = default);

    /// <summary>Kill the child and its process tree.</summary>
    void Kill();
}

/// <summary>
/// A live sandboxed process spawned by <see cref="MxcSandbox.Spawn(SandboxPolicy, string)"/>.
/// </summary>
/// <remarks>
/// <para>
/// Stream the child's stdio with <see cref="StandardInput"/> /
/// <see cref="StandardOutput"/> / <see cref="StandardError"/>, wait for it with
/// <see cref="Wait"/> / <see cref="WaitAsync"/>, or kill it (and its whole tree)
/// with <see cref="Kill"/>. <see cref="Warnings"/> reports policy relaxations
/// immediately. Each standard stream is a separate object; different streams
/// may be used concurrently on different threads, but a single stream must be
/// driven from one thread at a time (its native reads/writes are serialized
/// internally, since the underlying handle is not concurrency-safe).
/// </para>
/// <para>
/// <b>Draining.</b> Like the underlying Rust <c>Sandbox</c>, <see cref="Wait"/>
/// drains any standard stream you did <i>not</i> take, so a caller that ignores
/// the child's output cannot deadlock on a full pipe. If you <i>do</i> take
/// <see cref="StandardOutput"/> / <see cref="StandardError"/>, read them (e.g.
/// on background tasks or via <see cref="WaitForExitWithOutputAsync"/>) so the
/// child does not block on a full pipe while you wait.
/// </para>
/// <para>
/// <b>Threading.</b> The process-control operations (<see cref="Id"/>,
/// <see cref="Wait"/>, <see cref="WaitAsync"/>, <see cref="Kill"/>,
/// <see cref="Dispose"/>) are serialized internally, so <see cref="Kill"/> may be
/// called from another thread while <see cref="WaitAsync"/> is in flight. Each
/// standard stream serializes its own native reads/writes and refcounts its
/// native handle, so reading/writing a stream concurrently with
/// <see cref="Dispose"/> is safe — an in-flight read/write completes and the
/// handle is freed afterwards, never underneath it.
/// </para>
/// <para>
/// <b>Disposal.</b> <see cref="Dispose"/> kills the child tree if it is still
/// running and releases the native handles (draining and awaiting any internal
/// readers first). If it is skipped, the finalizers on the underlying
/// <see cref="System.Runtime.InteropServices.SafeHandle"/>s still reclaim the
/// native handles and kill the child.
/// </para>
/// </remarks>
public sealed class MxcSandboxProcess : ISandboxProcess
{
    // Poll cadence bounds for the try_wait-based wait loop: start short so a
    // quick child returns promptly, back off to a cap so a long-running child
    // does not spin a core.
    private static readonly TimeSpan MinPollInterval = TimeSpan.FromMilliseconds(1);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromMilliseconds(50);

    private readonly object _controlLock = new();
    private readonly MxcSandboxHandle _handle;
    private IReadOnlyList<string>? _warnings;
    private bool _disposed;

    // Tracks whether each readable standard stream is still available, has been
    // handed to the caller, or is being consumed by an internal drain task. A
    // draining stream must never be handed back out (see TakeReadStream), or the
    // caller would read the same handle concurrently with the drainer.
    private enum ReadStreamState
    {
        Untaken,
        CallerOwned,
        Draining,
    }

    private MxcStdinStream? _stdin;
    private MxcReadPipeStream? _stdout;
    private MxcReadPipeStream? _stderr;
    private bool _stdinTaken;
    private ReadStreamState _stdoutState;
    private ReadStreamState _stderrState;

    private readonly List<Task> _drainTasks = new();

    // The policy timeout (if any) and a monotonic start stamp. The polling wait
    // path enforces this deadline itself: mxc_sandbox_try_wait never kills, and
    // spawn starts no native watchdog, so without this SandboxPolicy.TimeoutMs
    // would be silently ignored on Wait()/WaitAsync().
    private readonly uint? _timeoutMs;
    private readonly long _startTimestamp = Stopwatch.GetTimestamp();

    internal MxcSandboxProcess(MxcSandboxHandle handle, uint? timeoutMs = null)
    {
        _handle = handle;
        _timeoutMs = NormalizeTimeout(timeoutMs);
    }

    internal static uint? NormalizeTimeout(uint? timeoutMs) =>
        timeoutMs is 0 ? null : timeoutMs;

    /// <summary>
    /// The child's OS process id (its PID on Unix, process id on Windows).
    /// </summary>
    /// <remarks>
    /// Returns <c>0</c> for a process obtained from
    /// <see cref="MxcLifecycle.ExecInSandbox"/>: a state-aware exec is driven by
    /// the backend behind its own waiter/terminator and exposes no OS process id.
    /// </remarks>
    public uint Id
    {
        get
        {
            lock (_controlLock)
            {
                ThrowIfDisposed();
                unsafe
                {
                    return NativeMethods.mxc_sandbox_id(_handle.Ptr);
                }
            }
        }
    }

    /// <summary>
    /// The child's stdin as a writable <see cref="Stream"/>. Returns the same
    /// stream on repeated access; <see cref="Stream.Dispose()"/> (or disposing
    /// this process) closes stdin, sending EOF to the child. Returns
    /// <see langword="null"/> if stdin was not piped.
    /// </summary>
    public Stream? StandardInput
    {
        get
        {
            lock (_controlLock)
            {
                ThrowIfDisposed();
                if (!_stdinTaken)
                {
                    _stdinTaken = true;
                    unsafe
                    {
                        var s = NativeMethods.mxc_sandbox_take_stdin(_handle.Ptr);
                        _stdin = s is null ? null : new MxcStdinStream(MxcWriteStreamHandle.FromRaw(s));
                    }
                }
                return _stdin;
            }
        }
    }

    /// <summary>
    /// The child's stdout as a readable <see cref="Stream"/>. A read of zero
    /// bytes signals EOF. Returns <see langword="null"/> if stdout was not piped.
    /// </summary>
    public Stream? StandardOutput => TakeReadStream(ref _stdoutState, ref _stdout, stdout: true);

    /// <summary>
    /// The child's stderr as a readable <see cref="Stream"/>. Returns
    /// <see langword="null"/> if stderr was not piped.
    /// </summary>
    public Stream? StandardError => TakeReadStream(ref _stderrState, ref _stderr, stdout: false);

    /// <summary>
    /// A closer that makes an in-flight or subsequent
    /// <see cref="StandardOutput"/> read return EOF without killing the child.
    /// </summary>
    /// <remarks>
    /// Take <see cref="StandardOutput"/> before requesting its closer. Closing a
    /// stream that no caller is draining can leave a child blocked on a full
    /// pipe. Returns <see langword="null"/> when the backend cannot interrupt
    /// stdout reads. Dispose the returned closer after use; each property access
    /// returns an independent handle.
    /// </remarks>
    public SandboxStreamCloser? StandardOutputCloser =>
        GetReadCloser(stdout: true);

    /// <summary>
    /// A closer that makes an in-flight or subsequent
    /// <see cref="StandardError"/> read return EOF without killing the child.
    /// </summary>
    /// <remarks>
    /// Take <see cref="StandardError"/> first. Returns <see langword="null"/>
    /// when the backend cannot interrupt stderr reads. Dispose the returned
    /// closer after use; each property access returns an independent handle.
    /// </remarks>
    public SandboxStreamCloser? StandardErrorCloser =>
        GetReadCloser(stdout: false);

    ISandboxStreamCloser? ISandboxProcess.StandardOutputCloser =>
        StandardOutputCloser;

    ISandboxStreamCloser? ISandboxProcess.StandardErrorCloser =>
        StandardErrorCloser;

    /// <summary>
    /// Security warnings emitted while applying the sandbox policy.
    /// </summary>
    public IReadOnlyList<string> Warnings
    {
        get
        {
            lock (_controlLock)
            {
                ThrowIfDisposed();
                if (_warnings is not null)
                {
                    return _warnings;
                }
                unsafe
                {
                    byte* json = null;
                    var status = NativeMethods.mxc_sandbox_warnings_json(_handle.Ptr, &json);
                    if (status != (int)ErrorCode.Success)
                    {
                        throw new MxcException(
                            (ErrorCode)status,
                            "retrieving sandbox security warnings failed");
                    }
                    if (json is null)
                    {
                        return _warnings = Array.Empty<string>();
                    }
                    try
                    {
                        var text = Marshal.PtrToStringUTF8((IntPtr)json);
                        _warnings = string.IsNullOrEmpty(text)
                            ? Array.Empty<string>()
                            : JsonSerializer.Deserialize<string[]>(text) ?? Array.Empty<string>();
                        return _warnings;
                    }
                    finally
                    {
                        NativeMethods.mxc_string_free(json);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Structured outputs produced by optional sandbox features. Metadata is
    /// available after a terminal wait completes; before then this is null.
    /// </summary>
    public SandboxOutputMetadata? OutputMetadata
    {
        get
        {
            lock (_controlLock)
            {
                ThrowIfDisposed();
                unsafe
                {
                    byte* json = null;
                    var status = NativeMethods.mxc_sandbox_output_metadata_json(_handle.Ptr, &json);
                    if (status != (int)ErrorCode.Success)
                    {
                        throw new MxcException(
                            (ErrorCode)status,
                            "retrieving sandbox output metadata failed");
                    }
                    if (json is null)
                    {
                        return null;
                    }
                    try
                    {
                        var text = Marshal.PtrToStringUTF8((IntPtr)json);
                        return string.IsNullOrEmpty(text)
                            ? null
                            : JsonSerializer.Deserialize<SandboxOutputMetadata>(text);
                    }
                    finally
                    {
                        NativeMethods.mxc_string_free(json);
                    }
                }
            }
        }
    }

    private Stream? TakeReadStream(ref ReadStreamState state, ref MxcReadPipeStream? slot, bool stdout)
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            switch (state)
            {
                case ReadStreamState.Untaken:
                    state = ReadStreamState.CallerOwned;
                    unsafe
                    {
                        var s = stdout
                            ? NativeMethods.mxc_sandbox_take_stdout(_handle.Ptr)
                            : NativeMethods.mxc_sandbox_take_stderr(_handle.Ptr);
                        slot = s is null ? null : new MxcReadPipeStream(MxcReadStreamHandle.FromRaw(s));
                    }
                    return slot;
                case ReadStreamState.CallerOwned:
                    return slot;
                default:
                    // Draining: a Wait()/WaitAsync() drain task already owns this
                    // stream. Handing it back would let the caller read the same
                    // native handle concurrently with the drainer (undefined
                    // behaviour). Take the stream before waiting, or use
                    // WaitForExitWithOutputAsync, which takes it for you.
                    throw new InvalidOperationException(
                        "this standard stream is being drained internally by a wait; " +
                        "take StandardOutput/StandardError before calling Wait/WaitAsync");
            }
        }
    }

    private SandboxStreamCloser? GetReadCloser(bool stdout)
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            var state = stdout ? _stdoutState : _stderrState;
            var stream = stdout ? _stdout : _stderr;
            if (state != ReadStreamState.CallerOwned)
            {
                throw new InvalidOperationException(
                    "take the standard stream before requesting its closer");
            }
            if (stream is null)
            {
                return null;
            }
            unsafe
            {
                var closer = stdout
                    ? NativeMethods.mxc_sandbox_stdout_closer(_handle.Ptr)
                    : NativeMethods.mxc_sandbox_stderr_closer(_handle.Ptr);
                return closer is null
                    ? null
                    : new SandboxStreamCloser(MxcStreamCloserHandle.FromRaw(closer));
            }
        }
    }

    /// <summary>
    /// Block until the child exits (honouring
    /// <see cref="SandboxPolicy.TimeoutMs"/> or
    /// <see cref="StateAwareExecOptions.TimeoutMs"/>), draining any standard
    /// stream you did not take so the child cannot block on a full pipe.
    /// </summary>
    /// <returns>The exit code, or a timed-out result.</returns>
    /// <exception cref="MxcException">A wait error occurred.</exception>
    public SandboxWaitResult Wait() => WaitCore(CancellationToken.None);

    /// <summary>
    /// Awaitable form of <see cref="Wait"/>. Honours <paramref name="cancellationToken"/>
    /// by abandoning the wait (it does <b>not</b> kill the child — call
    /// <see cref="Kill"/> or <see cref="Dispose"/> for that).
    /// </summary>
    public Task<SandboxWaitResult> WaitAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => WaitCore(cancellationToken), cancellationToken);

    /// <summary>
    /// Check whether the child has exited without blocking.
    /// </summary>
    /// <param name="exitCode">
    /// Receives the child's exit code when this method returns
    /// <see langword="true"/>, or <c>-1</c> when a native state-aware waiter
    /// completed because its deadline elapsed; otherwise receives zero.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the child has exited; otherwise
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// This is a status probe only. Call <see cref="Wait"/> or
    /// <see cref="WaitAsync(CancellationToken)"/> after exit to complete
    /// backend finalization, reclaim descendants, and make output metadata
    /// available.
    /// </remarks>
    /// <exception cref="MxcException">The process status could not be queried.</exception>
    public bool TryGetExitCode(out int exitCode)
    {
        return TryGetTerminalStatus(out exitCode, out _);
    }

    private bool TryGetTerminalStatus(out int exitCode, out bool timedOut)
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            var running = 1;
            var nativeExitCode = 0;
            var nativeTimedOut = 0;
            int status;
            unsafe
            {
                status = NativeMethods.mxc_sandbox_try_wait(
                    _handle.Ptr,
                    &nativeExitCode,
                    &running,
                    &nativeTimedOut);
            }
            if (status != (int)ErrorCode.Success)
            {
                throw new MxcException(
                    (ErrorCode)status,
                    "querying the sandbox process status failed");
            }
            exitCode = nativeExitCode;
            timedOut = nativeTimedOut != 0;
            return running == 0;
        }
    }

    private SandboxWaitResult WaitCore(CancellationToken cancellationToken)
    {
        EnsureDrainUntaken();

        var poll = MinPollInterval;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (TryGetTerminalStatus(out _, out _))
            {
                // try_wait is intentionally a non-blocking root-process poll.
                // Complete the native wait so a cached timeout is translated
                // into TimedOut and all backend finalization finishes before
                // the managed Wait/WaitAsync contract returns.
                return WaitBlocking();
            }

            // try_wait only reports exited / still-running, never a timeout, and
            // spawn starts no native watchdog, so the managed side owns the
            // policy deadline. Handing straight to the native blocking wait does
            // not work: mxc_sandbox_wait takes no deadline and applies the
            // spawn-time timeout as a duration from the call
            // (WaitForSingleObject(h, timeout_ms) on Windows, Instant::now() + d
            // on Unix), so it would grant a second full budget — up to 2x the
            // policy timeout, with _controlLock held the whole time.
            if (_timeoutMs is { } timeoutMs &&
                Stopwatch.GetElapsedTime(_startTimestamp).TotalMilliseconds >= timeoutMs)
            {
                return WaitAfterDeadline();
            }

            cancellationToken.WaitHandle.WaitOne(poll);
            var next = poll + poll;
            poll = next > MaxPollInterval ? MaxPollInterval : next;
        }
    }

    // The policy deadline has expired. Terminate the tree ourselves so the
    // native wait reaps an already-dead process immediately instead of starting
    // a fresh timeout_ms countdown, then report the timeout that the native call
    // can no longer observe (it sees a killed process, not an expired budget).
    private SandboxWaitResult WaitAfterDeadline()
    {
        // A child that exited in the window between the poll above and here ran
        // to completion, so surface its real status rather than a timeout.
        if (TryGetTerminalStatus(out _, out _))
        {
            return WaitBlocking();
        }

        // Safe to call after an exit that races this check: every backend
        // no-ops a kill once the child has been reaped.
        Kill();
        var result = WaitBlocking();
        return new SandboxWaitResult { ExitCode = result.ExitCode, TimedOut = true };
    }

    // Called only after try_wait reports exit or the managed deadline expired
    // and the tree was killed. It holds the control lock across the native wait
    // and must not be public: callers need Wait/WaitAsync so concurrent Kill and
    // Dispose stay responsive.
    private SandboxWaitResult WaitBlocking()
    {
        EnsureDrainUntaken();
        lock (_controlLock)
        {
            ThrowIfDisposed();
            int exit = 0;
            int timedOut = 0;
            int status;
            unsafe
            {
                status = NativeMethods.mxc_sandbox_wait(_handle.Ptr, &exit, &timedOut);
            }
            if (status != (int)ErrorCode.Success)
            {
                throw new MxcException((ErrorCode)status, "waiting on the sandbox failed");
            }
            return new SandboxWaitResult { ExitCode = exit, TimedOut = timedOut != 0 };
        }
    }

    /// <summary>
    /// Wait for the child to exit while concurrently reading
    /// <see cref="StandardOutput"/> and <see cref="StandardError"/> to end, so an
    /// output-heavy child cannot deadlock. The deadlock-free counterpart of
    /// taking the streams and waiting by hand.
    /// </summary>
    public async Task<(SandboxWaitResult Result, byte[] Stdout, byte[] Stderr)> WaitForExitWithOutputAsync(
        CancellationToken cancellationToken = default)
    {
        var outStream = StandardOutput;
        var errStream = StandardError;
        using var outCloser = outStream is null ? null : StandardOutputCloser;
        using var errCloser = errStream is null ? null : StandardErrorCloser;

        Task<byte[]> ReadAll(Stream? s) =>
            s is null ? Task.FromResult(Array.Empty<byte>()) : ReadToEndAsync(s, cancellationToken);

        var stdoutTask = ReadAll(outStream);
        var stderrTask = ReadAll(errStream);
        try
        {
            var result = await WaitAsync(cancellationToken).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            return (result, stdout, stderr);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var readsClosed =
                CloseQuietly(outCloser, outStream is not null) &
                CloseQuietly(errCloser, errStream is not null);
            if (!readsClosed)
            {
                KillQuietly();
            }
            await Task.WhenAll(SwallowAsync(stdoutTask), SwallowAsync(stderrTask))
                .ConfigureAwait(false);
            outStream?.Dispose();
            errStream?.Dispose();
            throw;
        }
        catch
        {
            // On cancellation/failure the reader tasks may be parked in a blocking
            // native read that only returns once the child's pipes reach EOF. Kill
            // the child first so those write ends close and the reads return;
            // awaiting them before killing would deadlock (and leak the native
            // child), because the reads can never otherwise complete.
            KillQuietly();
            await Task.WhenAll(SwallowAsync(stdoutTask), SwallowAsync(stderrTask))
                .ConfigureAwait(false);
            throw;
        }
    }

    private static bool CloseQuietly(SandboxStreamCloser? closer, bool required)
    {
        if (closer is null)
        {
            return !required;
        }
        try
        {
            closer.Close();
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (MxcException)
        {
            return false;
        }
    }

    // Best-effort kill for cleanup paths: swallow ObjectDisposedException (already
    // disposed) and MxcException (child already gone) so it never masks the
    // original error being unwound.
    private void KillQuietly()
    {
        try
        {
            Kill();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (MxcException)
        {
        }
    }

    private static async Task SwallowAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
            // Observed and ignored: the caller is already handling the outer error.
        }
    }

    private static async Task<byte[]> ReadToEndAsync(Stream s, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms, ct).ConfigureAwait(false);
        return ms.ToArray();
    }

    /// <summary>Kill the child and its whole process tree.</summary>
    /// <exception cref="MxcException">The kill failed.</exception>
    public void Kill()
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            int status;
            unsafe
            {
                status = NativeMethods.mxc_sandbox_kill(_handle.Ptr);
            }
            if (status != (int)ErrorCode.Success)
            {
                throw new MxcException((ErrorCode)status, "killing the sandbox failed");
            }
        }
    }

    // Start background readers that drain any standard stream the caller did not
    // take, so a full pipe can never wedge the child while we wait — mirroring
    // the Rust Sandbox::wait drain-untaken behaviour. Idempotent.
    private void EnsureDrainUntaken()
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            DrainIfUntaken(ref _stdoutState, ref _stdout, stdout: true);
            DrainIfUntaken(ref _stderrState, ref _stderr, stdout: false);
        }
    }

    private void DrainIfUntaken(ref ReadStreamState state, ref MxcReadPipeStream? slot, bool stdout)
    {
        if (state != ReadStreamState.Untaken)
        {
            // CallerOwned: the caller reads it. Draining: already draining.
            return;
        }
        unsafe
        {
            var s = stdout
                ? NativeMethods.mxc_sandbox_take_stdout(_handle.Ptr)
                : NativeMethods.mxc_sandbox_take_stderr(_handle.Ptr);
            if (s is null)
            {
                // Not piped: nothing to drain, and nothing to hand out later.
                state = ReadStreamState.CallerOwned;
                return;
            }
            slot = new MxcReadPipeStream(MxcReadStreamHandle.FromRaw(s));
        }
        state = ReadStreamState.Draining;
        var stream = slot;
        _drainTasks.Add(Task.Run(() =>
        {
            try
            {
                stream!.CopyTo(Stream.Null);
            }
            catch
            {
                // Draining is best-effort; a torn-down pipe surfaces as an I/O
                // error we intentionally swallow.
            }
        }));
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(MxcSandboxProcess));
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        List<Task> drains;
        lock (_controlLock)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            // Snapshot the drain tasks under the lock; no new ones start once
            // _disposed is set (EnsureDrainUntaken throws).
            drains = new List<Task>(_drainTasks);
        }

        // Free the sandbox handle first: mxc_sandbox_free kills the child tree,
        // closing the child's stdout/stderr write ends so any blocked reader or
        // drain task gets EOF and unblocks. (No control op can be running: they
        // hold _controlLock, which we just took to set _disposed.)
        _handle.Dispose();

        // Now the drain/read tasks observe EOF and finish; wait for them before
        // releasing the stream handles so no detached task keeps running.
        // Refcounting already makes the free itself safe against an in-flight
        // read; this just avoids leaking background tasks.
        try
        {
            Task.WaitAll(drains.ToArray());
        }
        catch
        {
            // Faulted drain tasks are best-effort; their handles are freed below.
        }

        _stdin?.Dispose();
        _stdout?.Dispose();
        _stderr?.Dispose();
    }
}

/// <summary>
/// Independently closes a sandbox output reader, making a blocking read return
/// EOF without terminating the sandboxed process.
/// </summary>
public sealed class SandboxStreamCloser : ISandboxStreamCloser
{
    private readonly MxcStreamCloserHandle _handle;

    internal SandboxStreamCloser(MxcStreamCloserHandle handle) => _handle = handle;

    /// <summary>
    /// Close the associated reader. Idempotent and safe to call concurrently
    /// with that reader.
    /// </summary>
    public void Close()
    {
        var added = false;
        try
        {
            _handle.DangerousAddRef(ref added);
            unsafe
            {
                var status = NativeMethods.mxc_stream_closer_close(_handle.Ptr);
                if (status != (int)ErrorCode.Success)
                {
                    throw new MxcException(
                        (ErrorCode)status,
                        "closing the sandbox output stream failed");
                }
            }
        }
        finally
        {
            if (added)
            {
                _handle.DangerousRelease();
            }
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _handle.Dispose();
}

/// <summary>Readable <see cref="Stream"/> over a native <c>MxcReadStream</c> (child stdout/stderr).</summary>
internal sealed class MxcReadPipeStream : Stream
{
    private readonly MxcReadStreamHandle _handle;

    // Serializes native reads on this handle. mxc_stream_read borrows the stream
    // mutably, so two concurrent reads on one handle would alias a &mut (undefined
    // behaviour, not merely interleaved bytes). Held only across the P/Invoke.
    private readonly object _ioLock = new();

    internal MxcReadPipeStream(MxcReadStreamHandle handle) => _handle = handle;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        if (offset + count > buffer.Length)
        {
            throw new ArgumentException("offset + count exceeds the buffer length");
        }
        if (count == 0)
        {
            return 0;
        }

        // Serialize the native read and hold a reference across it so a concurrent
        // read cannot alias the &mut and a concurrent Dispose cannot free the
        // handle underneath it (the SafeHandle defers the free until every
        // reference is released). The lock spans only the P/Invoke, so it cannot
        // deadlock with unrelated work — and Dispose does not take it.
        lock (_ioLock)
        {
            var added = false;
            try
            {
                _handle.DangerousAddRef(ref added);
                unsafe
                {
                    nuint read = 0;
                    fixed (byte* p = &buffer[offset])
                    {
                        var status = NativeMethods.mxc_stream_read(_handle.Ptr, p, (nuint)count, &read);
                        if (status != (int)ErrorCode.Success)
                        {
                            throw new MxcException((ErrorCode)status, "reading from the sandbox stream failed");
                        }
                    }
                    return (int)read;
                }
            }
            finally
            {
                if (added)
                {
                    _handle.DangerousRelease();
                }
            }
        }
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _handle.Dispose();
        }
        base.Dispose(disposing);
    }
}

/// <summary>Writable <see cref="Stream"/> over a native <c>MxcWriteStream</c> (child stdin).</summary>
internal sealed class MxcStdinStream : Stream
{
    private readonly MxcWriteStreamHandle _handle;

    // Serializes native writes/flushes on this handle (see MxcReadPipeStream):
    // mxc_stream_write / mxc_stream_flush borrow the stream mutably, so concurrent
    // calls would alias a &mut. Held only across the P/Invoke.
    private readonly object _ioLock = new();

    internal MxcStdinStream(MxcWriteStreamHandle handle) => _handle = handle;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        if (offset + count > buffer.Length)
        {
            throw new ArgumentException("offset + count exceeds the buffer length");
        }

        lock (_ioLock)
        {
            var written = 0;
            while (written < count)
            {
                // Reference the handle across each native write (see MxcReadPipeStream).
                var added = false;
                try
                {
                    _handle.DangerousAddRef(ref added);
                    unsafe
                    {
                        nuint n = 0;
                        fixed (byte* p = &buffer[offset + written])
                        {
                            var status = NativeMethods.mxc_stream_write(_handle.Ptr, p, (nuint)(count - written), &n);
                            if (status != (int)ErrorCode.Success)
                            {
                                throw new MxcException((ErrorCode)status, "writing to the sandbox stream failed");
                            }
                        }
                        if (n == 0)
                        {
                            throw new IOException("the sandbox stdin stream accepted no bytes (pipe closed?)");
                        }
                        written += (int)n;
                    }
                }
                finally
                {
                    if (added)
                    {
                        _handle.DangerousRelease();
                    }
                }
            }
        }
    }

    public override void Flush()
    {
        lock (_ioLock)
        {
            var added = false;
            try
            {
                _handle.DangerousAddRef(ref added);
                unsafe
                {
                    var status = NativeMethods.mxc_stream_flush(_handle.Ptr);
                    if (status != (int)ErrorCode.Success)
                    {
                        throw new MxcException((ErrorCode)status, "flushing the sandbox stream failed");
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                // Flushing an already-closed stdin is a no-op.
            }
            finally
            {
                if (added)
                {
                    _handle.DangerousRelease();
                }
            }
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _handle.Dispose();
        }
        base.Dispose(disposing);
    }
}
