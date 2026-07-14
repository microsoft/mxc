// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Mxc.Sdk.Native;

namespace Microsoft.Mxc.Sdk;

/// <summary>
/// A live sandboxed process spawned by <see cref="MxcSandbox.Spawn(SandboxPolicy, string)"/>.
/// </summary>
/// <remarks>
/// <para>
/// Stream the child's stdio with <see cref="StandardInput"/> /
/// <see cref="StandardOutput"/> / <see cref="StandardError"/>, wait for it with
/// <see cref="Wait"/> / <see cref="WaitAsync"/>, or kill it (and its whole tree)
/// with <see cref="Kill"/>. Each standard stream is a separate object and may be
/// read/written concurrently on different threads.
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
/// called from another thread while <see cref="WaitAsync"/> is in flight. The
/// standard streams refcount their native handle, so reading/writing a stream
/// concurrently with <see cref="Dispose"/> is safe — an in-flight read/write
/// completes and the handle is freed afterwards, never underneath it.
/// </para>
/// <para>
/// <b>Disposal.</b> <see cref="Dispose"/> kills the child tree if it is still
/// running and releases the native handles (draining and awaiting any internal
/// readers first). If it is skipped, the finalizers on the underlying
/// <see cref="System.Runtime.InteropServices.SafeHandle"/>s still reclaim the
/// native handles and kill the child.
/// </para>
/// </remarks>
public sealed class MxcSandboxProcess : IDisposable
{
    // Poll cadence bounds for the try_wait-based wait loop: start short so a
    // quick child returns promptly, back off to a cap so a long-running child
    // does not spin a core.
    private static readonly TimeSpan MinPollInterval = TimeSpan.FromMilliseconds(1);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromMilliseconds(50);

    private readonly object _controlLock = new();
    private readonly MxcSandboxHandle _handle;
    private bool _disposed;

    private MxcStdinStream? _stdin;
    private MxcReadPipeStream? _stdout;
    private MxcReadPipeStream? _stderr;
    private bool _stdinTaken;
    private bool _stdoutTaken;
    private bool _stderrTaken;

    private readonly List<Task> _drainTasks = new();

    internal MxcSandboxProcess(MxcSandboxHandle handle)
    {
        _handle = handle;
    }

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
    public Stream? StandardOutput => TakeReadStream(ref _stdoutTaken, ref _stdout, stdout: true);

    /// <summary>
    /// The child's stderr as a readable <see cref="Stream"/>. Returns
    /// <see langword="null"/> if stderr was not piped.
    /// </summary>
    public Stream? StandardError => TakeReadStream(ref _stderrTaken, ref _stderr, stdout: false);

    private Stream? TakeReadStream(ref bool taken, ref MxcReadPipeStream? slot, bool stdout)
    {
        lock (_controlLock)
        {
            ThrowIfDisposed();
            if (!taken)
            {
                taken = true;
                unsafe
                {
                    var s = stdout
                        ? NativeMethods.mxc_sandbox_take_stdout(_handle.Ptr)
                        : NativeMethods.mxc_sandbox_take_stderr(_handle.Ptr);
                    slot = s is null ? null : new MxcReadPipeStream(MxcReadStreamHandle.FromRaw(s));
                }
            }
            return slot;
        }
    }

    /// <summary>
    /// Block until the child exits (honouring the policy's
    /// <see cref="SandboxPolicy.TimeoutMs"/>), draining any standard stream you
    /// did not take so the child cannot block on a full pipe.
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

    private SandboxWaitResult WaitCore(CancellationToken cancellationToken)
    {
        EnsureDrainUntaken();

        var poll = MinPollInterval;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int status;
            int exit = 0;
            int running = 1;
            lock (_controlLock)
            {
                ThrowIfDisposed();
                unsafe
                {
                    status = NativeMethods.mxc_sandbox_try_wait(_handle.Ptr, &exit, &running);
                }
            }

            if (status != (int)ErrorCode.Success)
            {
                throw new MxcException((ErrorCode)status, "waiting on the sandbox failed");
            }
            if (running == 0)
            {
                return new SandboxWaitResult { ExitCode = exit, TimedOut = false };
            }

            // try_wait cannot report a timeout (only exited / still-running), so
            // once the child is gone we return Exited. A policy timeout is
            // enforced natively by killing the tree, which try_wait then sees as
            // an exit. Callers that need the timeout distinction should use the
            // blocking WaitBlocking() path.
            cancellationToken.WaitHandle.WaitOne(poll);
            var next = poll + poll;
            poll = next > MaxPollInterval ? MaxPollInterval : next;
        }
    }

    /// <summary>
    /// Block until the child exits using the native blocking wait, which reports
    /// a policy timeout distinctly (<see cref="SandboxWaitResult.TimedOut"/>).
    /// Unlike <see cref="Wait"/> this cannot be interrupted by a concurrent
    /// <see cref="Kill"/> — it holds the control lock for the whole wait — so use
    /// it only when you will not race a kill.
    /// </summary>
    public SandboxWaitResult WaitBlocking()
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
        catch
        {
            // On cancellation/failure, still observe the reader tasks so they do
            // not run detached. The stream handles are refcounted, so this is
            // safe regardless of when the caller disposes.
            await Task.WhenAll(SwallowAsync(stdoutTask), SwallowAsync(stderrTask))
                .ConfigureAwait(false);
            throw;
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
            DrainIfUntaken(ref _stdoutTaken, ref _stdout, stdout: true);
            DrainIfUntaken(ref _stderrTaken, ref _stderr, stdout: false);
        }
    }

    private void DrainIfUntaken(ref bool taken, ref MxcReadPipeStream? slot, bool stdout)
    {
        if (taken)
        {
            return;
        }
        taken = true;
        unsafe
        {
            var s = stdout
                ? NativeMethods.mxc_sandbox_take_stdout(_handle.Ptr)
                : NativeMethods.mxc_sandbox_take_stderr(_handle.Ptr);
            if (s is null)
            {
                return;
            }
            slot = new MxcReadPipeStream(MxcReadStreamHandle.FromRaw(s));
        }
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

/// <summary>Readable <see cref="Stream"/> over a native <c>MxcReadStream</c> (child stdout/stderr).</summary>
internal sealed class MxcReadPipeStream : Stream
{
    private readonly MxcReadStreamHandle _handle;

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
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        if (count == 0)
        {
            return 0;
        }

        // Hold a reference across the blocking native read so a concurrent
        // Dispose cannot free the handle underneath it (the SafeHandle defers
        // the actual free until every reference is released).
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
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

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

    public override void Flush()
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
