// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.IO.Pipes;

namespace Microsoft.Mxc.Samples.DenialConsumer;

/// <summary>
/// An anonymous-pipe consumer that receives the <c>captureDenials</c> stream
/// out-of-band from <c>wxc-exec</c> (the <c>--denials-fd</c> transport).
///
/// This is the C# counterpart of the Rust <c>DenialAnonPipe</c> in
/// <c>src/testing/wxc_e2e_tests/src/denial_consumer.rs</c>. Use it whenever the
/// workload runs under a PTY/ConPTY (so the denial bytes must not pollute the
/// terminal), or any time an application wants the denial stream on a dedicated
/// channel rather than interleaved on <c>wxc-exec</c>'s stderr.
///
/// Contract (see docs/learning-mode/consumer-guide.md §5):
/// <list type="bullet">
///   <item><description><b>Inbound only.</b> <c>wxc-exec</c> inherits the pipe's
///     write handle and writes to it; this consumer holds the read end.</description></item>
///   <item><description><b>Pass the handle.</b> Pass <see cref="ClientHandle"/> to
///     <c>wxc-exec</c> as <c>--denials-fd &lt;handle&gt;</c>. The client (write)
///     handle is created inheritable so the spawned child inherits it at the same
///     numeric value.</description></item>
///   <item><description><b>Inheritance.</b> Spawn <c>wxc-exec</c> with handle
///     inheritance enabled (redirect at least one standard stream so .NET sets
///     <c>bInheritHandles=TRUE</c>). The read end is never handed to the child.</description></item>
///   <item><description><b>Release after spawn.</b> Call
///     <see cref="DisposeLocalCopyOfClientHandle"/> right after starting
///     <c>wxc-exec</c> so the read end observes EOF once the child exits — EOF
///     requires every write handle (the child's and ours) to be closed.</description></item>
///   <item><description><b>Fallback awareness.</b> If <c>wxc-exec</c> cannot adopt
///     the handle it falls back to stderr; in that case no summary arrives on the
///     pipe. Inspect <c>wxc-exec</c>'s stderr for a fallback warning.</description></item>
/// </list>
/// </summary>
public sealed class DenialPipeConsumer : IDisposable
{
    private readonly AnonymousPipeServerStream _server;
    private readonly DenialStreamParser _parser;

    /// <summary>
    /// Creates an anonymous pipe immediately so its inheritable write handle
    /// exists before <c>wxc-exec</c> is spawned. Pass <see cref="ClientHandle"/>
    /// to the child as <c>--denials-fd &lt;handle&gt;</c>.
    /// </summary>
    /// <param name="applyDefaultFilters">
    /// When <c>true</c> (default), the default noise filters are applied before
    /// raising <see cref="DenialReceived"/>.
    /// </param>
    public DenialPipeConsumer(bool applyDefaultFilters = true)
    {
        // PipeDirection.In: wxc-exec writes, we read. The client (write) handle is
        // created Inheritable so the spawned wxc-exec inherits it; its numeric
        // value is what we pass as --denials-fd. Anonymous pipes have no name in
        // the object namespace, so no other process can open or squat the channel.
        _server = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        ClientHandle = _server.GetClientHandleAsString();

        _parser = new DenialStreamParser(applyDefaultFilters);
        _parser.OnDenial += d => DenialReceived?.Invoke(d);
        _parser.OnSummary += s =>
        {
            FinalSummary = s;
            SummaryReceived?.Invoke(s);
        };
    }

    /// <summary>
    /// The inherited write-handle value to pass to <c>wxc-exec</c> as
    /// <c>--denials-fd &lt;handle&gt;</c>.
    /// </summary>
    public string ClientHandle { get; }

    /// <summary>The terminating summary, once received (otherwise <c>null</c>).</summary>
    public Summary? FinalSummary { get; private set; }

    /// <summary>Number of unparsable <c>0x1E</c> frames seen.</summary>
    public int ParseErrors => _parser.ParseErrors;

    /// <summary>Raised live for each denial as it arrives (after filtering).</summary>
    public event Action<Denial>? DenialReceived;

    /// <summary>Raised once for the terminating summary record.</summary>
    public event Action<Summary>? SummaryReceived;

    /// <summary>
    /// Releases the launcher's own copy of the inheritable client (write) handle.
    /// Must be called <b>after</b> <c>wxc-exec</c> is started (so it inherits the
    /// handle) and before <see cref="RunAsync"/> can observe EOF: the read end
    /// only sees EOF once every write handle — the child's and ours — is closed.
    /// </summary>
    public void DisposeLocalCopyOfClientHandle() => _server.DisposeLocalCopyOfClientHandle();

    /// <summary>
    /// Reads the stream to EOF, dispatching <see cref="DenialReceived"/> /
    /// <see cref="SummaryReceived"/> as frames arrive. Returns when the child
    /// closes its write end (normal end of stream) or when
    /// <paramref name="cancellationToken"/> is canceled (e.g. the child fell back
    /// to stderr and never wrote anything).
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        byte[] buffer = new byte[8192];
        while (true)
        {
            int read;
            try
            {
                read = await _server.ReadAsync(buffer.AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (read == 0)
            {
                // EOF: every write handle is closed. The summary frame should
                // already have been dispatched before this point.
                return;
            }

            _parser.Feed(buffer.AsSpan(0, read));
        }
    }

    public void Dispose() => _server.Dispose();
}
