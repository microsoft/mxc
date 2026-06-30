// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.IO.Pipes;

namespace Microsoft.Mxc.Samples.DenialConsumer;

/// <summary>
/// An inbound named-pipe server that receives the <c>captureDenials</c> stream
/// out-of-band from <c>wxc-exec</c> (the <c>MXC_DENIALS_PIPE</c> transport).
///
/// This is the C# counterpart of the Rust <c>DenialPipeServer</c> in
/// <c>src/testing/wxc_e2e_tests/src/denial_consumer.rs</c>. Use it whenever the
/// workload runs under a PTY/ConPTY (so the denial bytes must not pollute the
/// terminal), or any time an application wants the denial stream on a dedicated
/// channel rather than interleaved on <c>wxc-exec</c>'s stderr.
///
/// Contract (see docs/learning-mode/consumer-guide.md §5):
/// <list type="bullet">
///   <item><description><b>Inbound only.</b> <c>wxc-exec</c> opens the pipe for
///     writing; this server reads.</description></item>
///   <item><description><b>Base name only.</b> Set <c>MXC_DENIALS_PIPE</c> to
///     <see cref="BaseName"/> with no <c>\\.\pipe\</c> prefix - both .NET and
///     <c>wxc-exec</c> prepend it.</description></item>
///   <item><description><b>Create before spawn.</b> Construct this consumer (which
///     creates the pipe) before starting <c>wxc-exec</c>, so the pipe exists when
///     the child opens it.</description></item>
///   <item><description><b>Fallback awareness.</b> If <c>wxc-exec</c> cannot open the
///     pipe it falls back to stderr; the client may therefore never connect. Cancel
///     <see cref="RunAsync"/> once the child has exited so a never-connected accept
///     is released.</description></item>
/// </list>
/// </summary>
public sealed class DenialPipeConsumer : IDisposable
{
    private readonly NamedPipeServerStream _server;
    private readonly DenialStreamParser _parser;

    /// <summary>
    /// Creates the named pipe immediately so it exists before <c>wxc-exec</c> is
    /// spawned. Set <c>MXC_DENIALS_PIPE</c> to <see cref="BaseName"/>.
    /// </summary>
    /// <param name="applyDefaultFilters">
    /// When <c>true</c> (default), the default noise filters are applied before
    /// raising <see cref="DenialReceived"/>.
    /// </param>
    /// <param name="baseName">
    /// Optional explicit pipe base name. When omitted a unique name is generated.
    /// </param>
    public DenialPipeConsumer(bool applyDefaultFilters = true, string? baseName = null)
    {
        BaseName = baseName ?? $"mxc-denials-{Guid.NewGuid():N}";

        // PipeDirection.In: wxc-exec writes, we read. maxNumberOfServerInstances
        // is 1 because exactly one wxc-exec invocation connects. Constructing the
        // stream creates the pipe in the object namespace right now.
        _server = new NamedPipeServerStream(
            BaseName,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 64 * 1024,
            outBufferSize: 0);

        _parser = new DenialStreamParser(applyDefaultFilters);
        _parser.OnDenial += d => DenialReceived?.Invoke(d);
        _parser.OnSummary += s =>
        {
            FinalSummary = s;
            SummaryReceived?.Invoke(s);
        };
    }

    /// <summary>
    /// The pipe base name to assign to <c>MXC_DENIALS_PIPE</c> (no <c>\\.\pipe\</c>
    /// prefix).
    /// </summary>
    public string BaseName { get; }

    /// <summary>The terminating summary, once received (otherwise <c>null</c>).</summary>
    public Summary? FinalSummary { get; private set; }

    /// <summary>Number of unparsable <c>0x1E</c> frames seen.</summary>
    public int ParseErrors => _parser.ParseErrors;

    /// <summary>Raised live for each denial as it arrives (after filtering).</summary>
    public event Action<Denial>? DenialReceived;

    /// <summary>Raised once for the terminating summary record.</summary>
    public event Action<Summary>? SummaryReceived;

    /// <summary>
    /// Accepts the single <c>wxc-exec</c> connection and reads the stream to EOF,
    /// dispatching <see cref="DenialReceived"/> / <see cref="SummaryReceived"/> as
    /// frames arrive. Returns when the client disconnects (normal end of stream)
    /// or when <paramref name="cancellationToken"/> is canceled (e.g. the child
    /// fell back to stderr and never connected).
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // No client ever connected (wxc-exec fell back to stderr, or the run
            // ended first). Nothing to read.
            return;
        }

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
                // EOF: the client disconnected. The summary frame should already
                // have been dispatched before this point.
                return;
            }

            _parser.Feed(buffer.AsSpan(0, read));
        }
    }

    public void Dispose() => _server.Dispose();
}
