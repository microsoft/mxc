// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Microsoft.Mxc.Samples.DenialConsumer;

/// <summary>
/// One denied access, as carried on the wire (<c>type:"denial"</c>).
/// Keys are camelCase and enum values are lowercase; this casing is a stable
/// contract guarded by tests in the MXC repository.
/// </summary>
public sealed record Denial
{
    [JsonPropertyName("path")] public string Path { get; init; } = "";

    /// <summary>One of <c>file</c>, <c>network</c>, <c>ui</c>, or <c>other</c>.</summary>
    [JsonPropertyName("resourceType")] public string ResourceType { get; init; } = "";

    /// <summary>One of <c>read</c>, <c>write</c>, <c>execute</c>, or <c>unknown</c>.</summary>
    [JsonPropertyName("accessType")] public string AccessType { get; init; } = "";

    /// <summary>The sandbox PID that hit the denial.</summary>
    [JsonPropertyName("pid")] public long Pid { get; init; }

    /// <summary>
    /// Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC) - NOT a
    /// Unix epoch. Use <see cref="DateTimeOffset.FromFileTime"/> to convert.
    /// </summary>
    [JsonPropertyName("filetime")] public ulong Filetime { get; init; }
}

/// <summary>
/// The stream terminator (<c>type:"summary"</c>); always the last record for a
/// given <c>wxc-exec</c> invocation.
/// </summary>
public sealed record Summary
{
    /// <summary>The WORKLOAD's exit code.</summary>
    [JsonPropertyName("exitCode")] public long ExitCode { get; init; }

    /// <summary>Count of unique <c>(path, accessType)</c> pairs.</summary>
    [JsonPropertyName("totalDenials")] public long TotalDenials { get; init; }

    /// <summary>
    /// <c>true</c> only when the ETW collector attached. When <c>false</c>,
    /// capture was requested but could not be activated (e.g. the shim was
    /// unreachable) - the only reliable way to distinguish "clean run" from
    /// "captured nothing", since both yield <c>totalDenials: 0</c>.
    /// </summary>
    [JsonPropertyName("captureDenialsActive")] public bool CaptureDenialsActive { get; init; }

    /// <summary><c>true</c> if the denial list reached the internal cap (partial list).</summary>
    [JsonPropertyName("deniedResourcesTruncated")] public bool DeniedResourcesTruncated { get; init; }

    /// <summary>Best-effort Toolhelp child-PID count (cross-check only).</summary>
    [JsonPropertyName("childProcessesObserved")] public long ChildProcessesObserved { get; init; }

    /// <summary>Descendants attached to the live ETW filter (authoritative descendant metric).</summary>
    [JsonPropertyName("descendantPidsCovered")] public long DescendantPidsCovered { get; init; }

    /// <summary>
    /// The full deduped denial array - the same set the live <c>denial</c> lines
    /// carried. Embedded so a consumer can perform a single race-free read after
    /// exit instead of accumulating the live records.
    /// </summary>
    [JsonPropertyName("deniedResources")] public List<Denial> DeniedResources { get; init; } = new();

    /// <summary>Pre-dedupe kernel event count; present only under <c>MXC_DENIAL_VERBOSE=1</c>.</summary>
    [JsonPropertyName("rawEventCount")] public long? RawEventCount { get; init; }
}

/// <summary>
/// Consumer-side default noise filters and NT-prefix helpers. These mirror the
/// Rust reference (<c>src/testing/wxc_e2e_tests/src/denial_consumer.rs</c>):
/// filtering is the consumer's responsibility - MXC streams the raw denials.
/// </summary>
public static class DenialFilters
{
    /// <summary>Strip the <c>\??\</c> NT DOS-device prefix so paths surface as <c>C:\…</c>.</summary>
    public static string StripNtPrefix(string path) =>
        path.StartsWith(@"\??\", StringComparison.Ordinal) ? path[4..] : path;

    private static readonly string[] LoaderExtensions =
        { ".dll", ".mui", ".mun", ".cat", ".cdf-ms", ".nls" };

    /// <summary>
    /// The two default filters the removed SDK applied: drop the
    /// AppContainer-default <c>\REGISTRY\USER\.DEFAULT\</c> probes and the OS
    /// loader's <c>System32</c> module searches. Returns <c>true</c> to keep.
    /// </summary>
    public static bool PassesDefaultFilters(Denial denial)
    {
        if (denial.Path.StartsWith(@"\REGISTRY\USER\.DEFAULT\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string p = StripNtPrefix(denial.Path);
        if (p.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase))
        {
            foreach (string ext in LoaderExtensions)
            {
                if (p.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }

        return true;
    }
}

/// <summary>
/// Incremental parser for the <c>0x1E</c>-framed NDJSON denial stream. Feed it
/// byte chunks as they arrive (in any chunking) and it raises <see cref="OnDenial"/>
/// and <see cref="OnSummary"/> per complete frame.
///
/// Each frame is <c>\x1e &lt;json&gt; \n</c>. Bytes that are not part of a frame
/// (the workload's own output, which can interleave on stderr in pipe mode) are
/// discarded - workload output never contains <c>0x1E</c>, so splitting on the
/// marker reliably demultiplexes MXC envelopes.
/// </summary>
public sealed class DenialStreamParser
{
    /// <summary>ASCII Record Separator (0x1E) that prefixes every envelope.</summary>
    public const byte Marker = 0x1E;
    private const byte Newline = (byte)'\n';

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        // Parse leniently so future additive fields do not break this consumer.
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
    };

    private readonly List<byte> _buffer = new();
    private readonly bool _applyDefaultFilters;

    /// <summary>Count of frames that began with <c>0x1E</c> but failed to parse.</summary>
    public int ParseErrors { get; private set; }

    /// <param name="applyDefaultFilters">
    /// When <c>true</c> (default), the default noise filters are applied before
    /// raising <see cref="OnDenial"/>. Pass <c>false</c> for the raw stream.
    /// </param>
    public DenialStreamParser(bool applyDefaultFilters = true)
    {
        _applyDefaultFilters = applyDefaultFilters;
    }

    /// <summary>Raised for each <c>type:"denial"</c> record (after filtering).</summary>
    public event Action<Denial>? OnDenial;

    /// <summary>Raised once for the terminating <c>type:"summary"</c> record.</summary>
    public event Action<Summary>? OnSummary;

    /// <summary>Feed a chunk of bytes; complete frames are dispatched immediately.</summary>
    public void Feed(ReadOnlySpan<byte> chunk)
    {
        foreach (byte b in chunk)
        {
            _buffer.Add(b);
        }

        Drain();
    }

    private void Drain()
    {
        while (true)
        {
            int rs = _buffer.IndexOf(Marker);
            if (rs < 0)
            {
                // No marker buffered: this is workload output (pipe mode) that
                // will never become a frame. Drop it to bound memory.
                _buffer.Clear();
                return;
            }

            if (rs > 0)
            {
                // Discard the workload bytes preceding the marker.
                _buffer.RemoveRange(0, rs);
            }

            int nl = _buffer.IndexOf(Newline, 1);
            if (nl < 0)
            {
                // Frame is incomplete; wait for more bytes.
                return;
            }

            // Body is between the marker (index 0) and the newline.
            byte[] body = _buffer.GetRange(1, nl - 1).ToArray();
            _buffer.RemoveRange(0, nl + 1);
            Dispatch(Encoding.UTF8.GetString(body));
        }
    }

    private void Dispatch(string json)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("type", out JsonElement typeElement))
            {
                ParseErrors++;
                return;
            }

            switch (typeElement.GetString())
            {
                case "denial":
                    Denial? denial = JsonSerializer.Deserialize<Denial>(json, JsonOptions);
                    if (denial is null)
                    {
                        ParseErrors++;
                        return;
                    }

                    if (!_applyDefaultFilters || DenialFilters.PassesDefaultFilters(denial))
                    {
                        OnDenial?.Invoke(denial);
                    }

                    break;

                case "summary":
                    Summary? summary = JsonSerializer.Deserialize<Summary>(json, JsonOptions);
                    if (summary is null)
                    {
                        ParseErrors++;
                        return;
                    }

                    OnSummary?.Invoke(summary);
                    break;

                default:
                    ParseErrors++;
                    break;
            }
        }
        catch (JsonException)
        {
            // A line that started with 0x1E but is not valid JSON is counted,
            // never treated as fatal.
            ParseErrors++;
        }
    }
}
