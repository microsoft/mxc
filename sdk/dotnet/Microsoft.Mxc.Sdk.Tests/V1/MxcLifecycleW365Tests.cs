// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

public class MxcLifecycleW365Tests
{
    private const string Pool = "11111111-1111-1111-1111-111111111111";
    private const string Session = "22222222-2222-2222-2222-222222222222";
    private const string Id = $"w365:{Pool}:{Session}";
    private const string Provision =
        $$$$"""{"version":"1.1.0-alpha","phase":"provision","containment":"w365_agents","w365Agents":{"provision":{"poolId":"{{{{Pool}}}}"}}}""";

    private static string Request(string phase) =>
        $$"""{"version":"1.1.0-alpha","phase":"{{phase}}","sandboxId":"{{Id}}"}""";

    [Fact]
    public async Task DevJsonChecksOutAndReleasesWithProvisionRecoveryInMessage()
    {
        await using var fixture = new Fixture();
        var options = new Dev.JsonOptions { Experimental = true };
        var denied = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision));
        Assert.Equal(ErrorCode.BackendUnavailable, denied.Code);
        Dev.MxcLifecycle.ValidateProvisionJson(Provision, options);
        var start = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(
                Request("start").Replace(Id, "w365:invalid"), options));
        Assert.Equal(ErrorCode.MalformedId, start.Code);
        const string exec = """{"version":"1.1.0-alpha","phase":"exec","sandboxId":"w365:invalid","process":{"commandLine":"echo must-not-run"}}""";
        var execution = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                exec, options, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.MalformedId, execution.Code);
        execution = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(exec, options));
        Assert.Equal(ErrorCode.MalformedId, execution.Code);
        Assert.Empty(fixture.Requests);

        fixture.Reply(200, $$"""{"sessionId":"{{Session}}","status":"Succeeded"}""");
        using var provision = JsonDocument.Parse(
            await Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision, options));
        Assert.Equal(Id, provision.RootElement.GetProperty("result").GetProperty("sandboxId").GetString());
        foreach (var phase in new[] { "stop", "deprovision" })
        {
            fixture.Reply(204, "");
            var result = phase == "stop"
                ? Dev.MxcLifecycle.StopContainerJson(Request(phase), options)
                : await Dev.MxcLifecycle.DeprovisionContainerJsonAsync(Request(phase), options);
            using var released = JsonDocument.Parse(result);
            Assert.True(released.RootElement.GetProperty("result").GetProperty("metadata")
                .GetProperty("releaseRequested").GetBoolean());
        }

        foreach (var knownId in new[] { true, false })
        {
            fixture.Reply(500, $$"""{"sessionId":"{{(knownId ? Session : "invalid")}}","connectivityUrl":"https://example.invalid/?ticket=must-not-surface"}""");
            var error = await Assert.ThrowsAsync<MxcException>(
                () => Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision, options));
            Assert.Equal(ErrorCode.BackendError, error.Code);
            Assert.Contains("provision_timeout", error.Message);
            var clientRequestId = fixture.Requests.Last().Split('\n')
                .Single(header => header.StartsWith("x-ms-client-request-id:", StringComparison.OrdinalIgnoreCase))
                .Split(':', 2)[1].Trim();
            Assert.Contains($"clientRequestId={clientRequestId}", error.Message);
            Assert.Contains("requestId=fixture-request", error.Message);
            Assert.Contains("possiblySucceeded=true", error.Message);
            Assert.Equal(knownId, error.Message.Contains(Id, StringComparison.Ordinal));
            Assert.Equal(knownId, error.Message.Contains("sandboxId", StringComparison.Ordinal));
            Assert.DoesNotContain("must-not-surface", error.Message);
            Assert.DoesNotContain("fixture-token", error.Message);
        }
        SetEnvironmentVariable("W365A_CP_TOKEN", "renewed-fixture-token");
        fixture.Reply(204, "");
        Dev.MxcLifecycle.DeprovisionContainerJson(Request("deprovision"), options);
        Assert.Equal(6, fixture.Requests.Count);
        var requests = fixture.Requests.ToArray();
        Assert.StartsWith($"POST /api/pools/{Pool}/sessions?api-version=3.0 ", requests[0]);
        Assert.DoesNotContain("user-type:", requests[0], StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith($"DELETE /api/sessions/{Session}?api-version=2.0 ", requests[^1]);
        Assert.Contains("Bearer renewed-fixture-token", requests[^1]);
    }

    [Fact]
    public async Task DevJsonStartsCapturesAndStreamsOnTheSameReservation()
    {
        await using var fixture = new Fixture(TimeSpan.FromSeconds(60));
        var options = new Dev.JsonOptions { Experimental = true };
        var ct = TestContext.Current.CancellationToken;
        fixture.Reply(200, """{"status":"Live"}""");
        fixture.Reply(200, """{"status":"Ready"}""");
        using var ready = JsonDocument.Parse(
            await Dev.MxcLifecycle.StartContainerJsonAsync(Request("start"), options));
        Assert.Equal("Ready", ready.RootElement.GetProperty("result").GetProperty("metadata")
            .GetProperty("status").GetString());
        var exec = $$$"""{"version":"1.1.0-alpha","phase":"exec","sandboxId":"{{{Id}}}","process":{"commandLine":"cmd.exe /c fixture","timeout":30000}}""";

        fixture.Exec(async stream =>
        {
            Assert.Empty(await Fixture.ReadStdin(stream, ct));
            await Fixture.Frame(stream, 0x12, Encoding.UTF8.GetBytes("captured-output"), ct);
            await Fixture.Frame(stream, 0x13, Encoding.UTF8.GetBytes("captured-error"), ct);
            await Fixture.Frame(stream, 0x14, """{"code":-1}"""u8.ToArray(), ct);
        });
        var captured = await Dev.MxcLifecycle.RunInContainerJsonAsync(exec, options, ct);
        Assert.Equal(-1, captured.ExitCode);
        Assert.Equal("captured-output", captured.Stdout);
        Assert.Equal("captured-error", captured.Stderr);

        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Exec(async stream =>
        {
            Assert.Equal(new byte[] { 0, 255, 65 }, await Fixture.ReadStdin(stream, ct));
            await release.Task.WaitAsync(ct);
            await Fixture.Frame(stream, 0x12, new byte[] { 255, 0, 66 }, ct);
            await Fixture.Frame(stream, 0x13, new byte[] { 128, 0, 67 }, ct);
            await Fixture.Frame(stream, 0x14, """{"code":7}"""u8.ToArray(), ct);
        });
        using (var pipe = await Dev.MxcLifecycle.SpawnInContainerJsonAsync(exec, options, ct))
        {
            Assert.False(pipe.TryGetExitCode(out _), "spawn must return before Exit");
            using (var stdin = pipe.StandardInput!)
                await stdin.WriteAsync(new byte[] { 0, 255, 65 }, ct);
            var output = pipe.WaitForExitWithOutputAsync(ct);
            release.SetResult();
            var (outcome, stdout, stderr) = await output;
            Assert.Equal(7, outcome.ExitCode);
            Assert.Equal(new byte[] { 255, 0, 66 }, stdout);
            Assert.Equal(new byte[] { 128, 0, 67 }, stderr);
        }
        fixture.Exec(async stream =>
        {
            Assert.Empty(await Fixture.ReadStdin(stream, ct));
            await Fixture.Frame(stream, 0x12, "partial"u8.ToArray(), ct);
            await Fixture.Frame(stream, 0x15, """{"code":"failed","message":"fixture failure"}"""u8.ToArray(), ct);
        });
        var error = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(exec, options, ct));
        Assert.Equal(ErrorCode.BackendError, error.Code);
        Assert.False(string.IsNullOrWhiteSpace(error.Message));

        var timedExec = exec.Replace("\"timeout\":30000", "\"timeout\":1000");
        foreach (var live in new[] { false, true })
        {
            fixture.Exec(async stream =>
            {
                Assert.Empty(await Fixture.ReadStdin(stream, ct));
                // The service drains output after enforcing the guest runtime limit.
                await Task.Delay(1200, ct);
                await Fixture.Frame(stream, 0x12, "drained-output"u8.ToArray(), ct);
                await Fixture.Frame(stream, 0x13, "drained-error"u8.ToArray(), ct);
                await Fixture.Frame(stream, 0x14, """{"code":124}"""u8.ToArray(), ct);
            }, expectedTimeoutMs: 1000);
            if (live)
            {
                using var pipe = await Dev.MxcLifecycle.SpawnInContainerJsonAsync(timedExec, options, ct);
                pipe.StandardInput!.Dispose();
                var (outcome, stdout, stderr) = await pipe.WaitForExitWithOutputAsync(ct);
                Assert.Equal(124, outcome.ExitCode);
                Assert.False(outcome.TimedOut);
                Assert.Equal("drained-output", Encoding.UTF8.GetString(stdout));
                Assert.Equal("drained-error", Encoding.UTF8.GetString(stderr));
            }
            else
            {
                var result = await Dev.MxcLifecycle.RunInContainerJsonAsync(timedExec, options, ct);
                Assert.Equal(124, result.ExitCode);
                Assert.False(result.TimedOut);
                Assert.Equal("drained-output", result.Stdout);
                Assert.Equal("drained-error", result.Stderr);
            }
        }

        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Exec(async stream =>
        {
            Assert.Empty(await Fixture.ReadStdin(stream, ct));
            await finish.Task.WaitAsync(ct);
        }, expectedTimeoutMs: 1000);
        var started = Stopwatch.StartNew();
        try
        {
            error = await Assert.ThrowsAsync<MxcException>(
                () => Dev.MxcLifecycle.RunInContainerJsonAsync(timedExec, options, ct));
            Assert.Equal(ErrorCode.BackendError, error.Code);
            Assert.InRange(started.Elapsed, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(45));
        }
        finally
        {
            finish.SetResult();
        }
        Assert.Equal(8, fixture.Requests.Count);
        Assert.All(fixture.Requests, request =>
            Assert.StartsWith($"GET /computers/{Session}/", request));
    }

    // On Unix, .NET caches environment updates without changing libc's environment.
    private static void SetEnvironmentVariable(string name, string? value)
    {
        Environment.SetEnvironmentVariable(name, value);
        if (!OperatingSystem.IsWindows())
            SetNativeEnvironmentVariable(name, value);
    }

    private static void SetNativeEnvironmentVariable(string name, string? value)
    {
        var result = value is null ? UnsetEnv(name) : SetEnv(name, value, 1);
        if (result != 0)
            throw new Win32Exception(Marshal.GetLastPInvokeError(),
                $"Could not update native environment variable {name}");
    }

    [DllImport("libc", EntryPoint = "getenv")]
    private static extern IntPtr GetEnv([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport("libc", EntryPoint = "setenv", SetLastError = true)]
    private static extern int SetEnv(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string value, int overwrite);

    [DllImport("libc", EntryPoint = "unsetenv", SetLastError = true)]
    private static extern int UnsetEnv([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly Dictionary<string, (string? Managed, string? Native)> environment;
        private readonly string directory = Path.Combine(Path.GetTempPath(), $"mxc-w365-{Guid.NewGuid():N}");
        private readonly X509Certificate2 certificate;
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource cancellation;
        private readonly ConcurrentQueue<(int Status, string Body)> replies = new();
        private readonly ConcurrentQueue<(Func<SslStream, Task> Script, uint? TimeoutMs)> executions = new();
        private readonly Task worker;
        public ConcurrentQueue<string> Requests { get; } = new();

        public Fixture(TimeSpan? timeout = null)
        {
            cancellation = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));
            environment = new[] { "W365A_CONTROLPLANE_URL", "W365A_CP_TOKEN",
                "W365A_DP_SUFFIX", "W365A_DP_TOKEN",
                "MXC_W365_TEST_CA", "MXC_W365_TEST_PORT" }
                .ToDictionary(key => key, key => (
                    Managed: Environment.GetEnvironmentVariable(key),
                    Native: OperatingSystem.IsWindows() ? null : Marshal.PtrToStringUTF8(GetEnv(key))));
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
            // macOS requires explicit TLS server-authentication usage.
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
            using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(1));
            // SChannel needs an imported server key. Without PersistKeySet,
            // disposing this certificate also deletes its temporary key.
            var archive = generated.Export(X509ContentType.Pkcs12, "fixture-only");
#if NET10_0_OR_GREATER
            certificate = X509CertificateLoader.LoadPkcs12(
                archive, "fixture-only", X509KeyStorageFlags.UserKeySet);
#else
            certificate = new X509Certificate2(
                archive, "fixture-only", X509KeyStorageFlags.UserKeySet);
#endif
            Directory.CreateDirectory(directory);
            var ca = Path.Combine(directory, "certificate.pem");
            File.WriteAllText(ca, certificate.ExportCertificatePem());
            listener.Start();
            SetEnvironmentVariable("W365A_CONTROLPLANE_URL", "localhost");
            SetEnvironmentVariable("W365A_CP_TOKEN", "fixture-token");
            SetEnvironmentVariable("W365A_DP_SUFFIX", "localhost");
            SetEnvironmentVariable("W365A_DP_TOKEN", "synthetic-data-plane-token");
            SetEnvironmentVariable("MXC_W365_TEST_CA", ca);
            SetEnvironmentVariable("MXC_W365_TEST_PORT",
                ((IPEndPoint)listener.LocalEndpoint).Port.ToString());
            worker = Serve();
        }

        public void Reply(int status, string body) => replies.Enqueue((status, body));
        public void Exec(Func<SslStream, Task> script, uint? expectedTimeoutMs = null) =>
            executions.Enqueue((script, expectedTimeoutMs));

        public static async Task Frame(SslStream stream, byte kind, byte[] payload, CancellationToken ct)
        {
            var header = new byte[5];
            header[0] = kind;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1), (uint)payload.Length);
            await stream.WriteAsync(header, ct);
            await stream.WriteAsync(payload, ct);
            await stream.FlushAsync(ct);
        }

        private static async Task<(byte Kind, byte[] Payload)> ReadFrame(SslStream stream, CancellationToken ct)
        {
            var header = new byte[5];
            await stream.ReadExactlyAsync(header, ct);
            var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
            Assert.True(length <= 65536);
            var payload = new byte[length];
            await stream.ReadExactlyAsync(payload, ct);
            return (header[0], payload);
        }

        public static async Task<byte[]> ReadStdin(SslStream stream, CancellationToken ct)
        {
            using var bytes = new MemoryStream();
            while (true)
            {
                var (kind, payload) = await ReadFrame(stream, ct);
                if (kind == 3)
                {
                    Assert.Empty(payload);
                    return bytes.ToArray();
                }
                Assert.Equal(2, kind);
                bytes.Write(payload);
            }
        }

        private async Task Serve()
        {
            while (!cancellation.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
                using var stream = new SslStream(client.GetStream());
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                }, cancellation.Token);
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var headers = new StringBuilder();
                while (await reader.ReadLineAsync(cancellation.Token) is { Length: > 0 } line)
                    headers.AppendLine(line);
                Requests.Enqueue(headers.ToString());
                if (headers.ToString().Contains("/microsoft.exec?api-version=1.0", StringComparison.Ordinal))
                {
                    Assert.Contains("Upgrade: exec", headers.ToString(), StringComparison.OrdinalIgnoreCase);
                    Assert.True(executions.TryDequeue(out var execution), "unexpected Exec request");
                    await stream.WriteAsync("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\n\r\n"u8.ToArray(), cancellation.Token);
                    await stream.FlushAsync(cancellation.Token);
                    var (kind, payload) = await ReadFrame(stream, cancellation.Token);
                    Assert.Equal(1, kind);
                    using var start = JsonDocument.Parse(payload);
                    Assert.Equal("raw", start.RootElement.GetProperty("shell").GetString());
                    Assert.Equal("pipe", start.RootElement.GetProperty("mode").GetString());
                    if (execution.TimeoutMs is { } timeoutMs)
                        Assert.Equal(timeoutMs, start.RootElement.GetProperty("timeoutMs").GetUInt32());
                    await Frame(stream, 0x11, """{"pid":123}"""u8.ToArray(), cancellation.Token);
                    await execution.Script(stream);
                    continue;
                }
                Assert.True(replies.TryDequeue(out var reply), "unexpected W365 service request");
                var response = Encoding.UTF8.GetBytes(
                    $"HTTP/1.1 {reply.Status} Fixture\r\nContent-Length: {Encoding.UTF8.GetByteCount(reply.Body)}\r\nx-ms-request-id: fixture-request\r\nConnection: close\r\n\r\n{reply.Body}");
                await stream.WriteAsync(response, cancellation.Token);
                await stream.FlushAsync(cancellation.Token);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await cancellation.CancelAsync();
            try
            {
                await worker;
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
            }
            finally
            {
                listener.Stop();
                certificate.Dispose();
                cancellation.Dispose();
                foreach (var (key, value) in environment)
                {
                    if (!OperatingSystem.IsWindows())
                        SetNativeEnvironmentVariable(key, value.Native);
                    Environment.SetEnvironmentVariable(key, value.Managed);
                }
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
