// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
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
    public Task DevJsonChecksOutAndReleasesWithProvisionRecoveryInMessage() =>
        RunFixture(ExerciseLifecycle);

    private static async Task ExerciseLifecycle(Fixture fixture)
    {
        var options = new Dev.JsonOptions { Experimental = true };
        var denied = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision));
        Assert.Equal(ErrorCode.BackendUnavailable, denied.Code);
        Dev.MxcLifecycle.ValidateProvisionJson(Provision, options);
        var start = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.StartContainerJson(Request("start"), options));
        Assert.Equal(ErrorCode.UnsupportedPhase, start.Code);
        var exec = $$$"""{"version":"1.1.0-alpha","phase":"exec","sandboxId":"{{{Id}}}","process":{"commandLine":"echo must-not-run"}}""";
        var execution = await Assert.ThrowsAsync<MxcException>(
            () => Dev.MxcLifecycle.RunInContainerJsonAsync(
                exec, options, TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.UnsupportedPhase, execution.Code);
        execution = Assert.Throws<MxcException>(
            () => Dev.MxcLifecycle.SpawnInContainerJson(exec, options));
        Assert.Equal(ErrorCode.UnsupportedPhase, execution.Code);
        Assert.Empty(fixture.Requests);

        fixture.Operation = "checkout";
        fixture.Reply(200, $$"""{"sessionId":"{{Session}}","status":"Succeeded"}""");
        using var provision = JsonDocument.Parse(
            await Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision, options));
        Assert.Equal(Id, provision.RootElement.GetProperty("result").GetProperty("sandboxId").GetString());
        foreach (var phase in new[] { "stop", "deprovision" })
        {
            fixture.Operation = phase;
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
            fixture.Operation = "checkout recovery";
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
        fixture.Operation = "deprovision with renewed token";
        SetEnvironmentVariable("W365A_CP_TOKEN", "renewed-fixture-token");
        fixture.Reply(204, "");
        Dev.MxcLifecycle.DeprovisionContainerJson(Request("deprovision"), options);
        Assert.Equal(6, fixture.Requests.Count);
        var requests = fixture.Requests.ToArray();
        Assert.StartsWith($"POST /api/pools/{Pool}/sessions?api-version=2.0 ", requests[0]);
        Assert.DoesNotContain("user-type:", requests[0], StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith($"DELETE /api/sessions/{Session}?api-version=2.0 ", requests[^1]);
        Assert.Contains("Bearer renewed-fixture-token", requests[^1]);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task FixtureDiagnosticsPreserveOperationAndServerFailures(
        bool failOperation, bool failServer)
    {
        var operationError = new MxcException(ErrorCode.BackendError, "synthetic checkout failure");
        var error = await Assert.ThrowsAsync<AggregateException>(() => RunFixture(async fixture =>
        {
            fixture.Operation = "diagnostic probe";
            if (failServer)
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, fixture.Port,
                    TestContext.Current.CancellationToken);
                client.Close();
                var serverError = await Record.ExceptionAsync(() =>
                    fixture.Completion.WaitAsync(TimeSpan.FromSeconds(10),
                        TestContext.Current.CancellationToken));
                Assert.IsType<IOException>(serverError);
            }
            if (failOperation)
                throw operationError;
        }));

        Assert.Equal((failOperation ? 1 : 0) + (failServer ? 1 : 0), error.InnerExceptions.Count);
        Assert.Equal(failOperation, error.InnerExceptions.Contains(operationError));
        if (failServer)
        {
            var serverError = Assert.Single(error.InnerExceptions.OfType<IOException>());
            Assert.Contains("TLS handshake", serverError.Message);
            Assert.NotNull(serverError.InnerException);
        }
        Assert.Contains("diagnostic probe", error.Message);
        Assert.Contains("receivedHttpRequests=0", error.Message);
        Assert.DoesNotContain("fixture-token", error.ToString());
    }

    private static async Task RunFixture(Func<Fixture, Task> exercise)
    {
        var fixture = new Fixture();
        var operationError = await Record.ExceptionAsync(() => exercise(fixture));
        var fixtureError = await Record.ExceptionAsync(async () => await fixture.DisposeAsync());
        var errors = new[] { operationError, fixtureError }.OfType<Exception>().ToArray();
        if (errors.Length != 0)
            throw new AggregateException(
                $"W365 fixture failed during {fixture.Operation} (receivedHttpRequests={fixture.Requests.Count}).",
                errors);
    }

    [Fact]
    public async Task FixtureDiagnosticsIncludeNativeTlsFailure()
    {
        var error = await Assert.ThrowsAsync<AggregateException>(() => RunFixture(async fixture =>
        {
            fixture.Operation = "checkout with untrusted certificate";
            fixture.TrustUnrelatedCertificate();
            await Dev.MxcLifecycle.ProvisionContainerJsonAsync(Provision,
                new Dev.JsonOptions { Experimental = true });
        }));

        var clientError = Assert.Single(error.InnerExceptions.OfType<MxcException>());
        Assert.Equal(ErrorCode.BackendError, clientError.Code);
        Assert.Contains("checkout_transport", clientError.Message);
        Assert.Contains("fixtureTransport: native_tls=", clientError.Message);
        Assert.DoesNotContain("fixture-token", error.ToString());
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
        private readonly CancellationTokenSource cancellation = new(TimeSpan.FromSeconds(30));
        private readonly ConcurrentQueue<(int Status, string Body)> replies = new();
        private readonly Task worker;
        public ConcurrentQueue<string> Requests { get; } = new();
        public string Operation { get; set; } = "validation";
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        public Task Completion => worker;

        public Fixture()
        {
            environment = new[] { "W365A_CONTROLPLANE_URL", "W365A_CP_TOKEN",
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
            SetEnvironmentVariable("MXC_W365_TEST_CA", ca);
            SetEnvironmentVariable("MXC_W365_TEST_PORT", Port.ToString());
            worker = Serve();
        }

        public void Reply(int status, string body) => replies.Enqueue((status, body));

        public void TrustUnrelatedCertificate()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=untrusted-fixture", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var unrelated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(1));
            File.WriteAllText(Path.Combine(directory, "certificate.pem"),
                unrelated.ExportCertificatePem());
        }

        private async Task Serve()
        {
            while (!cancellation.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
                using var stream = new SslStream(client.GetStream());
                try
                {
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate,
                    }, cancellation.Token);
                }
                catch (Exception error) when (error is IOException or AuthenticationException)
                {
                    throw new IOException(
                        $"W365 fixture TLS handshake failed (hasPrivateKey={certificate.HasPrivateKey}, publicKeyAlgorithm={certificate.PublicKey.Oid.Value}).",
                        error);
                }
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var headers = new StringBuilder();
                while (await reader.ReadLineAsync(cancellation.Token) is { Length: > 0 } line)
                    headers.AppendLine(line);
                Requests.Enqueue(headers.ToString());
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
