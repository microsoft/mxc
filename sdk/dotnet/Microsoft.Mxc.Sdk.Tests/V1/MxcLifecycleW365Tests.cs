// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
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
            Assert.Equal(knownId, error.Message.Contains(Id, StringComparison.Ordinal));
            Assert.Equal(knownId, error.Message.Contains("sandboxId", StringComparison.Ordinal));
            Assert.DoesNotContain("must-not-surface", error.Message);
            Assert.DoesNotContain("fixture-token", error.Message);
        }
        Environment.SetEnvironmentVariable("W365A_CP_TOKEN", "renewed-fixture-token");
        fixture.Reply(204, "");
        Dev.MxcLifecycle.DeprovisionContainerJson(Request("deprovision"), options);
        Assert.Equal(6, fixture.Requests.Count);
        var requests = fixture.Requests.ToArray();
        Assert.StartsWith($"POST /api/pools/{Pool}/sessions?api-version=2.0 ", requests[0]);
        Assert.DoesNotContain("user-type:", requests[0], StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith($"DELETE /api/sessions/{Session}?api-version=2.0 ", requests[^1]);
        Assert.Contains("Bearer renewed-fixture-token", requests[^1]);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly Dictionary<string, string?> environment;
        private readonly string directory = Path.Combine(Path.GetTempPath(), $"mxc-w365-{Guid.NewGuid():N}");
        private readonly X509Certificate2 certificate;
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource cancellation = new(TimeSpan.FromSeconds(30));
        private readonly ConcurrentQueue<(int Status, string Body)> replies = new();
        private readonly Task worker;
        public ConcurrentQueue<string> Requests { get; } = new();

        public Fixture()
        {
            environment = new[] { "W365A_CONTROLPLANE_URL", "W365A_CP_TOKEN",
                "MXC_W365_TEST_CA", "MXC_W365_TEST_PORT" }
                .ToDictionary(key => key, Environment.GetEnvironmentVariable);
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
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
            Environment.SetEnvironmentVariable("W365A_CONTROLPLANE_URL", "localhost");
            Environment.SetEnvironmentVariable("W365A_CP_TOKEN", "fixture-token");
            Environment.SetEnvironmentVariable("MXC_W365_TEST_CA", ca);
            Environment.SetEnvironmentVariable("MXC_W365_TEST_PORT",
                ((IPEndPoint)listener.LocalEndpoint).Port.ToString());
            worker = Serve();
        }

        public void Reply(int status, string body) => replies.Enqueue((status, body));

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
                Assert.True(replies.TryDequeue(out var reply), "unexpected W365 service request");
                var response = Encoding.UTF8.GetBytes(
                    $"HTTP/1.1 {reply.Status} Fixture\r\nContent-Length: {Encoding.UTF8.GetByteCount(reply.Body)}\r\nConnection: close\r\n\r\n{reply.Body}");
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
                    Environment.SetEnvironmentVariable(key, value);
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
