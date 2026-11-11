// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace W365SdkTestApp;

internal interface IStatusProbe
{
    Task<JsonObject> FetchAsync(Configuration config, string sessionId, string token);
}

internal sealed class StatusProbe(HttpMessageHandler? handler = null) : IStatusProbe
{
    public async Task<JsonObject> FetchAsync(Configuration config, string sessionId, string token)
    {
        var parts = config.Identity(sessionId).Split(':');
        using var client = new HttpClient(handler ?? new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
        });
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://{parts[1]}.{config.DataPlaneSuffix}/computers/{parts[2]}/status?api-version=1.0");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("x-ms-computerId", parts[2]);
        var clientRequestId = Guid.NewGuid().ToString("D");
        request.Headers.Add("x-ms-client-request-id", clientRequestId);
        JsonElement? context = null;
        try
        {
            using var response = await client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellation.Token).ConfigureAwait(false);
            context = JsonSerializer.SerializeToElement(new JsonObject
            {
                ["httpStatus"] = (int)response.StatusCode,
                ["clientRequestId"] = clientRequestId,
                ["requestId"] = response.Headers.TryGetValues("x-ms-request-id", out var ids)
                    ? ids.FirstOrDefault() : null,
            });
            if (response.StatusCode != HttpStatusCode.OK)
                throw new ToolException("status_http_error",
                    $"Status request failed (HTTP {(int)response.StatusCode}); no command was submitted.", context);
            await response.Content.LoadIntoBufferAsync(1024 * 1024, cancellation.Token).ConfigureAwait(false);
            using var document = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(cancellation.Token).ConfigureAwait(false));
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("status", out var state) ||
                state.ValueKind != JsonValueKind.String ||
                state.GetString() is not ("Waiting" or "Live" or "Ready"))
                throw new ToolException("invalid_status_response",
                    "Status response did not contain a recognized status; response text suppressed.", context);
            var result = Application.SafeDetails(context)!;
            result["status"] = state.GetString();
            result["checkedAtUtc"] = DateTimeOffset.UtcNow.ToString("O");
            return result;
        }
        catch (OperationCanceledException)
        {
            throw new ToolException("status_timeout", "Status request exceeded its 30-second budget.", context);
        }
        catch (HttpRequestException)
        {
            throw new ToolException(context is null ? "status_transport" : "status_response",
                "Status transport or bounded response read failed; exception text suppressed.", context);
        }
        catch (JsonException)
        {
            throw new ToolException("invalid_status_response",
                "Status response was not valid JSON; response text suppressed.", context);
        }
    }
}
