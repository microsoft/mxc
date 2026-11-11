// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Identity.Client;
using Microsoft.Mxc.Sdk.V1;

namespace W365SdkTestApp;

internal static class Application
{
    internal static async Task<int> RunAsync(string[] args, IAuthentication? authentication = null, ISdk? sdk = null)
    {
        if (args is ["--help"] or ["-h"])
        {
            Console.WriteLine("""
                W365SdkTestApp run --command <Windows command line> [--session-id <opaque MXC ID>]
                W365SdkTestApp release --session-id <opaque MXC ID>
                Options: --config <path>, --receipt-path <path>, --working-directory <guest path>,
                         --timeout-ms <integer>, --login-hint <hint>, --expected-user-object-id <guid>,
                         --force-sign-in, --dry-run
                Run without an ID checks out once. Sessions are retained until explicit release.
                --dry-run validates with synthetic credentials; no sign-in/cache/service access.
                """);
            return 0;
        }
        string? id = null;
        string? receipt = null;
        Journal? journal = null;
        FileStream? receiptLock = null;
        Configuration? config = null;
        var submitted = false;
        var created = false;
        JsonObject? output = null;
        try
        {
            if (!OperatingSystem.IsWindows())
                throw new ToolException("windows_required", "The test app requires Windows protected authentication.");
            var options = Arguments.Parse(args);
            config = Configuration.Read(options.ConfigPath, options.Operation == "release");
            id = options.SessionId is null ? null : config.Identity(options.SessionId);
            receipt = options.ReceiptPath ?? Path.Combine(Path.GetTempPath(), $"mxc-w365-sdk-{Guid.NewGuid():N}.json");
            sdk ??= new Sdk();
            if (!options.DryRun)
            {
                Console.Error.WriteLine($"Token-free receipt: {receipt}");
                receiptLock = new FileStream(receipt + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                if (File.Exists(receipt))
                {
                    if (id is null)
                        throw new ToolException("receipt_exists", "Never reuse an existing receipt for another checkout.");
                    journal = Journal.Read(receipt, config, options);
                }
            }
            var phases = options.Operation == "release" ? new[] { "deprovision" } :
                id is null ? ["provision", "start", "exec"] : ["start", "exec"];
            using (var environment = new SdkEnvironment(config, "synthetic-preflight-token"))
            {
                foreach (var phase in phases)
                    sdk.Call(phase, Request(config, options, phase, id ?? $"w365:{config.PoolId}:11111111-1111-1111-1111-111111111111",
                        options.ExpectedUserObjectId ?? "11111111-1111-1111-1111-111111111111"), true);
            }
            if (options.DryRun)
            {
                Write(new JsonObject { ["validationOnly"] = true }, id, null);
                return 0;
            }
            authentication ??= new Authentication();
            var expectedOwner = journal?.UserObjectId ?? options.ExpectedUserObjectId;
            var credentials = await authentication.AcquireAsync(config, options, expectedOwner, false).ConfigureAwait(false);
            if (expectedOwner is not null && credentials.UserObjectId != expectedOwner)
                throw new ToolException("owner_mismatch", "Authenticated owner does not match the operation.");
            if (journal is null)
            {
                journal = new Journal
                {
                    SessionId = id, SandboxId = id, PoolId = config.PoolId, TenantId = config.TenantId,
                    ClientId = config.ClientId, UserObjectId = credentials.UserObjectId,
                    ControlPlaneHost = config.ControlPlaneHost, DataPlaneSuffix = config.DataPlaneSuffix,
                    AllocationRequestCount = id is null ? 1 : 0,
                };
                journal.Save(receipt, create: true);
            }
            created = true;
            foreach (var phase in phases)
            {
                if (credentials.ExpiresOn < DateTimeOffset.UtcNow.AddMinutes(5))
                    credentials = await authentication.AcquireAsync(config, options, journal.UserObjectId, true).ConfigureAwait(false);
                if (credentials.UserObjectId != journal.UserObjectId)
                    throw new ToolException("owner_mismatch", "Renewed credentials do not match the session owner.");
                journal.State = phase + "Submitted";
                journal.Save(receipt);
                submitted = true;
                using (var environment = new SdkEnvironment(config, credentials.AccessToken))
                    output = sdk.Call(phase, Request(config, options, phase, id, journal.UserObjectId), false);
                if (phase == "provision")
                {
                    id = config.Identity(output["sandboxId"]?.GetValue<string>() ??
                        throw new ToolException("missing_session_id", "Provision returned no MXC identity; reconcile without replay."));
                    journal.SessionId = id;
                    journal.SandboxId = id;
                    journal.Save(receipt);
                    Console.Error.WriteLine($"MXC SessionId: {id}");
                    var parts = id.Split(':');
                    if (output["metadata"] is not JsonObject metadata ||
                        metadata["poolId"]?.GetValue<string>() != parts[1] ||
                        metadata["sessionId"]?.GetValue<string>() != parts[2] ||
                        metadata["computerId"]?.GetValue<string>() != parts[2])
                        throw new ToolException("metadata_mismatch", "Provision metadata does not match the saved cleanup identity.");
                }
                if (phase == "start" && output["metadata"]?["status"]?.GetValue<string>() != "Ready")
                    throw new ToolException("not_ready", "Start did not confirm Ready; no command submitted.");
                if (phase == "deprovision")
                {
                    if (output["metadata"]?["releaseRequested"]?.GetValue<bool>() != true ||
                        output["metadata"]?["restartable"]?.GetValue<bool>() != false)
                        throw new ToolException("release_unknown", "Release acceptance was not confirmed.");
                    journal.ReleaseAccepted = true;
                }
                journal.Operations.Add(phase);
                journal.Save(receipt);
            }
            journal.State = journal.ReleaseAccepted ? "ReleaseAccepted" : "Completed";
            journal.ErrorCode = null;
            journal.ErrorDetails = null;
            journal.Save(receipt);
            Write(new JsonObject { ["result"] = output, ["releaseAccepted"] = journal.ReleaseAccepted,
                ["remoteResetConfirmed"] = false }, id, receipt);
            return output?["exitCode"]?.GetValue<int>() ?? 0;
        }
        catch (Exception error) when (error is ToolException or MxcException or MsalException or
            Microsoft.Identity.Client.Extensions.Msal.MsalCachePersistenceException or
            JsonException or IOException or UnauthorizedAccessException or ArgumentException or
            InvalidOperationException or DllNotFoundException or BadImageFormatException or
            EntryPointNotFoundException or TypeInitializationException or System.Security.Cryptography.CryptographicException)
        {
            var code = error is ToolException tool ? tool.Code : error is MxcException native
                ? JsonNamingPolicy.SnakeCaseLower.ConvertName(native.Code.ToString()) : "test_app_failure";
            var details = error is MxcException sdkError ? SafeDetails(sdkError.Details) : null;
            if (details?["sandboxId"] is JsonValue cleanup && config is not null)
            {
                try
                {
                    var returned = config.Identity(cleanup.GetValue<string>());
                    if (id is null || id == returned) id = returned;
                    else code = "cleanup_identity_mismatch";
                }
                catch (ToolException) { code = "cleanup_identity_mismatch"; }
            }
            var journalUpdateFailed = false;
            if (created && submitted && journal is not null && receipt is not null)
            {
                journal.SessionId = id;
                journal.SandboxId = id;
                journal.State = journal.ReleaseAccepted ? "ReleaseAccepted" :
                    journal.State == "deprovisionSubmitted" ? "deprovisionSubmitted" : "FailedOrUnknown";
                journal.ErrorCode = code;
                journal.ErrorDetails = details?.DeepClone().AsObject();
                try { journal.Save(receipt); }
                catch (Exception writeError) when (writeError is IOException or UnauthorizedAccessException)
                {
                    journalUpdateFailed = true;
                    Console.Error.WriteLine("Receipt update failed; preserve the earlier journal and reconcile.");
                }
            }
            Console.Error.WriteLine(error is ToolException ? error.Message :
                $"Operation failed ({error.GetType().Name}); response and exception text suppressed.");
            if (id is not null) Console.Error.WriteLine($"Session NOT automatically released. MXC SessionId: {id}");
            Write(new JsonObject { ["error"] = new JsonObject { ["code"] = code, ["details"] = details },
                ["journalUpdateFailed"] = journalUpdateFailed }, id, receipt);
            return 1;
        }
        finally { receiptLock?.Dispose(); }
    }

    private static JsonObject Request(Configuration config, Arguments args, string phase, string? id, string owner)
    {
        var value = new JsonObject { ["version"] = "1.1.0-alpha", ["phase"] = phase };
        if (phase == "provision")
        {
            value["containment"] = "w365_agents";
            value["w365Agents"] = new JsonObject { ["provision"] = new JsonObject {
                ["poolId"] = config.PoolId, ["userType"] = "Local", ["userObjectId"] = owner } };
        }
        else value["sandboxId"] = id;
        if (phase == "exec")
        {
            var process = new JsonObject { ["commandLine"] = args.Command, ["timeout"] = args.TimeoutMs };
            if (args.WorkingDirectory is not null) process["cwd"] = args.WorkingDirectory;
            value["process"] = process;
        }
        return value;
    }

    private static JsonObject? SafeDetails(JsonElement? details)
    {
        if (details is not { ValueKind: JsonValueKind.Object } source) return null;
        var safe = new JsonObject();
        foreach (var name in new[] { "code", "requestId", "clientRequestId", "sandboxId", "poolId" })
            if (source.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
                value.GetString() is { Length: > 0 and <= 128 } text &&
                text.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':'))
                safe[name] = text;
        if (source.TryGetProperty("httpStatus", out var status) && status.ValueKind == JsonValueKind.Number &&
            status.TryGetInt32(out var number) && number is >= 100 and <= 599)
            safe["httpStatus"] = number;
        if (source.TryGetProperty("possiblySucceeded", out var uncertain) && uncertain.ValueKind is JsonValueKind.True or JsonValueKind.False)
            safe["possiblySucceeded"] = uncertain.GetBoolean();
        return safe;
    }

    private static void Write(JsonObject value, string? id, string? receipt)
    {
        value["sessionId"] = id;
        value["sandboxId"] = id;
        value["receiptPath"] = receipt;
        Console.WriteLine(value.ToJsonString());
    }
}

internal sealed class SdkEnvironment : IDisposable
{
    private readonly Dictionary<string, string?> previous = [];

    internal SdkEnvironment(Configuration config, string token)
    {
        foreach (var (name, value) in new Dictionary<string, string?> {
            ["W365A_CONTROLPLANE_URL"] = config.ControlPlaneHost, ["W365A_DP_SUFFIX"] = config.DataPlaneSuffix,
            ["W365A_CP_TOKEN"] = token, ["W365A_DP_TOKEN"] = token })
        {
            previous[name] = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    public void Dispose()
    {
        foreach (var (name, value) in previous) Environment.SetEnvironmentVariable(name, value);
    }
}
