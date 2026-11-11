// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.Json.Nodes;

namespace W365SdkTestApp;

internal sealed class Journal
{
    public string Format { get; set; } = "mxc-w365-sdk-test-v1";
    public string? SessionId { get; set; }
    public string? SandboxId { get; set; }
    public string PoolId { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string UserObjectId { get; set; } = "";
    public string ControlPlaneHost { get; set; } = "";
    public string DataPlaneSuffix { get; set; } = "";
    public string State { get; set; } = "Prepared";
    public int AllocationRequestCount { get; set; }
    public bool TokenPersisted { get; set; }
    public bool ReleaseAccepted { get; set; }
    public bool RemoteResetConfirmed { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
    public List<string> Operations { get; set; } = [];
    public string? ErrorCode { get; set; }
    public JsonObject? ErrorDetails { get; set; }

    internal static Journal Read(string path, Configuration config, Arguments args)
    {
        var journal = JsonSerializer.Deserialize<Journal>(File.ReadAllText(path), Configuration.JsonOptions)
            ?? throw new ToolException("invalid_receipt", "Invalid operation journal.");
        if (args.SessionId is null || journal.Format != "mxc-w365-sdk-test-v1" ||
            journal.SessionId != args.SessionId || journal.SandboxId != args.SessionId ||
            journal.PoolId != config.PoolId || journal.TenantId != config.TenantId ||
            journal.ClientId != config.ClientId ||
            !string.Equals(journal.ControlPlaneHost, config.ControlPlaneHost, StringComparison.OrdinalIgnoreCase) ||
            args.Operation == "run" && !string.Equals(journal.DataPlaneSuffix, config.DataPlaneSuffix, StringComparison.OrdinalIgnoreCase) ||
            journal.TokenPersisted || journal.RemoteResetConfirmed || journal.AllocationRequestCount is < 0 or > 1 ||
            journal.Operations is null || journal.State is not ("Completed" or "FailedOrUnknown" or
                "provisionSubmitted" or "startSubmitted" or "execSubmitted" or "deprovisionSubmitted" or "ReleaseAccepted") ||
            args.ExpectedUserObjectId is not null && args.ExpectedUserObjectId != journal.UserObjectId)
            throw new ToolException("receipt_mismatch", "Receipt identity, deployment, format, or state does not match.");
        _ = Configuration.GuidValue(journal.UserObjectId);
        if (journal.ReleaseAccepted || journal.State == "ReleaseAccepted")
            throw new ToolException("released_session", "Release was already accepted; do not reuse this session.");
        if (journal.State == "deprovisionSubmitted")
            throw new ToolException("reconciliation_required", "Reconcile the submitted release before another attempt; never replay an uncertain release.");
        if (args.Operation == "run" && journal.State != "Completed")
            throw new ToolException("reconciliation_required", "Reconcile the uncertain operation before running another command; explicit release is available.");
        return journal;
    }

    internal void Save(string path, bool create = false)
    {
        UpdatedUtc = DateTimeOffset.UtcNow;
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(JsonSerializer.SerializeToUtf8Bytes(this, Configuration.JsonOptions));
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: !create);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
