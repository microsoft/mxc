// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;

namespace W365SdkTestApp;

internal sealed record Credentials(string AccessToken, string UserObjectId, DateTimeOffset ExpiresOn);

internal interface IAuthentication
{
    Task<Credentials> AcquireAsync(Configuration config, Arguments args, string? expectedOwner, bool silentOnly);
}

internal sealed class Authentication : IAuthentication
{
    internal const string Resource = "274133f7-12bb-4bfb-ae3b-bd446b7e8a75";
    private static readonly string[] Scopes = [$"{Resource}/.default"];

    public async Task<Credentials> AcquireAsync(
        Configuration config, Arguments args, string? expectedOwner, bool silentOnly)
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "MXC", "w365-sdk-test-auth");
        Directory.CreateDirectory(directory);
        // Hold account selection/refresh as well as the cache library's own write lock.
        using var operationLock = new FileStream(
            Path.Combine(directory, $"{config.TenantId}_{config.ClientId}.operation.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var app = PublicClientApplicationBuilder.Create(config.ClientId)
            .WithAuthority($"https://login.microsoftonline.com/{config.TenantId}")
            .WithRedirectUri("http://localhost")
            .Build();
        var storage = new StorageCreationPropertiesBuilder(
            $"{config.TenantId}_{config.ClientId}.bin", directory).Build();
        var cache = await MsalCacheHelper.CreateAsync(storage).ConfigureAwait(false);
        cache.VerifyPersistence();
        cache.RegisterCache(app.UserTokenCache);
        var account = SelectAccount(await app.GetAccountsAsync().ConfigureAwait(false), args.LoginHint);
        AuthenticationResult? result = null;
        if ((!args.ForceSignIn || silentOnly) && account is not null)
        {
            try
            {
                result = await app.AcquireTokenSilent(Scopes, account).ExecuteAsync().ConfigureAwait(false);
            }
            catch (MsalUiRequiredException) when (!silentOnly) { }
        }
        if (result is null)
        {
            if (silentOnly)
                throw new ToolException("silent_auth_required", "Token renewal requires interaction; no service call was made.");
            Console.Error.WriteLine("Opening the system browser; existing MFA and consent policy applies.");
            var interactive = app.AcquireTokenInteractive(Scopes)
                .WithPrompt(Prompt.SelectAccount)
                .WithUseEmbeddedWebView(false);
            if (args.LoginHint is not null) interactive = interactive.WithLoginHint(args.LoginHint);
            result = await interactive.ExecuteAsync().ConfigureAwait(false);
        }
        return Verify(result.AccessToken, config, expectedOwner);
    }

    internal static IAccount? SelectAccount(IEnumerable<IAccount> accounts, string? loginHint)
    {
        // Guest accounts have a different home tenant; authority and token checks bind the resource tenant.
        var matches = accounts.Where(account => loginHint is null ||
            string.Equals(account.Username, loginHint, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length > 1)
            throw new ToolException("ambiguous_account", "Multiple cached accounts match; supply a unique --login-hint.");
        return matches.SingleOrDefault();
    }

    internal static Credentials Verify(string token, Configuration config, string? expectedOwner)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-' or '.')))
                throw new FormatException();
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var claims = JsonDocument.Parse(Convert.FromBase64String(payload));
            var root = claims.RootElement;
            var owner = Configuration.GuidValue(root.GetProperty("oid").GetString()!);
            var audience = root.GetProperty("aud").GetString();
            var callers = new[] { "azp", "appid" }.Where(name => root.TryGetProperty(name, out _)).ToArray();
            var scopes = root.GetProperty("scp").GetString()!.Split(' ').ToHashSet(StringComparer.Ordinal);
            var expires = DateTimeOffset.FromUnixTimeSeconds(root.GetProperty("exp").GetInt64());
            if (Configuration.GuidValue(root.GetProperty("tid").GetString()!) != config.TenantId ||
                callers.Length == 0 || callers.Any(name => Configuration.GuidValue(root.GetProperty(name).GetString()!) != config.ClientId) ||
                audience != Resource && audience != $"api://{Resource}" ||
                expectedOwner is not null && owner != expectedOwner ||
                !new[] { "Computer.Control", "Computer.Do", "Computer.Get", "Computer.See" }.All(scopes.Contains) ||
                expires < DateTimeOffset.UtcNow.AddMinutes(5) ||
                root.TryGetProperty("nbf", out var nbf) && nbf.GetInt64() > DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds())
                throw new FormatException();
            // MSAL and the service authenticate; decoded claims are sanity checks only.
            return new Credentials(token, owner, expires);
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or
            KeyNotFoundException or ArgumentException or ToolException or NullReferenceException)
        {
            throw new ToolException("token_mismatch", "Token identity, audience, scopes, or lifetime does not match.");
        }
    }
}
