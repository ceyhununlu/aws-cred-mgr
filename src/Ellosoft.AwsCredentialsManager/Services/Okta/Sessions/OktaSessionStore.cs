// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Text.Json;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Security;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;

public interface IOktaSessionStore
{
    /// <summary>
    ///     Saves the Okta session (session cookies or session id) carried by the authentication result in the secure storage
    /// </summary>
    /// <returns>true if the result carried a session that could be saved</returns>
    bool Save(string oktaProfile, AuthenticationResult authenticationResult);

    /// <summary>
    ///     Loads the Okta session saved for the profile, sessions saved for a different Okta domain are ignored
    /// </summary>
    AuthenticationResult? Load(string oktaProfile, Uri oktaDomain);

    void Delete(string oktaProfile);
}

public class OktaSessionStore(ISecureStorage secureStorage, ILogger<OktaSessionStore> logger) : IOktaSessionStore
{
    private const string SESSION_COOKIE_NAME = "sid";

    public bool Save(string oktaProfile, AuthenticationResult authenticationResult)
    {
        if (!authenticationResult.Authenticated)
            return false;

        var cookies = GetSessionCookies(authenticationResult);

        if (cookies.Count == 0)
            return false;

        var session = new StoredOktaSession
        {
            OktaDomain = authenticationResult.OktaDomain.ToString(),
            SessionId = authenticationResult.SessionId,
            UserAgent = authenticationResult.UserAgent,
            SavedAt = DateTime.UtcNow,
            Cookies = cookies
        };

        secureStorage.StoreSecret(GetKey(oktaProfile), JsonSerializer.Serialize(session, SourceGenerationContext.Default.StoredOktaSession));

        return true;
    }

    public AuthenticationResult? Load(string oktaProfile, Uri oktaDomain)
    {
        if (!secureStorage.TryRetrieveSecret(GetKey(oktaProfile), out var data))
            return null;

        StoredOktaSession? session;

        try
        {
            session = JsonSerializer.Deserialize(data, SourceGenerationContext.Default.StoredOktaSession);
        }
        catch (JsonException e)
        {
            logger.LogWarning(e, "Unable to read the saved Okta session for profile {OktaProfile}", oktaProfile);
            Delete(oktaProfile);

            return null;
        }

        if (session is null || !Uri.TryCreate(session.OktaDomain, UriKind.Absolute, out var sessionDomain)
                            || !string.Equals(sessionDomain.Host, oktaDomain.Host, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var cookieContainer = new CookieContainer();

        foreach (var cookie in session.Cookies.Where(c => c.Expires is null || c.Expires > DateTime.UtcNow))
            TryAddCookie(cookieContainer, cookie);

        if (cookieContainer.Count == 0)
            return null;

        return new AuthenticationResult
        {
            OktaDomain = oktaDomain,
            Authenticated = true,
            SessionId = session.SessionId,
            SessionCookies = cookieContainer,
            UserAgent = session.UserAgent,
            IsResumedSession = true
        };
    }

    public void Delete(string oktaProfile) => secureStorage.DeleteSecret(GetKey(oktaProfile));

    private static List<StoredOktaSessionCookie> GetSessionCookies(AuthenticationResult authenticationResult)
    {
        if (authenticationResult.SessionCookies is { Count: > 0 } sessionCookies)
        {
            return sessionCookies.GetAllCookies()
                .Where(c => !c.Expired)
                .Select(c => new StoredOktaSessionCookie(
                    c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HttpOnly, c.Expires == DateTime.MinValue ? null : c.Expires.ToUniversalTime()))
                .ToList();
        }

        // classic sessions are identified by the session id alone, which is the value of the Okta session cookie
        if (authenticationResult.SessionId is { } sessionId)
            return [new StoredOktaSessionCookie(SESSION_COOKIE_NAME, sessionId, authenticationResult.OktaDomain.Host, "/", true, true, null)];

        return [];
    }

    private void TryAddCookie(CookieContainer cookieContainer, StoredOktaSessionCookie cookie)
    {
        try
        {
            cookieContainer.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
            {
                Secure = cookie.Secure,
                HttpOnly = cookie.HttpOnly,
                Expires = cookie.Expires?.ToLocalTime() ?? DateTime.MinValue
            });
        }
        catch (CookieException e)
        {
            logger.LogDebug(e, "Ignoring invalid saved Okta cookie {CookieName}", cookie.Name);
        }
    }

    private static string GetKey(string oktaProfile) => $"okta_session_{oktaProfile}";
}

public sealed record StoredOktaSession
{
    public required string OktaDomain { get; init; }

    public string? SessionId { get; init; }

    public string? UserAgent { get; init; }

    public DateTime SavedAt { get; init; }

    public List<StoredOktaSessionCookie> Cookies { get; init; } = [];
}

public sealed record StoredOktaSessionCookie(string Name, string Value, string Domain, string Path, bool Secure, bool HttpOnly, DateTime? Expires);
