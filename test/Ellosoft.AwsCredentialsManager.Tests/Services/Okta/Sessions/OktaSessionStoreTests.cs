// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Ellosoft.AwsCredentialsManager.Services.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Sessions;

public class OktaSessionStoreTests
{
    private const string Profile = "default";
    private const string SessionKey = "okta_session_default";
    private static readonly Uri OktaDomain = new("https://xyz.okta.com/");
    private static readonly Uri OktaAppUri = new("https://xyz.okta.com/home/amazon_aws/abc/272");

    private readonly InMemorySecureStorage _secureStorage = new();
    private readonly OktaSessionStore _sessionStore;

    public OktaSessionStoreTests()
    {
        _sessionStore = new OktaSessionStore(_secureStorage, NullLogger<OktaSessionStore>.Instance);
    }

    [Fact]
    public void SaveAndLoad_WithSessionCookies_ShouldRestoreAllSessionCookies()
    {
        var cookies = new CookieContainer();
        cookies.Add(new Cookie("sid", "102sid", "/", "xyz.okta.com") { Secure = true, HttpOnly = true });
        cookies.Add(new Cookie("idx", "eyJ-idx-session", "/", "xyz.okta.com") { Secure = true, HttpOnly = true });
        cookies.Add(new Cookie("DT", "device-token", "/", ".okta.com") { Secure = true, Expires = DateTime.Now.AddDays(30) });

        var authResult = new AuthenticationResult
        {
            OktaDomain = OktaDomain,
            Authenticated = true,
            SessionId = "102sid",
            SessionCookies = cookies,
            UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/141.0"
        };

        _sessionStore.Save(Profile, authResult).ShouldBeTrue();

        var session = _sessionStore.Load(Profile, OktaDomain).ShouldNotBeNull();

        session.Authenticated.ShouldBeTrue();
        session.IsResumedSession.ShouldBeTrue();
        session.SessionId.ShouldBe("102sid");
        session.UserAgent.ShouldBe(authResult.UserAgent);

        var cookieHeader = session.SessionCookies.ShouldNotBeNull().GetCookieHeader(OktaAppUri);
        cookieHeader.ShouldContain("sid=102sid");
        cookieHeader.ShouldContain("idx=eyJ-idx-session");
        cookieHeader.ShouldContain("DT=device-token");
    }

    [Fact]
    public void SaveAndLoad_WithSessionIdOnly_ShouldRestoreOktaSessionCookie()
    {
        var authResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionToken = "used-token", SessionId = "102sid" };

        _sessionStore.Save(Profile, authResult).ShouldBeTrue();

        var session = _sessionStore.Load(Profile, OktaDomain).ShouldNotBeNull();

        session.SessionId.ShouldBe("102sid");
        session.SessionToken.ShouldBeNull();
        session.SessionCookies.ShouldNotBeNull().GetCookieHeader(OktaAppUri).ShouldBe("sid=102sid");
    }

    [Fact]
    public void Save_WithoutSession_ShouldNotSaveAnything()
    {
        var authResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionToken = "session-token" };

        _sessionStore.Save(Profile, authResult).ShouldBeFalse();

        _secureStorage.Secrets.ShouldBeEmpty();
    }

    [Fact]
    public void Save_WhenNotAuthenticated_ShouldNotSaveAnything()
    {
        var authResult = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = false, SessionId = "102sid" };

        _sessionStore.Save(Profile, authResult).ShouldBeFalse();

        _secureStorage.Secrets.ShouldBeEmpty();
    }

    [Fact]
    public void Load_WhenSessionWasSavedForAnotherOktaDomain_ShouldIgnoreIt()
    {
        _sessionStore.Save(Profile, new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" });

        _sessionStore.Load(Profile, new Uri("https://abc.okta.com/")).ShouldBeNull();
    }

    [Fact]
    public void Load_WhenSavedSessionIsUnreadable_ShouldRemoveIt()
    {
        _secureStorage.StoreSecret(SessionKey, "{not json");

        _sessionStore.Load(Profile, OktaDomain).ShouldBeNull();

        _secureStorage.Secrets.ShouldNotContainKey(SessionKey);
    }

    [Fact]
    public void Load_ShouldDropExpiredCookies()
    {
        StoreSession(
            Cookie("sid", "102sid", DateTime.UtcNow.AddHours(1)),
            Cookie("idx", "expired-idx", DateTime.UtcNow.AddMinutes(-1)));

        var session = _sessionStore.Load(Profile, OktaDomain).ShouldNotBeNull();

        session.SessionCookies.ShouldNotBeNull().GetCookieHeader(OktaAppUri).ShouldBe("sid=102sid");
    }

    [Fact]
    public void Load_WhenAllCookiesExpired_ShouldReturnNull()
    {
        StoreSession(Cookie("sid", "102sid", DateTime.UtcNow.AddMinutes(-1)));

        _sessionStore.Load(Profile, OktaDomain).ShouldBeNull();
    }

    [Fact]
    public void Delete_ShouldRemoveSavedSession()
    {
        _sessionStore.Save(Profile, new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" });

        _sessionStore.Delete(Profile);

        _sessionStore.Load(Profile, OktaDomain).ShouldBeNull();
    }

    private void StoreSession(params StoredOktaSessionCookie[] cookies)
    {
        var storedSession = new StoredOktaSession { OktaDomain = OktaDomain.ToString(), SessionId = "102sid", Cookies = [.. cookies] };

        _secureStorage.StoreSecret(SessionKey, JsonSerializer.Serialize(storedSession, StoredSessionJsonContext.Default.StoredOktaSession));
    }

    private static StoredOktaSessionCookie Cookie(string name, string value, DateTime expires) =>
        new(name, value, "xyz.okta.com", "/", Secure: true, HttpOnly: true, expires);

    private sealed class InMemorySecureStorage : ISecureStorage
    {
        public Dictionary<string, string> Secrets { get; } = [];

        public void StoreSecret(string key, string data) => Secrets[key] = data;

        public void DeleteSecret(string key) => Secrets.Remove(key);

        public bool TryRetrieveSecret(string key, [NotNullWhen(true)] out string? data) => Secrets.TryGetValue(key, out data);
    }
}

[JsonSerializable(typeof(StoredOktaSession))]
internal partial class StoredSessionJsonContext : JsonSerializerContext;
