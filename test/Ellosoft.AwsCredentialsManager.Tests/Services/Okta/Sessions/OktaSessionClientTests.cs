// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Idx;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Sessions;

public class OktaSessionClientTests
{
    private const string SessionUrl = "https://xyz.okta.com/api/v1/sessions/me";
    private const string UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/141.0";
    private static readonly Uri OktaDomain = new("https://xyz.okta.com/");

    private readonly FakeHttpMessageHandler _handler = new();
    private readonly OktaSessionClient _sessionClient;

    public OktaSessionClientTests()
    {
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(OktaSessionClient.HttpClientName).Returns(_ => new HttpClient(_handler, disposeHandler: false));

        _sessionClient = new OktaSessionClient(httpClientFactory, NullLogger<OktaSessionClient>.Instance);
    }

    [Fact]
    public async Task GetActiveSessionAsync_WithSessionCookies_ShouldSendSessionCookiesAndUserAgent()
    {
        _handler.OnJson(HttpMethod.Get, SessionUrl, """{ "id": "102sid", "status": "ACTIVE", "expiresAt": "2026-10-08T12:30:00.000Z" }""");

        var cookies = new CookieContainer();
        cookies.Add(new Cookie("sid", "102sid", "/", "xyz.okta.com"));
        cookies.Add(new Cookie("idx", "eyJ-idx-session", "/", "xyz.okta.com"));

        var session = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionCookies = cookies, UserAgent = UserAgent };

        var activeSession = await _sessionClient.GetActiveSessionAsync(session, TestContext.Current.CancellationToken);

        activeSession.ShouldBe(new OktaSessionInfo("102sid", new DateTimeOffset(2026, 10, 8, 12, 30, 0, TimeSpan.Zero)));

        var request = _handler.RequestsTo(HttpMethod.Get, SessionUrl).ShouldHaveSingleItem().Request;
        var cookieHeader = string.Join("; ", request.Headers.GetValues("Cookie"));

        cookieHeader.ShouldContain("sid=102sid");
        cookieHeader.ShouldContain("idx=eyJ-idx-session");
        request.Headers.UserAgent.ToString().ShouldBe(UserAgent);
    }

    [Fact]
    public async Task GetActiveSessionAsync_WithSessionIdOnly_ShouldSendOktaSessionCookie()
    {
        _handler.OnJson(HttpMethod.Get, SessionUrl, """{ "id": "102sid", "status": "ACTIVE" }""");

        var session = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" };

        var activeSession = await _sessionClient.GetActiveSessionAsync(session, TestContext.Current.CancellationToken);

        activeSession.ShouldBe(new OktaSessionInfo("102sid", null));

        var request = _handler.RequestsTo(HttpMethod.Get, SessionUrl).ShouldHaveSingleItem().Request;
        request.Headers.GetValues("Cookie").ShouldBe(["sid=102sid"]);
    }

    [Fact]
    public async Task GetActiveSessionAsync_WhenOktaNoLongerKnowsTheSession_ShouldReturnNull()
    {
        _handler.On(HttpMethod.Get, SessionUrl,
            _ => Task.FromResult(FakeHttpMessageHandler.Json("""{ "errorCode": "E0000007", "errorSummary": "Not found" }""", HttpStatusCode.NotFound)));

        var session = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" };

        var activeSession = await _sessionClient.GetActiveSessionAsync(session, TestContext.Current.CancellationToken);

        activeSession.ShouldBeNull();
    }

    [Fact]
    public async Task GetActiveSessionAsync_WhenSessionIsNotActive_ShouldReturnNull()
    {
        _handler.OnJson(HttpMethod.Get, SessionUrl, """{ "id": "102sid", "status": "MFA_REQUIRED" }""");

        var session = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" };

        var activeSession = await _sessionClient.GetActiveSessionAsync(session, TestContext.Current.CancellationToken);

        activeSession.ShouldBeNull();
    }

    [Fact]
    public async Task CloseSessionAsync_ShouldEndOktaSession()
    {
        _handler.OnStatus(HttpMethod.Delete, SessionUrl, HttpStatusCode.NoContent);

        var session = new AuthenticationResult { OktaDomain = OktaDomain, Authenticated = true, SessionId = "102sid" };

        var closed = await _sessionClient.CloseSessionAsync(session, TestContext.Current.CancellationToken);

        closed.ShouldBeTrue();
        _handler.RequestsTo(HttpMethod.Delete, SessionUrl).ShouldHaveSingleItem().Request.Headers.GetValues("Cookie").ShouldBe(["sid=102sid"]);
    }
}
