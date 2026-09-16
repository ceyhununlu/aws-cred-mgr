// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Spectre.Console.Testing;

namespace Ellosoft.AwsCredentialsManager.Tests.Services.Okta.Idx;

public class OktaAgentlessDssoHandlerTests
{
    private const string OktaDomain = "https://xyz.okta.com/";
    private const string IdpRedirectUrl = "https://xyz.okta.com/sso/idps/0oa1dsso?stateToken=02state-handle";
    private const string KerberosUrl = "https://xyz.kerberos.okta.com/login/agentlessDsso?stateToken=02state-handle";
    private const string DssoCallbackUrl = "https://xyz.okta.com/login/agentlessDsso/redirect?token=abc";
    private const string DashboardCallbackUrl = "https://xyz.okta.com/enduser/callback?code=xyz&state=123";
    private const string DirectEndpointUrl = "https://xyz.okta.com/login/agentlessDsso";

    private static readonly IdxIdpRedirect Redirect = new("AgentlessDSSO", "AgentlessDSSO", IdpRedirectUrl);

    private readonly FakeHttpMessageHandler _httpHandler = new();
    private readonly TestConsole _console = new();
    private readonly CookieContainer _cookies = new();
    private readonly OktaAgentlessDssoHandler _handler;

    private ICredentials? _credentials;

    public OktaAgentlessDssoHandlerTests()
    {
        var httpClientFactory = Substitute.For<IOktaIdxHttpClientFactory>();
        httpClientFactory.CreateDesktopSsoClient(_cookies, Arg.Do<ICredentials>(c => _credentials = c)).Returns(_ => new HttpClient(_httpHandler));

        _handler = new OktaAgentlessDssoHandler(httpClientFactory, _console, NullLogger<OktaAgentlessDssoHandler>.Instance);
    }

    [Fact]
    public async Task ExecuteAsync_ShouldFollowTheRedirectChainThroughTheKerberosEndpointAndReturnTheFinalPage()
    {
        // Okta -> org Kerberos endpoint (Negotiate handled by the HTTP stack) -> Okta callback -> dashboard callback
        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .OnKerberosRedirect(HttpMethod.Get, KerberosUrl, DssoCallbackUrl)
            .OnRedirect(HttpMethod.Get, DssoCallbackUrl, "/enduser/callback?code=xyz&state=123")
            .On(HttpMethod.Get, DashboardCallbackUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html>dashboard</html>")));

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.FinalUrl.ToString().ShouldBe(DashboardCallbackUrl);
        result.StatusCode.ShouldBe(HttpStatusCode.OK);
        result.Content.ShouldBe("<html>dashboard</html>");
        result.KerberosRejected.ShouldBeFalse();

        _httpHandler.Requests.Select(r => r.Url).ShouldBe([IdpRedirectUrl, KerberosUrl, DssoCallbackUrl, DashboardCallbackUrl]);
        _httpHandler.Requests.ShouldAllBe(r => r.Method == HttpMethod.Get);

        // the explicit Host header pins the Kerberos SPN to HTTP/xyz.kerberos.okta.com (no DNS canonicalisation)
        _httpHandler.RequestsTo(HttpMethod.Get, KerberosUrl).ShouldHaveSingleItem().Request.Headers.Host.ShouldBe("xyz.kerberos.okta.com");
        _console.Output.ShouldContain("Desktop Single Sign-on");
    }

    [Fact]
    public async Task ExecuteAsync_WhenTheKerberosPageBouncesViaMetaRefresh_ShouldFollowItToTheChallenge()
    {
        // Okta serves the DSSO step as a 200 page that meta-refreshes to the real Kerberos challenge URL
        const string bouncePage = """<html><head><meta http-equiv="refresh" content="0; url=https://xyz.kerberos.okta.com/login/agentlessDsso?stateToken=02state-handle"></head></html>""";

        _httpHandler
            .On(HttpMethod.Get, IdpRedirectUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html(bouncePage)))
            .On(HttpMethod.Get, KerberosUrl, _ =>
            {
                var challenged = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") };
                challenged.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Negotiate", "oYAB"));
                return Task.FromResult(challenged);
            });

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.NegotiateChallengeSeen.ShouldBeTrue();
        result.KerberosHost.ShouldBe("xyz.kerberos.okta.com");
        _httpHandler.Requests.Select(r => r.Url).ShouldBe([IdpRedirectUrl, KerberosUrl]);
    }

    [Fact]
    public async Task ExecuteAsync_WhenTheIdpRedirectServesAPage_ShouldFallBackToTheDocumentedDirectDssoEndpoint()
    {
        // GET /sso/idps/DSSO?stateToken=... answers 200 with a page (what the user's org does) instead of bouncing to Kerberos:
        // the documented https://{org}/login/agentlessDsso entry point is used instead
        _httpHandler
            .On(HttpMethod.Get, IdpRedirectUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html><title>Verizon Connect Inc. - Sign In</title><body>widget</body></html>")))
            .OnRedirect(HttpMethod.Get, DirectEndpointUrl, KerberosUrl)
            .OnKerberosRedirect(HttpMethod.Get, KerberosUrl, DssoCallbackUrl)
            .OnRedirect(HttpMethod.Get, DssoCallbackUrl, DashboardCallbackUrl)
            .On(HttpMethod.Get, DashboardCallbackUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html>dashboard</html>")));

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.NegotiateChallengeSeen.ShouldBeTrue();
        result.KerberosHost.ShouldBe("xyz.kerberos.okta.com");
        result.FinalUrl.ToString().ShouldBe(DashboardCallbackUrl);

        _httpHandler.Requests.Select(r => r.Url).ShouldBe([IdpRedirectUrl, DirectEndpointUrl, KerberosUrl, DssoCallbackUrl, DashboardCallbackUrl]);
        // the test console wraps long lines
        _console.Output.ReplaceLineEndings(" ").ShouldContain("trying the Desktop SSO endpoint directly");
    }

    [Fact]
    public async Task ExecuteAsync_WhenNeitherTheIdpRedirectNorTheDirectEndpointChallengeForKerberos_ShouldReportNoNegotiateChallenge()
    {
        _httpHandler
            .On(HttpMethod.Get, IdpRedirectUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html><body>please sign in</body></html>")))
            .On(HttpMethod.Get, DirectEndpointUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html><body>please sign in</body></html>")));

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.NegotiateChallengeSeen.ShouldBeFalse();
        result.KerberosHost.ShouldBeNull();
        result.KerberosRejected.ShouldBeFalse();
        result.FinalUrl.ToString().ShouldBe(DirectEndpointUrl);
    }

    [Fact]
    public async Task ExecuteAsync_WhenAnInterstitialPageAutoSubmitsAForm_ShouldPostItToTheNextStep()
    {
        // Okta interstitial: hidden form posted by script to the next step
        const string interstitial = """
            <html><body onload="document.forms[0].submit()">
            <form id="appForm" method="POST" action="https://xyz.kerberos.okta.com/login/agentlessDsso">
              <input type="hidden" name="stateToken" value="02state&#45;handle" />
              <input type="hidden" name="fromURI" value="/app/dashboard" />
            </form>
            </body></html>
            """;

        _httpHandler
            .On(HttpMethod.Get, IdpRedirectUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html(interstitial)))
            .On(HttpMethod.Post, "https://xyz.kerberos.okta.com/login/agentlessDsso", _ => Task.FromResult(FakeHttpMessageHandler.KerberosRedirect(DashboardCallbackUrl)))
            .On(HttpMethod.Get, DashboardCallbackUrl, _ => Task.FromResult(FakeHttpMessageHandler.Html("<html>dashboard</html>")));

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.NegotiateChallengeSeen.ShouldBeTrue();

        var post = _httpHandler.RequestsTo(HttpMethod.Post, "https://xyz.kerberos.okta.com/login/agentlessDsso").ShouldHaveSingleItem();
        post.Body.ShouldBe("stateToken=02state-handle&fromURI=%2Fapp%2Fdashboard");
    }

    [Theory]
    [InlineData("""<meta http-equiv="refresh" content="0;url=/login/step2">""", "https://xyz.okta.com/login/step2")]
    [InlineData("""<META HTTP-EQUIV='refresh' CONTENT='0; URL=https://xyz.kerberos.okta.com/x'>""", "https://xyz.kerberos.okta.com/x")]
    [InlineData("<script>window.location.href = 'https://xyz.okta.com/next';</script>", "https://xyz.okta.com/next")]
    [InlineData("<script>location.replace('/relative/path')</script>", "https://xyz.okta.com/relative/path")]
    [InlineData("<script>window.location.assign(\"/assigned\")</script>", "https://xyz.okta.com/assigned")]
    [InlineData("<script>document.location = '/doc';</script>", "https://xyz.okta.com/doc")]
    [InlineData("""<form action="/manual" method="post"><input type="text" name="user"></form>""", null)]
    [InlineData("<html><body>no redirect here</body></html>", null)]
    public void ExtractHtmlRedirect_ShouldFindClientSideRedirects(string html, string? expected)
    {
        var result = OktaAgentlessDssoHandler.ExtractHtmlRedirect(html, new Uri("https://xyz.okta.com/login/agentlessDsso"));

        result?.ToString().ShouldBe(expected);
    }

    [Fact]
    public void ExtractHtmlNavigation_WithAutoSubmittedGetForm_ShouldPutTheFieldsInTheQueryString()
    {
        const string html = """<form action="/next?a=1" method="get"><input type="hidden" name="b" value="2"></form><script>document.forms[0].submit();</script>""";

        var navigation = OktaAgentlessDssoHandler.ExtractHtmlNavigation(html, new Uri("https://xyz.okta.com/login/agentlessDsso")).ShouldNotBeNull();

        navigation.Method.ShouldBe(HttpMethod.Get);
        navigation.Url.ToString().ShouldBe("https://xyz.okta.com/next?a=1&b=2");
    }

    [Fact]
    public async Task ExecuteAsync_ShouldOnlyOfferTheKerberosTicketToOktaHosts()
    {
        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .OnKerberosRedirect(HttpMethod.Get, KerberosUrl, "https://evil.example.com/steal")
            .On(HttpMethod.Get, "https://evil.example.com/steal", _ => Task.FromResult(FakeHttpMessageHandler.Html("<html/>")));

        await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        var credentials = _credentials.ShouldNotBeNull();

        credentials.GetCredential(new Uri("https://xyz.okta.com/"), "Negotiate").ShouldBe(CredentialCache.DefaultNetworkCredentials);
        credentials.GetCredential(new Uri("https://xyz.kerberos.okta.com/"), "Negotiate").ShouldBe(CredentialCache.DefaultNetworkCredentials);
        credentials.GetCredential(new Uri("https://evil.example.com/"), "Negotiate").ShouldBeNull();

        // NTLM is never offered (Okta only accepts Kerberos tickets)
        credentials.GetCredential(new Uri("https://xyz.kerberos.okta.com/"), "NTLM").ShouldBeNull();
    }

    [Fact]
    public async Task ExecuteAsync_WhenKerberosIsRejected_ShouldReportTheKerberosHost()
    {
        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .On(HttpMethod.Get, KerberosUrl, _ =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent(string.Empty) };
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Negotiate"));
                return Task.FromResult(response);
            });

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.KerberosRejected.ShouldBeTrue();
        result.KerberosHost.ShouldBe("xyz.kerberos.okta.com");
        result.FinalUrl.ToString().ShouldBe(KerberosUrl);
    }

    [Fact]
    public async Task ExecuteAsync_WhenKerberosFailsAndOktaFallsBackToTheSignInPage_ShouldReturnTheSignInPage()
    {
        const string loginPage = """<html><script>var stateToken = '02new\x2Dtoken';</script></html>""";

        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .OnKerberosRedirect(HttpMethod.Get, KerberosUrl, "https://xyz.okta.com/login/default")
            .On(HttpMethod.Get, "https://xyz.okta.com/login/default", _ => Task.FromResult(FakeHttpMessageHandler.Html(loginPage)));

        var result = await _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None);

        result.StatusCode.ShouldBe(HttpStatusCode.OK);
        result.FinalUrl.ToString().ShouldBe("https://xyz.okta.com/login/default");
        OktaLoginPageStateTokenExtractor.Extract(result.Content).ShouldBe("02new-token");
    }

    [Fact]
    public async Task ExecuteAsync_WhenTheKerberosEndpointCannotBeReached_ShouldThrowNamingTheHost()
    {
        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .OnUnreachable(HttpMethod.Get, KerberosUrl);

        var exception = await Should.ThrowAsync<OktaFastPassException>(() => _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None));

        exception.Message.ShouldContain("xyz.kerberos.okta.com");
        exception.Message.ShouldContain("Connection refused");
    }

    [Fact]
    public async Task ExecuteAsync_WhenOktaKeepsRedirecting_ShouldThrow()
    {
        _httpHandler.OnRedirect(HttpMethod.Get, IdpRedirectUrl, IdpRedirectUrl);

        var exception = await Should.ThrowAsync<OktaFastPassException>(() => _handler.ExecuteAsync(new Uri(OktaDomain), Redirect, _cookies, CancellationToken.None));

        exception.Message.ShouldContain("redirect");
    }

    [Theory]
    [InlineData("https://xyz.okta.com/sso/idps/x", true)]
    [InlineData("https://xyz.kerberos.okta.com/login/agentlessDsso", true)]
    [InlineData("https://xyz.kerberos.oktapreview.com/login/agentlessDsso", true)]
    [InlineData("https://xyz.kerberos.okta-emea.com/login/agentlessDsso", true)]
    [InlineData("https://other.okta.com/", true)]
    [InlineData("http://xyz.kerberos.okta.com/login/agentlessDsso", false)]
    [InlineData("https://xyz.okta.com.evil.example.com/", false)]
    [InlineData("https://evil.example.com/", false)]
    public void IsTrustedOktaHost_ShouldOnlyTrustHttpsOktaHosts(string url, bool expected)
    {
        OktaAgentlessDssoHandler.IsTrustedOktaHost(new Uri(url), new Uri(OktaDomain)).ShouldBe(expected);
    }

    [Fact]
    public void IsTrustedOktaHost_WithCustomOktaDomain_ShouldTrustTheOktaKerberosEndpointAndTheCompanyDomain()
    {
        var customDomain = new Uri("https://login.contoso.com/");

        OktaAgentlessDssoHandler.IsTrustedOktaHost(new Uri("https://login.contoso.com/sso/idps/x"), customDomain).ShouldBeTrue();
        OktaAgentlessDssoHandler.IsTrustedOktaHost(new Uri("https://contoso.kerberos.okta.com/login/agentlessDsso"), customDomain).ShouldBeTrue();
        OktaAgentlessDssoHandler.IsTrustedOktaHost(new Uri("https://sso.contoso.com/"), customDomain).ShouldBeTrue();
        OktaAgentlessDssoHandler.IsTrustedOktaHost(new Uri("https://evil.example.com/"), customDomain).ShouldBeFalse();
    }

    [Theory]
    [InlineData("AgentlessDSSO", true)]
    [InlineData("agentlessdsso", true)]
    [InlineData("MICROSOFT", false)]
    [InlineData(null, false)]
    public void IsAgentlessDsso_ShouldMatchTheIdpTypeCaseInsensitively(string? type, bool expected)
    {
        OktaAgentlessDssoHandler.IsAgentlessDsso(new IdxIdpRedirect(type, "Desktop SSO", IdpRedirectUrl)).ShouldBe(expected);
    }
}
