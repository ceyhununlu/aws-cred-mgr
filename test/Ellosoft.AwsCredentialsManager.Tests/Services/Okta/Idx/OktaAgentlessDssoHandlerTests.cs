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
            .OnRedirect(HttpMethod.Get, KerberosUrl, DssoCallbackUrl)
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
    public async Task ExecuteAsync_ShouldOnlyOfferTheKerberosTicketToOktaHosts()
    {
        _httpHandler
            .OnRedirect(HttpMethod.Get, IdpRedirectUrl, KerberosUrl)
            .OnRedirect(HttpMethod.Get, KerberosUrl, "https://evil.example.com/steal")
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
            .OnRedirect(HttpMethod.Get, KerberosUrl, "https://xyz.okta.com/login/default")
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
