// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaIdxHttpClientFactory
{
    /// <summary>
    ///     Creates an HTTP client for a single Okta Identity Engine sign-in transaction: uses the given cookie jar
    ///     (Okta device/session cookies), follows redirects and identifies itself as a desktop browser
    ///     (Okta selects the FastPass challenge method based on the user agent platform)
    /// </summary>
    HttpClient CreateSessionClient(CookieContainer cookieContainer);

    /// <summary>
    ///     Creates an HTTP client to talk to the Okta Verify loopback server on localhost
    /// </summary>
    HttpClient CreateLoopbackClient();

    /// <summary>
    ///     Creates an HTTP client for Okta Agentless Desktop SSO: shares the sign-in cookie jar, answers "Negotiate"
    ///     challenges with the given credentials (Kerberos ticket of the OS user) and leaves redirects to the caller
    /// </summary>
    HttpClient CreateDesktopSsoClient(CookieContainer cookieContainer, ICredentials credentials);
}

public class OktaIdxHttpClientFactory : IOktaIdxHttpClientFactory
{
    public HttpClient CreateSessionClient(CookieContainer cookieContainer)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = cookieContainer,
            AllowAutoRedirect = true
        };

        return CreateBrowserLikeClient(handler);
    }

    public HttpClient CreateDesktopSsoClient(CookieContainer cookieContainer, ICredentials credentials)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = cookieContainer,
            AllowAutoRedirect = false,
            Credentials = credentials,
            PreAuthenticate = false
        };

        return CreateBrowserLikeClient(handler);
    }

    private static HttpClient CreateBrowserLikeClient(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(OktaHttpClient.GetPlatformUserAgent());

        return httpClient;
    }

    public HttpClient CreateLoopbackClient()
    {
        // never send loopback traffic through a proxy and never carry cookies to Okta Verify
        var handler = new HttpClientHandler
        {
            UseCookies = false,
            UseProxy = false,
            AllowAutoRedirect = false
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(5) };
    }
}
