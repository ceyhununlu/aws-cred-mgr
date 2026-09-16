// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaAgentlessDssoHandler
{
    /// <summary>
    ///     Completes an "AgentlessDSSO" identity provider redirect the way a browser does: follows it to the org Kerberos
    ///     endpoint (https://{org}.kerberos.okta.com/login/agentlessDsso) and answers the Negotiate challenge with the
    ///     Kerberos ticket of the OS user, then follows Okta back to the sign-in transaction / dashboard
    /// </summary>
    /// <param name="oktaDomain">Okta org domain</param>
    /// <param name="redirect">The "redirect-idp" remediation returned by Okta</param>
    /// <param name="sessionCookies">Cookie jar of the sign-in transaction (the Okta session cookie ends up here)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Where the redirect chain ended (URL, status code and body)</returns>
    Task<AgentlessDssoResult> ExecuteAsync(Uri oktaDomain, IdxIdpRedirect redirect, CookieContainer sessionCookies, CancellationToken cancellationToken);
}

/// <summary>
///     Outcome of the Desktop SSO redirect chain
/// </summary>
/// <param name="FinalUrl">URL of the last (non redirect) response</param>
/// <param name="StatusCode">Status code of the last response</param>
/// <param name="Content">Body of the last response (Okta sign-in page or dashboard HTML)</param>
/// <param name="KerberosHost">Host that issued the Negotiate challenge, if any</param>
/// <param name="NegotiateChallengeSeen">Whether any hop actually asked for a Kerberos (Negotiate) ticket</param>
public sealed record AgentlessDssoResult(Uri FinalUrl, HttpStatusCode StatusCode, string Content, string? KerberosHost, bool NegotiateChallengeSeen)
{
    /// <summary>
    ///     The Kerberos endpoint refused the sign-in (no ticket, NTLM instead of Kerberos, clock skew...)
    /// </summary>
    public bool KerberosRejected => StatusCode == HttpStatusCode.Unauthorized;
}

/// <summary>
///     A navigation an HTML page performs on its own: meta-refresh, <c>window.location = ...</c> or an auto-submitted form
/// </summary>
public sealed record HtmlNavigation(Uri Url, HttpMethod Method, IReadOnlyDictionary<string, string> FormFields)
{
    public static HtmlNavigation Get(Uri url) => new(url, HttpMethod.Get, new Dictionary<string, string>());
}

/// <summary>
///     Okta Agentless Desktop Single Sign-on: Okta answers with a 401 "WWW-Authenticate: Negotiate" on the org Kerberos
///     host, the client presents the Kerberos ticket of the signed-in OS user (SPN HTTP/{org}.kerberos.okta.com) and Okta
///     signs the user in. On Windows .NET uses SSPI for this, so the CLI can complete the flow without a browser.
/// </summary>
public partial class OktaAgentlessDssoHandler(IOktaIdxHttpClientFactory httpClientFactory, IAnsiConsole console, ILogger<OktaAgentlessDssoHandler> logger)
    : IOktaAgentlessDssoHandler
{
    public const string IdpType = "AgentlessDSSO";

    /// <summary>
    ///     Okta's documented direct Desktop SSO entry point ("sign in using the direct agentless DSSO endpoint URL"):
    ///     redirects to the org Kerberos host, runs the Negotiate handshake and creates the Okta session
    /// </summary>
    public const string DirectEndpointPath = "/login/agentlessDsso";

    /// <summary>
    ///     The last page the Desktop SSO chain settled on is saved here when debug logging is on (redirect diagnostics)
    /// </summary>
    public const string CapturedPageFileName = "okta-dsso-response.html";

    private const string NegotiateScheme = "Negotiate";
    private const int MaxRedirects = 15;
    private const int LoggedBodySnippetLength = 800;

    private static readonly string[] OktaKerberosDomains = [".kerberos.okta.com", ".kerberos.oktapreview.com", ".kerberos.okta-emea.com"];

    public static bool IsAgentlessDsso(IdxIdpRedirect redirect) => string.Equals(redirect.Type, IdpType, StringComparison.OrdinalIgnoreCase);

    public async Task<AgentlessDssoResult> ExecuteAsync(Uri oktaDomain, IdxIdpRedirect redirect, CookieContainer sessionCookies, CancellationToken cancellationToken)
    {
        console.MarkupLine($"Okta routed the sign-in to Desktop Single Sign-on ([green]{Markup.Escape(redirect.IdpName ?? IdpType)}[/]), signing in with your Windows (Kerberos) account...");

        // the OS user's Kerberos ticket is only ever presented to Okta hosts (the org and its *.kerberos.okta.com endpoint)
        var credentials = new CredentialCache();

        using var httpClient = httpClientFactory.CreateDesktopSsoClient(sessionCookies, credentials);

        var result = await FollowChainAsync(httpClient, credentials, oktaDomain, HtmlNavigation.Get(new Uri(oktaDomain, redirect.Href)), cancellationToken);

        if (result.NegotiateChallengeSeen)
            return result;

        // the identity provider redirect did not lead to a Kerberos challenge (Okta served a page instead): use the
        // documented direct Desktop SSO endpoint, which is what the Okta hosted sign-in page routes browsers through
        logger.LogWarning("Desktop SSO: the identity provider redirect settled at {Url} (HTTP {StatusCode}) without a Kerberos challenge, trying {Endpoint} directly",
            result.FinalUrl, (int)result.StatusCode, DirectEndpointPath);

        console.MarkupLine("Okta did not ask for a Kerberos ticket on the identity provider redirect, trying the Desktop SSO endpoint directly...");

        return await FollowChainAsync(httpClient, credentials, oktaDomain, HtmlNavigation.Get(new Uri(oktaDomain, DirectEndpointPath)), cancellationToken);
    }

    private async Task<AgentlessDssoResult> FollowChainAsync(HttpClient httpClient, CredentialCache credentials, Uri oktaDomain, HtmlNavigation navigation,
        CancellationToken cancellationToken)
    {
        string? kerberosHost = null;
        var negotiateChallengeSeen = false;

        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            var url = navigation.Url;

            PrepareCredentials(credentials, url, oktaDomain);

            using var response = await SendAsync(httpClient, navigation, hop, cancellationToken);

            // .NET answers the 401 Negotiate internally, so a challenge shows up either as a lingering 401 (rejected) or as
            // the WWW-Authenticate header echoed on the final response; either way it proves Okta asked for the Kerberos ticket
            if (response.StatusCode == HttpStatusCode.Unauthorized || response.Headers.WwwAuthenticate.Any(h => h.Scheme == NegotiateScheme))
            {
                negotiateChallengeSeen = true;
                kerberosHost ??= url.Host;
            }

            if (GetRedirectLocation(response, url) is { } location)
            {
                navigation = HtmlNavigation.Get(location);

                continue;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            LogSettledResponse(hop, url, response, content);

            // Okta interstitial pages bounce to the next step client side (meta-refresh, script, auto-submitted form);
            // a browser follows them, so must we (otherwise Kerberos is never actually attempted)
            if (GetHtmlNavigation(response, content, url, oktaDomain) is { } htmlNavigation)
            {
                logger.LogDebug("Desktop SSO hop {Hop}: following in-page navigation {Method} {Url}", hop, htmlNavigation.Method, htmlNavigation.Url);
                navigation = htmlNavigation;

                continue;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                logger.LogError("Desktop SSO: {Host} rejected the Kerberos sign-in (401). WWW-Authenticate: {Challenge}", url.Host, response.Headers.WwwAuthenticate);

            return new AgentlessDssoResult(url, response.StatusCode, content, kerberosHost, negotiateChallengeSeen);
        }

        throw new OktaFastPassException($"Desktop Single Sign-on did not complete: Okta kept redirecting (more than {MaxRedirects} redirects), last URL: {navigation.Url}");
    }

    private void PrepareCredentials(CredentialCache credentials, Uri url, Uri oktaDomain)
    {
        if (IsTrustedOktaHost(url, oktaDomain))
            TrustHost(credentials, url);
        else
            logger.LogWarning("Desktop SSO redirected to {Host}, which is not an Okta host: the Kerberos ticket will not be presented to it", url.Host);
    }

    private static Uri? GetRedirectLocation(HttpResponseMessage response, Uri currentUrl)
    {
        if (!IsRedirect(response.StatusCode) || response.Headers.Location is not { } location)
            return null;

        return location.IsAbsoluteUri ? location : new Uri(currentUrl, location);
    }

    private static HtmlNavigation? GetHtmlNavigation(HttpResponseMessage response, string content, Uri currentUrl, Uri oktaDomain)
    {
        if (response.StatusCode != HttpStatusCode.OK)
            return null;

        return ExtractHtmlNavigation(content, currentUrl) is { } navigation && IsTrustedOktaHost(navigation.Url, oktaDomain) ? navigation : null;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpClient httpClient, HtmlNavigation navigation, int hop, CancellationToken cancellationToken)
    {
        var url = navigation.Url;

        using var request = new HttpRequestMessage(navigation.Method, url);

        if (navigation.Method == HttpMethod.Post)
            request.Content = new FormUrlEncodedContent(navigation.FormFields);

        // the Kerberos SPN Okta registers is HTTP/{org}.kerberos.okta.com; with an explicit Host header .NET builds the SPN
        // from it instead of canonicalising the host through DNS (which would follow the CNAME and produce the wrong SPN)
        request.Headers.Host = url.IsDefaultPort ? url.Host : $"{url.Host}:{url.Port}";
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));

        try
        {
            var response = await httpClient.SendAsync(request, cancellationToken);

            var wwwAuthenticate = response.Headers.WwwAuthenticate.Count > 0
                ? string.Join(", ", response.Headers.WwwAuthenticate.Select(h => h.Scheme))
                : "none";

            logger.LogDebug("Desktop SSO hop {Hop}: {Method} {Url} -> {StatusCode} (WWW-Authenticate: {WwwAuthenticate}, Location: {Location}, Content-Type: {ContentType})",
                hop, navigation.Method, url, (int)response.StatusCode, wwwAuthenticate, response.Headers.Location?.ToString() ?? "none",
                response.Content.Headers.ContentType?.ToString() ?? "none");

            return response;
        }
        catch (HttpRequestException e)
        {
            logger.LogError(e, "Desktop SSO request to {Url} failed", url);

            throw new OktaFastPassException(
                $"Desktop Single Sign-on failed while contacting {url.Host}: {e.Message}. " +
                "This device must be able to reach Okta's Kerberos endpoint and a domain controller (corporate network or VPN)");
        }
    }

    private void LogSettledResponse(int hop, Uri url, HttpResponseMessage response, string content)
    {
        if (!logger.IsEnabled(LogLevel.Debug))
            return;

        var title = TitleRegex().Match(content) is { Success: true } match ? WebUtility.HtmlDecode(match.Groups["title"].Value).Trim() : "none";
        var snippet = content.Length > LoggedBodySnippetLength ? content[..LoggedBodySnippetLength] + "..." : content;

        logger.LogDebug("Desktop SSO hop {Hop}: {Url} settled at HTTP {StatusCode} ({Length} bytes, title: {Title}). Body: {Body}",
            hop, url, (int)response.StatusCode, content.Length, title, snippet);

        try
        {
            var path = AppDataDirectory.GetPath(CapturedPageFileName);
            File.WriteAllText(path, $"<!-- {url} -> HTTP {(int)response.StatusCode} -->\n{content}");

            logger.LogDebug("Desktop SSO hop {Hop}: full page saved to {Path}", hop, path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            logger.LogDebug(e, "Desktop SSO: could not save the page for diagnostics");
        }
    }

    /// <summary>
    ///     Finds the navigation an HTML page performs on its own: meta-refresh, a <c>location</c> assignment in a script
    ///     or an auto-submitted form (Okta interstitial pages post a hidden form to the next step)
    /// </summary>
    public static HtmlNavigation? ExtractHtmlNavigation(string html, Uri baseUrl)
    {
        if (string.IsNullOrWhiteSpace(html))
            return null;

        var match = MetaRefreshRegex().Match(html);

        if (!match.Success)
            match = JsLocationRegex().Match(html);

        if (match.Success)
        {
            var target = WebUtility.HtmlDecode(match.Groups["url"].Value).Trim();

            return Uri.TryCreate(baseUrl, target, out var uri) ? HtmlNavigation.Get(uri) : null;
        }

        return ExtractAutoSubmittedForm(html, baseUrl);
    }

    /// <summary>
    ///     Kept for callers that only need the target URL of a client side redirect
    /// </summary>
    public static Uri? ExtractHtmlRedirect(string html, Uri baseUrl) => ExtractHtmlNavigation(html, baseUrl)?.Url;

    private static HtmlNavigation? ExtractAutoSubmittedForm(string html, Uri baseUrl)
    {
        // only forms the page submits by itself (script calling submit()) are followed, never forms waiting for user input
        if (!FormSubmitScriptRegex().IsMatch(html))
            return null;

        var form = FormRegex().Match(html);

        if (!form.Success)
            return null;

        var attributes = form.Groups["attributes"].Value;
        var action = AttributeValue(attributes, "action");

        if (action is null || !Uri.TryCreate(baseUrl, WebUtility.HtmlDecode(action), out var url))
            return null;

        var method = string.Equals(AttributeValue(attributes, "method"), "post", StringComparison.OrdinalIgnoreCase) ? HttpMethod.Post : HttpMethod.Get;

        var fields = new Dictionary<string, string>();

        foreach (Match input in InputRegex().Matches(form.Groups["body"].Value))
        {
            var inputAttributes = input.Groups["attributes"].Value;

            if (AttributeValue(inputAttributes, "name") is { } name)
                fields[WebUtility.HtmlDecode(name)] = WebUtility.HtmlDecode(AttributeValue(inputAttributes, "value") ?? string.Empty);
        }

        if (method == HttpMethod.Get && fields.Count > 0)
        {
            var query = string.Join('&', fields.Select(f => $"{Uri.EscapeDataString(f.Key)}={Uri.EscapeDataString(f.Value)}"));
            url = new Uri(url.GetLeftPart(UriPartial.Path) + (url.Query.Length > 0 ? url.Query + "&" : "?") + query);
        }

        return new HtmlNavigation(url, method, fields);
    }

    private static string? AttributeValue(string attributes, string name)
    {
        var match = Regex.Match(attributes, $"""(?:^|\s){name}\s*=\s*(?:"(?<value>[^"]*)"|'(?<value>[^']*)'|(?<value>[^\s>]+))""",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        return match.Success ? match.Groups["value"].Value : null;
    }

    /// <summary>
    ///     Only Okta's own hosts may challenge for the Kerberos ticket: the org (including custom domains), the org's
    ///     parent Okta domain and the *.kerberos.okta.com endpoints Agentless DSSO uses
    /// </summary>
    public static bool IsTrustedOktaHost(Uri url, Uri oktaDomain)
    {
        if (url.Scheme != Uri.UriSchemeHttps)
            return false;

        var host = url.Host;

        if (string.Equals(host, oktaDomain.Host, StringComparison.OrdinalIgnoreCase))
            return true;

        if (OktaKerberosDomains.Any(d => host.EndsWith(d, StringComparison.OrdinalIgnoreCase)))
            return true;

        // xyz.okta.com -> anything under okta.com (e.g. xyz.kerberos.okta.com on preview/EMEA cells with other suffixes)
        var firstDot = oktaDomain.Host.IndexOf('.');

        return firstDot > 0 && host.EndsWith(oktaDomain.Host[firstDot..], StringComparison.OrdinalIgnoreCase);
    }

    private static void TrustHost(CredentialCache credentials, Uri url)
    {
        var prefix = new Uri(url.GetLeftPart(UriPartial.Authority));

        if (credentials.GetCredential(prefix, NegotiateScheme) is null)
            credentials.Add(prefix, NegotiateScheme, CredentialCache.DefaultNetworkCredentials);
    }

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    [GeneratedRegex("""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*(?<url>[^"']+)["']""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MetaRefreshRegex();

    [GeneratedRegex("""(?:window\.|document\.)?location(?:\.href)?\s*=\s*["'](?<url>[^"']+)["']|location\.(?:replace|assign)\(\s*["'](?<url>[^"']+)["']""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsLocationRegex();

    [GeneratedRegex(@"\.submit\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FormSubmitScriptRegex();

    [GeneratedRegex("""<form(?<attributes>[^>]*)>(?<body>.*?)</form>""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex FormRegex();

    [GeneratedRegex("""<input(?<attributes>[^>]*)>""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InputRegex();

    [GeneratedRegex("""<title[^>]*>(?<title>.*?)</title>""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex TitleRegex();
}
