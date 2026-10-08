// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using System.Net;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Models;

public record AuthenticationResult
{
    public required Uri OktaDomain { get; init; }

    public string? MfaUsed { get; init; }

    public string? StateToken { get; init; }

    public string? SessionId { get; init; }

    public string? SessionToken { get; init; }

    /// <summary>
    ///     Cookies set by Okta during an Identity Engine (FastPass) sign-in. In Identity Engine the session is carried by
    ///     several cookies (sid, idx, device token...), so subsequent Okta requests must send all of them, not only the session id
    /// </summary>
    public CookieContainer? SessionCookies { get; init; }

    /// <summary>
    ///     User agent of the client that created the Okta session, requests reusing the session identify themselves the same way
    /// </summary>
    public string? UserAgent { get; init; }

    /// <summary>
    ///     SAML response captured while signing in through the browser (the browser posts it to AWS straight after the sign-in)
    /// </summary>
    public CapturedSamlResponse? CapturedSaml { get; init; }

    /// <summary>
    ///     True when the session was restored from the secure storage instead of being created by a new sign-in
    /// </summary>
    public bool IsResumedSession { get; init; }

    public bool Authenticated { get; init; }

    /// <summary>
    ///     True when the result carries an Okta session: a session token (classic authentication),
    ///     a session id or session cookies (Identity Engine / FastPass / browser sign-in, where the session cookie is the session)
    /// </summary>
    public bool HasSession => Authenticated && (SessionToken is not null || SessionId is not null || SessionCookies is not null || CapturedSaml is not null);
}

/// <summary>
///     SAML response posted to AWS for the Okta app at <paramref name="OktaAppUrl" />
/// </summary>
public record CapturedSamlResponse(string OktaAppUrl, SamlData SamlData);
