// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;

public interface IOktaSessionService
{
    /// <summary>
    ///     Saves the Okta session carried by the authentication result for future runs
    /// </summary>
    /// <returns>true if the result carried a session that could be saved</returns>
    bool Save(string oktaProfile, AuthenticationResult authenticationResult);

    /// <summary>
    ///     Restores the saved Okta session, as long as Okta still considers it active (expired sessions are removed)
    /// </summary>
    Task<AuthenticationResult?> ResumeAsync(string oktaProfile, Uri oktaDomain, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Ends the saved Okta session in Okta and removes it
    /// </summary>
    /// <returns>true if there was a saved session</returns>
    Task<bool> EndAsync(string oktaProfile, Uri oktaDomain, CancellationToken cancellationToken = default);
}

public class OktaSessionService(
    IOktaSessionStore sessionStore,
    IOktaSessionClient sessionClient,
    IAnsiConsole console,
    ILogger<OktaSessionService> logger) : IOktaSessionService
{
    public bool Save(string oktaProfile, AuthenticationResult authenticationResult)
    {
        var saved = sessionStore.Save(oktaProfile, authenticationResult);

        if (saved)
            logger.LogDebug("Okta session saved for profile {OktaProfile}", oktaProfile);

        return saved;
    }

    public async Task<AuthenticationResult?> ResumeAsync(string oktaProfile, Uri oktaDomain, CancellationToken cancellationToken = default)
    {
        var session = sessionStore.Load(oktaProfile, oktaDomain);

        if (session is null)
            return null;

        try
        {
            var activeSession = await sessionClient.GetActiveSessionAsync(session, cancellationToken);

            if (activeSession is not null)
            {
                logger.LogDebug("Saved Okta session for profile {OktaProfile} is active until {ExpiresAt}", oktaProfile, activeSession.ExpiresAt);

                return session with { SessionId = activeSession.Id };
            }

            console.MarkupLine("[grey]Your saved Okta session has expired[/]");
            sessionStore.Delete(oktaProfile);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(e, "Unable to validate the saved Okta session for profile {OktaProfile}", oktaProfile);
        }

        return null;
    }

    public async Task<bool> EndAsync(string oktaProfile, Uri oktaDomain, CancellationToken cancellationToken = default)
    {
        var session = sessionStore.Load(oktaProfile, oktaDomain);

        sessionStore.Delete(oktaProfile);

        if (session is null)
            return false;

        try
        {
            await sessionClient.CloseSessionAsync(session, cancellationToken);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(e, "Unable to end the Okta session for profile {OktaProfile}", oktaProfile);
        }

        return true;
    }
}
