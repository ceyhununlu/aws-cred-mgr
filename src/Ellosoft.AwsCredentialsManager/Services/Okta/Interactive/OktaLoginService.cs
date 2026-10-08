// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Configuration;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Ellosoft.AwsCredentialsManager.Services.Okta.Idx;
using Ellosoft.AwsCredentialsManager.Services.Okta.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Sessions;
using Ellosoft.AwsCredentialsManager.Services.Security;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;

public interface IOktaLoginService
{
    /// <summary>
    ///     Execute an interactive Okta user login
    /// </summary>
    /// <param name="oktaProfile">Okta profile</param>
    /// <param name="createSession">If true, a new Okta session will be created (default: false)</param>
    /// <returns>Authentication result</returns>
    Task<AuthenticationResult?> InteractiveLogin(string oktaProfile, bool createSession = false);

    /// <summary>
    ///     Restores the Okta session saved by a previous sign-in, as long as Okta still considers it active
    /// </summary>
    /// <returns>The saved session or null if there is no active saved session</returns>
    Task<AuthenticationResult?> ResumeSessionAsync(string oktaProfile);

    /// <summary>
    ///     Saves the Okta session of the authentication result in the secure storage (if the Okta profile remembers sessions)
    /// </summary>
    /// <returns>The authentication result, including the session id when a classic session had to be created to be saved</returns>
    Task<AuthenticationResult> SaveSessionAsync(string oktaProfile, AuthenticationResult authenticationResult);

    /// <summary>
    ///     Ends the saved Okta session and removes it from the secure storage
    /// </summary>
    /// <returns>true if there was a saved session</returns>
    Task<bool> LogoutAsync(string oktaProfile);

    Task<AuthenticationResult> Login(Uri oktaDomain, UserCredentials userCredentials,
        string? preferredMfaType = null, bool savedCredentials = false, string userProfileKey = OktaConfiguration.DefaultProfileName);
}

public class OktaLoginService(
    IAnsiConsole console,
    IConfigManager configManager,
    IUserCredentialsManager userCredentialsManager,
    IOktaClassicAuthenticator classicAuthenticator,
    IOktaIdxAuthenticator idxAuthenticator,
    IOktaSessionService sessionService)
    : IOktaLoginService
{
    public async Task<AuthenticationResult?> InteractiveLogin(string oktaProfile, bool createSession = false)
    {
        var oktaConfig = GetOktaConfig(oktaProfile);
        var userCredentials = GetUserCredentials(oktaProfile, out var savedCredentials);
        var preferredMfa = GetOktaMfaFactorCode(oktaConfig.PreferredMfaType);

        var authResult = await Login(new Uri(oktaConfig.OktaDomain), userCredentials, preferredMfa, savedCredentials, oktaProfile);

        authResult = await SaveSessionAsync(oktaProfile, oktaConfig, authResult);

        return createSession ? await CreateClassicSessionAsync(authResult) : authResult;
    }

    public async Task<AuthenticationResult?> ResumeSessionAsync(string oktaProfile)
    {
        var oktaConfig = GetOktaConfig(oktaProfile);

        if (!oktaConfig.ShouldRememberSession)
            return null;

        return await sessionService.ResumeAsync(oktaProfile, new Uri(oktaConfig.OktaDomain));
    }

    public Task<AuthenticationResult> SaveSessionAsync(string oktaProfile, AuthenticationResult authenticationResult) =>
        SaveSessionAsync(oktaProfile, GetOktaConfig(oktaProfile), authenticationResult);

    public Task<bool> LogoutAsync(string oktaProfile) =>
        sessionService.EndAsync(oktaProfile, new Uri(GetOktaConfig(oktaProfile).OktaDomain));

    public async Task<AuthenticationResult> Login(Uri oktaDomain, UserCredentials userCredentials,
        string? preferredMfaType = null, bool savedCredentials = false, string userProfileKey = OktaConfiguration.DefaultProfileName)
    {
        try
        {
            var authResult = OktaMfaFactorSelector.IsFastPass(preferredMfaType)
                ? await idxAuthenticator.AuthenticateAsync(oktaDomain, userCredentials.Username, userCredentials.Password)
                : await classicAuthenticator.AuthenticateAsync(oktaDomain, userCredentials.Username, userCredentials.Password, preferredMfaType);

            SaveUserCredentials(userProfileKey, userCredentials, savedCredentials);

            return authResult;
        }
        catch (Exception e) when (e is InvalidUsernameOrPasswordException or PasswordExpiredException)
        {
            ClearStoredPassword(userProfileKey, userCredentials);

            return new AuthenticationResult { OktaDomain = oktaDomain, Authenticated = false };
        }
    }

    private async Task<AuthenticationResult> SaveSessionAsync(string oktaProfile, OktaConfiguration oktaConfig, AuthenticationResult authResult)
    {
        if (!authResult.Authenticated || !oktaConfig.ShouldRememberSession)
            return authResult;

        authResult = await CreateClassicSessionAsync(authResult);
        sessionService.Save(oktaProfile, authResult);

        return authResult;
    }

    /// <summary>
    ///     Exchanges a classic session token for an Okta session (Identity Engine sign-ins already carry the session)
    /// </summary>
    private async Task<AuthenticationResult> CreateClassicSessionAsync(AuthenticationResult authResult)
    {
        if (authResult is not { Authenticated: true, SessionToken: not null, SessionId: null })
            return authResult;

        var sessionResult = await classicAuthenticator.CreateSessionAsync(authResult.OktaDomain, authResult.SessionToken);

        return sessionResult is not null ? authResult with { SessionId = sessionResult.Id } : authResult;
    }

    private void SaveUserCredentials(string userProfileKey, UserCredentials userCredentials, bool savedCredentials)
    {
        if (savedCredentials || !userCredentialsManager.SupportCredentialsStore)
            return;

        if (console.Confirm("Do you want to save your Okta username and password for future logins ?"))
        {
            userCredentialsManager.SaveUserCredentials(userProfileKey, userCredentials);

            return;
        }

        console.MarkupLine("[yellow]Ok... :([/]");
    }

    private UserCredentials GetUserCredentials(string userProfileKey, out bool savedCredentials)
    {
        savedCredentials = false;

        var user = userCredentialsManager.GetUserCredentials(userProfileKey);

        if (!string.IsNullOrWhiteSpace(user?.Password))
        {
            savedCredentials = true;

            return user;
        }

        AnsiConsole.MarkupLine("Let's get you logged in !");

        var username = user?.Username is null
            ? AnsiConsole.Ask<string>("Enter your [green]Okta[/] username:")
            : AnsiConsole.Ask("Enter your [green]Okta[/] username:", user.Username);

        var password = AnsiConsole.Prompt(new TextPrompt<string>("Enter your [green]Okta[/] password:").Secret());

        return new UserCredentials(username, password);
    }

    private void ClearStoredPassword(string profileKey, UserCredentials userCredentials)
    {
        var credentialsWithoutPasswords = userCredentials with { Password = string.Empty };
        userCredentialsManager.SaveUserCredentials(profileKey, credentialsWithoutPasswords);
    }

    private OktaConfiguration GetOktaConfig(string profile)
    {
        if (configManager.AppConfig.Authentication?.Okta.TryGetValue(profile, out var config) == true)
            return config;

        throw new OktaProfileNotFoundException(profile);
    }

    private static string? GetOktaMfaFactorCode(string? mfaType) =>
        mfaType is not null ? OktaMfaFactorSelector.GetOktaMfaFactorCode(mfaType) : null;
}
