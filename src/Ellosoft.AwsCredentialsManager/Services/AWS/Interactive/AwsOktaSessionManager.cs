// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using Amazon.Runtime;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Interactive;
using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.AWS.Interactive;

public interface IAwsOktaSessionManager
{
    Task<AWSCredentials?> CreateOrResumeSessionAsync(string credentialProfile, string? outputAwsProfile, bool forceRenew = false);
}

public class AwsOktaSessionManager(
    ICredentialsManager credentialsManager,
    IOktaLoginService loginService,
    IOktaSamlService oktaSamlService,
    IAwsCredentialsService awsCredentialsService,
    IAwsSamlService awsSamlService,
    ILogger<AwsOktaSessionManager> logger) : IAwsOktaSessionManager
{
    private const int RENEWAL_THRESHOLD_IN_MINUTES = 60;

    public async Task<AWSCredentials?> CreateOrResumeSessionAsync(string credentialProfile, string? outputAwsProfile, bool forceRenew = false)
    {
        if (!credentialsManager.TryGetCredential(credentialProfile, out var credentialsConfig))
            return null;

        if (credentialsConfig is not { OktaProfile: { } oktaProfile, OktaAppUrl: { } oktaAppUrl })
            throw new InvalidOperationException($"The credential '{credentialProfile}' does not have an Okta profile and Okta app URL configured");

        var awsProfile = credentialsConfig.GetAwsProfileSafe(credentialProfile);
        var storedCredentials = forceRenew ? null : GetStoredCredentials(awsProfile, credentialsConfig.RoleArn);

        // short sessions would otherwise be renewed on every run
        var renewalThreshold = Math.Min(RENEWAL_THRESHOLD_IN_MINUTES, credentialsConfig.GetSessionDurationSafe() / 2);

        if (storedCredentials is not null && storedCredentials.ExpirationDateTime >= DateTime.Now.AddMinutes(renewalThreshold))
            return CreateAwsCredentials(storedCredentials, awsProfile, outputAwsProfile);

        // renewing with the saved Okta session needs no user interaction, so it happens before asking the user anything
        var samlData = await GetSamlDataWithSavedOktaSessionAsync(oktaProfile, oktaAppUrl);

        if (samlData is null)
        {
            if (storedCredentials is not null && !ConfirmRenewal(storedCredentials))
                return CreateAwsCredentials(storedCredentials, awsProfile, outputAwsProfile);

            samlData = await GetSamlDataWithNewOktaSessionAsync(oktaProfile, oktaAppUrl);

            if (samlData is null)
                return null;
        }

        var newCredentials = await AssumeRoleAsync(credentialProfile, awsProfile, credentialsConfig, samlData);

        return newCredentials is not null ? CreateAwsCredentials(newCredentials, awsProfile, outputAwsProfile) : null;
    }

    private AwsCredentialsData? GetStoredCredentials(string awsProfile, string roleArn)
    {
        var credentialsData = awsCredentialsService.GetCredentialsFromStore(awsProfile);

        return credentialsData?.RoleArn == roleArn ? credentialsData : null;
    }

    private static bool ConfirmRenewal(AwsCredentialsData credentialsData)
    {
        var expirationInMinutes = (int)(credentialsData.ExpirationDateTime - DateTime.Now).TotalMinutes;

        var renewCredentialsMessage = $"""
                                       [bold yellow]Your AWS credentials will expire in [bold green]{expirationInMinutes}[/] minutes.
                                       Any tokens (RDS password, PreSigned URLs, etc) created with it will also expired within that time frame.
                                       Do you want renew the credentials now ?[/]
                                       """;

        AnsiConsole.WriteLine();

        return AnsiConsole.Confirm(renewCredentialsMessage, defaultValue: false);
    }

    private async Task<SamlData?> GetSamlDataWithSavedOktaSessionAsync(string oktaProfile, string oktaAppUrl)
    {
        var savedSession = await loginService.ResumeSessionAsync(oktaProfile);

        if (savedSession is null)
            return null;

        try
        {
            var samlData = await oktaSamlService.GetAppSamlDataAsync(savedSession, oktaAppUrl);

            // Okta may have refreshed the session cookies while serving the app
            await loginService.SaveSessionAsync(oktaProfile, savedSession);

            AnsiConsole.MarkupLine("[green]Using your saved Okta session, no sign-in required[/]");

            return samlData;
        }
        catch (Exception e) when (e is InvalidOperationException or HttpRequestException)
        {
            logger.LogInformation(e, "The saved Okta session was not accepted for {OktaAppUrl}", oktaAppUrl);
            AnsiConsole.MarkupLine("[grey]Okta requires you to sign in again[/]");

            return null;
        }
    }

    private async Task<SamlData?> GetSamlDataWithNewOktaSessionAsync(string oktaProfile, string oktaAppUrl)
    {
        var authResult = await loginService.InteractiveLogin(oktaProfile, oktaAppUrl: oktaAppUrl);

        if (authResult is not { HasSession: true })
            return null;

        return await oktaSamlService.GetAppSamlDataAsync(authResult, oktaAppUrl);
    }

    private async Task<AwsCredentialsData?> AssumeRoleAsync(string credentialProfile, string awsProfile, CredentialsConfiguration credentialsConfig,
        SamlData samlData)
    {
        var idp = GetRoleIdp(credentialProfile, credentialsConfig.RoleArn, samlData.SamlAssertion);

        if (idp is null)
            return null;

        var awsCredentialsData = await awsCredentialsService.GetAwsCredentials(samlData.SamlAssertion, credentialsConfig.RoleArn, idp,
            credentialsConfig.GetSessionDurationSafe());

        awsCredentialsService.StoreCredentials(awsProfile, awsCredentialsData);

        return awsCredentialsData;
    }

    private string? GetRoleIdp(string credentialProfile, string roleArn, string samlAssertion)
    {
        var roles = awsSamlService.GetAwsRolesAndIdpFromSamlAssertion(samlAssertion);

        if (roles.TryGetValue(roleArn, out var idp))
            return idp;

        var invalidCredentialMessage = $"""
                                        [bold yellow]The AWS role ARN specified in the credential [b]'{credentialProfile}'[/] is not assigned to your user.
                                        Please update the [b]'{credentialProfile}'[/] credential, with one of the following roles:[/]
                                        """;

        AnsiConsole.MarkupLine(invalidCredentialMessage);

        foreach (var (role, _) in roles)
            AnsiConsole.MarkupLine(role);

        return null;
    }

    private SessionAWSCredentials CreateAwsCredentials(AwsCredentialsData credentialsData, string credentialProfile, string? outputAwsProfile)
    {
        if (outputAwsProfile is not null && outputAwsProfile != credentialProfile)
        {
            awsCredentialsService.StoreCredentials(outputAwsProfile, credentialsData);
        }

        return new SessionAWSCredentials(credentialsData.AccessKeyId, credentialsData.SecretAccessKey, credentialsData.SessionToken);
    }
}
