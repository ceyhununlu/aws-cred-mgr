// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

using System.Text.Json;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.AWS;

public record AwsCredentialsData(string AccessKeyId, string SecretAccessKey, string SessionToken, DateTime ExpirationDateTime, string RoleArn);

public interface IAwsCredentialsService
{
    /// <summary>
    ///     Assume AWS role and retrieve its credentials by using the SAML authentication assertion
    /// </summary>
    /// <param name="samlAssertion">A SAML authentication assertion used to authenticate the call to AWS STS.</param>
    /// <param name="roleArn">AWS role to be assumed.</param>
    /// <param name="idp">ARN of the SAML provider in AWS.</param>
    /// <param name="expirationInMinutes">
    ///     The duration, in minutes, for which the temporary security credentials are valid. (default 120 min)
    ///     When it exceeds the maximum session duration of the role, 60 minutes (default role maximum) are requested instead
    /// </param>
    /// <returns>AwsCredentialsData containing retrieved temporary AWS credentials.</returns>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when the SAML authentication assertion fails to meet the requirements
    ///     or AWS STS is unable to assume the specified role due to invalid parameters.
    /// </exception>
    /// <remarks>
    ///     The AssumeRoleWithSAMLAsync issues an HTTP POST request to https://sts.amazonaws.com, which does not require a region,
    ///     however the region is still required as part of the AmazonSecurityTokenServiceClient constructor validation, therefore USEast2 is being used.
    /// </remarks>
    Task<AwsCredentialsData> GetAwsCredentials(
        string samlAssertion,
        string roleArn,
        string idp,
        int expirationInMinutes = 120);

    /// <summary>
    ///     Store AWS credentials for a specific profile in the AWS credentials file.
    /// </summary>
    /// <param name="awsProfileName">The name of the AWS profile where the credentials should be stored.</param>
    /// <param name="credentials">AWS credentials to be stored.</param>
    void StoreCredentials(string awsProfileName, AwsCredentialsData credentials);

    /// <summary>
    ///     Retrieve AWS credentials for a specific profile from the AWS credentials file.
    /// </summary>
    /// <param name="awsProfileName">The name of the AWS profile where the credentials should be retrieved.</param>
    /// <returns>
    ///     AwsCredentialsData containing retrieved AWS credentials or
    ///     null if the profile isn't found or if the credential is about expire (15 min threshold).
    /// </returns>
    AwsCredentialsData? GetCredentialsFromStore(string awsProfileName);
}

public class AwsCredentialsService(ILogger<AwsCredentialsService> logger, Func<IAmazonSecurityTokenService> stsClientFactory) : IAwsCredentialsService
{
    /// <summary>
    ///     Maximum session duration of AWS roles unless the role is configured otherwise
    /// </summary>
    private const int DEFAULT_ROLE_MAX_SESSION_DURATION_IN_MINUTES = 60;

    internal sealed record ProfileMetadata(string RoleArn, string AccessKey, DateTime Expiration);

    public AwsCredentialsService(ILogger<AwsCredentialsService> logger)
        : this(logger, () => new AmazonSecurityTokenServiceClient(new AnonymousAWSCredentials(), RegionEndpoint.USEast2))
    {
    }

    public async Task<AwsCredentialsData> GetAwsCredentials(
        string samlAssertion,
        string roleArn,
        string idp,
        int expirationInMinutes = 120)
    {
        using var stsClient = stsClientFactory();

        try
        {
            return await AssumeRoleWithSessionDurationFallbackAsync(stsClient, samlAssertion, roleArn, idp, expirationInMinutes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Unable to assume AWS role {roleArn} using SAML", ex);
        }
    }

    private async Task<AwsCredentialsData> AssumeRoleWithSessionDurationFallbackAsync(IAmazonSecurityTokenService stsClient, string samlAssertion,
        string roleArn, string idp, int expirationInMinutes)
    {
        try
        {
            return await AssumeRoleWithSamlAsync(stsClient, samlAssertion, roleArn, idp, expirationInMinutes);
        }
        catch (AmazonSecurityTokenServiceException e) when (expirationInMinutes > DEFAULT_ROLE_MAX_SESSION_DURATION_IN_MINUTES &&
                                                            IsMaxSessionDurationExceeded(e))
        {
            logger.LogWarning(e, "The session duration of {Duration} minutes exceeds the maximum session duration of {RoleArn}", expirationInMinutes, roleArn);

            AnsiConsole.MarkupLineInterpolated(
                $"""
                 [yellow]The AWS role {roleArn} does not allow sessions of {expirationInMinutes} minutes, requesting {DEFAULT_ROLE_MAX_SESSION_DURATION_IN_MINUTES} minutes instead.
                 Set 'session_duration' in the credential to change it[/]
                 """);

            return await AssumeRoleWithSamlAsync(stsClient, samlAssertion, roleArn, idp, DEFAULT_ROLE_MAX_SESSION_DURATION_IN_MINUTES);
        }
    }

    private static async Task<AwsCredentialsData> AssumeRoleWithSamlAsync(IAmazonSecurityTokenService stsClient, string samlAssertion, string roleArn,
        string idp, int expirationInMinutes)
    {
        var request = new AssumeRoleWithSAMLRequest
        {
            DurationSeconds = expirationInMinutes * 60,
            RoleArn = roleArn,
            PrincipalArn = idp,
            SAMLAssertion = samlAssertion
        };

        var response = await stsClient.AssumeRoleWithSAMLAsync(request);

        return new AwsCredentialsData(
            response.Credentials.AccessKeyId,
            response.Credentials.SecretAccessKey,
            response.Credentials.SessionToken,
            response.Credentials.Expiration ?? DateTime.UtcNow.AddHours(1),
            roleArn);
    }

    /// <summary>
    ///     STS rejects durations above the role maximum with: "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
    /// </summary>
    private static bool IsMaxSessionDurationExceeded(AmazonSecurityTokenServiceException exception) =>
        exception.ErrorCode == "ValidationError" && exception.Message.Contains("MaxSessionDuration", StringComparison.OrdinalIgnoreCase);

    public void StoreCredentials(string awsProfileName, AwsCredentialsData credentials)
    {
        var options = new CredentialProfileOptions
        {
            AccessKey = credentials.AccessKeyId,
            SecretKey = credentials.SecretAccessKey,
            Token = credentials.SessionToken
        };

        var profile = new CredentialProfile(awsProfileName, options);

        var sharedFile = new SharedCredentialsFile();
        sharedFile.RegisterProfile(profile);

        SaveProfileMetadata(awsProfileName, new ProfileMetadata(credentials.RoleArn, credentials.AccessKeyId, credentials.ExpirationDateTime));
    }

    public AwsCredentialsData? GetCredentialsFromStore(string awsProfileName)
    {
        var sharedFile = new CredentialProfileStoreChain();

        if (!sharedFile.TryGetProfile(awsProfileName, out var profile) || !profile.CanCreateAWSCredentials)
            return null;

        var awsCredentials = profile.GetAWSCredentials(sharedFile);
        var immutableCredentials = awsCredentials.GetCredentials();

        var profileMetadata = GetProfileMetadata(awsProfileName);

        if (profileMetadata is null || profileMetadata.AccessKey != immutableCredentials.AccessKey || profileMetadata.Expiration < DateTime.Now.AddMinutes(15))
            return null;

        return new AwsCredentialsData(
            immutableCredentials.AccessKey,
            immutableCredentials.SecretKey,
            immutableCredentials.Token,
            profileMetadata.Expiration,
            profileMetadata.RoleArn);
    }

    private ProfileMetadata? GetProfileMetadata(string profileName)
    {
        var profileMetadataPath = GetProfileMetadataFilePath(profileName);

        if (!File.Exists(profileMetadataPath))
            return null;

        var bytes = File.ReadAllBytes(profileMetadataPath);

        try
        {
            return JsonSerializer.Deserialize(bytes, SourceGenerationContext.Default.ProfileMetadata);
        }
        catch (Exception e)
        {
            logger.LogError(e, "Unable to read AWS credentials profile metadata");

            return null;
        }
    }

    private static void SaveProfileMetadata(string profileName, ProfileMetadata metadata)
    {
        var profileMetadataPath = GetProfileMetadataFilePath(profileName);

        Directory.CreateDirectory(Path.GetDirectoryName(profileMetadataPath)!);

        File.WriteAllBytes(profileMetadataPath,
            JsonSerializer.SerializeToUtf8Bytes(metadata, SourceGenerationContext.Default.ProfileMetadata));
    }

    private static string GetProfileMetadataFilePath(string profileName) => AppDataDirectory.GetPath($"aws_profiles/{profileName}");
}
