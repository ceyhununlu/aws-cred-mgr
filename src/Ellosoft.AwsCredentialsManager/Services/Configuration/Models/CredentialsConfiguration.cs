// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

namespace Ellosoft.AwsCredentialsManager.Services.Configuration.Models;

public class CredentialsConfiguration : ResourceConfiguration
{
    public const int DefaultSessionDuration = 120;

    public const int MinSessionDuration = 15;

    public const int MaxSessionDuration = 720;

    public required string RoleArn { get; set; }

    public string? AwsProfile { get; set; }

    public string? OktaAppUrl { get; set; }

    public string? OktaProfile { get; set; }

    /// <summary>
    ///     How long the AWS credentials are valid, in minutes (15 to 720, default: 120).
    ///     It cannot exceed the maximum session duration of the AWS role
    /// </summary>
    public int? SessionDuration { get; set; }

    internal int GetSessionDurationSafe() => Math.Clamp(SessionDuration ?? DefaultSessionDuration, MinSessionDuration, MaxSessionDuration);

    /// <summary>
    ///     If the AwsProfile is populated then return its value otherwise returns the credential name
    /// </summary>
    internal string GetAwsProfileSafe(string credentialName) => AwsProfile ?? credentialName;
}
