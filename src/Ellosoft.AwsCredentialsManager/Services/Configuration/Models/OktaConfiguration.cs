// Copyright (c) 2023 Ellosoft Limited. All rights reserved.

namespace Ellosoft.AwsCredentialsManager.Services.Configuration.Models;

public class OktaConfiguration : ResourceConfiguration
{
    public const string DefaultProfileName = "default";

    public const string ClassicAuthType = "classic";

    /// <summary>
    ///     Sign in to Okta through a browser window (Microsoft Edge or Google Chrome)
    /// </summary>
    public const string BrowserAuthType = "browser";

    public required string OktaDomain { get; set; }

    /// <summary>
    ///     Preferred MFA method (this will be null if no MFA is required)
    /// </summary>
    public string? PreferredMfaType { get; set; }

    public string AuthType { get; set; } = ClassicAuthType;

    /// <summary>
    ///     Save the Okta session in the secure storage (macOS Keychain / Windows DPAPI) and reuse it to renew AWS credentials
    ///     without signing in again while Okta keeps the session active (default: true)
    /// </summary>
    public bool? RememberSession { get; set; }

    internal bool ShouldRememberSession => RememberSession ?? true;
}
