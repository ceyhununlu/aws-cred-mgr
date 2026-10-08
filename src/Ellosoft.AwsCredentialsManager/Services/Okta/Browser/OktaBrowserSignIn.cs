// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

public static class OktaBrowserSignIn
{
    /// <summary>
    ///     True when the Okta sign-in must run in a browser: the profile asks for it, or Okta FastPass is used on Windows,
    ///     where Okta routes the sign-in through steps that only a browser can complete (Desktop SSO / Kerberos, Okta Verify
    ///     launched by the sign-in page)
    /// </summary>
    public static bool IsRequired(string? preferredMfaType, string? authType) =>
        IsRequired(preferredMfaType, authType, OperatingSystem.IsWindows());

    public static bool IsRequired(string? preferredMfaType, string? authType, bool isWindows) =>
        string.Equals(authType, OktaConfiguration.BrowserAuthType, StringComparison.OrdinalIgnoreCase)
        || (isWindows && OktaMfaFactorSelector.IsFastPass(preferredMfaType));
}
