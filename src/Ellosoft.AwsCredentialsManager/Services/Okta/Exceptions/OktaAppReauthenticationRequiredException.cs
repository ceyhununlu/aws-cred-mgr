// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;

/// <summary>
///     Raised when Okta answers an app request with its sign-in page instead of the SAML response: the Okta session is
///     no longer valid or the app sign-on policy requires the user to verify again
/// </summary>
public class OktaAppReauthenticationRequiredException(string message) : InvalidOperationException(message);
