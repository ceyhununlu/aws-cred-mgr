// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Commands;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;

/// <summary>
///     Raised when the Okta sign-in in the browser cannot be completed (no browser installed, window closed, timeout...)
/// </summary>
public class OktaBrowserSignInException(string message) : CommandException(message);
