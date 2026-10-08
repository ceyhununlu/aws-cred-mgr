// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using Ellosoft.AwsCredentialsManager.Services.Configuration.Models;
using Ellosoft.AwsCredentialsManager.Services.Okta.Interactive;

namespace Ellosoft.AwsCredentialsManager.Commands.Okta;

[Name("logout")]
[Description("Sign out of Okta: ends the saved Okta session, the next AWS credentials renewal signs in again")]
[Examples(
    "logout",
    "logout xyz_profile")]
public class LogoutOkta(IOktaLoginService loginService) : AsyncCommand<LogoutOkta.Settings>
{
    public class Settings : CommonSettings
    {
        [CommandArgument(0, "[PROFILE]")]
        [DefaultValue(OktaConfiguration.DefaultProfileName)]
        [Description("Local Okta profile name")]
        public string Profile { get; set; } = OktaConfiguration.DefaultProfileName;
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var hadSession = await loginService.LogoutAsync(settings.Profile);

        AnsiConsole.MarkupLine(hadSession
            ? $"[green]Signed out of Okta, the '{settings.Profile}' Okta session was ended[/]"
            : $"[yellow]There is no saved Okta session for the '{settings.Profile}' Okta profile[/]");

        return 0;
    }
}
