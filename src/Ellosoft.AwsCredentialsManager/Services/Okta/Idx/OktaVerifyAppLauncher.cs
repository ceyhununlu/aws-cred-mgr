// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaVerifyAppLauncher
{
    /// <summary>
    ///     Opens an Okta Verify deep link (e.g. com-okta-authenticator:/deviceChallenge?challengeRequest=...) with the OS,
    ///     launching the Okta Verify desktop app
    /// </summary>
    /// <returns>true if the OS accepted the request</returns>
    bool TryLaunch(string uri);

    /// <summary>
    ///     Starts the Okta Verify desktop app without a challenge so that its loopback server becomes available
    ///     (Windows: OktaVerify.exe from the install directory / URI handler registration, macOS: <c>open -a "Okta Verify"</c>)
    /// </summary>
    /// <returns>true if the app was started (or was already running)</returns>
    bool TryStartApp();
}

public class OktaVerifyAppLauncher(ILogger<OktaVerifyAppLauncher> logger) : IOktaVerifyAppLauncher
{
    /// <summary>
    ///     URI scheme registered by the Okta Verify desktop app (CUSTOM_URI challenge method)
    /// </summary>
    public const string OktaVerifyScheme = "com-okta-authenticator";

    private const string WindowsExecutableName = "OktaVerify.exe";
    private const string MacOsAppName = "Okta Verify";
    private const string MacOsOpenCommand = "/usr/bin/open";

    private static readonly TimeSpan LauncherExitTimeout = TimeSpan.FromSeconds(10);

    public bool TryLaunch(string uri)
    {
        // the URI comes from the Okta response: only the Okta Verify scheme may be handed to the OS URI handler
        if (!IsOktaVerifyDeepLink(uri))
        {
            logger.LogWarning("Refusing to open Okta Verify: unexpected URI scheme '{Scheme}'", uri.Split(':')[0]);

            return false;
        }

        try
        {
            var startInfo = CreateStartInfo(uri);

            using var process = Process.Start(startInfo);

            // ShellExecute returns no process when the URI is handed to an already running Okta Verify instance
            if (OperatingSystem.IsWindows())
                return true;

            if (process is null)
                return false;

            // 'open' / 'xdg-open' exit with a non-zero code when no application handles the URI scheme
            return process.WaitForExit(LauncherExitTimeout) && process.ExitCode == 0;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException)
        {
            logger.LogWarning(e, "Unable to launch Okta Verify using URI scheme {Scheme}", uri.Split(':')[0]);

            return false;
        }
    }

    public bool TryStartApp()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return TryStartWindowsApp();

            if (OperatingSystem.IsMacOS())
                return TryStartMacOsApp();

            logger.LogWarning("Starting Okta Verify is not supported on this platform");

            return false;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException or PlatformNotSupportedException or System.Security.SecurityException)
        {
            logger.LogWarning(e, "Unable to start Okta Verify");

            return false;
        }
    }

    public static bool IsOktaVerifyDeepLink(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
        && string.Equals(parsed.Scheme, OktaVerifyScheme, StringComparison.OrdinalIgnoreCase);

    [SupportedOSPlatform("windows")]
    private bool TryStartWindowsApp()
    {
        var executable = FindWindowsExecutable();

        if (executable is null)
        {
            logger.LogWarning("Okta Verify does not seem to be installed ({Executable} not found)", WindowsExecutableName);

            return false;
        }

        logger.LogInformation("Starting Okta Verify: {Executable}", executable);

        // a second OktaVerify.exe instance hands over to the running one and exits, so the process handle is not meaningful
        using var process = Process.Start(new ProcessStartInfo(executable) { UseShellExecute = true });

        return true;
    }

    private bool TryStartMacOsApp()
    {
        logger.LogInformation("Starting Okta Verify: open -a \"{App}\"", MacOsAppName);

        using var process = Process.Start(new ProcessStartInfo(MacOsOpenCommand, ["-a", MacOsAppName])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        });

        // 'open' exits with a non-zero code when the application is not installed
        return process is not null && process.WaitForExit(LauncherExitTimeout) && process.ExitCode == 0;
    }

    [SupportedOSPlatform("windows")]
    private string? FindWindowsExecutable() =>
        WellKnownWindowsExecutablePaths()
            .Concat(WindowsExecutablePathsFromUriHandlerRegistration())
            .FirstOrDefault(File.Exists);

    private static IEnumerable<string> WellKnownWindowsExecutablePaths()
    {
        foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.LocalApplicationData })
        {
            var root = Environment.GetFolderPath(folder);

            if (!string.IsNullOrEmpty(root))
                yield return Path.Combine(root, "Okta", "Okta Verify", WindowsExecutableName);
        }
    }

    /// <summary>
    ///     Okta Verify registers the com-okta-authenticator URI scheme; the registered command starts with the executable path
    /// </summary>
    [SupportedOSPlatform("windows")]
    private IEnumerable<string> WindowsExecutablePathsFromUriHandlerRegistration()
    {
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            string? command;

            try
            {
                using var key = hive.OpenSubKey($@"Software\Classes\{OktaVerifyScheme}\shell\open\command");

                command = key?.GetValue(null) as string;
            }
            catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException)
            {
                logger.LogDebug(e, "Unable to read the Okta Verify URI handler registration from {Hive}", hive.Name);

                continue;
            }

            if (ExtractExecutablePath(command) is { } executable)
                yield return executable;
        }
    }

    /// <summary>
    ///     Reads the executable from a shell command such as <c>"C:\Program Files\Okta\Okta Verify\OktaVerify.exe" --URI "%1"</c>
    /// </summary>
    public static string? ExtractExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;

        command = command.Trim();

        string executable;

        if (command.StartsWith('"'))
        {
            var closingQuote = command.IndexOf('"', 1);

            if (closingQuote < 0)
                return null;

            executable = command[1..closingQuote];
        }
        else
        {
            var exeIndex = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);

            executable = exeIndex < 0 ? command.Split(' ')[0] : command[..(exeIndex + 4)];
        }

        return executable.EndsWith(WindowsExecutableName, StringComparison.OrdinalIgnoreCase) ? executable : null;
    }

    private static ProcessStartInfo CreateStartInfo(string uri)
    {
        if (OperatingSystem.IsWindows())
            return new ProcessStartInfo(uri) { UseShellExecute = true };

        var launcher = OperatingSystem.IsMacOS() ? "open" : "xdg-open";

        return new ProcessStartInfo(launcher, [uri])
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
    }
}
