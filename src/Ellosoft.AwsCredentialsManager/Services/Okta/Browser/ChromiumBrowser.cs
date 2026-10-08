// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Diagnostics;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

public sealed record BrowserLaunchOptions
{
    public bool Headless { get; init; }

    public IReadOnlyList<string> ExtraArguments { get; init; } = [];

    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
///     The DevTools endpoint of the browser did not come up: remote debugging is most likely disabled by an organization policy
/// </summary>
public sealed class BrowserDevToolsUnavailableException(string message) : OktaBrowserSignInException(message);

/// <summary>
///     A Chromium based browser (Edge, Chrome...) running with a dedicated profile and driven through the DevTools protocol
/// </summary>
public sealed class ChromiumBrowser : IAsyncDisposable
{
    private const string DEV_TOOLS_ACTIVE_PORT_FILE = "DevToolsActivePort";

    private readonly Process? _process;
    private readonly ILogger _logger;

    private ChromiumBrowser(CdpConnection connection, Process? process, ILogger logger)
    {
        Connection = connection;
        _process = process;
        _logger = logger;
    }

    public CdpConnection Connection { get; }

    /// <summary>
    ///     False when a browser left open by a previous sign-in (same profile) was reused
    /// </summary>
    public bool IsNewInstance => _process is not null;

    public static async Task<ChromiumBrowser> LaunchAsync(string executablePath, string userDataDirectory, BrowserLaunchOptions options,
        ILogger logger, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(userDataDirectory);

        var activePortFile = Path.Combine(userDataDirectory, DEV_TOOLS_ACTIVE_PORT_FILE);

        // a browser still running with this profile keeps it locked (a new process would just hand over to it), reuse it instead
        if (await TryConnectAsync(activePortFile, logger, cancellationToken) is { } existingConnection)
            return new ChromiumBrowser(existingConnection, null, logger);

        TryDeleteFile(activePortFile, logger);

        var process = StartProcess(executablePath, userDataDirectory, options, logger);

        try
        {
            var endpoint = await WaitForDevToolsEndpointAsync(executablePath, activePortFile, process, options.StartupTimeout, cancellationToken);
            var connection = await CdpConnection.ConnectAsync(endpoint, cancellationToken);

            return new ChromiumBrowser(connection, process, logger);
        }
        catch
        {
            KillProcess(process, logger);
            process.Dispose();

            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!Connection.IsClosed)
        {
            try
            {
                using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Connection.SendAsync("Browser.close", cancellationToken: closeTimeout.Token);
            }
            catch (Exception e) when (e is CdpException or OperationCanceledException)
            {
                _logger.LogDebug(e, "Unable to close the browser through the DevTools protocol");
            }
        }

        await Connection.DisposeAsync();

        if (_process is null)
            return;

        if (!await WaitForExitAsync(_process, TimeSpan.FromSeconds(5)))
            KillProcess(_process, _logger);

        _process.Dispose();
    }

    private static Process StartProcess(string executablePath, string userDataDirectory, BrowserLaunchOptions options, ILogger logger)
    {
        var startInfo = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var argument in GetArguments(userDataDirectory, options))
            startInfo.ArgumentList.Add(argument);

        Process? process;

        try
        {
            process = Process.Start(startInfo);
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException)
        {
            throw new OktaBrowserSignInException($"Unable to start the browser '{executablePath}': {e.Message}");
        }

        if (process is null)
            throw new OktaBrowserSignInException($"Unable to start the browser '{executablePath}'");

        // keep the browser console output out of the terminal
        process.OutputDataReceived += (_, e) => LogBrowserOutput(logger, e.Data);
        process.ErrorDataReceived += (_, e) => LogBrowserOutput(logger, e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        return process;
    }

    private static List<string> GetArguments(string userDataDirectory, BrowserLaunchOptions options)
    {
        var arguments = new List<string>
        {
            "--remote-debugging-port=0",
            $"--user-data-dir={userDataDirectory}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-search-engine-choice-screen",
            "--hide-crash-restore-bubble"
        };

        if (options.Headless)
            arguments.Add("--headless=new");

        arguments.AddRange(options.ExtraArguments);
        arguments.Add("about:blank");

        return arguments;
    }

    private static async Task<Uri> WaitForDevToolsEndpointAsync(string executablePath, string activePortFile, Process process, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            if (TryReadDevToolsEndpoint(activePortFile) is { } endpoint)
                return endpoint;

            if (process.HasExited)
            {
                throw new OktaBrowserSignInException(
                    $"The browser '{Path.GetFileName(executablePath)}' closed before the sign-in started (exit code {process.ExitCode}). " +
                    "If a browser window opened by aws-cred-mgr is still open, close it and try again");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
        }

        throw new BrowserDevToolsUnavailableException(
            $"Unable to control the browser '{Path.GetFileName(executablePath)}': its remote debugging endpoint did not start. " +
            "Remote debugging may be disabled by your organization, set 'browser_path' in the 'config' section of the aws-cred-mgr " +
            "configuration to a different Chromium based browser (Edge, Chrome)");
    }

    private static async Task<CdpConnection?> TryConnectAsync(string activePortFile, ILogger logger, CancellationToken cancellationToken)
    {
        if (TryReadDevToolsEndpoint(activePortFile) is not { } endpoint)
            return null;

        try
        {
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(TimeSpan.FromSeconds(2));

            return await CdpConnection.ConnectAsync(endpoint, connectTimeout.Token);
        }
        catch (Exception e) when (e is System.Net.WebSockets.WebSocketException or OperationCanceledException or HttpRequestException)
        {
            logger.LogDebug(e, "No browser running on the previous DevTools endpoint {Endpoint}", endpoint);

            return null;
        }
    }

    /// <summary>
    ///     Chromium writes the DevTools port (first line) and browser endpoint path (second line) to DevToolsActivePort
    /// </summary>
    private static Uri? TryReadDevToolsEndpoint(string activePortFile)
    {
        string[] lines;

        try
        {
            if (!File.Exists(activePortFile))
                return null;

            lines = File.ReadAllLines(activePortFile);
        }
        catch (IOException)
        {
            return null;
        }

        if (lines.Length < 2 || !int.TryParse(lines[0], out var port) || port <= 0 || !lines[1].StartsWith("/devtools/browser/", StringComparison.Ordinal))
            return null;

        return new Uri($"ws://127.0.0.1:{port}{lines[1].Trim()}");
    }

    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout)
    {
        using var exitTimeout = new CancellationTokenSource(timeout);

        try
        {
            await process.WaitForExitAsync(exitTimeout.Token);

            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static void KillProcess(Process process, ILogger logger)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch (Exception e) when (e is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            logger.LogDebug(e, "Unable to stop the browser process");
        }
    }

    private static void TryDeleteFile(string path, ILogger logger)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            logger.LogDebug(e, "Unable to delete {Path}", path);
        }
    }

    private static void LogBrowserOutput(ILogger logger, string? line)
    {
        if (!string.IsNullOrWhiteSpace(line))
            logger.LogTrace("Browser: {Line}", line);
    }
}
