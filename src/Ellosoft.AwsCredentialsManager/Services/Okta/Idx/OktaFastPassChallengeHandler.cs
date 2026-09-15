// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Ellosoft.AwsCredentialsManager.Services.Okta.Exceptions;
using Microsoft.Extensions.Logging;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Idx;

public interface IOktaFastPassChallengeHandler
{
    /// <summary>
    ///     Delivers an Okta Verify (FastPass) device challenge to the Okta Verify app running on this machine and polls
    ///     Okta until the sign-in transaction moves on
    /// </summary>
    /// <param name="idxClient">IDX client bound to the current sign-in transaction</param>
    /// <param name="oktaDomain">Okta org domain</param>
    /// <param name="challengeResponse">IDX response containing a "challenge-poll" or "device-challenge-poll" remediation</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    ///     The IDX response that ended the polling: success, an error, or a new remediation step
    ///     (e.g. "launch-authenticator" after Okta Verify could not be reached through the loopback server)
    /// </returns>
    Task<IdxResponse> ExecuteAsync(IdxClient idxClient, Uri oktaDomain, IdxResponse challengeResponse, CancellationToken cancellationToken);
}

/// <summary>
///     Implements the two FastPass challenge bindings used by the Okta Sign-In Widget on desktop:
///     LOOPBACK (Okta Verify local HTTP server) and CUSTOM_URI (deep link that launches Okta Verify)
/// </summary>
public class OktaFastPassChallengeHandler(
    IOktaIdxHttpClientFactory httpClientFactory,
    IOktaVerifyAppLauncher appLauncher,
    IAnsiConsole console,
    ILogger<OktaFastPassChallengeHandler> logger) : IOktaFastPassChallengeHandler
{
    private const string REASON_UNREACHABLE = "OV_UNREACHABLE_BY_LOOPBACK";
    private const string REASON_ERROR = "OV_RETURNED_ERROR";
    private const string REASON_CANCELED = "USER_CANCELED";
    private const string DefaultLoopbackDomain = "http://localhost";

    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MinProbeTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    ///     Maximum time to wait for the user to approve the sign-in in Okta Verify
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    ///     When Okta offers the loopback binding first, ask Okta to open Okta Verify (deep link) right away instead of
    ///     probing the loopback ports: the app comes to the foreground with the approval prompt, and it also works when
    ///     Okta Verify is not running. Loopback is still used when Okta does not offer to open the app.
    ///     <para>
    ///         Not on Windows: cancelling the loopback challenge there hands the sign-in back to the Okta identifier step,
    ///         which orgs commonly route to an external identity provider for Windows clients ("redirect-idp", a browser
    ///         navigation this tool cannot follow). On Windows the challenge is delivered to the Okta Verify tray app
    ///         through loopback, exactly like the Sign-In Widget does, and the app is started when it is not running.
    ///     </para>
    /// </summary>
    public bool PreferAppLaunch { get; set; } = !OperatingSystem.IsWindows();

    /// <summary>
    ///     When the loopback server does not answer, start Okta Verify and probe again (for up to <see cref="AppStartupTimeout" />)
    ///     before asking Okta for another way to open the app
    /// </summary>
    public bool StartOktaVerifyWhenUnreachable { get; set; } = OperatingSystem.IsWindows();

    /// <summary>
    ///     How long to keep probing the loopback server after Okta Verify has been started
    /// </summary>
    public TimeSpan AppStartupTimeout { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>
    ///     Delay between two loopback probes while waiting for Okta Verify to start
    /// </summary>
    public TimeSpan AppStartupProbeInterval { get; set; } = TimeSpan.FromSeconds(2);

    public async Task<IdxResponse> ExecuteAsync(IdxClient idxClient, Uri oktaDomain, IdxResponse challengeResponse, CancellationToken cancellationToken)
    {
        var context = PollingContext.Create(challengeResponse, oktaDomain);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);

        try
        {
            if (PreferAppLaunch && context.Challenge.IsLoopback)
            {
                var appLaunchResponse = await RequestAppLaunchAsync(idxClient, context, timeoutCts.Token);

                if (!KeepsLoopbackChallenge(appLaunchResponse))
                    return appLaunchResponse;

                logger.LogDebug("Okta did not offer to open Okta Verify, falling back to the loopback server");

                context = PollingContext.Create(appLaunchResponse, oktaDomain);
            }

            return await PollAsync(idxClient, oktaDomain, context, timeoutCts.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            await CancelPollingAsync(idxClient, context, REASON_CANCELED, null, CancellationToken.None);

            throw new OktaFastPassException("Timed out waiting for Okta Verify. Please try again");
        }
    }

    /// <summary>
    ///     Cancels the loopback challenge the same way the Sign-In Widget does when Okta Verify is not reachable;
    ///     Okta then returns the "launch-authenticator" remediation carrying the Okta Verify deep link
    /// </summary>
    private Task<IdxResponse> RequestAppLaunchAsync(IdxClient idxClient, PollingContext context, CancellationToken cancellationToken)
    {
        console.MarkupLine("Requesting Okta to open Okta Verify on this device...");

        return CancelPollingAsync(idxClient, context, REASON_UNREACHABLE, null, cancellationToken);
    }

    private static bool KeepsLoopbackChallenge(IdxResponse response) =>
        response is { IsSuccess: false, HasErrors: false, PollRemediation: not null, DeviceChallenge.IsLoopback: true }
        && response.GetRemediation(IdxResponse.LaunchAuthenticatorRemediation) is null;

    private async Task<IdxResponse> PollAsync(IdxClient idxClient, Uri oktaDomain, PollingContext context, CancellationToken cancellationToken)
    {
        using var recovery = new LoopbackRecovery();

        var loopbackTask = await DeliverChallengeAsync(idxClient, oktaDomain, context, cancellationToken);

        console.MarkupLine("Waiting for Okta Verify...");

        while (true)
        {
            if (loopbackTask is { IsCompleted: true })
            {
                var outcome = await loopbackTask;

                var nextStep = await HandleLoopbackOutcomeAsync(idxClient, oktaDomain, context, outcome, recovery, cancellationToken);

                if (nextStep.CancelResponse is not null)
                    return nextStep.CancelResponse;

                loopbackTask = nextStep.RetryTask;
            }
            else
            {
                await Task.Delay(GetPollInterval(context.PollRemediation), cancellationToken);
            }

            var response = await idxClient.PostAsync(context.PollRemediation.Href, context.StateHandle, cancellationToken);

            if (response.IsSuccess || response.HasErrors || response.DeviceChallenge is null || response.PollRemediation is null)
                return response;

            var previousChallenge = context.Challenge;
            context = context.Update(response);

            // Okta issued a new challenge (e.g. user verification step-up), deliver it as well
            if (!IsSameChallenge(previousChallenge, context.Challenge))
            {
                recovery.CancelPendingRetry();
                loopbackTask = await DeliverChallengeAsync(idxClient, oktaDomain, context, cancellationToken);
            }
        }
    }

    /// <summary>
    ///     Starts the loopback challenge (returned task completes when Okta Verify accepts or refuses the challenge)
    ///     or launches Okta Verify through its deep link
    /// </summary>
    private async Task<Task<LoopbackOutcome>?> DeliverChallengeAsync(IdxClient idxClient, Uri oktaDomain, PollingContext context, CancellationToken cancellationToken)
    {
        var challenge = context.Challenge;

        if (challenge.IsLoopback)
        {
            console.MarkupLine("Contacting Okta Verify on this device... If Okta Verify asks you to confirm the sign-in, please approve it");

            return RunLoopbackAsync(challenge, oktaDomain, cancellationToken);
        }

        console.MarkupLine("Opening Okta Verify... Please approve the sign-in request in the app");

        if (challenge.Href is not null && appLauncher.TryLaunch(challenge.Href))
            return null;

        logger.LogError("Unable to open Okta Verify using challenge method {Method}", challenge.Method);

        await CancelPollingAsync(idxClient, context, REASON_CANCELED, null, CancellationToken.None);

        throw new OktaFastPassException("Unable to open Okta Verify. Please make sure Okta Verify is installed on this device and try again");
    }

    /// <summary>
    ///     Decides what happens after a loopback attempt: keep polling (delivered), probe again once Okta Verify has been
    ///     started, or cancel the challenge and let Okta offer an alternative
    /// </summary>
    private async Task<LoopbackNextStep> HandleLoopbackOutcomeAsync(IdxClient idxClient, Uri oktaDomain, PollingContext context, LoopbackOutcome outcome,
        LoopbackRecovery recovery, CancellationToken cancellationToken)
    {
        switch (outcome.Kind)
        {
            case LoopbackOutcomeKind.Delivered:
                console.MarkupLine("[green]Okta Verify answered the sign-in request[/], confirming with Okta...");

                return LoopbackNextStep.KeepPolling;

            case LoopbackOutcomeKind.Unreachable:
                if (TryScheduleLoopbackRetry(oktaDomain, context, recovery, cancellationToken, out var retryTask))
                    return new LoopbackNextStep(null, retryTask);

                console.MarkupLine("[yellow]Okta Verify could not be reached on this device, asking Okta for another way to open it...[/]");

                return new LoopbackNextStep(await CancelAndCheckForDeadEndAsync(idxClient, context, REASON_UNREACHABLE, null,
                    $"could not be reached on this device (loopback ports {string.Join(", ", context.Challenge.Ports)})", cancellationToken), null);

            case LoopbackOutcomeKind.Error:
                console.MarkupLine($"[yellow]Okta Verify rejected the sign-in request (HTTP {outcome.StatusCode}), asking Okta for another option...[/]");

                return new LoopbackNextStep(await CancelAndCheckForDeadEndAsync(idxClient, context, REASON_ERROR, outcome.StatusCode,
                    $"rejected the FastPass challenge (HTTP {outcome.StatusCode})", cancellationToken), null);

            default:
                throw new InvalidOperationException($"Unknown loopback outcome {outcome.Kind}");
        }
    }

    /// <summary>
    ///     Okta Verify is not listening: start it (once) and keep probing until <see cref="AppStartupTimeout" /> elapses
    /// </summary>
    private bool TryScheduleLoopbackRetry(Uri oktaDomain, PollingContext context, LoopbackRecovery recovery, CancellationToken cancellationToken,
        [NotNullWhen(true)] out Task<LoopbackOutcome>? retryTask)
    {
        retryTask = null;

        if (!StartOktaVerifyWhenUnreachable)
            return false;

        if (!recovery.AppStartAttempted)
        {
            recovery.AppStartAttempted = true;

            console.MarkupLine("[yellow]Okta Verify is not reachable on this device, starting Okta Verify...[/]");

            if (!appLauncher.TryStartApp())
            {
                console.MarkupLine("[yellow]Okta Verify could not be started[/]");

                return false;
            }

            recovery.StartWaiting(AppStartupTimeout);
        }
        else if (!recovery.IsWaitingForApp)
        {
            logger.LogWarning("Okta Verify did not become reachable within {Timeout} after being started", AppStartupTimeout);

            return false;
        }

        retryTask = recovery.ScheduleRetry(retryToken => RetryLoopbackAsync(context.Challenge, oktaDomain, retryToken), cancellationToken);

        return true;
    }

    private async Task<LoopbackOutcome> RetryLoopbackAsync(IdxDeviceChallenge challenge, Uri oktaDomain, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(AppStartupProbeInterval, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // the retry was superseded by a new challenge (or the sign-in timed out), nothing to deliver anymore
            return LoopbackOutcome.Unreachable;
        }

        logger.LogDebug("Probing the Okta Verify loopback server again");

        return await RunLoopbackAsync(challenge, oktaDomain, cancellationToken);
    }

    /// <summary>
    ///     Cancels the loopback challenge (Okta then decides the next step). When Okta answers with nothing but an
    ///     identity provider redirect, the sign-in cannot continue outside a browser: fail with an explanation instead
    ///     of surfacing an "unsupported step" error
    /// </summary>
    private async Task<IdxResponse> CancelAndCheckForDeadEndAsync(IdxClient idxClient, PollingContext context, string reason, int? statusCode,
        string oktaVerifyFailure, CancellationToken cancellationToken)
    {
        var response = await CancelPollingAsync(idxClient, context, reason, statusCode, cancellationToken);

        if (!response.IsIdpRedirectOnly)
            return response;

        var idps = string.Join(" / ", response.IdpRedirects.Select(i => i.Description));

        logger.LogError("Okta Verify {Failure}; Okta answered the cancellation with an identity provider redirect only ({Idps})", oktaVerifyFailure, idps);

        throw new OktaFastPassException(
            $"Okta Verify {oktaVerifyFailure}, and Okta then redirected the sign-in to {idps} instead of offering another way to open Okta Verify " +
            "(this is how Okta identity provider routing rules behave, typically for Windows clients). " +
            "Okta FastPass can only complete when Okta Verify is installed, enrolled and running on this device: " +
            "check the Okta Verify icon in the system tray (open the app and sign in if it asks you to), then try again. " +
            "Alternatively configure a different MFA type (push, totp)");
    }

    /// <summary>
    ///     Mirrors the Sign-In Widget loopback probe: GET {domain}:{port}/probe for each port, then
    ///     POST {domain}:{port}/challenge with the challenge JWT on the first port that answers
    /// </summary>
    private async Task<LoopbackOutcome> RunLoopbackAsync(IdxDeviceChallenge challenge, Uri oktaDomain, CancellationToken cancellationToken)
    {
        var domain = challenge.Domain ?? DefaultLoopbackDomain;

        // the domain comes from the Okta response: the challenge JWT is only ever sent to the loopback interface over plain http
        if (!Uri.TryCreate(domain, UriKind.Absolute, out var domainUri) || domainUri.Scheme != Uri.UriSchemeHttp || !domainUri.IsLoopback)
        {
            logger.LogError("Ignoring Okta Verify loopback challenge for non-loopback domain {Domain}", domain);

            return LoopbackOutcome.Unreachable;
        }

        using var loopbackClient = httpClientFactory.CreateLoopbackClient();

        var probeTimeout = TimeSpan.FromMilliseconds(Math.Max(challenge.ProbeTimeoutMillis ?? 0, MinProbeTimeout.TotalMilliseconds));
        var origin = oktaDomain.GetLeftPart(UriPartial.Authority);
        var challengeBody = new JsonObject { ["challengeRequest"] = challenge.ChallengeRequest }.ToJsonString();

        foreach (var port in challenge.Ports)
        {
            var baseUrl = new UriBuilder(domainUri) { Port = port, Path = string.Empty, Query = string.Empty }.Uri.GetLeftPart(UriPartial.Authority);

            try
            {
                if (!await ProbeAsync(loopbackClient, baseUrl, probeTimeout, cancellationToken))
                {
                    logger.LogDebug("Okta Verify loopback probe at {BaseUrl} was not successful", baseUrl);

                    continue;
                }

                logger.LogDebug("Okta Verify is listening on {BaseUrl}, delivering the FastPass challenge", baseUrl);

                using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/challenge");
                request.Headers.TryAddWithoutValidation("Origin", origin);
                request.Content = new StringContent(challengeBody, Encoding.UTF8, "application/json");

                using var response = await loopbackClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    logger.LogDebug("Okta Verify at {BaseUrl} answered the challenge with status {StatusCode}", baseUrl, (int)response.StatusCode);

                    return LoopbackOutcome.Delivered;
                }

                // Okta Verify answers 503 when another OS user profile owns the port
                if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    logger.LogDebug("Okta Verify at {BaseUrl} belongs to another OS user profile (503), trying the next port", baseUrl);

                    continue;
                }

                logger.LogError("Okta Verify loopback server at {BaseUrl} rejected the challenge with status {StatusCode}", baseUrl, (int)response.StatusCode);

                return LoopbackOutcome.Error((int)response.StatusCode);
            }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException)
            {
                logger.LogDebug(e, "Okta Verify is not listening on {BaseUrl}", baseUrl);
            }
        }

        logger.LogInformation("Okta Verify loopback server not reachable on {Domain} ports {Ports}", domain, string.Join(", ", challenge.Ports));

        return LoopbackOutcome.Unreachable;
    }

    private static async Task<bool> ProbeAsync(HttpClient loopbackClient, string baseUrl, TimeSpan probeTimeout, CancellationToken cancellationToken)
    {
        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCts.CancelAfter(probeTimeout);

        using var probeResponse = await loopbackClient.GetAsync($"{baseUrl}/probe", probeCts.Token);

        return probeResponse.IsSuccessStatusCode;
    }

    private static async Task<IdxResponse> CancelPollingAsync(IdxClient idxClient, PollingContext context, string reason, int? statusCode,
        CancellationToken cancellationToken)
    {
        var body = new JsonObject
        {
            ["stateHandle"] = context.StateHandle,
            ["reason"] = reason,
            ["statusCode"] = statusCode
        };

        return await idxClient.PostAsync(context.CancelHref, body, cancellationToken);
    }

    private static bool IsSameChallenge(IdxDeviceChallenge current, IdxDeviceChallenge next) =>
        current.Method == next.Method && current.ChallengeRequest == next.ChallengeRequest && current.Href == next.Href;

    private static TimeSpan GetPollInterval(IdxRemediation pollRemediation)
    {
        var interval = pollRemediation.Refresh is { } refresh ? TimeSpan.FromMilliseconds(refresh) : DefaultPollInterval;

        return interval > MaxPollInterval ? MaxPollInterval : interval;
    }

    private sealed record PollingContext(IdxDeviceChallenge Challenge, IdxRemediation PollRemediation, string StateHandle, string CancelHref)
    {
        public static PollingContext Create(IdxResponse response, Uri oktaDomain) => new(
            response.DeviceChallenge ?? throw new InvalidOperationException("Okta response does not contain a device challenge"),
            response.PollRemediation ?? throw new InvalidOperationException("Okta response does not contain a poll remediation"),
            response.StateHandle ?? throw new InvalidOperationException("Okta response does not contain a state handle"),
            response.CancelPollingHref ?? new Uri(oktaDomain, "/idp/idx/authenticators/poll/cancel").ToString());

        public PollingContext Update(IdxResponse response) => this with
        {
            Challenge = response.DeviceChallenge ?? Challenge,
            PollRemediation = response.PollRemediation ?? PollRemediation,
            StateHandle = response.StateHandle ?? StateHandle,
            CancelHref = response.CancelPollingHref ?? CancelHref
        };
    }

    /// <summary>
    ///     Tracks the "start Okta Verify and probe again" recovery of one polling session
    /// </summary>
    private sealed class LoopbackRecovery : IDisposable
    {
        private long _waitDeadlineTimestamp;
        private CancellationTokenSource? _pendingRetry;

        /// <summary>
        ///     The polling session is over (success, error, cancellation): a retry still pending must not deliver anything
        /// </summary>
        public void Dispose() => CancelPendingRetry();

        public bool AppStartAttempted { get; set; }

        public bool IsWaitingForApp => Stopwatch.GetTimestamp() < _waitDeadlineTimestamp;

        public void StartWaiting(TimeSpan duration) => _waitDeadlineTimestamp = Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency);

        public Task<LoopbackOutcome> ScheduleRetry(Func<CancellationToken, Task<LoopbackOutcome>> retry, CancellationToken cancellationToken)
        {
            CancelPendingRetry();

            _pendingRetry = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            return retry(_pendingRetry.Token);
        }

        /// <summary>
        ///     A retry still waiting for its turn must not deliver a challenge Okta has already replaced
        /// </summary>
        public void CancelPendingRetry()
        {
            _pendingRetry?.Cancel();
            _pendingRetry?.Dispose();
            _pendingRetry = null;
        }
    }

    /// <summary>
    ///     What the polling loop does after a loopback attempt: return Okta's answer to the cancellation, wait for a
    ///     scheduled loopback retry, or just keep polling
    /// </summary>
    private sealed record LoopbackNextStep(IdxResponse? CancelResponse, Task<LoopbackOutcome>? RetryTask)
    {
        public static readonly LoopbackNextStep KeepPolling = new(null, null);
    }

    private enum LoopbackOutcomeKind
    {
        Delivered,
        Unreachable,
        Error
    }

    private sealed record LoopbackOutcome(LoopbackOutcomeKind Kind, int? StatusCode = null)
    {
        public static readonly LoopbackOutcome Delivered = new(LoopbackOutcomeKind.Delivered);
        public static readonly LoopbackOutcome Unreachable = new(LoopbackOutcomeKind.Unreachable);

        public static LoopbackOutcome Error(int statusCode) => new(LoopbackOutcomeKind.Error, statusCode);
    }
}
