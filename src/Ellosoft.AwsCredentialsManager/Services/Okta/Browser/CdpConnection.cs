// Copyright (c) 2026 Ellosoft Limited. All rights reserved.

using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;

namespace Ellosoft.AwsCredentialsManager.Services.Okta.Browser;

public sealed record CdpEvent(string Method, JsonObject Params, string? SessionId);

public class CdpException(string message) : Exception(message);

public sealed class CdpConnectionClosedException() : CdpException("The browser connection was closed");

/// <summary>
///     Minimal Chrome DevTools Protocol client (commands + events) over the browser WebSocket endpoint
/// </summary>
public sealed class CdpConnection : IAsyncDisposable
{
    private readonly ClientWebSocket _socket;
    private readonly ConcurrentDictionary<int, PendingCommand> _pendingCommands = new();
    private readonly Channel<CdpEvent> _events = Channel.CreateUnbounded<CdpEvent>(new UnboundedChannelOptions { SingleReader = true });
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Task _receiveLoop;
    private int _lastCommandId;
    private volatile bool _closed;

    private CdpConnection(ClientWebSocket socket)
    {
        _socket = socket;
        _receiveLoop = Task.Run(ReceiveLoopAsync, CancellationToken.None);
    }

    public ChannelReader<CdpEvent> Events => _events.Reader;

    public bool IsClosed => _closed;

    public static async Task<CdpConnection> ConnectAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        var socket = new ClientWebSocket();

        // the DevTools endpoint is on the loopback interface, it must never go through a proxy
        socket.Options.Proxy = null;

        try
        {
            await socket.ConnectAsync(endpoint, cancellationToken);
        }
        catch
        {
            socket.Dispose();

            throw;
        }

        return new CdpConnection(socket);
    }

    public async Task<JsonObject> SendAsync(string method, JsonObject? parameters = null, string? sessionId = null,
        CancellationToken cancellationToken = default)
    {
        var id = Interlocked.Increment(ref _lastCommandId);

        var message = new JsonObject
        {
            ["id"] = id,
            ["method"] = method,
            ["params"] = parameters ?? new JsonObject()
        };

        if (sessionId is not null)
            message["sessionId"] = sessionId;

        var pendingCommand = new PendingCommand(method);
        _pendingCommands[id] = pendingCommand;

        try
        {
            if (_closed)
                throw new CdpConnectionClosedException();

            var payload = Encoding.UTF8.GetBytes(message.ToJsonString());

            await _sendLock.WaitAsync(cancellationToken);

            try
            {
                await _socket.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
            }
            catch (Exception e) when (e is WebSocketException or ObjectDisposedException)
            {
                throw new CdpConnectionClosedException();
            }
            finally
            {
                _sendLock.Release();
            }

            await using var registration = cancellationToken.Register(() => pendingCommand.Completion.TrySetCanceled(cancellationToken));

            return await pendingCommand.Completion.Task;
        }
        finally
        {
            _pendingCommands.TryRemove(id, out _);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _disposeCts.CancelAsync();
        _socket.Abort();

        try
        {
            await _receiveLoop;
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException)
        {
            // the receive loop always ends once the socket is aborted
        }

        _socket.Dispose();
        _sendLock.Dispose();
        _disposeCts.Dispose();
    }

    private async Task ReceiveLoopAsync()
    {
        var buffer = new byte[16 * 1024];
        using var message = new MemoryStream();

        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                message.SetLength(0);
                ValueWebSocketReceiveResult result;

                do
                {
                    result = await _socket.ReceiveAsync(buffer.AsMemory(), _disposeCts.Token);

                    if (result.MessageType == WebSocketMessageType.Close)
                        return;

                    await message.WriteAsync(buffer.AsMemory(0, result.Count), _disposeCts.Token);
                } while (!result.EndOfMessage);

                if (Dispatch(message.GetBuffer().AsSpan(0, (int)message.Length)) is { } cdpEvent)
                    await _events.Writer.WriteAsync(cdpEvent, _disposeCts.Token);
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException or ObjectDisposedException)
        {
            // the browser closed the connection (browser closed by the user, crashed or disposed)
        }
        finally
        {
            _closed = true;
            _events.Writer.TryComplete();

            foreach (var pendingCommand in _pendingCommands.Values)
                pendingCommand.Completion.TrySetException(new CdpConnectionClosedException());
        }
    }

    /// <summary>
    ///     Completes the pending command a response belongs to, or returns the event carried by the message
    /// </summary>
    private CdpEvent? Dispatch(ReadOnlySpan<byte> payload)
    {
        JsonObject? message;

        try
        {
            message = JsonNode.Parse(payload) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }

        if (message is null)
            return null;

        if (message["id"] is JsonValue idValue && idValue.TryGetValue<int>(out var id))
        {
            if (!_pendingCommands.TryGetValue(id, out var pendingCommand))
                return null;

            if (message["error"] is JsonObject error)
                pendingCommand.Completion.TrySetException(new CdpException($"{pendingCommand.Method} failed: {error["message"]}"));
            else
                pendingCommand.Completion.TrySetResult(message["result"] as JsonObject ?? new JsonObject());

            return null;
        }

        if (message["method"] is not JsonValue methodValue || !methodValue.TryGetValue<string>(out var method))
            return null;

        var sessionId = message["sessionId"] is JsonValue sessionValue && sessionValue.TryGetValue<string>(out var value) ? value : null;

        return new CdpEvent(method, message["params"] as JsonObject ?? new JsonObject(), sessionId);
    }

    private sealed class PendingCommand(string method)
    {
        public string Method { get; } = method;

        public TaskCompletionSource<JsonObject> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
