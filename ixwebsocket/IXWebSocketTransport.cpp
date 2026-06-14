/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2012, 2013 <dhbaird@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 *  IXWebSocketTransport.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2019 Machine Zone, Inc. All rights reserved.
 */

//
// Adapted from https://github.com/dhbaird/easywsclient
//

#include "IXWebSocketTransport.h"

#include "IXHttp.h"
#include "IXSecureRandom.h"
#include "IXSocketFactory.h"
#include "IXSocketTLSOptions.h"
#include "IXStrCaseCompare.h"
#include "IXUniquePtr.h"
#include "IXUrlParser.h"
#include "IXUtf8Validator.h"
#include "IXWebSocketHandshake.h"
#include "IXWebSocketHttpHeaders.h"
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <string.h>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr size_t kMaxCloseReasonSize = 123;

    std::string truncateUtf8CloseReason(const std::string& reason)
    {
        std::string wireReason = reason;
        if (wireReason.size() > kMaxCloseReasonSize)
        {
            wireReason = wireReason.substr(0, kMaxCloseReasonSize);
        }

        while (!wireReason.empty() && !ix::validateUtf8(wireReason))
        {
            wireReason.pop_back();
        }

        return wireReason;
    }

    bool isValidCloseCodeForWire(uint16_t code)
    {
        return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
               (code >= 3000 && code <= 4999);
    }

    uint16_t sanitizeCloseCodeForWire(uint16_t code)
    {
        if (code == ix::WebSocketCloseConstants::kNoStatusCodeErrorCode)
        {
            return code;
        }

        return isValidCloseCodeForWire(code) ? code : ix::WebSocketCloseConstants::kProtocolErrorCode;
    }

    int clampInt64ToInt(int64_t value)
    {
        if (value > static_cast<int64_t>(std::numeric_limits<int>::max()))
        {
            return std::numeric_limits<int>::max();
        }

        if (value < static_cast<int64_t>(std::numeric_limits<int>::min()))
        {
            return std::numeric_limits<int>::min();
        }

        return static_cast<int>(value);
    }

    int secondsToMillisecondsClamped(int seconds)
    {
        return clampInt64ToInt(static_cast<int64_t>(seconds) * 1000);
    }

    bool isDefaultWebSocketPort(const std::string& protocol, int port)
    {
        return (protocol == "ws" && port == 80) || (protocol == "wss" && port == 443);
    }

    bool isSensitiveRedirectHeader(std::string_view name)
    {
        return ix::caseInsensitiveEquals(name, "authorization") ||
               ix::caseInsensitiveEquals(name, "proxy-authorization") ||
               ix::caseInsensitiveEquals(name, "cookie") ||
               ix::caseInsensitiveEquals(name, "cookie2") ||
               ix::caseInsensitiveEquals(name, "host");
    }

    void removeSensitiveRedirectHeaders(ix::WebSocketHttpHeaders& headers)
    {
        for (auto it = headers.begin(); it != headers.end();)
        {
            if (isSensitiveRedirectHeader(it->first))
            {
                it = headers.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    bool shouldForwardSensitiveHeaders(const std::string& fromUrl, const std::string& toUrl)
    {
        std::string fromProtocol;
        std::string fromHost;
        std::string fromPath;
        std::string fromQuery;
        int fromPort = 0;

        std::string toProtocol;
        std::string toHost;
        std::string toPath;
        std::string toQuery;
        int toPort = 0;

        if (!ix::UrlParser::parse(fromUrl, fromProtocol, fromHost, fromPath, fromQuery, fromPort) ||
            !ix::UrlParser::parse(toUrl, toProtocol, toHost, toPath, toQuery, toPort))
        {
            return false;
        }

        return ix::caseInsensitiveEquals(fromProtocol, toProtocol) &&
               ix::caseInsensitiveEquals(fromHost, toHost) && fromPort == toPort;
    }

    void splitPathAndQuery(const std::string& value, std::string& path, std::string& query)
    {
        std::string withoutFragment = value.substr(0, value.find('#'));
        auto queryPos = withoutFragment.find('?');

        if (queryPos == std::string::npos)
        {
            path = withoutFragment;
            query.clear();
            return;
        }

        path = withoutFragment.substr(0, queryPos);
        query = withoutFragment.substr(queryPos + 1);
    }

    std::string normalizeUrlPath(const std::string& path)
    {
        std::vector<std::string> segments;

        size_t start = 0;
        while (start <= path.size())
        {
            size_t slashPos = path.find('/', start);
            size_t end = (slashPos == std::string::npos) ? path.size() : slashPos;

            std::string segment = path.substr(start, end - start);
            if (segment == "..")
            {
                if (!segments.empty())
                {
                    segments.pop_back();
                }
            }
            else if (!segment.empty() && segment != ".")
            {
                segments.emplace_back(segment);
            }

            if (slashPos == std::string::npos)
            {
                break;
            }

            start = slashPos + 1;
        }

        std::string normalizedPath("/");
        for (size_t i = 0; i < segments.size(); ++i)
        {
            normalizedPath += segments[i];
            if (i + 1 != segments.size())
            {
                normalizedPath += '/';
            }
        }

        if (path.size() > 1 && path.back() == '/' && normalizedPath.back() != '/')
        {
            normalizedPath += '/';
        }

        return normalizedPath;
    }

    bool resolveRedirectUrl(const std::string& baseUrl,
                            const std::string& location,
                            std::string& resolvedUrl,
                            std::string& errorMsg)
    {
        if (location.empty())
        {
            errorMsg = "Redirect Location header is empty";
            return false;
        }

        if (ix::caseInsensitiveStartsWith(location, "ws://") ||
            ix::caseInsensitiveStartsWith(location, "wss://"))
        {
            resolvedUrl = location;
            return true;
        }

        if (ix::caseInsensitiveStartsWith(location, "http://"))
        {
            resolvedUrl = "ws://" + location.substr(7);
            return true;
        }

        if (ix::caseInsensitiveStartsWith(location, "https://"))
        {
            resolvedUrl = "wss://" + location.substr(8);
            return true;
        }

        std::string protocol;
        std::string host;
        std::string path;
        std::string query;
        int port = 0;
        if (!ix::UrlParser::parse(baseUrl, protocol, host, path, query, port))
        {
            errorMsg = "Could not parse redirect base url: " + baseUrl;
            return false;
        }

        std::string basePathOnly;
        std::string ignoredBaseQuery;
        splitPathAndQuery(path, basePathOnly, ignoredBaseQuery);
        if (basePathOnly.empty())
        {
            basePathOnly = "/";
        }

        if (location.rfind("//", 0) == 0)
        {
            resolvedUrl = protocol + ":" + location;
            return true;
        }

        std::string resolvedPath;
        std::string resolvedQuery;

        if (location[0] == '/')
        {
            splitPathAndQuery(location, resolvedPath, resolvedQuery);
        }
        else if (location[0] == '?')
        {
            resolvedPath = basePathOnly;
            resolvedQuery = location.substr(1);
        }
        else if (location[0] == '#')
        {
            resolvedPath = basePathOnly;
            resolvedQuery = query;
        }
        else
        {
            std::string basePath = basePathOnly;
            auto slashPos = basePath.rfind('/');
            std::string directory = (slashPos == std::string::npos) ? "/" : basePath.substr(0, slashPos + 1);

            std::string merged = directory + location;
            splitPathAndQuery(merged, resolvedPath, resolvedQuery);
        }

        resolvedPath = normalizeUrlPath(resolvedPath.empty() ? "/" : resolvedPath);

        std::stringstream ss;
        ss << protocol << "://" << ix::formatHttpHost(host);
        if (!isDefaultWebSocketPort(protocol, port))
        {
            ss << ":" << port;
        }
        ss << resolvedPath;
        if (!resolvedQuery.empty())
        {
            ss << "?" << resolvedQuery;
        }

        resolvedUrl = ss.str();
        return true;
    }
} // namespace

namespace ix
{
    const int WebSocketTransport::kDefaultPingIntervalSecs(-1);
    const bool WebSocketTransport::kDefaultEnablePong(true);
    const int WebSocketTransport::kClosingMaximumWaitingDelayInMs(300);
    constexpr size_t WebSocketTransport::kChunkSize;

    WebSocketTransport::WebSocketTransport()
        : _useMask(true)
        , _blockingSend(false)
        , _receivedMessageCompressed(false)
        , _readyState(ReadyState::CLOSED)
        , _closeCode(WebSocketCloseConstants::kInternalErrorCode)
        , _closeWireSize(0)
        , _closeRemote(false)
        , _enablePerMessageDeflate(false)
        , _requestInitCancellation(false)
        , _closingTimePoint(std::chrono::steady_clock::now())
        , _enablePong(kDefaultEnablePong)
        , _pingIntervalSecs(kDefaultPingIntervalSecs)
        , _pingTimeoutSecs(-1)
        , _idleTimeoutSecs(-1)
        , _sendTimeoutSecs(300)
        , _closeTimeoutMs(kClosingMaximumWaitingDelayInMs)
        , _pongReceived(false)
        , _lastPongTimePoint(std::chrono::steady_clock::now())
        , _lastActivityTimePoint(std::chrono::steady_clock::now())
        , _setCustomMessage(false)
        , _kPingMessage("ixwebsocket::heartbeat")
        , _pingType(SendMessageKind::Ping)
        , _pingCount(0)
        , _lastSendPingTimePoint(std::chrono::steady_clock::now())
    {
        setCloseReason(WebSocketCloseConstants::kInternalErrorMessage);
        _readbuf.resize(kChunkSize);
    }

    WebSocketTransport::~WebSocketTransport()
    {
        ;
    }

    void WebSocketTransport::configure(
        const WebSocketPerMessageDeflateOptions& perMessageDeflateOptions,
        const SocketTLSOptions& socketTLSOptions,
        const ProxyConfig& proxyConfig,
        bool enablePong,
        int pingIntervalSecs,
        int pingTimeoutSecs,
        int idleTimeoutSecs,
        int sendTimeoutSecs,
        int closeTimeoutSecs)
    {
        _perMessageDeflateOptions = perMessageDeflateOptions;
        _enablePerMessageDeflate = _perMessageDeflateOptions.enabled();
        _socketTLSOptions = socketTLSOptions;
        _proxyConfig = proxyConfig;
        _enablePong = enablePong;
        _pingIntervalSecs.store(pingIntervalSecs);
        _pingTimeoutSecs.store(pingTimeoutSecs);
        _idleTimeoutSecs.store(idleTimeoutSecs);
        _sendTimeoutSecs.store(sendTimeoutSecs);
        _closeTimeoutMs.store(secondsToMillisecondsClamped(closeTimeoutSecs));
    }

    // Client
    WebSocketInitResult WebSocketTransport::connectToUrl(const std::string& url,
                                                         const WebSocketHttpHeaders& headers,
                                                         int timeoutSecs)
    {
        std::string protocol, host, path, query;
        int port;
        std::string remoteUrl(url);
        WebSocketHttpHeaders currentHeaders(headers);

        WebSocketInitResult result;
        const int maxRedirections = 10;

        for (int i = 0; i < maxRedirections; ++i)
        {
            if (!UrlParser::parse(remoteUrl, protocol, host, path, query, port))
            {
                std::stringstream ss;
                ss << "Could not parse url: '" << url << "'";
                return WebSocketInitResult(false, 0, ss.str());
            }

            if (protocol != "ws" && protocol != "wss")
            {
                std::stringstream ss;
                ss << "Unsupported WebSocket protocol: " << protocol;
                return WebSocketInitResult(false, 0, ss.str());
            }

            std::string errorMsg;
            bool tls = protocol == "wss";
            auto socket = createSocket(tls, -1, errorMsg, _socketTLSOptions);
            auto perMessageDeflate = ix::make_unique<WebSocketPerMessageDeflate>();

            if (!socket)
            {
                return WebSocketInitResult(false, 0, errorMsg);
            }

            socket->setProxyConfig(_proxyConfig);

            WebSocketHandshake webSocketHandshake(_requestInitCancellation,
                                                  socket,
                                                  perMessageDeflate,
                                                  _perMessageDeflateOptions,
                                                  _enablePerMessageDeflate);

            result = webSocketHandshake.clientHandshake(
                remoteUrl, currentHeaders, protocol, host, path, port, timeoutSecs);

            if (result.http_status >= 300 && result.http_status < 400)
            {
                auto it = result.headers.find("Location");
                if (it == result.headers.end())
                {
                    std::stringstream ss;
                    ss << "Missing Location Header for HTTP Redirect response. "
                       << "Rejecting connection to " << url << ", status: " << result.http_status;
                    result.errorStr = ss.str();
                    break;
                }

                std::string redirectedUrl;
                if (!resolveRedirectUrl(remoteUrl, it->second, redirectedUrl, result.errorStr))
                {
                    result.success = false;
                    break;
                }

                if (!shouldForwardSensitiveHeaders(remoteUrl, redirectedUrl))
                {
                    removeSensitiveRedirectHeaders(currentHeaders);
                }
                remoteUrl = redirectedUrl;
                continue;
            }

            if (result.success)
            {
                if (_requestInitCancellation)
                {
                    socket->close();
                    return WebSocketInitResult(false, result.http_status, "Connection cancelled");
                }

                {
                    std::lock_guard<std::mutex> lock(_socketMutex);
                    if (_requestInitCancellation)
                    {
                        socket->close();
                        return WebSocketInitResult(false, result.http_status, "Connection cancelled");
                    }
                    _socket = std::move(socket);
                    _perMessageDeflate = std::move(perMessageDeflate);
                }
                resetConnectionState();
                setReadyState(ReadyState::OPEN);
            }
            return result;
        }

        return result;
    }

    // Server
    WebSocketInitResult WebSocketTransport::connectToSocket(std::unique_ptr<Socket> socket,
                                                            int timeoutSecs,
                                                            bool enablePerMessageDeflate,
                                                            HttpRequestPtr request,
                                                            const std::vector<std::string>& subProtocols)
    {
        // Server should not mask the data it sends to the client
        _useMask = false;
        _blockingSend = true;

        auto perMessageDeflate = ix::make_unique<WebSocketPerMessageDeflate>();

        WebSocketHandshake webSocketHandshake(_requestInitCancellation,
                                              socket,
                                              perMessageDeflate,
                                              _perMessageDeflateOptions,
                                              _enablePerMessageDeflate);

        auto result =
            webSocketHandshake.serverHandshake(timeoutSecs, enablePerMessageDeflate, request, subProtocols);
        if (result.success)
        {
            if (_requestInitCancellation)
            {
                socket->close();
                return WebSocketInitResult(false, result.http_status, "Connection cancelled");
            }

            {
                std::lock_guard<std::mutex> lock(_socketMutex);
                if (_requestInitCancellation)
                {
                    socket->close();
                    return WebSocketInitResult(false, result.http_status, "Connection cancelled");
                }
                _socket = std::move(socket);
                _perMessageDeflate = std::move(perMessageDeflate);
            }
            resetConnectionState();
            setReadyState(ReadyState::OPEN);
        }
        return result;
    }

    WebSocketTransport::ReadyState WebSocketTransport::getReadyState() const
    {
        return _readyState;
    }

    void WebSocketTransport::setReadyState(ReadyState readyState)
    {
        // Lock the _setReadyStateMutex for the duration of this
        // method. This ensures that only a single thread runs the
        // logic below avoiding concurrent execution of the
        // close callback my multiple threads at the same time.
        std::lock_guard<std::mutex> lock(_setReadyStateMutex);

        // No state change, return
        if (_readyState == readyState) return;

        if (readyState == ReadyState::CLOSED)
        {
            _readyState = readyState;
            if (_onCloseCallback)
            {
                _onCloseCallback(_closeCode, getCloseReason(), _closeWireSize, _closeRemote);
            }
            setCloseReason(WebSocketCloseConstants::kInternalErrorMessage);
            _closeCode = WebSocketCloseConstants::kInternalErrorCode;
            _closeWireSize = 0;
            _closeRemote = false;
        }
        else if (readyState == ReadyState::OPEN)
        {
            initTimePointsAfterConnect();
            _pongReceived = false;
        }

        if (_readyState != readyState)
        {
            _readyState = readyState;
        }
    }

    void WebSocketTransport::setOnCloseCallback(const OnCloseCallback& onCloseCallback)
    {
        _onCloseCallback = onCloseCallback;
    }

    void WebSocketTransport::initTimePointsAfterConnect()
    {
        std::lock_guard<std::mutex> lock(_timePointsMutex);
        auto now = std::chrono::steady_clock::now();
        _lastSendPingTimePoint = now;
        _lastPongTimePoint = now;
        _lastActivityTimePoint = now;
    }

    // Only consider send PING time points for that computation.
    bool WebSocketTransport::pingIntervalExceeded(int pingIntervalSecs)
    {
        if (pingIntervalSecs <= 0) return false;

        std::lock_guard<std::mutex> lock(_timePointsMutex);
        auto now = std::chrono::steady_clock::now();
        return now - _lastSendPingTimePoint > std::chrono::seconds(pingIntervalSecs);
    }

    void WebSocketTransport::setPingMessage(const std::string& message, SendMessageKind pingType)
    {
        std::lock_guard<std::mutex> lock(_pingConfigMutex);
        _setCustomMessage = true;
        _kPingMessage = message;
        _pingType = pingType;
    }

    SendMessageKind WebSocketTransport::getPingType() const
    {
        std::lock_guard<std::mutex> lock(_pingConfigMutex);
        return _pingType;
    }

    WebSocketSendInfo WebSocketTransport::sendHeartBeat(SendMessageKind pingMessage)
    {
        _pongReceived = false;
        std::string msg;
        bool setCustomMessage = false;
        {
            std::lock_guard<std::mutex> lock(_pingConfigMutex);
            msg = _kPingMessage;
            setCustomMessage = _setCustomMessage;
        }

        if (!setCustomMessage)
        {
            msg += "::" + std::to_string(_pingIntervalSecs.load()) + "s::" +
                   std::to_string(_pingCount++);
        }
        if (pingMessage == SendMessageKind::Ping)
        {
            return sendPing(msg);
        }
        else if (pingMessage == SendMessageKind::Binary)
        {
            WebSocketSendInfo info = sendBinary(msg, nullptr);
            if (info.success)
            {
                std::lock_guard<std::mutex> lock(_timePointsMutex);
                _lastSendPingTimePoint = std::chrono::steady_clock::now();
            }
            return info;
        }
        else if (pingMessage == SendMessageKind::Text)
        {
            WebSocketSendInfo info = sendText(msg, nullptr);
            if (info.success)
            {
                std::lock_guard<std::mutex> lock(_timePointsMutex);
                _lastSendPingTimePoint = std::chrono::steady_clock::now();
            }
            return info;
        }

        // unknown type ping message
        return {};
    }

    bool WebSocketTransport::closingDelayExceeded(int closeTimeoutMs)
    {
        std::lock_guard<std::mutex> lock(_closingTimePointMutex);
        auto now = std::chrono::steady_clock::now();
        return now - _closingTimePoint > std::chrono::milliseconds(closeTimeoutMs);
    }

    WebSocketTransport::PollResult WebSocketTransport::poll()
    {
        const int pingIntervalSecs = _pingIntervalSecs.load();
        const int pingTimeoutSecs = _pingTimeoutSecs.load();
        const int idleTimeoutSecs = _idleTimeoutSecs.load();
        const int closeTimeoutMs = _closeTimeoutMs.load();

        if (_readyState == ReadyState::OPEN)
        {
            SendMessageKind pingType = getPingType();

            // Check idle timeout and ping timeout
            {
                std::lock_guard<std::mutex> lock(_timePointsMutex);
                auto now = std::chrono::steady_clock::now();

                if (idleTimeoutSecs > 0)
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - _lastActivityTimePoint).count();
                    if (elapsed >= idleTimeoutSecs)
                    {
                        close(WebSocketCloseConstants::kInternalErrorCode, "Idle timeout");
                    }
                }

                // Check ping timeout (independent of ping interval)
                if (pingTimeoutSecs > 0 && pingType == SendMessageKind::Ping && !_pongReceived)
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - _lastPongTimePoint).count();
                    if (elapsed >= pingTimeoutSecs)
                    {
                        close(WebSocketCloseConstants::kInternalErrorCode,
                              WebSocketCloseConstants::kPingTimeoutMessage);
                    }
                }
            }

            if (pingIntervalExceeded(pingIntervalSecs))
            {
                // If it is not a 'ping' message of ping type, there is no need to judge whether
                // pong will receive it (legacy behavior when pingTimeoutSecs not set)
                if (pingTimeoutSecs <= 0 && pingType == SendMessageKind::Ping && !_pongReceived)
                {
                    // ping response (PONG) exceeds the maximum delay, close the connection
                    close(WebSocketCloseConstants::kInternalErrorCode,
                          WebSocketCloseConstants::kPingTimeoutMessage);
                }
                else
                {
                    sendHeartBeat(pingType);
                }
            }
        }

        // No timeout if state is not OPEN, otherwise computed
        // pingIntervalOrTimeoutGCD (equals to -1 if no ping and no ping timeout are set)
        int lastingTimeoutDelayInMs = (_readyState != ReadyState::OPEN) ? 0 : pingIntervalSecs;

        if (pingIntervalSecs > 0)
        {
            // compute lasting delay to wait for next ping / timeout, if at least one set
            std::lock_guard<std::mutex> lock(_timePointsMutex);
            auto now = std::chrono::steady_clock::now();
            auto timeSinceLastPingMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           now - _lastSendPingTimePoint)
                .count();
            int64_t timeoutDelay =
                static_cast<int64_t>(secondsToMillisecondsClamped(pingIntervalSecs)) -
                timeSinceLastPingMs;
            lastingTimeoutDelayInMs = clampInt64ToInt(timeoutDelay);
        }

        // The platform may not have select interrupt capabilities, so wait with a small timeout
        // Also need periodic wakeup for idle/ping timeout checks
        if (lastingTimeoutDelayInMs <= 0 &&
            (!_socket->isWakeUpFromPollSupported() || idleTimeoutSecs > 0 || pingTimeoutSecs > 0))
        {
            lastingTimeoutDelayInMs = 1000; // 1 second for timeout checks
        }

        // If we are requesting a cancellation, pass in a positive and small timeout
        // to never poll forever without a timeout.
        if (_requestInitCancellation)
        {
            lastingTimeoutDelayInMs = 100;
        }

        // poll the socket
        PollResultType pollResult = _socket->isReadyToRead(lastingTimeoutDelayInMs);

        // Make sure we send all the buffered data
        // there can be a lot of it for large messages.
        if (pollResult == PollResultType::SendRequest)
        {
            if (!flushSendBuffer())
            {
                return PollResult::CannotFlushSendBuffer;
            }
        }
        else if (pollResult == PollResultType::ReadyForRead)
        {
            if (!receiveFromSocket())
            {
                return PollResult::AbnormalClose;
            }
        }
        else if (pollResult == PollResultType::Error)
        {
            closeSocket();
        }
        else if (pollResult == PollResultType::CloseRequest)
        {
            closeSocket();
        }

        if (_readyState == ReadyState::CLOSING && closingDelayExceeded(closeTimeoutMs))
        {
            _rxbuf.clear();
            _rxbufOffset = 0;
            // close code and reason were set when calling close()
            closeSocket();
            setReadyState(ReadyState::CLOSED);
        }

        return PollResult::Succeeded;
    }

    bool WebSocketTransport::isSendBufferEmpty() const
    {
        std::lock_guard<std::mutex> lock(_txbufMutex);
        return _txbufOffset >= _txbuf.size();
    }

    void WebSocketTransport::compactTxBuf()
    {
        // Compact when offset exceeds half of buffer size
        if (_txbufOffset > _txbuf.size() / 2 && _txbufOffset > 0)
        {
            _txbuf.erase(_txbuf.begin(), _txbuf.begin() + _txbufOffset);
            _txbufOffset = 0;
        }
    }

    void WebSocketTransport::compactRxBuf()
    {
        // Compact when offset exceeds half of buffer size
        if (_rxbufOffset > _rxbuf.size() / 2 && _rxbufOffset > 0)
        {
            _rxbuf.erase(_rxbuf.begin(), _rxbuf.begin() + _rxbufOffset);
            _rxbufOffset = 0;
        }
    }

    void WebSocketTransport::resetConnectionState()
    {
        {
            std::lock_guard<std::mutex> lock(_txbufMutex);
            _txbuf.clear();
            _txbufOffset = 0;
        }

        _rxbuf.clear();
        _rxbufOffset = 0;
        _rxbufWanted = 0;

        _chunks.clear();
        _chunksSize = 0;
        _receivedMessageCompressed = false;

        _decompressedMessage.clear();
        _compressedMessage.clear();
    }

    template<class Iterator>
    bool WebSocketTransport::appendToSendBuffer(const uint8_t* header,
                                                size_t headerSize,
                                                Iterator begin,
                                                Iterator end,
                                                uint64_t message_size,
                                                uint8_t masking_key[4])
    {
        std::lock_guard<std::mutex> lock(_txbufMutex);

        const size_t maxSize = _txbuf.max_size();
        if (message_size > static_cast<uint64_t>(maxSize) || headerSize > maxSize - _txbuf.size())
        {
            return false;
        }

        const size_t payloadSize = static_cast<size_t>(message_size);
        const size_t headerEndSize = _txbuf.size() + headerSize;
        if (payloadSize > maxSize - headerEndSize)
        {
            return false;
        }

        const size_t requiredSize = headerEndSize + payloadSize;
        if (_txbuf.capacity() < requiredSize)
        {
            _txbuf.reserve(requiredSize);
        }

        _txbuf.insert(_txbuf.end(), header, header + headerSize);

        if (_useMask)
        {
            size_t startPos = _txbuf.size();
            _txbuf.insert(_txbuf.end(), begin, end);
            uint8_t* data = _txbuf.data() + startPos;
            size_t i = 0;
            for (; i < payloadSize && payloadSize - i >= 4; i += 4)
            {
                data[i]     ^= masking_key[0];
                data[i + 1] ^= masking_key[1];
                data[i + 2] ^= masking_key[2];
                data[i + 3] ^= masking_key[3];
            }
            for (; i < payloadSize; ++i)
            {
                data[i] ^= masking_key[i & 0x3];
            }
        }
        else
        {
            _txbuf.insert(_txbuf.end(), begin, end);
        }

        return true;
    }

    void WebSocketTransport::unmaskReceiveBuffer(const wsheader_type& ws)
    {
        if (ws.mask)
        {
            uint8_t* data = _rxbuf.data() + _rxbufOffset + ws.header_size;
            size_t j = 0;
            const size_t payloadSize = static_cast<size_t>(ws.N);
            for (; j < payloadSize && payloadSize - j >= 4; j += 4)
            {
                data[j]     ^= ws.masking_key[0];
                data[j + 1] ^= ws.masking_key[1];
                data[j + 2] ^= ws.masking_key[2];
                data[j + 3] ^= ws.masking_key[3];
            }
            for (; j < payloadSize; ++j)
            {
                data[j] ^= ws.masking_key[j & 0x3];
            }
        }
    }

    //
    // http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-------+-+-------------+-------------------------------+
    // |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    // |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    // |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    // | |1|2|3|       |K|             |                               |
    // +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    // |     Extended payload length continued, if payload len == 127  |
    // + - - - - - - - - - - - - - - - +-------------------------------+
    // |                               |Masking-key, if MASK set to 1  |
    // +-------------------------------+-------------------------------+
    // | Masking-key (continued)       |          Payload Data         |
    // +-------------------------------- - - - - - - - - - - - - - - - +
    // :                     Payload Data continued ...                :
    // + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    // |                     Payload Data continued ...                |
    // +---------------------------------------------------------------+
    //
    void WebSocketTransport::dispatch(WebSocketTransport::PollResult pollResult,
                                      const OnMessageCallback& onMessageCallback)
    {
        std::string payloadScratch;
        std::string mergedMessage;

        while (true)
        {
            wsheader_type ws;
            size_t avail = _rxbuf.size() - _rxbufOffset;  // Available bytes
            if (avail < 2) break;                /* Need at least 2 */
            const uint8_t* data = (uint8_t*) &_rxbuf[_rxbufOffset]; // peek, but don't consume
            ws.fin = (data[0] & 0x80) == 0x80;
            ws.rsv1 = (data[0] & 0x40) == 0x40;
            ws.rsv2 = (data[0] & 0x20) == 0x20;
            ws.rsv3 = (data[0] & 0x10) == 0x10;
            ws.opcode = (wsheader_type::opcode_type)(data[0] & 0x0f);
            ws.mask = (data[1] & 0x80) == 0x80;
            ws.N0 = (data[1] & 0x7f);
            ws.header_size =
                2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
            if (avail < ws.header_size) break; /* Need: ws.header_size - avail */

            if ((ws.rsv1 && !_enablePerMessageDeflate) || ws.rsv2 || ws.rsv3)
            {
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorReservedBitUsed,
                      avail);
                return;
            }

            //
            // Calculate payload length:
            // 0-125 mean the payload is that long.
            // 126 means that the following two bytes indicate the length,
            // 127 means the next 8 bytes indicate the length.
            //
            int i = 0;
            if (ws.N0 < 126)
            {
                ws.N = ws.N0;
                i = 2;
            }
            else if (ws.N0 == 126)
            {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 8;
                ws.N |= ((uint64_t) data[3]) << 0;
                i = 4;
            }
            else if (ws.N0 == 127)
            {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 56;
                ws.N |= ((uint64_t) data[3]) << 48;
                ws.N |= ((uint64_t) data[4]) << 40;
                ws.N |= ((uint64_t) data[5]) << 32;
                ws.N |= ((uint64_t) data[6]) << 24;
                ws.N |= ((uint64_t) data[7]) << 16;
                ws.N |= ((uint64_t) data[8]) << 8;
                ws.N |= ((uint64_t) data[9]) << 0;
                i = 10;
            }
            else
            {
                // invalid payload length according to the spec. bail out
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorMessage,
                      avail);
                return;
            }

            if ((ws.N0 == 126 && ws.N < 126) ||
                (ws.N0 == 127 && ((data[2] & 0x80) == 0x80 || ws.N < 65536)))
            {
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorMessage,
                      avail);
                return;
            }

            bool isControlFrame = ws.opcode == wsheader_type::PING ||
                                  ws.opcode == wsheader_type::PONG ||
                                  ws.opcode == wsheader_type::CLOSE;
            if ((isControlFrame || ws.opcode == wsheader_type::CONTINUATION) && ws.rsv1)
            {
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorReservedBitUsed,
                      avail);
                return;
            }

            if (isControlFrame && ws.N > 125)
            {
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorMessage,
                      avail);
                return;
            }

            // client frames MUST be masked and server frames MUST NOT be masked.
            if (ws.mask == _useMask)
            {
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorMessage,
                      avail);
                return;
            }

            if (ws.mask)
            {
                ws.masking_key[0] = ((uint8_t) data[i + 0]) << 0;
                ws.masking_key[1] = ((uint8_t) data[i + 1]) << 0;
                ws.masking_key[2] = ((uint8_t) data[i + 2]) << 0;
                ws.masking_key[3] = ((uint8_t) data[i + 3]) << 0;
            }
            else
            {
                ws.masking_key[0] = 0;
                ws.masking_key[1] = 0;
                ws.masking_key[2] = 0;
                ws.masking_key[3] = 0;
            }

            if (ws.N > kMaxFramePayloadSize ||
                ws.N > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
            {
                close(WebSocketCloseConstants::kMessageTooBigCode,
                      WebSocketCloseConstants::kMessageTooBigMessage,
                      avail);
                return;
            }

            const uint64_t wantedSize = static_cast<uint64_t>(ws.header_size) + ws.N;
            if (avail < wantedSize)
            {
                _rxbufWanted = wantedSize;
                return; /* Need: ws.header_size+ws.N - avail */
            }

            _rxbufWanted = 0;

            if (!ws.fin && (ws.opcode == wsheader_type::PING || ws.opcode == wsheader_type::PONG ||
                            ws.opcode == wsheader_type::CLOSE))
            {
                // Control messages should not be fragmented
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorCodeControlMessageFragmented);
                return;
            }

            unmaskReceiveBuffer(ws);
            const char* payloadData =
                reinterpret_cast<const char*>(_rxbuf.data() + _rxbufOffset + ws.header_size);
            const size_t payloadSize = static_cast<size_t>(ws.N);

            // We got a whole message, now do something with it:
            if (ws.opcode == wsheader_type::TEXT_FRAME ||
                ws.opcode == wsheader_type::BINARY_FRAME ||
                ws.opcode == wsheader_type::CONTINUATION)
            {
                if (ws.opcode != wsheader_type::CONTINUATION)
                {
                    _fragmentedMessageKind = (ws.opcode == wsheader_type::TEXT_FRAME)
                                                 ? MessageKind::MSG_TEXT
                                                 : MessageKind::MSG_BINARY;

                    _receivedMessageCompressed = _enablePerMessageDeflate && ws.rsv1;

                    // Continuation message needs to follow a non-fin TEXT or BINARY message
                    if (!_chunks.empty())
                    {
                        close(WebSocketCloseConstants::kProtocolErrorCode,
                              WebSocketCloseConstants::kProtocolErrorCodeDataOpcodeOutOfSequence);
                        return;
                    }
                }
                else if (_chunks.empty())
                {
                    // Continuation message need to follow a non-fin TEXT or BINARY message
                    close(
                        WebSocketCloseConstants::kProtocolErrorCode,
                        WebSocketCloseConstants::kProtocolErrorCodeContinuationOpCodeOutOfSequence);
                    return;
                }

                //
                // Usual case. Small unfragmented messages
                //
                if (ws.fin && _chunks.empty())
                {
                    payloadScratch.assign(payloadData, payloadSize);
                    bool emitted = emitMessage(_fragmentedMessageKind,
                                               payloadScratch,
                                               _receivedMessageCompressed,
                                               onMessageCallback);

                    _receivedMessageCompressed = false;
                    if (!emitted)
                    {
                        return;
                    }
                }
                else
                {
                    //
                    // Add intermediary message to our chunk list.
                    // We use a chunk list instead of a big buffer because resizing
                    // large buffer can be very costly when we need to re-allocate
                    // the internal buffer which is slow and can let the internal OS
                    // receive buffer fill out.
                    //
                    if (payloadSize > kMaxFragmentedMessageSize ||
                        _chunksSize > kMaxFragmentedMessageSize - payloadSize)
                    {
                        close(WebSocketCloseConstants::kProtocolErrorCode,
                              WebSocketCloseConstants::kProtocolErrorMessage,
                              avail);
                        return;
                    }

                    _chunksSize += payloadSize;
                    _chunks.emplace_back(payloadData, payloadSize);

                    if (ws.fin)
                    {
                        getMergedChunks(mergedMessage);
                        bool emitted = emitMessage(_fragmentedMessageKind,
                                                   mergedMessage,
                                                   _receivedMessageCompressed,
                                                   onMessageCallback);

                        _chunks.clear();
                        _chunksSize = 0;
                        _receivedMessageCompressed = false;
                        if (!emitted)
                        {
                            return;
                        }
                    }
                    else
                    {
                        if (!emitMessage(MessageKind::FRAGMENT, std::string(), false, onMessageCallback))
                        {
                            return;
                        }
                    }
                }
            }
            else if (ws.opcode == wsheader_type::PING)
            {
                if (_enablePong)
                {
                    // Reply back right away
                    bool compress = false;
                    IXWebSocketSendData pongPayload(payloadData, payloadSize);
                    sendData(wsheader_type::PONG, pongPayload, compress);
                }

                payloadScratch.assign(payloadData, payloadSize);
                if (!emitMessage(MessageKind::PING, payloadScratch, false, onMessageCallback))
                {
                    return;
                }
            }
            else if (ws.opcode == wsheader_type::PONG)
            {
                _pongReceived = true;
                {
                    std::lock_guard<std::mutex> lock(_timePointsMutex);
                    _lastPongTimePoint = std::chrono::steady_clock::now();
                }
                payloadScratch.assign(payloadData, payloadSize);
                if (!emitMessage(MessageKind::PONG, payloadScratch, false, onMessageCallback))
                {
                    return;
                }
            }
            else if (ws.opcode == wsheader_type::CLOSE)
            {
                std::string reason;
                uint16_t code = 0;

                if (ws.N == 1)
                {
                    code = WebSocketCloseConstants::kProtocolErrorCode;
                    reason = WebSocketCloseConstants::kProtocolErrorMessage;
                }
                else if (ws.N >= 2)
                {
                    const auto* payloadBytes = reinterpret_cast<const uint8_t*>(payloadData);

                    // Extract the close code first, available as the first 2 bytes
                    code = static_cast<uint16_t>((static_cast<uint16_t>(payloadBytes[0]) << 8) |
                                                 static_cast<uint16_t>(payloadBytes[1]));

                    // Get the reason.
                    if (payloadSize > 2)
                    {
                        reason.assign(payloadData + 2, payloadSize - 2);
                    }

                    // Validate that the reason is proper utf-8. Autobahn 7.5.1
                    if (!validateUtf8(reason))
                    {
                        code = WebSocketCloseConstants::kInvalidFramePayloadData;
                        reason = WebSocketCloseConstants::kInvalidFramePayloadDataMessage;
                    }

                    //
                    // Validate close codes per RFC 6455 Section 7.4.1.
                    // 1005, 1006, and 1015 are reserved and must not appear on the wire.
                    //
                    if (!isValidCloseCodeForWire(code))
                    {
                        // build up an error message containing the bad error code
                        std::stringstream ss;
                        ss << WebSocketCloseConstants::kInvalidCloseCodeMessage << ": " << code;
                        reason = ss.str();

                        code = WebSocketCloseConstants::kProtocolErrorCode;
                    }
                }
                else
                {
                    // no close code received
                    code = WebSocketCloseConstants::kNoStatusCodeErrorCode;
                    reason = WebSocketCloseConstants::kNoStatusCodeErrorMessage;
                }

                // We receive a CLOSE frame from remote and are NOT the ones who triggered the close
                if (_readyState != ReadyState::CLOSING)
                {
                    // send back the CLOSE frame
                    setReadyState(ReadyState::CLOSING);
                    sendCloseFrame(code, reason);

                    wakeUpFromPoll(SelectInterrupt::kCloseRequest);

                    bool remote = true;
                    closeSocketAndSwitchToClosedState(code, reason, avail, remote);
                }
                else
                {
                    // we got the CLOSE frame answer from our close, so we can close the connection
                    // if the code/reason are the same
                    bool identicalReason = _closeCode == code && getCloseReason() == reason;

                    if (identicalReason)
                    {
                        bool remote = false;
                        closeSocketAndSwitchToClosedState(code, reason, avail, remote);
                    }
                }

                return;
            }
            else
            {
                // Unexpected frame type
                close(WebSocketCloseConstants::kProtocolErrorCode,
                      WebSocketCloseConstants::kProtocolErrorMessage,
                      avail);
                return;
            }

            // Advance offset past the processed message
            _rxbufOffset += ws.header_size + (size_t) ws.N;
        }

        compactRxBuf();

        // if an abnormal closure was raised in poll, and nothing else triggered a CLOSED state in
        // the received and processed data then close the connection
        if (pollResult != PollResult::Succeeded)
        {
            _rxbuf.clear();
            _rxbufOffset = 0;

            // if we previously closed the connection (CLOSING state), then set state to CLOSED
            // (code/reason were set before)
            if (_readyState == ReadyState::CLOSING)
            {
                closeSocket();
                setReadyState(ReadyState::CLOSED);
            }
            // if we weren't closing, then close using abnormal close code and message
            else if (_readyState != ReadyState::CLOSED)
            {
                closeSocketAndSwitchToClosedState(WebSocketCloseConstants::kAbnormalCloseCode,
                                                  WebSocketCloseConstants::kAbnormalCloseMessage,
                                                  0,
                                                  false);
            }
        }
    }

    void WebSocketTransport::getMergedChunks(std::string& message) const
    {
        message.clear();
        message.reserve(_chunksSize);
        for (const auto& chunk : _chunks)
        {
            message.append(chunk);
        }
    }

    bool WebSocketTransport::emitMessage(MessageKind messageKind,
                                         const std::string& message,
                                         bool compressedMessage,
                                         const OnMessageCallback& onMessageCallback)
    {
        {
            std::lock_guard<std::mutex> lock(_timePointsMutex);
            _lastActivityTimePoint = std::chrono::steady_clock::now();
        }
        size_t wireSize = message.size();

        // When the RSV1 bit is 1 it means the message is compressed
        if (compressedMessage && messageKind != MessageKind::FRAGMENT)
        {
            bool success = _perMessageDeflate->decompress(message, _decompressedMessage);
            if (!success)
            {
                close(WebSocketCloseConstants::kInvalidFramePayloadData,
                      WebSocketCloseConstants::kInvalidFramePayloadDataMessage);
                return false;
            }

            if (messageKind == MessageKind::MSG_TEXT && !validateUtf8(_decompressedMessage))
            {
                close(WebSocketCloseConstants::kInvalidFramePayloadData,
                      WebSocketCloseConstants::kInvalidFramePayloadDataMessage);
                return false;
            }

            onMessageCallback(_decompressedMessage, wireSize, false, messageKind);
            return true;
        }
        else
        {
            if (messageKind == MessageKind::MSG_TEXT && !validateUtf8(message))
            {
                close(WebSocketCloseConstants::kInvalidFramePayloadData,
                      WebSocketCloseConstants::kInvalidFramePayloadDataMessage);
                return false;
            }

            onMessageCallback(message, wireSize, false, messageKind);
            return true;
        }
    }

    WebSocketSendInfo WebSocketTransport::sendData(wsheader_type::opcode_type type,
                                                   const IXWebSocketSendData& message,
                                                   bool compress,
                                                   const OnProgressCallback& onProgressCallback)
    {
        std::lock_guard<std::recursive_mutex> lock(_sendDataMutex);

        bool isControlFrame = type == wsheader_type::PING || type == wsheader_type::PONG ||
                              type == wsheader_type::CLOSE;
        if (isControlFrame && message.size() > 125)
        {
            return WebSocketSendInfo(false);
        }

        if (_readyState != ReadyState::OPEN && _readyState != ReadyState::CLOSING)
        {
            return WebSocketSendInfo(false);
        }

        size_t payloadSize = message.size();
        size_t wireSize = message.size();
        bool compressionError = false;

        auto message_begin = message.cbegin();
        auto message_end = message.cend();

        if (compress)
        {
            if (!_perMessageDeflate->compress(message, _compressedMessage))
            {
                bool success = false;
                compressionError = true;
                payloadSize = 0;
                wireSize = 0;
                return WebSocketSendInfo(success, compressionError, payloadSize, wireSize);
            }
            compressionError = false;
            wireSize = _compressedMessage.size();

            IXWebSocketSendData compressedSendData(_compressedMessage);
            message_begin = compressedSendData.cbegin();
            message_end = compressedSendData.cend();
        }

        bool success = true;

        // Common case for most message. No fragmentation required.
        if (wireSize < kChunkSize)
        {
            success = sendFragment(type, true, message_begin, message_end, wireSize, compress);

            if (success && onProgressCallback && !onProgressCallback(1, 1))
            {
                close(WebSocketCloseConstants::kInternalErrorCode, "Send cancelled");
                return WebSocketSendInfo(false, compressionError, payloadSize, wireSize);
            }
        }
        else
        {
            //
            // Large messages need to be fragmented
            //
            // Rules:
            // First message needs to specify a proper type (BINARY or TEXT)
            // Intermediary and last messages need to be of type CONTINUATION
            // Last message must set the fin byte.
            //
            auto steps = wireSize / kChunkSize + (wireSize % kChunkSize == 0 ? 0 : 1);

            auto begin = message_begin;
            auto end = message_end;

            for (uint64_t i = 0; i < steps; ++i)
            {
                bool firstStep = i == 0;
                bool lastStep = (i + 1) == steps;
                bool fin = lastStep;

                end = lastStep ? message_end : begin + kChunkSize;

                auto opcodeType = type;
                if (!firstStep)
                {
                    opcodeType = wsheader_type::CONTINUATION;
                }

                // Send message
                const uint64_t fragmentSize = static_cast<uint64_t>(end - begin);
                if (!sendFragment(opcodeType, fin, begin, end, fragmentSize, compress))
                {
                    return WebSocketSendInfo(false);
                }

                if (onProgressCallback && !onProgressCallback(i + 1, steps))
                {
                    close(WebSocketCloseConstants::kInternalErrorCode, "Send cancelled");
                    return WebSocketSendInfo(false, compressionError, payloadSize, wireSize);
                }

                begin = end;
            }
        }

        // Request to flush the send buffer on the background thread if it isn't empty
        if (!isSendBufferEmpty())
        {
            wakeUpFromPoll(SelectInterrupt::kSendRequest);

            if (_blockingSend && !flushSendBuffer())
            {
                success = false;
            }
        }

        return WebSocketSendInfo(success, compressionError, payloadSize, wireSize);
    }

    template<class Iterator>
    bool WebSocketTransport::sendFragment(wsheader_type::opcode_type type,
                                          bool fin,
                                          Iterator message_begin,
                                          Iterator message_end,
                                          uint64_t message_size,
                                          bool compress)
    {
        uint8_t masking_key[4] = {};
        if (_useMask && !secureRandomBytes(masking_key, sizeof(masking_key)))
        {
            return false;
        }

        // Max header size: 2 + 8 (extended length) + 4 (mask) = 14 bytes
        uint8_t headerBuf[14] = {};
        size_t headerSize = 2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) +
                            (_useMask ? 4 : 0);
        headerBuf[0] = type;

        // The fin bit indicate that this is the last fragment. Fin is French for end.
        if (fin)
        {
            headerBuf[0] |= 0x80;
        }

        // The rsv1 bit indicate that the frame is compressed
        // continuation opcodes should not set it. Autobahn 12.2.10 and others 12.X
        if (compress && type != wsheader_type::CONTINUATION)
        {
            headerBuf[0] |= 0x40;
        }

        if (message_size < 126)
        {
            headerBuf[1] = (message_size & 0xff) | (_useMask ? 0x80 : 0);

            if (_useMask)
            {
                headerBuf[2] = masking_key[0];
                headerBuf[3] = masking_key[1];
                headerBuf[4] = masking_key[2];
                headerBuf[5] = masking_key[3];
            }
        }
        else if (message_size < 65536)
        {
            headerBuf[1] = 126 | (_useMask ? 0x80 : 0);
            headerBuf[2] = (message_size >> 8) & 0xff;
            headerBuf[3] = (message_size >> 0) & 0xff;

            if (_useMask)
            {
                headerBuf[4] = masking_key[0];
                headerBuf[5] = masking_key[1];
                headerBuf[6] = masking_key[2];
                headerBuf[7] = masking_key[3];
            }
        }
        else
        { // TODO: run coverage testing here
            headerBuf[1] = 127 | (_useMask ? 0x80 : 0);
            headerBuf[2] = (message_size >> 56) & 0xff;
            headerBuf[3] = (message_size >> 48) & 0xff;
            headerBuf[4] = (message_size >> 40) & 0xff;
            headerBuf[5] = (message_size >> 32) & 0xff;
            headerBuf[6] = (message_size >> 24) & 0xff;
            headerBuf[7] = (message_size >> 16) & 0xff;
            headerBuf[8] = (message_size >> 8) & 0xff;
            headerBuf[9] = (message_size >> 0) & 0xff;

            if (_useMask)
            {
                headerBuf[10] = masking_key[0];
                headerBuf[11] = masking_key[1];
                headerBuf[12] = masking_key[2];
                headerBuf[13] = masking_key[3];
            }
        }

        // _txbuf will keep growing until it can be transmitted over the socket:
        if (!appendToSendBuffer(
                headerBuf, headerSize, message_begin, message_end, message_size, masking_key))
        {
            return false;
        }

        // Now actually send this data
        return sendOnSocket();
    }

    WebSocketSendInfo WebSocketTransport::sendPing(const IXWebSocketSendData& message)
    {
        bool compress = false;
        WebSocketSendInfo info = sendData(wsheader_type::PING, message, compress);

        if (info.success)
        {
            std::lock_guard<std::mutex> lock(_timePointsMutex);
            _lastSendPingTimePoint = std::chrono::steady_clock::now();
        }

        return info;
    }

    WebSocketSendInfo WebSocketTransport::sendBinary(const IXWebSocketSendData& message,
                                                     const OnProgressCallback& onProgressCallback)

    {
        return sendData(
            wsheader_type::BINARY_FRAME, message, _enablePerMessageDeflate, onProgressCallback);
    }

    WebSocketSendInfo WebSocketTransport::sendText(const IXWebSocketSendData& message,
                                                   const OnProgressCallback& onProgressCallback)

    {
        return sendData(
            wsheader_type::TEXT_FRAME, message, _enablePerMessageDeflate, onProgressCallback);
    }

    bool WebSocketTransport::sendOnSocket()
    {
        std::lock_guard<std::mutex> lock(_txbufMutex);

        while (_txbufOffset < _txbuf.size())
        {
            size_t remaining = _txbuf.size() - _txbufOffset;
            IoResult result;
            {
                std::lock_guard<std::mutex> lock(_socketMutex);
                result = _socket->send((const char*)(_txbuf.data() + _txbufOffset), remaining);
            }

            if (result.wouldBlock())
            {
                break;
            }
            else if (!result || result.closed())
            {
                closeSocket();
                if (_readyState != ReadyState::CLOSING)
                {
                    setReadyState(ReadyState::CLOSED);
                }
                return false;
            }
            else
            {
                _txbufOffset += result.bytes;
            }
        }

        compactTxBuf();
        return true;
    }

    bool WebSocketTransport::receiveFromSocket()
    {
        while (true)
        {
            // If _rxbufWanted isn't set, don't attempt to read more than kChunkSize
            // into _rxbuf. If a client is sending frames faster than they can be
            // processed this would otherwise bloat _rxbuf and further introduce
            // unnecessary processing overhead.
            //
            // Further, not reading everything from the socket will eventually
            // result in back pressure for the client.
            size_t avail = _rxbuf.size() - _rxbufOffset;
            if (_rxbufWanted == 0 && avail >= kChunkSize) break;

            // There's also no point in reading more bytes than needed.
            if (_rxbufWanted > 0 && avail >= _rxbufWanted) break;

            auto result = _socket->recv((char*) &_readbuf[0], _readbuf.size());

            if (result.wouldBlock())
            {
                break;
            }
            else if (!result || result.closed())
            {
                // if there are received data pending to be processed, then delay the abnormal
                // closure to after dispatch (other close code/reason could be read from the
                // buffer)

                closeSocket();
                return false;
            }
            else
            {
                _rxbuf.insert(_rxbuf.end(), _readbuf.begin(), _readbuf.begin() + result.bytes);
            }
        }

        return true;
    }

    void WebSocketTransport::sendCloseFrame(uint16_t code, const std::string& reason)
    {
        bool compress = false;
        code = sanitizeCloseCodeForWire(code);

        // if a status is set/was read
        if (code != WebSocketCloseConstants::kNoStatusCodeErrorCode)
        {
            // See list of close events here:
            // https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent
            std::string closure {(char) (code >> 8), (char) (code & 0xff)};

            // copy reason after code
            closure.append(reason);

            sendData(wsheader_type::CLOSE, closure, compress);
        }
        else
        {
            // no close code/reason set
            sendData(wsheader_type::CLOSE, std::string(""), compress);
        }
    }

    void WebSocketTransport::closeSocket()
    {
        std::lock_guard<std::mutex> lock(_socketMutex);
        if (_socket) _socket->close();
    }

    bool WebSocketTransport::wakeUpFromPoll(uint64_t wakeUpCode)
    {
        std::lock_guard<std::mutex> lock(_socketMutex);
        return _socket ? _socket->wakeUpFromPoll(wakeUpCode) : false;
    }

    void WebSocketTransport::closeSocketAndSwitchToClosedState(uint16_t code,
                                                               const std::string& reason,
                                                               size_t closeWireSize,
                                                               bool remote)
    {
        closeSocket();

        setCloseReason(reason);
        _closeCode = code;
        _closeWireSize = closeWireSize;
        _closeRemote = remote;

        setReadyState(ReadyState::CLOSED);
        _requestInitCancellation = false;
    }

    void WebSocketTransport::close(uint16_t code,
                                   const std::string& reason,
                                   size_t closeWireSize,
                                   bool remote)
    {
        std::lock_guard<std::mutex> lock(_closeMutex);

        _requestInitCancellation = true;

        if (_readyState == ReadyState::CLOSING || _readyState == ReadyState::CLOSED)
        {
            // Wake up the socket polling thread, as
            // Socket::isReadyToRead() might be still waiting the
            // interrupt event to happen.
            bool wakeUpPoll = false;
            {
              std::lock_guard<std::mutex> lock(_socketMutex);
              wakeUpPoll = (_socket && _socket->isWakeUpFromPollSupported());
            }
            if (wakeUpPoll)
            {
                wakeUpFromPoll(SelectInterrupt::kCloseRequest);
            }
            return;
        }

        std::string wireReason = truncateUtf8CloseReason(reason);
        uint16_t wireCode = sanitizeCloseCodeForWire(code);

        if (closeWireSize == 0)
        {
            closeWireSize = wireReason.size();
        }

        if (wireCode == WebSocketCloseConstants::kNoStatusCodeErrorCode)
        {
            wireReason = WebSocketCloseConstants::kNoStatusCodeErrorMessage;
            closeWireSize = 0;
        }

        setCloseReason(wireReason);
        _closeCode = wireCode;
        _closeWireSize = closeWireSize;
        _closeRemote = remote;

        {
            std::lock_guard<std::mutex> lock(_closingTimePointMutex);
            _closingTimePoint = std::chrono::steady_clock::now();
        }
        setReadyState(ReadyState::CLOSING);

        sendCloseFrame(wireCode, wireReason);

        // wake up the poll, but do not close yet
        wakeUpFromPoll(SelectInterrupt::kSendRequest);
    }

    size_t WebSocketTransport::bufferedAmount() const
    {
        std::lock_guard<std::mutex> lock(_txbufMutex);
        return _txbuf.size() - _txbufOffset;
    }

    bool WebSocketTransport::flushSendBuffer()
    {
        auto start = std::chrono::steady_clock::now();
        const int sendTimeoutSecs = _sendTimeoutSecs.load();

        while (!isSendBufferEmpty() && !_requestInitCancellation)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= sendTimeoutSecs)
            {
                return false;
            }

            // Wait with a 10ms timeout until the socket is ready to write.
            // This way we are not busy looping
            PollResultType result = _socket->isReadyToWrite(10);

            if (result == PollResultType::Error)
            {
                closeSocket();
                setReadyState(ReadyState::CLOSED);
                return false;
            }
            else if (result == PollResultType::ReadyForWrite)
            {
                if (!sendOnSocket())
                {
                    return false;
                }
            }
        }

        return true;
    }

    void WebSocketTransport::setCloseReason(const std::string& reason)
    {
        std::lock_guard<std::mutex> lock(_closeReasonMutex);
        _closeReason = reason;
    }

    std::string WebSocketTransport::getCloseReason() const
    {
        std::lock_guard<std::mutex> lock(_closeReasonMutex);
        return _closeReason;
    }
} // namespace ix
