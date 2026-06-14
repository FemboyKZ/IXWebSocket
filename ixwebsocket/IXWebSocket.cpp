/*
 *  IXWebSocket.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2017-2018 Machine Zone, Inc. All rights reserved.
 */

#include "IXWebSocket.h"

#include "IXExponentialBackoff.h"
#include "IXHttp.h"
#include "IXSetThreadName.h"
#include "IXUrlParser.h"
#include "IXUniquePtr.h"
#include "IXUtf8Validator.h"
#include "IXWebSocketHandshake.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <thread>
#include <utility>


namespace
{
    const std::string emptyMsg;
} // namespace


namespace ix
{
    OnTrafficTrackerCallback WebSocket::_onTrafficTrackerCallback = nullptr;
    std::mutex WebSocket::_trafficTrackerCallbackMutex;
    const int WebSocket::kDefaultHandShakeTimeoutSecs(60);
    const int WebSocket::kDefaultPingIntervalSecs(-1);
    const int WebSocket::kDefaultPingTimeoutSecs(-1);
    const bool WebSocket::kDefaultEnablePong(true);
    const uint32_t WebSocket::kDefaultMaxWaitBetweenReconnectionRetries(10 * 1000); // 10s
    const uint32_t WebSocket::kDefaultMinWaitBetweenReconnectionRetries(1);         // 1 ms

    WebSocket::WebSocket()
        : _onMessageCallback(OnMessageCallback())
        , _backpressureThreshold(0)
        , _backpressureActive(false)
        , _stop(false)
        , _threadRunning(false)
        , _threadStopping(false)
        , _automaticReconnection(true)
        , _maxWaitBetweenReconnectionRetries(kDefaultMaxWaitBetweenReconnectionRetries)
        , _minWaitBetweenReconnectionRetries(kDefaultMinWaitBetweenReconnectionRetries)
        , _handshakeTimeoutSecs(kDefaultHandShakeTimeoutSecs)
        , _enablePong(kDefaultEnablePong)
        , _pingIntervalSecs(kDefaultPingIntervalSecs)
        , _pingTimeoutSecs(kDefaultPingTimeoutSecs)
        , _pingType(SendMessageKind::Ping)
        , _autoThreadName(true)
    {
        _ws.setOnCloseCallback(
            [this](uint16_t code, const std::string& reason, size_t wireSize, bool remote)
            {
                invokeOnMessageCallback(ix::make_unique<WebSocketMessage>(WebSocketMessageType::Close,
                                                                           emptyMsg,
                                                                           wireSize,
                                                                           WebSocketErrorInfo(),
                                                                           WebSocketOpenInfo(),
                                                                           WebSocketCloseInfo(code, reason, remote)));
            });
    }

    WebSocket::~WebSocket()
    {
        stop();
        _ws.setOnCloseCallback(nullptr);
    }

    void WebSocket::setUrl(const std::string& url)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _url = url;
    }

    void WebSocket::setHandshakeTimeout(int handshakeTimeoutSecs)
    {
        if (handshakeTimeoutSecs < -1)
        {
            handshakeTimeoutSecs = -1;
        }
        _handshakeTimeoutSecs = handshakeTimeoutSecs;
    }

    int WebSocket::getHandshakeTimeout() const
    {
        return _handshakeTimeoutSecs;
    }

    void WebSocket::setExtraHeaders(const WebSocketHttpHeaders& headers)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _extraHeaders = headers;
    }

    const WebSocketHttpHeaders WebSocket::getExtraHeaders() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _extraHeaders;
    }

    const std::string WebSocket::getUrl() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _url;
    }

    void WebSocket::setPerMessageDeflateOptions(
        const WebSocketPerMessageDeflateOptions& perMessageDeflateOptions)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _perMessageDeflateOptions = perMessageDeflateOptions;
    }

    void WebSocket::setTLSOptions(const SocketTLSOptions& socketTLSOptions)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _socketTLSOptions = socketTLSOptions;
    }

    const SocketTLSOptions WebSocket::getTLSOptions() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _socketTLSOptions;
    }

    void WebSocket::setProxyConfig(const ProxyConfig& proxyConfig)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _proxyConfig = proxyConfig;
    }

    const ProxyConfig WebSocket::getProxyConfig() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _proxyConfig;
    }

    const WebSocketPerMessageDeflateOptions WebSocket::getPerMessageDeflateOptions() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _perMessageDeflateOptions;
    }

    void WebSocket::setPingMessage(const std::string& sendMessage, SendMessageKind pingType)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _pingMessage = sendMessage;
        _pingType = pingType;
        _ws.setPingMessage(_pingMessage, _pingType);
    }
    const std::string WebSocket::getPingMessage() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _pingMessage;
    }
    void WebSocket::setPingInterval(int pingIntervalSecs)
    {
        _pingIntervalSecs.store(pingIntervalSecs);
    }

    int WebSocket::getPingInterval() const
    {
        return _pingIntervalSecs.load();
    }

    void WebSocket::setPong(bool enabled)
    {
        _enablePong.store(enabled);
    }

    void WebSocket::setPerMessageDeflate(bool enabled)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _perMessageDeflateOptions = WebSocketPerMessageDeflateOptions(enabled);
    }

    void WebSocket::setMaxWaitBetweenReconnectionRetries(uint32_t maxWaitBetweenReconnectionRetries)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _maxWaitBetweenReconnectionRetries = maxWaitBetweenReconnectionRetries;
    }

    void WebSocket::setMinWaitBetweenReconnectionRetries(uint32_t minWaitBetweenReconnectionRetries)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _minWaitBetweenReconnectionRetries = minWaitBetweenReconnectionRetries;
    }

    uint32_t WebSocket::getMaxWaitBetweenReconnectionRetries() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _maxWaitBetweenReconnectionRetries;
    }

    uint32_t WebSocket::getMinWaitBetweenReconnectionRetries() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _minWaitBetweenReconnectionRetries;
    }

    void WebSocket::start()
    {
        std::lock_guard<std::mutex> startStopLock(_startStopMutex);

        {
            std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
            if (_threadRunning || _threadStopping)
            {
                return;
            }
        }

        if (_thread.joinable())
        {
            _thread.join();
        }

        _stop = false;
        {
            std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
            if (_threadRunning || _threadStopping)
            {
                return;
            }
            _threadRunning = true;
        }

        try
        {
            _thread = std::thread(&WebSocket::run, this);
        }
        catch (...)
        {
            {
                std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
                _threadRunning = false;
            }
            _threadExitCondition.notify_all();
            throw;
        }
    }

    void WebSocket::stop(uint16_t code, const std::string& reason)
    {
        close(code, reason);

        std::thread threadToJoin;
        bool waitForThreadExit = false;

        {
            std::unique_lock<std::mutex> startStopLock(_startStopMutex);
            std::unique_lock<std::mutex> lifecycleLock(_threadLifecycleMutex);

            if (_threadStopping)
            {
                if (_threadId == std::this_thread::get_id())
                {
                    return;
                }

                startStopLock.unlock();
                _threadExitCondition.wait(lifecycleLock, [this] { return !_threadStopping; });
                return;
            }

            _stop = true;
            _sleepCondition.notify_one();

            if (_thread.joinable())
            {
                if (_thread.get_id() == std::this_thread::get_id())
                {
                    _thread.detach();
                    return;
                }

                _threadStopping = true;
                threadToJoin = std::move(_thread);
            }
            else if (_threadRunning && _threadId == std::this_thread::get_id())
            {
                return;
            }
            else if (_threadRunning)
            {
                _threadStopping = true;
                waitForThreadExit = true;
            }
            else
            {
                _stop = false;
                return;
            }
        }

        if (threadToJoin.joinable())
        {
            threadToJoin.join();
        }

        if (waitForThreadExit)
        {
            std::unique_lock<std::mutex> lock(_threadLifecycleMutex);
            _threadExitCondition.wait(lock, [this] { return !_threadRunning; });
        }

        {
            std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
            _threadStopping = false;
            _stop = false;
        }
        _threadExitCondition.notify_all();
    }

    WebSocketInitResult WebSocket::connect(int timeoutSecs)
    {
        std::string url;
        WebSocketHttpHeaders headers;
        std::vector<std::string> subProtocols;
        int pingIntervalSecs = 0;
        SendMessageKind pingType = SendMessageKind::Ping;

        {
            std::lock_guard<std::mutex> lock(_configMutex);
            _ws.configure(_perMessageDeflateOptions,
                          _socketTLSOptions,
                          _proxyConfig,
                          _enablePong,
                          _pingIntervalSecs,
                          _pingTimeoutSecs,
                          _timeouts.idleTimeoutSecs,
                          _timeouts.sendTimeoutSecs,
                          _timeouts.closeTimeoutSecs);
            url = _url;
            headers = _extraHeaders;
            subProtocols = _subProtocols;
            pingIntervalSecs = _pingIntervalSecs.load();
            pingType = _pingType;
        }

        std::string subProtocolsHeader;
        if (!subProtocols.empty())
        {
            //
            // Sub Protocol strings are comma separated.
            // Python code to do that is:
            // >>> ','.join(['json', 'msgpack'])
            // 'json,msgpack'
            //
            int i = 0;
            for (const auto& subProtocol : subProtocols)
            {
                if (i++ != 0)
                {
                    subProtocolsHeader += ",";
                }
                subProtocolsHeader += subProtocol;
            }
            headers["Sec-WebSocket-Protocol"] = subProtocolsHeader;
        }

        WebSocketInitResult status = _ws.connectToUrl(url, headers, timeoutSecs);
        if (!status.success)
        {
            return status;
        }

        {
            std::lock_guard<std::mutex> lock(_statsMutex);
            _stats.reset();
        }

        invokeOnMessageCallback(ix::make_unique<WebSocketMessage>(
            WebSocketMessageType::Open,
            emptyMsg,
            0,
            WebSocketErrorInfo(),
            WebSocketOpenInfo(status.uri, status.headers, status.protocol),
            WebSocketCloseInfo()));

        if (pingIntervalSecs > 0)
        {
            // Send a heart beat right away
            _ws.sendHeartBeat(pingType);
        }

        return status;
    }

    WebSocketInitResult WebSocket::connectToSocket(std::unique_ptr<Socket> socket,
                                                   int timeoutSecs,
                                                   bool enablePerMessageDeflate,
                                                   HttpRequestPtr request,
                                                   const std::vector<std::string>& subProtocols)
    {
        int pingIntervalSecs = 0;
        SendMessageKind pingType = SendMessageKind::Ping;

        {
            std::lock_guard<std::mutex> lock(_configMutex);
            _ws.configure(_perMessageDeflateOptions,
                          _socketTLSOptions,
                          _proxyConfig,
                          _enablePong,
                          _pingIntervalSecs,
                          _pingTimeoutSecs,
                          _timeouts.idleTimeoutSecs,
                          _timeouts.sendTimeoutSecs,
                          _timeouts.closeTimeoutSecs);
            pingIntervalSecs = _pingIntervalSecs.load();
            pingType = _pingType;
        }

        WebSocketInitResult status =
            _ws.connectToSocket(std::move(socket), timeoutSecs, enablePerMessageDeflate, request, subProtocols);
        if (!status.success)
        {
            return status;
        }

        invokeOnMessageCallback(ix::make_unique<WebSocketMessage>(WebSocketMessageType::Open,
                                                                   emptyMsg,
                                                                   0,
                                                                   WebSocketErrorInfo(),
                                                                   WebSocketOpenInfo(status.uri, status.headers),
                                                                   WebSocketCloseInfo()));

        if (pingIntervalSecs > 0)
        {
            // Send a heart beat right away
            _ws.sendHeartBeat(pingType);
        }

        return status;
    }

    bool WebSocket::isConnected() const
    {
        return getReadyState() == ReadyState::Open;
    }

    bool WebSocket::isClosing() const
    {
        return getReadyState() == ReadyState::Closing;
    }

    void WebSocket::close(uint16_t code, const std::string& reason)
    {
        _ws.close(code, reason);
    }

    void WebSocket::checkConnection(bool firstConnectionAttempt)
    {
        using millis = std::chrono::duration<double, std::milli>;

        uint32_t retries = 0;
        millis duration(0);

        // Try to connect perpetually
        while (true)
        {
            if (isConnected() || isClosing() || _stop)
            {
                break;
            }

            if (!firstConnectionAttempt && !_automaticReconnection)
            {
                // Do not attempt to reconnect
                break;
            }

            firstConnectionAttempt = false;

            // Only sleep if we are retrying
            if (duration.count() > 0)
            {
                std::unique_lock<std::mutex> lock(_sleepMutex);
                _sleepCondition.wait_for(lock, duration);
            }

            if (_stop)
            {
                break;
            }

            // Try to connect synchronously
            ix::WebSocketInitResult status = connect(_handshakeTimeoutSecs);

            if (!status.success)
            {
                WebSocketErrorInfo connectErr;

                if (_automaticReconnection)
                {
                    uint32_t maxWaitBetweenReconnectionRetries = 0;
                    uint32_t minWaitBetweenReconnectionRetries = 0;
                    {
                        std::lock_guard<std::mutex> lock(_configMutex);
                        maxWaitBetweenReconnectionRetries = _maxWaitBetweenReconnectionRetries;
                        minWaitBetweenReconnectionRetries = _minWaitBetweenReconnectionRetries;
                    }

                    duration = millis(calculateRetryWaitMilliseconds(
                        retries++,
                        maxWaitBetweenReconnectionRetries,
                        minWaitBetweenReconnectionRetries));

                    connectErr.wait_time = duration.count();
                    connectErr.retries = retries;
                }

                connectErr.reason = status.errorStr;
                connectErr.http_status = status.http_status;

                invokeOnMessageCallback(ix::make_unique<WebSocketMessage>(WebSocketMessageType::Error,
                                                                          emptyMsg,
                                                                          0,
                                                                          connectErr,
                                                                          WebSocketOpenInfo(),
                                                                          WebSocketCloseInfo()));
            }
        }
    }

    void WebSocket::run()
    {
        {
            std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
            _threadId = std::this_thread::get_id();
            _threadRunning = true;
        }

        auto notifyThreadExit = [this]() {
            std::lock_guard<std::mutex> lock(_threadLifecycleMutex);
            _threadId = std::thread::id();
            _threadRunning = false;
            _threadExitCondition.notify_all();
        };

        if (getAutoThreadName())
        {
            setThreadName(getUrl());
        }

        bool firstConnectionAttempt = true;

        while (true)
        {
            // 1. Make sure we are always connected
            checkConnection(firstConnectionAttempt);

            firstConnectionAttempt = false;

            // if here we are closed then checkConnection was not able to connect
            if (getReadyState() == ReadyState::Closed)
            {
                break;
            }

            // We can avoid to poll if we want to stop and are not closing
            if (_stop && !isClosing()) break;

            // 2. Poll to see if there's any new data available
            WebSocketTransport::PollResult pollResult = _ws.poll();

            // 3. Dispatch the incoming messages
            _ws.dispatch(
                pollResult,
                [this](const std::string& msg,
                       size_t wireSize,
                       bool decompressionError,
                       WebSocketTransport::MessageKind messageKind)
                {
                    WebSocketMessageType webSocketMessageType {WebSocketMessageType::Error};
                    switch (messageKind)
                    {
                        case WebSocketTransport::MessageKind::MSG_TEXT:
                        case WebSocketTransport::MessageKind::MSG_BINARY:
                        {
                            webSocketMessageType = WebSocketMessageType::Message;
                            std::lock_guard<std::mutex> lock(_statsMutex);
                            _stats.messagesReceived++;
                            _stats.bytesReceived += wireSize;
                        }
                        break;

                        case WebSocketTransport::MessageKind::PING:
                        {
                            webSocketMessageType = WebSocketMessageType::Ping;
                            std::lock_guard<std::mutex> lock(_statsMutex);
                            _stats.pingsReceived++;
                            if (_enablePong)
                            {
                                _stats.pongsSent++;
                            }
                        }
                        break;

                        case WebSocketTransport::MessageKind::PONG:
                        {
                            webSocketMessageType = WebSocketMessageType::Pong;
                            std::lock_guard<std::mutex> lock(_statsMutex);
                            _stats.pongsReceived++;
                        }
                        break;

                        case WebSocketTransport::MessageKind::FRAGMENT:
                        {
                            webSocketMessageType = WebSocketMessageType::Fragment;
                        }
                        break;
                    }

                    WebSocketErrorInfo webSocketErrorInfo;
                    webSocketErrorInfo.decompressionError = decompressionError;

                    bool binary = messageKind == WebSocketTransport::MessageKind::MSG_BINARY;

                    invokeOnMessageCallback(ix::make_unique<WebSocketMessage>(webSocketMessageType,
                                                                              msg,
                                                                              wireSize,
                                                                              webSocketErrorInfo,
                                                                              WebSocketOpenInfo(),
                                                                              WebSocketCloseInfo(),
                                                                              binary));

                    WebSocket::invokeTrafficTrackerCallback(wireSize, true);
                });
        }

        notifyThreadExit();
    }

    void WebSocket::setOnMessageCallback(const OnMessageCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_messageCallbackMutex);
        _onMessageCallback = callback;
    }

    bool WebSocket::isOnMessageCallbackRegistered() const
    {
        std::lock_guard<std::mutex> lock(_messageCallbackMutex);
        return _onMessageCallback != nullptr;
    }

    void WebSocket::invokeOnMessageCallback(WebSocketMessagePtr&& message) const
    {
        OnMessageCallback callback;
        {
            std::lock_guard<std::mutex> lock(_messageCallbackMutex);
            callback = _onMessageCallback;
        }

        if (callback)
        {
            try
            {
                callback(message);
            }
            catch (const std::exception&)
            {
            }
            catch (...)
            {
            }
        }
    }

    void WebSocket::setTrafficTrackerCallback(const OnTrafficTrackerCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_trafficTrackerCallbackMutex);
        _onTrafficTrackerCallback = callback;
    }

    void WebSocket::resetTrafficTrackerCallback()
    {
        setTrafficTrackerCallback(nullptr);
    }

    void WebSocket::setBackpressureCallback(const OnBackpressureCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_backpressureMutex);
        _onBackpressureCallback = callback;
    }

    void WebSocket::setBackpressureThreshold(size_t threshold)
    {
        _backpressureThreshold.store(threshold);
    }

    size_t WebSocket::getBackpressureThreshold() const
    {
        return _backpressureThreshold.load();
    }

    void WebSocket::setTimeouts(const WebSocketTimeouts& timeouts)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _timeouts = timeouts;
        _pingIntervalSecs.store(timeouts.pingIntervalSecs);
        _pingTimeoutSecs.store(timeouts.pingTimeoutSecs);
    }

    const WebSocketTimeouts WebSocket::getTimeouts() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _timeouts;
    }

    void WebSocket::invokeTrafficTrackerCallback(size_t size, bool incoming)
    {
        OnTrafficTrackerCallback callback;
        {
            std::lock_guard<std::mutex> lock(_trafficTrackerCallbackMutex);
            callback = _onTrafficTrackerCallback;
        }

        if (callback)
        {
            try
            {
                callback(size, incoming);
            }
            catch (const std::exception&)
            {
            }
            catch (...)
            {
            }
        }
    }

    WebSocketSendInfo WebSocket::send(const std::string& data,
                                      bool binary,
                                      const OnProgressCallback& onProgressCallback)
    {
        return (binary) ? sendBinary(data, onProgressCallback) : sendText(data, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::sendBinary(const std::string& data,
                                            const OnProgressCallback& onProgressCallback)
    {
        return sendMessage(data, SendMessageKind::Binary, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::sendBinary(const IXWebSocketSendData& data,
                                            const OnProgressCallback& onProgressCallback)
    {
        return sendMessage(data, SendMessageKind::Binary, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::sendUtf8Text(const std::string& text,
                                              const OnProgressCallback& onProgressCallback)
    {
        return sendMessage(text, SendMessageKind::Text, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::sendUtf8Text(const IXWebSocketSendData& text,
                                              const OnProgressCallback& onProgressCallback)
    {
        return sendMessage(text, SendMessageKind::Text, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::sendText(const std::string& text,
                                          const OnProgressCallback& onProgressCallback)
    {
        if (!validateUtf8(text))
        {
            close(WebSocketCloseConstants::kInvalidFramePayloadData,
                  WebSocketCloseConstants::kInvalidFramePayloadDataMessage);
            return false;
        }
        return sendMessage(text, SendMessageKind::Text, onProgressCallback);
    }

    WebSocketSendInfo WebSocket::ping(const std::string& text, SendMessageKind pingType)
    {
        // Standard limit ping message size
        constexpr size_t pingMaxPayloadSize = 125;
        if (text.size() > pingMaxPayloadSize) return WebSocketSendInfo(false);

        return sendMessage(text, pingType);
    }

    WebSocketSendInfo WebSocket::sendMessage(const IXWebSocketSendData& message,
                                             SendMessageKind sendMessageKind,
                                             const OnProgressCallback& onProgressCallback)
    {
        if (!isConnected()) return WebSocketSendInfo(false);

        //
        // It is OK to read and write on the same socket in 2 different threads.
        // https://stackoverflow.com/questions/1981372/are-parallel-calls-to-send-recv-on-the-same-socket-valid
        //
        // This makes it so that messages are sent right away, and we dont need
        // a timeout while we poll to keep wake ups to a minimum (which helps
        // with battery life), and use the system select call to notify us when
        // incoming messages are arriving / there's data to be received.
        //
        WebSocketSendInfo webSocketSendInfo;

        {
            std::lock_guard<std::mutex> lock(_writeMutex);
            switch (sendMessageKind)
            {
                case SendMessageKind::Text:
                {
                    webSocketSendInfo = _ws.sendText(message, onProgressCallback);
                    if (webSocketSendInfo.success)
                    {
                        std::lock_guard<std::mutex> statsLock(_statsMutex);
                        _stats.messagesSent++;
                        _stats.bytesSent += webSocketSendInfo.wireSize;
                    }
                }
                break;

                case SendMessageKind::Binary:
                {
                    webSocketSendInfo = _ws.sendBinary(message, onProgressCallback);
                    if (webSocketSendInfo.success)
                    {
                        std::lock_guard<std::mutex> statsLock(_statsMutex);
                        _stats.messagesSent++;
                        _stats.bytesSent += webSocketSendInfo.wireSize;
                    }
                }
                break;

                case SendMessageKind::Ping:
                {
                    webSocketSendInfo = _ws.sendPing(message);
                    if (webSocketSendInfo.success)
                    {
                        std::lock_guard<std::mutex> statsLock(_statsMutex);
                        _stats.pingsSent++;
                    }
                }
                break;
            }
        }

        WebSocket::invokeTrafficTrackerCallback(webSocketSendInfo.wireSize, false);

        // Check backpressure
        size_t threshold = _backpressureThreshold.load();
        if (threshold > 0)
        {
            size_t currentBufferSize = _ws.bufferedAmount();
            bool isAboveThreshold = currentBufferSize >= threshold;
            bool wasActive = !isAboveThreshold;
            OnBackpressureCallback callback;
            if (_backpressureActive.compare_exchange_strong(wasActive, isAboveThreshold))
            {
                std::lock_guard<std::mutex> lock(_backpressureMutex);
                callback = _onBackpressureCallback;
            }

            if (callback)
            {
                try
                {
                    callback(currentBufferSize, isAboveThreshold);
                }
                catch (const std::exception&)
                {
                }
                catch (...)
                {
                }
            }
        }

        return webSocketSendInfo;
    }

    ReadyState WebSocket::getReadyState() const
    {
        switch (_ws.getReadyState())
        {
            case ix::WebSocketTransport::ReadyState::OPEN: return ReadyState::Open;
            case ix::WebSocketTransport::ReadyState::CONNECTING: return ReadyState::Connecting;
            case ix::WebSocketTransport::ReadyState::CLOSING: return ReadyState::Closing;
            case ix::WebSocketTransport::ReadyState::CLOSED: return ReadyState::Closed;
            default: return ReadyState::Closed;
        }
    }

    std::string WebSocket::readyStateToString(ReadyState readyState)
    {
        switch (readyState)
        {
            case ReadyState::Open: return "OPEN";
            case ReadyState::Connecting: return "CONNECTING";
            case ReadyState::Closing: return "CLOSING";
            case ReadyState::Closed: return "CLOSED";
            default: return "UNKNOWN";
        }
    }

    void WebSocket::setAutomaticReconnection(bool enabled)
    {
        _automaticReconnection = enabled;
    }

    bool WebSocket::isAutomaticReconnectionEnabled() const
    {
        return _automaticReconnection;
    }

    size_t WebSocket::bufferedAmount() const
    {
        return _ws.bufferedAmount();
    }

    WebSocketStats WebSocket::getStats() const
    {
        std::lock_guard<std::mutex> lock(_statsMutex);
        return _stats;
    }

    void WebSocket::resetStats()
    {
        std::lock_guard<std::mutex> lock(_statsMutex);
        _stats.reset();
    }

    void WebSocket::addSubProtocol(const std::string& subProtocol)
    {
        if (!isValidHttpHeaderName(subProtocol))
        {
            return;
        }

        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.push_back(subProtocol);
    }

    std::vector<std::string> WebSocket::getSubProtocols() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _subProtocols;
    }

    void WebSocket::clearSubProtocols()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.clear();
    }

    void WebSocket::removeSubProtocol(const std::string& subProtocol)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.erase(
            std::remove(_subProtocols.begin(), _subProtocols.end(), subProtocol),
            _subProtocols.end());
    }

    void WebSocket::setAutoThreadName(bool enabled)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _autoThreadName = enabled;
    }

    bool WebSocket::getAutoThreadName() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _autoThreadName;
    }
} // namespace ix
