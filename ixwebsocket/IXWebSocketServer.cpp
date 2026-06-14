/*
 *  IXWebSocketServer.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone, Inc. All rights reserved.
 */

#include "IXWebSocketServer.h"

#include "IXHttp.h"
#include "IXNetSystem.h"
#include <algorithm>
#include "IXSetThreadName.h"
#include "IXSocketConnect.h"
#include "IXWebSocket.h"
#include "IXWebSocketTransport.h"
#include <exception>
#include <future>
#include <sstream>
#include <string.h>

namespace ix
{
    const int WebSocketServer::kDefaultHandShakeTimeoutSecs(60); // 60 seconds
    const bool WebSocketServer::kDefaultEnablePong(true);
    const int WebSocketServer::kPingIntervalSeconds(-1); // disable heartbeat

    WebSocketServer::WebSocketServer(int port,
                                     const std::string& host,
                                     int backlog,
                                     size_t maxConnections,
                                     int handshakeTimeoutSecs,
                                     int addressFamily,
                                     int pingIntervalSeconds)
        : SocketServer(port, host, backlog, maxConnections, addressFamily)
        , _handshakeTimeoutSecs(handshakeTimeoutSecs)
        , _enablePong(kDefaultEnablePong)
        , _enablePerMessageDeflate(true)
        , _pingIntervalSeconds(pingIntervalSeconds)
        , _maxConnectionsPerIp(0)
    {
    }

    WebSocketServer::~WebSocketServer()
    {
        stop();
    }

    void WebSocketServer::stop()
    {
        stopAcceptingConnections();

        auto clients = getClients();
        for (const auto& [webSocket, connectionState] : clients)
        {
            webSocket->close();
        }

        SocketServer::stop();
    }

    void WebSocketServer::setPong(bool enabled)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _enablePong = enabled;
    }

    void WebSocketServer::setPerMessageDeflate(bool enabled)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _enablePerMessageDeflate = enabled;
    }

    void WebSocketServer::addSubProtocol(const std::string& subProtocol)
    {
        if (!isValidHttpHeaderName(subProtocol))
        {
            return;
        }

        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.push_back(subProtocol);
    }

    void WebSocketServer::clearSubProtocols()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.clear();
    }

    void WebSocketServer::removeSubProtocol(const std::string& subProtocol)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _subProtocols.erase(
            std::remove(_subProtocols.begin(), _subProtocols.end(), subProtocol),
            _subProtocols.end());
    }

    void WebSocketServer::setTimeouts(const WebSocketTimeouts& timeouts)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _timeouts = timeouts;
    }

    WebSocketTimeouts WebSocketServer::getTimeouts() const
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _timeouts;
    }

    void WebSocketServer::setMaxConnectionsPerIp(size_t maxConnections)
    {
        std::lock_guard<std::mutex> lock(_rateLimitMutex);
        _maxConnectionsPerIp = maxConnections;
    }

    size_t WebSocketServer::getMaxConnectionsPerIp() const
    {
        std::lock_guard<std::mutex> lock(_rateLimitMutex);
        return _maxConnectionsPerIp;
    }

    size_t WebSocketServer::getConnectionCountForIp(const std::string& ip)
    {
        std::lock_guard<std::mutex> lock(_rateLimitMutex);
        auto it = _connectionsPerIp.find(ip);
        return (it != _connectionsPerIp.end()) ? it->second : 0;
    }

    void WebSocketServer::setOnConnectionCallback(const OnConnectionCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _onConnectionCallback = callback;
    }

    void WebSocketServer::setOnClientMessageCallback(const OnClientMessageCallback& callback)
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        _onClientMessageCallback = callback;
    }

    void WebSocketServer::handleConnection(std::unique_ptr<Socket> socket,
                                           std::shared_ptr<ConnectionState> connectionState)
    {
        handleUpgrade(std::move(socket), connectionState);

        connectionState->setTerminated();
    }

    void WebSocketServer::handleUpgrade(std::unique_ptr<Socket> socket,
                                        std::shared_ptr<ConnectionState> connectionState,
                                        HttpRequestPtr request)
    {
        setThreadName("Srv:ws:" + connectionState->getId());

        std::string remoteIp = connectionState->getRemoteIp();
        auto decrementConnectionCount = [&]() {
            std::lock_guard<std::mutex> lock(_rateLimitMutex);
            auto it = _connectionsPerIp.find(remoteIp);
            if (it != _connectionsPerIp.end() && it->second > 0)
            {
                if (--it->second == 0)
                {
                    _connectionsPerIp.erase(it);
                }
            }
        };

        // Track connections per IP and check rate limit
        {
            std::lock_guard<std::mutex> lock(_rateLimitMutex);
            if (_maxConnectionsPerIp > 0 && _connectionsPerIp[remoteIp] >= _maxConnectionsPerIp)
            {
                logError("Rate limit exceeded for IP: " + remoteIp);
                connectionState->setTerminated();
                return;
            }
            _connectionsPerIp[remoteIp]++;
        }

        auto webSocket = std::make_shared<WebSocket>();

        int pingIntervalSeconds = 0;
        int handshakeTimeoutSecs = 0;
        bool enablePong = false;
        bool enablePerMessageDeflate = false;
        WebSocketTimeouts timeouts;
        std::vector<std::string> subProtocols;
        OnConnectionCallback onConnectionCallback;
        OnClientMessageCallback onClientMessageCallback;
        {
            std::lock_guard<std::mutex> lock(_configMutex);
            pingIntervalSeconds = _pingIntervalSeconds;
            handshakeTimeoutSecs = _handshakeTimeoutSecs;
            enablePong = _enablePong;
            enablePerMessageDeflate = _enablePerMessageDeflate;
            timeouts = _timeouts;
            subProtocols = _subProtocols;
            onConnectionCallback = _onConnectionCallback;
            onClientMessageCallback = _onClientMessageCallback;
        }

        webSocket->setAutoThreadName(false);
        webSocket->setPingInterval(pingIntervalSeconds);
        webSocket->setTimeouts(timeouts);

        if (onConnectionCallback)
        {
            try
            {
                onConnectionCallback(webSocket, connectionState);
            }
            catch (const std::exception& e)
            {
                logError(std::string("WebSocketServer connection callback threw: ") + e.what());
                connectionState->setTerminated();
                decrementConnectionCount();
                return;
            }
            catch (...)
            {
                logError("WebSocketServer connection callback threw");
                connectionState->setTerminated();
                decrementConnectionCount();
                return;
            }

            if (!webSocket->isOnMessageCallbackRegistered())
            {
                logError("WebSocketServer Application developer error: Server callback improperly "
                         "registered.");
                logError("Missing call to setOnMessageCallback inside setOnConnectionCallback.");
                connectionState->setTerminated();
                decrementConnectionCount();
                return;
            }
        }
        else if (onClientMessageCallback)
        {
            WebSocket* webSocketRawPtr = webSocket.get();
            webSocket->setOnMessageCallback(
                [onClientMessageCallback, webSocketRawPtr, connectionState](
                    const WebSocketMessagePtr& msg)
                { onClientMessageCallback(connectionState, *webSocketRawPtr, msg); });
        }
        else
        {
            logError(
                "WebSocketServer Application developer error: No server callback is registerered.");
            logError("Missing call to setOnConnectionCallback or setOnClientMessageCallback.");
            connectionState->setTerminated();
            decrementConnectionCount();
            return;
        }

        webSocket->setAutomaticReconnection(false);
        webSocket->setPong(enablePong);

        // Add this client to our client map
        {
            std::lock_guard<std::mutex> lock(_clientsMutex);
            _clients[webSocket] = connectionState;
        }

        auto status = webSocket->connectToSocket(std::move(socket),
                                                 handshakeTimeoutSecs,
                                                 enablePerMessageDeflate,
                                                 request,
                                                 subProtocols);
        if (status.success)
        {
            // Process incoming messages and execute callbacks
            // until the connection is closed
            webSocket->run();
        }
        else
        {
            std::stringstream ss;
            ss << "WebSocketServer::handleConnection() HTTP status: " << status.http_status
               << " error: " << status.errorStr;
            logError(ss.str());
        }

        webSocket->setOnMessageCallback(nullptr);

        // Remove this client from our client set
        {
            std::lock_guard<std::mutex> lock(_clientsMutex);
            if (_clients.erase(webSocket) != 1)
            {
                logError("Cannot delete client");
            }
        }

        decrementConnectionCount();
    }

    std::map<std::shared_ptr<WebSocket>, std::shared_ptr<ConnectionState>> WebSocketServer::getClients()
    {
        std::lock_guard<std::mutex> lock(_clientsMutex);
        return _clients;
    }

    std::shared_ptr<WebSocket> WebSocketServer::getClientById(const std::string& id)
    {
        std::lock_guard<std::mutex> lock(_clientsMutex);
        for (const auto& [webSocket, connectionState] : _clients)
        {
            if (connectionState && connectionState->getId() == id)
            {
                return webSocket;
            }
        }
        return nullptr;
    }

    size_t WebSocketServer::getConnectedClientsCount()
    {
        std::lock_guard<std::mutex> lock(_clientsMutex);
        return _clients.size();
    }

    //
    // Classic servers
    //
    void WebSocketServer::makeBroadcastServer()
    {
        setOnClientMessageCallback(
            [this](std::shared_ptr<ConnectionState>,
                   WebSocket& webSocket,
                   const WebSocketMessagePtr& msg)
            {
                if (msg->type == ix::WebSocketMessageType::Message)
                {
                    broadcast(msg->str, msg->binary, &webSocket);
                }
            });
    }

    void WebSocketServer::broadcast(const std::string& data, bool binary, WebSocket* exclude)
    {
        auto clients = getClients();
        for (const auto& [client, state] : clients)
        {
            if (client.get() != exclude)
            {
                client->send(data, binary);
            }
        }
    }

    bool WebSocketServer::listenAndStart()
    {
        auto err = listen();
        if (err)
        {
            return false;
        }

        start();
        return true;
    }

    int WebSocketServer::getHandshakeTimeoutSecs()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _handshakeTimeoutSecs;
    }

    void WebSocketServer::setHandshakeTimeoutSecs(int secs)
    {
        if (secs < -1)
        {
            secs = -1;
        }
        std::lock_guard<std::mutex> lock(_configMutex);
        _handshakeTimeoutSecs = secs;
    }

    int WebSocketServer::getSocketAcceptTimeoutSecs()
    {
        return getHandshakeTimeoutSecs();
    }

    bool WebSocketServer::isPongEnabled()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _enablePong;
    }

    bool WebSocketServer::isPerMessageDeflateEnabled()
    {
        std::lock_guard<std::mutex> lock(_configMutex);
        return _enablePerMessageDeflate;
    }
} // namespace ix
