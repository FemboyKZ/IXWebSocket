/*
 *  IXWebSocketServer.h
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone, Inc. All rights reserved.
 */

#pragma once

#include "IXSocketServer.h"
#include "IXWebSocket.h"
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility> // pair

namespace ix
{
    class WebSocketServer : public SocketServer
    {
    public:
        using OnConnectionCallback =
            std::function<void(std::weak_ptr<WebSocket>, std::shared_ptr<ConnectionState>)>;

        using OnClientMessageCallback = std::function<void(
            std::shared_ptr<ConnectionState>, WebSocket&, const WebSocketMessagePtr&)>;

        WebSocketServer(int port = SocketServer::kDefaultPort,
                        const std::string& host = SocketServer::kDefaultHost,
                        int backlog = SocketServer::kDefaultTcpBacklog,
                        size_t maxConnections = SocketServer::kDefaultMaxConnections,
                        int handshakeTimeoutSecs = WebSocketServer::kDefaultHandShakeTimeoutSecs,
                        int addressFamily = SocketServer::kDefaultAddressFamily,
                        int pingIntervalSeconds = WebSocketServer::kPingIntervalSeconds);
        virtual ~WebSocketServer();
        virtual void stop() final;

        void setPong(bool enabled);
        void enablePong() { setPong(true); }
        void disablePong() { setPong(false); }
        void setPerMessageDeflate(bool enabled);
        void enablePerMessageDeflate() { setPerMessageDeflate(true); }
        void disablePerMessageDeflate() { setPerMessageDeflate(false); }
        void addSubProtocol(const std::string& subProtocol);
        void clearSubProtocols();
        void removeSubProtocol(const std::string& subProtocol);
        void setTimeouts(const WebSocketTimeouts& timeouts);

        // Rate limiting
        void setMaxConnectionsPerIp(size_t maxConnections);
        size_t getMaxConnectionsPerIp() const;
        size_t getConnectionCountForIp(const std::string& ip);
        WebSocketTimeouts getTimeouts() const;

        void setOnConnectionCallback(const OnConnectionCallback& callback);
        void setOnClientMessageCallback(const OnClientMessageCallback& callback);

        // Get all the connected clients
        std::map<std::shared_ptr<WebSocket>, std::shared_ptr<ConnectionState>> getClients();
        std::shared_ptr<WebSocket> getClientById(const std::string& id);

        void makeBroadcastServer();
        bool listenAndStart();

        // Broadcast to all clients (optionally excluding sender)
        void broadcast(const std::string& data, bool binary = false, WebSocket* exclude = nullptr);

        const static int kDefaultHandShakeTimeoutSecs;

        int getHandshakeTimeoutSecs();
        void setHandshakeTimeoutSecs(int secs);
        bool isPongEnabled();
        bool isPerMessageDeflateEnabled();

    private:
        // Member variables
        mutable std::mutex _configMutex;
        int _handshakeTimeoutSecs;
        bool _enablePong;
        bool _enablePerMessageDeflate;
        int _pingIntervalSeconds;
        WebSocketTimeouts _timeouts;

        OnConnectionCallback _onConnectionCallback;
        OnClientMessageCallback _onClientMessageCallback;

        std::vector<std::string> _subProtocols;

        // Rate limiting
        size_t _maxConnectionsPerIp;
        std::map<std::string, size_t> _connectionsPerIp;
        mutable std::mutex _rateLimitMutex;

        std::mutex _clientsMutex;
        std::map<std::shared_ptr<WebSocket>, std::shared_ptr<ConnectionState>> _clients;

        const static bool kDefaultEnablePong;
        const static int kPingIntervalSeconds;

        // Methods
        virtual void handleConnection(std::unique_ptr<Socket> socket,
                                      std::shared_ptr<ConnectionState> connectionState);
        virtual size_t getConnectedClientsCount() final;
        virtual int getSocketAcceptTimeoutSecs() final;

    protected:
        void handleUpgrade(std::unique_ptr<Socket> socket,
                           std::shared_ptr<ConnectionState> connectionState,
                           HttpRequestPtr request = nullptr);
    };
} // namespace ix
