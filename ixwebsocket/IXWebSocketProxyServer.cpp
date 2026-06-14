/*
 *  IXWebSocketProxyServer.cpp
 *  Author: Benjamin Sergeant
 *  Copyright (c) 2018 Machine Zone, Inc. All rights reserved.
 */

#include "IXWebSocketProxyServer.h"

#include "IXWebSocketServer.h"
#include <chrono>
#include <sstream>
#include <thread>

namespace ix
{
    namespace
    {
        const std::chrono::milliseconds kUpstreamConnectionPollInterval(10);
        const std::chrono::seconds kUpstreamConnectionTimeout(10);

        bool waitForUpstreamConnection(ix::WebSocket& upstreamWebSocket)
        {
            const auto deadline = std::chrono::steady_clock::now() + kUpstreamConnectionTimeout;

            while (upstreamWebSocket.getReadyState() == ReadyState::Connecting &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(kUpstreamConnectionPollInterval);
            }

            return upstreamWebSocket.getReadyState() == ReadyState::Open;
        }

        std::string resolveUpstreamUrl(const std::string& defaultRemoteUrl,
                                       const RemoteUrlsMapping& remoteUrlsMapping,
                                       const WebSocketOpenInfo& openInfo)
        {
            std::string url(defaultRemoteUrl);

            auto hostIt = openInfo.headers.find("Host");
            if (hostIt != openInfo.headers.end())
            {
                auto mappingIt = remoteUrlsMapping.find(hostIt->second);
                if (mappingIt != remoteUrlsMapping.end())
                {
                    url = mappingIt->second;
                }
            }

            return url + openInfo.uri;
        }
    } // namespace

    class ProxyConnectionState : public ix::ConnectionState
    {
    public:
        ix::WebSocket& webSocket()
        {
            return _serverWebSocket;
        }

    private:
        ix::WebSocket _serverWebSocket;
    };

    int websocket_proxy_server_main(int port,
                                    const std::string& hostname,
                                    const ix::SocketTLSOptions& tlsOptions,
                                    const std::string& remoteUrl,
                                    const RemoteUrlsMapping& remoteUrlsMapping,
                                    bool /*verbose*/)
    {
        ix::WebSocketServer server(port, hostname);
        server.setTLSOptions(tlsOptions);

        auto factory = []() -> std::shared_ptr<ix::ConnectionState> {
            return std::make_shared<ProxyConnectionState>();
        };
        server.setConnectionStateFactory(factory);

        server.setOnConnectionCallback(
            [remoteUrl, remoteUrlsMapping](std::weak_ptr<ix::WebSocket> webSocket,
                                           std::shared_ptr<ConnectionState> connectionState) {
                auto state = std::static_pointer_cast<ProxyConnectionState>(connectionState);
                std::weak_ptr<ProxyConnectionState> weakState = state;

                // Server connection
                state->webSocket().setOnMessageCallback(
                    [webSocket, weakState](const WebSocketMessagePtr& msg) {
                        auto lockedState = weakState.lock();
                        if (!lockedState)
                        {
                            return;
                        }

                        if (msg->type == ix::WebSocketMessageType::Close)
                        {
                            lockedState->setTerminated();
                        }
                        else if (msg->type == ix::WebSocketMessageType::Message)
                        {
                            if (auto ws = webSocket.lock())
                            {
                                ws->send(msg->str, msg->binary);
                            }
                        }
                    });

                // Client connection
                if (auto ws = webSocket.lock())
                {
                    ws->setOnMessageCallback([weakState, remoteUrl, remoteUrlsMapping, webSocket](
                                                 const WebSocketMessagePtr& msg) {
                        auto lockedState = weakState.lock();
                        if (!lockedState)
                        {
                            return;
                        }

                        if (msg->type == ix::WebSocketMessageType::Open)
                        {
                            std::string url =
                                resolveUpstreamUrl(remoteUrl, remoteUrlsMapping, msg->openInfo);

                            lockedState->webSocket().setUrl(url);
                            lockedState->webSocket().setAutomaticReconnection(false);
                            lockedState->webSocket().start();

                            if (!waitForUpstreamConnection(lockedState->webSocket()))
                            {
                                lockedState->webSocket().stop();

                                if (auto downstream = webSocket.lock())
                                {
                                    downstream->close(
                                        WebSocketCloseConstants::kInternalErrorCode,
                                        "Cannot connect to upstream server");
                                }
                            }
                        }
                        else if (msg->type == ix::WebSocketMessageType::Close)
                        {
                            lockedState->webSocket().close(msg->closeInfo.code,
                                                           msg->closeInfo.reason);
                        }
                        else if (msg->type == ix::WebSocketMessageType::Message)
                        {
                            lockedState->webSocket().send(msg->str, msg->binary);
                        }
                    });
                }
            });

        auto err = server.listen();
        if (err)
        {
            return 1;
        }

        server.start();
        server.wait();

        return 0;
    }
} // namespace ix
